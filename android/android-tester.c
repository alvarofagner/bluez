/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdlib.h>
#include <unistd.h>

#include <glib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <libgen.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>

#define adapter_props adapter_prop_bdaddr, adapter_prop_bdname, \
			adapter_prop_uuids, adapter_prop_cod, \
			adapter_prop_scan_mode, adapter_prop_disc_timeout

/*
 * those are assigned to HAL methods and callbacks, we use ID later
 * on mapped in switch-case due to different functions prototypes.
 */

enum hal_bluetooth_callbacks_id {
	adapter_test_end,
	adapter_state_changed_on,
	adapter_state_changed_off,
	adapter_prop_bdaddr,
	adapter_prop_bdname,
	adapter_prop_uuids,
	adapter_prop_cod,
	adapter_prop_scan_mode,
	adapter_prop_disc_timeout,
	adapter_prop_service_record,
	adapter_prop_bonded_devices
};

struct generic_data {
	uint32_t expect_settings_set;
	uint8_t expected_hal_callbacks[];
};

#define WAIT_FOR_SIGNAL_TIME 2 /* in seconds */
#define EMULATOR_SIGNAL "emulator_started"

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	unsigned int mgmt_settings_id;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const struct generic_data *test_data;
	pid_t bluetoothd_pid;
	const bt_interface_t *if_bluetooth;

	bool mgmt_settings_set;
	bool hal_cb_called;

	GSList *expected_callbacks;
};

static char exec_dir[PATH_MAX + 1];

static void test_update_state(void)
{
	struct test_data *data = tester_get_data();

	if (data->mgmt_settings_set && data->hal_cb_called)
		tester_test_passed();
}

static void test_mgmt_settings_set(struct test_data *data)
{
	data->mgmt_settings_set = true;

	test_update_state();
}

static void command_generic_new_settings(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	uint32_t settings;

	if (length != 4) {
		tester_warn("Invalid parameter size for new settings event");
		tester_test_failed();
		return;
	}

	settings = bt_get_le32(param);

	if ((settings & data->test_data->expect_settings_set) !=
					data->test_data->expect_settings_set)
		return;

	test_mgmt_settings_set(data);
	mgmt_unregister(data->mgmt, data->mgmt_settings_id);
}

static void hal_cb_init(struct test_data *data)
{
	unsigned int i = 0;

	while (data->test_data->expected_hal_callbacks[i]) {
						data->expected_callbacks =
				g_slist_append(data->expected_callbacks,
		GINT_TO_POINTER(data->test_data->expected_hal_callbacks[i]));
		i++;
	}
}

static void mgmt_cb_init(struct test_data *data)
{
	if (!data->test_data->expect_settings_set)
		test_mgmt_settings_set(data);
	else
		data->mgmt_settings_id = mgmt_register(data->mgmt,
					MGMT_EV_NEW_SETTINGS, data->mgmt_index,
				command_generic_new_settings, NULL, NULL);
}

static int get_expected_hal_cb(void)
{
	struct test_data *data = tester_get_data();

	return GPOINTER_TO_INT(data->expected_callbacks->data);
}

static void remove_expected_hal_cb(void)
{
	struct test_data *data = tester_get_data();

	data->expected_callbacks = g_slist_remove(data->expected_callbacks,
						data->expected_callbacks->data);

	if (!data->expected_callbacks)
		data->hal_cb_called = true;

	test_update_state();
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	tester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (!tester_use_debug())
		fclose(stderr);

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0,
				NULL, read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void bluetoothd_start(int hci_index)
{
	char prg_name[PATH_MAX + 1];
	char index[8];
	char *prg_argv[4];

	snprintf(prg_name, sizeof(prg_name), "%s/%s", exec_dir, "bluetoothd");
	snprintf(index, sizeof(index), "%d", hci_index);

	prg_argv[0] = prg_name;
	prg_argv[1] = "-i";
	prg_argv[2] = index;
	prg_argv[3] = NULL;

	if (!tester_use_debug())
		fclose(stderr);

	execve(prg_argv[0], prg_argv, NULL);
}

static void emulator(int pipe, int hci_index)
{
	static const char SYSTEM_SOCKET_PATH[] = "\0android_system";
	char buf[1024];
	struct sockaddr_un addr;
	struct timeval tv;
	int fd;
	ssize_t len;

	fd = socket(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		goto failed;

	tv.tv_sec = WAIT_FOR_SIGNAL_TIME;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SYSTEM_SOCKET_PATH, sizeof(SYSTEM_SOCKET_PATH));

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind system socket");
		goto failed;
	}

	len = write(pipe, EMULATOR_SIGNAL, sizeof(EMULATOR_SIGNAL));

	if (len != sizeof(EMULATOR_SIGNAL))
		goto failed;

	memset(buf, 0, sizeof(buf));

	len = read(fd, buf, sizeof(buf));
	if (len <= 0 || (strcmp(buf, "ctl.start=bluetoothd")))
		goto failed;

	close(pipe);
	close(fd);
	bluetoothd_start(hci_index);

failed:
	close(pipe);
	close(fd);
}

static void adapter_state_changed_cb(bt_state_t state)
{
	switch (get_expected_hal_cb()) {
	case adapter_state_changed_on:
		if (state == BT_STATE_ON)
			remove_expected_hal_cb();
		else
			tester_test_failed();
		break;
	default:
		break;
	}
}

static void adapter_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	enum hal_bluetooth_callbacks_id hal_cb;
	int i;

	for (i = 0; i < num_properties; i++) {
		hal_cb = get_expected_hal_cb();
		switch (properties[i].type) {
		case BT_PROPERTY_BDADDR:
			if (hal_cb != adapter_prop_bdaddr) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_BDNAME:
			if (hal_cb != adapter_prop_bdname) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_UUIDS:
			if (hal_cb != adapter_prop_uuids) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_CLASS_OF_DEVICE:
			if (hal_cb != adapter_prop_cod) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_TYPE_OF_DEVICE:
			if (hal_cb != adapter_prop_bdaddr) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_SERVICE_RECORD:
			if (hal_cb != adapter_prop_service_record) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_ADAPTER_SCAN_MODE:
			if (hal_cb != adapter_prop_scan_mode) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
			if (hal_cb != adapter_prop_bonded_devices) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
			if (hal_cb != adapter_prop_disc_timeout) {
				tester_test_failed();
				return;
			}
			remove_expected_hal_cb();
			break;
		default:
			break;
		}
	}
}

static const struct generic_data bluetooth_enable_success_test = {
	.expected_hal_callbacks = {adapter_props, adapter_state_changed_on,
							adapter_test_end}
};

static bt_callbacks_t bt_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_state_changed_cb,
	.adapter_properties_cb = adapter_properties_cb,
	.remote_device_properties_cb = NULL,
	.device_found_cb = NULL,
	.discovery_state_changed_cb = NULL,
	.pin_request_cb = NULL,
	.ssp_request_cb = NULL,
	.bond_state_changed_cb = NULL,
	.acl_state_changed_cb = NULL,
	.thread_evt_cb = NULL,
	.dut_mode_recv_cb = NULL,
	.le_test_mode_cb = NULL
};

static void setup(struct test_data *data)
{
	const hw_module_t *module;
	hw_device_t *device;
	bt_status_t status;
	int signal_fd[2];
	char buf[1024];
	pid_t pid;
	int len;
	int err;

	if (pipe(signal_fd)) {
		tester_setup_failed();
		return;
	}

	pid = fork();

	if (pid < 0) {
		close(signal_fd[0]);
		close(signal_fd[1]);
		tester_setup_failed();
		return;
	}

	if (pid == 0) {
		if (!tester_use_debug())
			fclose(stderr);

		close(signal_fd[0]);
		emulator(signal_fd[1], data->mgmt_index);
		exit(0);
	}

	close(signal_fd[1]);
	data->bluetoothd_pid = pid;

	len = read(signal_fd[0], buf, sizeof(buf));
	if (len <= 0 || (strcmp(buf, EMULATOR_SIGNAL))) {
		close(signal_fd[0]);
		tester_setup_failed();
		return;
	}

	close(signal_fd[0]);

	err = hw_get_module(BT_HARDWARE_MODULE_ID, &module);
	if (err) {
		tester_setup_failed();
		return;
	}

	err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
	if (err) {
		tester_setup_failed();
		return;
	}

	data->if_bluetooth = ((bluetooth_device_t *)
					device)->get_bluetooth_interface();
	if (!data->if_bluetooth) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}
}

static void setup_base(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup(data);

	tester_setup_complete();
}

static void teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->if_bluetooth) {
		data->if_bluetooth->cleanup();
		data->if_bluetooth = NULL;
	}

	if (data->bluetoothd_pid)
		waitpid(data->bluetoothd_pid, NULL, 0);

	if (data->expected_callbacks)
		g_slist_free(data->expected_callbacks);

	tester_teardown_complete();
}

static void test_enable(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hal_cb_init(data);
	mgmt_cb_init(data);

	data->if_bluetooth->enable();
}

static void controller_setup(const void *test_data)
{
	tester_test_passed();
}

#define test_bredrle(name, data, test_setup, test, test_teardown) \
	do { \
		struct test_data *user; \
		user = g_malloc0(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		tester_add_full(name, data, test_pre_setup, test_setup, \
				test, test_teardown, test_post_teardown, \
							3, user, g_free); \
	} while (0)

int main(int argc, char *argv[])
{
	snprintf(exec_dir, sizeof(exec_dir), "%s", dirname(argv[0]));

	tester_init(&argc, &argv);

	test_bredrle("Test Init", NULL, setup_base, controller_setup, teardown);

	test_bredrle("Test Enable - Success", &bluetooth_enable_success_test,
					setup_base, test_enable, teardown);

	return tester_run();
}