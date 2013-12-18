/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <sys/signalfd.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "attrib/att.h"

#define SERVICE_IFACE			"org.bluez.GattService1"
#define GATT_MGR_IFACE			"org.bluez.GattManager1"
#define CHARACTERISTIC_IFACE		"org.bluez.GattCharacteristic1"

#define ERROR_IFACE			"org.bluez.Error"

/* Immediate Alert Service UUID */
#define IAS_UUID			"00001802-0000-1000-8000-00805f9b34fb"
#define ALERT_LEVEL_CHR_UUID		"00002a06-0000-1000-8000-00805f9b34fb"

static GMainLoop *main_loop;
static GSList *services;

struct characteristic {
	char *uuid;
	uint8_t *value;
	int vlen;
	const char **props;
};

/*
 * Alert Level support Write Without Response only. Supported
 * properties are defined at doc/gatt-api.txt. See "Flags"
 * property of the characteritic object.
 */
static const char const *ias_alert_level_props[] = {
						"write-without-response",
						NULL };

static gboolean chr_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct characteristic *chr = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &chr->uuid);

	return TRUE;
}

static gboolean chr_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct characteristic *chr = user_data;
	DBusMessageIter array;

	printf("Get(\"Value\")\n");

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&chr->value, chr->vlen);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean chr_get_props(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;
	DBusMessageIter array;
	int i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	for (i = 0; chr->props[i]; i++)
		dbus_message_iter_append_basic(&array,
					DBUS_TYPE_STRING, &chr->props[i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static void chr_set_value(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	struct characteristic *chr = user_data;
	DBusMessageIter array;
	uint8_t *value;
	int len;

	printf("Set('Value', ...)\n");

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		printf("Invalid value for Set('Value'...)\n");
		g_dbus_pending_property_error(id,
					ERROR_IFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &len);

	g_free(chr->value);
	chr->value = g_memdup(value, len);
	chr->vlen = len;

	g_dbus_pending_property_success(id);
}

static const GDBusPropertyTable chr_properties[] = {
	{ "UUID",	"s",	chr_get_uuid },
	{ "Value", "ay", chr_get_value, chr_set_value, NULL },
	{ "Flags", "as", chr_get_props, NULL, NULL },
	{ }
};

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	const char *uuid = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean service_get_includes(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return TRUE;
}

static gboolean service_exist_includes(const GDBusPropertyTable *property,
							void *user_data)
{
	return FALSE;
}

static DBusMessage *service_release(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	printf("Terminating...\n");

	g_main_loop_quit(main_loop);

	return NULL;
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_NOREPLY_METHOD("Release", NULL, NULL, service_release) },
	{ }
};

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_get_uuid },
	{ "Includes", "ao", service_get_includes, NULL,
					service_exist_includes },
	{ }
};

static void chr_iface_destroy(gpointer user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->uuid);
	g_free(chr->value);
	g_free(chr);
}

static int register_characteristic(DBusConnection *conn, const char *uuid,
					const uint8_t *value, int vlen,
					const char **props,
					const char *service_path)
{
	struct characteristic *chr;
	static int id = 1;
	char *path;
	int ret = 0;

	path = g_strdup_printf("%s/characteristic%d", service_path, id++);

	chr = g_new0(struct characteristic, 1);

	chr->uuid = g_strdup(uuid);

	chr->value = g_memdup(value, vlen);
	chr->vlen = vlen;
	chr->props = props;

	if (g_dbus_register_interface(conn, path, CHARACTERISTIC_IFACE,
					NULL, NULL, chr_properties,
					chr, chr_iface_destroy) == FALSE) {
		printf("Couldn't register characteristic interface\n");
		ret = -EIO;
	}

	g_free(path);

	return ret;
}

static char *register_service(DBusConnection *conn, const char *uuid)
{
	static int id = 1;
	char *path;

	path = g_strdup_printf("/service%d", id++);
	if (g_dbus_register_interface(conn, path, SERVICE_IFACE,
				service_methods, NULL, service_properties,
				g_strdup(uuid), g_free) == FALSE) {
		printf("Couldn't register service interface\n");
		g_free(path);
		return NULL;
	}

	return path;
}

static void create_services(DBusConnection *conn)
{
	char *service_path;
	uint8_t level = 0;
	int ret;

	service_path = register_service(conn, IAS_UUID);
	if (service_path == NULL)
		return;

	/* Add Alert Level Characteristic to Immediate Alert Service */
	ret = register_characteristic(conn, ALERT_LEVEL_CHR_UUID, &level,
					sizeof(level), ias_alert_level_props,
					service_path);
	if (ret < 0) {
		printf("Couldn't register Alert Level characteristic (IAS)\n");
		g_dbus_unregister_interface(conn, service_path, SERVICE_IFACE);
		g_free(service_path);
		return;
	}

	services = g_slist_prepend(services, service_path);
	printf("Registered service: %s\n", service_path);
}

static void register_external_service_reply(DBusPendingCall *call,
							void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	dbus_error_init(&derr);
	dbus_set_error_from_message(&derr, reply);

	if (dbus_error_is_set(&derr))
		printf("RegisterService: %s\n", derr.message);
	else
		printf("RegisterService: OK\n");

	dbus_message_unref(reply);
	dbus_error_free(&derr);
}

static void register_external_service(gpointer a, gpointer b)
{
	DBusConnection *conn = b;
	const char *path = a;
	DBusMessage *msg;
	DBusPendingCall *call;
	DBusMessageIter iter, dict;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					GATT_MGR_IFACE, "RegisterService");
	if (msg == NULL) {
		printf("Couldn't allocate D-Bus message\n");
		return;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	/* TODO: Add options dictionary */

	dbus_message_iter_close_container(&iter, &dict);

	if (g_dbus_send_message_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(call, register_external_service_reply,
								NULL, NULL);

	dbus_pending_call_unref(call);
}

static void connect_handler(DBusConnection *conn, void *user_data)
{
	g_slist_foreach(services, register_external_service, conn);
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	g_main_loop_quit(main_loop);

	return FALSE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

int main(int argc, char *argv[])
{
	GDBusClient *client;
	DBusConnection *dbus_conn;
	guint signal;

	signal = setup_signalfd();
	if (signal == 0)
		return -errno;

	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_dbus_attach_object_manager(dbus_conn);

	printf("gatt-service unique name: %s\n",
				dbus_bus_get_unique_name(dbus_conn));

	create_services(dbus_conn);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);

	g_source_remove(signal);

	g_slist_free_full(services, g_free);
	dbus_connection_unref(dbus_conn);

	return 0;
}
