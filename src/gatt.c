/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Instituto Nokia de Tecnologia - INdT
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

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "adapter.h"
#include "device.h"

#include "log.h"
#include "lib/uuid.h"
#include "attrib/att.h"

#include "gatt-dbus.h"
#include "gatt.h"

/* Common GATT UUIDs */
static const bt_uuid_t primary_uuid  = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	uint16_t value_len;
	uint8_t value[0];
};

static GList *local_attribute_db;
static uint16_t next_handle = 0x0001;
static guint unix_watch;

static int local_database_add(uint16_t handle, struct btd_attribute *attr)
{
	attr->handle = handle;

	local_attribute_db = g_list_append(local_attribute_db, attr);

	return 0;
}

struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid)
{
	uint16_t len = bt_uuid_len(uuid);
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
									len);

	/*
	 * Service DECLARATION
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +-------+---------------------------------+
	 * |0x2800 | 0xYYYY...                       |
	 * | (1)   | (2)                             |
	 * +------+----------------------------------+
	 * (1) - 2 octets: Primary/Secondary Service UUID
	 * (2) - 2 or 16 octets: Service UUID
	 */

	attr->type = primary_uuid;

	att_put_uuid(*uuid, attr->value);
	attr->value_len = len;

	if (local_database_add(next_handle, attr) < 0) {
		g_free(attr);
		return NULL;
	}

	/* TODO: missing overflow checking */
	next_handle = next_handle + 1;

	return attr;
}

static gboolean unix_accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct sockaddr_un uaddr;
	socklen_t len = sizeof(uaddr);
	GIOChannel *nio;
	int err, nsk, sk;

	sk = g_io_channel_unix_get_fd(io);

	nsk = accept(sk, (struct sockaddr *) &uaddr, &len);
	if (nsk < 0) {
		err = errno;
		error("ATT UNIX socket accept: %s(%d)", strerror(err), err);
		return TRUE;
	}

	nio = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(nio, TRUE);
	DBG("ATT UNIX socket: %p new client", nio);
	g_io_channel_unref(nio);

	return TRUE;
}

void gatt_init(void)
{
	struct sockaddr_un uaddr  = {
		.sun_family     = AF_UNIX,
		.sun_path       = "\0/bluetooth/unix_att",
	};
	GIOChannel *io;
	int sk, err;

	DBG("Starting GATT server");

	gatt_dbus_manager_register();

	sk = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC , 0);
	if (sk < 0) {
		err = errno;
		error("ATT UNIX socket: %s(%d)", strerror(err), err);
		return;
	}

	if (bind(sk, (struct sockaddr *) &uaddr, sizeof(uaddr)) < 0) {
		err = errno;
		error("binding ATT UNIX socket: %s(%d)", strerror(err), err);
		close(sk);
		return;
	}

	if (listen(sk, 5) < 0) {
		err = errno;
		error("listen ATT UNIX socket: %s(%d)", strerror(err), err);
		close(sk);
		return;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	unix_watch = g_io_add_watch(io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				unix_accept_cb, NULL);
	g_io_channel_unref(io);
}

void gatt_cleanup(void)
{
	DBG("Stopping GATT server");

	gatt_dbus_manager_unregister();
	g_source_remove(unix_watch);
}
