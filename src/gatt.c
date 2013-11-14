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
#include "attrib/gattrib.h"

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

static void send_error(GAttrib *attrib, uint8_t opcode, uint16_t handle,
								uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));

	g_attrib_send(attrib, 0, pdu, plen, NULL, NULL, NULL);
}

static void read_by_group_resp(GAttrib *attrib, uint16_t start,
					uint16_t end, bt_uuid_t *pattern)
{
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	GList *list;
	struct btd_attribute *last = NULL;
	uint8_t *group_start, *group_end = NULL, *group_uuid;
	unsigned int uuid_type = BT_UUID_UNSPEC;
	size_t group_len = 0, plen = 0;

	/*
	 * Read By Group Type Response format:
	 *    Attribute Opcode: 1 byte
	 *    Length: 1 byte (size of each group)
	 *    Group: start | end | <<UUID>>
	 */

	opdu[0] = ATT_OP_READ_BY_GROUP_RESP;
	group_start = &opdu[2];
	group_uuid = &opdu[6];

	for (list = local_attribute_db; list;
			last = list->data, list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, pattern) != 0)
			continue;

		if (uuid_type != BT_UUID_UNSPEC &&
						uuid_type != attr->type.type) {
			/*
			 * Groups should contain the same length: UUID16 and
			 * UUID128 should be sent on different ATT PDUs
			 */
			break;
		}

		/*
		 * MTU checking should not be shifted up, otherwise the
		 * handle of last end group will not be set properly.
		 */
		if ((plen + group_len) >= ATT_DEFAULT_LE_MTU)
			break;

		/* Start Grouping handle */
		att_put_u16(attr->handle, group_start);

		/* Grouping <<UUID>>: Value is little endian */
		memcpy(group_uuid, attr->value, attr->value_len);

		if (last && group_end) {
			att_put_u16(last->handle, group_end);
			group_end += group_len;
			plen += group_len;
		}

		/* Grouping initial settings: First grouping */
		if (uuid_type == BT_UUID_UNSPEC) {
			uuid_type = attr->type.type;

			/* start(0xXXXX) | end(0xXXXX) | <<UUID>> */
			group_len = 2 + 2 + bt_uuid_len(&attr->type);

			/* 2: ATT Opcode and Length */
			plen = 2 + group_len;

			/* Size of each Attribute Data */
			opdu[1] = group_len;

			group_end = &opdu[4];
		}

		group_start += group_len;
		group_uuid += group_len;
	}

	if (plen == 0) {
		send_error(attrib, ATT_OP_READ_BY_GROUP_REQ, start,
						ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	if (group_end)
		att_put_u16(last->handle, group_end);

	g_attrib_send(attrib, 0, opdu, plen, NULL, NULL, NULL);
}

static void read_by_group(GAttrib *attrib, const uint8_t *ipdu, size_t ilen)
{
	uint16_t decoded, start, end;
	bt_uuid_t pattern;

	decoded = dec_read_by_grp_req(ipdu, ilen, &start, &end, &pattern);
	if (decoded == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start > end || start == 0x0000) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	 /*
	  * Restricting Read By Group Type to <<Primary>>.
	  * Removing the checking below requires changes to support
	  * dynamic values(defined in the upper layer) and additional
	  * security verification.
	  */
	if (bt_uuid_cmp(&pattern, &primary_uuid) != 0) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_UNSUPP_GRP_TYPE);
		return;
	}

	read_by_group_resp(attrib, start, end, &pattern);
}

static void channel_handler_cb(const uint8_t *ipdu, uint16_t ilen,
							gpointer user_data)
{
	GAttrib *attrib = user_data;

	switch (ipdu[0]) {
	case ATT_OP_ERROR:
		break;

	/* Requests */
	case ATT_OP_WRITE_CMD:
	case ATT_OP_WRITE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_REQ_NOT_SUPP);
		break;

	case ATT_OP_READ_BY_GROUP_REQ:
		read_by_group(attrib, ipdu, ilen);
		break;

	/* Responses */
	case ATT_OP_MTU_RESP:
	case ATT_OP_FIND_INFO_RESP:
	case ATT_OP_FIND_BY_TYPE_RESP:
	case ATT_OP_READ_BY_TYPE_RESP:
	case ATT_OP_READ_RESP:
	case ATT_OP_READ_BLOB_RESP:
	case ATT_OP_READ_MULTI_RESP:
	case ATT_OP_READ_BY_GROUP_RESP:
	case ATT_OP_WRITE_RESP:
	case ATT_OP_PREP_WRITE_RESP:
	case ATT_OP_EXEC_WRITE_RESP:
	case ATT_OP_HANDLE_CNF:
		break;

	/* Notification & Indication */
	case ATT_OP_HANDLE_NOTIFY:
	case ATT_OP_HANDLE_IND:
		break;
	}
}

static gboolean unix_hup_cb(GIOChannel *io, GIOCondition cond,
						gpointer user_data)
{
	GAttrib *attrib = user_data;

	g_attrib_unregister_all(attrib);
	g_attrib_unref(attrib);

	return FALSE;
}

static gboolean unix_accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct sockaddr_un uaddr;
	socklen_t len = sizeof(uaddr);
	GIOChannel *nio;
	GAttrib *attrib;
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

	attrib = g_attrib_new(nio);

	g_attrib_register(attrib, GATTRIB_ALL_EVENTS, GATTRIB_ALL_HANDLES,
					channel_handler_cb, attrib, NULL);

	g_io_add_watch(nio, G_IO_HUP, unix_hup_cb, attrib);

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