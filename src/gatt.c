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
#include "hcid.h"
#include "gatt.h"

/* Common GATT UUIDs */
static const bt_uuid_t primary_uuid  = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };

static const bt_uuid_t chr_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	btd_attr_read_t read_cb;
	uint16_t value_len;
	uint8_t value[0];
};

struct procedure_data {
	uint16_t handle;		/* Operation handle */
	GAttrib *attrib;		/* Connection reference */
	GList *match;			/* List of matching attributes */
	size_t vlen;			/* Pattern: length of each value */
	size_t olen;				/* Output PDU length */
	uint8_t opdu[ATT_DEFAULT_LE_MTU];	/* Output PDU */
};

static GList *local_attribute_db;
static uint16_t next_handle = 0x0001;
static guint unix_watch;

static bool is_service(struct btd_attribute *attr)
{
	if (attr->type.type != BT_UUID16)
		return false;

	if (attr->type.value.u16 == GATT_PRIM_SVC_UUID ||
			attr->type.value.u16 == GATT_SND_SVC_UUID)
		return true;

	return false;
}

static uint8_t errno_to_att(int err)
{
	switch (err) {
	case EACCES:
		return ATT_ECODE_AUTHORIZATION;
	case EINVAL:
		return ATT_ECODE_INVAL_ATTR_VALUE_LEN;
	case ENOENT:
		return ATT_ECODE_ATTR_NOT_FOUND;
	default:
		return ATT_ECODE_UNLIKELY;
	}
}

static gint find_by_handle(gconstpointer a, gconstpointer b)
{
	const struct btd_attribute *attr = a;

	return attr->handle - GPOINTER_TO_UINT(b);
}

void btd_gatt_read_attribute(GAttrib *attrib, struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data)
{
	if (attrib == NULL)
		result(ECOMM, NULL, 0, user_data);

	/*
	 * When read_cb is available, it means that the attribute value
	 * is dynamic, and its value must be read from the external
	 * implementation. If "value_len" is set, the attribute value is
	 * constant. Additional checking are performed by the attribute server
	 * when the ATT Read request arrives based on the characteristic
	 * properties. At this point, properties bitmask doesn't need to be
	 * checked.
	 */
	if (attr->read_cb)
		attr->read_cb(attrib, attr, result, user_data);
	else if (attr->value_len > 0)
		result(0, attr->value, attr->value_len, user_data);
	else
		result(EPERM, NULL, 0, user_data);
}

/*
 * Helper function to create new attributes containing constant/static values.
 * eg: declaration of services/characteristics, and characteristics with
 * fixed values.
 */
static struct btd_attribute *new_const_attribute(const bt_uuid_t *type,
							const uint8_t *value,
							uint16_t len)
{
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
									len);

	memcpy(&attr->type, type, sizeof(*type));
	memcpy(&attr->value, value, len);
	attr->value_len = len;

	return attr;
}

static int local_database_add(uint16_t handle, struct btd_attribute *attr)
{
	attr->handle = handle;

	local_attribute_db = g_list_append(local_attribute_db, attr);

	return 0;
}

struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid)
{
	struct btd_attribute *attr;
	uint16_t len = bt_uuid_len(uuid);
	uint8_t value[len];

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

	/* Set attribute value */
	att_put_uuid(*uuid, value);

	attr = new_const_attribute(&primary_uuid, value, len);

	if (local_database_add(next_handle, attr) < 0) {
		g_free(attr);
		return NULL;
	}

	/* TODO: missing overflow checking */
	next_handle = next_handle + 1;

	return attr;
}

void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);
	bool first_node = local_attribute_db == list;

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	g_free(list->data);
	list = g_list_delete_link(list, list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data)) {
		g_free(list->data);
		list = g_list_delete_link(list, list);
	}

	/*
	 * When removing the first node, local attribute database head
	 * needs to be updated. Node removed from middle doesn't change
	 * the list head address.
	 */
	if (first_node)
		local_attribute_db = list;
}

struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
							btd_attr_read_t read_cb)
{
	struct btd_attribute *char_decl, *char_value = NULL;

	/* Attribute value length */
	uint16_t len = 1 + 2 + bt_uuid_len(uuid);
	uint8_t value[len];

	/*
	 * Characteristic DECLARATION
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +-------+---------------------------------+
	 * |0x2803 | 0xXX 0xYYYY 0xZZZZ...           |
	 * | (1)   |  (2)   (3)   (4)                |
	 * +------+----------------------------------+
	 * (1) - 2 octets: Characteristic declaration UUID
	 * (2) - 1 octet : Properties
	 * (3) - 2 octets: Handle of the characteristic Value
	 * (4) - 2 or 16 octets: Characteristic UUID
	 */

	value[0] = properties;

	/*
	 * Since we don't know yet the characteristic value attribute
	 * handle, we skip and set it later.
	 */

	att_put_uuid(*uuid, &value[3]);

	char_decl = new_const_attribute(&chr_uuid, value, len);
	if (local_database_add(next_handle, char_decl) < 0)
		goto fail;

	next_handle = next_handle + 1;

	/*
	 * Characteristic VALUE
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +----------+---------------------------------+
	 * |0xZZZZ... | 0x...                           |
	 * |  (1)     |  (2)                            |
	 * +----------+---------------------------------+
	 * (1) - 2 or 16 octets: Characteristic UUID
	 * (2) - N octets: Value is read dynamically from the service
	 * implementation (external entity).
	 */

	char_value = g_new0(struct btd_attribute, 1);
	memcpy(&char_value->type, uuid, sizeof(char_value->type));
	char_value->read_cb = read_cb;

	/* TODO: Write callback */

	if (local_database_add(next_handle, char_value) < 0)
		goto fail;

	next_handle = next_handle + 1;

	/*
	 * Update characteristic value handle in characteristic declaration
	 * attribute. For local attributes, we can assume that the handle
	 * representing the characteristic value will get the next available
	 * handle. However, for remote attribute this assumption is not valid.
	 */
	att_put_u16(char_value->handle, &char_decl->value[1]);

	return char_value;

fail:
	g_free(char_decl);
	g_free(char_value);

	return NULL;
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

static void read_by_type_result(GAttrib *attrib, uint8_t *value, size_t vlen,
								void *user_data)
{
	struct procedure_data *proc = user_data;
	GList *head = proc->match;
	struct btd_attribute *attr = head->data;

	proc->match = g_list_delete_link(proc->match, head);

	/* According to Core v4.0 spec, page 1853, if the attribute
	 * value is longer than (ATT_MTU - 4) or 253 octets, whichever
	 * is smaller, then the first (ATT_MTU - 4) or 253 octets shall
	 * be included in this response.
	 * TODO: Replace ATT_DEFAULT_LE_MTU by the correct transport MTU
	 */

	if (proc->olen == 0) {
		proc->vlen = MIN((uint16_t) (ATT_DEFAULT_LE_MTU - 4),
							MIN(vlen, 253));

		/* First entry: Set handle-value length */
		proc->opdu[proc->olen++] = ATT_OP_READ_BY_TYPE_RESP;
		proc->opdu[proc->olen++] = 2 + proc->vlen;
	} else if (proc->vlen != MIN(vlen, 253))
		/* Length doesn't match with handle-value length */
		goto send;

	/* It there space enough for another handle-value pair? */
	if (proc->olen + 2 + proc->vlen > ATT_DEFAULT_LE_MTU)
		goto send;

	/* Copy attribute handle into opdu */
	att_put_u16(attr->handle, &proc->opdu[proc->olen]);
	proc->olen += 2;

	/* Copy attribute value into opdu */
	memcpy(&proc->opdu[proc->olen], value, proc->vlen);
	proc->olen += proc->vlen;

	if (proc->match == NULL)
		goto send;

	/* Getting the next attribute */
	attr = proc->match->data;

	read_by_type_result(attrib, attr->value, attr->value_len, proc);

	return;

send:
	g_attrib_send(attrib, 0, proc->opdu, proc->olen, NULL, NULL, NULL);
	g_list_free(proc->match);
	g_free(proc);
}

static void read_by_type(GAttrib *attrib, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	struct btd_attribute *attr;
	GList *list;
	uint16_t start, end;
	bt_uuid_t uuid;

	if (dec_read_by_type_req(ipdu, ilen, &start, &end, &uuid) == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	DBG("Read By Type: 0x%04x to 0x%04x", start, end);

	if (start == 0x0000 || start > end) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	proc = g_malloc0(sizeof(*proc));

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, &uuid) != 0)
			continue;

		/* Checking attribute consistency */
		if (attr->value_len == 0)
			continue;

		proc->match = g_list_append(proc->match, attr);
	}

	if (proc->match == NULL) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_ATTR_NOT_FOUND);
		g_free(proc);
		return;
	}

	attr = proc->match->data;
	read_by_type_result(attrib, attr->value, attr->value_len, proc);
}

static void read_request_result(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct procedure_data *proc = user_data;
	size_t olen;

	if (err) {
		send_error(proc->attrib, ATT_OP_READ_REQ, proc->handle,
							errno_to_att(err));
		return;
	}

	olen = enc_read_resp(value, len, proc->opdu, sizeof(proc->opdu));

	g_attrib_send(proc->attrib, 0, proc->opdu, olen, NULL, NULL, NULL);

	g_attrib_unref(proc->attrib);
	g_free(proc);
}

static void read_request(GAttrib *attrib, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;

	if (dec_read_req(ipdu, ilen, &handle) == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	/* TODO: permission/property checking missing */

	/* Constant value */
	if (attr->value_len > 0) {
		uint8_t opdu[ATT_DEFAULT_LE_MTU];
		size_t olen = enc_read_resp(attr->value, attr->value_len, opdu,
								sizeof(opdu));

		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
		return;
	}

	/* Dynamic value provided by external entity */
	if (attr->read_cb == NULL) {
		send_error(attrib, ATT_OP_READ_REQ, handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	/*
	 * For external characteristics (GATT server), the read callback
	 * is mapped to a simple proxy function call.
	 */
	proc = g_malloc0(sizeof(*proc));
	proc->attrib = g_attrib_ref(attrib);
	proc->handle = handle;

	attr->read_cb(attrib, attr, read_request_result, proc);
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
	case ATT_OP_READ_BY_TYPE_REQ:
		read_by_type(attrib, ipdu, ilen);
		break;
	case ATT_OP_READ_REQ:
		read_request(attrib, ipdu, ilen);
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
