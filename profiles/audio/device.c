/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"

#include "error.h"
#include "dbus-common.h"
#include "device.h"
#include "avdtp.h"
#include "control.h"
#include "avctp.h"
#include "avrcp.h"
#include "sink.h"
#include "source.h"

#define AUDIO_INTERFACE "org.bluez.Audio"

#define CONTROL_CONNECT_TIMEOUT 2
#define AVDTP_CONNECT_TIMEOUT 1
#define AVDTP_CONNECT_TIMEOUT_BOOST 1

typedef enum {
	AUDIO_STATE_DISCONNECTED,
	AUDIO_STATE_CONNECTING,
	AUDIO_STATE_CONNECTED,
} audio_state_t;

struct dev_priv {
	audio_state_t state;

	sink_state_t sink_state;
	avctp_state_t avctp_state;

	guint control_timer;
	guint avdtp_timer;
	guint dc_id;

	gboolean disconnecting;

	unsigned int avdtp_callback_id;
	unsigned int avctp_callback_id;
	unsigned int sink_callback_id;
};

static void device_free(struct audio_device *dev)
{
	struct dev_priv *priv = dev->priv;

	if (priv) {
		if (priv->control_timer)
			g_source_remove(priv->control_timer);
		if (priv->avdtp_timer)
			g_source_remove(priv->avdtp_timer);
		if (priv->dc_id)
			device_remove_disconnect_watch(dev->btd_dev,
							priv->dc_id);

		avdtp_remove_state_cb(priv->avdtp_callback_id);
		avctp_remove_state_cb(priv->avctp_callback_id);
		sink_remove_state_cb(priv->sink_callback_id);

		g_free(priv);
	}

	btd_device_unref(dev->btd_dev);

	g_free(dev);
}

static const char *state2str(audio_state_t state)
{
	switch (state) {
	case AUDIO_STATE_DISCONNECTED:
		return "disconnected";
	case AUDIO_STATE_CONNECTING:
		return "connecting";
	case AUDIO_STATE_CONNECTED:
		return "connected";
	default:
		error("Invalid audio state %d", state);
		return NULL;
	}
}

static gboolean control_connect_timeout(gpointer user_data)
{
	struct audio_device *dev = user_data;

	dev->priv->control_timer = 0;

	if (dev->control)
		avrcp_connect(dev);

	return FALSE;
}

static gboolean device_set_control_timer(struct audio_device *dev)
{
	struct dev_priv *priv = dev->priv;

	if (!dev->control)
		return FALSE;

	if (priv->control_timer)
		return FALSE;

	priv->control_timer = g_timeout_add_seconds(CONTROL_CONNECT_TIMEOUT,
							control_connect_timeout,
							dev);

	return TRUE;
}

static void device_remove_control_timer(struct audio_device *dev)
{
	if (dev->priv->control_timer)
		g_source_remove(dev->priv->control_timer);
	dev->priv->control_timer = 0;
}

static void device_remove_avdtp_timer(struct audio_device *dev)
{
	if (dev->priv->avdtp_timer)
		g_source_remove(dev->priv->avdtp_timer);
	dev->priv->avdtp_timer = 0;
}

static void disconnect_cb(struct btd_device *btd_dev, gboolean removal,
				void *user_data)
{
	struct audio_device *dev = user_data;
	struct dev_priv *priv = dev->priv;

	if (priv->state == AUDIO_STATE_DISCONNECTED)
		return;

	if (priv->disconnecting)
		return;

	priv->disconnecting = TRUE;

	device_remove_control_timer(dev);
	device_remove_avdtp_timer(dev);

	if (dev->control)
		avrcp_disconnect(dev);

	if (dev->sink && priv->sink_state != SINK_STATE_DISCONNECTED)
		sink_disconnect(dev, TRUE);
	else
		priv->disconnecting = FALSE;
}

static void device_set_state(struct audio_device *dev, audio_state_t new_state)
{
	struct dev_priv *priv = dev->priv;
	const char *state_str;

	state_str = state2str(new_state);
	if (!state_str)
		return;

	if (new_state == AUDIO_STATE_DISCONNECTED) {
		if (priv->dc_id) {
			device_remove_disconnect_watch(dev->btd_dev,
							priv->dc_id);
			priv->dc_id = 0;
		}
	} else if (new_state == AUDIO_STATE_CONNECTING)
		priv->dc_id = device_add_disconnect_watch(dev->btd_dev,
						disconnect_cb, dev, NULL);

	if (dev->priv->state == new_state) {
		DBG("state change attempted from %s to %s",
							state_str, state_str);
		return;
	}

	dev->priv->state = new_state;

	if (new_state == AUDIO_STATE_DISCONNECTED)
		priv->disconnecting = FALSE;
}

static void device_avdtp_cb(struct audio_device *dev, struct avdtp *session,
				avdtp_session_state_t old_state,
				avdtp_session_state_t new_state)
{
	if (!dev->control)
		return;

	if (new_state == AVDTP_SESSION_STATE_CONNECTED) {
		if (avdtp_stream_setup_active(session))
			device_set_control_timer(dev);
		else
			avrcp_connect(dev);
	}
}

static void device_sink_cb(struct audio_device *dev,
				sink_state_t old_state,
				sink_state_t new_state,
				void *user_data)
{
	struct dev_priv *priv = dev->priv;

	if (!dev->sink)
		return;

	priv->sink_state = new_state;

	switch (new_state) {
	case SINK_STATE_DISCONNECTED:
		if (dev->control) {
			device_remove_control_timer(dev);
			avrcp_disconnect(dev);
		}

		device_set_state(dev, AUDIO_STATE_DISCONNECTED);
		break;
	case SINK_STATE_CONNECTING:
		device_remove_avdtp_timer(dev);
		device_set_state(dev, AUDIO_STATE_CONNECTING);
		break;
	case SINK_STATE_CONNECTED:
		if (old_state == SINK_STATE_PLAYING)
			break;
		device_set_state(dev, AUDIO_STATE_CONNECTED);
		break;
	case SINK_STATE_PLAYING:
		break;
	}
}

static void device_avctp_cb(struct audio_device *dev, avctp_state_t old_state,
							avctp_state_t new_state)
{
	if (!dev->control)
		return;

	dev->priv->avctp_state = new_state;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		break;
	case AVCTP_STATE_CONNECTING:
		device_remove_control_timer(dev);
		break;
	case AVCTP_STATE_CONNECTED:
		break;
	case AVCTP_STATE_BROWSING_CONNECTING:
		break;
	case AVCTP_STATE_BROWSING_CONNECTED:
		break;
	}
}

struct audio_device *audio_device_register(struct btd_device *device)
{
	struct audio_device *dev;

	DBG("%s", device_get_path(device));

	dev = g_new0(struct audio_device, 1);

	dev->btd_dev = btd_device_ref(device);
	dev->priv = g_new0(struct dev_priv, 1);
	dev->priv->state = AUDIO_STATE_DISCONNECTED;

	dev->priv->sink_callback_id = sink_add_state_cb(dev, device_sink_cb,
									NULL);
	dev->priv->avdtp_callback_id = avdtp_add_state_cb(dev, device_avdtp_cb);
	dev->priv->avctp_callback_id = avctp_add_state_cb(dev, device_avctp_cb);

	return dev;
}

gboolean audio_device_is_active(struct audio_device *dev,
						const char *interface)
{
	if (!interface) {
		if ((dev->sink || dev->source) && avdtp_is_connected(dev))
			return TRUE;
	} else if (!strcmp(interface, AUDIO_SINK_INTERFACE) && dev->sink &&
				avdtp_is_connected(dev))
		return TRUE;
	else if (!strcmp(interface, AUDIO_SOURCE_INTERFACE) && dev->source &&
				avdtp_is_connected(dev))
		return TRUE;
	else if (!strcmp(interface, AUDIO_CONTROL_INTERFACE) && dev->control &&
				control_is_active(dev))
		return TRUE;

	return FALSE;
}

void audio_device_unregister(struct audio_device *device)
{
	DBG("%s", device_get_path(device->btd_dev));

	if (device->sink)
		sink_unregister(device);

	if (device->source)
		source_unregister(device);

	if (device->control)
		control_unregister(device);

	device_free(device);
}
