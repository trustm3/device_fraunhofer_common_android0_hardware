/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define DEFAULT_WIFI_IFNAME "wlan0"

#define TRUSTME_COM_WIFI_PATH "/data/trustme-com/wifi"
#define CONTROL_IFACE_PATH  "@android:wpa_"

#define WPA_PROXY_COMMAND_ENABLE "enable"
#define WPA_PROXY_COMMAND_DISABLE "disable"

// see frameworks/base/core/jni/android_net_wifi_WifiNative.cpp
#define REPLY_BUF_SIZE 4096 // wpa_supplicant's maximum size.
#define EVENT_BUF_SIZE 2048

enum wpa_states {
	WPA_DISCONNECTED,
	WPA_INTERFACE_DISABLED,
	WPA_INACTIVE,
	WPA_SCANNING,
	WPA_AUTHENTICATING,
	WPA_ASSOCIATING,
	WPA_ASSOCIATED,
	WPA_4WAY_HANDSHAKE,
	WPA_GROUP_HANDSHAKE,
	WPA_COMPLETED
};
