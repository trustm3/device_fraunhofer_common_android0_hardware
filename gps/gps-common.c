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

#define LOG_TAG "GpsProxyCommon"
/* Uncomment to get the ALOGV messages */
//#define LOG_NDEBUG 0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <utils/Log.h>

#include <hardware/gps.h>

#include "gps-common.h"

ssize_t
gps_msg_recv(int sock, void *pmsg, size_t max_size)
{
	struct gps_msg_header_s *hdr = pmsg;
	size_t done = 0, size = max_size;
	ssize_t ret;
	char *p = pmsg;

        while (done < size) {
		ret = recv(sock, p + done, size - done, 0);
		if (ret == 0) { // EOF peer closed connection
			ALOGE("%s: recv failed: %s", __func__, strerror(errno));
			ret = EOF;
			goto error;
		}
		if (ret < 0) {
			if (errno == EAGAIN) {
				sched_yield();
				continue;
			} else {
				ALOGE("%s: recv failed: %s", __func__, strerror(errno));
				goto error;
			}
		}
		done += ret;
		if (size == max_size && done >= sizeof(*hdr))
			size = hdr->size;
	};

	ALOGV("%s: fd=%d op=%s size=%zu", __func__, sock, gps_msg_op_name(hdr->op), done);
	if (done != hdr->size)
		ALOGE("%s: inconsistant number of bytes received: done=%zu size=%zu",
		      __func__, done, hdr->size);

	return done;

error:
	return ret;
}

ssize_t
gps_msg_send(int sock, void *pmsg, size_t size)
{
	char *p = (char *)pmsg;
	struct gps_msg_header_s *hdr = pmsg;
	size_t done = 0;
	ssize_t ret;

	if (size != hdr->size)
		ALOGE("%s: size does not match header size: %zu != %zu", __func__, size, hdr->size);

        while (done < size) {
		size_t tx_size = (size - done < SNDRCV_BUF_SIZE) ? size - done : SNDRCV_BUF_SIZE;
		ret = send(sock, p + done, tx_size, 0);
		if (ret == 0) { // EOF peer closed connection
			ALOGE("%s: send failed: %s", __func__, strerror(errno));
			done = EOF;
			break;
		}
		if (ret < 0) {
			if (errno == EAGAIN) {
				sched_yield();
				continue;
			} else {
				ALOGE("send failed: msg_size=%zu max_msg_size=%d,'%s'", size, SNDRCV_BUF_SIZE, strerror(errno));
				done = ret;
				break;
			}
		}
		done += ret;
	};
	ALOGV("%s: fd=%d op=%s size=%zu", __func__, sock, gps_msg_op_name(hdr->op), done);
	return done;
}

void *gps_msg_alloc(enum gps_msg_op op, size_t size)
{
	struct gps_msg_header_s *hdr = malloc(size);

	ALOGV("%s: op=%s size=%zu", __func__, gps_msg_op_name(op), size);
	if (hdr) {
		hdr->op = op;
		hdr->size = size;
	} else {
		ALOGE("%s: couldn't allocate %zu bytes for %s",
		      __func__, size, gps_msg_op_name(op));
	}
	return hdr;
}

void gps_msg_free(void *pmsg)
{
	if (pmsg)
		free(pmsg);
	pmsg = NULL;
}

static const char *gps_msg_op_names[GPS_MSG_OP_MAX] = {
	"NOT_USED",
	"GPS_INIT",
	"GPS_START",
	"GPS_STOP",
	"GPS_CLEANUP",
	"GPS_INJECT_TIME",
	"GPS_INJECT_LOCATION",
	"GPS_DELETE_AIDING_DATA",
	"GPS_SET_POSITION_MODE",
	"GPS_GET_EXTENSION",
	"GPS_XTRA_INIT",
	"GPS_XTRA_INJECT_XTRA_DATA",
	"AGPS_INIT",
	"AGPS_DATA_CONN_OPEN",
	"AGPS_DATA_CONN_CLOSED",
	"AGPS_DATA_CONN_FAILED",
	"AGPS_SET_SERVER",
	"AGPS_DATA_CONN_OPEN_WITH_APN_IP_TYPE",
	"SUPL_CERTIFICATE_INSTALL_CERTS",
	"SUPL_CERTIFICATE_REVOKE_CERTS",
	"GPS_NI_INIT",
	"GPS_NI_RESPOND",
	"AGPS_RIL_INIT",
	"AGPS_RIL_SET_REF_LOCATION",
	"AGPS_RIL_SET_SET_ID",
	"AGPS_RIL_NI_MESSAGE",
	"AGPS_RIL_UPDATE_NETWORK_STATE",
	"AGPS_RIL_UPDATE_NETWORK_AVAILABILITY",
	"GPS_GEOFENCE_INIT",
	"GPS_GEOFENCE_ADD_GEOFENCE_AREA",
	"GPS_GEOFENCE_PAUSE_GEOFENCE",
	"GPS_GEOFENCE_RESUME_GEOFENCE",
	"GPS_GEOFENCE_REMOVE_GEOFENCE_AREA",
	"GPS_MEASUREMENT_INIT",
	"GPS_MEASUREMENT_CLOSE",
	"GPS_NAVIGATION_MESSAGE_INIT",
	"GPS_NAVIGATION_MESSAGE_CLOSE",
	"GNSS_CONFIGURATION_UPDATE",
	"GPS_LOCATION_CB",
	"GPS_STATUS_CB",
	"GPS_SV_STATUS_CB",
	"GPS_NMEA_CB",
	"GPS_SET_CAPABILITIES_CB",
	"GPS_ACQUIRE_WAKELOCK_CB",
	"GPS_RELEASE_WAKELOCK_CB",
	"GPS_CREATE_THREAD_CB",
	"GPS_REQUEST_UTC_TIME_CB",
	"GNSS_SET_SYSTEM_INFO_CB",
	"GNSS_SV_STATUS_CB",
	"GPS_XTRA_DOWNLOAD_REQUEST_CB",
	"GPS_XTRA_CREATE_THREAD_CB",
	"AGPS_STATUS_CB",
	"AGPS_CREATE_THREAD_CB",
	"GPS_NI_NOTIFY_CB",
	"GPS_NI_CREATE_THREAD_CB",
	"AGPS_RIL_REQUEST_SETID_CB",
	"AGPS_RIL_REQUEST_REFLOC_CB",
	"AGPS_RIL_CREATE_THREAD_CB",
	"GPS_GEOFENCE_TRANSITION_CB",
	"GPS_GEOFENCE_STATUS_CB",
	"GPS_GEOFENCE_ADD_CB",
	"GPS_GEOFENCE_REMOVE_CB",
	"GPS_GEOFENCE_PAUSE_CB",
	"GPS_GEOFENCE_RESUME_CB",
	"GPS_GEOFENCE_CREATE_THREAD_CB",
	"GPS_MEASUREMENT_CB",
	"GNSS_MEASUREMENT_CB",
	"GPS_NAVIGATION_MESSAGE_CB",
	"GNSS_NAVIGATION_MESSAGE_CB",
	"GPS_PROXY_PROPERTIES_CB",
};

const char *gps_msg_op_name(enum gps_msg_op op)
{
	if (op >= GPS_MSG_OP_MAX)
		op = 0;
	return gps_msg_op_names[op];
}
