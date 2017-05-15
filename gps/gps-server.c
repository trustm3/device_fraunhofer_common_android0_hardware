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

#define LOG_TAG "GpsProxyServer"
/* Uncomment to get the ALOGV messages */
//#define LOG_NDEBUG 0

#include <pthread.h>
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <cutils/sockets.h>

#include <hardware/gps.h>

#include <utils/Log.h>

#include "gps-common.h"

static const GpsInterface *gps_interface;
static const GpsXtraInterface *gps_xtra_interface;
static const AGpsInterface *agps_interface;
static const SuplCertificateInterface *supl_certificate_interface;
static const GpsNiInterface *gps_ni_interface;
static const AGpsRilInterface *agps_ril_interface;
static const GpsGeofencingInterface *gps_geofence_interface;
static const GpsMeasurementInterface *gps_measurement_interface;
static const GpsNavigationMessageInterface *gps_navigation_message_interface;
static const GnssConfigurationInterface *gnss_configuration_interface;
static const GpsDebugInterface *gps_debug_interface;

struct generic_thread_cb_args_s {
	void (*start)(void *data);
	void *arg;
};

struct gps_interface_conn_s {
	const char *sock_name;
	enum gps_msg_op create_thread_op;
	pthread_t thread;
	struct generic_thread_cb_args_s thread_args;
	int sock_listen;
	int sock;
};

static struct gps_interface_conn_s core_request = {
	.sock_name = CORE_REQUEST_SOCK_NAME,
};

static struct gps_interface_conn_s core_cb = {
	.sock_name = CORE_CALLBACK_SOCK_NAME,
};

static struct gps_interface_conn_s gps_cb = {
	.sock_name = GPS_CALLBACK_SOCK_NAME,
	.create_thread_op = GPS_CREATE_THREAD_CB,
};

static struct gps_interface_conn_s gps_xtra_cb = {
	.sock_name = GPS_XTRA_CALLBACK_SOCK_NAME,
	.create_thread_op = GPS_XTRA_CREATE_THREAD_CB,
};

static struct gps_interface_conn_s gps_ni_cb = {
	.sock_name = GPS_NI_CALLBACK_SOCK_NAME,
	.create_thread_op = GPS_NI_CREATE_THREAD_CB,
};

static struct gps_interface_conn_s agps_cb = {
	.sock_name = AGPS_CALLBACK_SOCK_NAME,
	.create_thread_op = AGPS_CREATE_THREAD_CB,
};

static struct gps_interface_conn_s agps_ril_cb = {
	.sock_name = AGPS_RIL_CALLBACK_SOCK_NAME ,
	.create_thread_op = AGPS_RIL_CREATE_THREAD_CB,
};

static struct gps_interface_conn_s gps_geofence_cb = {
	.sock_name = GPS_GEOFENCE_CALLBACK_SOCK_NAME ,
	.create_thread_op = GPS_GEOFENCE_CREATE_THREAD_CB,
};

/*
 * Helper functions
 */

static int
gps_socket_open(struct gps_interface_conn_s *conn)
{
	struct sockaddr_un server;
	int err;

	conn->sock_listen = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (conn->sock_listen < 0) {
		ALOGE("Couldn't open %s socket: %s", conn->sock_name, strerror(errno));
		return -1;
	}

	int buf_size = SNDRCV_BUF_SIZE;
	if (setsockopt(conn->sock_listen, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set receive buffer size on %s socket: %s",
			__func__, conn->sock_name, strerror(errno));
		return -1;
	}
	if (setsockopt(conn->sock_listen, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set send buffer size on %s socket: %s",
			__func__, conn->sock_name, strerror(errno));
		return -1;
	}

	/* Setup listening on that socket */
	memset(&server, 0, sizeof(server));
	server.sun_family = AF_UNIX;
	snprintf(server.sun_path, UNIX_PATH_MAX, "%s/%s.sock",
		 GPS_PROXY_SOCKET_PATH, conn->sock_name);

	ALOGD("Open UNIX socket %d and bind it to %s ", conn->sock_listen, server.sun_path);

	/* Unlink existing socket first */
	err = unlink(server.sun_path);
	if (err && errno != ENOENT)
		ALOGE("couldn't unlink %s: %s", server.sun_path, strerror(errno));

	err = bind(conn->sock_listen, (struct sockaddr *)&server, sizeof(server));
	if (err) {
		ALOGE("couldn't bind to %s socket: %s", conn->sock_name, strerror(errno));
		goto err_socket;
	}

	/* We currently allow just one client */
	err = listen(conn->sock_listen, 1);
	if (err) {
		ALOGE("couldn't listen to %s socket: %s", conn->sock_name, strerror(errno));
		goto err_socket;
	}

	return 0;

err_socket:
	close(conn->sock_listen);
	conn->sock_listen = -1;
	return err;
}

static int
gps_socket_accept(struct gps_interface_conn_s *conn)
{
	struct sockaddr_in remote;
	socklen_t remote_addrlen = sizeof(remote);

	if (conn->sock_listen <= 0) {
		ALOGE("%s: socket %s not yet opened", __func__, conn->sock_name);
		return -1;
	}

	ALOGD("Going to accept connections on %s socket %d", conn->sock_name, conn->sock_listen);

	conn->sock = accept(conn->sock_listen, (struct sockaddr *)&remote, &remote_addrlen);
	if (conn->sock < 0) {
		ALOGE("couldn't accept connection on %s socket: %s",
		      conn->sock_name, strerror(errno));
		close(conn->sock_listen);
		return conn->sock;
	}

	ALOGI("Accepted connection %d on %s socket %d",
	      conn->sock, conn->sock_name, conn->sock_listen);

	int buf_size = SNDRCV_BUF_SIZE;
	if (setsockopt(conn->sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set receive buffer size on %s socket: %s",
			__func__, conn->sock_name, strerror(errno));
		return -1;
	}
	if (setsockopt(conn->sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set send buffer size on %s socket: %s",
			__func__, conn->sock_name, strerror(errno));
		return -1;
	}

	return 0;
}

static int
gps_socket_open_and_accept(struct gps_interface_conn_s *conn)
{
	int err;

	err = gps_socket_open(conn);
	if (err)
		return err;

	return gps_socket_accept(conn);
}

static void
gps_msg_remote_cb(const struct gps_interface_conn_s *conn, void *pmsg)
{
	if (conn->sock <= 0) {
		ALOGE("%s: socket %s not yet open", __func__, conn->sock_name);
		return;
	}

	struct gps_msg_header_s *hdr = pmsg;

	if (gps_msg_send(conn->sock, pmsg, hdr->size) < 0)
		ALOGE("gps_msg_send() to socket %s failed: %s", strerror(errno), conn->sock_name);
	ALOGV("callback %s sent to %s socket", gps_msg_op_name(hdr->op), conn->sock_name);
}

static void
gps_msg_remote_cb_by_size(const struct gps_interface_conn_s *conn, void *pmsg, size_t size)
{
	struct gps_msg_header_s *hdr = pmsg;

	hdr->size = size;
	gps_msg_remote_cb(conn, pmsg);
}

static void
gps_msg_remote_cb_nodata(const struct gps_interface_conn_s *conn, enum gps_msg_op op)
{
	struct gps_msg_header_s hdr = {
		.op = op,
		.size = sizeof(hdr),
	};

	gps_msg_remote_cb(conn, &hdr);
}

static void
gps_msg_remote_cb_and_free(const struct gps_interface_conn_s *conn, void *pmsg)
{
	gps_msg_remote_cb(conn, pmsg);
	gps_msg_free(pmsg);
}

#define gps_msg_remote_cb_by_type(conn, pmsg) \
	gps_msg_remote_cb_by_size(conn, pmsg, sizeof(*(pmsg)))

static void *
generic_posix_cb_routine(void *data)
{
	struct generic_thread_cb_args_s *targs = data;

	targs->start(targs->arg);
	return NULL;
}

static pthread_t
generic_create_thread_cb(struct gps_interface_conn_s *conn,
			 const char *name, void (*start)(void *), void *arg)
{
	int err;

	ALOGD("Creating callback thread %s", name);

	if (!start || !conn) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return -1;
	}

	gps_msg_remote_cb_nodata(&core_cb, conn->create_thread_op);

	err = gps_socket_open_and_accept(conn);
	if (err) {
		ALOGE("%s: couldn't open and accept %s socket", __func__, conn->sock_name);
		return -1;
	}

	conn->thread_args.start = start;
	conn->thread_args.arg = arg;

	return pthread_create(&conn->thread, NULL, generic_posix_cb_routine, &conn->thread_args);
}

/* GPS XTRA callback */

static void
gps_xtra_download_request_cb(void)
{
	gps_msg_remote_cb_nodata(&gps_xtra_cb, GPS_XTRA_DOWNLOAD_REQUEST_CB);
}

static pthread_t
gps_xtra_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&gps_xtra_cb, name, start, arg);
}

static GpsXtraCallbacks gps_xtra_callbacks = {
	.download_request_cb = gps_xtra_download_request_cb,
	.create_thread_cb = gps_xtra_create_thread_cb,
};

/* GPS NI callbacks */

static pthread_t
gps_ni_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&gps_ni_cb, name, start, arg);
}

static void
gps_ni_notify_cb(GpsNiNotification *notification)
{
	if (!notification) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_ni_notify_cb_s msg = {
		.header = {.op = GPS_NI_NOTIFY_CB, },
		.notification = *notification,
	};
	gps_msg_remote_cb_by_type(&gps_ni_cb, &msg);
}

static GpsNiCallbacks gps_ni_callbacks = {
	.notify_cb = gps_ni_notify_cb,
	.create_thread_cb = gps_ni_create_thread_cb,
};

/* GP callbacks */

static pthread_t
gps_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&gps_cb, name, start, arg);
}

static void
gps_location_cb(GpsLocation *location)
{
	if (!location) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_location_cb_s msg = {
		.header = {.op = GPS_LOCATION_CB, },
		.location = *location,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static void
gps_status_cb(GpsStatus *status)
{
	if (!status) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_status_cb_s msg = {
		.header = {.op = GPS_STATUS_CB, },
		.status = *status,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static void
gps_sv_status_cb(GpsSvStatus *sv_status)
{
	if (!sv_status) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_sv_status_cb_s msg = {
		.header = {.op = GPS_SV_STATUS_CB, },
		.sv_status = *sv_status,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static void
gps_nmea_cb(GpsUtcTime timestamp, const char *nmea, int length)
{
	if (!nmea || !length) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_nmea_cb_s *msg = gps_msg_alloc_by_type(msg, GPS_NMEA_CB, length);
	if (msg) {
		msg->timestamp = timestamp;
		msg->length = length;
		memcpy(msg->nmea, nmea, length);
		gps_msg_remote_cb_and_free(&gps_cb, msg);
	}
}

static void
gps_set_capabilities_cb(uint32_t capabilities)
{
	ALOGD("%s: capabilities %x", __func__, capabilities);

	struct gps_set_capabilities_cb_s msg = {
		.header = {.op = GPS_SET_CAPABILITIES_CB, },
		.capabilities = capabilities,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static void
gps_acquire_wakelock_cb(void)
{
	gps_msg_remote_cb_nodata(&gps_cb, GPS_ACQUIRE_WAKELOCK_CB);
}

static void
gps_release_wakelock_cb(void)
{
	gps_msg_remote_cb_nodata(&gps_cb, GPS_RELEASE_WAKELOCK_CB);
}

static void
gps_request_utc_time_cb(void)
{
	gps_msg_remote_cb_nodata(&gps_cb, GPS_REQUEST_UTC_TIME_CB);
}

static void
gps_gnss_set_system_info_cb(const GnssSystemInfo* info)
{
	if (!info) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gnss_set_system_info_cb_s msg = {
		.header = {.op = GNSS_SET_SYSTEM_INFO_CB, },
		.info = *info,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static void
gps_gnss_sv_status_cb(GnssSvStatus* sv_info)
{
	if (!sv_info) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gnss_sv_status_cb_s msg = {
		.header = {.op = GNSS_SV_STATUS_CB, },
		.sv_info = *sv_info,
	};
	gps_msg_remote_cb_by_type(&gps_cb, &msg);
}

static GpsCallbacks gps_callbacks = {
	.size = sizeof(gps_callbacks),
	.location_cb = gps_location_cb,
	.status_cb = gps_status_cb,
	.sv_status_cb = gps_sv_status_cb,
	.nmea_cb = gps_nmea_cb,
	.set_capabilities_cb = gps_set_capabilities_cb,
	.acquire_wakelock_cb = gps_acquire_wakelock_cb,
	.release_wakelock_cb = gps_release_wakelock_cb,
	.create_thread_cb = gps_create_thread_cb,
	.request_utc_time_cb = gps_request_utc_time_cb,
#if PLATFORM_VERSION_MAJOR > 6
	.set_system_info_cb = gps_gnss_set_system_info_cb,
	.gnss_sv_status_cb = gps_gnss_sv_status_cb,
#endif
};

/* AGPS callbacks */

static pthread_t
agps_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&agps_cb, name, start, arg);
}

static void
gps_agps_status_cb(AGpsStatus *status)
{
	if (!status) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct agps_status_cb_s msg = {
		.header = {.op = AGPS_STATUS_CB, },
		.status = *status,
	};
	gps_msg_remote_cb_by_type(&agps_cb, &msg);
}

static AGpsCallbacks agps_callbacks = {
	.status_cb = gps_agps_status_cb,
	.create_thread_cb = agps_create_thread_cb,
};

/* AGPS RIL callbacks */

static pthread_t
agps_ril_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&agps_ril_cb, name, start, arg);
}

static void
agps_ril_request_setid_cb(uint32_t flags)
{
	struct agps_ril_request_setid_cb_s msg = {
		.header = {.op = AGPS_RIL_REQUEST_SETID_CB, },
		.flags = flags,
	};

	gps_msg_remote_cb_by_type(&agps_ril_cb, &msg);
}

static void
agps_ril_request_refloc_cb(uint32_t flags)
{
	struct agps_ril_request_refloc_cb_s msg = {
		.header = {.op = AGPS_RIL_REQUEST_REFLOC_CB, },
		.flags = flags,
	};

	gps_msg_remote_cb_by_type(&agps_ril_cb, &msg);
}

static AGpsRilCallbacks agps_ril_callbacks = {
	.create_thread_cb = agps_ril_create_thread_cb,
	.request_setid = agps_ril_request_setid_cb,
	.request_refloc = agps_ril_request_refloc_cb,
};

/* GPS Geofence callbacks */

static pthread_t
gps_geofence_create_thread_cb(const char *name, void (*start)(void *), void *arg)
{
	return generic_create_thread_cb(&gps_geofence_cb, name, start, arg);
}

static void
gps_geofence_transition_cb(int32_t geofence_id, GpsLocation *location,
			   int32_t transition, GpsUtcTime timestamp)
{
	struct gps_geofence_transition_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_TRANSITION_CB, },
		.geofence_id = geofence_id,
		.location = *location,
		.transition = transition,
		.timestamp = timestamp,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static void
gps_geofence_status_cb(int32_t status, GpsLocation *last_location)
{
	struct gps_geofence_status_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_STATUS_CB, },
		.status = status,
		.last_location = *last_location,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static void
gps_geofence_add_cb(int32_t geofence_id, int32_t status)
{
	struct gps_geofence_add_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_ADD_CB, },
		.geofence_id = geofence_id,
		.status = status,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static void
gps_geofence_remove_cb(int32_t geofence_id, int32_t status)
{
	struct gps_geofence_remove_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_REMOVE_CB, },
		.geofence_id = geofence_id,
		.status = status,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static void
gps_geofence_pause_cb(int32_t geofence_id, int32_t status)
{
	struct gps_geofence_pause_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_PAUSE_CB, },
		.geofence_id = geofence_id,
		.status = status,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static void
gps_geofence_resume_cb(int32_t geofence_id, int32_t status)
{
	struct gps_geofence_resume_cb_s msg = {
		.header = {.op = GPS_GEOFENCE_RESUME_CB, },
		.geofence_id = geofence_id,
		.status = status,
	};

	gps_msg_remote_cb_by_type(&gps_geofence_cb, &msg);
}

static GpsGeofenceCallbacks gps_geofence_callbacks = {
	.geofence_transition_callback = gps_geofence_transition_cb,
	.geofence_status_callback = gps_geofence_status_cb,
	.geofence_add_callback = gps_geofence_add_cb,
	.geofence_remove_callback = gps_geofence_remove_cb,
	.geofence_pause_callback = gps_geofence_pause_cb,
	.geofence_resume_callback = gps_geofence_resume_cb,
	.create_thread_cb = gps_geofence_create_thread_cb,
};

/* GPS Measurement callbacks (using core_cb) */

static void
gps_measurement_internal_cb(GpsData *data)
{
	if (!data) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_measurement_cb_s msg = {
		.header = {.op = GPS_MEASUREMENT_CB, },
		.data = *data,
	};
	gps_msg_remote_cb_by_type(&core_cb, &msg);
}

static void
gps_gnss_measurement_internal_cb(GnssData *data)
{
	if (!data) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gnss_measurement_cb_s msg = {
		.header = {.op = GNSS_MEASUREMENT_CB, },
		.data = *data,
	};
	gps_msg_remote_cb_by_type(&core_cb, &msg);
}

static GpsMeasurementCallbacks gps_measurement_callbacks = {
	.measurement_callback = gps_measurement_internal_cb,
#if PLATFORM_VERSION_MAJOR > 6
	.gnss_measurement_callback = gps_gnss_measurement_internal_cb,
#endif
};

/* GPS Navigation Message callbacks (using core_cb) */

static void
gps_navigation_message_internal_cb(GpsNavigationMessage *message)
{
	if (!message) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gps_navigation_message_cb_s *msg = gps_msg_alloc_by_type(msg, GPS_NAVIGATION_MESSAGE_CB, message->data_length);
	if (msg) {
		memcpy(&msg->message, message, sizeof(GpsNavigationMessage));
		memcpy(&msg->message_data, message->data, message->data_length);
		msg->message.data = NULL;
		gps_msg_remote_cb_and_free(&core_cb, msg);
	}
}

static void
gps_gnss_navigation_message_internal_cb(GnssNavigationMessage *message)
{
	if (!message) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return;
	}

	struct gnss_navigation_message_cb_s *msg = gps_msg_alloc_by_type(msg, GNSS_NAVIGATION_MESSAGE_CB, message->data_length);
	if (msg) {
		memcpy(&msg->message, message, sizeof(GnssNavigationMessage));
		memcpy(&msg->message_data, message->data, message->data_length);
		msg->message.data = NULL;
		gps_msg_remote_cb_and_free(&core_cb, msg);
	}
}

static GpsNavigationMessageCallbacks gps_navigation_message_callbacks = {
	.navigation_message_callback = gps_navigation_message_internal_cb,
#if PLATFORM_VERSION_MAJOR > 6
	.gnss_navigation_message_callback = gps_gnss_navigation_message_internal_cb,
#endif
};

/* GPS Proxy callback(s) (using core_cb) */

static void
gps_proxy_properties_cb(void)
{
	struct gps_proxy_properties_cb_s msg = {
		.header = {.op = GPS_PROXY_PROPERTIES_CB, },
		.props = {
			.gps_xtra_if_available = gps_xtra_interface ? 1 : 0,
			.gps_ni_if_available = gps_ni_interface ? 1 : 0,
			.agps_if_available = agps_interface ? 1 : 0,
			.agps_ril_if_available = agps_ril_interface ? 1 : 0,
			.gps_geofence_if_available = gps_geofence_interface ? 1 : 0,
			.supl_certificate_if_available = supl_certificate_interface ? 1 : 0,
			.gps_measurement_if_available = gps_measurement_interface ? 1 : 0,
			.gps_navigation_message_if_available = gps_navigation_message_interface ? 1 : 0,
			.gnss_configuration_if_available = gnss_configuration_interface ? 1 : 0,
			.gps_debug_if_available = gps_debug_interface ? 1 : 0,
			.available = 1,
		},
	};

	gps_msg_remote_cb_by_type(&core_cb, &msg);
}

/*
 * Interface handling
 */

static int
gps_server_request_handler(void *pmsg, struct gps_msg_reply_s *reply)
{
	if (!pmsg || !reply) {
		ALOGE("%s: Undefined or invalid argument(s)", __func__);
		return -1;
	}

	struct gps_msg_header_s *hdr = pmsg;
	int rc = 0;

	// Ovetake some values from the request message
	reply->header.op = hdr->op;
	reply->header.size = sizeof(*reply);
	reply->rc = 0;

	switch (hdr->op) {
	case AGPS_RIL_INIT:
		if (agps_ril_interface && agps_ril_interface->init)
			agps_ril_interface->init(&agps_ril_callbacks);
		else
			goto error_no_interface;
		break;

	case AGPS_RIL_SET_REF_LOCATION:
		if (agps_ril_interface && agps_ril_interface->set_ref_location) {
			struct agps_ril_set_ref_location_s *msg = pmsg;
			agps_ril_interface->set_ref_location(msg->agps_reflocation,
							     msg->sz_struct);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_RIL_SET_SET_ID:
		if (agps_ril_interface && agps_ril_interface->set_set_id) {
			struct agps_ril_set_set_id_s *msg = pmsg;
			agps_ril_interface->set_set_id(msg->type, msg->setid);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_RIL_UPDATE_NETWORK_STATE:
		if (agps_ril_interface && agps_ril_interface->update_network_state) {
			struct agps_ril_update_network_state_s *msg = pmsg;
			agps_ril_interface->update_network_state(msg->connected,
								 msg->type,
								 msg->roaming,
								 msg->extra_info);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_RIL_NI_MESSAGE:
		if (agps_ril_interface && agps_ril_interface->ni_message) {
			struct agps_ril_ni_message_s *msg = pmsg;
			agps_ril_interface->ni_message(msg->message, msg->length);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_RIL_UPDATE_NETWORK_AVAILABILITY:
		if (agps_ril_interface && agps_ril_interface->update_network_availability) {
			struct agps_ril_update_network_availablilty_s *msg = pmsg;
			agps_ril_interface->update_network_availability(msg->available,
									msg->apn);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_XTRA_INIT:
		if (gps_xtra_interface && gps_xtra_interface->init)
			rc = gps_xtra_interface->init(&gps_xtra_callbacks);
		else
			goto error_no_interface;
		break;

	case GPS_XTRA_INJECT_XTRA_DATA:
		if (gps_xtra_interface && gps_xtra_interface->inject_xtra_data) {
			struct gps_xtra_inject_xtra_data_s *msg = pmsg;
			rc = gps_xtra_interface->inject_xtra_data(msg->data, msg->length);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_INIT:
		if (agps_interface && agps_interface->init)
			agps_interface->init(&agps_callbacks);
		else
			goto error_no_interface;
		break;

	case AGPS_DATA_CONN_OPEN:
		if (agps_interface && agps_interface->data_conn_open) {
			struct agps_data_conn_open_s *msg = pmsg;
			rc = agps_interface->data_conn_open(msg->apn);
		} else {
			goto error_no_interface;
		}

	case AGPS_DATA_CONN_CLOSED:
		if (agps_interface && agps_interface->data_conn_closed)
			rc = agps_interface->data_conn_closed();
		else
			goto error_no_interface;
		break;

	case AGPS_DATA_CONN_FAILED:
		if (agps_interface && agps_interface->data_conn_failed)
			rc = agps_interface->data_conn_failed();
		else
			goto error_no_interface;
		break;

	case AGPS_SET_SERVER:
		if (agps_interface && agps_interface->set_server) {
			struct agps_set_server_s *msg = pmsg;
			rc = agps_interface->set_server(msg->type, msg->hostname, msg->port);
		} else {
			goto error_no_interface;
		}
		break;

	case AGPS_DATA_CONN_OPEN_WITH_APN_IP_TYPE:
		if (agps_interface && agps_interface->data_conn_open_with_apn_ip_type) {
			struct agps_data_conn_open_with_apn_ip_type_s *msg = pmsg;
			rc = agps_interface->data_conn_open_with_apn_ip_type(msg->apn, msg->apnIpType);
		} else {
			goto error_no_interface;
		}
		break;

	case SUPL_CERTIFICATE_INSTALL_CERTS:
		if (supl_certificate_interface && supl_certificate_interface->install_certificates) {
			struct supl_certificate_install_certificates_s *msg = pmsg;
			size_t raw_offset = 0;
			DerEncodedCertificate *certificates = malloc(msg->length*sizeof(DerEncodedCertificate));
			for (size_t i=0; i < msg->length; ++i) {
				if (raw_offset >= msg->raw_length) {
					ALOGE("%s: size violation -> overflow", __func__);
					rc = -1;
					free(certificates);
					goto out;
				}
				certificates[i].length = msg->raw_data[raw_offset];
				raw_offset += sizeof(size_t);
				certificates[i].data = msg->raw_data+raw_offset;
				raw_offset += certificates[i].length;
			}
			rc = supl_certificate_interface->install_certificates(certificates, msg->length);
			free(certificates);
		}
		else
			goto error_no_interface;
		break;

	case SUPL_CERTIFICATE_REVOKE_CERTS:
		if (supl_certificate_interface && supl_certificate_interface->revoke_certificates) {
			struct supl_certificate_revoke_certificates_s *msg = pmsg;
			rc = supl_certificate_interface->revoke_certificates(msg->fingerprints, msg->length);
		}
		else
			goto error_no_interface;
		break;

	case GPS_NI_INIT:
		if (gps_ni_interface && gps_ni_interface->init)
			gps_ni_interface->init(&gps_ni_callbacks);
		else
			goto error_no_interface;
		break;

	case GPS_NI_RESPOND:
		if (gps_ni_interface && gps_ni_interface->respond) {
			struct gps_ni_respond_s *msg = pmsg;
			gps_ni_interface->respond(msg->notif_id, msg->user_response);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_INIT:
		if (gps_interface && gps_interface->init) {
			rc = gps_interface->init(&gps_callbacks);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_START:
		if (gps_interface && gps_interface->start)
			rc = gps_interface->start();
		else
			goto error_no_interface;
		break;

	case GPS_STOP:
		if (gps_interface && gps_interface->stop)
			rc = gps_interface->stop();
		else
			goto error_no_interface;
		break;

	case GPS_CLEANUP:
		if (gps_interface && gps_interface->cleanup)
			gps_interface->cleanup();
		else
			goto error_no_interface;
		break;

	case GPS_INJECT_TIME:
		if (gps_interface && gps_interface->inject_time) {
			struct gps_inject_time_s *msg = pmsg;
			rc = gps_interface->inject_time(msg->time,
							msg->time_reference,
							msg->uncertainty);
			/* workaround some initialization issues */
			if (rc < 0) {
				ALOGW("%s: GPS_INJECT_TIME returned error, ignoring!", __func__);
				rc = 0;
			}
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_INJECT_LOCATION:
		if (gps_interface && gps_interface->inject_location) {
			struct gps_inject_location_s *msg = pmsg;
			rc = gps_interface->inject_location(msg->latitude,
							    msg->longitude,
							    msg->accuracy);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_DELETE_AIDING_DATA:
		if (gps_interface && gps_interface->delete_aiding_data) {
			struct gps_delete_aiding_data_s *msg = pmsg;
			gps_interface->delete_aiding_data(msg->flags);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_SET_POSITION_MODE:
		if (gps_interface && gps_interface->set_position_mode) {
			struct gps_set_position_mode_s *msg = pmsg;
			rc = gps_interface->set_position_mode(msg->mode,
							      msg->recurrence,
							      msg->min_interval,
							      msg->preferred_accuracy,
							      msg->preferred_time);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_GEOFENCE_INIT:
		if (gps_geofence_interface && gps_geofence_interface->init)
			gps_geofence_interface->init(&gps_geofence_callbacks);
		else
			goto error_no_interface;
		break;

	case GPS_GEOFENCE_ADD_GEOFENCE_AREA:
		if (gps_geofence_interface && gps_geofence_interface->add_geofence_area) {
			struct gps_geofence_add_geofence_area_s *msg = pmsg;
			gps_geofence_interface->add_geofence_area(
				msg->geofence_id, msg->latitude, msg->longitude,
				msg->radius_meters, msg->last_transition,
				msg->monitor_transitions, msg->notification_responsiveness_ms,
				msg->unknown_timer_ms);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_GEOFENCE_PAUSE_GEOFENCE:
		if (gps_geofence_interface && gps_geofence_interface->pause_geofence) {
			struct gps_geofence_pause_geofence_s *msg = pmsg;
			gps_geofence_interface->pause_geofence(msg->geofence_id);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_GEOFENCE_RESUME_GEOFENCE:
		if (gps_geofence_interface && gps_geofence_interface->resume_geofence) {
			struct gps_geofence_resume_geofence_s *msg = pmsg;
			gps_geofence_interface->resume_geofence(msg->geofence_id,
								msg->monitor_transitions);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_GEOFENCE_REMOVE_GEOFENCE_AREA:
		if (gps_geofence_interface && gps_geofence_interface->remove_geofence_area) {
			struct gps_geofence_remove_geofence_area_s *msg = pmsg;
			gps_geofence_interface->remove_geofence_area(msg->geofence_id);
		} else {
			goto error_no_interface;
		}
		break;

	case GPS_MEASUREMENT_INIT:
		if (gps_measurement_interface && gps_measurement_interface->init)
			rc = gps_measurement_interface->init(&gps_measurement_callbacks);
		else
			goto error_no_interface;
		break;

	case GPS_MEASUREMENT_CLOSE:
		if (gps_measurement_interface && gps_measurement_interface->close)
			gps_measurement_interface->close();
		else
			goto error_no_interface;
		break;

	case GPS_NAVIGATION_MESSAGE_INIT:
		if (gps_navigation_message_interface && gps_navigation_message_interface->init)
			rc = gps_navigation_message_interface->init(&gps_navigation_message_callbacks);
		else
			goto error_no_interface;
		break;

	case GPS_NAVIGATION_MESSAGE_CLOSE:
		if (gps_navigation_message_interface && gps_navigation_message_interface->close)
			gps_navigation_message_interface->close();
		else
			goto error_no_interface;
		break;

	case GNSS_CONFIGURATION_UPDATE:
		if (gnss_configuration_interface && gnss_configuration_interface->configuration_update) {
			struct gnss_configuration_update_s *msg = pmsg;
			gnss_configuration_interface->configuration_update(msg->config_data, msg->length);
		}
		else
			goto error_no_interface;
		break;


	default:
		ALOGW("%s: request %s not handled", __func__, gps_msg_op_name(hdr->op));
		break;
	}


	goto out;

error_no_interface:
	rc = -1;
	ALOGW("%s: Callbacks or function for callback %s is NULL",
	      __func__, gps_msg_op_name(hdr->op));

out:
	reply->rc = rc;
	ALOGV("request %s handled (rc=%d)", gps_msg_op_name(hdr->op), rc);
	return rc;
}

/*
 * Module interface
 */

static int
gps_server_load_module(void)
{
	hw_module_t *module;
	hw_device_t *device;
	int err;

	/* Load the proprietary hardware sensor libraries */
	ALOGI("loading '%s' hw module\n", GPS_SERVER_HARDWARE_MODULE_ID);
	err = hw_get_module(GPS_SERVER_HARDWARE_MODULE_ID, (hw_module_t const**)&module);
	if (err) {
		ALOGE("couldn't load GPS hardware module: %s", strerror(-err));
		return -1;
	}

	ALOGI("Hardware module '%s' loded", GPS_SERVER_HARDWARE_MODULE_ID);
	ALOGI("	 Module API version: %d", module->module_api_version);
	ALOGI("	 HAL API version: %d", module->hal_api_version);
	ALOGI("	 ID: %s", module->id);
	ALOGI("	 Name: %s", module->name);
	ALOGI("	 Author: %s", module->author);

	err = module->methods->open(module, GPS_SERVER_HARDWARE_MODULE_ID, &device);
	if (err) {
		ALOGE("couldn't open GPS hardware module: %s", strerror(-err));
		return -1;
	}

	struct gps_device_t *gps_device = (struct gps_device_t *)device;
	gps_interface = gps_device->get_gps_interface(gps_device);

	if (!gps_interface) {
		ALOGE("couldn't get GPS interface");
		return -1;
	}

	gps_xtra_interface =
		(const GpsXtraInterface *)gps_interface->get_extension(GPS_XTRA_INTERFACE);
	agps_interface =
		(const AGpsInterface *)gps_interface->get_extension(AGPS_INTERFACE);
	supl_certificate_interface = NULL ;
		//(const SuplCertificateInterface *)gps_interface->get_extension(SUPL_CERTIFICATE_INTERFACE);
	gps_ni_interface =
		(const GpsNiInterface *)gps_interface->get_extension(GPS_NI_INTERFACE);
	agps_ril_interface =
		(const AGpsRilInterface *)gps_interface->get_extension(AGPS_RIL_INTERFACE);
	gps_geofence_interface = NULL;
		//(const GpsGeofencingInterface *)gps_interface->get_extension(GPS_GEOFENCING_INTERFACE);
	gps_measurement_interface =
		(const GpsMeasurementInterface *)gps_interface->get_extension(GPS_MEASUREMENT_INTERFACE);
	gps_navigation_message_interface =
		(const GpsNavigationMessageInterface *)gps_interface->get_extension(GPS_NAVIGATION_MESSAGE_INTERFACE);
	gnss_configuration_interface =
		(const GnssConfigurationInterface *)gps_interface->get_extension(GNSS_CONFIGURATION_INTERFACE);
	gps_debug_interface =
		(const GpsDebugInterface *)gps_interface->get_extension(GPS_DEBUG_INTERFACE);

	ALOGD("gps_interface: %p", (void *) gps_interface);
	ALOGD("gps_xtra_interface: %p", (void *) gps_xtra_interface);
	ALOGD("agps_interface: %p", (void *) agps_interface);
	ALOGD("supl_certificate_interface: %p", (void *) supl_certificate_interface);
	ALOGD("gps_ni_interface: %p", (void *) gps_ni_interface);
	ALOGD("agps_ril_interface: %p", (void *) agps_ril_interface);
	ALOGD("gps_geofence_interface: %p", (void *) gps_geofence_interface);
	ALOGD("gps_measurement_interface: %p", (void *) gps_measurement_interface);
	ALOGD("gps_navigation_message_interface: %p", (void *) gps_navigation_message_interface);
	ALOGD("gnss_configuration_interface: %p", (void *) gnss_configuration_interface);
	ALOGD("gps_debug_interface: %p", (void *) gps_debug_interface);

	return 0;
}

static void
gps_server_request_loop(const struct gps_interface_conn_s *conn)
{
	struct gps_msg_header_s *request_hdr;
	struct gps_msg_reply_s reply_msg;
	/* We need a rather larger buffer for xtra data injection */
	const size_t request_msg_size = 128 * 1024;

	void *request_msg = malloc(request_msg_size);
	if (!request_msg) {
		ALOGE("couldn't allocate request message: %s", strerror(ENOMEM));
		return;
	}
	request_hdr = request_msg;

	while (1) {
		if (gps_msg_recv(conn->sock, request_msg, request_msg_size) < 0) {
			ALOGE("gps_msg_recv() failed: %s", strerror(errno));
			goto error;
		}
		ALOGV("request %s received from %s socket",
		      gps_msg_op_name(request_hdr->op), conn->sock_name);

		if (gps_server_request_handler(request_msg, &reply_msg)) {
			ALOGE("couldn't handle request %s", gps_msg_op_name(request_hdr->op));
			goto error;
		}

		if (gps_msg_send(conn->sock, &reply_msg, sizeof(reply_msg)) < 0) {
			ALOGE("gps_msg_send() failed: %s", strerror(errno));
			goto error;
		}
		ALOGV("reply %s sent to %s socket (rc=%d)",
		      gps_msg_op_name(reply_msg.header.op), conn->sock_name, reply_msg.rc);
	}

error:
	free(request_msg);
}

int
main(int argc __attribute__((__unused__)), char* argv[] __attribute__((__unused__)))
{
	int err;

	err = gps_server_load_module();
	if (err)
		return err;

	/* Open request and callback socket first */
	err = gps_socket_open(&core_request);
	if (err)
		return err;

	err = gps_socket_open(&core_cb);
	if (err)
		return err;

	/* Then accept connections */
	err = gps_socket_accept(&core_request);
	if (err)
		return err;

	err = gps_socket_accept(&core_cb);
	if (err)
		return err;

	/* Use the socket for other interfaces as default */
	gps_cb.sock =
	gps_xtra_cb.sock =
	gps_ni_cb.sock =
	agps_cb.sock =
	agps_ril_cb.sock =
	gps_geofence_cb.sock =
		core_cb.sock;

	/* Communicate properties to client */
	gps_proxy_properties_cb();

	/* main loop waiting for requests from the client */
	gps_server_request_loop(&core_request);

	ALOGI("exiting");

	return err;
}
