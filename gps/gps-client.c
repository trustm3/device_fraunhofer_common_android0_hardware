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

#define LOG_TAG "GpsProxyClient"
/* Uncomment to get the ALOGV messages */
//#define LOG_NDEBUG 0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <utils/Log.h>

#include <hardware/gps.h>

#include "gps-common.h"

static GpsCallbacks *gps_callbacks;
static GpsXtraCallbacks *gps_xtra_callbacks;
static GpsNiCallbacks *gps_ni_callbacks;
static AGpsCallbacks *agps_callbacks;
static AGpsRilCallbacks *agps_ril_callbacks;
static GpsGeofenceCallbacks *gps_geofence_callbacks;
static GpsMeasurementCallbacks *gps_measurement_callbacks;
static GpsNavigationMessageCallbacks *gps_navigation_message_callbacks;

static struct gps_proxy_properties_s gps_proxy_props;

struct gps_client_cb_s {
	const char *sock_name;
	void (*handler)(void *pmsg);
	pthread_t thread;
	int sock;
};

static struct gps_client_cb_s gps_cb;

static int core_request_sock = -1;

/*
 * Helper functions
 */

static int
gps_socket_open_and_connect(const char *name)
{
	struct sockaddr_un server;
	int sock, err, retries = 10;

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		ALOGE("couldn't open %s socket: %s", name, strerror(errno));
		goto error;
	}

	int buf_size = SNDRCV_BUF_SIZE;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set receive buffer size on %s socket: %s",
			__func__, name, strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
		ALOGE("%s: couldn't set send buffer size on %s socket: %s",
			__func__, name, strerror(errno));
		return -1;
	}

	memset(&server, 0, sizeof(server));
	server.sun_family = AF_UNIX;
	snprintf(server.sun_path, UNIX_PATH_MAX, "%s/%s.sock", GPS_PROXY_SOCKET_PATH, name);

	ALOGV("UNIX socket %d connecting to %s", sock, server.sun_path);

reconnect:
	err = connect(sock, (struct sockaddr *)&server, sizeof(server));
	if (err) {
		if (retries-- && errno == ENOENT) {
			ALOGI("reconnecting to %s\n", server.sun_path);
			usleep(100000);
			goto reconnect;
		}
		ALOGE("couldn't connect to %s: %s", server.sun_path, strerror(errno));
		close(sock);
		sock = err;
		goto error;
	}
	ALOGI("UNIX socket %d connected with %s", sock, server.sun_path);

error:
	return sock;
}

static int
gps_msg_remote_request(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;
	struct gps_msg_reply_s reply;
	int rc;

	rc = gps_msg_send(core_request_sock, pmsg, hdr->size);
	if (rc < 0)
		return rc;
	ALOGV("request %s sent to %s socket", gps_msg_op_name(hdr->op), CORE_REQUEST_SOCK_NAME);

	rc = gps_msg_recv(core_request_sock, &reply, sizeof(reply));
	if (rc < 0)
		return rc;
	ALOGV("reply %s received from %s socket (rc=%d)",
	      gps_msg_op_name(reply.header.op), CORE_REQUEST_SOCK_NAME, reply.rc);

	return reply.rc;
}

static int
gps_msg_remote_request_by_size(void *pmsg, size_t size)
{
	struct gps_msg_header_s *hdr = pmsg;

	hdr->size = size;
	return gps_msg_remote_request(pmsg);
}

static int
gps_msg_remote_request_nodata(enum gps_msg_op op)
{
	struct gps_msg_header_s hdr = {
		.op = op,
		.size = sizeof(hdr),
	};

	return gps_msg_remote_request(&hdr);
}

static int
gps_msg_remote_request_and_free(void *pmsg)
{
	int rc = gps_msg_remote_request(pmsg);

	gps_msg_free(pmsg);
	return rc;
}

#define gps_msg_remote_request_by_type(p) gps_msg_remote_request_by_size(p, sizeof(*(p)))

/*
 * Interface functions
 */

/* GPS XTRA interface */

static int
gps_xtra_init(GpsXtraCallbacks *callbacks)
{
	int rc = -1;

	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}
	gps_xtra_callbacks = callbacks;
	rc = gps_msg_remote_request_nodata(GPS_XTRA_INIT);

	return rc;
}

static int
gps_xtra_inject_xtra_data(char *data, int length)
{
	int rc = -1;

	if (!data || !length) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	struct gps_xtra_inject_xtra_data_s *msg =
		gps_msg_alloc_by_type(msg, GPS_XTRA_INJECT_XTRA_DATA, length);
	if (msg) {
		msg->length = length;
		memcpy(msg->data, data, length);
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static GpsXtraInterface gps_xtra_interface = {
	.size = sizeof(GpsXtraInterface),
	.init = gps_xtra_init,
	.inject_xtra_data = gps_xtra_inject_xtra_data,
};

/* AGPS interface */

static void
agps_init(AGpsCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	agps_callbacks = callbacks;
	gps_msg_remote_request_nodata(AGPS_INIT);
}

static int
agps_data_conn_open(const char *apn)
{
	int rc = -1;

	if (!apn) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	int length = strlen(apn) + 1;
	struct agps_data_conn_open_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_DATA_CONN_OPEN, length);
	if (msg) {
		memcpy(msg->apn, apn, length);
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static int
agps_data_conn_closed(void)
{
	return gps_msg_remote_request_nodata(AGPS_DATA_CONN_CLOSED);
}

static int
agps_data_conn_failed(void)
{
	return gps_msg_remote_request_nodata(AGPS_DATA_CONN_FAILED);
}

static int
agps_set_server(AGpsType type, const char *hostname, int port)
{
	int rc = -1;

	if (!hostname) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	int length = strlen(hostname) + 1;
	struct agps_set_server_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_SET_SERVER, length);
	if (msg) {
		msg->type = type;
		msg->port = port;
		memcpy(msg->hostname, hostname, length);
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static int
agps_data_conn_open_with_apn_ip_type(const char *apn, ApnIpType apnIpType)
{
	int rc = -1;

	if (!apn) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	int length = strlen(apn) + 1;
	struct agps_data_conn_open_with_apn_ip_type_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_DATA_CONN_OPEN_WITH_APN_IP_TYPE, length);
	if (msg) {
		msg->apnIpType = apnIpType;
		memcpy(msg->apn, apn, length);
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static AGpsInterface agps_interface = {
	.size = sizeof(AGpsInterface),
	.init = agps_init,
	.data_conn_open = agps_data_conn_open,
	.data_conn_closed = agps_data_conn_closed,
	.data_conn_failed = agps_data_conn_failed,
	.set_server = agps_set_server,
	.data_conn_open_with_apn_ip_type = agps_data_conn_open_with_apn_ip_type,
};

/* SUPL Certificate Interface */

static int
supl_certificate_install_certificates(const DerEncodedCertificate* certificates, size_t length)
{
	int rc = -1;

	if (!certificates) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	int raw_length = 0;
	for (size_t i=0; i<length; ++i)
		raw_length += certificates[i].length;

	struct supl_certificate_install_certificates_s *msg =
		gps_msg_alloc_by_type(msg, SUPL_CERTIFICATE_INSTALL_CERTS, length*sizeof(size_t)+raw_length);
	if (msg) {
		msg->length = length;
		raw_length = 0;
		for (size_t i=0; i<length; ++i) {
			memcpy(msg->raw_data+raw_length, &certificates[i].length, sizeof(size_t));
			raw_length += sizeof(size_t);
			memcpy(msg->raw_data+raw_length, certificates[i].data, certificates[i].length);
			raw_length += certificates[i].length;
		}
		msg->raw_length = raw_length;
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static int
supl_certificate_revoke_certificates(const Sha1CertificateFingerprint* fingerprints, size_t length)
{
	int rc = -1;

	if (!fingerprints) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return rc;
	}

	struct supl_certificate_revoke_certificates_s *msg =
		gps_msg_alloc_by_type(msg, SUPL_CERTIFICATE_REVOKE_CERTS, length*sizeof(Sha1CertificateFingerprint));
	if (msg) {
		msg->length= length;
		memcpy(msg->fingerprints, fingerprints, length*sizeof(Sha1CertificateFingerprint));
		rc = gps_msg_remote_request_and_free(msg);
	}

	return rc;
}

static const SuplCertificateInterface supl_certificate_interface = {
	.size = sizeof(SuplCertificateInterface),
	.install_certificates = supl_certificate_install_certificates,
	.revoke_certificates = supl_certificate_revoke_certificates,
};

/* GPS NI Interface */

static void
gps_ni_init(GpsNiCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	gps_ni_callbacks = callbacks;
	gps_msg_remote_request_nodata(GPS_NI_INIT);
}

static void
gps_ni_respond(int notif_id, GpsUserResponseType user_response)
{
	struct gps_ni_respond_s msg = {
		.header = {.op = GPS_NI_RESPOND, },
		.notif_id = notif_id,
		.user_response = user_response,
	};

	gps_msg_remote_request_by_type(&msg);
}

static const GpsNiInterface gps_ni_interface = {
	.size = sizeof(GpsNiInterface),
	.init = gps_ni_init,
	.respond = gps_ni_respond,
};

/* AGPS RIL Interface */

static void
agps_ril_init(AGpsRilCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	agps_ril_callbacks = callbacks;
	gps_msg_remote_request_nodata(AGPS_RIL_INIT);
}

static void
agps_ril_set_ref_location(const AGpsRefLocation *agps_reflocation, size_t sz_struct)
{
	if (!agps_reflocation || !sz_struct) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	struct agps_ril_set_ref_location_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_RIL_SET_REF_LOCATION, sz_struct);
	if (msg) {
		msg->sz_struct = sz_struct;
		memcpy(msg->agps_reflocation, agps_reflocation, sz_struct);
		gps_msg_remote_request_and_free(msg);
	}
}

static void
agps_ril_set_set_id(AGpsSetIDType type, const char *setid)
{
	if (!setid) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	int length = strlen(setid) + 1;
	struct agps_ril_set_set_id_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_RIL_SET_SET_ID, length);
	if (msg) {
		msg->type = type;
		memcpy(msg->setid, setid, length);
		gps_msg_remote_request_and_free(msg);
	}
}

static void
agps_ril_ni_message(uint8_t *message, size_t length)
{
	if (!message || !length) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	struct agps_ril_ni_message_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_RIL_NI_MESSAGE, length);
	if (msg) {
		msg->length = length;
		memcpy(msg->message, message, length);
		gps_msg_remote_request_and_free(msg);
	}
}

static void
agps_ril_update_network_state(int connected, int type, int roaming, const char *extra_info)
{
	if (!extra_info) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	int length = strlen(extra_info) + 1;
	struct	agps_ril_update_network_state_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_RIL_UPDATE_NETWORK_STATE, length);

	if (msg) {
		msg->connected = connected;
		msg->type = type;
		msg->roaming = roaming;
		memcpy(msg->extra_info, extra_info, length);
		gps_msg_remote_request_and_free(msg);
	}
}

static void
agps_ril_update_network_availability(int available, const char *apn)
{
	if (!apn) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	int length = strlen(apn) + 1;
	struct agps_ril_update_network_availablilty_s *msg =
		gps_msg_alloc_by_type(msg, AGPS_RIL_UPDATE_NETWORK_AVAILABILITY, length);
	if (msg) {
		msg->available = available;
		memcpy(msg->apn, apn, length);
		gps_msg_remote_request_and_free(msg);
	};
}

static AGpsRilInterface agps_ril_interface = {
	.size = sizeof(AGpsRilInterface),
	.init = agps_ril_init,
	.set_ref_location = agps_ril_set_ref_location,
	.set_set_id = agps_ril_set_set_id,
	.ni_message = agps_ril_ni_message,
	.update_network_state = agps_ril_update_network_state,
	.update_network_availability = agps_ril_update_network_availability,
};

/* GPS Geofence Interface */

static void
gps_geofence_init(GpsGeofenceCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	gps_geofence_callbacks = callbacks;
	gps_msg_remote_request_nodata(GPS_GEOFENCE_INIT);
}

void
gps_geofence_add_geofence_area(int32_t geofence_id, double latitude,
			       double longitude, double radius_meters,
			       int last_transition, int monitor_transitions,
			       int notification_responsiveness_ms,
			       int unknown_timer_ms)
{
	struct gps_geofence_add_geofence_area_s msg = {
		.header = {.op = GPS_GEOFENCE_ADD_GEOFENCE_AREA, },
		.geofence_id = geofence_id,
		.latitude = latitude,
		.longitude = longitude,
		.radius_meters = radius_meters,
		.last_transition = last_transition,
		.monitor_transitions = monitor_transitions,
		.notification_responsiveness_ms = notification_responsiveness_ms,
		.unknown_timer_ms = unknown_timer_ms,
	};

	gps_msg_remote_request_by_type(&msg);
}

void
gps_geofence_pause_geofence(int32_t geofence_id)
{
	struct gps_geofence_pause_geofence_s msg = {
		.header = {.op = GPS_GEOFENCE_PAUSE_GEOFENCE, },
		.geofence_id = geofence_id,
	};

	gps_msg_remote_request_by_type(&msg);
}

void
gps_geofence_resume_geofence(int32_t geofence_id, int monitor_transitions)
{
	struct gps_geofence_resume_geofence_s msg = {
		.header = {.op = GPS_GEOFENCE_RESUME_GEOFENCE, },
		.geofence_id = geofence_id,
		.monitor_transitions = monitor_transitions,
	};

	gps_msg_remote_request_by_type(&msg);
}

void
gps_geofence_remove_geofence_area(int32_t geofence_id)
{
	struct gps_geofence_remove_geofence_area_s msg = {
		.header = {.op = GPS_GEOFENCE_REMOVE_GEOFENCE_AREA, },
		.geofence_id = geofence_id,
	};

	gps_msg_remote_request_by_type(&msg);
}

static GpsGeofencingInterface gps_geofence_interface = {
	.size = sizeof(GpsGeofencingInterface),
	.init = gps_geofence_init,
	.add_geofence_area = gps_geofence_add_geofence_area,
	.pause_geofence = gps_geofence_pause_geofence,
	.resume_geofence = gps_geofence_resume_geofence,
	.remove_geofence_area = gps_geofence_remove_geofence_area,
};

/* GPS Measurment Interface */

static int
gps_measurement_init(GpsMeasurementCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return -1;
	}

	gps_measurement_callbacks = callbacks;
	return gps_msg_remote_request_nodata(GPS_MEASUREMENT_INIT);
}

static void
gps_measurement_close(void)
{
	gps_msg_remote_request_nodata(GPS_MEASUREMENT_CLOSE);
}

static const GpsMeasurementInterface gps_measurement_interface = {
	.size = sizeof(GpsMeasurementInterface),
	.init = gps_measurement_init,
	.close = gps_measurement_close,
};

/* GPS Navigation Message Interface */

static int
gps_navigation_message_init(GpsNavigationMessageCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return -1;
	}

	gps_navigation_message_callbacks = callbacks;
	return gps_msg_remote_request_nodata(GPS_NAVIGATION_MESSAGE_INIT);
}

static void
gps_navigation_message_close(void)
{
	gps_msg_remote_request_nodata(GPS_NAVIGATION_MESSAGE_CLOSE);
}

static const GpsNavigationMessageInterface gps_navigation_message_interface = {
	.size = sizeof(GpsNavigationMessageInterface),
	.init = gps_navigation_message_init,
	.close = gps_navigation_message_close,
};

/* GNSS Configuration Interface */

static void
gnss_configuration_update(const char *config_data, int32_t length)
{
	if (!config_data) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return;
	}

	int len = strlen(config_data) + 1;
	struct gnss_configuration_update_s *msg =
		gps_msg_alloc_by_type(msg, GNSS_CONFIGURATION_UPDATE, len);
	if (msg) {
		msg->length = length;
		memcpy(msg->config_data, config_data, len);
		gps_msg_remote_request_and_free(msg);
	}
}

static const GnssConfigurationInterface gnss_configuration_interface = {
	.size = sizeof(GnssConfigurationInterface),
	.configuration_update = gnss_configuration_update,
};


/* GPS Interface */

static int
gps_init(GpsCallbacks *callbacks)
{
	if (!callbacks) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return -1;
	}

	gps_callbacks = callbacks;

	return gps_msg_remote_request_nodata(GPS_INIT);
}

static int
gps_start(void)
{
	return gps_msg_remote_request_nodata(GPS_START);
}

static int
gps_stop(void)
{
	return gps_msg_remote_request_nodata(GPS_STOP);
}

static void
gps_cleanup(void)
{
	gps_msg_remote_request_nodata(GPS_CLEANUP);
}

static int
gps_inject_time(GpsUtcTime time, int64_t time_reference, int uncertainty)
{
	struct gps_inject_time_s msg = {
		.header = {.op = GPS_INJECT_TIME,},
		.time = time,
		.time_reference = time_reference,
		.uncertainty = uncertainty,
	};

	return gps_msg_remote_request_by_type(&msg);
}

static int
gps_inject_location(double latitude, double longitude, float accuracy)
{
	struct gps_inject_location_s msg = {
		.header = {.op = GPS_INJECT_LOCATION, },
		.latitude = latitude,
		.longitude = longitude,
		.accuracy = accuracy,
	};

	return gps_msg_remote_request_by_type(&msg);
}

static void
gps_delete_aiding_data(GpsAidingData flags)
{
	struct gps_delete_aiding_data_s msg = {
		.header = {.op = GPS_DELETE_AIDING_DATA, },
		.flags = flags,
	};

	gps_msg_remote_request_by_type(&msg);
}

static int
gps_set_position_mode(GpsPositionMode mode, GpsPositionRecurrence recurrence,
		      uint32_t min_interval, uint32_t preferred_accuracy,
		      uint32_t preferred_time)
{
	struct gps_set_position_mode_s msg = {
		.header = {.op = GPS_SET_POSITION_MODE, },
		.mode = mode,
		.recurrence = recurrence,
		.min_interval = min_interval,
		.preferred_accuracy = preferred_accuracy,
		.preferred_time = preferred_time,
	};

	return gps_msg_remote_request_by_type(&msg);
}

static const void *
gps_get_extension(const char *name)
{
	if (!name) {
		ALOGE("%s: undefined or invalid argument(s)", __func__);
		return NULL;
	}

	if (!gps_proxy_props.available) {
		ALOGE("%s: properties of the GPS proxy not yet available", __func__);
		return NULL;
	}

	if (gps_proxy_props.gps_xtra_if_available && !strcmp(name, GPS_XTRA_INTERFACE))
		return &gps_xtra_interface;
	else if (gps_proxy_props.agps_if_available && !strcmp(name, AGPS_INTERFACE))
		return &agps_interface;
	else if (gps_proxy_props.supl_certificate_if_available && !strcmp(name, SUPL_CERTIFICATE_INTERFACE))
		return &supl_certificate_interface;
	else if (gps_proxy_props.gps_ni_if_available && !strcmp(name, GPS_NI_INTERFACE))
		return &gps_ni_interface;
	else if (gps_proxy_props.agps_ril_if_available && !strcmp(name, AGPS_RIL_INTERFACE))
		return &agps_ril_interface;
	else if (gps_proxy_props.gps_geofence_if_available && !strcmp(name, GPS_GEOFENCING_INTERFACE))
		return &gps_geofence_interface;
	else if (gps_proxy_props.gps_measurement_if_available && !strcmp(name, GPS_MEASUREMENT_INTERFACE))
		return &gps_measurement_interface;
	else if (gps_proxy_props.gps_navigation_message_if_available && !strcmp(name, GPS_NAVIGATION_MESSAGE_INTERFACE))
		return &gps_navigation_message_interface;
	else if (gps_proxy_props.gnss_configuration_if_available && !strcmp(name, GNSS_CONFIGURATION_INTERFACE))
		return &gnss_configuration_interface;

	return NULL;
}

static GpsInterface gps_hardware_interface = {
	.size = sizeof(GpsInterface),
	.init = gps_init,
	.start = gps_start,
	.stop = gps_stop,
	.cleanup = gps_cleanup,
	.inject_time = gps_inject_time,
	.inject_location = gps_inject_location,
	.delete_aiding_data = gps_delete_aiding_data,
	.set_position_mode = gps_set_position_mode,
	.get_extension = gps_get_extension,
};

/*
 * Callback handling
 */

static void *
generic_cb_routine(void *data)
{
	struct gps_client_cb_s *cb = (struct gps_client_cb_s *)data;
	struct gps_msg_header_s *cb_hdr;
	const size_t cb_msg_size = 4 * 1024;
	int ret;

	void *cb_msg = malloc(cb_msg_size);
	if (!cb_msg) {
		ALOGE("couldn't allocate callback message: %s", strerror(ENOMEM));
		return NULL;
	}
	cb_hdr = cb_msg;

open_and_connect:
	if (cb->sock < 0) {
		cb->sock = gps_socket_open_and_connect(cb->sock_name);
		if (cb->sock < 0)
			goto error;
	}

	while (1) {
		ret = gps_msg_recv(cb->sock, cb_msg, cb_msg_size);
		if (ret < 0) {
			close(cb->sock);
			cb->sock = -1;
			goto open_and_connect;
		}
		ALOGV("callback %s received from %s socket",
		      gps_msg_op_name(cb_hdr->op), CORE_CALLBACK_SOCK_NAME);

		cb->handler(cb_msg);
	}

error:
	if (cb->sock >= 0)
		close(cb->sock);
	free(cb_msg);

	return NULL;
}

static void
generic_cb_jroutine(void *data)
{
	// discard return value of type (void *)
	(void) generic_cb_routine(data);
}

/* GPS callbacks */

static void
gps_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!gps_callbacks) {
		ALOGE("%s: gps_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case GPS_LOCATION_CB:
		if (gps_callbacks->location_cb) {
			struct gps_location_cb_s *msg = pmsg;
			gps_callbacks->location_cb(&msg->location);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_STATUS_CB:
		if (gps_callbacks->status_cb) {
			struct gps_status_cb_s *msg = pmsg;
			gps_callbacks->status_cb(&msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_SV_STATUS_CB:
		if (gps_callbacks->sv_status_cb) {
			struct gps_sv_status_cb_s *msg = pmsg;
			gps_callbacks->sv_status_cb(&msg->sv_status);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_NMEA_CB:
		if (gps_callbacks->nmea_cb) {
			struct gps_nmea_cb_s *msg = pmsg;
			gps_callbacks->nmea_cb(msg->timestamp, msg->nmea, msg->length);

		} else {
			goto error_no_cb;
		}
		break;

	case GPS_SET_CAPABILITIES_CB:
		if (gps_callbacks->set_capabilities_cb) {
			struct gps_set_capabilities_cb_s *msg = pmsg;
			gps_callbacks->set_capabilities_cb(msg->capabilities);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_ACQUIRE_WAKELOCK_CB:
		if (gps_callbacks->acquire_wakelock_cb)
			gps_callbacks->acquire_wakelock_cb();
		else
			goto error_no_cb;
		break;

	case GPS_RELEASE_WAKELOCK_CB:
		if (gps_callbacks->release_wakelock_cb)
			gps_callbacks->release_wakelock_cb();
		else
			goto error_no_cb;
		break;

	case GPS_REQUEST_UTC_TIME_CB:
		if (gps_callbacks->request_utc_time_cb)
			gps_callbacks->request_utc_time_cb();
		else
			goto error_no_cb;
		break;

#if PLATFORM_VERSION_MAJOR > 6
	case GNSS_SET_SYSTEM_INFO_CB:
		if (gps_callbacks->set_system_info_cb) {
			struct gnss_set_system_info_cb_s *msg = pmsg;
			gps_callbacks->set_system_info_cb(&msg->info);
		} else {
			goto error_no_cb;
		}
		break;

	case GNSS_SV_STATUS_CB:
		if (gps_callbacks->gnss_sv_status_cb) {
			struct gnss_sv_status_cb_s *msg = pmsg;
			gps_callbacks->gnss_sv_status_cb(&msg->sv_info);
		} else {
			goto error_no_cb;
		}
		break;
#endif

	case GPS_CREATE_THREAD_CB:
		if (gps_callbacks->create_thread_cb) {
			gps_cb.thread =
				gps_callbacks->create_thread_cb("gps",
								generic_cb_jroutine,
								&gps_cb);
		} else {
			goto error_no_cb;
		}
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));

	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s gps_cb = {
	.sock_name = GPS_CALLBACK_SOCK_NAME,
	.handler = gps_cb_handler,
	.sock = -1,
};

/* GPS XTRA callbacks */

static void
gps_xtra_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!gps_xtra_callbacks) {
		ALOGE("%s: gps_xtra_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case GPS_XTRA_DOWNLOAD_REQUEST_CB:
		if (gps_xtra_callbacks->download_request_cb)
			gps_xtra_callbacks->download_request_cb();
		else
			goto error_no_cb;
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s gps_xtra_cb = {
	.sock_name = GPS_XTRA_CALLBACK_SOCK_NAME,
	.handler = gps_xtra_cb_handler,
	.sock = -1,
};

/* GPS NI callbacks */

static void
gps_ni_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!gps_ni_callbacks) {
		ALOGE("%s: gps_ni_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case GPS_NI_NOTIFY_CB:
		if (gps_ni_callbacks->notify_cb) {
			struct gps_ni_notify_cb_s *msg = pmsg;
			gps_ni_callbacks->notify_cb(&msg->notification);
		} else {
			goto error_no_cb;
		}
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s gps_ni_cb = {
	.sock_name = GPS_NI_CALLBACK_SOCK_NAME,
	.handler = gps_ni_cb_handler,
	.sock = -1,
};

/* AGPS callbacks */

static void
agps_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!agps_callbacks) {
		ALOGE("%s: agps_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case AGPS_STATUS_CB:
		if (agps_callbacks->status_cb) {
			struct agps_status_cb_s *msg = pmsg;
			agps_callbacks->status_cb(&msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s agps_cb = {
	.sock_name = AGPS_CALLBACK_SOCK_NAME,
	.handler = agps_cb_handler,
	.sock = -1,
};

/* AGPS RIL callbacks */

static void
agps_ril_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!agps_ril_callbacks) {
		ALOGE("%s: agps_ril_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case AGPS_RIL_REQUEST_SETID_CB:
		if (agps_ril_callbacks->request_setid) {
			struct agps_ril_request_setid_cb_s *msg = pmsg;
			agps_ril_callbacks->request_setid(msg->flags);
		} else {
			goto error_no_cb;
		}
		break;

	case AGPS_RIL_REQUEST_REFLOC_CB:
		if (agps_ril_callbacks->request_refloc) {
			struct agps_ril_request_refloc_cb_s *msg = pmsg;
			agps_ril_callbacks->request_refloc(msg->flags);
		} else {
			goto error_no_cb;
		}
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s agps_ril_cb = {
	.sock_name = AGPS_RIL_CALLBACK_SOCK_NAME,
	.handler = agps_ril_cb_handler,
	.sock = -1,
};

/* GPS Geofence callbacks */

static void
gps_geofence_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	if (!gps_geofence_callbacks) {
		ALOGE("%s: gps_geofence_callbacks == NULL", __func__);
		return;
	}

	switch (hdr->op) {
	case GPS_GEOFENCE_TRANSITION_CB:
		if (gps_geofence_callbacks->geofence_transition_callback) {
			struct gps_geofence_transition_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_transition_callback(msg->geofence_id,
									     &msg->location,
									     msg->transition,
									     msg->timestamp);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_STATUS_CB:
		if (gps_geofence_callbacks->geofence_status_callback) {
			struct gps_geofence_status_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_status_callback(msg->status,
									 &msg->last_location);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_ADD_CB:
		if (gps_geofence_callbacks->geofence_add_callback) {
			struct gps_geofence_add_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_add_callback(msg->geofence_id,
								      msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_REMOVE_CB:
		if (gps_geofence_callbacks->geofence_remove_callback) {
			struct gps_geofence_remove_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_remove_callback(msg->geofence_id,
									 msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_PAUSE_CB:
		if (gps_geofence_callbacks->geofence_pause_callback) {
			struct gps_geofence_pause_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_pause_callback(msg->geofence_id,
									msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_RESUME_CB:
		if (gps_geofence_callbacks->geofence_resume_callback) {
			struct gps_geofence_resume_cb_s *msg = pmsg;
			gps_geofence_callbacks->geofence_resume_callback(msg->geofence_id,
									 msg->status);
		} else {
			goto error_no_cb;
		}
		break;

	default:
		ALOGE("%s: Unexpected callback %s", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Function for callback %s is NULL", __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s gps_geofence_cb = {
	.sock_name = GPS_GEOFENCE_CALLBACK_SOCK_NAME,
	.handler = gps_geofence_cb_handler,
	.sock = -1,
};


/* Core callbacks */

static void
core_cb_handler(void *pmsg)
{
	struct gps_msg_header_s *hdr = pmsg;

	switch (hdr->op) {
	case GPS_PROXY_PROPERTIES_CB: {
		struct gps_proxy_properties_cb_s *msg = pmsg;
		gps_proxy_props = msg->props;
		break;
	}

	case GPS_CREATE_THREAD_CB:
		if (gps_callbacks && gps_callbacks->create_thread_cb) {
			gps_cb.thread =
				gps_callbacks->create_thread_cb("gps",
								generic_cb_jroutine,
								&gps_cb);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_NI_CREATE_THREAD_CB:
		if (gps_ni_callbacks && gps_ni_callbacks->create_thread_cb) {
			gps_ni_cb.thread =
				gps_ni_callbacks->create_thread_cb("gps-ni",
								generic_cb_jroutine,
								&gps_ni_cb);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_XTRA_CREATE_THREAD_CB:
		if (gps_xtra_callbacks && gps_xtra_callbacks->create_thread_cb) {
			gps_xtra_cb.thread =
				gps_xtra_callbacks->create_thread_cb("gps-xtra",
								     generic_cb_jroutine,
								     &gps_xtra_cb);
		} else {
			goto error_no_cb;
		}
		break;

	case AGPS_CREATE_THREAD_CB:
		if (agps_callbacks && agps_callbacks->create_thread_cb) {
			agps_cb.thread =
				agps_callbacks->create_thread_cb("agps",
								generic_cb_jroutine,
								&agps_cb);
		} else {
			goto error_no_cb;
		}
		break;

	case AGPS_RIL_CREATE_THREAD_CB:
		if (agps_ril_callbacks && agps_ril_callbacks->create_thread_cb) {
			agps_ril_cb.thread =
				agps_ril_callbacks->create_thread_cb("ril",
								     generic_cb_jroutine,
								     &agps_ril_cb);
		} else {
			goto error_no_cb;
		}
		break;

	case GPS_GEOFENCE_CREATE_THREAD_CB:
	  if (gps_geofence_callbacks && gps_geofence_callbacks->create_thread_cb) {
			gps_geofence_cb.thread =
			  gps_geofence_callbacks->create_thread_cb("gps-geofence",
								   generic_cb_jroutine,
								   &gps_geofence_cb);
		} else {
			goto error_no_cb;
		}
		break;

	/* GPS Measurement callbacks */
	case GPS_MEASUREMENT_CB:
		if (gps_measurement_callbacks->measurement_callback) {
			struct gps_measurement_cb_s *msg = pmsg;
			gps_measurement_callbacks->measurement_callback(&msg->data);
		} else {
			goto error_no_cb;
		}
		break;

	/* GPS Navigation Message callbacks */
	case GPS_NAVIGATION_MESSAGE_CB:
		if (gps_navigation_message_callbacks->navigation_message_callback) {
			struct gps_navigation_message_cb_s *msg = pmsg;
			msg->message.data = msg->message_data;
			gps_navigation_message_callbacks->navigation_message_callback(&msg->message);
		} else {
			goto error_no_cb;
		}
		break;

#if PLATFORM_VERSION_MAJOR > 6
	/* GNSS extension callbacks */
	case GNSS_MEASUREMENT_CB:
		if (gps_measurement_callbacks->gnss_measurement_callback) {
			struct gnss_measurement_cb_s *msg = pmsg;
			gps_measurement_callbacks->gnss_measurement_callback(&msg->data);
		} else {
			goto error_no_cb;
		}
		break;

	case GNSS_NAVIGATION_MESSAGE_CB:
		if (gps_navigation_message_callbacks->gnss_navigation_message_callback) {
			struct gnss_navigation_message_cb_s *msg = pmsg;
			msg->message.data = msg->message_data;
			gps_navigation_message_callbacks->gnss_navigation_message_callback(&msg->message);
		} else {
			goto error_no_cb;
		}
		break;
#endif

	default:
		ALOGW("%s: Callback %s not handled", __func__, gps_msg_op_name(hdr->op));
		break;
	}

	ALOGV("callback %s handled", gps_msg_op_name(hdr->op));
	return;

error_no_cb:
	ALOGE("%s: Callbacks or function for callback %s is NULL",
	      __func__, gps_msg_op_name(hdr->op));
}

static struct gps_client_cb_s core_cb = {
	.sock_name = CORE_CALLBACK_SOCK_NAME,
	.handler = core_cb_handler,
	.sock = -1,
};

/*
 * Module interface
 */
static int
gps_client_init(void)
{
	int err;

	/* Open and connect to the core request socket */
	core_request_sock = gps_socket_open_and_connect(CORE_REQUEST_SOCK_NAME);
	if (core_request_sock < 0) {
		ALOGE("couldn't open %s socket", CORE_REQUEST_SOCK_NAME);
		return core_request_sock;
	}

	/* Open and connect to the core callback socket */
	core_cb.sock = gps_socket_open_and_connect(core_cb.sock_name);
	if (core_cb.sock < 0) {
		ALOGE("couldn't open %s socket", core_cb.sock_name);
		close(core_request_sock);
		return core_cb.sock;
	}

	/* Create pthread to handle the core callbacks */
	err = pthread_create(&core_cb.thread, NULL, generic_cb_routine, &core_cb);
	if (err) {
		ALOGE("%s: couldn't create thread: %s", __func__, strerror(-err));
		close(core_request_sock);
		close(core_cb.sock);
		return -1;
	}

	/* Wait until the properties of the GPS proxy are received */
	int retries = 10;
	while (!gps_proxy_props.available && retries--)
		usleep(10000);
	if (!retries) {
		ALOGE("%s: proxy properties not received in time", __func__);
		return -1;
	}

	return 0;
}

const GpsInterface *
gps_get_hardware_interface(struct gps_device_t *dev __attribute__((__unused__)))
{
	return &gps_hardware_interface;
}

static int
open_gps(const struct hw_module_t* module, char const* name, struct hw_device_t** device)
{
	struct gps_device_t *dev = malloc(sizeof(struct gps_device_t));

	ALOGI("%s: hardware module %s\n", __func__, name);

	if (!dev)
		return -1;
	memset(dev, 0, sizeof(*dev));

	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = (struct hw_module_t*)module;
	dev->get_gps_interface = gps_get_hardware_interface;

	if (gps_client_init()) {
		ALOGE("failed to initialize GPS client");
		goto error;
	}

	*device = (struct hw_device_t*)dev;

	return 0;

error:
	if (dev)
		free(dev);
	*device = NULL;

	return -1;
}

static struct hw_module_methods_t gps_module_methods = {
	.open = open_gps
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = GPS_HARDWARE_MODULE_ID,
	.name = "GPS Proxy Client",
	.author = "Fraunhofer AISEC",
	.methods = &gps_module_methods,
};
