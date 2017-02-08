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

#ifndef __GPS_COMMON_H
#define __GPS_COMMON_H

#if PLATFORM_VERSION_MAJOR < 6
typedef void* GnssData;
typedef struct {
	size_t data_length;
	void* data;
} GnssNavigationMessage;
typedef void* GnssSystemInfo;
typedef void* GnssSvStatus;
#endif

#define GPS_PROXY_SOCKET_PATH "/data/trustme-com/gps"

#define CORE_REQUEST_SOCK_NAME		"request"
#define CORE_CALLBACK_SOCK_NAME		"callback"
#define GPS_CALLBACK_SOCK_NAME		"gps-callback"
#define GPS_XTRA_CALLBACK_SOCK_NAME	"gps-xtra-callback"
#define GPS_NI_CALLBACK_SOCK_NAME	"gps-ni-callback"
#define AGPS_CALLBACK_SOCK_NAME		"agps-callback"
#define AGPS_RIL_CALLBACK_SOCK_NAME	"agps-ril-callback"
#define GPS_GEOFENCE_CALLBACK_SOCK_NAME	"gps-geofence-callback"


struct gps_proxy_properties_s {
	int gps_xtra_if_available;
	int gps_ni_if_available;
	int agps_if_available;
	int agps_ril_if_available;
	int gps_geofence_if_available;
	int supl_certificate_if_available;
	int gps_measurement_if_available;
	int gps_navigation_message_if_available;
	int gnss_configuration_if_available;
	int gps_debug_if_available;
	int available;
};

/*
 * GPS message operations
 */
enum gps_msg_op {
	/* Used for error checking */
	UNDEFINED = 0,

	/* Interfaces */
	GPS_INIT,
	GPS_START,
	GPS_STOP,
	GPS_CLEANUP,
	GPS_INJECT_TIME,
	GPS_INJECT_LOCATION,
	GPS_DELETE_AIDING_DATA,
	GPS_SET_POSITION_MODE,
	GPS_GET_EXTENSION,
	GPS_XTRA_INIT,
	GPS_XTRA_INJECT_XTRA_DATA,
	AGPS_INIT,
	AGPS_DATA_CONN_OPEN,
	AGPS_DATA_CONN_CLOSED,
	AGPS_DATA_CONN_FAILED,
	AGPS_SET_SERVER,
	AGPS_DATA_CONN_OPEN_WITH_APN_IP_TYPE,
	SUPL_CERTIFICATE_INSTALL_CERTS,
	SUPL_CERTIFICATE_REVOKE_CERTS,
	GPS_NI_INIT,
	GPS_NI_RESPOND,
	AGPS_RIL_INIT,
	AGPS_RIL_SET_REF_LOCATION,
	AGPS_RIL_SET_SET_ID,
	AGPS_RIL_NI_MESSAGE,
	AGPS_RIL_UPDATE_NETWORK_STATE,
	AGPS_RIL_UPDATE_NETWORK_AVAILABILITY,
	GPS_GEOFENCE_INIT,
	GPS_GEOFENCE_ADD_GEOFENCE_AREA,
	GPS_GEOFENCE_PAUSE_GEOFENCE,
	GPS_GEOFENCE_RESUME_GEOFENCE,
	GPS_GEOFENCE_REMOVE_GEOFENCE_AREA,
	GPS_MEASUREMENT_INIT,
	GPS_MEASUREMENT_CLOSE,
	GPS_NAVIGATION_MESSAGE_INIT,
	GPS_NAVIGATION_MESSAGE_CLOSE,
	GNSS_CONFIGURATION_UPDATE,

	/* Callbacks */
	GPS_LOCATION_CB,
	GPS_STATUS_CB,
	GPS_SV_STATUS_CB,
	GPS_NMEA_CB,
	GPS_SET_CAPABILITIES_CB,
	GPS_ACQUIRE_WAKELOCK_CB,
	GPS_RELEASE_WAKELOCK_CB,
	GPS_CREATE_THREAD_CB,
	GPS_REQUEST_UTC_TIME_CB,
	GNSS_SET_SYSTEM_INFO_CB,
	GNSS_SV_STATUS_CB,
	GPS_XTRA_DOWNLOAD_REQUEST_CB,
	GPS_XTRA_CREATE_THREAD_CB,
	AGPS_STATUS_CB,
	AGPS_CREATE_THREAD_CB,
	GPS_NI_NOTIFY_CB,
	GPS_NI_CREATE_THREAD_CB,
	AGPS_RIL_REQUEST_SETID_CB,
	AGPS_RIL_REQUEST_REFLOC_CB,
	AGPS_RIL_CREATE_THREAD_CB,
	GPS_GEOFENCE_TRANSITION_CB,
	GPS_GEOFENCE_STATUS_CB,
	GPS_GEOFENCE_ADD_CB,
	GPS_GEOFENCE_REMOVE_CB,
	GPS_GEOFENCE_PAUSE_CB,
	GPS_GEOFENCE_RESUME_CB,
	GPS_GEOFENCE_CREATE_THREAD_CB,
	GPS_MEASUREMENT_CB,
	GNSS_MEASUREMENT_CB,
	GPS_NAVIGATION_MESSAGE_CB,
	GNSS_NAVIGATION_MESSAGE_CB,
	GPS_PROXY_PROPERTIES_CB,

	GPS_MSG_OP_MAX,
};

struct gps_msg_header_s {
	enum gps_msg_op op;	/* RPC operation code */
	size_t size;		/* total message size */
};

struct gps_msg_reply_s {
	struct gps_msg_header_s header;
	int rc;			/* return code */
};

/*
 * Global GPS proxy properties
 */
struct gps_proxy_properties_cb_s {
	struct gps_msg_header_s header;
	struct gps_proxy_properties_s props;
};

/*
 * GPS XTRA Interface
 */
struct gps_xtra_inject_xtra_data_s {
	struct gps_msg_header_s header;
	int length;
	char data[];
};

/*
 * AGPS Interface
 */
struct agps_data_conn_open_s {
	struct gps_msg_header_s header;
	char apn[];
};

struct agps_set_server_s {
	struct gps_msg_header_s header;
	AGpsType type;
	int port;
	char hostname[];
};

struct agps_data_conn_open_with_apn_ip_type_s {
	struct gps_msg_header_s header;
	ApnIpType apnIpType;
	char apn[];
};

struct agps_status_cb_s {
	struct gps_msg_header_s header;
	AGpsStatus status;
};

/*
 * SUPL Certificate Interface
 */
struct supl_certificate_install_certificates_s {
	struct gps_msg_header_s header;
	size_t length;
	size_t raw_length;
	u_char raw_data[];
};

struct supl_certificate_revoke_certificates_s {
	struct gps_msg_header_s header;
	size_t length;
	Sha1CertificateFingerprint fingerprints[];
};

/*
 * GPS NI Interface
 */
struct gps_ni_respond_s {
	struct gps_msg_header_s header;
	int notif_id;
	GpsUserResponseType user_response;
};

struct gps_ni_notify_cb_s {
	struct gps_msg_header_s header;
	GpsNiNotification notification;
};

/*
 * RIL Interface
 */
struct agps_ril_set_ref_location_s {
	struct gps_msg_header_s header;
	size_t sz_struct;
	AGpsRefLocation agps_reflocation[];
};

struct agps_ril_set_set_id_s {
	struct gps_msg_header_s header;
	AGpsSetIDType type;
	char setid[];
};

struct agps_ril_ni_message_s {
	struct gps_msg_header_s header;
	int length;
	uint8_t message[];
};

struct agps_ril_update_network_state_s {
	struct gps_msg_header_s header;
	int connected;
	int type;
	int roaming;
	char extra_info[];
};

struct agps_ril_update_network_availablilty_s {
	struct gps_msg_header_s header;
	int available;
	char apn[];
};

struct agps_ril_request_setid_cb_s {
	struct gps_msg_header_s header;
	uint32_t flags;
};

struct agps_ril_request_refloc_cb_s {
	struct gps_msg_header_s header;
	uint32_t flags;
};

/*
 * GPS Geofence Interface
 */
struct gps_geofence_add_geofence_area_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	double latitude;
	double longitude;
	double radius_meters;
	int last_transition;
	int monitor_transitions;
	int notification_responsiveness_ms;
	int unknown_timer_ms;
};

struct gps_geofence_pause_geofence_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
};

struct gps_geofence_resume_geofence_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	int monitor_transitions;
};

struct gps_geofence_remove_geofence_area_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
};

struct gps_geofence_transition_cb_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	GpsLocation location;
	int32_t transition;
	GpsUtcTime timestamp;
};

struct gps_geofence_status_cb_s {
	struct gps_msg_header_s header;
	int32_t status;
	GpsLocation last_location;
};

struct gps_geofence_add_cb_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	int32_t status;
};

struct gps_geofence_remove_cb_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	int32_t status;
};

struct gps_geofence_pause_cb_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	int32_t status;
};

struct gps_geofence_resume_cb_s {
	struct gps_msg_header_s header;
	int32_t geofence_id;
	int32_t status;
};

/*
 * GPS Measurement Interface
 */
struct gps_measurement_cb_s {
	struct gps_msg_header_s header;
	GpsData data;
};

struct gnss_measurement_cb_s {
	struct gps_msg_header_s header;
	GnssData data;
};

/*
 * GPS Navigation Message Interface
 */
struct gps_navigation_message_cb_s {
	struct gps_msg_header_s header;
	GpsNavigationMessage message;
	uint8_t message_data[];
};

struct gnss_navigation_message_cb_s {
	struct gps_msg_header_s header;
	GnssNavigationMessage message;
	uint8_t message_data[];
};

/*
 * GNSS Configuration Interface
 */
struct gnss_configuration_update_s {
	struct gps_msg_header_s header;
	int32_t length;
	char config_data[];
};

/*
 * GPS Interface
 */
struct gps_inject_time_s {
	struct gps_msg_header_s header;
	GpsUtcTime time;
	int64_t time_reference;
	int uncertainty;
};

struct gps_inject_location_s {
	struct gps_msg_header_s header;
	double latitude;
	double longitude;
	float accuracy;
};

struct gps_delete_aiding_data_s {
	struct gps_msg_header_s header;
	GpsAidingData flags;
};

struct gps_set_position_mode_s {
	struct gps_msg_header_s header;
	GpsPositionMode mode;
	GpsPositionRecurrence recurrence;
	uint32_t min_interval;
	uint32_t preferred_accuracy;
	uint32_t preferred_time;
};

struct gps_location_cb_s {
	struct gps_msg_header_s header;
	GpsLocation location;
};

struct gps_status_cb_s {
	struct gps_msg_header_s header;
	GpsStatus status;
};

struct gps_sv_status_cb_s {
	struct gps_msg_header_s header;
	GpsSvStatus sv_status;
};

struct gps_nmea_cb_s {
	struct gps_msg_header_s header;
	GpsUtcTime timestamp;
	int length;
	char nmea[];
};

struct gps_set_capabilities_cb_s {
	struct gps_msg_header_s header;
	uint32_t capabilities;
};

struct gnss_set_system_info_cb_s {
	struct gps_msg_header_s header;
	GnssSystemInfo info;
};

struct gnss_sv_status_cb_s {
	struct gps_msg_header_s header;
	GnssSvStatus sv_info;
};

/*
 * Common functions
 */
int gps_msg_send_by_size(int fd, void *p, size_t size);
int gps_msg_send_nodata(int fd, enum gps_msg_op op);

void *gps_msg_alloc(enum gps_msg_op op, size_t size);
void gps_msg_free(void *pmsg);

ssize_t gps_msg_recv(int fd, void *pmsg, size_t max_size);
ssize_t gps_msg_send(int fd, void *data, size_t size);

const char *gps_msg_op_name(enum gps_msg_op op);

/*
 * Macro definitions
 */
#define gps_msg_send_by_type(p) gps_msg_send_by_size(p, sizeof(*(p)))
#define gps_msg_alloc_by_type(p, op, len) gps_msg_alloc(op, sizeof(*(p)) + (len))

#define SNDRCV_BUF_SIZE 2097152

#endif /* __GPS_COMMON_H */
