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

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/list.h"

#include <cutils/properties.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <signal.h>
#include <wpa_ctrl.h>
#include <unistd.h>

#include "common.h"

#define BSS_RANGE_CMD "IFNAME=" DEFAULT_WIFI_IFNAME " BSS RANGE=0- MASK=0x21987"
#define SCAN_RESULTS_CMD "IFNAME=" DEFAULT_WIFI_IFNAME " SCAN_RESULTS"
#define STATUS_CMD "STATUS"

static bool wpad_state_reconnecting = false;
static bool wpad_state_terminating = false;
static bool wpad_state_connected = false;
static bool wpad_state_scanning = false;
static bool wpad_state_dhcp_connected = false;

static char *path_supp = CONTROL_IFACE_PATH DEFAULT_WIFI_IFNAME;
static char *path_ctrl = TRUSTME_COM_WIFI_PATH "/wpad_ctrl_" DEFAULT_WIFI_IFNAME;
static char *path_mon  = TRUSTME_COM_WIFI_PATH "/wpad_mon_" DEFAULT_WIFI_IFNAME;

static char *path_enable = TRUSTME_COM_WIFI_PATH "/wifi_enable_" DEFAULT_WIFI_IFNAME;

// event_io for  global monitor connection
// have to be added on connect and removed on disconnt to wpa supplicant
event_io_t *event_io_global_mon = NULL;

#define TERMINATION_TIMEOUT 5000
#define RECONNECTION_INTERVAL 2000
#define DHCP_CONNECTION_INTERVAL 1000
#define CONNECTED_INTERVAL 1000

// stateless connection to wpa supplicant
static struct wpa_ctrl *wpa_ctrl_conn_global;
static struct wpa_ctrl *wpa_mon_conn_global;

typedef enum {
	CONNECTION_STATE_TERMINATING,
	CONNECTION_STATE_STARTING,
	CONNECTION_STATE_INITIALIZED
} connection_state_t;

// struct to keep wpa_ctrl connections in sync between wpa supplicant and container sockets
typedef struct wpad_connection {
	int sock_container;	// communication socket to container
	connection_state_t state;
	struct wpad_connection* mon;
	struct wpad_connection* ctrl;
	bool is_monitor;
} wpad_connection_t;

// wpa state change strings
static char *wpa_completed = NULL;
static char *wpa_4way_handshake = NULL;
static char *wpa_group_handshake = NULL;

static wpad_connection_t *last_ctrl_con = NULL;

// buffer for connection reply connection events on container start
static char *wpad_latest_state_change_event = NULL;
static char *wpad_connected_event = NULL;

static list_t *wpad_connection_list = NULL;
static list_t *wpad_wifi_enable_list = NULL;

static void
wpad_cb_accept(int fd, unsigned events, event_io_t *io, void *data);

static void
wpad_monitor_global_cb_recv(int fd, unsigned events, event_io_t *io, UNUSED void *data);

/******************************************************************************/


static void
wpad_init_state_strings(void)
{
	wpa_completed = mem_printf("state=%d", WPA_COMPLETED);
	wpa_4way_handshake = mem_printf("state=%d", WPA_4WAY_HANDSHAKE);
	wpa_group_handshake = mem_printf("state=%d", WPA_GROUP_HANDSHAKE);
}

static void
wpad_free_state_strings(void)
{
	mem_free(wpa_completed);
	mem_free(wpa_4way_handshake);
	mem_free(wpa_group_handshake);
}

///**
// * Helperfunction to find last occurence of a substring
// */
//static char *
//rstrstr(const char *src_str, const char *sub_str)
//{
//	if (src_str == NULL || sub_str == NULL || *sub_str == '\0')
//		return (char *) src_str;
//
//	char *res = NULL;
//	for (;;) {
//		char *cur_str = strstr(src_str, sub_str);
//		if (cur_str == NULL)
//			break;
//		res = cur_str;
//		src_str = cur_str + 1;
//	}
//	return res;
//}

wpad_connection_t *
wpad_connection_new(int sock_container, bool is_monitor)
{
	wpad_connection_t *con = mem_new0(wpad_connection_t, 1);
	con->sock_container = sock_container;
	con->state = CONNECTION_STATE_STARTING;
	con->mon = con;
	con->ctrl = con;
	con->is_monitor = is_monitor;

	wpad_connection_list = list_append(wpad_connection_list, con);

	return con;
}

static void
wpad_connection_free(wpad_connection_t *con, bool remove)
{
	// closing container endpoint
	close(con->sock_container);

	// remove wpad_connection_t from global connection list
	if (remove)
		wpad_connection_list = list_remove(wpad_connection_list, con);

	free(con);
}

/**
 * Join a monitor and a control connection.
 *
 * This function interconnects to wpad_connection_ts
 * to allow referencing a containers monitor or control connection from each other.
 */
static void
wpad_connection_join(wpad_connection_t *ctrl, wpad_connection_t* mon)
{
	ASSERT(ctrl);
	ASSERT(mon);

	ctrl->mon = mon;
	mon->ctrl = ctrl;
}

static int
wpad_recv_msg(int fd, char* buf, ssize_t buf_len)
{
	int res;
	res = recvfrom(fd, buf, buf_len - 1, 0, NULL, NULL);
	if (res < 0) {
		TRACE("no data recvfrom");
		buf[0] = '\0';
		return res;
	}
	buf[res] = '\0';
	return res;
}

/**
 * enable/disable wifi in containers
 */
static void
wpad_enable_wifi_in_containers(bool enable)
{
	for (list_t *l = wpad_wifi_enable_list; l; l = l->next) {
		int* enable_fd = l->data;
		ssize_t bytes_sent;
		if (enable)
			bytes_sent = send(*enable_fd, WPA_PROXY_COMMAND_ENABLE, strlen(WPA_PROXY_COMMAND_ENABLE), 0);
		else
			bytes_sent = send(*enable_fd, WPA_PROXY_COMMAND_DISABLE, strlen(WPA_PROXY_COMMAND_DISABLE), 0);
		if (-1 == bytes_sent)
			WARN_ERRNO("Failed to send command enable=%d enable_fd %d!", enable, *enable_fd);
		INFO("Sent command enable=%d to enable_fd %d!", enable, *enable_fd);
	}
}


/**
 * Timer callback to connect to wpa supplicant's global control socket
 *
 * @param timer   timer which trigger this callback
 * @param data	  not used
 */
static void
wpad_connect_to_supp_cb(event_timer_t *timer, UNUSED void *data)
{
	wpa_ctrl_conn_global = wpa_ctrl_open(path_supp);
	if (wpa_ctrl_conn_global == NULL) {
		TRACE("Unable to open connection to supplicant on %s, retrying", path_supp);
		return;
	}

	// Open connection for unsolicited messages
	wpa_mon_conn_global = wpa_ctrl_open(path_supp);
	if (wpa_mon_conn_global == NULL) {
		TRACE("Unable to open monitor connection to supplicant on %s, retrying", path_supp);
		wpa_ctrl_close(wpa_ctrl_conn_global);
		wpa_ctrl_conn_global = NULL;
		return;
	}

	if (wpa_ctrl_attach(wpa_mon_conn_global) != 0) {
		wpa_ctrl_close(wpa_mon_conn_global);
		wpa_ctrl_close(wpa_ctrl_conn_global);
		wpa_ctrl_conn_global = NULL;
		wpa_mon_conn_global = NULL;
	}

	int wpa_monitor_fd_global = wpa_ctrl_get_fd(wpa_mon_conn_global);
	fd_make_non_blocking(wpa_monitor_fd_global);

	event_io_global_mon = event_io_new(wpa_monitor_fd_global, EVENT_IO_READ, wpad_monitor_global_cb_recv, NULL);
	event_add_io(event_io_global_mon);

	INFO("Connection to supplicant on %s established, now listening ", path_supp);
	wpad_state_reconnecting = false;
	wpad_state_terminating = false;

	// reset container connections
	for (list_t *l = wpad_connection_list; l; l = l->next) {
		wpad_connection_t *con = l->data;
		con->state = CONNECTION_STATE_STARTING;
	}
	// enable wifi in containers
	wpad_enable_wifi_in_containers(true);

	event_remove_timer(timer);
	event_timer_free(timer);
}

/**
 * Funtion to cleanup connections and reconnect to wpa supplicant
 */
static void
wpad_reconnect(void)
{
	// check if we are allready waiting for a reconnection
	if (wpad_state_reconnecting) return;
	wpad_state_reconnecting = true;

	if (event_io_global_mon) {
		event_remove_io(event_io_global_mon);
		event_io_free(event_io_global_mon);
		event_io_global_mon = NULL;
	}

	wpa_ctrl_close(wpa_mon_conn_global);
	wpa_ctrl_close(wpa_ctrl_conn_global);
	wpa_ctrl_conn_global = NULL;
	wpa_mon_conn_global = NULL;

	// trigger connection to wpa supplicant
	event_timer_t* event_connect = event_timer_new(RECONNECTION_INTERVAL, EVENT_TIMER_REPEAT_FOREVER, &wpad_connect_to_supp_cb, NULL);
	event_add_timer(event_connect);
}

#if 0
static void
wpad_update_dhcp_connected_state_cb(event_timer_t *timer, UNUSED void *data)
{
	char prop_buf[PROP_VALUE_MAX];
	bool old_state = wpad_state_dhcp_connected;
        if (property_get("dhcp.wlan0.result", prop_buf, "fail")) {
		wpad_state_dhcp_connected = strncmp("ok", prop_buf, strlen("ok")) == 0 ? true : false;
	} else {
		wpad_state_dhcp_connected = false;
	}
	// if dhcpd state change to connected enable wifi in containers
	if ((old_state != wpad_state_dhcp_connected) && wpad_state_dhcp_connected) {
		for (list_t *l = wpad_wifi_enable_list; l; l = l->next) {
			int* enable_fd = l->data;
			ssize_t bytes_sent = send(*enable_fd, WPA_PROXY_COMMAND_ENABLE, strlen(WPA_PROXY_COMMAND_ENABLE), 0);
			if (-1 == bytes_sent)
				WARN_ERRNO("Failed to send command %s enable_fd %d!", WPA_PROXY_COMMAND_ENABLE, *enable_fd);
			INFO("Sent command %s to enable_fd %d!", WPA_PROXY_COMMAND_ENABLE, *enable_fd);
		}
		// we are now connected to the network no need to check
		event_remove_timer(timer);
		event_timer_free(timer);
	}
}
#endif

static bool
wpad_allowed_event(const char* event)
{
	ASSERT(event);
	// filter state change events
	if (strstr(event, "CTRL-EVENT-STATE-CHANGE") != NULL) {
		// // skip key negosiation istates
		// if (
		// 	strstr(event, wpa_4way_handshake) != NULL ||
		// 	strstr(event, wpa_group_handshake) != NULL
		// ) {
		// 	return false;
		// }
		return true;
	}
	// filter remaining events
	if (
		strstr(event, "CTRL-EVENT-CONNECTED") != NULL ||
		strstr(event, "CTRL-EVENT-DISCONNECTED") != NULL ||
		strstr(event, "CTRL-EVENT-SCAN-STARTED") != NULL ||
		strstr(event, "CTRL-EVENT-SCAN-RESULTS") != NULL ||
		strstr(event, "CTRL-EVENT-BSS-ADDED") != NULL ||
		strstr(event, "CTRL-EVENT-BSS-REMOVED") != NULL
	) {
		return true;
	}
	return false;
}

/**
 * Forward and filter incoming unsol data from the wpa supplicant monitor socket
 *
 * @param event     buffer with the wpa event which is to be forwarded
 * @param event_len size of the wpa event string
 * @param con	    connection to which the event should be forwarded
 */
static void
wpad_do_forward_event(const char* event, size_t event_len, wpad_connection_t *con)
{
	ASSERT(con);
	ASSERT(event_len == strlen(event));

	int fd = con->sock_container;

	// skipping control connections
	if (!con->is_monitor)
		return;

	// do filtering here
	if (con->state < CONNECTION_STATE_INITIALIZED || !wpad_allowed_event(event)) {
		// only forward EVENTs when client has initially setup
		DEBUG("Discarding event %s for container %d.", event, fd);
		return;
	}

	// Send unsol message to container
	TRACE("Monitor MSG send l=%d: %s", event_len, event);
	if (-1 == send(fd, event, event_len, 0)) {
		ERROR_ERRNO("Failed to send response to container! Closing connection fd %d...", fd);
		wpad_connection_free(con, true);
		return;
	}

	TRACE("Handled wpa_supplicant monitor connection %d", fd);
	return;
}

static void
wpad_monitor_global_cb_recv(int fd, unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	ssize_t bytes_read;
	char *buf = NULL;

	TRACE("wpa_supplicant global monitor recv cb %d", fd);

	if (events & EVENT_IO_EXCEPT) {
		WARN("wpa_supplicant global monitor io error %d", fd);
		goto termination;
	}

	if (events & EVENT_IO_READ) {
		buf = mem_alloc(EVENT_BUF_SIZE);

		// Read unsol message from suppicant
		TRACE("wpa_supplicant monitor data available %d", fd);
		bytes_read = wpad_recv_msg(fd, buf, EVENT_BUF_SIZE);
		if (-1 == bytes_read) {
			ERROR_ERRNO("Failed to receive message from supplicant!");
			goto termination;
		}

		TRACE("Global supplicant Monitor MSG l=%d: %s", bytes_read, buf);

		if (strstr(buf, "CTRL-EVENT-STATE-CHANGE") && strstr(buf, wpa_completed)) {
			if (wpad_latest_state_change_event)
				mem_free(wpad_latest_state_change_event);
			wpad_latest_state_change_event = strdup(buf);
		}

		if (strstr(buf, "CTRL-EVENT-CONNECTED") && !wpad_state_terminating) {
			// store initial connected event for container
			if (wpad_connected_event)
				mem_free(wpad_connected_event);
			wpad_connected_event = strdup(buf);
			#if 0
			// periodically update dhcpd connected wifi_enable
			event_timer_t* event_dhcp_connect =
				event_timer_new(DHCP_CONNECTION_INTERVAL, EVENT_TIMER_REPEAT_FOREVER, &wpad_update_dhcp_connected_state_cb, NULL);
			event_add_timer(event_dhcp_connect);
			#endif
			wpad_state_connected = true;
		}

		if (strstr(buf, "CTRL-EVENT-DISCONNECTED")) {
			wpad_state_connected = false;
			if (wpad_connected_event) {
				mem_free(wpad_connected_event);
				wpad_connected_event = NULL;
			}
		}

		if (strstr(buf, "CTRL-EVENT-SCAN-STARTED")) {
			wpad_state_scanning = true;
		}

		if (strstr(buf, "CTRL-EVENT-SCAN-RESULTS")) {
			wpad_state_scanning = false;
		}

		if (strstr(buf, "CTRL-EVENT-TERMINATING") && !wpad_state_terminating)
		{
			goto termination;
		}

		// forward unsol events to containers
		for (list_t *l = wpad_connection_list; l; l = l->next) {
			wpad_connection_t *con = l->data;
			wpad_do_forward_event(buf, bytes_read, con);
		}

		mem_free(buf);
	}
	return;

termination:
	wpad_state_terminating = true;
	wpad_state_connected = false;
	wpad_state_dhcp_connected = false;
	wpad_state_scanning = false;

	// disable wifi in containers
	wpad_enable_wifi_in_containers(false);

	INFO("Termination event: wpa_supplicant is going to die...");

	for (list_t *l = wpad_connection_list; l; l = l->next) {
		wpad_connection_t *con = l->data;
		con->state = CONNECTION_STATE_TERMINATING;
	}

	close(fd);
	if (buf) mem_free(buf);
	WARN("seems we have lost connection to supplicant -> cleanup and do reconnect.");
	wpad_reconnect();
}


static void
wpad_send_connected_event(wpad_connection_t *con)
{
	ASSERT(con && con->mon);
	wpad_connection_t *monitor = con->mon;

	if (!wpad_state_connected)
		return;

	// Send unsol message to container
	if (-1 == send(monitor->sock_container, wpad_latest_state_change_event, strlen(wpad_latest_state_change_event), 0)) {
		WARN_ERRNO("Failed to send initial state change connected event to container!");
		return;
	}
	if (-1 == send(monitor->sock_container, wpad_connected_event, strlen(wpad_connected_event), 0)) {
		WARN_ERRNO("Failed to send initial connected event to container!");
	}
}

static bool
wpad_allowed_ctrl_cmd(const char* command, connection_state_t state)
{
	ASSERT(command);

	switch (state) {
		case CONNECTION_STATE_STARTING:
			if (
				strstr(command, "STATUS") != NULL ||
				strstr(command, "GET_NETWORK") != NULL ||
				strstr(command, "LIST_NETWORKS") != NULL ||
				((strstr(command, "SCAN") != NULL) && !wpad_state_scanning) ||
				strstr(command, "SCAN_RESULTS") != NULL ||
				strstr(command, "BSS") != NULL
			) {
				return true;
			}
			return false;

		case CONNECTION_STATE_INITIALIZED:
			if (
				strstr(command, "P2P_") != NULL ||
				strstr(command, "DRIVER SETSUSPENDMODE") != NULL ||
				strstr(command, "STATUS") != NULL ||
				strstr(command, "BSS") != NULL ||
				strstr(command, "GET_NETWORK") != NULL ||
				strstr(command, "LIST_NETWORKS") != NULL ||
				((strstr(command, "SCAN") != NULL) && !wpad_state_scanning) ||
				strstr(command, "SCAN_RESULTS") != NULL ||
				strstr(command, "SIGNAL_POLL") != NULL ||
				((strstr(command, "RECONNECT") != NULL) && !wpad_state_connected) ||
				strstr(command, "SAVE_CONFIG") != NULL ||
				strstr(command, "PING") != NULL
			) {
				return true;
			}
			return false;

		case CONNECTION_STATE_TERMINATING:

		default:
			return false;
	}
	return false;
}

/**
 * Event callback for incoming connections on the wpad stateless server control socket
 * invoked by client side requests of containers
 *
 * @param fd	    file descriptor of incoming data must be equal to the descriptor of the
 *                  corresponding sock_container fd inside the wpad_connection_t struct (see data)
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to the associated wpad_connection_t struct
 */
static void
wpad_cb_control_recv(int fd, unsigned events, event_io_t *io, void *data)
{
	wpad_connection_t* con = data;
	ASSERT(con);
	ASSERT(fd == con->sock_container);

	char *buf = NULL;
	ssize_t bytes_read, bytes_sent;

	bool send_connected = false;

	TRACE("Statless control data");

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		goto error;
	}

	if (events & EVENT_IO_READ) {
		buf = mem_alloc(REPLY_BUF_SIZE);

		// Read request
		bytes_read = wpad_recv_msg(fd, buf, REPLY_BUF_SIZE);
		if (bytes_read <= 0) {
			ERROR_ERRNO("Failed to receive message from container!");
			goto error;
		}
		TRACE("CTRL Command MSG recv l=%d: %s", bytes_read, buf);

		// The Global "STATUS" command finishes the startup seequenze of a container
		if (strncmp(buf, STATUS_CMD, strlen(STATUS_CMD)) == 0) {
			// check if container starts with wifi enabled but disabled in a0
			if (wpad_state_reconnecting || wpad_state_terminating) {
				con->state = CONNECTION_STATE_TERMINATING;
				con->mon->state = CONNECTION_STATE_TERMINATING;
				wpad_enable_wifi_in_containers(false);
			} else {
				con->state = CONNECTION_STATE_INITIALIZED;
				con->mon->state = CONNECTION_STATE_INITIALIZED;
				INFO("connection fd %d now initialized: MSG recv l=%d: %s", fd, bytes_read, buf);
				send_connected = true;
			}
		}

		if (wpad_state_reconnecting || wpad_state_terminating || !wpad_allowed_ctrl_cmd(buf, con->state)) {
			// while disconnected from wpa_supplicant or command is not allowed just acknowledge any command
			TRACE("filtered msg: %s", buf);
			snprintf(buf, REPLY_BUF_SIZE, "OK\n");
			bytes_read = strlen("OK\n");
			goto out;
		}

		// return buffered detailed scan results only
		if (strncmp(buf, BSS_RANGE_CMD, strlen(BSS_RANGE_CMD)) == 0) {
			send_connected = true;
		}

		// Doing actual command forwarding here
		int wpa_ctrl_fd = wpa_ctrl_get_fd(wpa_ctrl_conn_global);
		bytes_sent = send(wpa_ctrl_fd, buf, strlen(buf), 0);
		if (-1 == bytes_sent) {
			ERROR_ERRNO("Failed to send message to ctrl_conn!");
			snprintf(buf, REPLY_BUF_SIZE, "FAIL\n");
			bytes_read = strlen("FAIL\n");
			goto out;
		}
		bytes_read = wpad_recv_msg(wpa_ctrl_fd, buf, REPLY_BUF_SIZE);
		if (-1 == bytes_read) {
			ERROR_ERRNO("Failed to receive message from ctrl_conn!");
			snprintf(buf, REPLY_BUF_SIZE, "FAIL\n");
			bytes_read = strlen("FAIL\n");
			//goto out;
		}
out:
		buf[bytes_read] = '\0';

		// Send response
		TRACE("CRTL Response MSG send l=%d: %s", bytes_read, buf);

		bytes_sent = send(fd, buf, strlen(buf), 0);
		if (-1 == bytes_sent) {
			ERROR_ERRNO("Failed to send response to container!");
			goto error;
		}

		if (send_connected)
			wpad_send_connected_event(con);

		mem_free(buf);
	}
	return;

error:
	event_remove_io(io);
	event_io_free(io);
	wpad_connection_free(con, true);
	if (buf) mem_free(buf);
}

/*
 * Event callback for when a new client (container) connects to the wpad
 * listening sockets wpad_mon_<ifname> or wpad_ctrl_<ifname>
 *
 * it creates a new connection to the wpa supplicant by calling
 * wpad_connect_to_supplicant(). For monitor connections the wpad_connect_to_supplicant()
 * function is instructed to attach the new monitor.
 */
static void
wpad_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	char *path = data;
	ASSERT(path);

	if (events & EVENT_IO_EXCEPT) {
		WARN("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept connection on path: %s", path);
		return;
	}
	DEBUG("Accepted connection %d on path: %s", cfd, path);

	fd_make_non_blocking(cfd);

	if (strstr(path, "wpad_mon_")) {
		wpad_connection_t *con = wpad_connection_new(cfd, true);
		wpad_connection_join(last_ctrl_con, con);
	} else { // "wpad_ctrl_"
		wpad_connection_t *con = wpad_connection_new(cfd, false);
		last_ctrl_con = con; // remember refeference for joining with monitor connection
		event_io_t *event = event_io_new(cfd, EVENT_IO_READ, wpad_cb_control_recv, con);
		event_add_io(event);
	}
}


static void
wpad_cb_wifi_enable_recv(int fd, unsigned events, event_io_t *io, void *data)
{
	int *wifi_enable_sock = data;
	ASSERT(wifi_enable_sock);
	ASSERT(fd == *wifi_enable_sock);

	char* buf = NULL;

	TRACE("Enabler data");

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on wifi_enable socket %d, closing...", fd);
		goto error;
	}
	if (events & EVENT_IO_READ) {
		buf = mem_alloc(REPLY_BUF_SIZE);

		// Read msg from wifi_enable, we do not expect data but have to handle EOF
		TRACE("wpa_supplicant monitor data available %d", fd);
		int bytes_read = wpad_recv_msg(fd, buf, REPLY_BUF_SIZE);
		if (0 == bytes_read) {
			ERROR_ERRNO("EOF: on wifi_enable socket %d, closing...", fd);
			goto error;
		}
		free(buf);
	}
	return;
error:
	event_remove_io(io);
	event_io_free(io);
	wpad_wifi_enable_list = list_remove(wpad_wifi_enable_list, wifi_enable_sock);
	mem_free(wifi_enable_sock);
	if (buf) mem_free(buf);
	close(fd);
}

static void
wpad_cb_wifi_enable_accept(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	if (events & EVENT_IO_EXCEPT) {
		WARN("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept connection on path: %s", path_enable);
		return;
	}
	DEBUG("Accepted connection %d on path: %s", cfd, path_enable);

	fd_make_non_blocking(cfd);

	int *wifi_enable_sock = mem_alloc(sizeof(int));
	wifi_enable_sock[0] = cfd;
	wpad_wifi_enable_list = list_append(wpad_wifi_enable_list, wifi_enable_sock);

	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, wpad_cb_wifi_enable_recv, wifi_enable_sock);
	event_add_io(event);

	/* send initial state */
	ssize_t bytes_sent;
	if (wpad_state_connected)
		bytes_sent = send(cfd, WPA_PROXY_COMMAND_ENABLE, strlen(WPA_PROXY_COMMAND_ENABLE), 0);
	else
		bytes_sent = send(cfd, WPA_PROXY_COMMAND_DISABLE, strlen(WPA_PROXY_COMMAND_DISABLE), 0);

	if (-1 == bytes_sent)
		WARN_ERRNO("Failed to send initial state %d enable_fd %d!", wpad_state_connected, cfd);

}

/******************************************************************************/

static void
main_core_dump_enable(void)
{
	struct rlimit core_limit;

	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
		ERROR_ERRNO("Could not set rlimits for core dump generation");
}

static void
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
        FATAL("Received SIGINT...");
}

/******************************************************************************/

int
main(UNUSED int argc,char **argv)
{
	int err;
	logf_handler_t *h;

	h = logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	h = logf_register(&logf_file_write, stdout);
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	main_core_dump_enable();

	INFO("Starting wpad ...");

	err = unlink(path_ctrl);
	if (err && errno != ENOENT) {
		ERROR_ERRNO("Couldn't unlink %s", path_ctrl);
	}

	err = unlink(path_mon);
	if (err && errno != ENOENT) {
		ERROR_ERRNO("Couldn't unlink %s", path_mon);
	}

	// listen for clients
	int wpad_wifi_enable_sock = sock_unix_create_and_bind(SOCK_SEQPACKET | SOCK_NONBLOCK, path_enable);
	if (wpad_wifi_enable_sock < 0)
		FATAL("Could not create and bind UNIX domain socket: %s", path_enable);
	if (sock_unix_listen(wpad_wifi_enable_sock) < 0)
                FATAL_ERRNO("Could not listen on new socket: %s", path_enable);

	int wpad_control_sock = sock_unix_create_and_bind(SOCK_SEQPACKET | SOCK_NONBLOCK, path_ctrl);
	if (wpad_control_sock < 0)
		FATAL("Could not create and bind UNIX domain socket: %s", path_ctrl);
	if (sock_unix_listen(wpad_control_sock) < 0)
		FATAL_ERRNO("Could not listen on new socket: %s", path_ctrl);

	int wpad_monitor_sock = sock_unix_create_and_bind(SOCK_SEQPACKET | SOCK_NONBLOCK, path_mon);
	if (wpad_monitor_sock < 0)
		FATAL_ERRNO("Could not create and bind UNIX domain socket: %s", path_mon);
	if (sock_unix_listen(wpad_monitor_sock) < 0)
		FATAL_ERRNO("Could not listen on new socket: %s", path_mon);

	event_init();

	event_signal_t *sig = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig);

	wpad_init_state_strings();

	// initial connct to wpa supplicant
	wpad_reconnect();

	// connection to wifi_enable
	event_io_t *event_wifi_enable_accept = event_io_new(wpad_wifi_enable_sock, EVENT_IO_READ, wpad_cb_wifi_enable_accept, NULL);
	event_add_io(event_wifi_enable_accept);

	// connection to control sockets
	event_io_t *event_ctrl_accept = event_io_new(wpad_control_sock, EVENT_IO_READ, wpad_cb_accept, path_ctrl);
	event_add_io(event_ctrl_accept);

	// coonection to monitor sockets
	event_io_t *event_mon_accept = event_io_new(wpad_monitor_sock, EVENT_IO_READ, wpad_cb_accept, path_mon);
	event_add_io(event_mon_accept);

	INFO("Starting event loop ...");
	event_loop();

	wpad_free_state_strings();

	return 0;
}

