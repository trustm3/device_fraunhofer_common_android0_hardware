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
#include "common/file.h"
#include "common/event.h"
#include "common/list.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <unistd.h>

#include <cutils/properties.h>

#include "common.h"

#define CTRL_EVENT_TERMINATING "IFNAME=wlan0 <3>CTRL-EVENT-TERMINATING wpa_supplicant is exiting"

// socket fd to wpad control connections
static int wpad_control_sock;

// stateless connection to JAVA layer
static int wpa_ctrl_sock_global;

// struct to keep wpa_mon connections in sync between  JAVA layer and wpad
typedef struct wpa_proxy_connection {
	struct sockaddr_un *wpa_mon_addr;// wpa mon connection to wpa_supplicant
	int wpad_monitor_sock;	// communication socket to wpad in a0
	event_io_t *event;
} wpa_proxy_connection_t;

static wpa_proxy_connection_t* wpa_proxy_mon_con = NULL;

static char* wpa_proxy_p2p0_mac = NULL;
static char* wpa_proxy_wlan0_mac = NULL;

static bool wpa_proxy_state_terminating = false;

static char *
wpad_proxy_get_mac_new(const char *ifname)
{
	char* sys_path = mem_printf("/sys/class/net/%s/address", ifname);
	return file_read_new(sys_path, sizeof("00:11:22:33:44:55"));
}

static void
wpa_proxy_connection_free(wpa_proxy_connection_t* con)
{
	IF_NULL_RETURN(con);

	if (con->wpa_mon_addr)
		mem_free(con->wpa_mon_addr);

	if (con->event) {
		event_remove_io(con->event);
		event_io_free(con->event);
	}

	mem_free(con);
}

static void
wpa_proxy_terminate(void)
{
	// closing wpad monitor endpoint
	close(wpa_proxy_mon_con->wpad_monitor_sock);

	// close monitor to JAVA layer
	if (wpa_proxy_mon_con->wpa_mon_addr) {
		// send terminating event
		int err = sendto(wpa_ctrl_sock_global, CTRL_EVENT_TERMINATING, strlen(CTRL_EVENT_TERMINATING),
				0, (struct sockaddr *) wpa_proxy_mon_con->wpa_mon_addr, sizeof(struct sockaddr_un));
		// disconnect monitor (EOF)
		err |= sendto(wpa_ctrl_sock_global, "\0", strlen("\0"),
				0, (struct sockaddr *) wpa_proxy_mon_con->wpa_mon_addr, sizeof(struct sockaddr_un));

		if (err)
			WARN_ERRNO("monitor socket already closed");
	}

	wpa_proxy_connection_free(wpa_proxy_mon_con);

	// close global connections
	close(wpa_ctrl_sock_global);
	close(wpad_control_sock);

	exit(0);
}

#if 0
static void
wpad_proxy_replace_macs(char *buf)
{
	char *mac_offset;
	char *replace_str;

	/*
	 * a STATUS reply from wpa supplicant looks like the followinf example;
	 * thus, it is sufficient to use a simple strstr search and replace:
	 *
	 * bssid=c4:7d:4f:4c:14:92
	 * freq=2412
	 * ssid=ems-lab-wlan
	 * id=0
	 * mode=station
	 * pairwise_cipher=CCMP
	 * group_cipher=TKIP
	 * key_mgmt=WPA2-PSK
	 * wpa_state=COMPLETED
	 * ip_address=10.144.207.162
	 * p2p_device_address=36:fc:ef:e1:30:f2
	 * address=34:fc:ef:e1:30:f2
	 * uuid=fe9ddecb-c386-501e-90cb-11ce8772e379/
	 */

	mac_offset = strstr(buf, "p2p_device_address=");
	if (mac_offset != NULL) {
		replace_str = mem_printf("p2p_device_address=%s\naddress=%s", wpa_proxy_p2p0_mac, wpa_proxy_wlan0_mac);
		memcpy(mac_offset, replace_str, strlen(replace_str));
		mem_free(replace_str);
	}
        INFO("Replaced macs in buffer:\n%s", buf);
}
#endif

/**
 * Event callback to receive unsolicited messages from wpad's monitor socket
 */
static void
wpad_cb_monitor_recv(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	char *buf = NULL;

	if (events & EVENT_IO_EXCEPT) {
		WARN("wpa_supplicant monitor io error %d", fd);
		wpa_proxy_state_terminating = true;
		goto error_io;
	}

	if (events & EVENT_IO_READ) {
		TRACE("wpa_supplicant monitor data available %d", fd);
		buf = mem_alloc(EVENT_BUF_SIZE);

		ssize_t bytes_read = recv(fd, buf, EVENT_BUF_SIZE - 1 , 0);
		if (-1 == bytes_read) {
			ERROR_ERRNO("Failed to receive message!");
			wpa_proxy_state_terminating = true;
			goto error_io;
		}

		buf[bytes_read] = '\0';

		// terminate wpa_proxy if wpa_supplicant has closed connection (user triggered)
		// settings ui to disable wifi in a0 -> the corresponding framework intent cannot
		// be generated by wpa_proxy. Needs to be handled by cmld's c_service and TrustmeService
		if (0 == bytes_read) {
			INFO("wpad closed connection terminating...");
			wpa_proxy_state_terminating = true;
			goto error_io;
			//wpa_proxy_terminate();
		}

		TRACE("Monitor MSG send l=%d: %s", bytes_read, buf);

		// msg from wpad commes without trailing '\0', thus we can use bytes_read directly
		if (sendto(wpa_ctrl_sock_global, buf, bytes_read, 0, (struct sockaddr *) wpa_proxy_mon_con->wpa_mon_addr, sizeof(struct sockaddr_un)) < 0) {
			ERROR_ERRNO("sento JAVA layer");
			goto error_j;
		}

		// insert macs of virtual interfaces here

		TRACE("Handled wpa_supplicant monitor connection %d", fd);
		mem_free(buf);
	}
	return;

error_j:
	wpa_proxy_connection_free(wpa_proxy_mon_con);
	wpa_proxy_mon_con = NULL;

error_io:
	event_remove_io(io);
	event_io_free(io);
	if (buf) mem_free(buf);
}

/**
 * Event callback to handle wpa requests from JAVA layer and forward them to
 * wpad's control socket. This method also is responsible to corectly filter ATTACH requests and
 * connect the socket for unsol messages. wpad cannot handle this for himself. Further ATTACH
 * requests are enforced to be filtered out on the control socket on wpad side. Them same holds for
 * DETACH requests.
 */
static void
wpa_proxy_cb_ctrl_recv(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	bool insert_macs = false;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	ssize_t bytes_read, bytes_sent;

	TRACE("wpa_proxy_cb_ctrl_recv");

	if (events & EVENT_IO_EXCEPT) {
		event_remove_io(io);
		ERROR_ERRNO("Failed to read from JAVA layer!");
		wpa_proxy_terminate();
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	char *buf = mem_alloc(REPLY_BUF_SIZE);

	bytes_read = recvfrom(fd, buf, REPLY_BUF_SIZE - 1, 0, (struct sockaddr *) &from, &fromlen);

	if (bytes_read < 0 ) {
		WARN_ERRNO("recvfrom");
		mem_free(buf);
		return;
	}

	buf[bytes_read] = '\0';

        TRACE("MSG recvfrom l=%d: %s", bytes_read, buf);

	if (strstr(buf, "TERMINATE") != NULL ) {
		INFO("Termination request MSG recv l=%d: %s", bytes_read, buf);
		// Send OK and terminate (just closeing ctrl socket may cause framework to hang)
		if (sendto(fd, "OK\n", strlen("OK\n"), 0, (struct sockaddr *) &from, fromlen) < 0)
			WARN_ERRNO("sento JAVA layer, terminating anyway ...");
		wpa_proxy_terminate();
	}

	if (wpa_proxy_state_terminating) {
		// Send OK and terminate (just closeing ctrl socket may cause framework to hang)
		bytes_read = strlen("OK\n");
		wpa_proxy_state_terminating = true;
		goto out;
	}

	if (strncmp(buf, "ATTACH", 6) == 0) {
		char *path_mon = mem_printf("%s/%s%s", TRUSTME_COM_WIFI_PATH, "wpad_mon_", DEFAULT_WIFI_IFNAME);
		if (wpa_proxy_mon_con)
			wpa_proxy_connection_free(wpa_proxy_mon_con);
		wpa_proxy_mon_con = mem_new0(wpa_proxy_connection_t, 1);

		wpa_proxy_mon_con->wpad_monitor_sock = sock_unix_create_and_connect(SOCK_SEQPACKET | SOCK_NONBLOCK, path_mon);
	        if (wpa_proxy_mon_con->wpad_monitor_sock < 0) {
			WARN("Could not create and connect UNIX domain socket: %s", path_mon);
			mem_free(path_mon);
			wpa_proxy_connection_free(wpa_proxy_mon_con);
			wpa_proxy_mon_con = NULL;
			memcpy(buf, "FAIL\n", sizeof("FAIL\n"));
			bytes_read = strlen("FAIL\n");
			goto out;
                }
		DEBUG("connected to monitor socket: %s", path_mon);

		wpa_proxy_mon_con->wpa_mon_addr = mem_alloc0(sizeof(struct sockaddr_un));
		memcpy(wpa_proxy_mon_con->wpa_mon_addr, &from, fromlen);

		wpa_proxy_mon_con->event = event_io_new(wpa_proxy_mon_con->wpad_monitor_sock, EVENT_IO_READ, wpad_cb_monitor_recv, NULL);
		event_add_io(wpa_proxy_mon_con->event);

		mem_free(path_mon);
		memcpy(buf, "OK\n", sizeof("OK\n"));
		bytes_read = strlen("OK\n");
		goto out;

	} else if (strncmp(buf, "DETACH", 6) == 0) {
		memcpy(buf, "OK\n", sizeof("OK\n"));
		bytes_read = strlen("OK\n");
		goto out;

	} else if (strstr(buf, "STATUS") != NULL ) {
		INFO("STATUS MSG recv l=%d: %s", bytes_read, buf);
		insert_macs = true;
	}

	// do actual command forwarding to wpad
	bytes_sent = send(wpad_control_sock, buf, bytes_read, 0);
	if (-1 == bytes_sent) {
		ERROR_ERRNO("Failed to send message to wpad!");
		// Send FAIL and terminate (just closeing ctrl socket may cause framework to hang)
		memcpy(buf, "OK\n", sizeof("OK\n"));
		bytes_read = strlen("OK\n");
		wpa_proxy_state_terminating = true;
		goto out;
	}

	bytes_read = recv(wpad_control_sock, buf, REPLY_BUF_SIZE - 1, 0);
	if (-1 == bytes_read) {
		ERROR_ERRNO("Failed to receive resonse from wpad!");
		// Send FAIL and terminate (just closeing ctrl socket may cause framework to hang)
		memcpy(buf, "OK\n", sizeof("OK\n"));
		bytes_read = strlen("OK\n");
		wpa_proxy_state_terminating = true;
		goto out;
	}

out:
	buf[bytes_read] = '\0';

	//if (insert_macs)
        //	wpad_proxy_replace_macs(buf);

        TRACE("MSG recv l=%d: %s", bytes_read, buf);

	// Send respons to JAVA layer
	if (sendto(fd, buf, strlen(buf), 0, (struct sockaddr *) &from, fromlen) < 0) {
		WARN_ERRNO("sento JAVA layer failed");
		mem_free(buf);
		if (!wpa_proxy_state_terminating)
			 wpa_proxy_terminate();
	}
	mem_free(buf);
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
main_sig_cb(int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	if (signum == SIGTERM) {
		INFO("Received SIGTERM, cleaning up and exit...");
		wpa_proxy_terminate();
	}

        FATAL("Received SIGINT...");
}

/******************************************************************************/

int
main(UNUSED int argc, UNUSED char **argv)
{
	logf_handler_t *h;

	h = logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	h = logf_register(&logf_file_write, stdout);
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	main_core_dump_enable();

	INFO("Starting wpa_proxy ...");

	char *path_ctrl = mem_printf("%s/%s%s", TRUSTME_COM_WIFI_PATH, "wpad_ctrl_", DEFAULT_WIFI_IFNAME);

	wpa_proxy_p2p0_mac = wpad_proxy_get_mac_new("p2p0");
	if (wpa_proxy_p2p0_mac == NULL) wpa_proxy_p2p0_mac = "00:11:22:33:44:55";
	INFO("\tp2p0-MAC: %s", wpa_proxy_p2p0_mac);

	wpa_proxy_wlan0_mac = wpad_proxy_get_mac_new("wlan0");
	if (wpa_proxy_wlan0_mac == NULL) wpa_proxy_wlan0_mac = "00:11:22:33:44:55";
	INFO("\twlan0-MAC: %s", wpa_proxy_wlan0_mac);

	event_init();

	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sig_cb, NULL);
	event_add_signal(sig_int);

	event_signal_t *sig_term = event_signal_new(SIGTERM, &main_sig_cb, NULL);
	event_add_signal(sig_term);

	wpad_control_sock = sock_unix_create_and_connect(SOCK_SEQPACKET, path_ctrl);
	if (wpad_control_sock < 0) {
		FATAL_ERRNO("Could not create and connect UNIX domain socket: %s", path_ctrl);
		return -1;
	}
	INFO("Connection to wpad on %s established", path_ctrl);

	wpa_ctrl_sock_global = android_get_control_socket("wpa_wlan0");
	if (wpa_ctrl_sock_global < 0) {
		FATAL_ERRNO("android_get_control_socket");
		return -1;
	}

	fd_make_non_blocking(wpa_ctrl_sock_global);

	event_io_t *event_ctrl = event_io_new(wpa_ctrl_sock_global, EVENT_IO_READ, wpa_proxy_cb_ctrl_recv, NULL);
	event_add_io(event_ctrl);

	INFO("Starting event loop ...");
        event_loop();

	return 0;
}

