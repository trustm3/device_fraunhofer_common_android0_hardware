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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define SVC_PATH "/system/bin/svc"

static int
wifi_enable_fork_and_execvp(const char *path, const char * const *argv)
{
	ASSERT(path);
	//ASSERT(argv);     // on some OSes, argv can be NULL...

	pid_t pid = fork();
	if (pid == -1) {    // error
		ERROR_ERRNO("Could not fork '%s'", path);
	} else if (pid == 0) {      // child
		// cast away const from char (!) for compatibility with legacy (not so clever) execv API
		// see discussion at http://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html#tag_16_111_08
		execvp(path, (char * const *)argv);
		ERROR_ERRNO("Could not execv '%s'", path);
	} else {
	// parent
	int status;
	if (waitpid(pid, &status, 0) != pid) {
		ERROR_ERRNO("Could not waitpid for '%s'", path);
	} else if (!WIFEXITED(status)) {
		ERROR("Child '%s' terminated abnormally", path);
	} else
		return WEXITSTATUS(status);
	}
	return -1;
}


static int
wifi_enable_set_wifi(char *command)
{
	const char * const argv[] = {"svc", "wifi", command, NULL};
	return wifi_enable_fork_and_execvp (SVC_PATH, argv);
}

/**
 * Event callback to receive enable disable messages from wpad's wifi_enable socket
 */
static void
wifi_enable_cb_recv(int fd, unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	if (events & EVENT_IO_EXCEPT)
		FATAL("IO error %d", fd);

	if (events & EVENT_IO_READ) {
		TRACE("wifi_enable socket data available %d", fd);
		char* buf = mem_alloc(EVENT_BUF_SIZE);

		ssize_t bytes_read = recv(fd, buf, EVENT_BUF_SIZE - 1 , 0);
		if (0 == bytes_read)
			FATAL("EOF: Remote side closed connection.");
		if (-1 == bytes_read) {
			FATAL_ERRNO("Failed to receive message!");
		}

		buf[bytes_read] = '\0';

		if (wifi_enable_set_wifi(buf) != 0)
			WARN("Set wifi failed: malformated command");
		INFO("Set wifi to %s done", buf);

		mem_free(buf);
	}
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
main_sig_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
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

	INFO("Starting wifi_enable ...");

	char *path_enable = mem_printf("%s/%s%s", TRUSTME_COM_WIFI_PATH, "wifi_enable_", DEFAULT_WIFI_IFNAME);

	event_init();

	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sig_cb, NULL);
	event_add_signal(sig_int);

	int wifi_enable_sock = sock_unix_create_and_connect(SOCK_SEQPACKET, path_enable);
	if (wifi_enable_sock < 0) {
		FATAL_ERRNO("Could not create and connect UNIX domain socket: %s", path_enable);
		return -1;
	}
	INFO("Connection to wpad on %s established", path_enable);

	event_io_t *event_ctrl = event_io_new(wifi_enable_sock, EVENT_IO_READ, wifi_enable_cb_recv, NULL);
	event_add_io(event_ctrl);

	INFO("Starting event loop ...");
	event_loop();

	mem_free(path_enable);
	return 0;
}

