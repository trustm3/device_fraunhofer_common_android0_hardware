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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#define LOG_TAG "PowerHALProxy"
#include <utils/Log.h>

#include <hardware/hardware.h>
#include <hardware/power.h>

#define MAX_LENGTH	   50
#define BOOST_SOCKET	   "/dev/socket/pb"
#define BOOST_PROXY_SOCKET "/data/trustme-com/power/pb"

int main(int argc, char *argv[])
{
	struct sockaddr_un real_addr, proxy_addr;
	char data[MAX_LENGTH];
	int real_sockfd, proxy_sockfd;
	int err, n;

	/* Proxy power boost socket
	 */
	err = unlink(BOOST_PROXY_SOCKET);
	if (err && errno != ENOENT)
		ALOGE("couldn't unlink %s: %s", BOOST_PROXY_SOCKET, strerror(errno));
	proxy_sockfd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (proxy_sockfd < 0) {
		ALOGE("%s: couldn't create proxy pb socket: %s", __func__, strerror(errno));
		return -1;
	}
	memset(&proxy_addr, 0, sizeof(struct sockaddr_un));
	proxy_addr.sun_family = AF_UNIX;
	snprintf(proxy_addr.sun_path, UNIX_PATH_MAX, BOOST_PROXY_SOCKET);
	err = bind(proxy_sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
	if (err) {
		ALOGE("couldn't bind proxy pb socket: %s", strerror(errno));
		goto err_proxy_sockfd;
	}
	chown(proxy_addr.sun_path, 0, 1000);
	chmod(proxy_addr.sun_path, 0666);

	/* Real power boost socket
	 */
	real_sockfd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (real_sockfd < 0) {
		ALOGE("%s: couldn't create real pb socket: %s", __func__, strerror(errno));
		goto err_real_sockfd;
	}
	memset(&real_addr, 0, sizeof(struct sockaddr_un));
	real_addr.sun_family = AF_UNIX;
	snprintf(real_addr.sun_path, UNIX_PATH_MAX, BOOST_SOCKET);

	while (1) {
		n = recv(proxy_sockfd, data, sizeof(data), 0);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) /* restart */
				continue;
			ALOGE("%s: couldn't recv from proxy pb socket: %s",
			      __func__, strerror(errno));
			break;
		}
		ALOGV("%s: forward %d bytes", __func__, n);
		n = sendto(real_sockfd, data, n, 0,
			   (const struct sockaddr *)&real_addr, sizeof(struct sockaddr_un));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == ENOENT) /* restart */
				continue;
			ALOGE("%s: couldn't send to real pb socket: %s",
			      __func__, strerror(errno));
			break;
		}
	}


err_real_sockfd:
	close(real_sockfd);

err_proxy_sockfd:
	close(proxy_sockfd);

	ALOGE("exiting main() unexpectedly...");
	return -1;
}
