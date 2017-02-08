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
#include "common/file.h"

#include <cutils/properties.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/resource.h>

#define RESOLV_CONF "/data/misc/dhcp/dnsmasq.resolv.conf"
#define DNSMASQ_PID_FILE "/data/misc/dhcp/dnsmasq.pid"

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

/******************************************************************************/

static pid_t
get_pid_from_file(const char *file_name)
{
	FILE *pid_file;
	pid_t pid;

	pid_file = fopen(file_name, "r");
	if (pid_file == NULL)
		return 0;

	if (fscanf(pid_file, "%d", &pid) <= 0) {
		fclose(pid_file);
		return 0;
	}

	fclose(pid_file);
	return pid;
}

int
main(UNUSED int argc,char **argv)
{
	logf_handler_t *h;

	h = logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	h = logf_register(&logf_file_write, stdout);
	logf_handler_set_prio(h, LOGF_PRIO_DEBUG);

	main_core_dump_enable();

	char dns1[PROP_VALUE_MAX];
	char dns2[PROP_VALUE_MAX];

        if (property_get("net.dns1", dns1, "")) {
		DEBUG("1: nameserver %s\n", dns1);
		if (property_get("net.dns2", dns2, "")) {
			DEBUG("2: nameserver %s\n", dns2);
			file_printf(RESOLV_CONF, "nameserver %s\nnameserver %s\n", dns1, dns2);
		} else
			file_printf(RESOLV_CONF, "nameserver %s\n", dns1);
	} else {
		ERROR("cannot get dns property!");
		return -1;
	}


	// Inform dnsmasq about change of resolv.conf
	pid_t pid = get_pid_from_file(DNSMASQ_PID_FILE);
	if (!pid) {
		WARN_ERRNO("cannot read dnsmasq's pid_file!");
		return 0;
	}
	// SIGHUP causes dnsmasq ro re-read resolv.conf if dnsmasq is runnign with --no-poll
	if (kill(pid, SIGHUP))
		WARN_ERRNO("cannot reload dnsmasq!");

	return 0;
}

