#
# This file is part of trust|me
# Copyright(c) 2013 - 2017 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2 (GPL 2), as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
#

LOCAL_PATH := $(call my-dir)

ifneq ($(TARGET_SIMULATOR),true)

PLATFORM_VERSION_MAJOR = $(shell echo $(PLATFORM_VERSION) | cut -f1 -d.)

# HAL module implemenation, not prelinked, and stored in
# hw/<GPS_HARDWARE_MODULE_ID>.<ro.product.board>.so
include $(CLEAR_VARS)

LOCAL_MODULE := gps-client.default

LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw

LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS := -pedantic -Wall -Wextra -Werror -std=c99 \
	-DPLATFORM_VERSION_MAJOR=$(PLATFORM_VERSION_MAJOR)

LOCAL_SRC_FILES := gps-client.c gps-common.c

LOCAL_SHARED_LIBRARIES := liblog libcutils libdl
LOCAL_PRELINK_MODULE := false

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CFLAGS := -pedantic -Wall -Wextra -Werror -std=c99 \
	-DPLATFORM_VERSION_MAJOR=$(PLATFORM_VERSION_MAJOR)

LOCAL_SRC_FILES:= gps-server.c gps-common.c

LOCAL_SHARED_LIBRARIES := libcutils libhardware

LOCAL_MODULE:= gps-server

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

endif # !TARGET_SIMULATOR
