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

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := wpad
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/file.c \
	common/fd.c \
	wpad.c

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libwpa_client \
	liblog

LOCAL_C_INCLUDES := external/wpa_supplicant_8/src/common

LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=c99

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := wpa_proxy
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/file.c \
	common/fd.c \
	wpa_proxy.c

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog

LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=c99

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := wifi_enable
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/file.c \
	common/fd.c \
	wifi_enable.c

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog

LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=c99

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)
