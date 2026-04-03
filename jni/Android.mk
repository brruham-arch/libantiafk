LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE           := libantiafk
LOCAL_SRC_FILES        := main.cpp

LOCAL_CPPFLAGS         := -std=c++17 -O2 -fvisibility=hidden
LOCAL_LDFLAGS          := -Wl,--exclude-libs,ALL

# Wajib: static libstdc++ agar tidak depend ke shared STL
LOCAL_LDLIBS           := -llog -ldl

LOCAL_STATIC_LIBRARIES := stlport_static

include $(BUILD_SHARED_LIBRARY)
