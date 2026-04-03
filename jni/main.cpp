#include <android/log.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG     "AntiAFK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── ModInfo — tanpa handlerVer, sesuai AML 1.2.1 ───────
struct ModInfo_t {
    const char* id;
    const char* name;
    const char* version;
    const char* author;
};

static ModInfo_t g_modInfo = {
    "antiafk",
    "Anti AFK",
    "1.0",
    "brruham-arch"
};

// ─── Offset AFK handler di libsamp.so ───────────────────
#define AFK_HANDLER_OFF  0x1514D0   // Thumb → +1 saat digunakan

// ─── Dobby hook typedef ──────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
static void    (*AFKHandler_orig)()                             = nullptr;
static ssize_t (*sendto_orig)(int, const void*, size_t,
                               int, const struct sockaddr*,
                               socklen_t)                       = nullptr;

// ─── Util: baca base library dari /proc/self/maps ────────
static uintptr_t getLibBase(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname)) {
            sscanf(line, "%x-", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

// ─── Hook 1: AFK Handler ─────────────────────────────────
void AFKHandler_hook() {
    // Block AFK state — jangan panggil orig
    LOGI("AFK handler blocked");
}

// ─── Hook 2: sendto filter ───────────────────────────────
ssize_t sendto_hook(int sockfd,
                    const void* buf, size_t len,
                    int flags,
                    const struct sockaddr* dest,
                    socklen_t addrlen)
{
    if (buf && len >= 4) {
        const uint8_t* d = (const uint8_t*)buf;
        // Cari signature "AFK" dalam 8 byte pertama packet
        for (size_t i = 0; i < len && i < 8; i++) {
            if (d[i] == 'A' && (i+2) < len &&
                d[i+1] == 'F' && d[i+2] == 'K') {
                LOGI("AFK packet dropped (len=%zu)", len);
                return (ssize_t)len;
            }
        }
    }
    return sendto_orig(sockfd, buf, len, flags, dest, addrlen);
}

// ─── AML Required Exports ────────────────────────────────

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() {
    return &g_modInfo;
}

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    // Tidak ada parameter — sesuai requirements
    LOGI("AntiAFK: PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {

    // ── Load Dobby via dlopen ─────────────────────────────
    void* dobbyLib = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyLib) {
        LOGE("libdobby.so not found: %s", dlerror());
        return;
    }
    DobbyHook = (DobbyHook_t)dlsym(dobbyLib, "DobbyHook");
    if (!DobbyHook) {
        LOGE("DobbyHook symbol not found");
        return;
    }
    LOGI("Dobby loaded @ %p", (void*)DobbyHook);

    // ── Dapatkan base libsamp.so ──────────────────────────
    uintptr_t sampBase = getLibBase("libsamp.so");
    if (!sampBase) {
        LOGE("libsamp.so base not found in maps");
        return;
    }
    LOGI("libsamp.so base: 0x%X", (unsigned)sampBase);

    // ── Hook 1: AFK Handler (Thumb → +1) ─────────────────
    uintptr_t afkAddr = sampBase + AFK_HANDLER_OFF + 1;
    int r1 = DobbyHook((void*)afkAddr,
                       (void*)AFKHandler_hook,
                       (void**)&AFKHandler_orig);
    if (r1 == 0) {
        LOGI("Hook 1 OK: AFK handler @ 0x%X", (unsigned)afkAddr);
    } else {
        LOGE("Hook 1 FAIL (ret=%d) — offset mungkin meleset", r1);
    }

    // ── Hook 2: sendto ────────────────────────────────────
    void* sendtoPtr = (void*)sendto;
    int r2 = DobbyHook(sendtoPtr,
                       (void*)sendto_hook,
                       (void**)&sendto_orig);
    if (r2 == 0) {
        LOGI("Hook 2 OK: sendto @ %p", sendtoPtr);
    } else {
        LOGE("Hook 2 FAIL: sendto (ret=%d)", r2);
    }

    LOGI("AntiAFK v1.0 loaded!");
}
