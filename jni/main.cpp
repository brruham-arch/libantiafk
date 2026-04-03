#include <android/log.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define TAG     "AntiAFK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── ModInfo ─────────────────────────────────────────────
struct ModInfo_t {
    unsigned int  handlerVer;
    const char*   id;
    const char*   name;
    const char*   version;
    const char*   author;
    unsigned int  flags;
};

static ModInfo_t g_modInfo = {
    1,
    "antiafk",
    "Anti AFK",
    "1.0",
    "brruham-arch",
    0
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original sendto ─────────────────────────────────────
static ssize_t (*sendto_orig)(int, const void*, size_t,
                               int, const struct sockaddr*,
                               socklen_t) = nullptr;

// ─── Status file ─────────────────────────────────────────
static void writeStatus(const char* msg) {
    FILE* f = fopen("/storage/emulated/0/Download/antiafk_status.txt", "a");
    if (f) { fprintf(f, "[AntiAFK] %s\n", msg); fclose(f); }
}

// ─── Hook: sendto filter ─────────────────────────────────
// Drop packet UDP yang mengandung AFK signature
ssize_t sendto_hook(int sockfd,
                    const void* buf, size_t len,
                    int flags,
                    const struct sockaddr* dest,
                    socklen_t addrlen)
{
    if (buf && len >= 4) {
        const uint8_t* d = (const uint8_t*)buf;
        for (size_t i = 0; i < len && i < 8; i++) {
            if (d[i] == 'A' && (i+2) < len &&
                d[i+1] == 'F' && d[i+2] == 'K') {
                LOGI("AFK packet dropped (len=%zu)", len);
                writeStatus("AFK packet dropped!");
                return (ssize_t)len;
            }
        }
    }
    return sendto_orig(sockfd, buf, len, flags, dest, addrlen);
}

// ─── AML Exports ─────────────────────────────────────────

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() {
    return &g_modInfo;
}

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    LOGI("PreLoad OK");
    writeStatus("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOGI("OnModLoad start");
    writeStatus("OnModLoad start");

    // Load Dobby
    void* dobbyLib = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyLib) {
        LOGE("libdobby.so not found: %s", dlerror());
        writeStatus("ERROR: libdobby.so not found");
        return;
    }
    DobbyHook = (DobbyHook_t)dlsym(dobbyLib, "DobbyHook");
    if (!DobbyHook) {
        LOGE("DobbyHook not found");
        writeStatus("ERROR: DobbyHook symbol not found");
        return;
    }
    writeStatus("Dobby OK");

    // ── Hook: sendto saja dulu ────────────────────────────
    // Hook 1 (AFK handler direct) di-skip dulu karena
    // offset 0x1514D0 perlu diverifikasi ulang via objdump -M thumb
    int r = DobbyHook((void*)sendto,
                      (void*)sendto_hook,
                      (void**)&sendto_orig);
    LOGI("Hook sendto: %s", r == 0 ? "OK" : "FAIL");
    writeStatus(r == 0 ? "Hook sendto: OK" : "Hook sendto: FAIL");

    LOGI("AntiAFK v1.0 loaded! (sendto filter active)");
    writeStatus("=== AntiAFK v1.0 LOADED ===");
}
