#include <android/log.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define TAG     "AntiAFK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── ModInfo — SAMA PERSIS dengan versi pertama yang crash ───
// Versi pertama terbukti ter-load AML (crash di OnModLoad bukan di GetModInfo)
struct ModInfo_t {
    unsigned int  handlerVer;   // = 1, WAJIB di posisi pertama
    const char*   id;
    const char*   name;
    const char*   version;
    const char*   author;
    unsigned int  flags;        // = 0
};

static ModInfo_t g_modInfo = {
    1,
    "antiafk",
    "Anti AFK",
    "1.0",
    "brruham-arch",
    0
};

// ─── Offset AFK handler di libsamp.so ────────────────────
#define AFK_HANDLER_OFF  0x1514D0

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
static void    (*AFKHandler_orig)()                          = nullptr;
static ssize_t (*sendto_orig)(int, const void*, size_t,
                               int, const struct sockaddr*,
                               socklen_t)                    = nullptr;

// ─── Util: base library dari /proc/self/maps ─────────────
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

// ─── Konfirmasi visual: tulis file ke sdcard ─────────────
static void writeStatus(const char* msg) {
    FILE* f = fopen("/storage/emulated/0/Download/antiafk_status.txt", "a");
    if (f) {
        fprintf(f, "[AntiAFK] %s\n", msg);
        fclose(f);
    }
}

// ─── Hook 1: AFK Handler ─────────────────────────────────
void AFKHandler_hook() {
    LOGI("AFK handler blocked!");
    writeStatus("AFK blocked!");
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
        LOGE("DobbyHook symbol not found");
        writeStatus("ERROR: DobbyHook not found");
        return;
    }
    LOGI("Dobby OK");

    // Base libsamp.so
    uintptr_t sampBase = getLibBase("libsamp.so");
    if (!sampBase) {
        LOGE("libsamp.so base not found");
        writeStatus("ERROR: libsamp.so not found");
        return;
    }
    LOGI("libsamp.so base: 0x%X", (unsigned)sampBase);
    writeStatus("libsamp.so found");

    // Hook 1: AFK handler (Thumb +1)
    uintptr_t afkAddr = sampBase + AFK_HANDLER_OFF + 1;
    int r1 = DobbyHook((void*)afkAddr,
                       (void*)AFKHandler_hook,
                       (void**)&AFKHandler_orig);
    LOGI("Hook1 AFK: %s (0x%X)", r1 == 0 ? "OK" : "FAIL", (unsigned)afkAddr);
    writeStatus(r1 == 0 ? "Hook1 AFK: OK" : "Hook1 AFK: FAIL");

    // Hook 2: sendto
    int r2 = DobbyHook((void*)sendto,
                       (void*)sendto_hook,
                       (void**)&sendto_orig);
    LOGI("Hook2 sendto: %s", r2 == 0 ? "OK" : "FAIL");
    writeStatus(r2 == 0 ? "Hook2 sendto: OK" : "Hook2 sendto: FAIL");

    LOGI("AntiAFK v1.0 loaded!");
    writeStatus("=== AntiAFK v1.0 LOADED ===");
}
