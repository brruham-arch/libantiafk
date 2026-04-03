#include <android/log.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG     "AntiAFK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── Minimal AML Interface ───────────────────────────────
// Sesuai reverse Burhan: aml->GetLib / aml->Hook
struct IAML {
    virtual uintptr_t   GetLib(const char* name)                                    = 0;
    virtual bool        Hook(void* addr, void* hook, void** orig)                   = 0;
    virtual uintptr_t   GetSym(uintptr_t lib, const char* sym)                      = 0;
    virtual bool        Unprot(uintptr_t addr, size_t len)                          = 0;
    virtual void        Write(uintptr_t addr, uintptr_t val, size_t len)            = 0;
    virtual void        Read(uintptr_t addr, uintptr_t* val, size_t len)            = 0;
    virtual void        PlaceBL(uintptr_t addr, uintptr_t dest)                     = 0;
    virtual void        PlaceB(uintptr_t addr, uintptr_t dest)                      = 0;
    virtual void        PlaceNOP(uintptr_t addr, size_t count)                      = 0;
};
static IAML* aml = nullptr;

// ─── ModInfo struct ──────────────────────────────────────
struct ModInfo_t {
    unsigned int  handlerVer;   // AML handler version
    const char*   id;
    const char*   name;
    const char*   version;
    const char*   author;
    unsigned int  flags;
};

static ModInfo_t g_modInfo = {
    1,                  // handlerVer
    "antiafk",          // id
    "Anti AFK",         // name
    "1.0",              // version
    "brruham-arch",     // author
    0                   // flags
};

// ─── State ───────────────────────────────────────────────
static uintptr_t g_sampBase = 0;
static bool      g_enabled  = true;

// ─── Offsets (libsamp.so) ────────────────────────────────
// Thumb function → offset | 1
#define AFK_HANDLER_OFF  0x1514D0   // mulai dari analisis objdump

// ─── Original pointers ───────────────────────────────────
static void (*AFKHandler_orig)()                              = nullptr;
static ssize_t (*sendto_orig)(int, const void*, size_t,
                               int, const struct sockaddr*,
                               socklen_t)                     = nullptr;

// ─── Hook 1: AFK Handler ─────────────────────────────────
// Fungsi yang memanggil afk_icon dan set AFK state.
// Kalau g_enabled → return early, AFK state tidak jalan.
void AFKHandler_hook() {
    if (g_enabled) {
        LOGI("AFK handler blocked");
        return;
    }
    if (AFKHandler_orig) AFKHandler_orig();
}

// ─── Hook 2: sendto filter ───────────────────────────────
// Fallback: drop packet UDP yang mengandung AFK marker.
// "0FAFK" di binary = byte { 0x30, 0x46, 0x41, 0x46, 0x4B }
// Atau sebagai packet ID check: 'A','F','K' setelah byte pertama.
ssize_t sendto_hook(int sockfd,
                    const void* buf, size_t len,
                    int flags,
                    const struct sockaddr* dest,
                    socklen_t addrlen)
{
    if (g_enabled && buf && len >= 4) {
        const uint8_t* d = (const uint8_t*)buf;
        // Cek signature AFK packet: cari 'A','F','K' dalam 8 byte pertama
        for (size_t i = 0; i < len && i < 8; i++) {
            if (d[i] == 'A' && i+2 < len &&
                d[i+1] == 'F' && d[i+2] == 'K') {
                // Drop → return len supaya caller tidak error
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
void OnModPreLoad(IAML* iaml) {
    aml = iaml;
    LOGI("AntiAFK: PreLoad OK, aml=%p", aml);
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    if (!aml) {
        LOGE("aml is null, abort");
        return;
    }

    // Dapatkan base libsamp.so
    g_sampBase = aml->GetLib("libsamp.so");
    if (!g_sampBase) {
        LOGE("libsamp.so not found!");
        return;
    }
    LOGI("libsamp.so base: 0x%X", (unsigned)g_sampBase);

    // ── Hook 1: AFK Handler function ──────────────────────
    // +1 = Thumb mode address
    uintptr_t afkAddr = g_sampBase + AFK_HANDLER_OFF + 1;
    if (aml->Hook((void*)afkAddr,
                  (void*)AFKHandler_hook,
                  (void**)&AFKHandler_orig)) {
        LOGI("Hook 1 OK: AFK handler @ 0x%X", (unsigned)afkAddr);
    } else {
        LOGE("Hook 1 FAIL @ 0x%X — akan pakai sendto saja", (unsigned)afkAddr);
    }

    // ── Hook 2: sendto (imported oleh libsamp.so) ─────────
    void* sendtoSym = (void*)aml->GetSym(g_sampBase, "sendto");
    if (!sendtoSym) {
        // Fallback: ambil dari libc langsung
        sendtoSym = (void*)sendto;
    }
    if (aml->Hook(sendtoSym,
                  (void*)sendto_hook,
                  (void**)&sendto_orig)) {
        LOGI("Hook 2 OK: sendto @ %p", sendtoSym);
    } else {
        LOGE("Hook 2 FAIL: sendto");
    }

    LOGI("AntiAFK v1.0 loaded. AFK state blocked.");
}
