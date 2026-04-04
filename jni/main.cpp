#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>
#include <math.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

// ─── Logger ───────────────────────────────────────────────
static FILE* g_logFile = nullptr;
static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK v6.0 ===\n"); fflush(g_logFile); }
}
static void logWrite(const char* level, const char* fmt, ...) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm* t = localtime(&ts.tv_sec);
    char tbuf[32]; strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
    char mbuf[512]; va_list a; va_start(a, fmt); vsnprintf(mbuf, sizeof(mbuf), fmt, a); va_end(a);
    if (g_logFile) { fprintf(g_logFile, "[%s.%03ld] [%s] %s\n", tbuf, ts.tv_nsec/1000000, level, mbuf); fflush(g_logFile); }
    __android_log_print(strcmp(level,"ERR")==0?ANDROID_LOG_ERROR:ANDROID_LOG_INFO, TAG, "%s", mbuf);
}
#define LOG(...)    logWrite("INF", __VA_ARGS__)
#define LOGERR(...) logWrite("ERR", __VA_ARGS__)
#define LOGDBG(...) logWrite("DBG", __VA_ARGS__)

// ─── ModInfo ─────────────────────────────────────────────
struct ModInfo_t {
    unsigned int handlerVer;
    const char*  id, *name, *version, *author;
    unsigned int flags;
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "6.0", "brruham-arch", 0
};

// ─── Mini BitStream ───────────────────────────────────────
struct BitStream {
    uint8_t  buf[128];
    uint32_t bitPos;  // posisi bit saat ini

    BitStream() : bitPos(0) { memset(buf, 0, sizeof(buf)); }

    void writeBits(uint32_t val, int bits) {
        for (int i = 0; i < bits; i++) {
            uint32_t byteIdx = bitPos / 8;
            uint32_t bitIdx  = 7 - (bitPos % 8); // MSB first (RakNet)
            if (val & (1u << (bits - 1 - i)))
                buf[byteIdx] |= (1u << bitIdx);
            bitPos++;
        }
    }

    void writeU8(uint8_t v)   { writeBits(v, 8); }
    void writeU16(uint16_t v) { writeBits(v, 16); }
    void writeU32(uint32_t v) { writeBits(v, 32); }

    void writeFloat(float v) {
        uint32_t tmp;
        memcpy(&tmp, &v, 4);
        writeU32(tmp);
    }

    void writeI16(int16_t v)  { writeBits((uint32_t)(uint16_t)v, 16); }

    uint32_t byteSize() { return (bitPos + 7) / 8; }
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void*, void*, void**);
static DobbyHook_t DobbyHook = nullptr;

// ─── Network capture ──────────────────────────────────────
static pthread_mutex_t g_netMutex      = PTHREAD_MUTEX_INITIALIZER;
static int             g_sockFd        = -1;
static struct sockaddr g_serverAddr;
static socklen_t       g_serverAddrLen = 0;
static volatile bool   g_netCaptured   = false;

// ─── Last known player state ──────────────────────────────
// Diupdate dari packet 207 asli saat game normal
static pthread_mutex_t g_stateMutex = PTHREAD_MUTEX_INITIALIZER;
struct PlayerState {
    float x, y, z;
    float qw, qx, qy, qz;
    uint8_t health, armour;
    uint8_t weaponId;
    bool valid;
};
static PlayerState g_state = {0,0,0, 1,0,0,0, 100,0, 0, false};

// ─── IsAndroidPaused pointer ──────────────────────────────
static volatile int* g_isAndroidPaused = nullptr;

static ssize_t (*sendto_orig)(int, const void*, size_t, int,
                               const struct sockaddr*, socklen_t) = nullptr;

// ─── Build OnFootSync packet (ID 207) ────────────────────
// Struktur: https://github.com/Brunoo16/samp-packet-list/wiki
static uint32_t buildOnFootSync(uint8_t* outBuf, const PlayerState& s) {
    BitStream bs;

    bs.writeU8(207);           // Packet_ID
    bs.writeU16(0);            // lrKey  (0 = tidak ada input)
    bs.writeU16(0);            // udKey
    bs.writeU16(0);            // keys
    bs.writeFloat(s.x);        // X
    bs.writeFloat(s.y);        // Y
    bs.writeFloat(s.z);        // Z
    bs.writeFloat(s.qw);       // quat_w
    bs.writeFloat(s.qx);       // quat_x
    bs.writeFloat(s.qy);       // quat_y
    bs.writeFloat(s.qz);       // quat_z
    bs.writeU8(s.health);      // health
    bs.writeU8(s.armour);      // armour
    bs.writeBits(0, 2);        // additional_key (2 bits)
    bs.writeBits(s.weaponId & 0x3F, 6); // weapon_id (6 bits)
    bs.writeU8(0);             // special_action
    bs.writeFloat(0.0f);       // velocity_x
    bs.writeFloat(0.0f);       // velocity_y
    bs.writeFloat(0.0f);       // velocity_z
    bs.writeFloat(0.0f);       // surfing_offset_x
    bs.writeFloat(0.0f);       // surfing_offset_y
    bs.writeFloat(0.0f);       // surfing_offset_z
    bs.writeU16(0xFFFF);       // surfing_vehicle_id (0xFFFF = none)
    bs.writeI16(0);            // animation_id
    bs.writeI16(0);            // animation_flags

    uint32_t size = bs.byteSize();
    memcpy(outBuf, bs.buf, size);
    return size;
}

// ─── Hook sendto ─────────────────────────────────────────
ssize_t sendto_hook(int sockfd, const void* buf, size_t len,
                    int flags, const struct sockaddr* dest, socklen_t addrlen)
{
    // Capture socket
    if (!g_netCaptured && dest && addrlen > 0 && len > 0) {
        pthread_mutex_lock(&g_netMutex);
        if (!g_netCaptured) {
            g_sockFd = sockfd;
            memcpy(&g_serverAddr, dest, addrlen);
            g_serverAddrLen = addrlen;
            g_netCaptured = true;
            LOG("Network captured: sockfd=%d", sockfd);
        }
        pthread_mutex_unlock(&g_netMutex);
    }

    // Sniff packet 207 — update last known player state
    // Packet 207 cukup panjang (>30 bytes)
    if (buf && len > 30) {
        const uint8_t* d = (const uint8_t*)buf;
        if (d[0] == 207) {
            // Parse posisi dari packet asli (offset setelah header bits)
            // Setelah ID(1) + lrKey(2) + udKey(2) + keys(2) = 7 bytes
            // lalu X(4) Y(4) Z(4)
            if (len >= 19) {
                pthread_mutex_lock(&g_stateMutex);
                memcpy(&g_state.x,  d + 7,  4);
                memcpy(&g_state.y,  d + 11, 4);
                memcpy(&g_state.z,  d + 15, 4);
                g_state.health  = len > 35 ? d[35] : 100;
                g_state.armour  = len > 36 ? d[36] : 0;
                g_state.valid   = true;
                pthread_mutex_unlock(&g_stateMutex);
                LOGDBG("State updated: x=%.1f y=%.1f z=%.1f",
                       g_state.x, g_state.y, g_state.z);
            }
        }
    }

    return sendto_orig(sockfd, buf, len, flags, dest, addrlen);
}

// ─── Keepalive thread ────────────────────────────────────
static void* keepaliveThread(void*) {
    LOG("Keepalive thread start");
    int lastState = -1;

    while (true) {
        struct timespec ts = {0, 500 * 1000000L};
        nanosleep(&ts, nullptr);

        if (!g_isAndroidPaused || !g_netCaptured) continue;

        int paused = *g_isAndroidPaused;
        if (paused != lastState) {
            LOG("Pause state: %d → %d", lastState, paused);
            lastState = paused;
        }
        if (!paused) continue;

        // Ambil state terakhir
        pthread_mutex_lock(&g_stateMutex);
        PlayerState s = g_state;
        pthread_mutex_unlock(&g_stateMutex);

        if (!s.valid) {
            LOGDBG("State belum valid, skip");
            continue;
        }

        // Build dan kirim OnFootSync
        uint8_t pktBuf[128];
        uint32_t pktLen = buildOnFootSync(pktBuf, s);

        pthread_mutex_lock(&g_netMutex);
        int fd = g_sockFd;
        struct sockaddr addr = g_serverAddr;
        socklen_t addrlen    = g_serverAddrLen;
        pthread_mutex_unlock(&g_netMutex);

        ssize_t sent = sendto_orig(fd, pktBuf, pktLen, 0, &addr, addrlen);
        LOGDBG("OnFootSync sent: %s (len=%u sent=%zd)",
               sent > 0 ? "OK" : "FAIL", pktLen, sent);
    }
    return nullptr;
}

static uintptr_t getLibBase(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, libname)) { sscanf(line, "%x-", &base); break; }
    fclose(f);
    return base;
}

// ─── AML Exports ─────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK v6.0 ===");
    LOG("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOG("OnModLoad start");

    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) { LOGERR("libdobby: %s", dlerror()); return; }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) { LOGERR("DobbyHook not found"); return; }
    LOG("Dobby OK");

    // IsAndroidPaused pointer
    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    if (gtasaBase) {
        g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
        LOG("IsAndroidPaused @ 0x%X = %d",
            (unsigned)(gtasaBase + 0x6855bc), (int)*g_isAndroidPaused);
    } else LOGERR("libGTASA.so base tidak ketemu");

    // Hook sendto
    int r = DobbyHook((void*)sendto, (void*)sendto_hook, (void**)&sendto_orig);
    LOG("Hook sendto: %s", r==0?"OK":"FAIL");

    // Keepalive thread
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, keepaliveThread, nullptr);
    pthread_attr_destroy(&attr);
    LOG("=== AntiAFK v6.0 LOADED ===");
}
