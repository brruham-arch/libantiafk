#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

static FILE* g_logFile = nullptr;
static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK v6.2 ===\n"); fflush(g_logFile); }
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

// ─── ModInfo ──────────────────────────────────────────────
struct ModInfo_t {
    unsigned int handlerVer;
    const char*  id, *name, *version, *author;
    unsigned int flags;
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "6.2", "brruham-arch", 0
};

typedef int (*DobbyHook_t)(void*, void*, void**);
static DobbyHook_t DobbyHook = nullptr;

// ─── Pause state ──────────────────────────────────────────
// IsAndroidPaused: berubah saat tombol Home fisik ditekan
static volatile int*     g_isAndroidPaused = nullptr;
// m_UserPause: berubah saat player buka map / pause menu in-game
static volatile uint8_t* g_userPause       = nullptr;

// ─── Network state ────────────────────────────────────────
static pthread_mutex_t g_netMutex      = PTHREAD_MUTEX_INITIALIZER;
static int             g_sockFd        = -1;
static struct sockaddr g_serverAddr;
static socklen_t       g_serverAddrLen = 0;
static volatile bool   g_netCaptured   = false;

// ─── Last packet capture ──────────────────────────────────
#define MAX_PKT 512
static uint8_t  g_lastPkt[MAX_PKT];
static size_t   g_lastPktLen  = 0;
static bool     g_lastPktValid = false;
static size_t   g_maxPktLen   = 0;

static ssize_t (*sendto_orig)(int, const void*, size_t, int,
                               const struct sockaddr*, socklen_t) = nullptr;

// ─── Hook sendto ──────────────────────────────────────────
ssize_t sendto_hook(int sockfd, const void* buf, size_t len,
                    int flags, const struct sockaddr* dest, socklen_t addrlen)
{
    // Capture socket + server addr (ambil dari paket pertama yang valid)
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

    // Capture packet terpanjang sebagai kandidat OnFootSync/VehicleSync
    if (buf && len > 20 && len < MAX_PKT) {
        pthread_mutex_lock(&g_netMutex);
        if (len > g_maxPktLen) {
            g_maxPktLen = len;
            memcpy(g_lastPkt, buf, len);
            g_lastPktLen  = len;
            g_lastPktValid = true;
            LOGDBG("New max packet: len=%zu byte[0]=0x%02X", len, ((uint8_t*)buf)[0]);
        }
        pthread_mutex_unlock(&g_netMutex);
    }

    return sendto_orig(sockfd, buf, len, flags, dest, addrlen);
}

// ─── Helper: cek apakah sedang pause (Home ATAU map/menu) ─
static int isPaused() {
    int androidPaused = (g_isAndroidPaused) ? *g_isAndroidPaused : 0;
    int userPaused    = (g_userPause)        ? (int)*g_userPause  : 0;
    return androidPaused || userPaused;
}

// ─── Keepalive thread ─────────────────────────────────────
static void* keepaliveThread(void*) {
    LOG("Keepalive thread start");
    int lastState   = -1;
    int lastAndroid = -1;
    int lastUser    = -1;

    while (true) {
        struct timespec ts = {0, 500 * 1000000L};
        nanosleep(&ts, nullptr);

        if (!g_netCaptured) continue;

        int androidPaused = (g_isAndroidPaused) ? *g_isAndroidPaused : 0;
        int userPaused    = (g_userPause)        ? (int)*g_userPause  : 0;
        int paused        = androidPaused || userPaused;

        // Log perubahan state individual
        if (androidPaused != lastAndroid) {
            LOG("AndroidPaused: %d → %d", lastAndroid, androidPaused);
            lastAndroid = androidPaused;
        }
        if (userPaused != lastUser) {
            LOG("UserPause(map): %d → %d", lastUser, userPaused);
            lastUser = userPaused;
        }

        // Reset packet tracker saat resume supaya dapat packet fresh
        if (paused != lastState) {
            if (!paused) {
                pthread_mutex_lock(&g_netMutex);
                g_maxPktLen   = 0;
                g_lastPktValid = false;
                pthread_mutex_unlock(&g_netMutex);
                LOG("Packet tracker reset (resumed)");
            } else {
                LOG("Pause detected — keepalive aktif");
            }
            lastState = paused;
        }

        if (!paused) continue;

        // Ambil packet snapshot
        pthread_mutex_lock(&g_netMutex);
        bool   valid   = g_lastPktValid;
        uint8_t pkt[MAX_PKT];
        size_t  pktLen = g_lastPktLen;
        int     fd     = g_sockFd;
        struct sockaddr addr    = g_serverAddr;
        socklen_t       addrlen = g_serverAddrLen;
        if (valid) memcpy(pkt, g_lastPkt, pktLen);
        pthread_mutex_unlock(&g_netMutex);

        if (!valid) {
            LOGDBG("Belum ada packet ter-capture, skip");
            continue;
        }

        ssize_t sent = sendto_orig(fd, pkt, pktLen, 0, &addr, addrlen);
        LOGDBG("Replay: len=%zu sent=%zd errno=%d %s",
               pktLen, sent, errno, sent > 0 ? "OK" : "FAIL");
    }
    return nullptr;
}

// ─── Util: cari base address library ──────────────────────
static uintptr_t getLibBase(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, libname)) { sscanf(line, "%x-", &base); break; }
    fclose(f);
    return base;
}

// ─── AML Exports ──────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK v6.2 ===");
    LOG("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOG("OnModLoad start");

    // Load Dobby
    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) { LOGERR("libdobby: %s", dlerror()); return; }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) { LOGERR("DobbyHook not found"); return; }
    LOG("Dobby OK");

    // Cari base libGTASA.so
    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    if (gtasaBase) {
        // IsAndroidPaused — berubah saat Home ditekan
        g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
        LOG("IsAndroidPaused @ 0x%X = %d",
            (unsigned)(gtasaBase + 0x6855bc), (int)*g_isAndroidPaused);

        // CTimer::m_UserPause — berubah saat map/menu dibuka
        g_userPause = (volatile uint8_t*)(gtasaBase + 0x96b514);
        LOG("m_UserPause(map) @ 0x%X = %d",
            (unsigned)(gtasaBase + 0x96b514), (int)*g_userPause);
    } else {
        LOGERR("libGTASA.so tidak ketemu");
    }

    // Hook sendto
    int r = DobbyHook((void*)sendto, (void*)sendto_hook, (void**)&sendto_orig);
    LOG("Hook sendto: %s", r == 0 ? "OK" : "FAIL");

    // Jalankan keepalive thread (raw pthread — tidak ikut suspend NVThread)
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, keepaliveThread, nullptr);
    pthread_attr_destroy(&attr);

    LOG("=== AntiAFK v6.2 LOADED ===");
}
