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
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK v5.2 ===\n"); fflush(g_logFile); }
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

struct ModInfo_t {
    unsigned int handlerVer;
    const char*  id;
    const char*  name;
    const char*  version;
    const char*  author;
    unsigned int flags;
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "5.2", "brruham-arch", 0
};

typedef int (*DobbyHook_t)(void*, void*, void**);
static DobbyHook_t DobbyHook = nullptr;

// ─── Network capture ──────────────────────────────────────
static pthread_mutex_t g_netMutex    = PTHREAD_MUTEX_INITIALIZER;
static int             g_sockFd      = -1;
static struct sockaddr g_serverAddr;
static socklen_t       g_serverAddrLen = 0;
static volatile bool   g_netCaptured   = false;

// ─── Pointer langsung ke IsAndroidPaused global var ───────
// Offset 0x6855bc dari nm: 006855bc D IsAndroidPaused
static volatile int* g_isAndroidPaused = nullptr;

static ssize_t (*sendto_orig)(int, const void*, size_t, int,
                               const struct sockaddr*, socklen_t) = nullptr;

static const uint8_t PING_PACKET[] = { 0x00 };

ssize_t sendto_hook(int sockfd, const void* buf, size_t len,
                    int flags, const struct sockaddr* dest, socklen_t addrlen)
{
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
    return sendto_orig(sockfd, buf, len, flags, dest, addrlen);
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

// ─── Keepalive thread ────────────────────────────────────
// Poll IsAndroidPaused langsung dari memori — tidak perlu hook
static void* keepaliveThread(void*) {
    LOG("Keepalive thread start — polling IsAndroidPaused");
    int lastState = -1;

    while (true) {
        struct timespec ts = {0, 500 * 1000000L};
        nanosleep(&ts, nullptr);

        if (!g_isAndroidPaused || !g_netCaptured) continue;

        int paused = *g_isAndroidPaused;

        // Log transisi state
        if (paused != lastState) {
            LOG("IsAndroidPaused berubah: %d → %d", lastState, paused);
            lastState = paused;
        }

        if (!paused) continue; // game normal, tidak perlu keepalive

        // Game pause — kirim ping ke server
        pthread_mutex_lock(&g_netMutex);
        int fd = g_sockFd;
        struct sockaddr addr = g_serverAddr;
        socklen_t addrlen    = g_serverAddrLen;
        pthread_mutex_unlock(&g_netMutex);

        ssize_t sent = sendto_orig(fd, PING_PACKET, sizeof(PING_PACKET),
                                   0, &addr, addrlen);
        LOGDBG("Keepalive ping: %s (sent=%zd errno=%d)",
               sent > 0 ? "OK" : "FAIL", sent, errno);
    }
    return nullptr;
}

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK v5.2 ===");
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

    // Ambil pointer IsAndroidPaused langsung dari memori
    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    if (gtasaBase) {
        g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
        LOG("IsAndroidPaused @ 0x%X = %d", 
            (unsigned)(gtasaBase + 0x6855bc), (int)*g_isAndroidPaused);
    } else {
        LOGERR("libGTASA.so base tidak ketemu!");
    }

    // Hook sendto untuk capture socket
    int r = DobbyHook((void*)sendto, (void*)sendto_hook, (void**)&sendto_orig);
    LOG("Hook sendto: %s", r==0?"OK":"FAIL");

    // Spawn raw pthread
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r2 = pthread_create(&thread, &attr, keepaliveThread, nullptr);
    pthread_attr_destroy(&attr);
    LOG("Keepalive thread: %s", r2==0?"OK":"FAIL");

    LOG("=== AntiAFK v5.2 LOADED ===");
}
