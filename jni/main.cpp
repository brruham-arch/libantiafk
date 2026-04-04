#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

// ─── Logger ───────────────────────────────────────────────
static FILE* g_logFile = nullptr;
static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK v5.1 ===\n"); fflush(g_logFile); }
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

// ─── ModInfo — struct format yang TERBUKTI ter-load ───────
// Referensi: crash log pertama, mod muncul di loaded list
struct ModInfo_t {
    unsigned int  handlerVer;  // = 1
    const char*   id;
    const char*   name;
    const char*   version;
    const char*   author;
    unsigned int  flags;       // = 0
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "5.1", "brruham-arch", 0
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void*, void*, void**);
static DobbyHook_t DobbyHook = nullptr;

// ─── Network capture ──────────────────────────────────────
static pthread_mutex_t g_netMutex    = PTHREAD_MUTEX_INITIALIZER;
static int             g_sockFd      = -1;
static struct sockaddr g_serverAddr;
static socklen_t       g_serverAddrLen = 0;
static volatile bool   g_netCaptured   = false;

// ─── Pause state ─────────────────────────────────────────
static volatile int g_isPaused = 0;

// ─── Original pointers ───────────────────────────────────
static ssize_t (*sendto_orig)(int, const void*, size_t, int,
                               const struct sockaddr*, socklen_t) = nullptr;
static void    (*SetAndroidPaused_orig)(int)                      = nullptr;

// ─── Minimal RakNet ping ─────────────────────────────────
static const uint8_t PING_PACKET[] = { 0x00 };

// ─── Hook: sendto — capture socket info ──────────────────
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

// ─── Hook: SetAndroidPaused ───────────────────────────────
void SetAndroidPaused_hook(int isPaused) {
    g_isPaused = isPaused;
    LOG("SetAndroidPaused(%d)", isPaused);
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
}

// ─── Keepalive thread (raw pthread, bukan NVThread) ───────
static void* keepaliveThread(void*) {
    LOG("Keepalive thread start");
    while (true) {
        struct timespec ts = {0, 500 * 1000000L};
        nanosleep(&ts, nullptr);

        if (!g_isPaused || !g_netCaptured) continue;

        pthread_mutex_lock(&g_netMutex);
        int fd = g_sockFd;
        struct sockaddr addr = g_serverAddr;
        socklen_t addrlen    = g_serverAddrLen;
        pthread_mutex_unlock(&g_netMutex);

        ssize_t sent = sendto_orig(fd, PING_PACKET, sizeof(PING_PACKET),
                                   0, &addr, addrlen);
        LOGDBG("Keepalive: %s (sent=%zd)", sent>0?"OK":"FAIL", sent);
    }
    return nullptr;
}

// ─── Util ─────────────────────────────────────────────────
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
    LOG("=== AntiAFK v5.1 ===");
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

    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);

    // Hook SetAndroidPaused
    void* sym = gtasaLib ? dlsym(gtasaLib, "_Z16SetAndroidPausedi") : nullptr;
    if (!sym && gtasaBase) sym = (void*)(gtasaBase + 0x269ae4);
    if (sym) {
        int r = DobbyHook(sym, (void*)SetAndroidPaused_hook, (void**)&SetAndroidPaused_orig);
        LOG("Hook SetAndroidPaused: %s", r==0?"OK":"FAIL");
    }

    // Hook sendto
    int r2 = DobbyHook((void*)sendto, (void*)sendto_hook, (void**)&sendto_orig);
    LOG("Hook sendto: %s", r2==0?"OK":"FAIL");

    // Spawn raw pthread keepalive
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r3 = pthread_create(&thread, &attr, keepaliveThread, nullptr);
    pthread_attr_destroy(&attr);
    LOG("Keepalive thread: %s", r3==0?"OK":"FAIL");

    LOG("=== AntiAFK v5.1 LOADED ===");
}
