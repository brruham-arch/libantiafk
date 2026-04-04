#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

static FILE* g_logFile = nullptr;
static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK v6.4 ===\n"); fflush(g_logFile); }
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
    1, "antiafk", "Anti AFK Pause", "6.4", "brruham-arch", 0
};

typedef int (*DobbyHook_t)(void*, void*, void**);
static DobbyHook_t DobbyHook = nullptr;

// ─── Pause state (untuk log monitoring) ───────────────────
static volatile int*     g_isAndroidPaused = nullptr;
static volatile uint8_t* g_userPause       = nullptr;

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

// ─── Hook AndroidPaused() ─────────────────────────────────
// AndroidPaused() adalah fungsi yang di-poll NVThread system
// untuk decide apakah suspend semua thread.
// Kalau kita return 0 selalu → tidak ada thread yang di-suspend
// → RakNet network thread SA-MP tetap jalan saat pause.
//
// AndroidPaused() @ libGTASA.so + 0x269ad4
// Signature: int AndroidPaused(void)
//
static int (*AndroidPaused_orig)() = nullptr;
static int AndroidPaused_hook() {
    // Selalu report "tidak paused" ke NVThread system
    // sehingga network thread SA-MP tidak di-suspend
    return 0;
}

// ─── Monitor thread (log state perubahan) ─────────────────
static void* monitorThread(void*) {
    int lastAndroid = -1;
    int lastUser    = -1;
    while (true) {
        struct timespec ts = {0, 500 * 1000000L};
        nanosleep(&ts, nullptr);

        int androidPaused = g_isAndroidPaused ? *g_isAndroidPaused : 0;
        int userPaused    = g_userPause        ? (int)*g_userPause  : 0;

        if (androidPaused != lastAndroid) {
            LOG("IsAndroidPaused: %d → %d", lastAndroid, androidPaused);
            lastAndroid = androidPaused;
        }
        if (userPaused != lastUser) {
            LOG("UserPause(map): %d → %d", lastUser, userPaused);
            lastUser = userPaused;
        }
    }
    return nullptr;
}

// ─── AML Exports ──────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK v6.4 ===");
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
    if (!gtasaBase) { LOGERR("libGTASA.so tidak ketemu"); return; }
    LOG("libGTASA.so base: 0x%X", (unsigned)gtasaBase);

    // Setup pointer untuk monitoring
    g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
    g_userPause       = (volatile uint8_t*)(gtasaBase + 0x96b514);
    LOG("IsAndroidPaused @ 0x%X = %d",
        (unsigned)(gtasaBase + 0x6855bc), (int)*g_isAndroidPaused);
    LOG("m_UserPause     @ 0x%X = %d",
        (unsigned)(gtasaBase + 0x96b514), (int)*g_userPause);

    // Hook AndroidPaused() — Thumb function, butuh +1
    // Offset dari nm: 0x269ad4
    uintptr_t androidPausedAddr = gtasaBase + 0x269ad4;
    int r = DobbyHook(
        (void*)(androidPausedAddr + 1),   // +1 = Thumb mode
        (void*)AndroidPaused_hook,
        (void**)&AndroidPaused_orig
    );
    LOG("Hook AndroidPaused @ 0x%X: %s",
        (unsigned)androidPausedAddr, r == 0 ? "OK" : "FAIL");

    if (r != 0) {
        // Fallback: patch manual — tulis "MOV R0, #0 / BX LR" (Thumb)
        // MOV R0, #0 = 0x2000, BX LR = 0x4770
        LOG("Dobby gagal, coba manual patch...");
        void* target = (void*)androidPausedAddr;
        uintptr_t page = androidPausedAddr & ~0xFFF;
        if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            uint16_t* p = (uint16_t*)target;
            p[0] = 0x2000; // MOV R0, #0
            p[1] = 0x4770; // BX LR
            __builtin___clear_cache((char*)target, (char*)target + 4);
            LOG("Manual patch AndroidPaused: OK");
        } else {
            LOGERR("mprotect FAIL errno=%d", errno);
        }
    }

    // Monitor thread untuk log state
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, monitorThread, nullptr);
    pthread_attr_destroy(&attr);

    LOG("=== AntiAFK v6.4 LOADED ===");
    LOG("Strategy: AndroidPaused() hook → NVThread tidak suspend SA-MP");
}
