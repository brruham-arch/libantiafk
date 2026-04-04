#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

// ─── ModInfo ─────────────────────────────────────────────
struct ModInfo_t {
    unsigned int handlerVer;
    const char*  id;
    const char*  name;
    const char*  version;
    const char*  author;
    unsigned int flags;
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "3.1", "brruham-arch", 0
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
static int  (*AndroidPaused_orig)()       = nullptr;
static void (*SetAndroidPaused_orig)(int) = nullptr;

// ─── State ───────────────────────────────────────────────
static volatile int* g_isAndroidPaused = nullptr;
// Flag: aktifkan bypass hanya setelah game fully loaded
// Delay 10 detik dari launch agar init game selesai dulu
static volatile bool g_bypassActive = false;

// ─── Realtime Logger ─────────────────────────────────────
static FILE* g_logFile = nullptr;

static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) {
        fprintf(g_logFile, "=== AntiAFK Log v3.1 ===\n");
        fflush(g_logFile);
    }
}

static void logWrite(const char* level, const char* fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm* t = localtime(&ts.tv_sec);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
    char mbuf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(mbuf, sizeof(mbuf), fmt, args);
    va_end(args);
    if (g_logFile) {
        fprintf(g_logFile, "[%s.%03ld] [%s] %s\n",
                tbuf, ts.tv_nsec/1000000, level, mbuf);
        fflush(g_logFile);
    }
    __android_log_print(
        strcmp(level,"ERR")==0 ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO,
        TAG, "%s", mbuf);
}

#define LOG(...)    logWrite("INF", __VA_ARGS__)
#define LOGERR(...) logWrite("ERR", __VA_ARGS__)
#define LOGDBG(...) logWrite("DBG", __VA_ARGS__)

// ─── Util ─────────────────────────────────────────────────
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

// ─── Hook: AndroidPaused() ───────────────────────────────
int AndroidPaused_hook() {
    int realVal = AndroidPaused_orig ? AndroidPaused_orig() : 0;

    // Bypass hanya aktif setelah game selesai init
    if (!g_bypassActive) {
        return realVal; // jangan ganggu saat init
    }

    // Log hanya saat transisi
    static int lastVal = -1;
    if (realVal != lastVal) {
        LOG("AndroidPaused() = %d → return 0 (bypass active)", realVal);
        lastVal = realVal;
    }
    return 0;
}

// ─── Hook: SetAndroidPaused(int) ─────────────────────────
void SetAndroidPaused_hook(int isPaused) {
    if (g_bypassActive) {
        LOG("SetAndroidPaused(%d) intercepted", isPaused);
    }
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
}

// ─── Watchdog thread ─────────────────────────────────────
static void* watchdogThread(void*) {
    // Tunggu 10 detik dulu → game pasti sudah selesai loading
    LOG("Watchdog: menunggu 10 detik sebelum aktif...");
    struct timespec delay = { 10, 0 };
    nanosleep(&delay, nullptr);

    g_bypassActive = true;
    LOG("Watchdog: AKTIF — bypass pause dimulai");

    while (true) {
        if (g_isAndroidPaused && *g_isAndroidPaused != 0) {
            LOGDBG("Watchdog: paksa IsAndroidPaused = 0");
            *g_isAndroidPaused = 0;
        }
        struct timespec ts = { 0, 100 * 1000000 }; // 100ms
        nanosleep(&ts, nullptr);
    }
    return nullptr;
}

// ─── AML Exports ─────────────────────────────────────────

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK Pause v3.1 ===");
    LOG("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOG("OnModLoad start");

    // ── Load Dobby ────────────────────────────────────────
    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) { LOGERR("libdobby not found: %s", dlerror()); return; }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) { LOGERR("DobbyHook not found"); return; }
    LOG("Dobby OK");

    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    LOG("libGTASA.so base: 0x%X", (unsigned)gtasaBase);
    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);

    // ── Hook 1: AndroidPaused() ───────────────────────────
    {
        void* sym = gtasaLib ? dlsym(gtasaLib, "_Z13AndroidPausedv") : nullptr;
        if (!sym && gtasaBase)
            sym = (void*)(gtasaBase + 0x269ad4);
        if (sym) {
            int r = DobbyHook(sym,
                              (void*)AndroidPaused_hook,
                              (void**)&AndroidPaused_orig);
            LOG("Hook1 AndroidPaused(): %s @ %p", r==0?"OK":"FAIL", sym);
        } else {
            LOGERR("AndroidPaused symbol tidak ketemu");
        }
    }

    // ── Hook 2: SetAndroidPaused(int) ─────────────────────
    {
        void* sym = gtasaLib ? dlsym(gtasaLib, "_Z16SetAndroidPausedi") : nullptr;
        if (!sym && gtasaBase)
            sym = (void*)(gtasaBase + 0x269ae4);
        if (sym) {
            int r = DobbyHook(sym,
                              (void*)SetAndroidPaused_hook,
                              (void**)&SetAndroidPaused_orig);
            LOG("Hook2 SetAndroidPaused(): %s @ %p", r==0?"OK":"FAIL", sym);
        }
    }

    // ── Pointer ke IsAndroidPaused global var ─────────────
    if (gtasaBase) {
        g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
        LOG("IsAndroidPaused var @ %p (val sekarang=%d)",
            g_isAndroidPaused, (int)*g_isAndroidPaused);
        LOG("Nilai 1 saat init = normal, watchdog belum aktif");
    }

    // ── Watchdog thread (delay 10 detik) ──────────────────
    pthread_t wdThread;
    if (pthread_create(&wdThread, nullptr, watchdogThread, nullptr) == 0) {
        pthread_detach(wdThread);
        LOG("Watchdog thread created, aktif dalam 10 detik");
    } else {
        LOGERR("Watchdog thread gagal dibuat");
    }

    LOG("=== AntiAFK Pause v3.1 LOADED ===");
    LOG("Bypass akan aktif 10 detik setelah launch");
}
