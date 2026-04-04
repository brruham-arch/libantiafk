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
    1, "antiafk", "Anti AFK Pause", "3.0", "brruham-arch", 0
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
// AndroidPaused() → getter yang dibaca SA-MP untuk cek status pause
static int  (*AndroidPaused_orig)()   = nullptr;
// SetAndroidPaused(int) → setter, tetap kita hook untuk logging
static void (*SetAndroidPaused_orig)(int) = nullptr;

// ─── Global: pointer ke IsAndroidPaused variable ─────────
// Sebagai fallback watchdog jika hook getter tidak cukup
static volatile int* g_isAndroidPaused = nullptr;

// ─── Realtime Logger ─────────────────────────────────────
static FILE* g_logFile = nullptr;

static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) {
        fprintf(g_logFile, "=== AntiAFK Log v3.0 ===\n");
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

// ─── Hook: AndroidPaused() ───────────────────────────────
// Ini getter yang dibaca SA-MP sync thread untuk cek pause state
// Kita selalu return 0 → SA-MP pikir game tidak pernah pause
int AndroidPaused_hook() {
    // Log hanya sekali per transisi supaya tidak flood
    static int lastVal = 0;
    int realVal = AndroidPaused_orig ? AndroidPaused_orig() : 0;
    if (realVal != lastVal) {
        LOG("AndroidPaused() = %d (kita return 0)", realVal);
        lastVal = realVal;
    }
    return 0; // selalu tidak paused
}

// ─── Hook: SetAndroidPaused(int) ─────────────────────────
// Untuk logging saja — kita tetap panggil orig
void SetAndroidPaused_hook(int isPaused) {
    LOG("SetAndroidPaused(%d) dipanggil", isPaused);
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
    LOG("SetAndroidPaused orig done");
}

// ─── Watchdog thread ─────────────────────────────────────
// Fallback: paksa IsAndroidPaused = 0 setiap 100ms
// Jalan paralel dengan hook, double protection
static void* watchdogThread(void*) {
    LOG("Watchdog thread started");
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
    LOG("=== AntiAFK Pause v3.0 ===");
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

    // ── libGTASA via dlopen ───────────────────────────────
    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    LOG("libGTASA.so base: 0x%X", (unsigned)gtasaBase);

    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);

    // ── Hook 1: AndroidPaused() ← KUNCI UTAMA ────────────
    // SA-MP sync thread panggil ini sebelum kirim packet
    {
        void* sym = gtasaLib ? dlsym(gtasaLib, "_Z13AndroidPausedv") : nullptr;
        if (!sym && gtasaBase) {
            // Fallback offset: 0x00269ad4, ARM (bukan Thumb) → tidak +1
            sym = (void*)(gtasaBase + 0x269ad4);
            LOG("AndroidPaused fallback ke offset 0x269ad4");
        }
        if (sym) {
            int r = DobbyHook(sym,
                              (void*)AndroidPaused_hook,
                              (void**)&AndroidPaused_orig);
            LOG("Hook1 AndroidPaused(): %s @ %p", r==0?"OK":"FAIL", sym);
        } else {
            LOGERR("AndroidPaused symbol tidak ketemu!");
        }
    }

    // ── Hook 2: SetAndroidPaused(int) ← logging ──────────
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

    // ── Pointer ke IsAndroidPaused global variable ────────
    // 0x006855bc = offset di libGTASA.so (D = data symbol)
    if (gtasaBase) {
        g_isAndroidPaused = (volatile int*)(gtasaBase + 0x6855bc);
        LOG("IsAndroidPaused var @ %p (val=%d)",
            g_isAndroidPaused, (int)*g_isAndroidPaused);
    }

    // ── Watchdog thread ───────────────────────────────────
    pthread_t wdThread;
    int wr = pthread_create(&wdThread, nullptr, watchdogThread, nullptr);
    if (wr == 0) {
        pthread_detach(wdThread);
        LOG("Watchdog thread started OK");
    } else {
        LOGERR("Watchdog thread failed: %d", wr);
    }

    LOG("=== AntiAFK Pause v3.0 LOADED ===");
}
