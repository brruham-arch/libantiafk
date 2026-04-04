#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

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
    1, "antiafk", "Anti AFK Pause", "3.2", "brruham-arch", 0
};

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
static int  (*AndroidPaused_orig)()       = nullptr;
static void (*SetAndroidPaused_orig)(int) = nullptr;

// ─── State tracking ──────────────────────────────────────
// Bypass hanya aktif setelah game pernah val=0 minimal sekali.
// Ini artinya init selesai dan game sudah berjalan normal.
static volatile bool g_gameWasUnpaused = false;

// ─── Realtime Logger ─────────────────────────────────────
static FILE* g_logFile = nullptr;

static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) {
        fprintf(g_logFile, "=== AntiAFK Log v3.2 ===\n");
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

    // Kalau game sudah pernah running normal (val=0),
    // tandai sebagai init selesai
    if (realVal == 0) {
        if (!g_gameWasUnpaused) {
            g_gameWasUnpaused = true;
            LOG("Game fully running (val=0 detected) — bypass armed");
        }
        return 0; // normal, game memang tidak pause
    }

    // val=1 → cek apakah ini init atau pause sungguhan
    if (!g_gameWasUnpaused) {
        // Masih init — jangan ganggu
        LOGDBG("AndroidPaused()=1 saat init, dibiarkan");
        return realVal;
    }

    // Game sudah pernah unpaused, ini pause sungguhan → block
    static bool loggedBlock = false;
    if (!loggedBlock) {
        LOG("AndroidPaused()=1 DIBLOK — return 0 (sync tetap jalan)");
        loggedBlock = true;
    }
    return 0;
}

// ─── Hook: SetAndroidPaused(int) ─────────────────────────
void SetAndroidPaused_hook(int isPaused) {
    LOG("SetAndroidPaused(%d) | gameWasUnpaused=%d",
        isPaused, (int)g_gameWasUnpaused);
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
}

// ─── AML Exports ─────────────────────────────────────────

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK Pause v3.2 ===");
    LOG("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOG("OnModLoad start");

    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) { LOGERR("libdobby not found: %s", dlerror()); return; }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) { LOGERR("DobbyHook not found"); return; }
    LOG("Dobby OK");

    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    LOG("libGTASA.so base: 0x%X", (unsigned)gtasaBase);
    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);

    // Hook 1: AndroidPaused() — kunci utama
    {
        void* sym = gtasaLib ? dlsym(gtasaLib, "_Z13AndroidPausedv") : nullptr;
        if (!sym && gtasaBase)
            sym = (void*)(gtasaBase + 0x269ad4);
        if (sym) {
            int r = DobbyHook(sym,
                              (void*)AndroidPaused_hook,
                              (void**)&AndroidPaused_orig);
            LOG("Hook1 AndroidPaused(): %s @ %p", r==0?"OK":"FAIL", sym);
        } else LOGERR("AndroidPaused tidak ketemu");
    }

    // Hook 2: SetAndroidPaused(int) — logging
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

    LOG("=== AntiAFK v3.2 LOADED ===");
    LOG("Bypass armed — menunggu game running normal...");
}
