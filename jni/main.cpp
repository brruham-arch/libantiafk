#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define TAG      "AntiAFK"
#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"
#define ADDR_PATH "/storage/emulated/0/Download/antiafk_addr.txt"

// ─── Realtime Logger ─────────────────────────────────────
static FILE* g_logFile = nullptr;

static void logInit() {
    g_logFile = fopen(LOG_PATH, "w");
    if (g_logFile) { fprintf(g_logFile, "=== AntiAFK Log v4.0 ===\n"); fflush(g_logFile); }
}

static void logWrite(const char* level, const char* fmt, ...) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm* t = localtime(&ts.tv_sec);
    char tbuf[32]; strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
    char mbuf[512];
    va_list args; va_start(args, fmt);
    vsnprintf(mbuf, sizeof(mbuf), fmt, args); va_end(args);
    if (g_logFile) {
        fprintf(g_logFile, "[%s.%03ld] [%s] %s\n", tbuf, ts.tv_nsec/1000000, level, mbuf);
        fflush(g_logFile);
    }
    __android_log_print(strcmp(level,"ERR")==0 ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, TAG, "%s", mbuf);
}

#define LOG(...)    logWrite("INF", __VA_ARGS__)
#define LOGERR(...) logWrite("ERR", __VA_ARGS__)

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── State ───────────────────────────────────────────────
static volatile int g_isPaused = 0; // 1 = game pause, 0 = normal

// ─── Original pointers ───────────────────────────────────
static void (*SetAndroidPaused_orig)(int) = nullptr;

// ─── Hook: SetAndroidPaused ──────────────────────────────
void SetAndroidPaused_hook(int isPaused) {
    g_isPaused = isPaused;
    LOG("SetAndroidPaused(%d)", isPaused);
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
}

// ─── API yang diekspos ke Lua via FFI ────────────────────
static int  api_isPaused()         { return g_isPaused; }
static void api_setForcePause(int v) { g_isPaused = v; }

struct AntiAfkAPI {
    int  (*isPaused)();
    void (*setForcePause)(int);
};

static AntiAfkAPI g_api = {
    api_isPaused,
    api_setForcePause,
};

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
extern "C" {

// Format string pipe-delimited — sesuai AML versi ini (lihat voicefx)
void* __GetModInfo() {
    static const char* info = "antiafk|1.0|Anti AFK Pause|brruham-arch";
    return (void*)info;
}

void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK v4.0 ===");
    LOG("PreLoad OK");
}

void OnModLoad() {
    LOG("OnModLoad start");

    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) { LOGERR("libdobby: %s", dlerror()); return; }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) { LOGERR("DobbyHook not found"); return; }
    LOG("Dobby OK");

    uintptr_t gtasaBase = getLibBase("libGTASA.so");
    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);

    // Hook SetAndroidPaused untuk track pause state
    void* sym = gtasaLib ? dlsym(gtasaLib, "_Z16SetAndroidPausedi") : nullptr;
    if (!sym && gtasaBase) sym = (void*)(gtasaBase + 0x269ae4);
    if (sym) {
        int r = DobbyHook(sym, (void*)SetAndroidPaused_hook, (void**)&SetAndroidPaused_orig);
        LOG("Hook SetAndroidPaused: %s @ %p", r==0?"OK":"FAIL", sym);
    }

    // Tulis alamat g_api ke file untuk Lua
    FILE* af = fopen(ADDR_PATH, "w");
    if (af) {
        fprintf(af, "%lu\n", (unsigned long)&g_api);
        fclose(af);
        LOG("API addr ditulis: %lu → " ADDR_PATH, (unsigned long)&g_api);
    } else {
        LOGERR("Gagal tulis addr file");
    }

    LOG("=== AntiAFK v4.0 LOADED ===");
}

} // extern "C"
