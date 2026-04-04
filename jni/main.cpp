#include <android/log.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define TAG     "AntiAFK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define LOG_PATH "/storage/emulated/0/Download/antiafk_log.txt"

// ─── ModInfo ─────────────────────────────────────────────
struct ModInfo_t {
    unsigned int  handlerVer;
    const char*   id;
    const char*   name;
    const char*   version;
    const char*   author;
    unsigned int  flags;
};
static ModInfo_t g_modInfo = {
    1, "antiafk", "Anti AFK Pause", "2.0", "brruham-arch", 0
};

// ─── Offsets libsamp.so ───────────────────────────────────
#define STOPTHREAD_OFF   0x214B4   // Thumb → +1

// ─── Dobby ───────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* hook, void** orig);
static DobbyHook_t DobbyHook = nullptr;

// ─── Original pointers ───────────────────────────────────
static void (*SetAndroidPaused_orig)(int) = nullptr;
static void (*StopThread_orig)()          = nullptr;

// ─── Realtime Logger ─────────────────────────────────────
static FILE* g_logFile = nullptr;

static void logInit() {
    // Buka file sekali saat load, tetap terbuka (realtime flush)
    g_logFile = fopen(LOG_PATH, "w"); // 'w' = fresh tiap launch
    if (g_logFile) {
        fprintf(g_logFile, "=== AntiAFK Log - Session Start ===\n");
        fflush(g_logFile);
    }
}

static void logWrite(const char* level, const char* fmt, ...) {
    // Timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm* tm_info = localtime(&ts.tv_sec);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);

    // Format message
    char msgbuf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    va_end(args);

    // Tulis ke file + flush langsung (realtime)
    if (g_logFile) {
        fprintf(g_logFile, "[%s.%03ld] [%s] %s\n",
                timebuf, ts.tv_nsec / 1000000, level, msgbuf);
        fflush(g_logFile); // flush tiap baris = realtime
    }

    // Tetap log ke logcat juga
    if (strcmp(level, "ERR") == 0)
        LOGE("%s", msgbuf);
    else
        LOGI("%s", msgbuf);
}

// Shortcut macros
#define LOG(...)  logWrite("INF", __VA_ARGS__)
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

// ─── Hook 1: SetAndroidPaused ────────────────────────────
void SetAndroidPaused_hook(int isPaused) {
    LOG("SetAndroidPaused(%d) — game %s",
        isPaused, isPaused ? "PAUSING" : "RESUMING");
    if (SetAndroidPaused_orig) SetAndroidPaused_orig(isPaused);
    LOG("SetAndroidPaused orig done, SA-MP thread still alive");
}

// ─── Hook 2: StopThread ──────────────────────────────────
void StopThread_hook() {
    // NOP — SA-MP thread tidak boleh berhenti
    LOG("StopThread BLOCKED — sync tetap jalan!");
}

// ─── AML Exports ─────────────────────────────────────────

extern "C" __attribute__((visibility("default")))
void* __GetModInfo() { return &g_modInfo; }

extern "C" __attribute__((visibility("default")))
void OnModPreLoad() {
    logInit();
    LOG("=== AntiAFK Pause v2.0 ===");
    LOG("PreLoad OK");
}

extern "C" __attribute__((visibility("default")))
void OnModLoad() {
    LOG("OnModLoad start");

    // ── Load Dobby ────────────────────────────────────────
    void* dobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobby) {
        LOGERR("libdobby.so not found: %s", dlerror());
        return;
    }
    DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (!DobbyHook) {
        LOGERR("DobbyHook symbol not found");
        return;
    }
    LOG("Dobby loaded OK");

    // ── Hook 1: SetAndroidPaused ─────────────────────────
    void* gtasaLib = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);
    if (gtasaLib) {
        void* sym = dlsym(gtasaLib, "_Z16SetAndroidPausedi");
        if (sym) {
            int r = DobbyHook(sym,
                              (void*)SetAndroidPaused_hook,
                              (void**)&SetAndroidPaused_orig);
            LOG("Hook1 SetAndroidPaused [dlsym]: %s @ %p",
                r==0?"OK":"FAIL", sym);
        } else {
            LOGERR("_Z16SetAndroidPausedi not found via dlsym");
        }
    } else {
        // Fallback offset
        LOG("libGTASA dlopen failed, fallback ke offset 0x269ae4");
        uintptr_t gtasaBase = getLibBase("libGTASA.so");
        if (gtasaBase) {
            void* addr = (void*)(gtasaBase + 0x269ae4 + 1);
            int r = DobbyHook(addr,
                              (void*)SetAndroidPaused_hook,
                              (void**)&SetAndroidPaused_orig);
            LOG("Hook1 SetAndroidPaused [offset]: %s @ %p",
                r==0?"OK":"FAIL", addr);
        } else {
            LOGERR("libGTASA.so base tidak ketemu");
        }
    }

    // ── Hook 2: StopThread ───────────────────────────────
    uintptr_t sampBase = getLibBase("libsamp.so");
    if (!sampBase) {
        LOGERR("libsamp.so base tidak ketemu");
        return;
    }
    LOG("libsamp.so base: 0x%X", (unsigned)sampBase);

    uintptr_t stopAddr = sampBase + STOPTHREAD_OFF + 1;
    int r2 = DobbyHook((void*)stopAddr,
                       (void*)StopThread_hook,
                       (void**)&StopThread_orig);
    LOG("Hook2 StopThread: %s @ 0x%X",
        r2==0?"OK":"FAIL", (unsigned)stopAddr);

    LOG("=== AntiAFK Pause v2.0 LOADED - Log: " LOG_PATH " ===");
}
