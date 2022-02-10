#include "pch.h"
#include <fstream>

#include "xhook.h"

#define LOG_FILE "spy1.log"

using namespace std;

static FILE* g_fdTrace = NULL;

typedef VOID(WINAPI* Sleep_t)(_In_ DWORD dwMilliseconds);
static Sleep_t& Sleep_f() {
    static Sleep_t fn = (Sleep_t)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "Sleep");
    if (!fn)
        fn = (Sleep_t)GetProcAddress(GetModuleHandleA("KernelBase.dll"), "Sleep");
    return fn;
}

static VOID WINAPI hook_Sleep(_In_ DWORD dwMilliseconds)
{
    printf("This is hook_Sleep(%lu)!\n", dwMilliseconds);
}

static BOOL InitApiSpy()
{
    BOOL ok = TRUE;

    freopen_s(&g_fdTrace, LOG_FILE, "w", stdout);
    if (g_fdTrace) {
        setvbuf(stdout, NULL, _IONBF, 0);
    }
    else {
        ofstream os;
        os.open(LOG_FILE);
        os << "Failed to redirect stdout!" << endl;
        os.close();
    }

    XHookRestoreAfterWith();
    XHookTransactionBegin();
    XHookUpdateThread(GetCurrentThread());
    ok &= (XHookAttach((PVOID*)&Sleep_f(), &hook_Sleep) == NO_ERROR);
    XHookTransactionCommit();

    printf("%s to hook Sleep!\n", ok ? "Succeeded" : "Failed");
    return ok;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return InitApiSpy();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

