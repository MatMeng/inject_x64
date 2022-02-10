#include <windows.h>
#include <sdkddkver.h>
#include <iostream>

#include "xinject.h"

using namespace std;
using namespace xinject;

WCHAR g_wszDllPath[MAX_PATH];

int main(int argc, char *argv[])
{
    WIN32_FIND_DATAA fd;
    HANDLE hFind = NULL;

    if (argc != 3) {
        cerr << "Usage: pstart <EXE_PATH> <DLL_PATH>" << endl;
        return -1;
    }

    hFind = FindFirstFileA(argv[1], &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        cerr << "EXE file \"" << argv[1] << "\" not exist!" << endl;
        return -1;
    }
    FindClose(hFind);

    hFind = FindFirstFileA(argv[2], &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        cerr << "DLL file \"" << argv[1] << "\" not exist!" << endl;
        return -1;
    }
    FindClose(hFind);

    if (MultiByteToWideChar(CP_UTF8, 0,
                            argv[2], (int)strlen(argv[2]) + 1,
                            g_wszDllPath, (int)MAX_PATH) <= 0) {
        cerr << "Failed to convert DLL path to wide characters: "
             << GetLastErrorString() << endl;
        return -1;
    }

    if (!InjectWin64(argv[1], g_wszDllPath)) {
        return -1;
    }

    cout << "Succeeded to start process \"" << argv[1]
         << "\" with DLL \"" << argv[2] << "\" injected!" << endl;
    return 0;
}
