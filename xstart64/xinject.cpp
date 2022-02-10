#include "xinject.h"
#include <iostream>
#include <imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

using namespace std;

namespace xinject {

static BYTE initInstructs[] = {
    0x55,                                                       // push rbp
    0x48, 0x89, 0xE5,                                           // mov  rbp,rsp
    0x48, 0x83, 0xEC, 0x30,                                     // sub  rsp,30h

    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rdx,0
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rcx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r9,0
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r8,0
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rdx,0
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rcx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r9,0
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r8,0
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rdx,0
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rcx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x48, 0x89, 0xC1,                                           // mov  rcx,rax
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0x48, 0x89, 0x44, 0x24, 0x20,                               // mov  [rsp+20h],rax
    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r9,0
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  r8,0
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rdx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0x49, 0x89, 0xC1,                                           // mov  r9,rax
    0x4C, 0x8B, 0x00,                                           // mov  r8,[rax]
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rdx,0
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rcx,0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax,0
    0xFF, 0xD0,                                                 // call rax

    0x48, 0x89, 0xEC,                                           // mov  rsp,rbp
    0x5D,                                                       // pop  rbp
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                         // jmp  dword ptr [rip]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // entry point
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                         // old code
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static LPBYTE GetExeEntryPoint(HANDLE hProcess, LPCSTR szAppPath)
{
    PIMAGE_NT_HEADERS pNTHeader;
    ULONGLONG pEntryPoint;
    PLOADED_IMAGE pImage;
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return NULL;
    }

    PROCNTQSIP NtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(hNtdll,
        "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        return NULL;
    }

    NtQueryInformationProcess(hProcess,
        0,
        (PVOID)&pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        return NULL;
    }

    if (NULL == (pImage = ImageLoad(szAppPath, NULL))) {
        return NULL;
    }

    pNTHeader = pImage->FileHeader;
    pEntryPoint = (ULONGLONG)peb.ImageBaseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint;

    ImageUnload(pImage);

    return (LPBYTE)pEntryPoint;
}

BOOL InjectWin64(LPCSTR szAppPath, const LPCWSTR wszDllPath)
{
    char szPath[MAX_PATH];
    STARTUPINFOA stInfo;
    PROCESS_INFORMATION procInfo;
    INJECT_CODE injectCode;
    JMP_CODE jmpCode;
    SIZE_T cBytes = 0;
    HMODULE hNtdll = 0;
    HMODULE hKernel32 = 0;
    PRtlInitUnicodeString fnRtlInitUnicodeString = NULL;
    PLdrLoadDll fnLdrLoadDll = NULL;
    PVirtualProtect fnVirtualProtect = NULL;
    PGetCurrentProcess fnGetCurrentProcess = NULL;
    PWriteProcessMemory fnWriteProcessMemory = NULL;
    LPBYTE lpEntryPoint = NULL;
    LPBYTE lpInjectPoint = NULL;
    DWORD dwNewFlg, dwOldFlg;
    BOOL res = TRUE;

    /* Create the process which is going to be injected. */
    ::ZeroMemory(&stInfo, sizeof(stInfo));
    stInfo.cb = sizeof(stInfo);
    stInfo.dwFlags = STARTF_USESHOWWINDOW;
    stInfo.wShowWindow = SW_HIDE;
    ::ZeroMemory(&procInfo, sizeof(procInfo));
    strncpy_s(szPath, szAppPath, strlen(szAppPath) + 1);
    if (!CreateProcessA(NULL, szPath, 0, 0, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW,
        NULL, NULL,
        &stInfo,
        &procInfo)) {
        cerr << "Failed to create process \"" << szAppPath << "\": "
             << GetLastErrorString() << endl;
        return FALSE;
    }

    /* Get the handle of "ntdll.dll". */
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "Failed to load \"ntdll.dll\": " << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the address of function "RtlInitUnicodeString". */
    fnRtlInitUnicodeString = (PRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
    if (!fnRtlInitUnicodeString) {
        cerr << "Failed to load RtlInitUnicodeString from \"ntdll.dll\": "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the address of function "LdrLoadDll". */
    fnLdrLoadDll = (PLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
    if (!fnLdrLoadDll) {
        cerr << "Failed to load fnLdrLoadDll from \"ntdll.dll\": "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the handle of "Kernel32.dll". */
    hKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!hKernel32) {
        cerr << "Failed to load \"Kernel32.dll\": " << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the address of function "VirtualProtect". */
    fnVirtualProtect = (PVirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    if (!fnVirtualProtect) {
        cerr << "Failed to load VirtualProtect from \"Kernel32.dll\": "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the address of function "GetCurrentProcess". */
    fnGetCurrentProcess = (PGetCurrentProcess)GetProcAddress(hKernel32, "GetCurrentProcess");
    if (!fnGetCurrentProcess) {
        cerr << "Failed to load GetCurrentProcess from \"Kernel32.dll\": "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Get the address of function "WriteProcessMemory". */
    fnWriteProcessMemory = (PWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    if (!fnWriteProcessMemory) {
        cerr << "Failed to load WriteProcessMemory from \"Kernel32.dll\": "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Allocate memory in the remote process for injecting code. */
    lpInjectPoint = (LPBYTE)VirtualAllocEx(procInfo.hProcess, NULL,
        sizeof(INJECT_CODE),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpInjectPoint) {
        cerr << "Failed to allocate memory for the injecting code: "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Initialize the instructs to be injected. */
    ::ZeroMemory(&injectCode, sizeof(injectCode));
    memcpy(injectCode.u.bytes, initInstructs, sizeof(initInstructs));

    /* Get the entry point of the remote process. */
    lpEntryPoint = GetExeEntryPoint(procInfo.hProcess, szAppPath);

    /* Backup the instructs of the entry point. */
    if (!ReadProcessMemory(procInfo.hProcess, lpEntryPoint,
        &injectCode.u.s.oldCode, sizeof(JMP_CODE),
        &cBytes)) {
        cerr << "Failed to read memory from the entry point of \""
             << szAppPath << "\": " << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Setup the argument of dll path. */
    memcpy(injectCode.wszDllName, wszDllPath, (wcslen(wszDllPath) + 1) * sizeof(WCHAR));
    injectCode.ulFlags = 0;
    injectCode.hModuleHandle = INVALID_HANDLE_VALUE;

    /* Setup the instructs of function call "RtlInitUnicodeString". */
    injectCode.u.s.dwlFunc1RdxVal = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, wszDllName);
    injectCode.u.s.dwlFunc1RcxVal = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, UnicodeString);
    injectCode.u.s.dwlFunc1RaxVal = (DWORD64)fnRtlInitUnicodeString;

    /* Setup the instructs of function call "LdrLoadDll". */
    injectCode.u.s.dwlFunc2R9Val = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, hModuleHandle);
    injectCode.u.s.dwlFunc2R8Val = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, UnicodeString);
    injectCode.u.s.dwlFunc2RdxVal = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, ulFlags);
    injectCode.u.s.dwlFunc2RcxVal = (DWORD64)NULL;
    injectCode.u.s.dwlFunc2RaxVal = (DWORD64)fnLdrLoadDll;

    /* Setup the instructs of function call "VirtualProtect". */
    injectCode.u.s.dwlFunc3R9Val = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, ulFlags);
    injectCode.u.s.dwlFunc3R8Val = (DWORD64)PAGE_READWRITE;
    injectCode.u.s.dwlFunc3RdxVal = (DWORD64)sizeof(JMP_CODE);
    injectCode.u.s.dwlFunc3RcxVal = (DWORD64)lpEntryPoint;
    injectCode.u.s.dwlFunc3RaxVal = (DWORD64)fnVirtualProtect;

    /* Setup the instructs of function call GetCurrentProcess. */
    injectCode.u.s.dwlFunc4RaxVal = (DWORD64)fnGetCurrentProcess;

    /* Setup the instructs of function call WriteProcessMemory. */
    injectCode.u.s.dwlFunc5RaxVal1 = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, dwSize);
    injectCode.u.s.dwlFunc5R9Val = (DWORD64)sizeof(JMP_CODE);
    injectCode.u.s.dwlFunc5R8Val = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, u.s.oldCode);
    injectCode.u.s.dwlFunc5RdxVal = (DWORD64)lpEntryPoint;
    injectCode.u.s.dwlFunc5RaxVal2 = (DWORD64)fnWriteProcessMemory;

    /* Setup the instructs of function call "VirtualProtect". */
    injectCode.u.s.dwlFunc6RaxVal1 = (DWORD64)lpInjectPoint + offsetof(INJECT_CODE, ulFlags);
    injectCode.u.s.dwlFunc6RdxVal = (DWORD64)sizeof(JMP_CODE);
    injectCode.u.s.dwlFunc6RcxVal = (DWORD64)lpEntryPoint;
    injectCode.u.s.dwlFunc6RaxVal2 = (DWORD64)fnVirtualProtect;

    /* Setup the jmp destination. */
    injectCode.u.s.jmpCode.lpEntryPoint = lpEntryPoint;

    /* Code injecting. */
    if (!WriteProcessMemory(procInfo.hProcess, lpInjectPoint,
        &injectCode, sizeof(injectCode), &cBytes)) {
        cerr << "Failed to write inject code: "
             << GetLastErrorString() << endl;
        res = FALSE;
        goto out;
    }

    /* Write insturct "jmp far" which will jump to the injected code. */
    jmpCode.wJmpFar = 0x25FF;
    jmpCode.dwJmpOff = 0;
    jmpCode.lpEntryPoint = lpInjectPoint;
    dwNewFlg = PAGE_READWRITE;
    VirtualProtectEx(procInfo.hProcess, lpEntryPoint,
        sizeof(jmpCode), dwNewFlg, &dwOldFlg);
    if (!WriteProcessMemory(procInfo.hProcess, lpEntryPoint,
        &jmpCode, sizeof(jmpCode), &cBytes)) {
        cerr << "Failed to write jmp insturct: "
             << GetLastErrorString() << endl;
        res = FALSE;
    }
    VirtualProtectEx(procInfo.hProcess, lpEntryPoint,
        sizeof(jmpCode), dwOldFlg, &dwNewFlg);
    if (res == FALSE) {
        goto out;
    }

    ResumeThread(procInfo.hThread);

out:
    if (res == FALSE) {
        TerminateProcess(procInfo.hProcess, 0);
    }
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
    return res;
}

} /* namespace xinject */