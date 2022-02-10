#pragma once

#include <windows.h>
#include <string>
#include <sstream>

#define RTL_MAX_DRIVE_LETTERS 32

namespace xinject {

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[13];
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef LONG(NTAPI* PRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef LONG(NTAPI* PLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
typedef LONG(NTAPI* PROCNTQSIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef BOOL(NTAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(NTAPI* PGetCurrentProcess)();
typedef BOOL(NTAPI* PWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);

#pragma pack (push, 1)  // Byte align
typedef struct {
    WORD    wJmpFar;     // JMP QWORD PTR [RIP] (0x25FF)
    DWORD32 dwJmpOff;    // 0x00000000
    LPBYTE  lpEntryPoint;
} JMP_CODE, *LPJMP_CODE;

typedef struct {
    union {
        BYTE bytes[296];
        struct {
            /* Reserve stack space for function call arguments. */
            BYTE     bPushRbp;        // PUSH RBP (0x55)
            WORD     wMovRbp;         // MOV (0x8948)
            BYTE     bMovRbpRsp;      // RBP, RSP (0xE5)
            DWORD32  dwsSubRsp;       // SUB RSP, 30H (0x30EC8348)

            /* Function call1: RtlInitUnicodeString. */
            WORD     wFunc1MovRdx;    // MOV RDX, wszDllName (0xBA48)
            DWORD64  dwlFunc1RdxVal;  // wszDllName
            WORD     wFunc1MovRcx;    // MOV RCX, &UnicodeString (0xB948)
            DWORD64  dwlFunc1RcxVal;  // &UnicodeString
            WORD     wFunc1MovRax;    // MOV RAX, fnRtlInitUnicodeString (0xB848)
            DWORD64  dwlFunc1RaxVal;  // fnRtlInitUnicodeString
            WORD     wFunc1CallRax;   // fnRtlInitUnicodeString(&UnicodeString, wszDllName) (0xD0FF)

            /* Function call2: LdrLoadDll. */
            WORD     wFunc2MovR9;     // MOV R9, &hModuleHandle (0xB949)
            DWORD64  dwlFunc2R9Val;   // &hModuleHandle
            WORD     wFunc2MovR8;     // MOV R8, &UnicodeString (0xB849)
            DWORD64  dwlFunc2R8Val;   // &UnicodeString
            WORD     wFunc2MovRdx;    // MOV RDX, &ulFlags (0xBA48)
            DWORD64  dwlFunc2RdxVal;  // &ulFlags
            WORD     wFunc2MovRcx;    // MOV RCX, wszDllPath (0xB948)
            DWORD64  dwlFunc2RcxVal;  // NULL
            WORD     wFunc2MovRax;    // MOV RAX, fnLdrLoadDll (0xB848)
            DWORD64  dwlFunc2RaxVal;  // fnLdrLoadDll
            WORD     wFunc2CallRax;   // fnLdrLoadDll(wszDllPath, &ulFlags, &UnicodeString, &hModuleHandle) (0xD0FF)

            /* Function call3: VirtualProtect for write permition. */
            WORD     wFunc3MovR9;     // MOV R9, &ulFlags (0xB949)
            DWORD64  dwlFunc3R9Val;   // &ulFlags
            WORD     wFunc3MovR8;     // MOV R8, PAGE_READWRITE (0xB849)
            DWORD64  dwlFunc3R8Val;   // PAGE_READWRITE
            WORD     wFunc3MovRdx;    // MOV RDX, sizeof(oldCode) (0xBA48)
            DWORD64  dwlFunc3RdxVal;  // sizeof(oldCode)
            WORD     wFunc3MovRcx;    // MOV RCX, lpEntryPoint (0xB948)
            DWORD64  dwlFunc3RcxVal;  // lpEntryPoint
            WORD     wFunc3MovRax;    // MOV RAX, fnVirtualProtect (0xB848)
            DWORD64  dwlFunc3RaxVal;  // fnVirtualProtect
            WORD     wFunc3CallRax;   // fnVirtualProtect(lpEntryPoint, sizeof(oldCode), PAGE_READWRITE, &ulFlags) (0xD0FF)

            /* Function call4: GetCurrentProcess (Return value will be stored in RAX). */
            WORD     wFunc4MovRax;    // MOV RAX, fnGetCurrentProcess (0xB848)
            DWORD64  dwlFunc4RaxVal;  // fnGetCurrentProcess
            WORD     wFunc4CallRax;   // fnGetCurrentProcess() (0xD0FF)

            /* Function call5: WriteProcessMemory for entry point retrieving. */
            WORD     wFunc5MovRcx;    // MOV (0x8948)
            BYTE     wFunc5MovRcxRax; // RCX, RAX (0xC1)
            WORD     wFunc5MovRax1;   // MOV RAX, &dwSize (0xB848)
            DWORD64  dwlFunc5RaxVal1; // &dwSize
            DWORD32  dwsFunc5MovRsp;  // MOV [RSP+20H], RAX (0x24448948)
            BYTE     bFunc5MovRspOff; // 0x20
            WORD     wFunc5MovR9;     // MOV R9, sizeof(oldCode) (0xB949)
            DWORD64  dwlFunc5R9Val;   // sizeof(oldCode)
            WORD     wFunc5MovR8;     // MOV R8, &oldCode (0xB849)
            DWORD64  dwlFunc5R8Val;   // &oldCode
            WORD     wFunc5MovRdx;    // MOV RDX, lpEntryPoint (0xBA48)
            DWORD64  dwlFunc5RdxVal;  // lpEntryPoint
            WORD     wFunc5MovRax2;   // MOV RAX, fnWriteProcessMemory (0xB848)
            DWORD64  dwlFunc5RaxVal2; // fnWriteProcessMemory
            WORD     wFunc5CallRax;   // fnWriteProcessMemory(PROCESS_HANDLE /* Returned from function call4 */,
                                      //                      lpEntryPoint,
                                      //                      &oldCode, sizeof(oldCode),
                                      //                      &dwSize) (0xD0FF)

            /* Function call6: VirtualProtect for permition retrieving. */
            WORD     wFunc6MovRax1;   // MOV RAX, &ulFlags (0xB848)
            DWORD64  dwlFunc6RaxVal1; // &ulFlags
            WORD     wFunc6MovR9;     // MOV (0x8949)
            BYTE     wFunc6MovR9Rax;  // R9, RAX (0xC1)
            WORD     wFunc6MovR8Rax;  // MOV (0x8B4C)
            BYTE     bFunc6MovR8Off;  // R8, [RAX] (0x00)
            WORD     wFunc6MovRdx;    // MOV RDX, sizeof(oldCode) (0xBA48)
            DWORD64  dwlFunc6RdxVal;  // sizeof(oldCode)
            WORD     wFunc6MovRcx;    // MOV RCX, lpEntryPoint (0xB948)
            DWORD64  dwlFunc6RcxVal;  // lpEntryPoint
            WORD     wFunc6MovRax2;   // MOV RAX, fnVirtualProtect (0xB848)
            DWORD64  dwlFunc6RaxVal2; // fnVirtualProtect
            WORD     wFunc6CallRax;   // fnVirtualProtect(lpEntryPoint, sizeof(oldCode), ulFlags, &ulFlags) (0xD0FF)

            /* Restore stack. */
            WORD     wMovRsp;         // MOV (0x8948)
            BYTE     bMovRspRbp;      // RSP, RBP (0xEC)
            BYTE     bPopRbp;         // POP RBP (0x5D)
            JMP_CODE jmpCode;
            JMP_CODE oldCode;
        } s;
    } u;
    UNICODE_STRING        UnicodeString;
    WCHAR                 wszDllName[MAX_PATH];
    ULONG                 ulFlags;
    HANDLE                hModuleHandle;
    SIZE_T                dwSize;
} INJECT_CODE, *LPINJECT_CODE;
#pragma pack (pop, 1)

static LPCSTR GetLastErrorString()
{
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);
    return (LPCSTR)lpMsgBuf;
}

BOOL InjectWin64(LPCSTR szAppPath, const LPCWSTR wszDllPath);

} /* namespace xinject */