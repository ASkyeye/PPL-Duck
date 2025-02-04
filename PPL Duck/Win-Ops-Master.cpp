#include "Win-Ops-Master.h"
#include "NtDefine.h"
#include <sddl.h>
#include <iostream>
#include <threadpoolapiset.h>
#include <random>

DWORD LastError = 0;

OpsMaster::OpsMaster()
{
	LoadLibrary(L"ntdll.dll");
	HMODULE hm = GetModuleHandle(L"ntdll.dll");
	_NtRaiseHardError = (NTSTATUS(WINAPI*)(NTSTATUS ErrorStactus, ULONG NumberOfParameters,
		ULONG UnicodeStringParameterMask, PULONG_PTR * Parameters, ULONG ValidResponseOption, PULONG Response))GetProcAddress(hm, "NtRaiseHardError");
	_RtlAdjustPrivilege = (NTSTATUS(WINAPI*) (ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled))GetProcAddress(hm, "RtlAdjustPrivilege");
	_NtSetInformationFile = (NTSTATUS(WINAPI*) (HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass))GetProcAddress(hm, "NtSetInformationFile");
	_RtlNtStatusToDosError = (ULONG(WINAPI*) (NTSTATUS Status))GetProcAddress(hm, "RtlNtStatusToDosError");
	_RtlInitUnicodeString = (NTSTATUS(WINAPI*)(PUNICODE_STRING, PCWSTR)) GetProcAddress(hm, "RtlInitUnicodeString");
	_NtCreateSymbolicLinkObject = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
	_NtCreateFile = (NTSTATUS(WINAPI*)(
		PHANDLE            FileHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK   IoStatusBlock,
		PLARGE_INTEGER     AllocationSize,
		ULONG              FileAttributes,
		ULONG              ShareAccess,
		ULONG              CreateDisposition,
		ULONG              CreateOptions,
		PVOID              EaBuffer,
		ULONG              EaLength))GetProcAddress(hm, "NtCreateFile");
	_NtSetSecurityObject = (NTSTATUS(WINAPI*)(
		HANDLE               Handle,
		SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor
		))GetProcAddress(hm, "NtSetSecurityObject");
	_NtOpenProcess = (NTSTATUS(WINAPI*)(
		PHANDLE            ProcessHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID         ClientId
		))GetProcAddress(hm, "NtOpenProcess");
	_NtTerminateProcess = (NTSTATUS(WINAPI*)(
		IN HANDLE               ProcessHandle OPTIONAL,
		IN NTSTATUS             ExitStatus
		))GetProcAddress(hm, "NtTerminateProcess");
	_NtClose = (NTSTATUS(WINAPI*)(HANDLE Handle))GetProcAddress(hm, "NtClose");
	_NtDeviceIoControlFile = (NTSTATUS(WINAPI*)(
		HANDLE           FileHandle,
		HANDLE           Event,
		PIO_APC_ROUTINE  ApcRoutine,
		PVOID            ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG            IoControlCode,
		PVOID            InputBuffer,
		ULONG            InputBufferLength,
		PVOID            OutputBuffer,
		ULONG            OutputBufferLength)) GetProcAddress(hm, "NtDeviceIoControlFile");
	_NtCreateDirectoryObjectEx = (NTSTATUS(WINAPI*)(
		PHANDLE, ACCESS_MASK,
		POBJECT_ATTRIBUTES, HANDLE, BOOLEAN
		))GetProcAddress(hm, "NtCreateDirectoryObjectEx");
	_NtOpenDirectoryObject = (NTSTATUS(WINAPI*)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES
		))GetProcAddress(hm, "NtOpenDirectoryObject");
	_NtWriteFile = (NTSTATUS(WINAPI*)
		(HANDLE           FileHandle,
			HANDLE           Event,
			PIO_APC_ROUTINE  ApcRoutine,
			PVOID            ApcContext,
			PIO_STATUS_BLOCK IoStatusBlock,
			PVOID            Buffer,
			ULONG            Length,
			PLARGE_INTEGER   ByteOffset,
			PULONG           Key)) GetProcAddress(hm, "NtWriteFile");
	_NtWaitForSingleObject = (NTSTATUS(WINAPI*)(
		IN HANDLE               ObjectHandle,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       TimeOut OPTIONAL)) GetProcAddress(hm, "NtWaitForSingleObject");
	_NtReadFile = (NTSTATUS(WINAPI*)(
		_In_     HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_    PIO_STATUS_BLOCK IoStatusBlock,
		_Out_    PVOID            Buffer,
		_In_     ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key
		))GetProcAddress(hm, "NtReadFile");
	_NtCompareTokens = (NTSTATUS(WINAPI*)(
		_In_  HANDLE   FirstTokenHandle,
		_In_  HANDLE   SecondTokenHandle,
		_Out_ PBOOLEAN Equal
		)) GetProcAddress(hm, "NtCompareTokens");
	_ZwDeleteFile = (NTSTATUS(WINAPI*)
		(POBJECT_ATTRIBUTES ObjectAttributes))GetProcAddress(hm, "ZwDeleteFile");
	_ZwCreateKey = (NTSTATUS(WINAPI*)
		(PHANDLE            KeyHandle,
			ACCESS_MASK        DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			ULONG              TitleIndex,
			PUNICODE_STRING    Class,
			ULONG              CreateOptions,
			PULONG             Disposition))GetProcAddress(hm, "ZwCreateKey");
	_ZwDeleteKey = (NTSTATUS(WINAPI*)
		(HANDLE KeyHandle))GetProcAddress(hm, "ZwDeleteKey");
	_ZwSetValueKey = (NTSTATUS(WINAPI*)(
		HANDLE          KeyHandle,
		PUNICODE_STRING ValueName,
		ULONG           TitleIndex,
		ULONG           Type,
		PVOID           Data,
		ULONG           DataSize
		))GetProcAddress(hm, "ZwSetValueKey");
	_NtSuspendProcess = (NTSTATUS(WINAPI*)(
		HANDLE ProcessHandle
		))GetProcAddress(hm, "NtSuspendProcess");
	_NtResumeProcess = (NTSTATUS(WINAPI*)(
		HANDLE ProcessHandle
		))GetProcAddress(hm, "NtResumeProcess");
	_ZwMakeTemporaryObject = (NTSTATUS(WINAPI*)(
		HANDLE Handle
		))GetProcAddress(hm, "ZwMakeTemporaryObject");
	_ZwMakePermanentObject = (NTSTATUS(WINAPI*)(
		HANDLE Handle
		))GetProcAddress(hm, "ZwMakePermanentObject");
	_RtlDosPathNameToRelativeNtPathName_U = (BOOL(NTAPI*)(
		_In_       PCWSTR DosFileName,
		_Out_      PUNICODE_STRING NtFileName,
		_Out_opt_  PWSTR * FilePath,
		_Out_opt_  PRTL_RELATIVE_NAME RelativeName
		))GetProcAddress(hm, "RtlDosPathNameToRelativeNtPathName_U");
	_NtSetInformationProcess = (NTSTATUS(NTAPI*)(
		IN HANDLE               ProcessHandle,
		IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
		IN PVOID                ProcessInformation,
		IN ULONG                ProcessInformationLength
		))GetProcAddress(hm, "NtSetInformationProcess");

	/*_NtOpenSymbolicLinkObject = (NTSTATUS(WINAPI*)(
		_Out_ PHANDLE            LinkHandle,
		_In_  ACCESS_MASK        DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes
		))GetProcAddress(hm, "NtOpenSymbolicLinkObject");*/

	return;
}
std::wstring OpsMaster::BuildNativePath(std::wstring path) {
    //object manager exclusion
	if (path[0] == L'\\' && path[1] != L'\\')
		return path;
	UNICODE_STRING ntpath;
	_RtlDosPathNameToRelativeNtPathName_U(path.c_str(), &ntpath, NULL, NULL);
	return ntpath.Buffer;
}

DWORD OpsMaster::NtStatusToDOS(NTSTATUS status) {
	return _RtlNtStatusToDosError(status);
}

DWORD OpsMaster::GetLastErr() {
	return LastError;
}

void SetLastErr(DWORD err) {
	LastError = err;
}

bool OpsMaster::MoveByHandle(HANDLE hfile, std::wstring target)
{
	target = BuildNativePath(target);
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (target.size() * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_sz);
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = target.size() * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], target.c_str(), target.size() * sizeof(wchar_t));
	IO_STATUS_BLOCK io = { 0 };
	NTSTATUS status = _NtSetInformationFile(hfile, &io, rename_info, buffer_sz, FileRenameInformationEx);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	HeapFree(GetProcessHeap(),NULL, rename_info);
	SetLastErr(GetLastError());
	return true;
}

bool OpsMaster::MoveByHandle(HANDLE hfile, std::string target) {
	return OpsMaster::MoveByHandle(hfile, std::wstring(target.begin(), target.end()));
}


HANDLE OpsMaster::CreateNativeSymlink(std::wstring link, std::wstring target) {
	HANDLE ret;
	UNICODE_STRING ulnk;
	UNICODE_STRING utarget;
	NTSTATUS status;
	_RtlInitUnicodeString(&ulnk, link.c_str());
	_RtlInitUnicodeString(&utarget, target.c_str());

	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &ulnk, NULL, nullptr, nullptr);

	NTSTATUS stat = _NtCreateSymbolicLinkObject(&ret, SYMBOLIC_LINK_ALL_ACCESS,
		&objattr, &utarget);
	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return nullptr;
	}
	return ret;
}

HANDLE OpsMaster::CreateNativeSymlink(std::string link, std::string target) {
	return OpsMaster::CreateNativeSymlink(std::wstring(link.begin(), link.end()),
		std::wstring(target.begin(), target.end()));
}
bool OpsMaster::CreateDosDeviceLink(std::string link, std::string target) {
	return OpsMaster::CreateDosDeviceLink(
		std::wstring(link.begin(), link.end()),
		std::wstring(target.begin(), target.end()));
}

bool OpsMaster::CreateDosDeviceLink(std::wstring link, std::wstring target)
{
	if (link[0] == L'\\') {
		link = L"Global\\GLOBALROOT" + link;
	}
	target = BuildNativePath(target);
	DWORD LastErr = GetLastError();
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, link.c_str(), target.c_str()))
	{
		SetLastErr(GetLastError());
		SetLastError(LastErr);
		return true;
	}
	SetLastErr(GetLastError());
	SetLastError(LastErr);
	return false;
}

bool OpsMaster::RemoveDosDeviceLink(std::string link)
{
	return OpsMaster::RemoveDosDeviceLink(std::wstring(link.begin(), link.end()));
}

bool OpsMaster::RemoveDosDeviceLink(std::wstring link)
{
	if (link[0] == L'\\') {
		link = L"Global\\GLOBALROOT" + link;
	}
	DWORD LastErr = GetLastError();
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH |
		DDD_REMOVE_DEFINITION,
		link.c_str(), NULL))
	{
		SetLastErr(GetLastError());
		SetLastError(LastErr);
		return true;
	}
	SetLastErr(GetLastError());
	SetLastError(LastErr);
	return false;
}



HANDLE OpsMaster::OpenDirectory(std::wstring directory, DWORD access_mask, DWORD share_mode, DWORD creation_disposition, DWORD flags)
{
	directory = BuildNativePath(directory);
	HANDLE h;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	IO_STATUS_BLOCK io;
	NTSTATUS status;
	_RtlInitUnicodeString(&target, directory.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	switch (creation_disposition) {
	case CREATE_NEW:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_CREATE, flags ? FILE_DIRECTORY_FILE|flags : FILE_DIRECTORY_FILE | FILE_FLAG_OPEN_REPARSE_POINT, NULL, NULL);
		break;
	case OPEN_EXISTING:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_OPEN, flags ? FILE_DIRECTORY_FILE | flags : FILE_DIRECTORY_FILE | FILE_FLAG_OPEN_REPARSE_POINT, NULL, NULL);
		break;
	default:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_OPEN_IF, flags ? FILE_DIRECTORY_FILE | flags : FILE_DIRECTORY_FILE | FILE_FLAG_OPEN_REPARSE_POINT, NULL, NULL);

	}
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return h;
}

HANDLE OpsMaster::OpenDirectory(std::string directory, DWORD access_mask, DWORD share_mode, DWORD creation_disposition, DWORD flags)
{
	return OpsMaster::OpenDirectory(std::wstring(directory.begin(),
		directory.end()), access_mask, share_mode,
		creation_disposition);
}

HANDLE OpsMaster::OpenFileNative(std::wstring file, DWORD access_mask, DWORD share_mode, DWORD creation_dispostion, DWORD flags)
{
	file = BuildNativePath(file);
	access_mask |= SYNCHRONIZE;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	IO_STATUS_BLOCK io;
	_RtlInitUnicodeString(&target, file.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	NTSTATUS status;
	HANDLE ret = 0;
	switch (creation_dispostion) {
	case OPEN_EXISTING:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | flags, NULL, NULL);
		break;
	case OPEN_ALWAYS:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE | flags, NULL, NULL);
		break;
	case CREATE_ALWAYS:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE | flags, NULL, NULL);
		break;
	case CREATE_NEW:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_CREATE,
			FILE_NON_DIRECTORY_FILE | flags, NULL, NULL);
		break;
	case TRUNCATE_EXISTING:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OVERWRITE,
			FILE_NON_DIRECTORY_FILE | flags, NULL, NULL);
		break;
	}
	if (status != STATUS_SUCCESS)
		SetLastErr(_RtlNtStatusToDosError(status));
	return ret;
}

HANDLE OpsMaster::OpenFileNative(std::string file, DWORD access_mask, DWORD share_mode, DWORD creation_dispostion, DWORD flags)
{
	return OpsMaster::OpenFileNative(std::wstring(file.begin(), file.end()),
		access_mask, share_mode, creation_dispostion);
}

bool OpsMaster::WriteFileNative(HANDLE hfile, PVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER li;
	li.LowPart = 0;
	li.HighPart = 0;
	NTSTATUS status = _NtWriteFile(hfile, NULL,
		NULL, NULL, &io, lpBuffer, nNumberOfBytesToWrite, &li, NULL);
	if (status == STATUS_PENDING)
		status = _NtWaitForSingleObject(hfile, FALSE, NULL);
	if (lpNumberOfBytesWritten != nullptr)
		*lpNumberOfBytesWritten = io.Information;
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	
	return true;
}

bool OpsMaster::ReadFileNative(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead)
{
	if (nNumberOfBytesToRead == 0) {
		LARGE_INTEGER sz;
		GetFileSizeEx(hFile, &sz);
		nNumberOfBytesToRead = sz.QuadPart;
	}
	LARGE_INTEGER offset;
	offset.LowPart = 0;
	offset.HighPart = 0;
	IO_STATUS_BLOCK io;
	NTSTATUS status = _NtReadFile(hFile, NULL, NULL, NULL,
		&io, lpBuffer, nNumberOfBytesToRead, &offset, NULL);
	if (status == STATUS_PENDING)
		status = _NtWaitForSingleObject(hFile, FALSE, NULL);

	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	if (lpNumberOfBytesRead != nullptr)
		*lpNumberOfBytesRead = io.Information;
	return true;
}

HANDLE OpsMaster::OpenProcessNative(DWORD PID, DWORD access_mask)
{
	HANDLE hret = nullptr;
	OBJECT_ATTRIBUTES objattr;
	CLIENT_ID id = { (HANDLE)PID,0 };
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	NTSTATUS status = _NtOpenProcess(&hret, access_mask, &objattr, &id);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
	}
	return hret;
}

bool OpsMaster::SuspendProcess(HANDLE hprocess)
{
	NTSTATUS status = _NtSuspendProcess(hprocess);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::ResumeProcess(HANDLE hprocess)
{
	NTSTATUS status = _NtResumeProcess(hprocess);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::TerminateProcessNative(DWORD process_id)
{
	CLIENT_ID id = { (HANDLE)process_id, 0 };
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	HANDLE proc;
	NTSTATUS status = _NtOpenProcess(&proc, PROCESS_TERMINATE, &objattr, &id);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	status = _NtTerminateProcess(proc, STATUS_SUCCESS);
	_NtClose(proc);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}
bool OpsMaster::TerminateProcessNative(HANDLE hprocess)
{
	NTSTATUS status = _NtTerminateProcess(hprocess, STATUS_SUCCESS);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

HANDLE OpsMaster::SetTokenDosDevice(std::wstring device_path, HANDLE htoken)
{
	if (htoken != NULL) {
		ImpersonateLoggedOnUser(htoken);
	}
	HANDLE hret = OpsMaster::CreateNativeSymlink(std::wstring(L"\\??\\c:"), std::wstring(device_path));
	if (htoken != NULL) {
		RevertToSelf();
	}
	return hret;
}

HANDLE OpsMaster::SetTokenDosDevice(std::string device_path, HANDLE htoken)
{
	return OpsMaster::SetTokenDosDevice(std::wstring(device_path.begin(), device_path.end()),
		htoken);
}

void OpsMaster::bsod() {
	BOOLEAN b;
	ULONG r;
	_RtlAdjustPrivilege(19, true, false, &b);
	_NtRaiseHardError(0xDeadDead, 0, 0, 0, 6, &r);
	return;
}

HANDLE OpsMaster::OpenNamedPipe(std::wstring pipe_name, DWORD desired_access, DWORD impersonation_level)
{

	UNICODE_STRING pipe;
	OBJECT_ATTRIBUTES objattr;
	HANDLE ret;
	IO_STATUS_BLOCK io;
	_RtlInitUnicodeString(&pipe, pipe_name.c_str());
	InitializeObjectAttributes(&objattr, &pipe, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	DWORD dwattr = FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | impersonation_level;
	NTSTATUS status = _NtCreateFile(&ret, desired_access, &objattr, &io, NULL, dwattr, ALL_SHARING,
		FILE_OPEN, NULL, NULL, NULL);

	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return ret;
}

HANDLE OpsMaster::OpenNamedPipe(std::string pipe_name, DWORD desired_access, DWORD impersonation_level)
{
	return OpsMaster::OpenNamedPipe(std::wstring(pipe_name.begin(), pipe_name.end()),
		desired_access, impersonation_level);
}

bool OpsMaster::CreateNativeHardLink(HANDLE hfile, std::wstring target)
{
	target = BuildNativePath(target);
	IO_STATUS_BLOCK io;
	FILE_LINK_INFORMATION* link_inf = (FILE_LINK_INFORMATION*)HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS|HEAP_ZERO_MEMORY,sizeof(FILE_LINK_INFORMATION) + (target.size() * sizeof(WCHAR)));
	link_inf->FileNameLength = target.size() * sizeof(WCHAR);
	link_inf->ReplaceIfExists = TRUE;
	link_inf->RootDirectory = NULL;
	memcpy(&link_inf->FileName[0], target.c_str(), target.size() * sizeof(WCHAR));
	NTSTATUS status = _NtSetInformationFile(hfile, &io, link_inf, sizeof(FILE_LINK_INFORMATION) + (target.size() * sizeof(WCHAR)), FileLinkInformation);
	HeapFree(GetProcessHeap(), NULL, link_inf);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::CreateNativeHardLink(HANDLE hfile, std::string target)
{
	return OpsMaster::CreateNativeHardLink(hfile, std::wstring(target.begin(), target.end()));
}

bool OpsMaster::CreateNativeHardLink(std::wstring link, std::wstring target)
{

	// Before windows hardlink mitigation, only GENERIC_READ is required to create the hardlink
	// but since the mitigation, WRITE_ATTRIBUTES is now required to create a hardlink
	// the best solution for me here is to open the file with MAXIMUM_ALLOWED
	HANDLE hf = OpsMaster::OpenFileNative(link);
	bool ret = OpsMaster::CreateNativeHardLink(hf, target);
	_NtClose(hf);
	return ret;
}

bool OpsMaster::CreateNativeHardLink(std::string link, std::string target)
{
	// Before windows hardlink mitigation, only GENERIC_READ is required to create the hardlink
	// but since the mitigation, WRITE_ATTRIBUTES is now required to create a hardlink
	// the best solution for me here is to open the file with MAXIMUM_ALLOWED
	HANDLE hf = OpsMaster::OpenFileNative(link);
	bool ret = OpsMaster::CreateNativeHardLink(hf, target);
	_NtClose(hf);
	return ret;
}

bool OpsMaster::CreateMountPoint(HANDLE hdir, std::wstring target, std::wstring printname)
{
	
	target = BuildNativePath(target);
	size_t targetsz = target.size() * 2;
	size_t printnamesz = printname.size() * 2;
	size_t pathbuffersz = targetsz + printnamesz + 12;
	size_t totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
	REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS| HEAP_ZERO_MEMORY, totalsz);
	//memset(rdb, 0, totalsz);
	rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
	rdb->Reserved = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer, target.c_str(), targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer + target.size() + 1, printname.c_str(), printnamesz + 2);
	DWORD cb = 0;
	OVERLAPPED ov = { 0 };
	HANDLE hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	ov.hEvent = hevent;
	bool ret = false;
	DWORD retsz = 0;
	DeviceIoControl(hdir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
	HeapFree(GetProcessHeap(), NULL, rdb);
	if (GetLastError() == ERROR_IO_PENDING) {
		GetOverlappedResult(hdir, &ov, &retsz, TRUE);
	}
	if (GetLastError() == ERROR_SUCCESS) {
		ret = true;
	}
	else
		SetLastErr(GetLastError());
	CloseHandle(hevent);

	return ret;
}

bool OpsMaster::CreateMountPoint(HANDLE hdir, std::string target, std::string printname)
{
	return OpsMaster::CreateMountPoint(hdir, std::wstring(target.begin(), target.end()),
		std::wstring(printname.begin(), printname.end()));
}

bool OpsMaster::CreateMountPoint(std::wstring dir, std::wstring target, std::wstring printname)
{
	
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_ALWAYS);
	bool ret = CreateMountPoint(hdir, target, printname);
	_NtClose(hdir);
	return ret;
}

bool OpsMaster::CreateMountPoint(std::string dir, std::string target, std::string printname)
{
	return OpsMaster::CreateMountPoint(std::wstring(dir.begin(), dir.end()),
		std::wstring(target.begin(), target.end()), std::wstring(printname.begin(), printname.end()));
}

bool OpsMaster::DeleteMountPoint(HANDLE hdir)
{
	REPARSE_GUID_DATA_BUFFER rp_buffer = { 0 };
	rp_buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	OVERLAPPED ov = { 0 };
	HANDLE hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	ov.hEvent = hevent;
	bool ret = false;
	DeviceIoControl(hdir, FSCTL_DELETE_REPARSE_POINT, &rp_buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
		nullptr, NULL, &cb, &ov);
	if (GetLastError() == ERROR_IO_PENDING) {
		GetOverlappedResult(hdir, &ov, &cb, TRUE);
	}
	if (GetLastError() == ERROR_SUCCESS) {
		ret = true;
	}
	else
		SetLastErr(GetLastError());
	CloseHandle(hevent);

	return ret;
}

bool OpsMaster::DeleteMountPoint(std::wstring dir)
{
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_EXISTING);
	bool rt = OpsMaster::DeleteMountPoint(hdir);
	_NtClose(hdir);
	return rt;
}

bool OpsMaster::DeleteMountPoint(std::string dir)
{
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_EXISTING);
	bool rt = OpsMaster::DeleteMountPoint(hdir);
	_NtClose(hdir);
	return rt;
}

std::wstring OpsMaster::GetMountPointData(HANDLE hdir, std::wstring)
{
	REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)_malloca(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

	DWORD rd = 0;

	if (!DeviceIoControl(hdir, FSCTL_GET_REPARSE_POINT, NULL,
		NULL, rdb, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &rd, nullptr))
		return L"";
	WCHAR* bs = &rdb->MountPointReparseBuffer.PathBuffer[rdb->MountPointReparseBuffer.SubstituteNameOffset / 2];
	std::wstring ret = std::wstring(bs, bs + (rdb->MountPointReparseBuffer.SubstituteNameLength / 2));
	free(rdb);
	return ret;
}

std::string OpsMaster::GetMountPointData(HANDLE hdir, std::string)
{
	std::wstring rt = OpsMaster::GetMountPointData(hdir, L"");
	return std::string(rt.begin(), rt.end());
}

std::wstring OpsMaster::GetMountPointData(std::wstring dir)
{
	HANDLE hdir = OpsMaster::OpenDirectory(dir, GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	std::wstring ret = OpsMaster::GetMountPointData(hdir, L"");
	_NtClose(hdir);
	return ret;
}

std::string OpsMaster::GetMountPointData(std::string dir)
{
	HANDLE hdir = OpsMaster::OpenDirectory(dir, GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	std::string ret = OpsMaster::GetMountPointData(hdir, "");
	_NtClose(hdir);
	return ret;
}

HANDLE OpsMaster::CreateObjDir(std::wstring dir, HANDLE hshadow)
{
	HANDLE rt = NULL;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	_RtlInitUnicodeString(&target, dir.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	NTSTATUS status = _NtCreateDirectoryObjectEx(&rt, GENERIC_ALL, &objattr, hshadow, NULL);


	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return rt;
}

HANDLE OpsMaster::CreateObjDir(std::string dir, HANDLE hshadow)
{
	return OpsMaster::CreateObjDir(std::wstring(dir.begin(), dir.end()), hshadow);
}

HANDLE OpsMaster::OpenObjDir(std::wstring dir, DWORD access)
{
	OBJECT_ATTRIBUTES objattr;
	HANDLE ret;
	UNICODE_STRING udir;
	_RtlInitUnicodeString(&udir, dir.c_str());
	InitializeObjectAttributes(&objattr, &udir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = _NtOpenDirectoryObject(&ret, access, &objattr);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return ret;
}

HANDLE OpsMaster::OpenObjDir(std::string dir, DWORD access)
{
	return OpsMaster::OpenObjDir(std::wstring(dir.begin(), dir.end()), access);
}

bool OpsMaster::MakePermanentObj(HANDLE hobj)
{
	NTSTATUS status = _ZwMakePermanentObject(hobj);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::CreateAndWaitLock(std::wstring file, _UserCallback cb, bool IsDirectory)
{
	HANDLE h;
	if (IsDirectory)
		h = OpenDirectory(file);

	else
		h = OpenFileNative(file);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	lock_ptr lk = FileOpLock::CreateLock(h, cb);
	if (lk != nullptr) { lk->WaitForLock(INFINITE); }
	else {
		_NtClose(h);
		delete lk;
		return false;
	}
	_NtClose(h);
	delete lk;
	return true;
}

bool OpsMaster::CreateAndWaitLock(std::string file, _UserCallback cb, bool IsDirectory)
{
	return OpsMaster::CreateAndWaitLock(std::wstring(file.begin(), file.end()), cb, IsDirectory);
}

bool OpsMaster::CreateAndWaitLock(HANDLE h, _UserCallback cb)
{
	FileOpLock* lk = FileOpLock::CreateLock(h, cb);
	if (lk != nullptr) {
		lk->WaitForLock(INFINITE);
		return false;
	}
	return true;
}

lock_ptr OpsMaster::CreateLock(HANDLE h, _UserCallback cb)
{
	lock_ptr lk = FileOpLock::CreateLock(h, cb);
	return lk;
}

lock_ptr OpsMaster::CreateLock(std::wstring file, _UserCallback cb, bool IsDirectory)
{
	HANDLE g;
	if (IsDirectory)
		g = OpsMaster::OpenDirectory(file);
	else
		g = OpsMaster::OpenFileNative(file);
	return OpsMaster::CreateLock(g, cb);
}

lock_ptr OpsMaster::CreateLock(std::string file, _UserCallback cb, bool IsDirectory)
{
	return OpsMaster::CreateLock(std::wstring(file.begin(), file.end()), cb, IsDirectory);
}

bool OpsMaster::MoveFileToTempDir(HANDLE h, DWORD temp_location, std::wstring loc)
{

	std::wstring randomstr = this->GenerateRandomStr();
	std::wstring path_to_move;
	WCHAR temp_path[MAX_PATH];
	switch (temp_location) {
	case USE_USER_TEMP_DIR:
		ExpandEnvironmentStrings(L"%TEMP%", temp_path, MAX_PATH);
		path_to_move = temp_path + std::wstring(L"\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	case USE_SYSTEM_TEMP_DIR:
		GetWindowsDirectory(temp_path, MAX_PATH);
		path_to_move = temp_path + std::wstring(L"\\Temp\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	case USE_CUSTOM_TEMP_DIR:
		path_to_move = loc + std::wstring(L"\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	}
	return false;
}

bool OpsMaster::MoveFileToTempDir(std::wstring file, bool IsDirectory, DWORD temp_location, std::wstring loc)
{
	HANDLE g;
	if (IsDirectory)
		g = OpsMaster::OpenDirectory(file, DELETE, ALL_SHARING, OPEN_EXISTING);
	else
		g = OpsMaster::OpenFileNative(file, DELETE, ALL_SHARING, OPEN_EXISTING);
	return OpsMaster::MoveFileToTempDir(g, temp_location, L"");
}

bool OpsMaster::MoveFileToTempDir(std::string file, bool IsDirectory, DWORD temp_location, std::string loc)
{
	return OpsMaster::MoveFileToTempDir(std::wstring(file.begin(), file.end()), IsDirectory, temp_location,
		std::wstring(loc.begin(), loc.end()));
}

bool OpsMaster::DeleteChild(HANDLE root, std::wstring child)
{
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING _child;
	_RtlInitUnicodeString(&_child, child.c_str());
	InitializeObjectAttributes
	(
		&objattr,//object attributes pointer
		&_child,//object name in this case the file to be deleted
		OBJ_CASE_INSENSITIVE,//object attributes
		root,//root directory HANDLE
		NULL//security descriptor must be null
	);
	NTSTATUS status = _ZwDeleteFile(&objattr);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::DeleteFileNative(std::wstring full_path) {
	full_path = BuildNativePath(full_path);
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING _full_path;
	_RtlInitUnicodeString(&_full_path, full_path.c_str());
	InitializeObjectAttributes
	(
		&objattr,
		&_full_path,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);
	NTSTATUS status = _ZwDeleteFile(&objattr);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}
bool OpsMaster::DeleteFileNative(std::string full_path) {
	return OpsMaster::DeleteFileNative(std::wstring(full_path.begin(), full_path.end()));
}

bool OpsMaster::RRemoveDirectory(std::wstring dir)
{
	//this code isn't designed to handle symbolic link, only junctions
	DWORD fst_attr = GetFileAttributes(dir.c_str());
	if (fst_attr & FILE_ATTRIBUTE_NORMAL)
		return OpsMaster::DeleteFileNative(dir);
	if (fst_attr & FILE_ATTRIBUTE_REPARSE_POINT)
		return RemoveDirectory(dir.c_str());
	std::wstring search_path = std::wstring(dir) + L"\\*.*";
	std::wstring s_p = std::wstring(dir) + std::wstring(L"\\");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(search_path.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
			{
				continue;
			}
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				RemoveDirectory(std::wstring(s_p + fd.cFileName).c_str());
				continue;
			}
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				OpsMaster::DeleteFileNative(std::wstring(s_p + fd.cFileName));
				continue;
			}
			if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
			{
				OpsMaster::RRemoveDirectory(s_p + fd.cFileName);
			}
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	if (RemoveDirectoryW(dir.c_str()) != 0) {
		return false;
	}
	return true;
}


bool OpsMaster::RRemoveDirectory(std::string dir)
{
	return OpsMaster::RRemoveDirectory(std::wstring(dir.begin(), dir.end()));
}

bool OpsMaster::DeleteByHandle(HANDLE hfile)
{
	FILE_DISPOSITION_INFORMATION_EX dispositioninfo = { 0 };
	dispositioninfo.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE | FILE_DISPOSITION_POSIX_SEMANTICS;
	IO_STATUS_BLOCK io;
	NTSTATUS status = _NtSetInformationFile(hfile, &io, &dispositioninfo, sizeof(FILE_DISPOSITION_INFORMATION_EX), FileDispositionInformationEx);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}


std::wstring OpsMaster::GenerateRandomStr()
{
	GUID gg;
	HRESULT hs = CoCreateGuid(&gg);
	WCHAR mx[MAX_PATH];
	int x = StringFromGUID2(gg, mx, MAX_PATH);
	return mx;
}




OpsMaster::FileOpLock::FileOpLock(UserCallback cb) :
	g_inputBuffer({ 0 }), g_outputBuffer({ 0 }), g_o({ 0 }), g_hFile(INVALID_HANDLE_VALUE), g_hLockCompleted(nullptr), g_wait(nullptr), _cb(cb)
{
	g_inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_inputBuffer.StructureLength = sizeof(g_inputBuffer);
	g_inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	g_inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	g_outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_outputBuffer.StructureLength = sizeof(g_outputBuffer);
}


OpsMaster::FileOpLock::~FileOpLock()
{
	if (g_wait)
	{
		SetThreadpoolWait(g_wait, nullptr, nullptr);
		CloseThreadpoolWait(g_wait);
		g_wait = nullptr;
	}

	if (g_o.hEvent)
	{
		CloseHandle(g_o.hEvent);
		g_o.hEvent = nullptr;
	}

	if (g_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}
}

bool OpsMaster::FileOpLock::BeginLock(HANDLE h)
{
	g_hLockCompleted = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	g_hFile = h;
	g_wait = CreateThreadpoolWait(WaitCallback, this, nullptr);
	if (g_wait == nullptr)
	{
		return false;
	}

	SetThreadpoolWait(g_wait, g_o.hEvent, nullptr);

	DWORD bytesReturned;
	DeviceIoControl(g_hFile, FSCTL_REQUEST_OPLOCK,
		&g_inputBuffer, sizeof(g_inputBuffer),
		&g_outputBuffer, sizeof(g_outputBuffer),
		nullptr, &g_o);

	SetLastErr(GetLastError());
	if (GetLastError() != ERROR_IO_PENDING) {
		return false;
	}
	return true;
}

OpsMaster::FileOpLock* OpsMaster::FileOpLock::CreateLock(HANDLE h, OpsMaster::FileOpLock::UserCallback cb)
{
	OpsMaster::FileOpLock* ret = new OpsMaster::FileOpLock(cb);
	if (ret->BeginLock(h))
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}

void OpsMaster::FileOpLock::WaitForLock(UINT Timeout)
{
	WaitForSingleObject(g_hLockCompleted, Timeout);
}

void OpsMaster::FileOpLock::WaitCallback(PTP_CALLBACK_INSTANCE Instance,
	PVOID Parameter, PTP_WAIT Wait,
	TP_WAIT_RESULT WaitResult)
{
	UNREFERENCED_PARAMETER(Instance);
	UNREFERENCED_PARAMETER(Wait);
	UNREFERENCED_PARAMETER(WaitResult);

	OpsMaster::FileOpLock* lock = reinterpret_cast<FileOpLock*>(Parameter);

	lock->DoWaitCallback();
}

void OpsMaster::FileOpLock::DoWaitCallback()
{
	DWORD dwBytes;
	if (!GetOverlappedResult(g_hFile, &g_o, &dwBytes, TRUE)) {
	}

	if (_cb)
	{
		_cb();
	}

	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;
	SetEvent(g_hLockCompleted);
}

std::wstring OpsMaster::GetUserSid(HANDLE htoken) {

	//I'm gonna change this later, but too lazy to actually do it. I guess I'll stick with this for a while
	//It does work so there will be a quite long time before I touch this again
	DWORD dwSize;

	GetTokenInformation(htoken, TokenUser, nullptr, 0, &dwSize);

	std::vector<BYTE> userbuffer(dwSize);

	GetTokenInformation(htoken, TokenUser, &userbuffer[0], dwSize, &dwSize);

	PTOKEN_USER user = reinterpret_cast<PTOKEN_USER>(&userbuffer[0]);

	LPWSTR lpUser;
	std::wstring ret = L"";

	if (ConvertSidToStringSid(user->User.Sid, &lpUser))
	{
		ret = lpUser;
		LocalFree(lpUser);
	}

	return ret;
}

HANDLE OpsMaster::GetAnonymousToken()
{
	HANDLE htoken = NULL;
	HANDLE hret = NULL;
	ImpersonateAnonymousToken(GetCurrentThread());
	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &htoken);
	RevertToSelf();
	return htoken;
}

bool OpsMaster::MakeTemporaryObj(HANDLE hobj)
{
	NTSTATUS status = _ZwMakeTemporaryObject(hobj);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

std::wstring OpsMaster::GetCurrentExeDir()
{
	WCHAR mx[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), mx, MAX_PATH);
	std::wstring ret = mx;
	for (int i = ret.size(); i > 0; i--) {
		if (ret[i] != L'\\') {
			continue;
		}
		ret.erase(i, ret.size());
		break;
	}
	return ret;
}

std::wstring OpsMaster::GetCurrentExeDirWithFileAppended(std::wstring file)
{

	return OpsMaster::GetCurrentExeDir() + L"\\" + file;
}

std::wstring OpsMaster::RegPathToNative(LPCWSTR lpPath)
{
	std::wstring regpath = L"\\REGISTRY\\";

	// Already native rooted
	if (lpPath[0] == '\\')
	{
		return lpPath;
	}

	if (_wcsnicmp(lpPath, L"HKLM\\", 5) == 0)
	{
		return regpath + L"MACHINE\\" + &lpPath[5];
	}
	else if (_wcsnicmp(lpPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
		return regpath + L"MACHINE\\" + &lpPath[19];
	}
	else if (_wcsnicmp(lpPath, L"HKU\\", 4) == 0)
	{
		return regpath + L"USER\\" + &lpPath[4];
	}
	else if (_wcsnicmp(lpPath, L"HKEY_USERS\\", 11) == 0)
	{
		return regpath + L"USER\\" + &lpPath[11];
	}
	else if (_wcsnicmp(lpPath, L"HKCU\\", 5) == 0)
	{
		std::wstring ret = regpath + L"USER\\" + GetUserSid().c_str() + L"\\" + &lpPath[5];
		return ret;
	}
	else if (_wcsnicmp(lpPath, L"HKEY_CURRENT_USER\\", 18) == 0)
	{
		std::wstring ret = regpath + L"USER\\" + GetUserSid().c_str() + L"\\" + &lpPath[18];
		return ret;
	}
	else
	{
		//error
		return L"";
	}
}

HANDLE OpsMaster::RegCreateKeyNative(std::wstring target, DWORD desired_access, bool OpenLink, bool CreateLink)
{
	HANDLE hret = NULL;
	UNICODE_STRING _target;
	target = RegPathToNative(target.c_str());
	_RtlInitUnicodeString(&_target, target.c_str());
	DWORD _objflag = OBJ_CASE_INSENSITIVE | (OpenLink ? OBJ_OPENLINK : NULL);
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &_target, _objflag, NULL, NULL);
	if (!(desired_access & KEY_WOW64_64KEY)) {
		desired_access |= KEY_WOW64_64KEY;
	}
	NTSTATUS status = _ZwCreateKey(&hret, desired_access,
		&objattr, NULL, NULL,
		(CreateLink ? INTERNAL_REG_OPTION_CREATE_LINK : NULL) | REG_OPTION_NON_VOLATILE, NULL);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
	}
	return hret;
}

HANDLE OpsMaster::RegCreateKeyNative(std::string target, DWORD desired_access, bool OpenLink, bool CreateLink) {
	return OpsMaster::RegCreateKeyNative(
		std::wstring(target.begin(), target.end()),
		desired_access, OpenLink, CreateLink
	);
}

bool OpsMaster::RegDeleteKeyNative(HANDLE hkey) {

	NTSTATUS status = _ZwDeleteKey(hkey);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::RegDeleteKeyNative(std::wstring target) {
	HANDLE hk = OpsMaster::RegCreateKeyNative(target, DELETE, true);
	bool ret = OpsMaster::RegDeleteKeyNative(hk);
	_NtClose(hk);
	return ret;
}

bool OpsMaster::RegDeleteKeyNative(std::string target) {
	return OpsMaster::RegDeleteKeyNative(std::wstring(target.begin(), target.end()));
}

bool OpsMaster::RegCreateNativeLink(HANDLE hkey, std::wstring target) {

	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING value;
	target = RegPathToNative(target.c_str());
	_RtlInitUnicodeString(&value, L"SymbolicLinkValue");

	NTSTATUS status = _ZwSetValueKey(hkey, &value, NULL, REG_LINK,
		(PVOID)target.c_str(), target.length() * sizeof(WCHAR));
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;

}
bool OpsMaster::RegCreateNativeLink(HANDLE hkey, std::string target) {
	return OpsMaster::RegCreateNativeLink(hkey, std::wstring(target.begin(), target.end()));
}
bool OpsMaster::RegCreateNativeLink(std::wstring link, std::wstring target) {
	HANDLE hk = OpsMaster::RegCreateKeyNative(link, KEY_CREATE_LINK | KEY_WRITE, true, true);
	if (!hk) {
		return false;
	}
	bool ret = OpsMaster::RegCreateNativeLink(hk, target);
	_NtClose(hk);
	return ret;
}
bool OpsMaster::RegCreateNativeLink(std::string link, std::string target) {
	std::wstring lnk = std::wstring(link.begin(), link.end());
	std::wstring _target = std::wstring(target.begin(), target.end());
	return OpsMaster::RegCreateNativeLink(lnk,
		_target);
}

bool OpsMaster::SetShortFileNameNative(HANDLE hfile, std::wstring short_name) {

	size_t fni_sz = sizeof(FILE_NAME_INFORMATION) + (short_name.size() * sizeof(WCHAR));
	FILE_NAME_INFORMATION* fni = (FILE_NAME_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fni_sz);
	fni->FileNameLength = short_name.size() * sizeof(WCHAR);
	memcpy(&fni->FileName[0], short_name.c_str(), fni->FileNameLength);
	IO_STATUS_BLOCK io_status = { 0 };
	NTSTATUS stat = _NtSetInformationFile(hfile, &io_status, fni, fni_sz, FileShortNameInformation);
	HeapFree(GetProcessHeap(), NULL, fni);
	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return false;
	}
	return true;

}

bool OpsMaster::SetCaseSensitiveDirectory(HANDLE hf, bool enable) {

	IO_STATUS_BLOCK iob;
	FILE_CASE_SENSITIVE_INFORMATION fcsi = { FILE_CS_FLAG_CASE_SENSITIVE_DIR };
	IO_STATUS_BLOCK io = { 0 };
	NTSTATUS stat = _NtSetInformationFile(hf, &io, &fcsi, sizeof(fcsi), FileCaseSensitiveInformation);
	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return false;
	}
	return true;
}

bool OpsMaster::CreateNTFSLink(HANDLE hfile, std::wstring target, std::wstring printname, bool relative)
{

	BOOLEAN b;
	_RtlAdjustPrivilege(35, true, false, &b);

	DWORD target_byte_size = target.size() * 2;
	DWORD printname_byte_size = printname.size() * 2;
	DWORD path_buffer_size = target_byte_size + printname_byte_size + 16;
	DWORD total_size = path_buffer_size + REPARSE_DATA_BUFFER_HEADER_LENGTH;
	REPARSE_DATA_BUFFER* buff = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, total_size);

	buff->ReparseTag = IO_REPARSE_TAG_SYMLINK;
	buff->ReparseDataLength = path_buffer_size;
	buff->Reserved = NULL;
	buff->SymbolicLinkReparseBuffer.SubstituteNameLength = target_byte_size;
	buff->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
	memcpy(buff->SymbolicLinkReparseBuffer.PathBuffer, target.c_str(), target_byte_size + 2);
	buff->SymbolicLinkReparseBuffer.PrintNameLength = printname_byte_size;
	buff->SymbolicLinkReparseBuffer.PrintNameOffset = target_byte_size + 2;
	buff->SymbolicLinkReparseBuffer.Flags = relative ? SYMLINK_FLAG_RELATIVE : 0;
	memcpy(buff->SymbolicLinkReparseBuffer.PathBuffer + target.size() + 1, printname.c_str(), printname_byte_size + 2);

	HANDLE hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED ov = { 0 };
	ov.hEvent = hevent;
	DWORD ret_sz = 0;
	bool ret = false;
	DeviceIoControl(hfile, FSCTL_SET_REPARSE_POINT, buff, total_size, NULL, NULL, &ret_sz, &ov);
	HeapFree(GetProcessHeap(), NULL, buff);
	if (GetLastError() == ERROR_IO_PENDING) {
		GetOverlappedResult(hfile, &ov, &ret_sz, TRUE);
	}
	if (GetLastError() == ERROR_SUCCESS) {
		ret = true;
	}
	else
		SetLastErr(GetLastError());
	CloseHandle(hevent);


	return ret;
}

bool OpsMaster::SetProcessDeviceMap(HANDLE hprocess, HANDLE hdevice_map) {
	// ProcessDeviceMap = 23
	NTSTATUS stat = _NtSetInformationProcess(hprocess, (PROCESS_INFORMATION_CLASS)23, &hdevice_map, sizeof(hdevice_map));
	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return false;
	}
	return true;
}

/*
HANDLE OpsMaster::OpenObjLink(std::wstring link,DWORD desired_access) {

	UNICODE_STRING lnk;
	_RtlInitUnicodeString(&lnk, link.c_str());
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &lnk, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hd = NULL;
	NTSTATUS stat = _NtOpenSymbolicLinkObject(&hd, desired_access, &objattr);
	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return NULL;
	}
	return hd;
}
//not tested yet 
*/