#include <windows.h>
#include <stdio.h>

// msvcrt.dll exports
typedef int(WINAPI* WPRINTF)(
	const wchar_t* format,
	...
);

typedef void*(WINAPI* CALLOC)(
	size_t num,
	 size_t size
);

typedef char*(WINAPI* STRSTR)(
	const char *str,
	 const char *strSearch
);

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);

// parun's fart functions
typedef BOOL(WINAPI *CreateProcessA_t) (
    LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef NTSTATUS(WINAPI *NtReadVirtualMemory_t)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID               Buffer,
	ULONG                NumberOfBytesToRead,
	PULONG              NumberOfBytesReaded
	);

typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID lpAddress,
	size_t dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);

typedef NTSTATUS(NTAPI* NtDelayExecution_t)(
	BOOL Alertable,
	PLARGE_INTEGER DelayInterval
);

typedef LPVOID(WINAPI* VirtualAlloc_t)(
	LPVOID lpAddress,
	size_t dwSize,
	DWORD flAllocationType,
	DWORD flProtect
);

typedef BOOL(WINAPI* TerminateProcess_t)(
	HANDLE hProcess,
	UINT uExitCode
);