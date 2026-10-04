#include <Windows.h>
#include <stdarg.h>
#include "util.h"

// legacy globals kept so other TUs link
DWORD g_ssn = 0;
PVOID g_syscall = NULL;

// ---- manual_procaddress: same as before, used for ntdll export walks ----
PVOID manual_procaddress(HMODULE mod_handle, const char* funcName) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_handle;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)mod_handle + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[0].Size;
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mod_handle + exportRVA);

    DWORD* names = (DWORD*)((BYTE*)mod_handle + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)mod_handle + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)mod_handle + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)mod_handle + names[i]);
        if (strcmp(name, funcName) == 0) {
            WORD  ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];

            if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) {
                char* forwardStr = (char*)((BYTE*)mod_handle + funcRVA);
                char fwdDll[128] = { 0 };
                char fwdFunc[128] = { 0 };

                char* dot = strchr(forwardStr, '.');
                if (!dot) return NULL;

                size_t dllLen = dot - forwardStr;
                RtlCopyMemory(fwdDll, forwardStr, dllLen);
                if (dllLen + 4 < sizeof(fwdDll)) {
                    fwdDll[dllLen] = '.';
                    fwdDll[dllLen + 1] = 'd';
                    fwdDll[dllLen + 2] = 'l';
                    fwdDll[dllLen + 3] = 'l';
                    fwdDll[dllLen + 4] = '\0';
                }

                size_t funcLen = strlen(dot + 1);
                if (funcLen < sizeof(fwdFunc)) {
                    RtlCopyMemory(fwdFunc, dot + 1, funcLen + 1);
                }

                HMODULE fwdMod = LoadLibraryA(fwdDll);
                if (!fwdMod) return NULL;
                return manual_procaddress(fwdMod, fwdFunc);
            }

            return (PVOID)((BYTE*)mod_handle + funcRVA);
        }
    }
    return NULL;
}

// ---- check_seimpersonate: still works with WinAPI ----
BOOL check_seimpersonate() {
    TOKEN_PRIVILEGES* ptp = NULL;
    DWORD dwLength = 0;

    GetTokenInformation(GetCurrentProcessToken(), TokenPrivileges, NULL, 0, &dwLength);
    if (dwLength == 0) {
        printf("[-] ERROR: GetTokenInformation(size) failed %lu\n", GetLastError());
        return 0;
    }

    ptp = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (!ptp) return 0;

    BOOL ok = FALSE;
    if (GetTokenInformation(GetCurrentProcessToken(), TokenPrivileges, ptp, dwLength, &dwLength)) {
        LUID seimpersonateLuid = { 0 };
        LookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &seimpersonateLuid);
        for (DWORD i = 0; i < ptp->PrivilegeCount; i++) {
            if (ptp->Privileges[i].Luid.LowPart == seimpersonateLuid.LowPart &&
                ptp->Privileges[i].Luid.HighPart == seimpersonateLuid.HighPart) {
                if (ptp->Privileges[i].Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) {
                    printf("[x] SeImpersonatePrivilege\n");
                    ok = TRUE;
                    break;
                }
            }
        }
    }
    if (!ok) {
        printf("[-] ERROR: Missing SeImpersonatePrivilege!\n");
    }
    HeapFree(GetProcessHeap(), 0, ptp);
    return ok;
}