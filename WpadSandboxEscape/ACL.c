#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <AclAPI.h>

#pragma comment(lib, "AdvAPI32.lib")

BOOL AddFileAcl(const wchar_t *FilePath, const wchar_t *SID) {
	PACL pDacl = NULL, pNewDACL = NULL;
	EXPLICIT_ACCESSW ExplicitAccess = { 0 };
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	PSID psid = NULL;
	BOOL bSuccess = FALSE;
	uint32_t dwError = -1;

	if ((dwError = GetNamedSecurityInfoW(FilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor)) == ERROR_SUCCESS) {
		if (ConvertStringSidToSidW(SID, &psid)) {

			ExplicitAccess.grfAccessMode = SET_ACCESS;
			ExplicitAccess.grfAccessPermissions = GENERIC_ALL;
			ExplicitAccess.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
			ExplicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ExplicitAccess.Trustee.pMultipleTrustee = NULL;
			ExplicitAccess.Trustee.ptstrName = (wchar_t*)psid;
			ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

			if ((dwError = SetEntriesInAclW(1, &ExplicitAccess, pDacl, &pNewDACL)) == ERROR_SUCCESS) {
				if ((dwError = SetNamedSecurityInfoW((wchar_t *)FilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL)) == ERROR_SUCCESS) {
					bSuccess = TRUE;
				}
				else {
					printf("... failed to set new DACL for %ws to (error 0x%08x)\r\n", FilePath, dwError);
				}

				LocalFree(pNewDACL);
			}
			else {
				printf("... failed to set new entry in DACL for %ws to (error 0x%08x)\r\n", FilePath, dwError);
			}
		}
		else {
			printf("... failed to convert string %ws to SID (error 0x%08x)\r\n", SID, GetLastError());
		}
		LocalFree(psid);
	}
	else {
		printf("... failed to query DACL for file object at %ws (error 0x%08x)\r\n", FilePath, dwError);
	}

	return bSuccess;
}

BOOL SetEveryoneFileAcl(const wchar_t *FilePath) {
	HANDLE hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL); // Create the file if it doesn't exist

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	else {
		CloseHandle(hFile);
		return AddFileAcl(FilePath, L"S-1-1-0");
	}
}