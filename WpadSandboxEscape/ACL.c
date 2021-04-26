#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <AclAPI.h>

#pragma comment(lib, "AdvAPI32.lib")

BOOL SetObjectAclAllAccess(HANDLE hObject, wchar_t *SID, SE_OBJECT_TYPE ObjectType) {
	PACL pDacl = NULL, pNewDACL = NULL;
	EXPLICIT_ACCESSW ExplicitAccess = { 0 };
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	PSID pSID = NULL;
	BOOL bSuccess = FALSE;
	uint32_t dwError = -1;

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
