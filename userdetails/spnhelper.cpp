#include "spnhelper.h"
#include <Windows.h>
#include <DSRole.h>
#include <DsGetDC.h>
#include <lm.h>
#include <NtDsAPI.h>
#include <NTSecAPI.h>
#include <stdio.h>
#include <string>

int ResolveLDAPServer(TCHAR* pOutDCName, unsigned long cchOutDCName)
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC* domainInfo = NULL;

	// Get information about the primary domain
	DWORD status = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (BYTE**)&domainInfo);
	int cchDCName = -1;

	if (status == ERROR_SUCCESS) {
		// Get the LDAP server's hostname
		DOMAIN_CONTROLLER_INFO* dcInfo;

		status = DsGetDcName(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dcInfo);

		if (status == ERROR_SUCCESS) {
			cchDCName = _tcslen(dcInfo->DomainControllerName);
			_tcsncpy(pOutDCName, dcInfo->DomainControllerName, cchOutDCName-1);
			pOutDCName[cchOutDCName-1] = '\0';
			NetApiBufferFree(dcInfo);
		}
		else {
			cchDCName = -1;
		}
	}

	DsRoleFreeMemory(domainInfo);

	return cchDCName;
}


int GetLdapServerSPN(TCHAR* pOutSPNData, unsigned long cchSPNData) {
	TCHAR ** spn = NULL;
	DWORD dwSpnCount;
	int cchSPNLen = -1;

	TCHAR tszDCName[256] = { 0 };
	if (ResolveLDAPServer(tszDCName, _countof(tszDCName)) <= 0) {
		return -1;
	}

	// Get SPN data
	DWORD status = DsGetSpn(
		DS_SPN_SERVICE,     // Service class (DS_SPN_SERVICE for LDAP)
		L"ldap",            // Service name (ldap for LDAP)
		tszDCName,          // Hostname of the server
		0,                  // Instance port (0 for default)
		0,                  // Instance count (0 for default)
		NULL,               // No service principal name
		NULL,               // No domain name
		&dwSpnCount,        // Number of SPNs retrieved
		&spn                // Output: SPN data
	);

	if (status == ERROR_SUCCESS && dwSpnCount > 0) {
		cchSPNLen = _tcslen(spn[0]);
		_tcsncpy(pOutSPNData, spn[0], cchSPNData - 1);
		pOutSPNData[cchSPNData - 1] = '\0';
		DsFreeSpnArray(dwSpnCount, spn);
	}

	return cchSPNLen;
}

int GetDNSDomainName(TCHAR* pOutDNSDomain, unsigned long cchDNSDomain)
{
	LSA_HANDLE PolicyHandle;
	LSA_OBJECT_ATTRIBUTES LsaObjectAttributes = { 0 };
	LsaObjectAttributes.Length = sizeof(LsaObjectAttributes);
	int len = 0;

	NTSTATUS status = LsaOpenPolicy(0, &LsaObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &PolicyHandle);
	if (!LSA_SUCCESS(status)) {
		return -1;
	}

	PPOLICY_DNS_DOMAIN_INFO pPolicyDNSDomainInfo;
	status = LsaQueryInformationPolicy(PolicyHandle, PolicyDnsDomainInformation, (void**)&pPolicyDNSDomainInfo);
	if (!LSA_SUCCESS(status)) {
		LsaClose(PolicyHandle);
		return -1;
	}
	if (!pPolicyDNSDomainInfo->Sid) {
		// Not a domain member so return an empty string
		if (cchDNSDomain > 0) {
			pOutDNSDomain[0] = '\0';
		}
	}
	else {
		len = wcslen(pPolicyDNSDomainInfo->DnsDomainName.Buffer);
#ifdef UNICODE
		wcsncpy(pOutDNSDomain, pPolicyDNSDomainInfo->DnsDomainName.Buffer, cchDNSDomain-1);
#else
		wcstombs(pOutDNSDomain, pPolicyDNSDomainInfo->DnsDomainName.Buffer, cchDNSDomain-1);
#endif
		pOutDNSDomain[cchDNSDomain - 1] = '\0';
	}
	LsaFreeMemory(pPolicyDNSDomainInfo);
	LsaClose(PolicyHandle);
	return len;
}

int GetDomainDN(TCHAR* pOutDomainDN, unsigned long cchDomainDN)
{
	TCHAR tszDomainName[256] = { 0 };
	int cchDomainName = GetDNSDomainName(tszDomainName, _countof(tszDomainName));
	if (cchDomainName <= 0) {
		return -1;
	}
	if (cchDomainName == 0) {
		return 0;
	}
	pOutDomainDN[0] = '\0';
	TCHAR* pos = tszDomainName;
	while (pos < tszDomainName + cchDomainName) {
		TCHAR* endpos = _tcschr(pos, '.');
		if (endpos) {
			*endpos = '\0';
		}
		if (pos != tszDomainName) {
			_tcsncat(pOutDomainDN, _T(","), cchDomainDN - _tcslen(pOutDomainDN) - 1);
		}
		_tcsncat(pOutDomainDN, _T("DC="), cchDomainDN - _tcslen(pOutDomainDN) - 1);
		_tcsncat(pOutDomainDN, pos, cchDomainDN - _tcslen(pOutDomainDN) - 1);
		if (endpos) {
			pos = endpos + 1;
		}
		else {
			break;
		}
	}
	return _tcslen(pOutDomainDN);
}

std::string to_hex(unsigned long num)
{
	char buf[32];
	snprintf(buf, _countof(buf), "%0X", num);
	return std::string(buf);
}
