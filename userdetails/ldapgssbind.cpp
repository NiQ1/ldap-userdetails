#include "ldapgssbind.h"
#include "spnhelper.h"
#include <sspi.h>

void LDAPGSSAPIBind(LDAP* pLDAP, LPTSTR ptszDCName)
{
	CredHandle SSPICreds = { 0 };
	TimeStamp CredExpiry = { 0 };
	SECURITY_STATUS status = 0;
	CtxtHandle SecurityContext = { 0 };
	SecBufferDesc OutBufferDescFirst = { 0 };
	SecBuffer OutBufferFirst = { 0 };
	// ISC_REQ_ALLOCATE_MEMORY seems to sometimes corrupt the heap,
	// causing FreeContextBuffer() to segfault and crash. I don't think
	// a security token can be bigger than 65535 bytes so I'm hardcoding
	// it because it's better than crashing.
	SEC_CHAR OutBufferFirstBuf[65535] = { 0 };
	SecBufferDesc InBufferDesc = { 0 };
	SecBuffer InBuffer = { 0 };
	SecBufferDesc OutBufferDescNext = { 0 };
	SecBuffer OutBufferNext = { 0 };
	SEC_CHAR OutBufferNextBuf[65535] = { 0 };
	unsigned long ulContextAttr;

	try {
		// Get Kerberos ticket of the current user
		status = AcquireCredentialsHandle(NULL, (LPTSTR)_T("Kerberos"), SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &SSPICreds, &CredExpiry);
		if (status != SEC_E_OK) {
			throw std::runtime_error("AcquireCredentialsHandle failed with status " + to_hex(status));
		}

		OutBufferFirst.BufferType = SECBUFFER_TOKEN;
		OutBufferFirst.pvBuffer = OutBufferFirstBuf;
		OutBufferFirst.cbBuffer = sizeof(OutBufferFirstBuf);
		OutBufferDescFirst.ulVersion = SECBUFFER_VERSION;
		OutBufferDescFirst.pBuffers = &OutBufferFirst;
		OutBufferDescFirst.cBuffers = 1;
		status = InitializeSecurityContext(&SSPICreds,
			NULL,
			ptszDCName,
			ISC_REQ_MUTUAL_AUTH,
			0,
			SECURITY_NATIVE_DREP,
			NULL,
			0,
			&SecurityContext,
			&OutBufferDescFirst,
			&ulContextAttr,
			&CredExpiry);
		// Must return "continue needed" since we need to negotiate
		// with the remote LDAP server. SEC_E_SUCCESS is actually not
		// a good response.
		if (status != SEC_I_CONTINUE_NEEDED) {
			throw std::runtime_error("InitializeSecurityContext failed with status " + to_hex(status));
		}

		// Authenticate using GSSAPI with the permissions of the current thread
		BERVAL cred;
		cred.bv_len = OutBufferFirst.cbBuffer;
		cred.bv_val = (PCHAR)OutBufferFirst.pvBuffer;
		PBERVAL pCredReturn;
		int ldap_rv = ldap_sasl_bind_s(pLDAP, (LPTSTR)_T(""), (LPTSTR)_T("GSSAPI"), &cred, NULL, NULL, &pCredReturn);
		if (ldap_rv != LDAP_SUCCESS) {
			throw std::runtime_error("ldap_sasl_bind_s initial call failed (code=0x" + to_hex(ldap_rv) + ").");
		}
		InBuffer.BufferType = SECBUFFER_TOKEN;
		InBuffer.cbBuffer = pCredReturn->bv_len;
		InBuffer.pvBuffer = pCredReturn->bv_val;
		InBufferDesc.ulVersion = SECBUFFER_VERSION;
		InBufferDesc.pBuffers = &InBuffer;
		InBufferDesc.cBuffers = 1;
		OutBufferNext.BufferType = SECBUFFER_TOKEN;
		OutBufferNext.pvBuffer = OutBufferNextBuf;
		OutBufferNext.cbBuffer = sizeof(OutBufferNextBuf);
		OutBufferDescNext.ulVersion = SECBUFFER_VERSION;
		OutBufferDescNext.pBuffers = &OutBufferNext;
		OutBufferDescNext.cBuffers = 1;
		status = InitializeSecurityContext(&SSPICreds,
			&SecurityContext,
			ptszDCName,
			ISC_REQ_MUTUAL_AUTH,
			0,
			SECURITY_NATIVE_DREP,
			&InBufferDesc,
			0,
			&SecurityContext,
			&OutBufferDescNext,
			&ulContextAttr,
			&CredExpiry);
		// Should be successful now, but we still need to pass it back to the server
		if (status != SEC_E_OK) {
			throw std::runtime_error("InitializeSecurityContext failed with status " + to_hex(status));
		}

		SecPkgContext_Sizes sizes;
		status = QueryContextAttributes(&SecurityContext, SECPKG_ATTR_SIZES, &sizes);
		if (status != SEC_E_OK) {
			throw std::runtime_error("QueryContextAttributes failed with status " + to_hex(status));
		}

		cred.bv_len = OutBufferNext.cbBuffer;
		cred.bv_val = (PCHAR)OutBufferNext.pvBuffer;
		ldap_rv = ldap_sasl_bind_s(pLDAP, (LPTSTR)_T(""), (LPTSTR)_T("GSSAPI"), &cred, NULL, NULL, &pCredReturn);
		if (ldap_rv != LDAP_SUCCESS) {
			throw std::runtime_error("ldap_sasl_bind_s second call failed (code=0x" + to_hex(ldap_rv) + ").");
		}
		InBuffer.cbBuffer = pCredReturn->bv_len;
		InBuffer.pvBuffer = pCredReturn->bv_val;
		InBuffer.BufferType = SECBUFFER_STREAM;
		InBufferDesc.ulVersion = SECBUFFER_VERSION;
		InBufferDesc.cBuffers = 1;
		InBufferDesc.pBuffers = &InBuffer;
		ULONG fQOP;
		status = DecryptMessage(&SecurityContext, &InBufferDesc, 0, &fQOP);
		if (status != SEC_E_OK) {
			throw std::runtime_error("DecryptMessage failed with status " + to_hex(status));
		}
		if ((((BYTE*)InBuffer.pvBuffer)[0] & 0x01) == 0) {
			throw std::runtime_error("Server does not support plaintext layer.");
		}
		ULONG pLastResponseSize = sizes.cbSecurityTrailer + sizes.cbBlockSize + 4 + 1;
		SEC_CHAR* pLastResponse = (SEC_CHAR*)alloca(pLastResponseSize);
		memset(pLastResponse, 0, pLastResponseSize);
		// Choose no security layer
		SEC_CHAR* pLastResponseUser = pLastResponse + sizes.cbSecurityTrailer;
		pLastResponseUser[0] = 0x01;
		pLastResponseUser[1] = 0;
		pLastResponseUser[2] = 0;
		pLastResponseUser[3] = 0;
		SecBuffer WrapBuffers[3];
		WrapBuffers[0].BufferType = SECBUFFER_TOKEN;
		WrapBuffers[0].cbBuffer = sizes.cbSecurityTrailer;
		WrapBuffers[0].pvBuffer = pLastResponse;
		WrapBuffers[1].BufferType = SECBUFFER_DATA;
		WrapBuffers[1].cbBuffer = 4;
		WrapBuffers[1].pvBuffer = pLastResponse + sizes.cbSecurityTrailer;
		WrapBuffers[2].BufferType = SECBUFFER_PADDING;
		WrapBuffers[2].cbBuffer = sizes.cbBlockSize;
		WrapBuffers[2].pvBuffer = pLastResponse + sizes.cbSecurityTrailer + 4;
		SecBufferDesc WrapBuffersDesc;
		WrapBuffersDesc.ulVersion = SECBUFFER_VERSION;
		WrapBuffersDesc.cBuffers = 3;
		WrapBuffersDesc.pBuffers = WrapBuffers;

		status = EncryptMessage(&SecurityContext, SECQOP_WRAP_NO_ENCRYPT, &WrapBuffersDesc, 0);
		if (status != SEC_E_OK) {
			throw std::runtime_error("EncryptMessage failed with status " + to_hex(status));
		}
		// This should complete the bind
		ULONG pEncryptedBufSize = 0;
		for (ULONG i = 0; i < WrapBuffersDesc.cBuffers; i++) {
			pEncryptedBufSize += WrapBuffers[i].cbBuffer;
		}
		SEC_CHAR* pEncryptedBuf = (SEC_CHAR*)alloca(pEncryptedBufSize);
		ULONG pos = 0;
		for (ULONG i = 0; i < WrapBuffersDesc.cBuffers; i++) {
			memcpy(pEncryptedBuf + pos, WrapBuffers[i].pvBuffer, WrapBuffers[i].cbBuffer);
			pos += WrapBuffers[i].cbBuffer;
		}
		cred.bv_len = pos;
		cred.bv_val = pEncryptedBuf;
		ldap_rv = ldap_sasl_bind_s(pLDAP, (LPTSTR)_T(""), (LPTSTR)_T("GSSAPI"), &cred, NULL, NULL, &pCredReturn);
		if (ldap_rv != LDAP_SUCCESS) {
			throw std::runtime_error("ldap_sasl_bind_s third call failed (code=0x" + to_hex(ldap_rv) + ").");
		}
	}
	catch (std::exception&) {
		if (SecurityContext.dwLower || SecurityContext.dwUpper) {
			DeleteSecurityContext(&SecurityContext);
		}
		if (SSPICreds.dwLower || SSPICreds.dwUpper) {
			FreeCredentialsHandle(&SSPICreds);
		}
		throw;
	}
	if (SecurityContext.dwLower || SecurityContext.dwUpper) {
		DeleteSecurityContext(&SecurityContext);
	}
	if (SSPICreds.dwLower || SSPICreds.dwUpper) {
		FreeCredentialsHandle(&SSPICreds);
	}
}