#ifndef INC_LDAPGSSBIND
#define INC_LDAPGSSBIND

#include <Windows.h>
#include <Winldap.h>

/**
 *	Bind an LDAP connection using GSSAPI and the permissions
 *	of the current thread.
 *	@param pLDAP Initialized and connected LDAP session
 *	@param ptszDCName Hostname of the LDAP server
 *	@throw std::runtime_error with error description
 */
void LDAPGSSAPIBind(LDAP* pLDAP, LPTSTR ptszDCName);

#endif
