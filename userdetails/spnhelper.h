#ifndef INC_SPNHELPER
#define INC_SPNHELPER

#include <tchar.h>
#include <string>

/**
 *	Retrieves the FQDN of the domain controller of the current domain.
 *	@param pOutDCName OUT Receives the FQDN of the domain controller
 *	@param cchOutDCName Size of pOutDCName in characters
 *	@return Number of characters in the domain controller name or -1 on error
 */
int ResolveLDAPServer(TCHAR* pOutDCName, unsigned long cchOutDCName);

/**
 *	Retrieves the SPN of the LDAP directory service of the current
 *	active directory domain.
 *	@param pOutSPNData The SPN data string
 *	@param cchSPNData Sizeof pOutSPNData in characters
 *	@return Number of characters in the SPN or -1 on error
 */
int GetLdapServerSPN(TCHAR* pOutSPNData, unsigned long cchSPNData);

/**
 *	Retrieves the DNS domain name of the domain the current computer
 *	is joined into.
 *	@param pOutDNSDomain Receives the DNS domain
 *	@param cchDNSDomain Size of pOutDNSDomain in characters
 *	@return Number of characters in the DNS domain name
 */
int GetDNSDomainName(TCHAR* pOutDNSDomain, unsigned long cchDNSDomain);

/**
 *	Retreives the distinguished name of the domain the current computer
 *	is joined into.
 *	@param pOutDomainDN Receives the domain distinguished name
 *	@param cchDomainDN Size of pOutDomainDN in characters
 *	@return Number of characters copied to the output buffer
 */
int GetDomainDN(TCHAR* pOutDomainDN, unsigned long cchDomainDN);

 /**
  *	Converts an integer to a std::string in base 16
  *	@param num Number to convert
  *	@return The number as a string object
  */
std::string to_hex(unsigned long num);

#endif
