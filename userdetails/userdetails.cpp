#include <io.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string>
#include <stdexcept>
#include <memory>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <stdio.h>
#include <malloc.h>
#include <Windows.h>
#include <sspi.h>
#include <tchar.h>
#include <Winldap.h>
#include <WinBer.h>
#include <json.h>
#include <writer.h>

#include "tstring.h"
#include "spnhelper.h"
#include "ldapgssbind.h"

#ifdef _MSC_VER
#define ssize_t SSIZE_T
#endif

std::string FileToString(FILE* input, ssize_t len = -1)
{
	char temp[1024];
	ssize_t bytes_read = 0;
	std::string result;

	while (!feof(input) && !ferror(input) && ((len < 0) || (bytes_read < len))) {
		ssize_t to_read = sizeof(temp) - 1;
		if ((len >= 0) && (len - bytes_read < to_read)) {
			to_read = len - bytes_read;
		}
		ssize_t read_now = fread(temp, 1, to_read, input);
		temp[read_now] = '\0';
		bytes_read += read_now;
		result += temp;
	}
	
	return result;
}

int _tmain(int argc, TCHAR* argv[])
{
	std::string inputText;
	tstring username;
	LDAPMessage* pSearchResult = NULL;
	LDAPMessage* pEntry = NULL;
	BerElement* pBer = NULL;
	berval** berValues = NULL;
	TCHAR* tszAttribName = NULL;
	std::ifstream fstreamJsonIn;
	std::istream* streamJsonIn = &std::cin;
	std::ofstream fstreamJsonOut;
	std::ostream* streamJsonOut = &std::cout;
	Json::Value output;
	std::string outDetails;
	//FILE* debugfile = fopen("C:\\inetpub\\temp\\log\\cgidebug.txt", "w");
	//_ftprintf(debugfile, _T("Start.\n"));
	//fflush(debugfile);
	try {
		// that will be used instead of stdin
		// Avoid LF -> CRLF shenanigans that would break the
		// Content-Length value.
		_setmode(_fileno(stdin), _O_BINARY);
		_setmode(_fileno(stdout), _O_BINARY);

		//TCHAR tszUser[1024];
		//tszUser[0] = '\0';
		//DWORD cchUser = 1024;
		//GetUserName(tszUser, &cchUser);
		//_ftprintf(debugfile, _T("Own username: %s\n"), tszUser);

		// CGI does not always send EOF so we'll count on the number
		// of bytes passed in the CONTENT_LENGTH header
		TCHAR* tszContentLength = _tgetenv(_T("CONTENT_LENGTH"));
		ssize_t sstContentLength = -1;
		if (tszContentLength && (tszContentLength[0] != '\0')) {
			sstContentLength = _tcstoul(tszContentLength, NULL, 10);
			//_ftprintf(debugfile, _T("Got content length: %zd\n"), sstContentLength);
			//fflush(debugfile);
		}
		//else {
		//	_ftprintf(debugfile, _T("Got no content length\n"));
		//	fflush(debugfile);
		//}
		// For debugging, argv[1] can be used to point to a file
		if (argc > 1) {
			//_ftprintf(debugfile, _T("Using %s as input\n"), argv[1]);
			// Throw if file cannot be opened
			//fstreamJsonIn.exceptions(std::ifstream::badbit);
			//fstreamJsonIn.open(argv[1]);
			//streamJsonIn = &fstreamJsonIn;
			FILE* inputfile = _tfopen(argv[1], _T("rb"));
			if (!inputfile) {
				throw std::runtime_error("Cannot open input file.");
			}
			inputText = FileToString(inputfile, sstContentLength);
		}
		else {
			inputText = FileToString(stdin, sstContentLength);
		}
		// The lookup username is stored as a JSON
		// string promptly named "username"
		//_ftprintf(debugfile, _T("Parsing JSON.\n"));
		Json::Value root;
		std::istringstream iss(inputText);
		iss >> root;
		//_ftprintf(debugfile, _T("Data read.\n"));
		//fflush(debugfile);
		const char* rawUserName = root["username"].asCString();
		username = UTF8toTstring(std::string(rawUserName));
		//_ftprintf(debugfile, _T("Username is %s\n"), username.c_str());
		//fflush(debugfile);
		// Remove the domain component.
		// NOTE: We assume that there's only one domain so we ignore it completely.
		// Supporting forests means supporting multiple LDAP servers and is out
		// of the scope of this program.
		size_t posBackslash = username.find('\\');
		if (posBackslash != tstring::npos) {
			username = username.substr(posBackslash + 1);
		}
		// Resolve current domain's domain controller
		TCHAR tszDCName[256] = { 0 };
		if (ResolveLDAPServer(tszDCName, _countof(tszDCName)) <= 0) {
			throw std::runtime_error("LDAP resolve failed. Is this computer joined to a domain?");
		}
		tstring RawDCName;
		tstring DCName = _T("ldap/");
		if (_tcsstr(tszDCName, _T("\\\\")) == tszDCName) {
			RawDCName = tszDCName + 2;
		}
		else {
			RawDCName = tszDCName;
		}
		DCName += RawDCName;
		// Resolve domain name
		TCHAR tszDomainDN[256] = { 0 };
		if (GetDomainDN(tszDomainDN, _countof(tszDomainDN)) <= 0) {
			throw std::runtime_error("Domain resolve failed. Is this computer joined to a domain?");
		}

		// Connect to Active Directory LDAP service
		LDAP* pLDAPConnection = ldap_init((PTSTR)RawDCName.c_str(), LDAP_PORT);
		if (pLDAPConnection == NULL) {
			throw std::runtime_error("LDAP connection failed.");
		}
		std::shared_ptr<LDAP> AutoLDAPConnection(pLDAPConnection, ldap_unbind);

		// Using LDAP version 3
		ULONG ulLDAPVersion = LDAP_VERSION3;
		ldap_set_option(pLDAPConnection, LDAP_OPT_PROTOCOL_VERSION, &ulLDAPVersion);
		void* pOptVal = LDAP_OPT_OFF;
		ldap_set_option(pLDAPConnection, LDAP_OPT_AUTO_RECONNECT, &pOptVal);
		pOptVal = LDAP_OPT_OFF;
		ldap_set_option(pLDAPConnection, LDAP_OPT_REFERRALS, &pOptVal);
		int ldap_rv = ldap_connect(pLDAPConnection, NULL);
		if (ldap_rv != LDAP_SUCCESS) {
			throw std::runtime_error("ldap_connect call failed (code=0x" + to_hex(ldap_rv) + ").");
		}
		LDAPGSSAPIBind(pLDAPConnection, (LPTSTR)DCName.c_str());

		// This runs the actual search
		TCHAR tszFilter[1024];
		_sntprintf(tszFilter, _countof(tszFilter) - 1, _T("(&(objectClass=user)(sAMAccountName=%s))"), username.c_str());
		tszFilter[_countof(tszFilter) - 1] = '\0';
		TCHAR tszBaseDN[1024];
		//_tcsncpy(tszBaseDN, _T("CN=Users,"), _countof(tszBaseDN) - 1);
		_tcsncpy(tszBaseDN, tszDomainDN, _countof(tszBaseDN) - 1);
		tszBaseDN[_countof(tszBaseDN) - 1] = '\0';
		ldap_rv = ldap_search_s(pLDAPConnection, tszBaseDN, LDAP_SCOPE_SUBTREE, tszFilter, NULL, 0, &pSearchResult);
		if (ldap_rv != LDAP_SUCCESS) {
			throw std::runtime_error("ldap_search_s call failed (code=0x" + to_hex(ldap_rv) + ").");
		}

		ldap_rv = ldap_count_entries(pLDAPConnection, pSearchResult);
		if (ldap_rv > 0) {
			pEntry = ldap_first_entry(pLDAPConnection, pSearchResult);
			if (!pEntry) {
				throw std::runtime_error("ldap_first_entry call failed.");
			}
			tszAttribName = ldap_first_attribute(pLDAPConnection, pEntry, &pBer);
			while (tszAttribName) {
				Json::Value attrib;
				//_tprintf(_T("Attribute Name: %s\n"), tszAttribName);
				berValues = ldap_get_values_len(pLDAPConnection, pEntry, tszAttribName);
				int i = 0;
				if (berValues[0] && berValues[1]) {
					while (berValues[i]) {
						attrib[i] = berValues[i]->bv_val;
						i++;
					}
				}
				else if (berValues[0]) {
					attrib = berValues[i]->bv_val;
				}
				else {
					attrib = Json::Value::nullSingleton();
				}
				output[TStringtoUTF8(tstring(tszAttribName)).c_str()] = attrib;
				tszAttribName = ldap_next_attribute(pLDAPConnection, pEntry, pBer);
			}
			// Note: Since sAMAccountName is unique (supposedly), we won't bother
			// iterating over multiple entries.

		}

		// TODO: Figure out why ldap_first_attribute corrupts the heap
		// and fix this crash
		//if (berValues) {
		//	ldap_value_free_len(berValues);
		//}
		//if (tszAttribName) {
		//	ldap_memfree(tszAttribName);
		//}
		//if (pBer) {
		//	ber_free(pBer, 0);
		//}
		//if (pEntry) {
		//	ldap_msgfree(pEntry);
		//}
		//if (pSearchResult) {
		//	ldap_msgfree(pSearchResult);
		//}
		//printf("Success!\n");
	}
	catch (std::exception& e) {
		// TODO: Figure out why ldap_first_attribute corrupts the heap
		// and fix this crash
		//if (berValues) {
		//	ldap_value_free_len(berValues);
		//}
		//if (tszAttribName) {
		//	ldap_memfree(tszAttribName);
		//}
		//if (pBer) {
		//	ber_free(pBer, 0);
		//}
		//if (pEntry) {
		//	ldap_msgfree(pEntry);
		//}
		//if (pSearchResult) {
		//	ldap_msgfree(pSearchResult);
		//}
		output["exception"] = e.what();
	}
	// Generate output JSON
	try {
		Json::StreamWriterBuilder builder;
		// Not sure why but for some reason writeString returns an invalid value
		builder.settings_["emitUTF8"] = true;
		std::stringstream ss;
		std::unique_ptr<Json::StreamWriter> const writer(builder.newStreamWriter());
		if (output.isNull()) {
			// Make sure we always return a valid JSON
			output = Json::objectValue;
		}
		writer->write(output, &ss);
		outDetails = ss.str();
		std::cout << "Content-Type: application/json\r\nContent-Length: " << outDetails.length() << "\r\n\r\n" << outDetails;
	}
	catch (std::exception& e) {
		std::cout << "Content-Type: text/plain\r\n\r\n" << e.what();
	}
	//fclose(debugfile);

	return 0;
}
