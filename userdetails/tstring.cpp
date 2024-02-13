#include "tstring.h"
#include <Windows.h>
#include <malloc.h>

tstring UTF8toTstring(std::string inputstring)
{
#ifdef UNICODE
	if (inputstring.length() == 0) {
		return tstring();
	}
	TCHAR temp[65535];
	temp[0] = '\0';
	MultiByteToWideChar(CP_UTF8, 0, inputstring.c_str(), -1, temp, _countof(temp));
	temp[_countof(temp) - 1] = '\0';
	return tstring(temp);
#else
	return inputstring;
#endif
}

std::string TStringtoUTF8(tstring inputstring)
{
#ifdef UNICODE
	if (inputstring.length() == 0) {
		return std::string();
	}
	char temp[65535];
	temp[0] = '\0';
	WideCharToMultiByte(CP_UTF8, 0, inputstring.c_str(), -1, temp, _countof(temp), NULL, NULL);
	temp[_countof(temp) - 1] = '\0';
	return std::string(temp);
#else
	return inputstring;
#endif
}
