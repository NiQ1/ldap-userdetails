#ifndef INC_TSTRING
#define INC_TSTRING

#include <string>

#ifdef UNICODE
#define tstring std::wstring
#else
#define tstring std::string
#endif

/**
 *	Converts a UTF-8 encoded string to a tstring
 *	@param inputstring UTF-8 encoded string to convert
 *	@return Converted string
 *	@note If UNICODE is not defined, it just returns the input
 *	string as is.
 */
tstring UTF8toTstring(std::string inputstring);

/**
*	Converts a tstring to a UTF-8 encoded string
*	@param inputstring tstring to convert
*	@return Converted string
*	@note If UNICODE is not defined, it just returns the input
*	string as is.
*/
std::string TStringtoUTF8(tstring inputstring);

#endif

