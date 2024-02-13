# LDAP Active Directory User Details

This is a small CGI program that looks up Active Directory user details. It receives a user name and outputs all user details and attributes.
Details are pulled from the domain controller of the current domain using LDAP. Binding is done using Kerberos / GSSAPI so the program does not need a dedicated user account.

## Copyright
© 2024 Dan Haim, all rights reserved.
Usage, modification and redistribution is allowed under the terms of the GNU AGPLv3. Please note that under the terms of the AGPL, using this CGI program in a public website is regarded as distribution of the software.

## Usage
On Apache, copy the program to your ScriptAlias directory (e.g. cgi-bin). On IIS, copy it to a directory that has execute permissions.
The program must run as a domain user, the local system account or the network service account. Note that by default IIS runs CGI applications as the "IUSR" account, which does not have network permissions, so this must be changed in the application pool settings.
Use the program by sending a POST request with a minimal JSON body in the following format:

    {
        "username":"<user>"
    }
Where *&lt;user&gt;* is the SAM account name of the user to look up.
The result would be similar to this:

    {
    "accountExpires" : "0",
    "cn" : "John Smith",
    "codePage" : "0",
    "countryCode" : "0",
    "displayName" : "John Smith",
    "distinguishedName" : "CN=John Smith,CN=Users,DC=example,DC=com",
    "givenName" : "John",
    "lastLogon" : "0",
    "logonCount" : "1",
    "mail" : "john@example.com",
    "memberOf" :
    [
        "CN=Test Users,CN=Users,DC=example,DC=com",
        "CN=Developers,CN=Users,DC=example,DC=com"
    ],
    "name" : "John Smith",
    "objectCategory" : "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com",
    "objectClass" :
    [
        "top",
        "person",
        "organizationalPerson",
        "user"
    ],
    "objectGUID" : "0",
    "objectSid" : "0",
    "primaryGroupID" : "0",
    "pwdLastSet" : "0",
    "sAMAccountName" : "john",
    "sAMAccountType" : "0",
    "sn" : "Smith",
    "userPrincipalName" : "john@example.com",
    "whenChanged" : "20240101110000.0Z",
    "whenCreated" : "20240101110000.0Z"
    }
The fields may vary according to the information stored in the active directory.
If the user does not exist, an empty JSON will be returned. If an error occurs, a minimal JSON is returned containing an "exception" string type field whose value is the specific error message.

## Compiling
Use Microsoft Visual Studio 2017 or later to compile this program. The easiest method is to use the included solution file.
### Dependencies
The program requires the Windows 10 or Windows 11 SDK.
In addition, the jsoncpp library is required for parsing and building the JSON format used for input and output. Change the include and library path in the project to match the location of jsoncpp before building.
## Known Issues and Limitations

 - **This program runs only on Windows**. It will not run on Linux. Using WINE may work if it's compiled with Kerberos support but this is untested.
 - The computer must be joined into an Active Directory domain. Running on standalone computer will result in an error.
 - The program will only lookup user details in the domain into which the computer is joined. Domain forests are not supported at this point (though theoretically possible).
