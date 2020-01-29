#include <Windows.h>
#include <stdio.h>
#include <Lm.h>
#include <sddl.h>

#pragma comment(lib, "Netapi32.lib")

BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken)
		CloseHandle(hToken);

	return fRet;
}

NET_API_STATUS AddUser(
	LPWSTR lpszUser,
	LPWSTR lpszPassword,
	LPWSTR lpszLocalGroup)
{
	USER_INFO_1               user_info;
	NET_API_STATUS            err = 0;
	DWORD                     parm_err = 0;
	LOCALGROUP_INFO_1         localgroup_info;
	LOCALGROUP_MEMBERS_INFO_3 localgroup_members;

	user_info.usri1_name = lpszUser;
	user_info.usri1_password = lpszPassword;
	user_info.usri1_priv = USER_PRIV_USER;
	user_info.usri1_home_dir = L"";
	user_info.usri1_comment = L"";
	user_info.usri1_flags = UF_SCRIPT;
	user_info.usri1_script_path = L"";

	// Add user
	err = NetUserAdd(NULL, 1, (LPBYTE)&user_info, &parm_err);

	switch (err)
	{
	case 0:
		printf("User successfully created.\n");
		break;
	case NERR_UserExists:
		printf("User already exists.\n");
		err = 0;
		break;
	case ERROR_INVALID_PARAMETER:
		printf("Invalid parameter error adding user; parameter index = %d\n",
			parm_err);
		return err;
	case ERROR_ACCESS_DENIED:
		printf("ERROR_ACCESS_DENIED; parameter index = %d\n",
			parm_err);
		return err;
	default:
		printf("Error adding user: %d\n", err);
		return err;
	}

	// Add local group
	localgroup_info.lgrpi1_name = lpszLocalGroup;
	localgroup_info.lgrpi1_comment = L"Sample local group.";

	err = NetLocalGroupAdd(NULL, 1, (LPBYTE)&localgroup_info, &parm_err);

	switch (err)
	{
	case 0:
		printf("Local group successfully created.\n");
		break;
	case ERROR_ALIAS_EXISTS:
		printf("Local group already exists.\n");
		err = 0;
		break;
	case ERROR_INVALID_PARAMETER:
		printf("Invalid parameter error adding local group; parameter index = %d\n", err);
	default:
		printf("Error adding local group: %d\n", err);
	}

	// Now add the user to the local group
	localgroup_members.lgrmi3_domainandname = lpszUser;

	err = NetLocalGroupAddMembers(NULL, lpszLocalGroup, 3, (LPBYTE)&localgroup_members, 1);

	switch (err)
	{
	case 0:
		printf("User successfully added to local group.\n");
		break;
	case ERROR_MEMBER_IN_ALIAS:
		printf("User already in local group.\n");
		err = 0;
		break;
	default:
		printf("Error adding user to local group: %d\n", err);
		break;
	}

	return err;
}

BOOL DisableUSB()
{
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\USBSTOR", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key))
		return FALSE;

	DWORD number = 4;
	if (RegSetValueExW(key, L"Start", 0, REG_DWORD, (LPBYTE)&number, sizeof(DWORD)))
	{
		RegCloseKey(key);
		return FALSE;
	}

	RegCloseKey(key);
	return TRUE;
}

void SetEnvironmentVariables()
{
	DWORD bufferSize = 4096;
	DWORD dwErr;
	BOOL fExist = FALSE;

	LPWSTR pszOldVal = (LPWSTR)malloc(bufferSize * sizeof(WCHAR));
	if (!pszOldVal)
	{
		printf("Out of memory.\n");
		return;
	}

	DWORD dwRet = GetEnvironmentVariableW(L"PATH", pszOldVal, bufferSize);
	
	if (!dwRet)
	{
		dwErr = GetLastError();
		if (dwErr == ERROR_ENVVAR_NOT_FOUND)
		{
			printf("Environment variable does not exist.\n");
			fExist = FALSE;
		}
	}
	else if (bufferSize < dwRet)
	{
		pszOldVal = (LPWSTR)realloc(pszOldVal, dwRet * sizeof(WCHAR));
		if (!pszOldVal)
		{
			printf("Out of memory.\n");
			return;
		}

		dwRet = GetEnvironmentVariableW(L"PATH", pszOldVal, dwRet);
		if (!dwRet)
		{
			free(pszOldVal);
			return;
		}
		else 
		{
			fExist = TRUE;
		}
	}
	else
	{
		fExist = TRUE;
	}

	if (fExist)
	{
		printf("%ls: %ls\n", L"PATH", pszOldVal);
	
		// Check if the current environment variables contains codeblocks' environment variable
		if (!wcsstr(pszOldVal, L"\\CodeBlocks\\MinGW\\bin"))
		{
			// Set Environment Variables
			HKEY key;
			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key))
			{
				free(pszOldVal);
				return;
			}

			WCHAR newPath[] = L"C:\\Program Files (x86)\\CodeBlocks\\MinGW\\bin;";
			DWORD size = dwRet * sizeof(WCHAR) + sizeof(newPath) + 1;
			LPWSTR concat = (LPWSTR)malloc(size);
			wcscpy(concat, newPath);
			wcscat(concat, pszOldVal);

			if (RegSetValueExW(key, L"Path", 0, REG_SZ, (LPBYTE)concat, size))
			{
				RegCloseKey(key);
				free(concat);
				free(pszOldVal);
				return;
			}

			RegCloseKey(key);
			free(concat);

			printf("Environment variables were set.\n");
		}
		else
		{
			printf("Current environment variables already contain that path.\n");
		}
	}

	free(pszOldVal);
}

BOOL CreateMyDACL(SECURITY_ATTRIBUTES* pSA)
{
	// Define the SDDL for the DACL
	WCHAR* szSD = L"D:"         // Discretionary ACL
		//L"(A;OICI;GA;;;SY)"     // SYSTEM - All permissions
		L"(A;OICI;GA;;;BA)";    // Administrators - All permissions

	if (!pSA)
		return FALSE;

	return ConvertStringSecurityDescriptorToSecurityDescriptor(szSD, SDDL_REVISION_1, &(pSA->lpSecurityDescriptor), NULL);
}

void CreateAdminRestrictedFolder()
{
	// https://docs.microsoft.com/en-us/windows/desktop/secbp/creating-a-dacl
	// https://docs.microsoft.com/en-us/windows/desktop/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptora
	// https://docs.microsoft.com/bg-bg/windows/desktop/SecAuthZ/security-descriptor-string-format
	// https://docs.microsoft.com/bg-bg/windows/desktop/SecAuthZ/sid-strings
	// https://docs.microsoft.com/bg-bg/windows/desktop/SecAuthZ/ace-strings

	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	if (!CreateMyDACL(&sa))
		return;
	
	if (!CreateDirectoryW(L"C:\\advfirewall", &sa))
		return;

	LocalFree(sa.lpSecurityDescriptor);
}

BOOL DirectoryExists(LPCWSTR dirName) 
{
	DWORD attribs = GetFileAttributesW(dirName);
	
	if (attribs == INVALID_FILE_ATTRIBUTES) 
		return FALSE;

	return (attribs & FILE_ATTRIBUTE_DIRECTORY);
}

// https://docs.microsoft.com/en-us/previous-versions//aa364726(v=vs.85)
void SetUpWindowsFirewall()
{
	if (DirectoryExists(L"C:\\advfirewall"))
	{
		// Export current settings
		system("netsh advfirewall export \"%SystemDrive%\\advfirewall\\firewall_before.wfw\"");

		// Add rules
		system("netsh advfirewall firewall set rule all new enable=no");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.61");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.62");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.63");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.64");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.65");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_servers\" dir=out action=allow protocol=ANY remoteip=172.20.0.66");
		system("netsh advfirewall firewall add rule name=\"lti2019_access_dhcp\" dir=out action=allow protocol=UDP remoteport=67");

		// Block everything
		system("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");
	}
}

int main()
{
	if (IsElevated())
	{
		// Add user
		AddUser(L"lti2019", L"lti2019", L"Users");

		// Disable USB
		if (DisableUSB())
			printf("Disabled USB.\n");
		else
			printf("An error occurred while disabling USB.\n");

		// Set Environment Variables
		SetEnvironmentVariables();

		// Create an admin restricted folder
		CreateAdminRestrictedFolder();

		// Set up Windows Firewall
		SetUpWindowsFirewall();
	
		printf("Done.\n");
	}
	else
	{
		printf("Please run as administrator.\n");
	}

	getchar();

	return 0;
}