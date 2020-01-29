#include <Windows.h>
#include <stdio.h>
#include <Lm.h>

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

BOOL EnableUSB()
{
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\services\\USBSTOR", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key))
		return FALSE;

	DWORD number = 3;
	if (RegSetValueExW(key, L"Start", 0, REG_DWORD, (LPBYTE)&number, sizeof(DWORD)))
	{
		RegCloseKey(key);
		return FALSE;
	}

	RegCloseKey(key);
	return TRUE;
}

NET_API_STATUS RemoveUser(LPCWSTR username)
{
	NET_API_STATUS err = 0;

	// Delete user
	err = NetUserDel(NULL, username);

	switch (err)
	{
	case 0:
		printf("User successfully removed.\n");
		break;
	case NERR_UserNotFound:
		printf("Username could not be found.\n");
		err = 0;
		break;
	case ERROR_ACCESS_DENIED:
		printf("ERROR_ACCESS_DENIED\n");
		return err;
	default:
		printf("Error adding user: %d\n", err);
		return err;
	}

	return err;
}

void RestoreWindowsFirewall()
{
	system("netsh advfirewall import \"%SystemDrive%\\advfirewall\\firewall_before.wfw\"");
}

void DeleteFolder(LPCWSTR path)
{
	SHFILEOPSTRUCT fileOp = { 0 };
	fileOp.hwnd = NULL;
	fileOp.wFunc = FO_DELETE;
	fileOp.pFrom = path;
	fileOp.pTo = L"";
	fileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
	fileOp.fAnyOperationsAborted = FALSE;
	fileOp.hNameMappings = 0;
	fileOp.lpszProgressTitle = L"";

	SHFileOperation(&fileOp);
}

int main()
{
	if (IsElevated())
	{
		// Add user
		RemoveUser(L"lti2019");

		// Enable USB
		if (EnableUSB())
			printf("Enabled USB.\n");
		else
			printf("An error occurred while enabling USB.\n");

		// Restore Windows Firewall
		system("netsh advfirewall import \"%SystemDrive%\\advfirewall\\firewall_before.wfw\"");

		// Delete advfirewall folder
		DeleteFolder(L"C:\\advfirewall");

		printf("Done.\n");
	}
	else
	{
		printf("Please run as administrator.\n");
	}

	getchar();

	return 0;
}