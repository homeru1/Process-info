#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <sddl.h>
#include <Winternl.h>
#include <tchar.h>
#include <aclapi.h>
#include <MetaHost.h>
#include<assert.h>
//#include <imagehlp.h>
#include <dbghelp.h>
#include <fstream>
#include <list>


#pragma comment( lib, "Version.lib" )
#pragma comment( lib, "Dbghelp.lib" )
#pragma comment( lib, "advapi32.lib" )
#pragma comment(lib, "mscoree.lib")
using namespace std;
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

struct Process {
    TCHAR ProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR ProcessFilePath[MAX_PATH] = TEXT("<unknown>");
    TCHAR ProcessParentName[MAX_PATH] = TEXT("<unknown>");
    TCHAR ProcessParentFilePath[MAX_PATH] = TEXT("<unknown>");
    TCHAR* ProcessInfo = NULL;

    LPSTR SID = 0;

    wstring Owner;
    wstring dll;

     list<int> Threads;

    string priveleges;
    string IntegrityLevel;
    string FileIntegrityLevel ="Medium";

    DWORD PID = 0;
    DWORD PPID = 0;
    DWORD size = sizeof(ProcessName) / sizeof(TCHAR);

    BOOL type = 1;
    BOOL dep = 0;
    BOOL aslr = 0;
    BOOL net = 0;

    char ACL[1024] = "<unknown>";
    char OwnerOfFile[1024] = "<unknown>";
};

struct Holder {
    Process* main = NULL;
    int size = 0;
};

Holder mainb;

enum proc_type
{
    x32,
    x64
};

struct dll_info

{
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    void* imageBase = nullptr;
    IMAGE_NT_HEADERS* headers = nullptr;
    proc_type bitness;
};

void GetProcessInfo(Process* cur)
{
    TCHAR* fileName = cur->ProcessFilePath;
    PLONG infoBuffer;  // буфер, куда будем читать информацию
    DWORD infoSize;    // и его размер

    struct LANGANDCODEPAGE { // структура для получения кодовых страниц по языкам трансляции ресурсов файла
        WORD wLanguage;
        WORD wCodePage;
    } *pLangCodePage;

    // имена параметров, значения которых будем запрашивать
    const TCHAR* paramNames[] = {
            _T("FileDescription"),
    };

    TCHAR paramNameBuf[256]; // здесь формируем имя параметра
    UINT paramSz;            // здесь будет длина значения параметра, который нам вернет функция VerQueryValue 
    // получаем размер информации о версии файла
    infoSize = GetFileVersionInfoSize(fileName, NULL);
    if (infoSize > 0)
    {
    // выделяем память
    infoBuffer = (PLONG)malloc(infoSize);
    // получаем информацию
    if (0 != GetFileVersionInfo(fileName, NULL, infoSize, infoBuffer))
    {
        // информация находится блоками в виде "\StringFileInfo\кодовая_страница\имя_параметра
        // т.к. мы не знаем заранее сколько и какие локализации (кодовая_страница) ресурсов имеются в файле,
        // то будем перебирать их все

        UINT cpSz;
        // получаем список кодовых страниц
        if (VerQueryValue(infoBuffer,                      // наш буфер, содержащий информацию
            _T("\\VarFileInfo\\Translation"),// запрашиваем имеющиеся трансляции
            (LPVOID*)&pLangCodePage,        // сюда функция вернет нам указатель на начало интересующих нас данных 
            &cpSz))                         // а сюда - размер этих данных 
        {
            _stprintf(paramNameBuf, _T("\\StringFileInfo\\%04x%04x\\%s"),
                pLangCodePage->wLanguage,  // ну, или можно сделать фильтр для 
                pLangCodePage->wCodePage,  // какой-то отдельной кодовой страницы
                *paramNames);

            // получаем значение параметра
            VerQueryValue(infoBuffer, paramNameBuf, (LPVOID*)&(cur->ProcessInfo), &paramSz);
            // и выводим его на экран 
        }
    }
    }
}

void GetParrentPid(Process* cur)
{
    DWORD pid = cur->PID;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(h, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                break;
            }
        } while (Process32Next(h, &pe));
    }

    CloseHandle(h);
    cur->PPID = pe.th32ParentProcessID;
}

#define SPACE "   "
void OutPut(Process* cur, wfstream& myfile , wfstream& myprocess) {
    if (cur->PPID == 0)return;
    //EnterSpace(myfile, 2);
    myprocess << "  {\n" << SPACE;
    myprocess << "\"Parrent ID\" : \"" << cur->PPID << "\"" << endl << "   ";
    myprocess << "\"Process name\" : \"" << cur->ProcessName << "\"" << endl << SPACE;
    myprocess << "\"PID\" : \"" << cur->PID << "\""  << endl << SPACE;
    if (cur->type == 1) {
        myprocess << "\"Type\" : \"x64\"" << endl << SPACE;
    }
    else {
        myprocess << "\"Type\" : \"x32\"" << endl << SPACE;
    }
    if (cur->net == 0) {
        myprocess << "\"Using\" : \"Native Code\"" << endl << SPACE;
    }
    else {
        myprocess << "\"Using\" : \"CLR.Net\"" << endl << SPACE;
    }
    if (cur->dep == 1) {
        myprocess << "\"DEP\" : \"Yes\"" << endl << SPACE;
    }
    else {
        myprocess << "\"DEP\" : \"No\"" << endl << SPACE;
    }
    if (cur->aslr == 1) {
        myprocess << "\"ASLR\" : \"Yes\"" << endl << SPACE;
    }
    else {
        myprocess << "\"ASLR\" : \"No\"" << endl << SPACE;
    }
    myprocess << "\"Process Owner\" : \"" << cur->Owner.c_str() << "\"" << endl << SPACE;
    myprocess << "\"DLL\" : \"" << cur->dll.c_str() << "\"" << endl << SPACE; // add normal
    myprocess << "\"IntegrityLevel\" : \"" << cur->IntegrityLevel.c_str() << "\"" << endl << SPACE;
    myprocess << "\"Prveleges\" : \"" << cur->priveleges.c_str() << "\"" << endl << SPACE;
    myprocess << "\"All Threads\" : \"";
    for (auto v : cur->Threads) {
        myprocess << v << " ";
    }
    myprocess << "\"" << endl;
    myprocess << "  }\n";

    myfile << "  {\n" << SPACE;
    myfile << "\"File path\" : \"" << cur->ProcessFilePath << "\"" << endl << SPACE;
    if (cur->ProcessInfo == NULL) {
        myfile << "\"File info\" : \"<unknown>\"" << endl << SPACE;
    }
    else {
        myfile << "\"File info\" : \"" << cur->ProcessInfo << "\"" << endl << SPACE;
    }
    myfile << "\"Parrent filename\" : \"" << cur->ProcessParentName << "\"" << endl << SPACE;
    myfile << "\"Parrent filename path\" : \"" << cur->ProcessParentFilePath << "\"" << endl << SPACE;
    if (cur->SID != NULL) {
        myfile << "\"SID\" : \"" << cur->SID << "\"" << endl << SPACE;
    }
    myfile << "\"File Owner\" : [" << endl << SPACE << "  {"<<endl<<SPACE<<"  \"name\" : \"";
    for (int i = 0; i < strlen(cur->OwnerOfFile)-1; i++) {
        if (cur->OwnerOfFile[i] == '\n') {
            myfile << "\"" << endl << SPACE << "  \"";
        }
        else if (cur->OwnerOfFile[i] == ':'){
            myfile << "\" : \"";
}
        else {
            myfile << cur->OwnerOfFile[i];
        }
    }
    myfile << endl << SPACE << "  }" << endl<<SPACE<<" ]"<<endl <<SPACE;
    myfile << "\"ACL\" : [" << endl << SPACE << "  {" << endl << SPACE <<" ";
    for (int i = 0; i < strlen(cur->ACL)-1; i++) {
        if (cur->ACL[i] == '\n') {
            myfile << endl << SPACE << " ";
        }
        else {
            myfile << cur->ACL[i];
        }
    }
    myfile << endl << SPACE << "  }" << endl << SPACE << " ]" << endl << SPACE;
    myfile << "\"File IntegrityLevel\" : \"" << cur->FileIntegrityLevel.c_str() << "\"" << endl;
    myfile << "  }\n";
    printf("===========================================\n");
    _tprintf(TEXT("Process name:%s\n"), cur->ProcessName);
    _tprintf(TEXT("PID:%u\n"), cur->PID);
    _tprintf(TEXT("File path:%s\n"), cur->ProcessFilePath);
    _tprintf(TEXT("File info:%s\n"), cur->ProcessInfo);
    _tprintf(TEXT("Parrent filename:%s\n"), cur->ProcessParentName);
    _tprintf(TEXT("Parrent ID:%i\n"), cur->PPID);
    _tprintf(TEXT("Parrent filename path:%s\n"), cur->ProcessParentFilePath);
    if (cur->type == 1) {
        _tprintf(TEXT("Type:x64\n"));
    }
    else {
        _tprintf(TEXT("Type:x32\n"));
    }
    if (cur->net == 0)cout << "Using Native Code" << endl;
    else cout << "Using CLR.Net" << endl;
    _tprintf(TEXT("DEP:%d\n"), cur->dep);
    _tprintf(TEXT("ASLR:%d\n"), cur->aslr);
    if(cur->SID != NULL)wcout << "SID:" << cur->SID << endl;
    wcout << "Process Owner:" << cur->Owner << endl;
    wcout << "DLL:" << cur->dll << endl;
    cout << "IntegrityLevel:" << cur->IntegrityLevel << endl;
    cout << "Prveleges:" << cur->priveleges<< endl;
    cout << "File Owner:" << cur->OwnerOfFile<< endl;
    cout << "ACL:" << cur->ACL << endl;
    cout << "File IntegrityLevel:" << cur->FileIntegrityLevel << endl;
    cout << "All threads:";
    //_tprintf(TEXT("%s  (PID: %u); FilePath:%s; info:%s; ParrentName:%s\n"), szProcessName, processID, szProcessFilePath, szProcessInfo, szProcessParrentName);
    printf("===========================================\n");
}

void GetParrentFile(Process* cur, HANDLE hProcess) {
    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, cur->ProcessParentName,
                cur->size);
            GetModuleFileNameEx(hProcess, hMod, cur->ProcessParentFilePath,
                MAX_PATH);
        }
    }
}

void GetSID(Process* cur, HANDLE Handle) {

    DWORD dwSize = 0;

    if (Handle == NULL)return;

    if (!OpenProcessToken(Handle, TOKEN_READ, &Handle)) {
        return;
    }
    if (!(GetTokenInformation(Handle, TokenUser, NULL, dwSize, &dwSize) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
        return;
    }
    PTOKEN_USER pUserToken = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);

    if (pUserToken == NULL) {
        GlobalFree(pUserToken);
        return;
    }
    if (!GetTokenInformation(Handle, TokenUser, pUserToken, dwSize, &dwSize)) {
        GlobalFree(pUserToken);
        return;
    }
    SID_NAME_USE snuSIDNameUse;
    TCHAR szUser[MAX_PATH] = { 0 };
    DWORD dwUserNameLength = MAX_PATH;
    TCHAR szDomain[MAX_PATH] = { 0 };
    DWORD dwDomainNameLength = MAX_PATH;

    if (!LookupAccountSid(NULL, pUserToken->User.Sid, szUser, &dwUserNameLength, szDomain, &dwDomainNameLength, &snuSIDNameUse)) {
        GlobalFree(pUserToken);
        return;
    }
    if (!ConvertSidToStringSidA(pUserToken->User.Sid, &(cur->SID))) {
        GlobalFree(pUserToken);
        return;
    }
    std::wstring temp(szUser);
    cur->Owner += temp;

    GlobalFree(pUserToken);
    return;
}

void GetDll(Process* cur) {
    MODULEENTRY32 moduleInfo;
    moduleInfo.dwSize = sizeof(moduleInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, cur->PID);
    int flag = 0;
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    {
        return;
    }
    for (BOOL bok = Module32First(processesSnapshot, &moduleInfo); bok; bok = Module32Next(processesSnapshot, &moduleInfo))
    {
        std::wstring temp(moduleInfo.szModule);
        if (flag == 0) {
            flag = 1;
        }
        else {
            cur->dll += temp;
            cur->dll += ' ';
        }

    }

    CloseHandle(processesSnapshot);
    return;

}

void GetIntegrityLevel(Process* cur, HANDLE hProcess) {
    DWORD dwLengthNeeded;
    //	DWORD dwError = ERROR_SUCCESS;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;
    bool intlvl = false;
    HANDLE hToken;

    if (hProcess == NULL) {
        return;
    }

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        cur->IntegrityLevel += "System";
        return;
    }
    if (GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
        if (pTIL == NULL)
        {
            return;
        }
        if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))

        {

            dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

            if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) { intlvl = true; cur->IntegrityLevel += "Low"; }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                intlvl = true; cur->IntegrityLevel += "Medium";
            }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) { intlvl = true; cur->IntegrityLevel += "High"; }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) { intlvl = true; cur->IntegrityLevel += "System"; }

            LocalFree(pTIL);

            return;
        }else
        {
            LocalFree(pTIL);
            return;
        }
    }else{
            return;
    }
}

void Owner(Process *cur)
{
    char answer[1024];
    ZeroMemory(&answer, sizeof(answer));
    DWORD dwRes = 0;
    PSID pOwnerSID;
    wstring test(&cur->ProcessFilePath[0]); //convert to wstring
    string path(test.begin(), test.end()); //and convert to string.
    HKEY hkey = NULL;
    LPCSTR subkey, root;
    char sid[1024];
    PSECURITY_DESCRIPTOR pSecDescr;
    dwRes = GetNamedSecurityInfoA(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
    if (dwRes != ERROR_SUCCESS)
    {
        printf("Не получить SID владельца %i\n", GetLastError());//error
        LocalFree(pSecDescr);
    }
    char szOwnerName[1024];
    char szDomainName[1024];
    DWORD dwUserNameLength = sizeof(szOwnerName);
    DWORD dwDomainNameLength = sizeof(szDomainName);
    SID_NAME_USE sidUse;
    dwRes = LookupAccountSidA(NULL, pOwnerSID, szOwnerName, &dwUserNameLength,
        szDomainName, &dwDomainNameLength, &sidUse);
    if (dwRes == 0)
    {
        printf("ERROR!\n");
    }
    else
    {
        LPSTR SID = NULL;
        char name[1024] = "";
        BOOL flag = ConvertSidToStringSidA(pOwnerSID, &SID);
        sprintf(cur->OwnerOfFile, "%s\nDomain: %s\nSID: %s\n", szOwnerName, szDomainName, SID);

    }
}

void GetACE(Process* cur)
{
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    HKEY hkey = NULL;
    bool isKey = true;
    //GetWindowsDirectory(cur->ProcessFilePath, MAX_PATH);
    wstring test(&cur->ProcessFilePath[0]); //convert to wstring
    string test2(test.begin(), test.end()); //and convert to string.
    LPCSTR tmp = (LPCSTR)test2.c_str();
    if (GetNamedSecurityInfoA(tmp, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pACL, NULL, &pSD) != ERROR_SUCCESS)
        return;
    if (pACL == NULL)
        return;

    ACL_SIZE_INFORMATION aclInfo;

    if (!GetAclInformation(pACL, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        return;

    char* bufi = cur->ACL;
    memset(bufi, 0, sizeof(bufi));
    ACCESS_ALLOWED_ACE* pACE;
    PSID pSID;
    SID_NAME_USE sid_nu;
    char user[MAX_PATH] = { 0 }, domain[MAX_PATH] = { 0 };
    int userLen = MAX_PATH, domainLen = MAX_PATH;
    LPSTR SID_string;

    for (unsigned int i = 0; i < aclInfo.AceCount; i++)
    {
        if (GetAce(pACL, i, (LPVOID*)&pACE))
        {
            pSID = (PSID)(&(pACE->SidStart));
            if (LookupAccountSidA(NULL, pSID, user, (LPDWORD)&userLen, domain, (LPDWORD)&domainLen, &sid_nu))
            {
                sprintf(bufi + strlen(bufi), "\"User\" : \"%s\" || \"Domain\" : \"%s\"\n", user, domain);
                if (pACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)
                    sprintf(bufi + strlen(bufi), "\"Denied ACE\",\n");
                else if (pACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
                    sprintf(bufi + strlen(bufi), "\"Allwed ACE\",\n");
                else if (pACE->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
                    sprintf(bufi + strlen(bufi), "\"System Audit ACE\",\n");
                else if (pACE->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
                    sprintf(bufi + strlen(bufi), "\"System Alarm ACE\",\n");

                if ((pACE->Mask & FILE_GENERIC_READ))
                    sprintf(bufi + strlen(bufi), "\"GENERIC_READ\",\n");
                if ((pACE->Mask & FILE_GENERIC_WRITE))
                    sprintf(bufi + strlen(bufi), "\"GENERIC_WRITE\",\n");
                if ((pACE->Mask & FILE_GENERIC_EXECUTE))
                    sprintf(bufi + strlen(bufi), "\"GENERIC_EXECUTE\",\n");

                if (pACE->Mask & DELETE)
                    sprintf(bufi + strlen(bufi), "\"DELETE\",\n");
                if (pACE->Mask & READ_CONTROL)
                    sprintf(bufi + strlen(bufi), "\"READ_CONTROL\",\n");
                if (pACE->Mask & WRITE_DAC)
                    sprintf(bufi + strlen(bufi), "\"WRITE_DAC\",\n");
                if (pACE->Mask & WRITE_OWNER)
                    sprintf(bufi + strlen(bufi), "\"WRITE_OWNER\",\n");
                if (pACE->Mask & SYNCHRONIZE)
                    sprintf(bufi + strlen(bufi), "\"SYNCHRONIZE\",\n");
            }
        }
    }
}

void printProcessPrivileges(Process* cur, HANDLE hProcess) {
    DWORD i, dwSize = 0, dwResult = 0;
    PTOKEN_PRIVILEGES pPrivelegesInfo = NULL;
    char lpName[MAX_PATH] = { 0 };
    HANDLE hToken = NULL;
    /*
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
    printf("OpenProcessToken Error %u\n", GetLastError());
    return FALSE;
    }
    */
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {

        // Call GetTokenInformation to get the buffer size.
        if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwSize, &dwSize))
        {
            // Allocate the buffer.
            pPrivelegesInfo = (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, dwSize);

            // Call GetTokenInformation again to get the group information.
            if (GetTokenInformation(hToken, TokenPrivileges, pPrivelegesInfo,
                dwSize, &dwSize))
            {
                for (i = 0; i < pPrivelegesInfo->PrivilegeCount; i++) {
                    dwSize = MAX_PATH;

                    if (LookupPrivilegeNameA(NULL, &pPrivelegesInfo->Privileges[i].Luid, lpName, &dwSize)) {
                        cur->priveleges += lpName;
                        cur->priveleges += ' ';

                       // printf("%s\n", lpName);
                    }
                }
            }
        }
        else
        {
           // printf("ACCESS DENIED\n");
        }
    }
    else
    {
        //printf("ACCESS DENIED\n");
    }

    if (pPrivelegesInfo)
        GlobalFree(pPrivelegesInfo);
    if (hToken)
        CloseHandle(hToken);
}

void GetFileIntegrityLevel(Process* cur)
{
    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;
    ULONG err = GetNamedSecurityInfoW(cur->ProcessFilePath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD);
    if (!err)
    {
        if (0 != acl && 0 < acl->AceCount)
        {
            SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
            if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
            {
                SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
                integrityLevel = sid->SubAuthority[0];
            }
        }

        PWSTR stringSD;
        ULONG stringSDLen = 0;

        ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

        if (integrityLevel == 4096)
            cur->FileIntegrityLevel = "Low";
        else if (integrityLevel == 8192)
            cur->FileIntegrityLevel = "Medium";
        else if (integrityLevel == 12288)
            cur->FileIntegrityLevel = "High";
        if (pSD)
        {
            LocalFree(pSD);
        }
    }
}

BOOL GetThreads(Process* cur )
{
    DWORD dwOwnerPID = cur->PID;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32))
    {
        cout<<"Thread32First";  // Show cause of failure
        CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
        return(FALSE);
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            cur->Threads.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    //  Don't forget to clean up the snapshot object.
    CloseHandle(hThreadSnap);
    return(TRUE);
}

void GetNet(Process* cur) {
    ICLRMetaHost* host;
    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&host);
    assert(SUCCEEDED(hr));
    if (hr == S_OK) {
        WCHAR buf[16];
        DWORD written;
        hr = host->GetVersionFromFile(cur->ProcessFilePath, buf, &written);
        assert(hr == S_OK || hr == HRESULT_FROM_WIN32(ERROR_BAD_FORMAT));
        host->Release();
    }
    cur->net = SUCCEEDED(hr);
}

int GetProcessEverything(Process* cur, int mode) { // PROCESS_QUERY_INFORMATION ???
    HANDLE hProcess = NULL;
    switch (mode)
    {
    case 1:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 2:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 3:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 4:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 5:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PPID);
        break;
    case 6:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,
            FALSE, cur->PID);
        break;
    case 7:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cur->PID);
        break;
    case 8:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cur->PID);
        break;
    case 9:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cur->PID);
        break;
    case 10:
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 11:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cur->PID);
    case 12:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cur->PID);
        break;
    case 13://ace
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
    case 14://file
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ,
            FALSE, cur->PID);
        break;
    case 15:
        GetThreads(cur);
    default:
        break;
    }
    DWORD error = 0;
    BOOL success = 0;
    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded)||( mode > 5 && mode <13))
        {
            switch (mode)
            {
            case 1: //Name
                GetModuleBaseName(hProcess, hMod, cur->ProcessName,
                    MAX_PATH);
                break;
            case 2: // FilePath and net
                GetModuleFileNameEx(hProcess, hMod, cur->ProcessFilePath,
                    MAX_PATH);
                GetNet(cur);
                break;
            case 3: // info
                GetProcessInfo(cur);
                break;
            case 4: // PPID
                GetParrentPid(cur);
                break;
            case 5: // parrent filepath
                GetParrentFile(cur, hProcess);
                break;
            case 6: // Process type
                typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
                LPFN_ISWOW64PROCESS fnIsWow64Process;
                fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
                fnIsWow64Process(hProcess, &cur->type);
                break;
            case 7: // dep
                PROCESS_MITIGATION_DEP_POLICY depPolicy = PROCESS_MITIGATION_DEP_POLICY();
                cur->dep = GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
                break;
            case 8: //ASLR
                PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = PROCESS_MITIGATION_ASLR_POLICY();
                cur->aslr = GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));
                break;
            case 9: //GetSid
                GetSID(cur, hProcess);
                break;
            case 10: //Getdll
                GetDll(cur);  //Fix Problems!
                break;
            case 11://GetInteLvl
                GetIntegrityLevel(cur, hProcess);
                break;
            case 12: //Prive
                printProcessPrivileges(cur, hProcess);
                break;
            case 13://ACE and owner
                Owner(cur);
                GetACE(cur);
                break;
            case 14:
                GetFileIntegrityLevel(cur);
                break;
            default:
                break;
            }
        }
    }
    error = GetLastError();
    SetLastError(0);
    if(hProcess!=NULL)
        CloseHandle(hProcess);
    if (error != 0) {
        //printf("Error!!");
        error = 0;
    }
    return 1;
}

int PrintProcessNameAndID(DWORD PID, Process* cur)
{
    //Process cur;
    cur->PID = PID;
    for (int i = 1; i <= 15; i++) {
        GetProcessEverything(cur, i);
    }
    //OutPut(&cur);
    return 1;
}

int main(void)
{
    // Get the list of process identifiers.
    //EnableDebugPrivilege(1);
    setlocale(LC_ALL, "Russian");
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);
    mainb.size = cProcesses;
    mainb.main = new Process[cProcesses];//(Process*)calloc(cProcesses,sizeof(struct Process));
    // Print the name and process identifier for each process.
    //proc[0].IntegrityLevel = "Medium";
    HANDLE hProcess = NULL;
    int counter = 0;
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, aProcesses[i]);
            if (hProcess !=NULL){
                CloseHandle(hProcess);
                PrintProcessNameAndID(aProcesses[i], &mainb.main[counter]);
                counter++;
            }
        }
    }
    //locale defaultLocale("");

    wfstream myfile, myprocess;
    //myfile.imbue(defaultLocale);
    myprocess.open("mbks1Proc.json", wfstream::out);
    myfile.open("mbks1File.json", wfstream::out);
    myfile << "[\n";
    myprocess << "[\n";
    for (i = 1; i < cProcesses; i++)
    {
        OutPut(&mainb.main[i], myfile, myprocess);
    }
    myfile << "]";
    myfile.close();
    myprocess << "]";
    myprocess.close();

    return 0;
}