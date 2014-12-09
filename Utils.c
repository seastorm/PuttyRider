#include "Utils.h"
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <psapi.h>
#include <ws2tcpip.h>


/* Global variable needed by GetWindowHandler() */
HWND g_HWND = NULL;

/* An implementation of Boyer Moore Horspool algorithm
 * Source: http://en.wikipedia.org/wiki/Boyer%E2%80%93Moore%E2%80%93Horspool_algorithm
 *
 * Returns a pointer to the first occurrence of "needle"
 * within "haystack", or NULL if not found. Works like
 * memmem().
 * 
 * Note: In this example needle is a C string. The ending
 * 0x00 will be cut off, so you could call this example with
 * memmem(haystack, hlen, "abc", sizeof("abc")-1)
 */
const unsigned char* memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */
    size_t last;
 
    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;
 
    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;
 
    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;
 
    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;
 
    /* ---- Do the matching ---- */
 
    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return haystack;
 
        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }
 
    return NULL;
}


DWORD GetModuleBaseAddress() 
{ 
    /* Source: http://www.cheatengine.org/forum/viewtopic.php?t=567806 */
    
    MODULEENTRY32 me32  = { sizeof(MODULEENTRY32) }; 
    HANDLE hSnapshot    = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId()); 

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0; 
    }
        
    if (Module32First( hSnapshot, &me32 )) { 
        CloseHandle( hSnapshot );
        return (DWORD)me32.modBaseAddr; 
    }

    CloseHandle(hSnapshot); 
    return 0; 
}


BOOL GetTextSection(CHAR* modulePath, PDWORD pStartAddr, PDWORD pSize)
{
    /* Adapted after https://rstforums.com/proiecte/Licenta.docx */

    FILE*                   pFD;
    IMAGE_DOS_HEADER        dosHeader;
    IMAGE_NT_HEADERS        ntHeaders;
    IMAGE_SECTION_HEADER    sectHeader;
    SIZE_T                  numBytes;
    SIZE_T                  i;
    BOOL                    bFound = FALSE;
    unsigned char*          pRawSectionTable;
    
    if ((pFD = fopen(modulePath, "rb")) == NULL) {
        printf("[-] Could not open module %s\n", modulePath);
        return FALSE;
    }
    
    /* Read the DOS header */
    if (fread(&dosHeader, 1, sizeof(dosHeader), pFD) != sizeof(dosHeader)) {
        printf("[-] Could not read DOS header\n");
        return FALSE;
    }
    
    /* Seek to NT headers position */
    if(fseek(pFD, dosHeader.e_lfanew, SEEK_SET) != 0) {
        printf("[-] Could not seek to NT headers\n");
        return FALSE;
    }

    /* Read the NT headers */
    if (fread(&ntHeaders, 1, sizeof(ntHeaders), pFD) != sizeof(ntHeaders)) {
        printf("[-] Could not read NT headers\n");
        return FALSE;
    }

    /* File pointer is positioned immediatly afer NT Headers so we can read the section table */
    pRawSectionTable = (unsigned char *)malloc(ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if(pRawSectionTable == NULL) {
        printf("[-] Could not allocate memory\n");
        return FALSE;
    }
    
    /* Read Sections table */
    numBytes = ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if(fread(pRawSectionTable, 1, numBytes, pFD) != numBytes) {
        printf("[-] Could not read Sections table\n");
        free(pRawSectionTable);
        return FALSE;
    }
    
    /* Iterate through each section from our buffer */
    for(i = 0; i < numBytes; i += sizeof(IMAGE_SECTION_HEADER)) {
    
        sectHeader = *(IMAGE_SECTION_HEADER *)(pRawSectionTable + i);
        
        if(strcmp(sectHeader.Name, ".text") == 0) {
            *pStartAddr = sectHeader.VirtualAddress;
            *pSize = sectHeader.Misc.VirtualSize;
            bFound = TRUE;
            break;
        }
        
        /*
        printf("Section #%d\n",             i / sizeof(IMAGE_SECTION_HEADER));
        printf("Name: %s\n",                 sectHeader.Name);
        printf("VirtualSize: %.8lX\n",         sectHeader.Misc.VirtualSize);
        printf("VirtualAddress: %.8lX\n",     sectHeader.VirtualAddress);
        printf("SizeOfRawData %lu\n",         sectHeader.SizeOfRawData);
        printf("PointerToRawData: %.8lX\n", sectHeader.PointerToRawData);
        printf("PointerToLinenumbers: %.8lX\n", sectHeader.PointerToLinenumbers);
        printf("NumberOfRelocations: %d\n",     sectHeader.NumberOfRelocations);
        printf("NumberOfLinenumbers: %d\n",     sectHeader.NumberOfLinenumbers);
        printf("Characteristics: %.8lX\n\n",     sectHeader.Characteristics);
        */
    }

    free(pRawSectionTable);
    fclose(pFD);
    
    if(bFound == FALSE) {
        printf("[-] Could not find .text section\n");
        return FALSE;
    }
    
    return TRUE;
}


BOOL HexStringToBytes(CHAR* pHexStr, UCHAR* pByteArray)
{
    SIZE_T    iStrLen = strlen(pHexStr);
    SIZE_T    i;
    if (iStrLen % 2 != 0) {
        printf("[-] Hex string length must be multiple of 2\n");
        return FALSE;
    }
    for (i = 0; i < iStrLen/2; i++) {
        sscanf(pHexStr + 2*i, "%02x", &pByteArray[i]);
    }
    return TRUE;
}


BOOL ReadPipeMessage(HANDLE hPipe, CHAR* buffer)
{
    DWORD msgSize;
    DWORD numBytes;
    
    memset(buffer, 0, BUFSIZE);
    
    if (ReadFile(hPipe, &msgSize, sizeof(DWORD), &numBytes, NULL) == FALSE || numBytes != sizeof(DWORD)) {
        return FALSE;
    }
    
    //printf("New message: %i bytes\n", msgSize);
    
    if (msgSize >= BUFSIZE) {
        printf("[-] Message too big: %i\n", msgSize);
        return FALSE;
    }
    
    if (ReadFile(hPipe, buffer, msgSize, &numBytes, NULL) == FALSE || numBytes != msgSize) {
        return FALSE;
    }
    
    return TRUE;
}


BOOL WritePipeMessage(HANDLE hPipe, CHAR* buffer)
{
    DWORD msgSize = strlen(buffer);
    DWORD numBytes;
    
    if (WriteFile(hPipe, &msgSize, sizeof(DWORD), &numBytes, NULL) == FALSE || numBytes != sizeof(DWORD)) {
        return FALSE;
    }
    
    //printf("Sending message: %i bytes\n", msgSize);
    
    /* We do not send the trailing 0 on the pipe but must leave 1 byte for the receiver to fill the 0 */
    if (msgSize >= BUFSIZE-1) {
        msgSize = BUFSIZE-1;
    }
    
    if (WriteFile(hPipe, buffer, msgSize, &numBytes, NULL) == FALSE || numBytes != msgSize) {
        return FALSE;
    }
    
    return TRUE;
}


/* Returns the first established TCP connection for the given process id
 * Adapted after http://msdn.microsoft.com/en-us/library/windows/desktop/aa366026%28v=vs.85%29.aspx
 */
BOOL GetEstablishedConnOfPid(DWORD pid, MIB_TCPROW_OWNER_PID* pConnInfo)
{
    #define MALLOC(x)   HeapAlloc(GetProcessHeap(), 0, (x))
    #define FREE(x)     HeapFree(GetProcessHeap(), 0, (x))

    MIB_TCPTABLE_OWNER_PID*     pTcpTable;
    DWORD                       dwSize;
    DWORD                       dwRetVal;
    DWORD                       i;
    BOOL                        bFound = FALSE;
        
    /* Make an initial call to GetExtendedTcpTable to get 
     * the necessary size into the dwSize variable 
     */
    if ((dwRetVal = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)MALLOC(dwSize);
        if (pTcpTable == NULL) {
            printf("[-] Error allocating memory\n");
            return FALSE;
        }
    }
    
    /* Make a second call to GetTcpTable to get
     * the actual data we require
     */
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
        for (i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (pTcpTable->table[i].dwOwningPid == pid && pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                *pConnInfo = pTcpTable->table[i];
                bFound = TRUE;
                break;
            }
        }
    } else {
        printf("[-] GetExtendedTcpTable failed\n");
        FREE(pTcpTable);
        return FALSE;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

    return bFound;
}


/* Converts an IPv4 address from DWORD to dotted notation string
 */
BOOL IPv4ToString(DWORD ip, CHAR* dst, INT dstSize)
{
    struct in_addr IpAddr;

    IpAddr.S_un.S_addr = (u_long) ip;
    strcpy_s(dst, dstSize, inet_ntoa(IpAddr));

    return TRUE;
}


VOID PrintLastError()
{
    LPSTR     messageBuffer     = NULL;
    size_t    size;
    DWORD     errorMessageID     = GetLastError();
    
    if(errorMessageID == 0) {
        return;
    }
    
    size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    printf("Error: %.*s\n", size, messageBuffer);

    //Free the buffer.
    LocalFree(messageBuffer);

    return;
}

/* Find the pid of the first process named procName
 */
DWORD GetPidFromProcname(CHAR* procName)
{
    PROCESSENTRY32  pe; 
    HANDLE          hSnapshot; 
    BOOL            retVal;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
    if(hSnapshot == INVALID_HANDLE_VALUE) { 
        printf("[-] Failed to create snapshot of running processes\n"); 
        return 0; 
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    retVal = Process32First(hSnapshot, &pe); 

    while(retVal) { 
        if(StrStrI(pe.szExeFile, procName) != NULL) { 
            return pe.th32ProcessID; 
        }
        retVal    = Process32Next(hSnapshot,&pe); 
        pe.dwSize = sizeof(PROCESSENTRY32); 
    }

    return 0;
}

/* Enumerate all Putty processes and return the first one that is not injected with our DLL
 */
DWORD GetPidNotInjected(CHAR* procName, UCHAR* dllName)
{
    PROCESSENTRY32  pe; 
    HANDLE          hSnapshot; 
    BOOL            retVal;
    INT             i;
    BOOL            bFound;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
    if(hSnapshot == INVALID_HANDLE_VALUE) { 
        printf("[-] Failed to create snapshot of running processes\n"); 
        return 0; 
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    retVal = Process32First(hSnapshot, &pe); 

    while(retVal) { 
        if(StrStrI(pe.szExeFile, procName) != NULL) { 
        
            if (IsDllLoaded(pe.th32ProcessID, dllName) == FALSE) {
                return pe.th32ProcessID;
            }
        }
        retVal    = Process32Next(hSnapshot,&pe); 
        pe.dwSize = sizeof(PROCESSENTRY32); 
    }

    return 0;
}

VOID ListPuttyProcesses(UCHAR* procName, UCHAR* dllName)
{
    PROCESSENTRY32          pe; 
    HANDLE                  hSnapshot; 
    BOOL                    retVal;
    MIB_TCPROW_OWNER_PID    connInfo;
    CHAR                    ipAddr1[BUFSIZE];
    CHAR                    ipAddr2[BUFSIZE];
    UCHAR                   buffer[BUFSIZE];
    UCHAR                   dllInjected[BUFSIZE];

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
    if(hSnapshot == INVALID_HANDLE_VALUE) { 
        printf("[-] Failed to create snapshot of running processes\n"); 
        return; 
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    retVal = Process32First(hSnapshot, &pe); 

    printf("\n");
    printf("Process Name\tPID\tLocal Address\t\tRemote Address\t\tInjected\n");
    printf("------------\t---\t-------------\t\t--------------\t\t--------\n");
    
    while(retVal) { 
        if(StrStrI(pe.szExeFile, procName) != NULL) { 
            if(IsDllLoaded(pe.th32ProcessID, dllName) == TRUE) {
                sprintf(dllInjected, "Yes");
            } else {
                sprintf(dllInjected, "No");
            }
        
            printf("%s\t%i\t", procName, pe.th32ProcessID);
            
            if (GetEstablishedConnOfPid(pe.th32ProcessID, &connInfo) == FALSE) {
                printf("-           \t\t-            \t\t%s\n", dllInjected);
            } else {
                IPv4ToString(connInfo.dwLocalAddr, ipAddr1, BUFSIZE);
                printf("%s:%i\t", ipAddr1, ntohs(connInfo.dwLocalPort));

                IPv4ToString(connInfo.dwRemoteAddr, ipAddr2, BUFSIZE);
                printf("%s:%i\t", ipAddr2, ntohs(connInfo.dwRemotePort));
                
                printf("%s\n", dllInjected);
            }
        } 
        retVal    = Process32Next(hSnapshot,&pe); 
        pe.dwSize = sizeof(PROCESSENTRY32); 
    }
    printf("\n");
    
    return;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    DWORD dwProcessId;
    UCHAR tmpBuf[BUFSIZE];
    
    GetWindowThreadProcessId(hWnd, &dwProcessId);
    if (dwProcessId == lParam) {
    
        memset(tmpBuf, 0, BUFSIZE);
        GetClassName(hWnd, tmpBuf, BUFSIZE);
    
        if (strcmp(tmpBuf, "PuTTY") == 0) {
            g_HWND = hWnd;
            return FALSE;
        }
    }
    return TRUE;
}

HWND GetCurrentWindowHandler()
{
    EnumWindows(EnumWindowsProc, GetCurrentProcessId());
    return g_HWND;
}

/* Simulate a key press in the main Putty window 
 */ 
BOOL PressPuttyKey(UINT keyCode)
{
    HWND hWnd;
    
    hWnd = GetCurrentWindowHandler();
    if (hWnd == NULL) {
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS); 
    
    PostMessage(hWnd, WM_CHAR, keyCode, 0);
    
    if (GetLastError() != ERROR_SUCCESS) {
        return FALSE;
    }
    
    return TRUE;
}
 
/* Tell if the DLL is loaded in the target process
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms682621%28v=vs.85%29.aspx
 */
BOOL IsDllLoaded( DWORD processID, UCHAR* dllName )
{
    HMODULE         hMods[1024];
    HANDLE          hProcess;
    DWORD           cbNeeded;
    unsigned int    i;

    /* Get a handle to the process. */
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, processID );
    if (NULL == hProcess) {
        return FALSE;
    }

    /* Get a list of all the modules in this process. */
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            TCHAR szModName[MAX_PATH];

            /* Get the full path to the module's file. */
            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
                    sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                if (strcmp(dllName, szModName) == 0) {
                    CloseHandle( hProcess );
                    return TRUE;
                }
            }
        }
    }
    
    /* Release the handle to the process. */
    CloseHandle( hProcess );

    return FALSE;
} 
 
/* Convert wide-char to normal char 
 */
VOID ConvertToChar(WCHAR *wbuf, CHAR *buf) 
{
    while (*buf++ = (CHAR)*wbuf++); 
}

/* Get the pid of parent process 
 * https://gist.github.com/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4 
 */
DWORD GetPPid()
{
    HANDLE          hSnapshot;
    PROCESSENTRY32  pe32;
    DWORD           ppid    = 0;
    DWORD           pid     = GetCurrentProcessId();
 
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if( hSnapshot == INVALID_HANDLE_VALUE ) {
        return 0;
    }
 
    ZeroMemory( &pe32, sizeof( pe32 ) );
    pe32.dwSize = sizeof( pe32 );
    if( !Process32First( hSnapshot, &pe32 ) ) {
        return 0;
    }
 
    do {
        if( pe32.th32ProcessID == pid ){
            ppid = pe32.th32ParentProcessID;
            break;
        }
    } while( Process32Next( hSnapshot, &pe32 ) );
 
    CloseHandle( hSnapshot );
    
    return ppid;
}


BOOL ValidateIPv4Address(CHAR* ipAddr)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddr, &(sa.sin_addr));
    return result != 0;
}

BOOL ParseIPPort(CHAR* connectBackInfo, CHAR* connectBackIP, DWORD* connectBackPort)
{
    CHAR*    pos;

    if (strlen(connectBackInfo) < 3) {
        printf("[-] Invalid format for reverse connection. Must be IP:PORT\n");
        return FALSE;                    
    }
    pos = strstr(connectBackInfo, ":");
    if (pos == NULL) {
        printf("[-] Invalid format for reverse connection. Must be IP:PORT\n");
        return FALSE;                    
    }
    if (connectBackInfo[0] == ':' || connectBackInfo[strlen(connectBackInfo)-1] == ':') {
        printf("[-] Invalid format for reverse connection. Must be IP:PORT\n");
        return FALSE;                    
    }
    *pos = 0;
    sprintf(connectBackIP, connectBackInfo);
    if (ValidateIPv4Address(connectBackIP) == FALSE) {
        printf("[-] Invalid IP address for reverse connection\n");
        return FALSE;                
    }
    if (sscanf(pos+1, "%d", connectBackPort) == 0) {
        printf("[-] Invalid port number for reverse connection. Must be an integer\n");
        return FALSE;
    }
    if (*connectBackPort <= 0 || *connectBackPort > 65535) {
        printf("[-] Invalid port number for reverse connection. Must be in range 0..65535\n");
        return FALSE;
    }
    return TRUE;
}