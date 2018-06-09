/**
  Copyright © 2008,2018 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#ifndef SC2_H
#define SC2_H

#define UNICODE

#include <Windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <Winternl.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "payload.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#ifdef _WIN32  
#define SUBTAG_OFFSET 0xF60
#else
#define SUBTAG_OFFSET 0xFC1
#endif

#define SCAN_TYPE_STRING 0
#define SCAN_TYPE_BINARY 1

#define SCAN_ERROR_END   0  // we reached end of memory
#define SCAN_ERROR_FOUND 1  // we found data in memory
#define SCAN_ERROR_QUERY 2  // query of memory failed..

typedef struct _SCAN_DATA_T {
  LPBYTE addr;     // current address
  DWORD  pos;      // last position scanned
  DWORD  size;     // size of memory being scanned
  
  DWORD  type;     // type of data
  LPVOID data;     // data to find
  DWORD  len;      // length of data
} SCAN_DATA, *PSCAN_DATA;

typedef struct _INTERNAL_DISPATCH_ENTRY {
  LPWSTR                  ServiceName;
  LPWSTR                  ServiceRealName;
  LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
  LPHANDLER_FUNCTION_EX   ControlHandler;
  HANDLE                  StatusHandle;
  DWORD                   ServiceFlags;
  DWORD                   Tag;
  HANDLE                  MainThreadHandle;
  DWORD                   dwReserved;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;

typedef struct _SERVICE_ENTRY {
  INTERNAL_DISPATCH_ENTRY ide;               // copy of IDE
  LPVOID                  ide_addr;          // remote address of IDE
  WCHAR                   service[MAX_PATH]; // name of service
  DWORD                   tid;               // thread id belonging to service
  DWORD                   pid;               // process id hosting service
  WCHAR                   process[MAX_PATH]; // process name hosting service
} SERVICE_ENTRY, *PSERVICE_ENTRY;

typedef struct _THREAD_BASIC_INFORMATION {   
    DWORD     ExitStatus;   
    LPVOID    TebBaseAddress;   
    CLIENT_ID ClientId;   
    ULONG_PTR AffinityMask;   
    LONG      Priority;   
    LONG      BasePriority;   
} THREAD_BASIC_INFORMATION;   

typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
    ServiceNameFromTagInformation = 1,
    ServiceNamesReferencingModuleInformation,
    ServiceNameTagMappingInformation
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;
 
typedef struct _SC_SERVICE_TAG_QUERY {
    DWORD  dwProcessId;
    DWORD  dwServiceTag;
    DWORD  dwTagType;
    LPWSTR pszName;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;
 
typedef NTSTATUS (WINAPI *NtQueryInformationThread_t)(
  IN      HANDLE          ThreadHandle,
  IN      THREADINFOCLASS ThreadInformationClass,
  IN OUT   PVOID           ThreadInformation,
  IN      ULONG           ThreadInformationLength,
  _Out_opt_ PULONG          ReturnLength);  
  
typedef NTSTATUS (WINAPI *NtReadVirtualMemory_t)(
  IN     HANDLE          ProcessHandle,
  IN     PVOID           BaseAddress,
  IN OUT PVOID           Buffer,
  IN     ULONG           NumberOfBytesToRead,
  OUT    PULONG          NumberOfBytesReaded);
  
typedef DWORD (WINAPI *RtlCreateUserThread_t)(
	IN HANDLE 					    ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN BOOL 					      CreateSuspended,
	IN ULONG					      StackZeroBits,
	IN OUT PULONG				    StackReserved,
	IN OUT PULONG			    	StackCommit,
	IN LPVOID					      StartAddress,
	IN LPVOID					      StartParameter,
	OUT HANDLE 					    ThreadHandle,
	OUT LPVOID					    ClientID);

typedef DWORD (WINAPI *I_QueryTagInformation_t)(
    _In_opt_ LPCWSTR                   pszMachineName,
    _In_     SC_SERVICE_TAG_QUERY_TYPE QueryType,
    _Inout_  PSC_SERVICE_TAG_QUERY     Query);
    
#endif
