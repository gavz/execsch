   // api need to be implicitly declared, otherwise compiler stores the strings
   // in the data section
   
DWORD szGetProcAddress[4];

szGetProcAddress[0]=0x50746547;
szGetProcAddress[1]=0x41636F72;
szGetProcAddress[2]=0x65726464;
szGetProcAddress[3]=0x00007373;

DWORD szGetModuleHandleA[5];

szGetModuleHandleA[0]=0x4D746547;
szGetModuleHandleA[1]=0x6C75646F;
szGetModuleHandleA[2]=0x6E614865;
szGetModuleHandleA[3]=0x41656C64;
szGetModuleHandleA[4]=0;

DWORD szkernel32[3];

szkernel32[0]=0x6E72656B;
szkernel32[1]=0x32336C65;
szkernel32[2]=0;

DWORD szuser32[2];

szuser32[0]=0x72657375;
szuser32[1]=0x00003233;

DWORD szUxSubclassInfo[4];

szUxSubclassInfo[0]=0x75537855;
szUxSubclassInfo[1]=0x616C6362;
szUxSubclassInfo[2]=0x6E497373;
szUxSubclassInfo[3]=0x00006F66;

DWORD szMessageBoxA[3];

szMessageBoxA[0]=0x7373654D;
szMessageBoxA[1]=0x42656761;
szMessageBoxA[2]=0x0041786F;

DWORD msg[4];

msg[0]=0x6C6C6548;
msg[1]=0x57202C6F;
msg[2]=0x646C726F;
msg[3]=0x00000021;

DWORD title[3];

title[0]=0x504F5250;
title[1]=0x74616761;
title[2]=0x00000065;

DWORD szpropagate[3];

szpropagate[0]=0x706F7270;
szpropagate[1]=0x74616761;
szpropagate[2]=0x00000065;

DWORD szSetEvent[3];

szSetEvent[0]=0x45746553;
szSetEvent[1]=0x746E6576;
szSetEvent[2]=0;

DWORD szOpenEventA[3];

szOpenEventA[0]=0x6E65704F;
szOpenEventA[1]=0x6E657645;
szOpenEventA[2]=0x00004174;

DWORD szCloseHandle[3];

szCloseHandle[0]=0x736F6C43;
szCloseHandle[1]=0x6E614865;
szCloseHandle[2]=0x00656C64;

DWORD szGetForegroundWindow[5];

szGetForegroundWindow[0]=0x46746547;
szGetForegroundWindow[1]=0x6765726F;
szGetForegroundWindow[2]=0x6E756F72;
szGetForegroundWindow[3]=0x6E695764;
szGetForegroundWindow[4]=0x00776F64;

