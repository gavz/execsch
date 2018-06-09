@echo off
cl -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /entry:SubclassProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000