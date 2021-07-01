#include "pch.h"
#include <windows.h>
#include <stdio.h>

DWORD SendHookAddress = 0xD39018; // E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 8B 46 38
DWORD SendCallAddress = 0xD3C660;
DWORD SendReturnAddress = 0xD3901D;

BYTE jmp[] = {0xE9, 0x00, 0x00, 0x00, 0x00};

void PrintMethod(char* method) {
    printf("Method: %.10s", method);
    printf("\n");
}

void PrintBodyHex(char* body, LPDWORD size)
{
    printf("Body:");

    for (int i = 0; i < (int)size; i++) {
        printf(" %02hhX", (unsigned char)body[i]);
    }

    printf("\n\n");
}

DWORD Hook(LPVOID lpFunction)
{
    DWORD calcedAddress = ((DWORD)lpFunction - SendHookAddress - 5);

    memcpy(&jmp[1], &calcedAddress, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)SendHookAddress, jmp, sizeof(jmp), 0);
    return SendHookAddress;
}

void __declspec(naked) SendHook() {
    __asm {
        pushad

        mov ebx, [esi+0x34]

        add ebx, 6
        push ebx
        sub ebx, 6
        call PrintMethod
        add esp, 4

        push [ebx+18]
        add ebx, 22
        push ebx
        sub ebx, 22
        call PrintBodyHex
        add esp, 8

        popad

        call SendCallAddress

        jmp SendReturnAddress
    }
}

void Start()
{
    SendHookAddress = SendHookAddress + (DWORD)GetModuleHandleA("KakaoTalk.exe");
    SendCallAddress = SendCallAddress + (DWORD)GetModuleHandleA("KakaoTalk.exe");
    SendReturnAddress = SendReturnAddress + (DWORD)GetModuleHandleA("KakaoTalk.exe");
    Hook(SendHook);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CON", "w", stdout);
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Start, NULL, NULL, NULL);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

