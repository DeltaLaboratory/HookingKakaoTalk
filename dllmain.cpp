#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include "nlohmann/json.hpp"

using json = nlohmann::json;
using std::vector;
using std::cout;
using std::endl;

DWORD SendHookAddress = 0xD39018 + 0x220; // E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 8B 46 38
DWORD SendCallAddress = 0xD3C660 + 0x220;
DWORD SendReturnAddress = 0xD3901D + 0x220;

BYTE jmp[] = {0xE9, 0x00, 0x00, 0x00, 0x00};

char* GetTimeStamp()
{
    char* buffer = (char*)malloc(sizeof(char) * 25);
    time_t timer;
    struct tm t;

    timer = time(NULL);
    localtime_s(&t, &timer);

    sprintf_s(buffer, 25, "[%04d-%02d-%02dT%02d:%02d:%02d]",
        t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
        t.tm_hour, t.tm_min, t.tm_sec);

    return buffer;
}

void PrintMethod(char* method) {
    std::cout << "Time : " << GetTimeStamp() << std::endl;
    std::cout << "Method : " << method << std::endl;
}

void PrintBodyHex(char* body, LPDWORD size)
{
    //ping 보내면 뒤지더라
    if (body == NULL) return;
    std::vector<std::uint8_t> buffer(body, body + (size_t)size);
    json decoded_body = json::from_bson(buffer);
    std::cout << "Body : " << decoded_body.dump() << std::endl << std::endl;
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

