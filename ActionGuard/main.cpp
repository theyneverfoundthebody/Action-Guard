#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

bool basicretardedcheck(const std::wstring& fileName) {
    return fileName.find(L"malware") != std::wstring::npos;
}

void filestatistics(const std::wstring& action, const std::wstring& fileName) {
    std::wstring extension = fileName.substr(fileName.find_last_of(L".") + 1);
    if (extension != L"exe" && extension != L"pdb" && extension != L"sln" && extension != L"txt") {
        return;
    }
    std::wcout << L"File " << fileName << L" has been " << action << L"." << std::endl;
    if (basicretardedcheck(fileName)) {
        std::wcout << L"Malicious file detected: " << fileName << L" [ % ]" << std::endl;
    }
}

void directorymonitoring(const std::wstring& directory) {
    HANDLE hDir = CreateFileW(
        directory.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error opening directory: " << directory << std::endl;
        return;
    }

    BYTE buffer[1024];
    DWORD bytesReturned;

    while (true) {
        if (!ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL)) {
            std::wcerr << L"Error reading directory changes." << std::endl;
            break;
        }

        FILE_NOTIFY_INFORMATION* fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
        do {
            std::wstring fileName(fileInfo->FileName, fileInfo->FileNameLength / sizeof(wchar_t));
            switch (fileInfo->Action) {
            case FILE_ACTION_ADDED:
                filestatistics(L"created", fileName);
                break;
            case FILE_ACTION_MODIFIED:
                filestatistics(L"modified", fileName);
                break;
            default:
                break;
            }
            fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<BYTE*>(fileInfo) + fileInfo->NextEntryOffset);
        } while (fileInfo->NextEntryOffset != 0);
    }

    CloseHandle(hDir);
}

DWORD WINAPI passiverunninglogging(LPVOID lpParam) {
    const std::wstring& directory = *reinterpret_cast<const std::wstring*>(lpParam);
    HANDLE hDir = CreateFileW(
        directory.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error opening directory: " << directory << std::endl;
        return 1;
    }

    BYTE buffer[1024];
    DWORD bytesReturned;
    OVERLAPPED overlapped = { 0 };

    while (true) {
        if (!ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME,
            &bytesReturned,
            &overlapped,
            NULL)) {
            std::wcerr << L"Error reading directory changes." << std::endl;
            break;
        }

        DWORD waitStatus = WaitForSingleObject(hDir, INFINITE);
        if (waitStatus == WAIT_OBJECT_0) {
            FILE_NOTIFY_INFORMATION* fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
            do {
                std::wstring fileName(fileInfo->FileName, fileInfo->FileNameLength / sizeof(wchar_t));
                filestatistics(L"executed", fileName);
                fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<BYTE*>(fileInfo) + fileInfo->NextEntryOffset);
            } while (fileInfo->NextEntryOffset != 0);
        }
        else {
            std::wcerr << L"Wait failed: " << GetLastError() << std::endl;
            break;
        }
    }

    CloseHandle(hDir);
    return 0;
}

void drivemonitoring() {
    DWORD drivesMask = GetLogicalDrives();
    std::vector<std::wstring> driveLetters;
    for (int i = 0; i < 26; ++i) {
        if ((drivesMask >> i) & 1) {
            wchar_t driveLetter[] = { L'A' + static_cast<wchar_t>(i), L':', L'\\', L'\0' };
            driveLetters.push_back(driveLetter);
        }
    }

    for (const auto& driveLetter : driveLetters) {
        std::wcout << L"Monitoring directory: " << driveLetter << std::endl;
        directorymonitoring(driveLetter);
    }
}

int main() {
    drivemonitoring();

    const std::wstring system32Dir = L"C:\\Windows\\System32";
    HANDLE hThread = CreateThread(NULL, 0, passiverunninglogging, const_cast<LPVOID>(static_cast<const void*>(&system32Dir)), 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create thread." << std::endl;
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
