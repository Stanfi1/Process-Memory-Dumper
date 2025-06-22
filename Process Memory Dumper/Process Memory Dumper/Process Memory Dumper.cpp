#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <filesystem>
#include <set>
#include <string>
#include <chrono>

void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintInfo(const std::string& msg) {
    SetColor(14); // yellow
    std::cout << "[INFO] " << msg << "\n";
    SetColor(7);
}

void PrintSuccess(const std::string& msg) {
    SetColor(10); // green
    std::cout << "[OK] " << msg << "\n";
    SetColor(7);
}

void PrintError(const std::string& msg) {
    SetColor(12); // red
    std::cerr << "[ERROR] " << msg << "\n";
    SetColor(7);
}

void PrintString(const std::string& msg) {
    SetColor(9); // blue
    std::cout << "[STRING] " << msg << "\n";
    SetColor(7);
}

// Convert wide string - UTF-8 string
std::string WideStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

enum class DumpRegionType {
    ALL,
    HEAP,
    STACK
};

bool IsRegionTypeValid(const MEMORY_BASIC_INFORMATION& mbi, DumpRegionType regionType) {
    if (regionType == DumpRegionType::ALL) {
        return true;
    }

    // HEAP (MEM_PRIVATE)
    if (regionType == DumpRegionType::HEAP) {
        return (mbi.Type == MEM_PRIVATE);
    }

    // STACK (MEM_PRIVATE + protect PAGE_GUARD)
    if (regionType == DumpRegionType::STACK) {
        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_GUARD)) {
            return true;
        }
        //PAGE_READWRITE
        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
            return true;
        }
        return false;
    }

    return false;
}

bool DumpProcess(DWORD pid, const std::string& name, const std::string& grep, DumpRegionType dumpRegion, size_t maxDumpSize) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        PrintError("Cannot open process " + std::to_string(pid));
        return false;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    std::vector<char> dump;
    size_t totalRegions = 0;
    size_t skippedRegions = 0;

    for (BYTE* addr = (BYTE*)sysInfo.lpMinimumApplicationAddress;
        addr < (BYTE*)sysInfo.lpMaximumApplicationAddress;
        addr += 0x1000) {

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            ++skippedRegions;
            continue;
        }

        ++totalRegions;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            IsRegionTypeValid(mbi, dumpRegion)) {

            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                if (maxDumpSize > 0 && dump.size() + bytesRead > maxDumpSize) {
                    size_t spaceLeft = maxDumpSize - dump.size();
                    dump.insert(dump.end(), buffer.begin(), buffer.begin() + spaceLeft);
                    break; // limit
                }
                else {
                    dump.insert(dump.end(), buffer.begin(), buffer.begin() + bytesRead);
                }
            }
            else {
                ++skippedRegions;
            }
        }
        else {
            ++skippedRegions;
        }
    }

    CloseHandle(hProcess);

    std::string outPath = "dumps/" + name + "_" + std::to_string(pid) + ".bin";
    std::filesystem::create_directories("dumps");

    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        PrintError("Failed to open file for writing: " + outPath);
        return false;
    }
    out.write(dump.data(), dump.size());
    out.close();

    PrintSuccess("Dumped process to " + outPath);

    PrintInfo("Dump size: " + std::to_string(dump.size() / 1024) + " KB");
    PrintInfo("Total memory regions processed: " + std::to_string(totalRegions));
    PrintInfo("Skipped/unreadable regions: " + std::to_string(skippedRegions));

    // string 
    if (!grep.empty()) {
        std::set<std::string> matches;
        size_t pos = 0;
        while ((pos = std::search(dump.begin() + pos, dump.end(), grep.begin(), grep.end()) - dump.begin()) != dump.size()) {
            size_t start = pos;
            while (start > 0 && dump[start - 1] != '\0') --start;

            size_t end = pos;
            while (end < dump.size() && dump[end] != '\0') ++end;

            std::string found(&dump[start], &dump[end]);
            if (found.find(grep) != std::string::npos)
                matches.insert(found);

            pos = end;
            if (pos >= dump.size())
                break;
        }

        for (const auto& match : matches) {
            PrintString(match);
        }
    }

    return true;
}

DumpRegionType ParseRegionType(const std::string& input) {
    if (input == "heap") return DumpRegionType::HEAP;
    if (input == "stack") return DumpRegionType::STACK;
    return DumpRegionType::ALL;
}

void FindProcessesAndDump(const std::wstring& target, const std::string& grep, DumpRegionType dumpRegion, size_t maxDumpSize) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintError("Failed to create process snapshot.");
        return;
    }

    PROCESSENTRY32W entry; // Unicode 
    entry.dwSize = sizeof(entry);
    std::vector<std::thread> threads;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, target.c_str()) == 0) {
                DWORD pid = entry.th32ProcessID;
                std::wstring wName(entry.szExeFile);
                std::string name = WideStringToString(wName);
                threads.emplace_back([=]() {
                    DumpProcess(pid, name, grep, dumpRegion, maxDumpSize);
                    });
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    for (auto& t : threads)
        t.join();
}

int main() {
    std::wstring target;
    std::string grep, regionInput, maxSizeInput;

    PrintInfo("Enter process name (e.g. chrome.exe): ");
    std::getline(std::wcin, target);  // wide input

    PrintInfo("Enter string to search for (or leave empty to dump full memory): ");
    std::getline(std::cin, grep);

    PrintInfo("Enter memory region to dump (all / heap / stack), default all: ");
    std::getline(std::cin, regionInput);
    if (regionInput.empty()) regionInput = "all";

    PrintInfo("Enter max dump size in MB (0 for unlimited): ");
    std::getline(std::cin, maxSizeInput);

    size_t maxDumpSize = 0;
    try {
        maxDumpSize = std::stoul(maxSizeInput) * 1024 * 1024;
    }
    catch (...) {
        maxDumpSize = 0;
    }

    DumpRegionType dumpRegion = ParseRegionType(regionInput);

    auto start = std::chrono::high_resolution_clock::now();

    FindProcessesAndDump(target, grep, dumpRegion, maxDumpSize);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    PrintSuccess("All done.");
    PrintInfo("Elapsed time: " + std::to_string(elapsed.count()) + " seconds");


    PrintInfo("Press Enter to exit...");
    std::cin.get();
    return 0;
}
