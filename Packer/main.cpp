// src/main.cpp
#include "Packer.h"
#include "Util.h"
#include <windows.h>
#include <string>
#include <stdexcept>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        MessageBoxW(
            NULL,
            L"Drag & drop an EXE onto this icon to protect it.",
            L"CustomPacker",
            MB_OK | MB_ICONINFORMATION
        );
        return 0;
    }

    std::wstring input = argv[1];
    std::wstring desktop = Util::GetDesktopPath();
    std::wstring base = Util::GetFileNameWithoutExt(input);
    std::wstring output = desktop + L"\\" + base + L" - protected.exe";

    try {
        Packer packer;
        packer.Pack(input, output);

        MessageBoxW(
            NULL,
            (L"Protected EXE created:\n" + output).c_str(),
            L"CustomPacker",
            MB_OK
        );
    }
    catch (const std::exception& e) {
        MessageBoxW(
            NULL,
            (L"Error: " + Util::ToWString(e.what())).c_str(),
            L"CustomPacker Error",
            MB_OK | MB_ICONERROR
        );
        return 1;
    }
    return 0;
}
