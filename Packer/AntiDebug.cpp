// src/AntiDebug.cpp
#include "AntiDebug.h"
#include <windows.h>

namespace AntiDebug {
    void InstallAntiDebugMeasures() {
        if (IsDebuggerPresent()) {
            ExitProcess(1);
        }
        // TODO: add timing checks, API hooks, etc.
		// This is a simple check, you can expand it with more sophisticated measures.
    }
}
