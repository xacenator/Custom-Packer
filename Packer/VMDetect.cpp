// src/VMDetect.cpp
#include "VMDetect.h"
#include <intrin.h>
#include <string>
#include <cstring>

namespace VMDetect {

    bool IsRunningInVM() {
        int cpu[4] = { 0 };

        // Step 1: check hypervisor bit (bit 31 of ECX in leaf 1)
        __cpuid(cpu, 1);
        if ((cpu[2] & (1 << 31)) == 0) {
            // No hypervisor present at all
            return false;
        }

        // Step 2: query the hypervisor vendor signature
        // leaf 0x40000000 is reserved for hypervisor vendor ID
        __cpuid(cpu, 0x40000000);
        char vendor[13];
        std::memcpy(&vendor[0], &cpu[1], 4);  // EBX
        std::memcpy(&vendor[4], &cpu[2], 4);  // ECX
        std::memcpy(&vendor[8], &cpu[0], 4);  // EAX
        vendor[12] = '\0';

        const std::string hv{ vendor };
        // Only treat known VM vendors as “VM”
        if (hv.find("VMware") != std::string::npos ||
            hv.find("VBoxVBoxV") != std::string::npos ||
            hv.find("XenVMMXenV") != std::string::npos ||
            hv.find("Microsoft Hv") != std::string::npos) {
            return true;
        }

        // Otherwise it’s some other hypervisor (e.g. Hyper-V), ignore
        return false;
    }

} // namespace VMDetect
