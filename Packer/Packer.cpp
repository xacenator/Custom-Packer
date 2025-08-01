// src/Packer.cpp

#include "Packer.h"
#include "Crypto.h"
#include "VMDetect.h"
#include "AntiDebug.h"
#include "Virtualizer.h"
#include "Util.h"

#include <LIEF/PE.hpp>
#include <stdexcept>
#include <vector>
#include <limits>
#include <cstdint>

using namespace LIEF::PE;

struct Packer::Impl {
    std::unique_ptr<Binary> bin;
    std::vector<uint8_t>    key, iv;
    uint32_t                originalEP;
    uint64_t                imageBase;
};

Packer::Packer() : p(new Impl()) {
    // Initialize key/IV
    p->key.assign(16, 0xAA);
    p->iv.assign(16, 0xBB);

    // Initialize EP and base to zero
    p->originalEP = 0;
    p->imageBase = 0;
}

void Packer::Pack(const std::wstring& inPath, const std::wstring& outPath) {
    // 1) Load and parse the input PE
    std::string inp = Util::WStringToString(inPath);
    p->bin = Parser::parse(inp);
    if (!p->bin) {
        throw std::runtime_error("Failed to parse PE");
    }

    // 2) Disable ASLR: clear the DYNAMIC_BASE flag (0x0040)
    {
        uint16_t dllChars = p->bin->optional_header().dll_characteristics();
        dllChars &= ~static_cast<uint16_t>(0x0040);
        p->bin->optional_header().dll_characteristics(dllChars);
    }

    // 3) Record the Original Entry Point (RVA) and Preferred Image Base
    p->originalEP = p->bin->optional_header().addressof_entrypoint();
    p->imageBase = p->bin->optional_header().imagebase();

    // 4) Anti-VM & Anti-Debug
    if (VMDetect::IsRunningInVM()) {
        throw std::runtime_error("VM detected");
    }
    AntiDebug::InstallAntiDebugMeasures();

    // 5) Encrypt key sections: .text, .rdata, .data
    for (auto const& name : { ".text", ".rdata", ".data" }) {
        if (Section* s = p->bin->get_section(name)) {
            // copy existing bytes
            auto span_data = s->content();
            std::vector<uint8_t> raw(span_data.begin(), span_data.end());

            // encrypt
            auto enc = Crypto::AES_CBC_Encrypt(raw, p->key, p->iv);
            if (enc.size() > std::numeric_limits<uint32_t>::max()) {
                throw std::runtime_error("Encrypted data too large for 32-bit size");
            }

            // write back and resize
            s->content(enc);
            s->size(static_cast<uint32_t>(enc.size()));          // SizeOfRawData
            s->virtual_size(static_cast<uint32_t>(enc.size()));  // VirtualSize

            // allow runtime write for stub decrypt
            s->add_characteristic(Section::CHARACTERISTICS::MEM_WRITE);
        }
    }

    // 6) (noop) Virtualizer placeholder
    Virtualizer::VirtualizeSections(p->bin.get());

    // 7) Inject a minimal jump-stub that jumps to (ImageBase + OriginalEP)
    {
        uint64_t targetVA = p->imageBase + p->originalEP;
        std::vector<uint8_t> stub;

        // mov rax, imm64
        stub.push_back(0x48);
        stub.push_back(0xB8);
        for (int i = 0; i < 8; ++i) {
            stub.push_back(static_cast<uint8_t>((targetVA >> (8 * i)) & 0xFF));
        }
        // jmp rax
        stub.push_back(0xFF);
        stub.push_back(0xE0);

        Section js(".stub");
        js.content(stub);
        js.add_characteristic(Section::CHARACTERISTICS::MEM_READ);
        js.add_characteristic(Section::CHARACTERISTICS::MEM_EXECUTE);

        p->bin->add_section(js, PE_SECTION_TYPES::TEXT);
        p->bin->optional_header().addressof_entrypoint(js.virtual_address());
    }

    // 8) Build and write the protected EXE
    Builder builder{ *p->bin };
    builder.build();
    builder.write(Util::WStringToString(outPath));
}
