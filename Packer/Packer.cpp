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

using namespace LIEF::PE;  // brings in Section, PE_SECTION_TYPES, etc.

struct Packer::Impl {
    std::unique_ptr<Binary> bin;
    std::vector<uint8_t>     key, iv;
    uint32_t                 originalEP;
};

Packer::Packer() : p(new Impl()) {
    p->key.assign(16, 0xAA);
    p->iv.assign(16, 0xBB);
}

void Packer::Pack(const std::wstring& inPath, const std::wstring& outPath) {
    // 1) Parse input PE
    std::string inp = Util::WStringToString(inPath);
    p->bin = Parser::parse(inp);  // Parser::parse returns unique_ptr<Binary> :contentReference[oaicite:0]{index=0}
    if (!p->bin) throw std::runtime_error("Failed to parse PE");

    p->originalEP = p->bin->optional_header().addressof_entrypoint();

    // 2) Anti-VM and Anti-Debug
    if (VMDetect::IsRunningInVM())       throw std::runtime_error("VM detected");  // uses CPUID hypervisor bit :contentReference[oaicite:1]{index=1}
    AntiDebug::InstallAntiDebugMeasures();                                // exits on IsDebuggerPresent() :contentReference[oaicite:2]{index=2}

    for (auto const& name : { ".text", ".rdata", ".data" }) {
        if (Section* s = p->bin->get_section(name)) {
            auto payload = s->content();                                 // span<const uint8_t>
            std::vector<uint8_t> data(payload.begin(), payload.end());   // now a vector

            auto enc = Crypto::AES_CBC_Encrypt(data, p->key, p->iv);
            s->content(enc);                                             // setter accepts vector

            s->add_characteristic(Section::CHARACTERISTICS::MEM_WRITE);
        }
    }

    // 4) Placeholder virtualization
    Virtualizer::VirtualizeSections(p->bin.get());

    // 5) Inject loader stub
    std::vector<uint8_t> stub = Virtualizer::GetLoaderStub(
        p->key, p->iv, p->originalEP
    );

    // Build a new Section object
    Section new_stub(".stub");
    new_stub.content(stub);                                           // fill with your shellcode
    new_stub.add_characteristic(Section::CHARACTERISTICS::MEM_READ);  // set READ
    new_stub.add_characteristic(Section::CHARACTERISTICS::MEM_EXECUTE); // set EXECUTE

    // Add it as a TEXT-type section and redirect EntryPoint
    p->bin->add_section(new_stub, PE_SECTION_TYPES::TEXT);           // correct factory method :contentReference[oaicite:5]{index=5}
    p->bin->optional_header().addressof_entrypoint(new_stub.virtual_address());

    // 6) Build & write out  
    Builder builder{ *p->bin };
    builder.build();
    builder.write(Util::WStringToString(outPath));                   // two-step build/write API :contentReference[oaicite:6]{index=6}
}
