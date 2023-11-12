#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/WithColor.h"

#include "BrokerFacade.h"
#include "Brokers/Broker.h"
#include "Brokers/BrokerPlugin.h"
#include "MDCategories.h"
#include "RegionMarker.h"

using namespace llvm;
using namespace llvm::object;
using namespace mcad;

#define DEBUG_TYPE "mcad-instaddr-broker"

template <class ELFT>
static std::pair<uint64_t, uint64_t> get_textOffsets(const ELFFile<ELFT> &Elf)
{
    const typename ELFFile<ELFT>::Elf_Shdr *result;
    auto sections = Elf.sections();
    if (auto err = sections.takeError())
        return std::make_pair(0, 0);

    for (auto &section : *sections) {
        auto sectionName = Elf.getSectionName(section);
        if (!sectionName)
            continue;
        if (*sectionName == ".text") {
            result = &section;
            break;
        }
    }

    if (!result)
        return std::make_pair(0, 0);

    return std::make_pair(result->sh_addr, result->sh_offset);
}

class InstAddrBroker : public Broker
{
    std::unique_ptr<MCDisassembler> disasm;
    const MCSubtargetInfo &mcSubtargetInfo;
    MCContext &mcCtx;
    const Target &target;
    OwningBinary<Binary> oBinary;
    std::unique_ptr<MemoryBuffer> memBuffer;
    bool resolved = false;

    int fetch(MutableArrayRef<const MCInst *> MCIS, int Size,
              Optional<MDExchanger> MDE) override
    {
        return fetchRegion(MCIS, Size, MDE).first;
    }

    std::pair<int, RegionDescriptor>
    fetchRegion(MutableArrayRef<const MCInst *> MCIS, int Size = -1,
                Optional<MDExchanger> MDE = llvm::None) override
    {
        if (resolved)
            return std::make_pair(-1, RegionDescriptor(false));

        if (Size < 0 || Size > MCIS.size())
            Size = MCIS.size();

        const auto &binary = oBinary.getBinary();
        std::pair<uint64_t, uint64_t> offsets{0, 0};
        if (const auto* elf32le = dyn_cast<ELF32LEObjectFile>(binary)) {
            offsets = get_textOffsets(elf32le->getELFFile());
        } else if (const auto* elf64le = dyn_cast<ELF64LEObjectFile>(binary)) {
            offsets = get_textOffsets(elf64le->getELFFile());
        } else if (const auto* elf32be = dyn_cast<ELF32BEObjectFile>(binary)) {
            offsets = get_textOffsets(elf32be->getELFFile());
        } else if (const auto* elf64be = dyn_cast<ELF64BEObjectFile>(binary)) {
            offsets = get_textOffsets(elf64be->getELFFile());
        }

        uint64_t textVma = offsets.first;
        uint64_t textOff = offsets.second;

        // XXX: on x86 instruction can be 1-15 bytes long.
        uint64_t disasmSize = 15;

        const auto &binaryBuff = binary->getData();
        auto buf = memBuffer->getBuffer();
        auto i = 0;
        while (buf.size()) {
            StringRef addr;
            std::tie(addr, buf) = buf.split('\n');
            unsigned vAddr = std::strtoul(addr.data(), nullptr, 16);

            uint64_t fileOff = textOff + (vAddr - textVma);
            if (fileOff < 0) {
                WithColor::error() << "File offset incorrect for " << format_hex(vAddr, 16) << "\n";
                continue;
            }

            auto binaryData = binaryBuff.slice(fileOff, fileOff + disasmSize);
            ArrayRef<uint8_t> bytes{binaryData.bytes_begin(), binaryData.bytes_end()};

            auto MCI = std::make_shared<MCInst>();
            auto disassembled = disasm->getInstruction(*MCI, disasmSize,
                                                       bytes,
                                                       vAddr,
                                                       nulls());

            if (!disassembled) {
                WithColor::error() << "Failed to disassemble at " << format_hex(vAddr, 16) << "\n";
                continue;
            }

            MCIS[i] = MCI.get();

            ++i;
        }

        // XXX: We parse the entire text file at once, for now.
        resolved = true;

        return std::make_pair(i == 0 ? -1 : i, RegionDescriptor(false));
    }

public:
    struct Options
    {
        StringRef BinaryFileName, InstAddrFileName;

        Options(int argc, const char *const *argv)
        {
            for (int i = 0 ; i < argc ;  ++i) {
                StringRef Arg(argv[i]);

                if (Arg.startswith("-binary") && Arg.contains("=")) {
                    BinaryFileName = Arg.split('=').second;
                }

                if (Arg.startswith("-instaddr") && Arg.contains("=")) {
                    InstAddrFileName = Arg.split('=').second;
                }
            }
        }
    };

    InstAddrBroker(const Options &Opts, const MCSubtargetInfo &mcSubtargetInfo,
                   MCContext &ctx, const Target &target) : target(target),
                                                            mcCtx(mcCtx),
                                                            mcSubtargetInfo(mcSubtargetInfo)
    {
        auto OBinary = createBinary(Opts.BinaryFileName);
        if (auto EC = OBinary.takeError()) {
            WithColor::error() << Opts.BinaryFileName << ": " << EC << '\n';
            return;
        }
        if (!isa<ELFObjectFileBase>(*OBinary->getBinary())) {
            WithColor::error() << "Non-ELF files are currently not supported.\n";
            return;
        }
        oBinary = std::move(*OBinary);

        auto MemBuffer = MemoryBuffer::getFile(Opts.InstAddrFileName);
        if (auto EC = MemBuffer.getError()) {
            WithColor::error() << Opts.InstAddrFileName << ":" << EC.message() << '\n';
            return;
        }
        memBuffer = std::move(*MemBuffer);

        disasm.reset(target.createMCDisassembler(mcSubtargetInfo, mcCtx));
    }
};


extern "C" ::llvm::mcad::BrokerPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
mcadGetBrokerPluginInfo()
{
  return {
    LLVM_MCAD_BROKER_PLUGIN_API_VERSION, "InstAddrBroker", "v0.1",
    [](int argc, const char *const *argv, BrokerFacade &BF) {
      InstAddrBroker::Options BrokerOpts(argc, argv);
      BF.setBroker(std::make_unique<InstAddrBroker>(BrokerOpts,
            BF.getSTI(), BF.getCtx(),
            BF.getTarget()));
    }
  };
}
