#pragma once
#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>

typedef struct INST_INFO {
    uint64_t address;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    std::vector<uint8_t> bytes;
};

class Disasm {
public:
    Disasm() {
        m_status = ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }

    bool is_valid() {
        return ZYAN_SUCCESS(m_status);
    }

    bool disasm(uint64_t address, uint8_t* data, uint64_t size, std::vector<INST_INFO>& instructions) {

        size_t offset = 0;

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        while(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder, data + offset, size - offset, &instruction, operands))) {

            INST_INFO inst{0};
            inst.address = address;
            inst.bytes.insert(inst.bytes.end(), &data[offset], &data[offset] + instruction.length);
            inst.instruction = instruction;
            
            for (size_t i = 0; i < instruction.operand_count; i++)
            {
                inst.operands[i] = operands[i];
            }

            instructions.push_back(inst);

            

            address += inst.instruction.length;
            offset += inst.instruction.length;
        }

        return true;
    }

    uint64_t get_ff15_addr(INST_INFO info) {
        
        if (info.address == 0x0000000140001074) {
            printf("");
        }

        if (info.bytes.size() < 2) {
            return 0;
        }

        if (info.bytes[0] != 0xFF && info.bytes[1] != 0x15) {
            return 0;
        }

        return info.address + info.operands[0].mem.disp.value + info.instruction.length;
    }

private:
    ZydisDecoder m_decoder;
    ZyanStatus m_status;
};

