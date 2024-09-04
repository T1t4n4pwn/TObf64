#include "obfhandler.h"
#include "zasm/zasm.hpp"
#include "asmutils.h"

using namespace zasm;

bool process_lea(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr)
{
    Program program{ MachineMode::AMD64 };
    x86::Assembler a{program};

    x86::Gp reg;
    AsmUtils::to_zasm_reg(insn.operands[0].reg.value, reg);

    if (insn.operands[1].mem.base == ZYDIS_REGISTER_RIP) {

        uint64_t dest_addr = insn.address + insn.operands[1].mem.disp.value + insn.bytes.size();
        
        Label l1 = a.createLabel();
        /*
            call $0�Ὣ��ǰָ�����һ��ָ��ĵ�ַѹ��ջ��������һ����л��������������ض�λ����Ҫ-5
        */
        a.call(l1);
        a.bind(l1);
        a.add(x86::qword_ptr(x86::rsp), (dest_addr - current_addr) - 5);
        a.pop(reg);

        Serializer serial;
        Error err = serial.serialize(program, current_addr);
        if (err == ErrorCode::None) {
            obf_code.insert(obf_code.end(), serial.getCode(), serial.getCode() + serial.getCodeSize());
            current_addr += serial.getCodeSize();
            return true;
        }
    }

    return false;
}

bool process_mov(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr)
{

    Program program{ MachineMode::AMD64 };
    x86::Assembler a{ program };

    //mov reg, imm
    //��ԭ�������������������Ľ��ѹ��ջ����ֱ�ӽ�ջ����ֵ�������õ�ԭ����ֵ���ٵ���Ŀ��Ĵ������Ա�֤ջƽ��
    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        
        if (insn.operands[0].reg.value > ZYDIS_REGISTER_R15) {
            return false; //�����Ĵ����ݲ�����
        }

        x86::Gp reg;
        uint64_t imm = insn.operands[1].imm.value.u;

        AsmUtils::to_zasm_reg(insn.operands[0].reg.value, reg);

        if (imm == 0 || imm == 0xFFFFFFFFFFFFFFFF) {
            return false; //��򾡿��ܵıܿ�0
        }

        uint32_t rand_num = AsmUtils::get_random_num(imm + 1, 0xFFFF);

        a.push(imm ^ rand_num);
        a.xor_(x86::qword_ptr(x86::rsp), rand_num);
        a.pop(reg);

        Serializer serial;
        Error err = serial.serialize(program, current_addr);
        if (err == ErrorCode::None) {
            obf_code.insert(obf_code.end(), serial.getCode(), serial.getCode() + serial.getCodeSize());
            current_addr += serial.getCodeSize();
            return true;
        }
    }

    //mov reg, mem

    return false;
}

bool process_call(INST_INFO insn, std::vector<uint8_t>& obf_code, uint64_t& current_addr)
{
    Program program{ MachineMode::AMD64 };
    x86::Assembler a{ program };
    /*callָ���ݲ������������ȴ����ض�λ����*/
    if (insn.bytes[0] == 0xE8) {
        uint64_t dest_addr = insn.address + insn.operands[0].imm.value.u + 5;
        a.call(dest_addr);

        Serializer serial;
        Error err = serial.serialize(program, current_addr);
        if (err == ErrorCode::None) {
            obf_code.insert(obf_code.end(), serial.getCode(), serial.getCode() + serial.getCodeSize());
            current_addr += serial.getCodeSize();
            return true;
        }
        
    }

    /*���� FF15 call*/
    if (insn.bytes[0] == 0xFF && insn.bytes[1] == 0x15) {
        uint64_t dest_addr = insn.address + insn.operands[0].mem.disp.value + 6;

        uint8_t opcode[6] = { 0xFF, 0x15, 0x0, 0x0, 0x0, 0x0 };
        uint32_t operand = dest_addr - current_addr - 6;
        memcpy(&opcode[2], &operand, 4);

        obf_code.insert(obf_code.end(), opcode, opcode + sizeof(opcode));

        current_addr += sizeof(opcode);

        return true;
    }

    return false;
}
