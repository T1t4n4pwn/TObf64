#pragma once
#include <iostream>
#include <Zydis/Zydis.h>
#include <zasm/zasm.hpp>
#include <vector>
#include <map>
#include <random>

class AsmUtils {
public:

	static bool to_zasm_reg(ZydisRegister reg, zasm::x86::Gp& dest_reg) {
		std::map<ZydisRegister, zasm::x86::Gp> regs = {
			{ZYDIS_REGISTER_RAX, zasm::x86::rax},
			{ZYDIS_REGISTER_RBX, zasm::x86::rbx},
			{ZYDIS_REGISTER_RCX, zasm::x86::rcx},
			{ZYDIS_REGISTER_RDX, zasm::x86::rdx},
			{ZYDIS_REGISTER_RBP, zasm::x86::rbp},
			{ZYDIS_REGISTER_RSP, zasm::x86::rsp},
			{ZYDIS_REGISTER_RSI, zasm::x86::rsi},
			{ZYDIS_REGISTER_RDI, zasm::x86::rdi},

			{ZYDIS_REGISTER_R8, zasm::x86::r8},
			{ZYDIS_REGISTER_R9, zasm::x86::r9},
			{ZYDIS_REGISTER_R10, zasm::x86::r10},
			{ZYDIS_REGISTER_R11, zasm::x86::r11},
			{ZYDIS_REGISTER_R12, zasm::x86::r12},
			{ZYDIS_REGISTER_R13, zasm::x86::r13},
			{ZYDIS_REGISTER_R14, zasm::x86::r14},
			{ZYDIS_REGISTER_R15, zasm::x86::r15},

		};

		auto it = regs.find(reg);
		if (it == regs.end()) {
			return false;
		}

		dest_reg = it->second;

		return true;
	}

	static uint32_t get_random_num(uint32_t min, uint32_t max) {

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<int> dis(min, max);

		return dis(gen);
		
	}

	static bool create_jmp(uint64_t current_addr, uint64_t dest_addr, std::vector<uint8_t>& patch_code) {
		zasm::Program program{ zasm::MachineMode::AMD64 };
		zasm::x86::Assembler a{ program };

		a.jmp(dest_addr + 1);

		zasm::Serializer serial;
		zasm::Error err = serial.serialize(program, current_addr);
		if (err == zasm::ErrorCode::None) {
			patch_code.clear();
			patch_code.insert(patch_code.end(), serial.getCode(), serial.getCode() + serial.getCodeSize());
			return true;
		}

		return false;
	}

};