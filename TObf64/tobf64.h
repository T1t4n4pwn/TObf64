#pragma once

#include <iostream>
#include <vector>
#include <Windows.h>
#include "pefile64.h"
#include "disasm.h"

typedef struct {
    uint64_t startAddr;
    uint64_t endAddr;
    std::vector<INST_INFO> code;
}FUNCTION_INFO;

class TObf64
{
public:
    TObf64(PEFile64& pe);
    ~TObf64();

    bool searchSDK(std::vector<FUNCTION_INFO>& functions);

    bool protect(const std::vector<FUNCTION_INFO>& functions);

private:
    PEFile64& m_pe;
};