#define ZYDIS_STATIC_BUILD
#define ZYCORE_STATIC_BUILD

#include <iostream>
#include "pefile64.h"
#include "disasm.h"
#include "tobf64.h"

int main() {

    PEFile64 pe;
    pe.load_file("C:\\Users\\T1t4n4pwn\\source\\repos\\Project2\\x64\\Release\\Project2.exe");

    std::vector<uint8_t> data;

    pe.get_section_data(".text", data);

    Disasm disasm;
    std::vector<INST_INFO> insts;
    disasm.disasm(0x140001000, &data[0], data.size(), insts);

    TObf64 obf{pe};

    std::vector<FUNCTION_INFO> functions;
    obf.searchSDK(functions);

    obf.protect(functions);

    
    


    std::cout << "Ok" << std::endl;
    return 0;
}
