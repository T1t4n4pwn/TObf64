#include "TObf64.h"
/*解决windows.h的宏与标准库函数冲突的问题*/
#undef max
#undef min
#include "transform.h"

#include "asmutils.h"

TObf64::TObf64(PEFile64& pe) : m_pe(pe)
{

}

TObf64::~TObf64()
{
}

bool TObf64::searchSDK(std::vector<FUNCTION_INFO>& functions)
{
    uint64_t startVA = m_pe.find_import_addr_va("TProtect64Start") + m_pe.get_image_base();
    uint64_t endVA = m_pe.find_import_addr_va("TProtect64End") + m_pe.get_image_base();

    std::vector<uint8_t> code;
    if (!m_pe.get_section_data(".text", code)) {
        return false;
    }

    std::vector<INST_INFO> insns;

    Disasm disasm;
    if (!disasm.disasm(0x140001000, &code[0], code.size(), insns)) {
        return false;
    }

    functions.clear();
    size_t startCount = 0;
    size_t endCount = 0;

    for (const auto& e : insns) {

        static bool isFuncStart = false;

        if (disasm.get_ff15_addr(e) == startVA) {
            FUNCTION_INFO info{ 0 };
            info.startAddr = e.address;
            functions.push_back(info);

            isFuncStart = true;

            startCount++;
        }

        if (!functions.empty() && isFuncStart) {
            if (disasm.get_ff15_addr(e) != startVA && disasm.get_ff15_addr(e) != endVA) {
                functions[functions.size() - 1].code.push_back(e);
            }
        }

        if (disasm.get_ff15_addr(e) == endVA) {
            functions[functions.size() - 1].endAddr = e.address;
            isFuncStart = false;
            endCount++;
        }
    }

    for (const auto& func : functions)
    {
        if (func.startAddr == 0 || func.endAddr == 0) {
            std::cout << "混淆开始和结束标记混乱无序! 可能存在连续两个开始或结束标记" << std::endl;;
            return false;
        }
    }

    if (startCount != endCount) {
        std::cout << "混淆开始和结束标记数量不匹配!" << std::endl;
        return false;
    }

    return true;
}

bool TObf64::protect(const std::vector<FUNCTION_INFO>& functions)
{
    PIMAGE_SECTION_HEADER section = m_pe.get_last_section();

    uint64_t addr = m_pe.get_image_base() + section->VirtualAddress + m_pe.alignment(section->Misc.VirtualSize, 0x1000);

    std::vector<uint8_t> obf_code;


    for (size_t i = 0; i < functions.size(); i++)
    {
        std::vector<uint8_t> start_patch;
        std::vector<uint8_t> end_patch;

        auto current_func = functions[i];
        auto current_code = current_func.code;
        auto current_last_code = current_code[current_code.size() - 1];

        auto patch_start_addr = current_code[0].address - 6;
        auto patch_end_addr = current_last_code.address + current_last_code.bytes.size() + 6;

        AsmUtils::create_jmp(patch_start_addr, addr, start_patch);
        m_pe.patch_by_va(patch_start_addr, &start_patch[0], start_patch.size());

        Transform::process(current_code, addr, obf_code);

        AsmUtils::create_jmp(addr, patch_end_addr, end_patch);
        obf_code.insert(obf_code.end(), end_patch.data(), end_patch.data() + end_patch.size());
        addr += end_patch.size();
    }


    m_pe.create_section(".tobf64", obf_code.data(), obf_code.size(), 0x60000020);
    std::string file_path = m_pe.file_path().append(".obf.exe");
    DeleteFileA(file_path.c_str());
    m_pe.save_file(file_path);

    return true;
}
