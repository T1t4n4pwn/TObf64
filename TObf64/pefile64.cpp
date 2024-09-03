//
// Created by T1t4n4pwn on 2024/9/3.
//

#include "pefile64.h"

#include "fileutils.h"

PEFile64::PEFile64() {

}

bool PEFile64::load_file(const std::string& file_path) {
    m_file_path = file_path;
    m_buffer.clear();

    if(!FileUtils::read_binary(file_path, m_buffer)){
        return false;
    }

    update_data();

    return true;
}

bool PEFile64::is_valid() {
    if(m_dos_header->e_magic != IMAGE_DOS_SIGNATURE){
        return false;
    }
    if(m_nt_headers->Signature != IMAGE_NT_SIGNATURE){
        return false;
    }

    return true;
}

uint64_t PEFile64::alignment(uint64_t size, uint64_t align) {
    if(size % align == 0){
        return size;
    }

    return ((size / align) + 1) * align;
}

uint64_t PEFile64::get_entry_point()
{
    return m_optional_headers->AddressOfEntryPoint;
}

void PEFile64::set_entry_point(uint64_t rva)
{
    m_optional_headers->AddressOfEntryPoint = rva;
}

PIMAGE_SECTION_HEADER PEFile64::get_last_section()
{
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(m_nt_headers);
    return firstSection + (m_file_header->NumberOfSections - 1);
}

bool PEFile64::create_section(const char *name, const uint8_t *data, size_t size, uint32_t properties)
{
    uint64_t newSize = alignment(m_buffer.size() + size, m_optional_headers->FileAlignment);

    m_buffer.resize(newSize);

    update_data();

    PIMAGE_SECTION_HEADER lastSection = get_last_section();
    PIMAGE_SECTION_HEADER newSection = lastSection + 1;

    std::memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));

    newSection->Characteristics = properties;
    newSection->Misc.VirtualSize = alignment(size, m_optional_headers->SectionAlignment);
    newSection->SizeOfRawData = alignment(size, m_optional_headers->FileAlignment);
    newSection->PointerToRawData = lastSection->PointerToRawData + lastSection->SizeOfRawData;
    newSection->VirtualAddress = lastSection->VirtualAddress + alignment(lastSection->Misc.VirtualSize, m_optional_headers->SectionAlignment);

    std::memcpy(newSection->Name, name, 8);

    m_file_header->NumberOfSections++;

    m_optional_headers->SizeOfImage += alignment(size, m_optional_headers->SectionAlignment);

    if (data == nullptr) {
        std::memset(&m_buffer[0] + newSection->PointerToRawData, 0, size);
    }
    else {
        std::memcpy(&m_buffer[0] + newSection->PointerToRawData, data, size);
    }


    return true;
}

void PEFile64::copy_data(uint64_t offset, const uint8_t* data, size_t size)
{
    std::memcpy(&m_buffer[offset], data, size);
}

bool PEFile64::get_section_data(const std::string& name, std::vector<uint8_t> &data)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(m_nt_headers);

    for (int i = 0; i < m_file_header->NumberOfSections; i++) {
        if(name.compare((char*)section->Name) == 0){
            data.resize(section->SizeOfRawData);
            memcpy(&data[0], &m_buffer[0] + section->PointerToRawData, data.size());
            return true;
        }
    }

    return false;
}

void PEFile64::save_file(const std::string &file_path)
{
    FileUtils::write_binary(file_path, m_buffer);
}

uint64_t PEFile64::find_import_addr_va(const char *name) {
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(&m_buffer[0] + rva_to_foa(m_optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

    for (; import_desc->Name; import_desc++) {

        std::string lib_name = std::string((char*)&m_buffer[0] + rva_to_foa(import_desc->Name));

        if(lib_name.compare("TProtect64SDK.dll") != 0){
            continue;
        }

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(&m_buffer[0] + rva_to_foa(import_desc->FirstThunk));

        for (int i = 0; thunk->u1.Ordinal != 0; i += 8) {
            PIMAGE_IMPORT_BY_NAME func_name = (PIMAGE_IMPORT_BY_NAME)(&m_buffer[0] + rva_to_foa(thunk->u1.AddressOfData));
            std::string fName = func_name->Name;
            if (fName.compare(name) == 0)
            {
                return import_desc->FirstThunk + i;
            }

            thunk++;
        }

    }

    return 0;
}

uint64_t PEFile64::rva_to_foa(uint64_t rva)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(m_nt_headers);
    for(int i = 0; i < m_file_header->NumberOfSections; i++) {
        IMAGE_SECTION_HEADER current_section = section[i];
        if(rva >= current_section.VirtualAddress && rva <= (current_section.VirtualAddress + current_section.Misc.VirtualSize)){
            uint64_t offset = rva - current_section.VirtualAddress;
            return current_section.PointerToRawData + offset;
        }
    }
    return 0;
}

uint64_t PEFile64::get_image_base()
{
    return m_optional_headers->ImageBase;
}

void PEFile64::update_data()
{
    m_dos_header = (PIMAGE_DOS_HEADER)&m_buffer[0];
    m_nt_headers = (PIMAGE_NT_HEADERS)(&m_buffer[0] + m_dos_header->e_lfanew);
    m_file_header = &m_nt_headers->FileHeader;
    m_optional_headers = &m_nt_headers->OptionalHeader;
}

void PEFile64::patch_by_rva(uint64_t rva, uint8_t* data, size_t size) {
    uint64_t foa = rva_to_foa(rva);
    memcpy(&m_buffer[foa], data, size);
}

void PEFile64::patch_by_va(uint64_t va, uint8_t* data, size_t size) {
    uint64_t rva = va - get_image_base();
    patch_by_rva(rva, data, size);
}

std::string PEFile64::file_path() const
{
    return m_file_path;
}

PIMAGE_DOS_HEADER PEFile64::dos_header() const
{
    return m_dos_header;
}

PIMAGE_NT_HEADERS PEFile64::nt_header() const
{
    return m_nt_headers;
}

PIMAGE_FILE_HEADER PEFile64::file_header() const
{
    return m_file_header;
}

PIMAGE_OPTIONAL_HEADER PEFile64::optional_header() const
{
    return m_optional_headers;
}