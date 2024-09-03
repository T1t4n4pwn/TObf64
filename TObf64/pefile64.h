#pragma once
#include <iostream>
#include <vector>
#include <windows.h>

class PEFile64 {
public:
    PEFile64();

    bool load_file(const std::string& file_path);

    bool is_valid();

    uint64_t alignment(uint64_t size, uint64_t align);

    uint64_t get_entry_point();

    void set_entry_point(uint64_t rva);

    PIMAGE_SECTION_HEADER get_last_section();

    bool create_section(const char* name, const uint8_t* data, size_t size, uint32_t properties);
    
    void copy_data(uint64_t offset, const uint8_t* data, size_t size);

    bool get_section_data(const std::string& name, std::vector<uint8_t>& data);

    void save_file(const std::string& file_path);

    uint64_t find_import_addr_va(const char* name);

    uint64_t rva_to_foa(uint64_t rva);

    uint64_t get_image_base();

    void update_data();

    void patch_by_rva(uint64_t rva, uint8_t* data, size_t size);

    void patch_by_va(uint64_t va, uint8_t* data, size_t size);

    std::string file_path() const;

    PIMAGE_DOS_HEADER dos_header() const;

    PIMAGE_NT_HEADERS nt_header() const;

    PIMAGE_FILE_HEADER file_header() const;

    PIMAGE_OPTIONAL_HEADER optional_header() const;

private:
    std::string m_file_path;
    std::vector<uint8_t> m_buffer;

    PIMAGE_DOS_HEADER m_dos_header;
    PIMAGE_NT_HEADERS m_nt_headers;
    PIMAGE_FILE_HEADER m_file_header;
    PIMAGE_OPTIONAL_HEADER m_optional_headers;
};
