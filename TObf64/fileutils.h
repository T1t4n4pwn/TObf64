#pragma once
#include <iostream>
#include <fstream>
#include <vector>

class FileUtils{
public:
    static bool read_binary(const std::string& file_path, std::vector<uint8_t>& data){
        std::ifstream in(file_path, std::ios::in | std::ios::binary);
        if(!in.is_open()){
            return false;
        }

        in.seekg(0, std::ios::end);
        data.resize(in.tellg());
        in.seekg(0, std::ios::beg);

        in.read((char*)&data[0], data.size());

        return true;
    }

    static bool write_binary(const std::string& file_path, const std::vector<uint8_t>& data, bool flush = true){
        std::ofstream out(file_path, std::ios::out | std::ios::binary);
        if(!out.is_open()){
            return false;
        }

        out.write((char*)&data[0], data.size());

        return true;
    }
};
