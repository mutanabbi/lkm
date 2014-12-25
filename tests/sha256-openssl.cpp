#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " " << "<filename>" << std::endl;
        return -1;
    }

    SHA256_CTX hash;
    unsigned char obuf[SHA256_DIGEST_LENGTH];
    try
    {
        if (! SHA256_Init(&hash))
            throw std::runtime_error("Init");

        static const size_t SZ = 1024;
        char buf[SZ];
        std::ifstream file(argv[1], std::ios::in | std::ios::binary | std::ios::ate);
        file.seekg(0, file.beg);
        if (!file.is_open())
        {
            std::cerr << "Can't open file: " << argv[1] << std::endl;
            return -2;
        }

        while (file.read(buf, SZ))
            if (! SHA256_Update(&hash, buf, file.gcount()))
                throw std::runtime_error("Update");

        if (!file.eof() && file.fail())
        {
            std::cerr << "Unexpected error" << std::endl;
            return -3;
        }

        if (! SHA256_Final(obuf, &hash))
            throw std::runtime_error("Finish");
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << "Unexpected openssl exception: " << ex.what() << std::endl;
        return -4;
    }

    for (auto i: obuf)
        std::cout << std::hex << static_cast<int>(i) << " ";
    std::cout << std::endl;

    return 0;
}
