#include <crypto++/sha.h>
#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " " << "<filename>" << std::endl;
        return -1;
    }

    using namespace CryptoPP;

    byte obuf[SHA256::DIGESTSIZE];
    try
    {
        SHA256 hash;

        static const size_t SZ = 1024;
        byte buf[SZ];
        std::ifstream file(argv[1], std::ios::in | std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Can't open file: " << argv[1] << std::endl;
            return -2;
        }

        while (file.read(reinterpret_cast<char*>(buf), SZ))
            hash.Update(buf, file.gcount());

        if (!file.eof() && file.fail())
        {
            std::cerr << "Unexpected error" << std::endl;
            return -3;
        }

        hash.Final(obuf);
    }
    catch (const Exception& ex)
    {
        std::cerr << "Unexpected openssl exception: " << ex.what() << std::endl;
        return -4;
    }

    for (auto i: obuf)
        std::cout << std::hex << static_cast<int>(i) << " ";
    std::cout << std::endl;
    return 0;
}
