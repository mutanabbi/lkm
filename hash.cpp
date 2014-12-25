#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <stdexcept>

namespace sentry {

std::string hash(const std::string& filename)
{
    SHA256_CTX hash;
    std::string obuf(SHA256_DIGEST_LENGTH, '\0');

    if (! SHA256_Init(&hash))
        throw std::runtime_error("Init");

    static const size_t SZ = 1024;
    char buf[SZ];
    std::ifstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Can't open file");


    while (file.read(buf, SZ))
        if (! SHA256_Update(&hash, buf, file.gcount()))
            throw std::runtime_error("Update");

    if (!file.eof() && file.fail())
        throw std::runtime_error("IO error");

    if (! SHA256_Final(reinterpret_cast<unsigned char*>(&obuf[0]), &hash))
        throw std::runtime_error("Finish");

    return obuf;
}

}                                                           // namespace sentry
