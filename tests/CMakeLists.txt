find_library(CRYPTOPP crypto++ /usr/lib)

add_executable(sha256-crypt sha256-crypt.cpp)
target_link_libraries(sha256-crypt ${CRYPTOPP})

add_executable(sha256-openssl sha256-openssl.cpp)
target_link_libraries(sha256-openssl ${OPENSSL_LIBRARIES})
