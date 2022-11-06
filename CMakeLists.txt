cmake_minimum_required(VERSION 3.13)

project(crypto_server)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

option(BAREMETAL "Baremetal build" OFF)

if (BAREMETAL)

else()

add_definitions(-D_STD_LIBC_)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=alignment)
    add_link_options(-fsanitize=address,undefined -fno-sanitize=alignment)
endif()

endif()

add_subdirectory(crypto)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(crypto_server
    crypto_server.c
    )

target_link_libraries(crypto_server
    PRIVATE
    enclave crypto mbedcrypto pthread
    )

target_include_directories(crypto_server
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    )
