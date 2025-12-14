cmake_minimum_required(VERSION 3.20)
project(vgbd_unpack_decode LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(vgbd_unpack_decode vgbd_unpack_decode.cpp)

# Prefer CONFIG package from vcpkg (zstd), fall back to FindZSTD if present.
find_package(zstd CONFIG QUIET)

if (TARGET zstd::libzstd_static)
    target_link_libraries(vgbd_unpack_decode PRIVATE zstd::libzstd_static)
elseif (TARGET zstd::libzstd_shared)
    target_link_libraries(vgbd_unpack_decode PRIVATE zstd::libzstd_shared)
else()
    find_package(ZSTD REQUIRED)
    target_link_libraries(vgbd_unpack_decode PRIVATE ZSTD::ZSTD)
endif()
