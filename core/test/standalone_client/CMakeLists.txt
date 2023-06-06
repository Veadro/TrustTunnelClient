cmake_minimum_required(VERSION 3.1)
project(core C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(VPN_CORE_DIR ${VPN_LIB_DIR}/core)

if (MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Zi /EHs-c- /W0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi /EHs-c- /std:c++latest /W0")
endif (MSVC)

include(${VPN_LIB_DIR}/cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT "${VPN_LIB_DIR}" CONANFILE "${VPN_LIB_DIR}/conanfile.py" SCOPE_NAME agvpn)

set(SOURCE_FILES
        config.cpp
        standalone_client.cpp
        )

add_executable(standalone_client EXCLUDE_FROM_ALL ${SOURCE_FILES})

if (NOT MSVC)
    target_compile_options(standalone_client PRIVATE "-fno-exceptions")
endif (NOT MSVC)

target_compile_definitions(standalone_client PRIVATE TOML_EXCEPTIONS=0)
target_compile_definitions(standalone_client PRIVATE _HAS_EXCEPTIONS=0)
target_compile_definitions(standalone_client PRIVATE CXXOPTS_NO_RTTI)

target_link_libraries(standalone_client vpnlibs_core CONAN_PKG::cxxopts)
target_link_libraries(standalone_client CONAN_PKG::magic_enum)
target_link_libraries(standalone_client CONAN_PKG::native_libs_common)
target_link_libraries(standalone_client CONAN_PKG::tomlplusplus)

configure_file(standalone_client.toml ${CMAKE_CURRENT_BINARY_DIR}/standalone_client.toml COPYONLY)

enable_testing()
add_dependencies(tests standalone_client)
