cmake_minimum_required(VERSION 3.14)
project(peks_ndn VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(MCL_LIB    mcl   PATHS /usr/local/lib REQUIRED)
find_path(MCL_INCLUDE   mcl/bls12_381.hpp PATHS /usr/local/include REQUIRED)
find_library(GMP_LIB    gmp   REQUIRED)
find_library(GMPXX_LIB  gmpxx REQUIRED)
find_package(OpenSSL REQUIRED)

# ── libpeks (static) ────────────────────────────────────────────
add_library(peks STATIC ate_pairing.cpp peks.cpp)
target_include_directories(peks PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/peks>
    ${MCL_INCLUDE}
)
target_link_libraries(peks PUBLIC ${MCL_LIB} ${GMP_LIB} ${GMPXX_LIB} rt OpenSSL::Crypto)

install(TARGETS peks DESTINATION lib)
install(FILES ate_pairing.hpp peks.hpp DESTINATION include/peks)

# ── standalone tests ────────────────────────────────────────────
add_executable(ate_pairing_test ate_pairing_test.cpp)
target_link_libraries(ate_pairing_test peks)

add_executable(peks_test peks_test.cpp)

# ── PEKS-NDN standalone simulation (no ndn-cxx needed) ──────────
add_executable(sim_peks_ndn sim_peks_ndn.cpp)
target_link_libraries(sim_peks_ndn peks)
target_link_libraries(peks_test peks)

# ── NDN integration (optional — requires ndn-cxx via pkg-config) ─
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(NDN_CXX libndn-cxx QUIET)
    if(NDN_CXX_FOUND)
        message(STATUS "ndn-cxx found — building NDN integration")
        add_subdirectory(ndn)
    else()
        message(STATUS "ndn-cxx not found — skipping NDN integration")
    endif()
endif()
