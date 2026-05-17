find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)

# peks_ndn — serialization bridge used by both producer and consumer
add_library(peks_ndn STATIC peks_name.cpp)
target_include_directories(peks_ndn PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NDN_CXX_INCLUDE_DIRS}
)
target_link_libraries(peks_ndn PUBLIC peks ${NDN_CXX_LIBRARIES})
target_compile_options(peks_ndn PUBLIC ${NDN_CXX_CFLAGS_OTHER})

# Producer application
add_executable(peks_producer producer.cpp)
target_link_libraries(peks_producer peks_ndn)

# Consumer application
add_executable(peks_consumer consumer.cpp)
target_link_libraries(peks_consumer peks_ndn)

install(TARGETS peks_producer peks_consumer DESTINATION bin)
