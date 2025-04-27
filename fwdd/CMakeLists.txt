cmake_minimum_required(VERSION 3.22.1)
project(fwdd)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2 -march=native -ffast-math")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

if(DPDK_FOUND)
    include_directories(${DPDK_INCLUDE_DIRS})
    link_directories(${DPDK_LIBRARY_DIRS})
    add_definitions(${DPDK_CFLAGS_OTHER})
else()
    message(FATAL_ERROR "DPDK not found")
endif()

aux_source_directory(. SOURCES)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DPDK_LIBRARIES})

set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/output")
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR}/lib
)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/fwdd.service DESTINATION ${OUTPUT_DIR}/conf)