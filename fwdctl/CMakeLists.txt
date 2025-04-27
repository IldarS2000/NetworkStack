cmake_minimum_required(VERSION 3.22.1)
project(fwdctl)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2 -march=native -ffast-math")

aux_source_directory(. SOURCES)
add_executable(${PROJECT_NAME} ${SOURCES})

set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/output")
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR}/lib
)
