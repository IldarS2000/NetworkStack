cmake_minimum_required(VERSION 3.15)
project(fwdd)

find_package(DPDK REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2 -march=native")

include_directories(${DPDK_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} ${DPDK_LIBRARIES})

set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/output")
file(MAKE_DIRECTORY "${OUTPUT_DIR}")  # Create the directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)