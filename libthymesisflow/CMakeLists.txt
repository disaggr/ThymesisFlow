cmake_minimum_required(VERSION 3.3.0)
set(CMAKE_CXX_STANDARD 11)

option(MOCK "mock thymesisflow backend" OFF)

project(libthymesisflow)
add_library(libthymesisflow
	src/agent.c
	src/client.c
	src/connection.c
	src/iport.c
	src/proto.c
	src/stats.c
	src/thymesisflow.c)

add_executable(thymesisf-agent cmd/thymesisf-agent.c)
add_executable(thymesisf-cli cmd/thymesisf-cli.c)
add_executable(unittest unittest/unittest.c)

include_directories(include)

target_link_libraries(libthymesisflow -locxl -lpthread)
target_link_libraries(thymesisf-agent libthymesisflow)
target_link_libraries(thymesisf-cli libthymesisflow)
target_link_libraries(unittest libthymesisflow)

if (MOCK)
	add_compile_definitions(MOCK=1)
endif()

enable_testing()
add_test(unittest unittest)
