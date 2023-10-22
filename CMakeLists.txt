cmake_minimum_required(VERSION 3.24)
project(pydocstring)

set(CMAKE_CXX_STANDARD 17)

add_executable(pydocstring_test lib_test.cpp library.h)
