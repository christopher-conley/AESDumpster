cmake_minimum_required(VERSION 3.16)
project(AESDumpster CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/AESDumpster/AESDumpster)

add_executable(AESDumpster
  ${SRC_DIR}/AESDumpster/AESDumpster.cpp
  ${SRC_DIR}/KeyTools/KeyDumpster.cpp
  ${SRC_DIR}/OtherTools/OtherTools.cpp
)
