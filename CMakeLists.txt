cmake_minimum_required(VERSION 3.8)
project(cpp_rest_sdk)

# set default cmake build type  (None Debug Release RelWithDebInfo MinSizeRel)
IF( NOT CMAKE_BUILD_TYPE )
	SET( CMAKE_BUILD_TYPE "RelWithDebInfo" )
ENDIF()
message(STATUS "Current build type is : ${CMAKE_BUILD_TYPE}")

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSION OFF)

# Boost
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.67.0 REQUIRED COMPONENTS system)

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

# OpenSSL
find_package(OpenSSL REQUIRED)

include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

add_executable(cpp_rest_sdk main.cpp)
target_link_libraries(cpp_rest_sdk ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})

ENABLE_TESTING()
