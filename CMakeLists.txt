# CMakeLists.txt
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(licensepp-openssl LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}" ${CMAKE_MODULE_PATH})

find_package(Boost REQUIRED COMPONENTS system thread)
set(LIB ${LIB} ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY})

# OpenSSL
find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(LIB ${LIB} OpenSSL::Crypto)

# Licensepp
set(LIB ${LIB} OpenSSL::Crypto liblicensepp.so.1.0.6)

# add Source
set(SRC ${SRC} license-manager.cpp)

add_executable(${PROJECT_NAME} main.cpp)
target_sources(${PROJECT_NAME} PRIVATE ${SRC})

# include_directories(${INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIB})
