cmake_minimum_required(VERSION 3.2.3)
project(cpp_v3)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -std=c++11")

include_directories(./include)
set(HEADER_FILES include/xt_util.h include/xt_detector.h include/xt_node.h
        include/xt_record.h include/xt_log.h include/xt_file.h include/xt_flag.h)
aux_source_directory(./src SOURCE_FILES)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

## boost
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED OFF)
set(Boost_USE_STATIC_RUNTIME OFF)
set(Boost_USE_DEBUG_RUNTIME ON)
find_package(Boost 1.55.0 COMPONENTS program_options REQUIRED)
if(Boost_FOUND)
    message(STATUS "Boost_LIBRARIES:${Boost_LIBRARIES}")
    include_directories( ${Boost_INCLUDE_DIRS} )
    add_executable(detector ${SOURCE_FILES} ${HEADER_FILES})
    target_link_libraries(detector ${Boost_LIBRARIES} )
endif()