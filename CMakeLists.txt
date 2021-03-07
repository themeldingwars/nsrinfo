cmake_minimum_required(VERSION 3.15)

project(nsrinfo)

set(CMAKE_CXX_STANDARD 17)

add_executable(nsrinfo main.cpp)

find_package(zlib)
if (NOT zlib_FOUND)
    message("Fetch zlib content instead...")
    include(FetchContent)
    FetchContent_Declare(
        zlib
        GIT_REPOSITORY "https://github.com/madler/zlib.git"
        GIT_TAG "v1.2.11"
    )
    FetchContent_GetProperties(zlib)
    if (NOT zlib_POPULATED)
        FetchContent_Populate(zlib)
        add_subdirectory(${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})
    endif()
    target_include_directories(nsrinfo PUBLIC ${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})
endif()

# Static Runtime
if(WIN32 AND MSVC AND ${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.15.0")
	set_property(TARGET nsrinfo PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

target_link_libraries(nsrinfo zlibstatic)