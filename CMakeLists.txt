# (C) 2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
cmake_minimum_required(VERSION 3.9.4)

project(badtun VERSION 0.5)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_BUILD_TYPE RelWithDebInfo)
#set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVERSION=\"\\\"0.1\\\"\"")

add_compile_options(-Wall -pedantic)

add_executable(badtun
	log.cpp
	main.cpp
	net.cpp
	time.cpp
)

include(FindPkgConfig)

pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
target_link_libraries(badtun ${LIBCRYPTO_LIBRARIES})
target_include_directories(badtun PUBLIC ${LIBCRYPTO_INCLUDE_DIRS})
target_compile_options(badtun PUBLIC ${LIBCRYPTO_CFLAGS_OTHER})
