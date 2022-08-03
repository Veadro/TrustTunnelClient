cmake_minimum_required(VERSION 3.1)

project(fflibs C)

set(SOURCES
	ff/FF/data/ffutf8.c
	ff/FF/data/ffparse.c
	ff/FF/data/ffjson.c
	ff/FF/net/ffhttp.c
	ff/FF/net/ffproto.c
	ff/FF/net/ffurl.c
	ff/FF/sys/ffsys.c
	ff/FF/ffarray.c
	ff/FF/ffcrc.c
	ff/FF/ffhashtab.c
	ff/FF/ffrbtree.c
	ff/FF/ffpath.c
	ff/FF/ffstring.c

	ffos/FFOS/ffos.c
)

if(WIN32)
set(SOURCES
	${SOURCES}
	ffos/FFOS/ffwin.c
)
endif()

if(UNIX AND NOT APPLE)
set(SOURCES
	${SOURCES}
	ffos/FFOS/ffunix.c
	ffos/FFOS/ffunix-thd.c
	ffos/FFOS/fflinux.c
)
endif()

if(APPLE)
set(SOURCES
	${SOURCES}
	ffos/FFOS/ffunix.c
	ffos/FFOS/ffunix-thd.c
	ffos/FFOS/ffapple.c
)
endif()

add_library(fflibs_static STATIC EXCLUDE_FROM_ALL ${SOURCES})
set_property(TARGET fflibs_static PROPERTY POSITION_INDEPENDENT_CODE ON)
if(NOT MSVC)
target_compile_options(fflibs_static PRIVATE -Wall -Werror -Wno-missing-field-initializers -Wno-unused-parameter -Wno-deprecated-declarations -Wno-implicit-fallthrough)
endif()
target_include_directories(fflibs_static PUBLIC ./ff)
target_include_directories(fflibs_static PUBLIC ./ffos)

if(WIN32)
target_compile_options(fflibs_static PRIVATE -DFF_WIN=0x0501)
endif()
