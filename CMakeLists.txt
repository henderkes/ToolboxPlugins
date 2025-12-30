cmake_minimum_required(VERSION 3.16)

set(CMAKE_GENERATOR_PLATFORM win32)

project(tb_plugins)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT(CMAKE_SIZEOF_VOID_P EQUAL 4))
    message(FATAL_ERROR "You are configuring a non 32-bit build, this is not supported. Run cmake with `-A Win32`")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/")

add_compile_options(/MP /permissive-)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_path(SIMPLEINI_INCLUDE_DIRS "ConvertUTF.c")
find_package(unofficial-uwebsockets CONFIG REQUIRED)
find_package(wolfssl CONFIG REQUIRED)
find_package(minhook CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(ctre CONFIG REQUIRED)
find_package(directxtex CONFIG REQUIRED)

include(gwtoolboxpp)

MACRO(SUBDIRLIST result curdir)
  FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
  SET(dirlist "")
  FOREACH(child ${children})
    IF(IS_DIRECTORY ${curdir}/${child})
      LIST(APPEND dirlist ${child})
    ENDIF()
  ENDFOREACH()
  SET(${result} ${dirlist})
ENDMACRO()
SUBDIRLIST(SUBDIRS ${PROJECT_SOURCE_DIR}/plugins)

FOREACH(subdir ${SUBDIRS})
	add_library(${subdir} SHARED)

	file(GLOB SOURCES
		"plugins/${subdir}/*.h"
		"plugins/${subdir}/*.cpp"
		${gwtoolboxpp_SOURCE_DIR}/plugins/Base/*.h
		${gwtoolboxpp_SOURCE_DIR}/plugins/Base/*.cpp
		)

	target_include_directories(${subdir} PRIVATE
		${gwtoolboxpp_SOURCE_DIR}/plugins/Base
		${gwtoolboxpp_SOURCE_DIR}/GWToolboxdll
		)
	target_link_libraries(${subdir} PRIVATE
		RestClient
		imgui
		directxtex
		gwca
		earcut
		easywsclient
		discord_game_sdk
		nlohmann_json::nlohmann_json
		wolfssl::wolfssl
	    minhook::minhook
	    ctre::ctre
		simpleini
		imgui::fonts
		IconFontCppHeaders
		nativefiledialog
		wintoast
		)
	target_link_options(${subdir} PRIVATE
		"$<$<CONFIG:DEBUG>:/NODEFAULTLIB:LIBCMT>"
		)
	source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCES})
	target_sources(${subdir} PRIVATE ${SOURCES})
	target_compile_definitions(${subdir} PRIVATE
		"NOMINMAX"
		"_WIN32_WINNT=_WIN32_WINNT_WIN7"
		"WIN32_LEAN_AND_MEAN"
		"VC_EXTRALEAN"
		"BUILD_DLL"
		)
	
	set_target_properties(${subdir} PROPERTIES FOLDER "plugins")
ENDFOREACH()
