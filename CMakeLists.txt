cmake_minimum_required(VERSION 2.6)
cmake_policy(SET CMP0048 NEW)
project(
    sentry-module
    VERSION 0.0.1
    LANGUAGES C CXX
)

execute_process(COMMAND uname -r OUTPUT_VARIABLE KVERSION RESULT_VARIABLE RET OUTPUT_STRIP_TRAILING_WHITESPACE)
if (${RET})
    message(FATAL_ERROR "Can't perform `uname -r' command")
endif ()

configure_file(Kbuild.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild)
add_custom_target(
    module ALL
    ${CMAKE_MAKE_PROGRAM} -C /lib/modules/${KVERSION}/build M=${CMAKE_CURRENT_SOURCE_DIR} modules
    DEPENDS Kbuild.in
    SOURCES sentry.c
)

add_custom_target(
    clean-module
    ${CMAKE_MAKE_PROGRAM} -C /lib/modules/${KVERSION}/build M=${CMAKE_CURRENT_SOURCE_DIR} clean
    DEPENDS Kbuild.in
    SOURCES sentry.c
)

find_package (
    Boost REQUIRED
    COMPONENTS system
)

if (NOT Boost_FOUND)
  message (FATAL_ERROR "Required Boost libraries not found. Please get a copy from http://www.boost.org")
endif ()

set(CMAKE_CXX_FLAGS "-pipe --std=c++11 -pthread ${CMAKE_CXX_FLAGS}")

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})
include_directories(${Boost_INCLUDE_DIRS})

add_executable(daemon daemon.cpp)
target_link_libraries(daemon ${Boost_SYSTEM_LIBRARY})

#foreach(NAME daemon)
#    get_target_property(TEMP ${NAME} COMPILE_FLAGS)
#    if(TEMP STREQUAL "TEMP-NOTFOUND")
#        SET(TEMP "") # set to empty string
#    else()
#        SET(TEMP "${TEMP} ") # a space to cleanly separate from existing content
#    endif()
#    # append our values
#    SET(TEMP "${TEMP}${GCC_COVERAGE_COMPILE_FLAGS}" )
#    set_target_properties(${NAME} PROPERTIES COMPILE_FLAGS ${TEMP} )
#endforeach(NAME)

