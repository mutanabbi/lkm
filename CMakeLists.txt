cmake_minimum_required(VERSION 2.6)
project(sentry-module C CXX)

# Dependencies
find_package(Threads REQUIRED)
find_package (
    Boost REQUIRED
    COMPONENTS system
)

if (NOT Boost_FOUND)
  message (FATAL_ERROR "Required Boost libraries not found. Please get a copy from http://www.boost.org")
endif ()

# Necessary variables and system info
set(CMAKE_CXX_FLAGS "-pipe --std=c++11 -pthread ${CMAKE_CXX_FLAGS}")
execute_process(COMMAND uname -r OUTPUT_VARIABLE KVERSION RESULT_VARIABLE RET OUTPUT_STRIP_TRAILING_WHITESPACE)
if (${RET})
    message(FATAL_ERROR "Can't perform `uname -r' command")
endif ()

# Build module
set(SENTRY_SOURCE_FILES sentry.c)
add_custom_target(
    module ALL
    ${CMAKE_MAKE_PROGRAM} -C /lib/modules/${KVERSION}/build M=${CMAKE_BINARY_DIR} modules
    DEPENDS Kbuild.in
    SOURCES ${SENTRY_SOURCE_FILES}
)
configure_file(Kbuild.in ${CMAKE_BINARY_DIR}/Kbuild)
foreach(NAME ${SENTRY_SOURCE_FILES})
    configure_file(${NAME} ${CMAKE_BINARY_DIR}/${NAME} COPY_ONLY)
endforeach()

# Build application
include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})
include_directories(${Boost_INCLUDE_DIRS})

add_executable(daemon daemon.cpp)
target_link_libraries(daemon ${Boost_SYSTEM_LIBRARY})
# Supress wrong format string warning (I use boost::format notation)
set_target_properties(daemon PROPERTIES COMPILE_FLAGS "-Wno-format-security")

# Build test apps if necessary
if (TESTS)
    add_subdirectory(tests)
endif()

# Clean targets
add_custom_target(
    clean-module
    ${CMAKE_MAKE_PROGRAM} -C /lib/modules/${KVERSION}/build M=${CMAKE_BINARY_DIR} clean
)
set_property(
    DIRECTORY ${CMAKE_SOURCE_DIR}
    PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${ADDITIONAL_MAKE_CLEAN_FILE} ${CMAKE_BINARY_DIR}/Kbuild
)
add_custom_target(
    clean-all
    ${CMAKE_MAKE_PROGRAM} clean-module
    ${CMAKE_MAKE_PROGRAM} clean
)

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

