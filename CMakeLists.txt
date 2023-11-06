##
## this file can be ignored
##

cmake_minimum_required( VERSION 3.25 )
project( LdrLibraryEx C )

set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )

include_directories( include )

# source code files
set( SOURCE
    src/LdrLibraryEx.c

    tests/TestCryptsp.c
    tests/TestCryptspEx.c
    tests/TestRundll32Exe.c
    tests/TestCryptspMemory.c
    tests/TestApiSet.c
)

add_compile_definitions( LIBRARYEX_TEST )

add_executable( LdrLibraryEx ${SOURCE} )
