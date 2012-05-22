# - Try to find mysqlpp
# Once done this will define
#
#  LLVM_FOUND - system has llvm
#  LLVM_INCLUDE_DIR - the llvm include directory

SET (LLVM_VER 2.9)


# Be quiet if llvm was already found
IF (llvm_INCLUDE_DIR AND llvm_LIBRARY)
    SET(llvm_QUIET TRUE)
ENDIF (llvm_INCLUDE_DIR AND llvm_LIBRARY)


FIND_PATH(llvm_INCLUDE_DIR
    NAMES LLVMContext.h
    PATH_SUFFIXES llvm
    )

FIND_LIBRARY(llvm_LIBRARY
    NAMES LLVM-${LLVM_VER}
    PATHS /usr/lib /usr/local/lib
    PATH_SUFFIXES llvm
    )

MARK_AS_ADVANCED(llvm_INCLUDE_DIR llvm_LIBRARY)


IF (llvm_INCLUDE_DIR AND llvm_LIBRARY)
    SET(LLVM_FOUND TRUE)
    SET(LLVM_INCLUDE_DIR ${llvm_INCLUDE_DIR})
    SET(LLVM_LIBRARIES ${llvm_LIBRARY})

    IF (NOT llvm_FIND_QUIETLY AND NOT llvm_QUIET)
        MESSAGE(STATUS "Found llvm: ${llvm_LIBRARY}")
    ENDIF (NOT llvm_FIND_QUIETLY AND NOT llvm_QUIET)
ENDIF (llvm_INCLUDE_DIR AND llvm_LIBRARY)

# Bail out if llvm is not found but required
IF (NOT LLVM_FOUND AND llvm_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could NOT find llvm library ${LLVM_INCLUDE_DIR}")
ENDIF (NOT LLVM_FOUND AND llvm_FIND_REQUIRED)
