# - Try to find mysqlpp
# Once done this will define
#
#  CRYPTOPP_FOUND - system has cryptopp
#  CRYPTOPP_INCLUDE_DIR - the cryptopp include directory

# Be quiet if cryptopp was already found
IF (cryptopp_INCLUDE_DIR AND cryptopp_LIBRARY)
    SET(cryptopp_QUIET TRUE)
ENDIF (cryptopp_INCLUDE_DIR AND cryptopp_LIBRARY)


FIND_PATH(cryptopp_INCLUDE_DIR
    NAMES cryptlib.h
    PATH_SUFFIXES crypto++
    )

FIND_LIBRARY(cryptopp_LIBRARY
    NAMES crypto++
    PATHS /usr/lib /usr/local/lib
    )

MARK_AS_ADVANCED(cryptopp_INCLUDE_DIR cryptopp_LIBRARY)


IF (cryptopp_INCLUDE_DIR AND cryptopp_LIBRARY)
    SET(CRYPTOPP_FOUND TRUE)
    SET(CRYPTOPP_INCLUDE_DIR ${cryptopp_INCLUDE_DIR})
    SET(CRYPTOPP_LIBRARIES ${cryptopp_LIBRARY})

    IF (NOT cryptopp_FIND_QUIETLY AND NOT cryptopp_QUIET)
        MESSAGE(STATUS "Found cryptopp: ${cryptopp_LIBRARY}")
    ENDIF (NOT cryptopp_FIND_QUIETLY AND NOT cryptopp_QUIET)
ENDIF (cryptopp_INCLUDE_DIR AND cryptopp_LIBRARY)

# Bail out if cryptopp is not found but required
IF (NOT CRYPTOPP_FOUND AND cryptopp_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could NOT find cryptopp library ${CRYPTOPP_INCLUDE_DIR}")
ENDIF (NOT CRYPTOPP_FOUND AND cryptopp_FIND_REQUIRED)
