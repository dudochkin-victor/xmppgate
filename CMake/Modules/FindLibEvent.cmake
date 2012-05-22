# - Try to find mysqlpp
# Once done this will define
#
#  LIBEVENT_FOUND - system has libevent
#  LIBEVENT_INCLUDE_DIR - the libevent include directory

# Be quiet if libevent was already found
IF (libevent_INCLUDE_DIR AND libevent_LIBRARY)
    SET(libevent_QUIET TRUE)
ENDIF (libevent_INCLUDE_DIR AND libevent_LIBRARY)


FIND_PATH(libevent_INCLUDE_DIR
    NAMES event.h
#    PATH_SUFFIXES crypto++
    )

FIND_LIBRARY(libevent_LIBRARY
    NAMES event
    PATHS /usr/lib /usr/local/lib
    )

MARK_AS_ADVANCED(libevent_INCLUDE_DIR libevent_LIBRARY)


IF (libevent_INCLUDE_DIR AND libevent_LIBRARY)
    SET(LIBEVENT_FOUND TRUE)
    SET(LIBEVENT_INCLUDE_DIR ${libevent_INCLUDE_DIR})
    SET(LIBEVENT_LIBRARIES ${libevent_LIBRARY})

    IF (NOT libevent_FIND_QUIETLY AND NOT libevent_QUIET)
        MESSAGE(STATUS "Found libevent: ${libevent_LIBRARY}")
    ENDIF (NOT libevent_FIND_QUIETLY AND NOT libevent_QUIET)
ENDIF (libevent_INCLUDE_DIR AND libevent_LIBRARY)

# Bail out if libevent is not found but required
IF (NOT LIBEVENT_FOUND AND libevent_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could NOT find libevent library ${LIBEVENT_INCLUDE_DIR}")
ENDIF (NOT LIBEVENT_FOUND AND libevent_FIND_REQUIRED)
