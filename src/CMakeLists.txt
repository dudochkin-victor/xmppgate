FIND_PACKAGE(MySQL REQUIRED)
FIND_PACKAGE(CRYPTOPP REQUIRED)
FIND_PACKAGE(MYSQLPP REQUIRED)
FIND_PACKAGE(LibXml2 REQUIRED)
FIND_PACKAGE(LibEvent REQUIRED)
FIND_PACKAGE( Boost 1.36.0 COMPONENTS regex )

ADD_SUBDIRECTORY(service)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/game/include
    ${CMAKE_CURRENT_SOURCE_DIR}/engine/include
    ${CMAKE_CURRENT_SOURCE_DIR}/math/include
    ${MYSQL_INCLUDE_DIR}
    ${MYSQLPP_INCLUDE_DIR}
    ${LIBXML2_INCLUDE_DIR}
    )

SET (PROGRAMS jazzd)

SET(JAZZ_SRCS
    AppSurfing.cpp
    debug.cpp
    jazz.cpp
    Response.cpp
    Session.cpp
    Url.cpp
    User.cpp
    Variant.cpp
    )

#set (INTERNAL_LIBRARIES ${INTERNAL_LIBRARIES}
#    crgame
#    crengine
#    crmath
#    )

SET(JAZZ_HEADERS
    include/AppSurfing.h
    include/debug.h
    include/Response.h
    include/Session.h
    include/Url.h
    include/User.h
    include/Variant.h
    )
ADD_EXECUTABLE(jazzd ${JAZZ_SRCS} ${JAZZ_HEADERS})

TARGET_LINK_LIBRARIES(jazzd
    ${INTERNAL_LIBRARIES}
    ${MYSQL_LIBRARIES}
    ${MYSQLPP_LIBRARIES}
    ${CRYPTOPP_LIBRARIES}
    ${LIBEVENT_LIBRARIES}
    ${LIBXML2_LIBRARIES}
    ${LIBINTL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${EXTRA_LIBRARIES})

INSTALL(TARGETS jazzd RUNTIME DESTINATION ${PKG_BINDIR})
INSTALL(FILES ${JAZZ_HEADERS} DESTINATION include)

