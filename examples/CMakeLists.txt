# Copyright (c) 2006, 2017, Oracle and/or its affiliates.
# Copyright (c) 2008, 2018, MariaDB Corporation
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

PROJECT(OpenSSL)

PROJECT(UCM63XX_CGI)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.2 FATAL_ERROR)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set(CMAKE_BUILD_TYPE "Debug")

SET(INCLUDE_PATH ${PROJECT_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES(${INCLUDE_PATH})

SET(SOURCE_PATH ${PROJECT_SOURCE_DIR}/src)

SET(OPENSSL_CLIENT_CA_PATH ${CMAKE_INSTALL_PREFIX}/keys/client)
SET(OPENSSL_SERVER_CA_PATH ${CMAKE_INSTALL_PREFIX}/keys/server)

configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/config.h"
  )

IF(SSL_PATH)
    SET(SSL_INCLUDES "${SSL_PATH}/include")
    SET(SSL_LIB_DIR "${SSL_PATH}/lib")
    SET(SSL_FLAGS "-L${SSL_LIB_DIR}")

    IF(NOT SSL_LINK_DYNAMIC AND EXISTS "${SSL_LIB_DIR}/libssl.so")
        SET(SSL_LIBRARY "${SSL_LIB_DIR}/libssl.so")
    ENDIF(NOT SSL_LINK_DYNAMIC AND EXISTS "${SSL_LIB_DIR}/libssl.so")
ELSE(SSL_PATH)
    INCLUDE (CheckIncludeFiles)
    CHECK_INCLUDE_FILES(openssl/ssl.h HAVE_SSL_H)

    IF(NOT HAVE_SSL_H)
        MESSAGE(FATAL_ERROR "openssl/ssl.h could not be found")
    ENDIF(NOT HAVE_SSL_H)

    INCLUDE (CheckLibraryExists)
    CHECK_LIBRARY_EXISTS(ssl SSL_state "" HAVE_SSL_LIB)

    IF(NOT HAVE_SSL_LIB)
        MESSAGE(FATAL_ERROR "ssl lib could not be found")
    ELSE(HAVE_SSL_LIB)
        SET(SSL_LIBRARY "ssl")
    ENDIF(NOT HAVE_SSL_LIB)
ENDIF(SSL_PATH)

IF(CRYPTO_PATH)
    SET(CRYPTO_INCLUDES "${CRYPTO_PATH}/include")
    SET(CRYPTO_LIB_DIR "${CRYPTO_PATH}/lib")
    SET(CRYPTO_FLAGS "-L${CRYPTO_LIB_DIR}")

    IF(NOT SSL_LINK_DYNAMIC AND EXISTS "${SSL_LIB_DIR}/libcrypto.so")
        SET(CRYPTO_LIBRARY "${CRYPTO_LIB_DIR}/libcrypto.so")
    ENDIF(NOT CRYPTO_LINK_DYNAMIC AND EXISTS "${SSL_LIB_DIR}/libcrypto.so")
ELSE(CRYPTO_PATH)
    INCLUDE (CheckIncludeFiles)
    CHECK_INCLUDE_FILES(openssl/modes.h HAVE_CRYPTO_H)

    IF(NOT HAVE_CRYPTO_H)
        MESSAGE(FATAL_ERROR "openssl/modes.h could not be found")
    ENDIF(NOT HAVE_CRYPTO_H)

    INCLUDE (CheckLibraryExists)
    CHECK_LIBRARY_EXISTS(crypto CRYPTO_ctr128_encrypt_ctr32 "" HAVE_CRYPTO_LIB)

    IF(NOT HAVE_CRYPTO_LIB)
        MESSAGE(FATAL_ERROR "crypto lib could not be found")
    ELSE(HAVE_CRYPTO_LIB)
        SET(CRYPTO_LIBRARY crypto)
    ENDIF(NOT HAVE_CRYPTO_LIB)
ENDIF(CRYPTO_PATH)

ADD_DEFINITIONS(
    -g
)

ADD_EXECUTABLE(openssl_v23_server
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_v23_server.c)

TARGET_LINK_LIBRARIES(openssl_v23_server
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

ADD_EXECUTABLE(openssl_v23_client
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_v23_client.c)

TARGET_LINK_LIBRARIES(openssl_v23_client
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

ADD_EXECUTABLE(openssl_dtls_server
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_dtls_server.c)

TARGET_LINK_LIBRARIES(openssl_dtls_server
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

ADD_EXECUTABLE(openssl_dtls_client
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_dtls_client.c)

TARGET_LINK_LIBRARIES(openssl_dtls_client
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

ADD_EXECUTABLE(openssl_dtls_client2
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_dtls_client2.c)

TARGET_LINK_LIBRARIES(openssl_dtls_client2
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

ADD_EXECUTABLE(openssl_dtls_server2
    ${SOURCE_PATH}/openssl.c
    ${SOURCE_PATH}/inet_sock.c
    ${SOURCE_PATH}/openssl_dtls_server2.c)

TARGET_LINK_LIBRARIES(openssl_dtls_server2
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
)

INSTALL(PROGRAMS
    ${CMAKE_BINARY_DIR}/openssl_v23_server
    ${CMAKE_BINARY_DIR}/openssl_v23_client
    ${CMAKE_BINARY_DIR}/openssl_dtls_server
    ${CMAKE_BINARY_DIR}/openssl_dtls_server2
    ${CMAKE_BINARY_DIR}/openssl_dtls_client
    ${CMAKE_BINARY_DIR}/openssl_dtls_client2
    DESTINATION
    ${CMAKE_INSTALL_PREFIX}/sbin)

INSTALL(FILES
    ${CMAKE_BINARY_DIR}/../keys/client/ClientCAcert.pem
    ${CMAKE_BINARY_DIR}/../keys/client/ClientPrivkey.pem
    DESTINATION
    ${CMAKE_INSTALL_PREFIX}/keys/client)

INSTALL(FILES
    ${CMAKE_BINARY_DIR}/../keys/server/ServerCAcert.pem
    ${CMAKE_BINARY_DIR}/../keys/server/ServerPrivkey.pem
    DESTINATION
    ${CMAKE_INSTALL_PREFIX}/keys/server)