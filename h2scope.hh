//
//  http-test.hpp
//  http2-test
//
//  Created by 姜木慧 on 15/12/4.
//  Copyright © 2015年 Tom Hu. All rights reserved.
//

#ifndef http_test_hpp
#define http_test_hpp


#ifdef HAVE_CONFIG_H

#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <string.h>

#include <includes/nghttp2/nghttp2.h>

#include <nghttp2_buf.h>
#include <nghttp2_callbacks.h>
#include <nghttp2_frame.h>
#include <nghttp2_hd.h>
#include <nghttp2_hd_huffman.h>
#include <nghttp2_helper.h>
#include <nghttp2_http.h>
#include <nghttp2_int.h>
#include <nghttp2_map.h>
#include <nghttp2_mem.h>
#include <nghttp2_net.h>
#include <nghttp2_npn.h>
#include <nghttp2_option.h>
#include <nghttp2_outbound_item.h>
#include <nghttp2_pq.h>
#include <nghttp2_priority_spec.h>
#include <nghttp2_queue.h>
#include <nghttp2_session.h>
#include <nghttp2_stream.h>
#include <nghttp2_submit.h>
//int continuation_count=0;
enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(NAME, VALUE)                                                   \
{                                                                            \
(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
NGHTTP2_NV_FLAG_NONE                                                   \
}

#define MAKE_NV_CS(NAME, VALUE)                                                \
{                                                                            \
(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),       \
NGHTTP2_NV_FLAG_NONE                                                   \
}



struct Connection {
    SSL *ssl;
    nghttp2_session *session;
    /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
    int want_io;
};

struct Request {
    char *host;
    /* In this program, path contains query component as well. */
    char *path;
    /* This is the concatenation of host and port with ":" in
     between. */
    char *hostport;
    /* Stream ID for this request. */
    int32_t stream_id;
    uint16_t port;
};

struct test_result{
    int16_t support_http2;
    int16_t received_data;
    int16_t support_server_push;
};

//struct test_result result;

struct URI {
    const char *host;
    /* In this program, path contains query component as well. */
    const char *path;
    size_t pathlen;
    const char *hostport;
    size_t hostlen;
    size_t hostportlen;
    uint16_t port;
};

struct static_resource{
    const char *js_url;
    const char *css_url;
    const char *png_url;
};

struct id_size{
    int stream_id;
    unsigned long size;
};

struct window_update{
    int stream_id;
    int size_increment;
};

struct data_frame{
    int stream_id;
    unsigned long size;
    int end;
};

struct CONFIG{
    char * uri;
    char * ssl_connection;
    int multiplexing;
    char * flow_control;
    char * zero_window_update;
    char * large_window_update;
    int server_push;
    int priority_mechanism;
    int self_dependent;
    int hpack;
    int h2_ping;
    int no_feature;
    int debug;
};


typedef enum {
    MULTIPLEXING=1,
    CONTROL_HEADERS,
    CONTROL_DATA,
    ZERO_WINDOW_UPDATE_STREAM,
    ZERO_WINDOW_UPDATE_CONNECTION,
    LARGE_WINDOW_UPDATE_STREAM,
    LARGE_WINDOW_UPDATE_CONNECTION,
    SERVER_PUSH,
    PRIORITY_MECHANISM,
    SELF_DEPENDENT,
    HPACK,
    H2_PING
}FEATURE;

#endif /* http_test_hpp */
#define MAX_OUTLEN 4096

