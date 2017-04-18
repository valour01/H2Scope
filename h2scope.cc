//
//  http-test.cpp
//  http2-test
//
//  Created by 姜木慧 on 15/12/4.
//  Copyright © 2015年 Tom Hu. All rights reserved.
//

#include "h2scope.hh"
#include "iostream"
#include "fstream"
#include "vector"
#include "map"
#include "mysql.h"
#include <sstream>
using namespace std;

int support_server_push;
int support_http2;
int support_ssl;
vector<data_frame>receive_data_frames;
vector<id_size>receive_headers_frames;
vector<id_size>send_data_frames;
vector<id_size>send_headers_frames;
vector<id_size>receive_push_promises;
vector<window_update>send_window_update;
vector<int>recv_sequence;
vector<int>finish_sequence;
vector<int>priority_sequence;
vector<int>max_concurrent_sequence;
vector<int>rst_sequence;
string recv_go_away;
string recv_go_away_detail;
string fatal;
int server_push_disable_test_made;
int server_push_disable_test_receive_push_promise;
int default_max_concurrent_streams;
int changed_max_concurrent_streams;
int range_stream_id;
int support_range;
//string html;
char * test_uri;
string header_name;
string server;
timeval timeout;
clock_t begTime;
clock_t timespend;

void print_settings_frame(const nghttp2_settings *settings_frame);
void print_rst_stream_frame(const nghttp2_rst_stream *rst_stream_frame);
void print_header(FILE *f, const uint8_t *name, size_t namelen,
                  const uint8_t *value, size_t valuelen);
void print_window_update_frame(const nghttp2_window_update *window_update_frame);
void print_priority_frame(const nghttp2_priority *priority_frame) ;
void print_goaway_frame(const nghttp2_goaway *goaway_frame);
void print_stream_state(nghttp2_stream *stream) ;
void print_push_promise_frame(const nghttp2_push_promise *push_promise_frame);
string print_err_code_string(uint32_t error_code);
void print_headers_frame(const nghttp2_headers *headers_frame);
void print_ping_frame(const nghttp2_ping *ping_frame) ;
int on_begin_frame_callback(nghttp2_session *session,
                            const nghttp2_frame_hd *hd,
                            void *user_data);
void print_result();
void server_push_disable_test();
//struct test_result my_result;
//static FILE* result_fp;
ofstream result_out;
//ofstream html_out;

static char *strcopy(const char *s, size_t len) {
    char *dst;
    dst = (char*)malloc(len + 1);
    memcpy(dst, s, len);
    dst[len] = '\0';
    return dst;
}

string int_to_string(int target){
    stringstream ss;
    ss<<target;
    return ss.str();
}

string char_star_to_string(const char * target)
{
    string s(target);
    return s;
}
/*
 * Prints error message |msg| and exit.
 */

void init_result_parameter(){
    support_server_push=0;
    support_http2=0;
    support_ssl=0;
    receive_data_frames.clear();
    receive_headers_frames.clear();
    receive_push_promises.clear();
    send_headers_frames.clear();
    send_data_frames.clear();
    send_window_update.clear();
    recv_sequence.clear();
    finish_sequence.clear();
    priority_sequence.clear();
    max_concurrent_sequence.clear();
    rst_sequence.clear();
    server_push_disable_test_made=0;
    server_push_disable_test_receive_push_promise=0;
    default_max_concurrent_streams=0;
    changed_max_concurrent_streams=0;
    range_stream_id=0;
    support_range=0;
}

static void die(const char *msg) {
    cout<<"die"<<endl;
    fatal=char_star_to_string(msg);
    fprintf(stderr, "FATAL: %s\n", msg);
    print_result();
    exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and message |msg|
 * and exit.
 */

static void dief(const char *func, const char *msg) {
        cout<<"dief"<<endl;
    fatal=char_star_to_string(func)+":"+char_star_to_string(msg);
    fprintf(stderr, "FATAL: %s: %s\n", func, msg);
    print_result();
    //print_test_result(&my_result);
    exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and error code
 * |error_code| and exit.
 */

static void diec(const char *func, int error_code) {
    fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code,
            nghttp2_strerror(error_code));
    fatal=char_star_to_string(nghttp2_strerror(error_code));
    //print_test_result(&my_result);
    print_result();
     exit(EXIT_FAILURE);
}

/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL *ssl , unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg ) {
    int rv;
    cout<<"select_next_proto_cb=================="<<endl;
    /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
    rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (rv <= 0) {
        die("Server did not advertise HTTP/2 protocol");
    }
    else{
        support_http2=1;
	cout<<"support_http2:"<<support_http2<<endl;
    }
    //my_result.support_http2 = rv;
    return SSL_TLSEXT_ERR_OK;
}

/*
 * Setup SSL/TLS context.
 */
static void init_ssl_ctx(SSL_CTX *ssl_ctx) {
    /* Disable SSLv2 and enable all workarounds for buggy servers */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    /* Set NPN callback */
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static void ssl_handshake(SSL *ssl, int fd) {
    int rv;

    fd_set fdset;
    long arg;
    arg = fcntl(fd, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(fd, F_SETFL, arg);
    socklen_t lon;
    int valopt;
    timeout.tv_sec=5;
    timeout.tv_usec=0;

    if (SSL_set_fd(ssl, fd) == 0) {
        dief("SSL_set_fd", ERR_error_string(ERR_get_error(), NULL));
    }

    ERR_clear_error();

    cout<<"before ssl connectss"<<endl;

    //rv = SSL_connect(ssl);

    rv = SSL_connect(ssl);
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    if(rv<0){
        if(select(fd+1, NULL, &fdset, NULL, &timeout)>0){
                    lon = sizeof(int);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                    if(valopt==0){
                        cout<<"made it"<<endl;
                        arg = fcntl(fd, F_GETFL, NULL);
                        arg &= (~O_NONBLOCK);
                        fcntl(fd, F_SETFL, arg);

        printf("[INFO] SSL/TLS handshake completed\n");
        //result_out<<"ssl/tls:1"<<endl;
        support_ssl=1;
                        return;
                    }
        } 
        else{
            cout<<"timeout"<<endl;
            die("time out\n");
        }
        }  
}

/*
 * Connects to the host |host| and port |port|.  This function returns
 * the file descriptor of the client socket.
 */
static int connect_to(const char *host, uint16_t port) {
    struct addrinfo hints;
    int fd = -1;
    //make_non_block(fd);
    fd_set fdset;
    fd_set err;
    int rv;
    char service[NI_MAXSERV];
    struct addrinfo *res, *rp;
    snprintf(service, sizeof(service), "%u", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(host, service, &hints, &res);
    printf("host:%s\n",host);
    printf("port:%d\n",port);
    cout<<rv<<endl;
    if (rv != 0) {
        cout<<"connect_to"<<endl;
        dief("getaddrinfo", gai_strerror(rv));
    }
    
    for (rp = res; rp; rp = rp->ai_next) {
        //cout<<"debug"<<endl;
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        //make_non_block(fd);
        cout<<"fd"<<fd<<endl;
        if (fd == -1) {
            continue;
        }
        long arg;
        arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);
        socklen_t lon;
        int valopt;
        timeout.tv_sec=5;
        timeout.tv_usec=0;
        
            while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 && errno == EINTR);
        cout<<"rv"<<rv<<endl;
                if (rv == 0) {
                    break;
               }
               cout<<"errno:"<<errno<<endl;
        if (rv < 0) {
            if (errno == EINPROGRESS) {
                cout<<"errno:"<<errno<<endl;
                cout<<"testsss"<<endl;
                timeout.tv_sec = 10;
                timeout.tv_usec = 0;
                FD_ZERO(&fdset);
                FD_SET(fd, &fdset);
                if (select(fd+1, NULL, &fdset, NULL, &timeout) > 0) {
                    lon = sizeof(int);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);

                    if (valopt==0) {
                        
                        arg = fcntl(fd, F_GETFL, NULL);
                        arg &= (~O_NONBLOCK);
                        fcntl(fd, F_SETFL, arg);

                        break;
                    }
                    if (valopt) {
                        //cout<<"tmddddd"<<endl;
                        die("error in connection\n");
                    }
                }
                else {
                        die("time out\n");
                }
            } 
            else { 
                    die("timeout or error\n");
            } 
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);
        close(fd);
        fd = -1;
    }
    
    freeaddrinfo(res);
    return fd;
}

static void make_non_block(int fd) {
    int flags, rv;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1) {
        dief("fcntl", strerror(errno));
    }
    while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (rv == -1) {
        dief("fcntl", strerror(errno));
    }
}

static void set_tcp_nodelay(int fd) {
    int val = 1;
    int rv;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
    if (rv == -1) {
        dief("setsockopt", strerror(errno));
    }
}

/*
 * Update |pollfd| based on the state of |connection|.
 */
static void ctl_poll(struct pollfd *pollfd, struct Connection *connection) {
    pollfd->events = 0;
    if (nghttp2_session_want_read(connection->session) ||
        connection->want_io == WANT_READ) {
        pollfd->events |= POLLIN;
        //cout<<"aaaaaaaaaaaa"<<endl;
    }
    if (nghttp2_session_want_write(connection->session) ||
        connection->want_io == WANT_WRITE) {
        pollfd->events |= POLLOUT;
        //cout<<"bbbbbbbbbbbb"<<endl;
    }
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
 single header name/value pair. */
int on_header_callback(nghttp2_session *session ,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t namelen, const uint8_t *value,
                       size_t valuelen, uint8_t flags ,
                       void *user_data ) {
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                /* Print response headers for the initiated request. */
                print_header(stderr, name, namelen, value, valuelen);
            }
            break;
        case NGHTTP2_PUSH_PROMISE:
            print_header(stderr, name, namelen, value, valuelen);
            break;
    }
    return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
 started to receive header block. */
int on_begin_headers_callback(nghttp2_session *session ,
                              const nghttp2_frame *frame,
                              void *user_data ) {
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                fprintf(stderr, "Response headers for stream ID=%d:\n",
                        frame->hd.stream_id);
            }
            break;
    }
    return 0;
}


/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
ssize_t send_callback(nghttp2_session *session , const uint8_t *data,
                      size_t length, int flags , void *user_data) {
    struct Connection *connection;
    int rv;
    connection = (struct Connection *)user_data;
    connection->want_io = IO_NONE;
    ERR_clear_error();
    rv = SSL_write(connection->ssl, data, (int)length);
    if (rv <= 0) {
        int err = SSL_get_error(connection->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            connection->want_io =
            (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
ssize_t recv_callback(nghttp2_session *session , uint8_t *buf,
                      size_t length, int flags , void *user_data) {
    struct Connection *connection;
    int rv;
    connection = (struct Connection *)user_data;
    connection->want_io = IO_NONE;
    ERR_clear_error();
    rv = SSL_read(connection->ssl, buf, (int)length);
    if (rv < 0) {
        int err = SSL_get_error(connection->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            connection->want_io =
            (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else if (rv == 0) {
        rv = NGHTTP2_ERR_EOF;
    }
    return rv;
}

int on_frame_send_callback(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data ) {
    switch (frame->hd.type) {
        case NGHTTP2_DATA:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (DATA)\n");
            break;
        case NGHTTP2_HEADERS:
            if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
                printf("[INFO] C ----------------------------> S (FRAME SEND) (HEADERS)\n");
                print_headers_frame(&frame->headers);
            }
            break;
        case NGHTTP2_PRIORITY:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (PRIORITY)\n");
            print_priority_frame(&frame->priority);
            break;
        case NGHTTP2_RST_STREAM:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (RST_STREAM)\n");
            print_rst_stream_frame(&frame->rst_stream);
            break;
        case NGHTTP2_SETTINGS:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (SETTINGS)\n");
            print_settings_frame(&frame->settings);
            break;
        case NGHTTP2_PUSH_PROMISE:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (PUSH_PROMISE)\n");
            print_push_promise_frame(&frame->push_promise);
            break;
        case NGHTTP2_PING:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (PING)\n");
            print_ping_frame(&frame->ping);
            break;
        case NGHTTP2_GOAWAY:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (GOAWAY)\n");
            print_goaway_frame(&frame->goaway);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            printf("[INFO] C ----------------------------> S (FRAME SEND) (WINDOW_UPDATE)\n");
            print_window_update_frame(&frame->window_update);
            window_update window_temp;
            window_temp.stream_id=frame->hd.stream_id;
            window_temp.size_increment=(frame->window_update).window_size_increment;
            send_window_update.push_back(window_temp);
            break;
    }
    
    printf("\n=====STREAM STATE (ID: %d)=====\n", frame->hd.stream_id);
    nghttp2_stream *stream = nghttp2_session_find_stream(session, frame->hd.stream_id);
    if (stream) {
        print_stream_state(stream);
    } else {
        printf("(Invalid stream)\n");
    }
    printf("===============================\n");
    
    return 0;
}



int on_frame_recv_callback(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data ) {
    //    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->hd.stream_id, NGHTTP2_CANCEL);
    //    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_CANCEL);
    
    switch (frame->hd.type) {
        case NGHTTP2_DATA:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (DATA)\n");
            printf("[INFO] LENGTH <---------------------------- %zu",frame->hd.length);
            //result_out<<frame->hd.stream_id<<"data_frame"<<frame->hd.length<<endl;
            //printf(frame->data.padlen);
            data_frame data_temp;
            data_temp.stream_id=frame->hd.stream_id;
            data_temp.size = frame->hd.length;
            data_temp.end=frame->data.hd.flags;
            receive_data_frames.push_back(data_temp);
            if(recv_sequence.size()==0)
            {
                recv_sequence.push_back(frame->hd.stream_id);
            }
            else{
                int has_recv=0;
                for(int i=0;i<recv_sequence.size();i++){
                    if(recv_sequence.at(i)==frame->hd.stream_id){
                        has_recv=1;
                    }
                }
                if(has_recv==0){
                    recv_sequence.push_back(frame->hd.stream_id);
                }
                
            }
            if (frame->data.hd.flags==1) {
                finish_sequence.push_back(frame->hd.stream_id);
            }
            
            
            if (frame->hd.stream_id==range_stream_id && frame->hd.length==201 && frame->hd.flags==1) {
                support_range=1;
            }
            break;
        case NGHTTP2_HEADERS: {
            id_size headers_temp;
            headers_temp.stream_id = frame->hd.stream_id;
            headers_temp.size = frame->hd.length;
            receive_headers_frames.push_back(headers_temp);

            struct Request *req = NULL;
            nghttp2_nv *nva = NULL;
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: RESPONSE)\n");
                nva = frame->headers.nva;
                req = (Request*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            } else if (frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
                printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: PUSH_RESPONSE)\n");
                //result_out<<frame->hd.stream_id<<"push_promise"<<frame->hd.length<<endl;
                nva = frame->headers.nva;
                req = (Request*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            } else if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: REQUEST)\n");
                nva = frame->headers.nva;
                req = (Request*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            } else if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
                printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: ???)\n");
                nva = frame->headers.nva;
                req = (Request*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            }
            
            if (req) {
                printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADERS)\n");
                // 'nvlen' is always 0
                // the header name/value pairs are emitted via 'nghttp2_on_header_callback'
            }
        }
            break;
        case NGHTTP2_PRIORITY:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (PRIORITY)\n");
            print_priority_frame(&frame->priority);
            break;
        case NGHTTP2_RST_STREAM:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (RST_STREAM)\n");
            print_rst_stream_frame(&frame->rst_stream);
            rst_sequence.push_back(frame->hd.stream_id);
            break;
        case NGHTTP2_SETTINGS:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (SETTINGS)\n");
            print_settings_frame(&frame->settings);
            break;
        case NGHTTP2_PUSH_PROMISE:
            printf("[INFO] C <--------------------------- S (FRAME RECV) (PUSH_PROMISE)\n");
            support_server_push=1;
            id_size push_temp;
            push_temp.stream_id = frame->push_promise.promised_stream_id;
            push_temp.size = frame->hd.length;
            receive_push_promises.push_back(push_temp);
           /* nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->push_promise.promised_stream_id, NGHTTP2_CANCEL);
            if(server_push_disable_test_made==1)
            {
                server_push_disable_test_receive_push_promise=1;
            }
            server_push_disable_test();*/

            //            nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->push_promise.promised_stream_id, NGHTTP2_CANCEL);
            break;
        case NGHTTP2_PING:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (PING)\n");
            print_ping_frame(&frame->ping);
            break;
        case NGHTTP2_GOAWAY:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (GOAWAY)\n");
            recv_go_away+="LS_ID:"+int_to_string(frame->goaway.last_stream_id)+"|";
            recv_go_away+="EC:"+print_err_code_string(frame->goaway.error_code)+"|";
            recv_go_away_detail.assign((char*)frame->goaway.opaque_data,frame->goaway.opaque_data_len);
            recv_go_away+="Detail:"+recv_go_away_detail+"|";
            print_goaway_frame(&frame->goaway);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (WINDOW_UPDATE)\n");
            print_window_update_frame(&frame->window_update);
            break;
        case NGHTTP2_CONTINUATION:
            printf("[INFO] C <---------------------------- S (FRAME RECV) (CONTINUATION)\n");
            break;
    }
    
    printf("\n=====STREAM STATE (ID: %d)=====\n", frame->hd.stream_id);
    nghttp2_stream *stream = nghttp2_session_find_stream(session, frame->hd.stream_id);
    if (stream) {
        print_stream_state(stream);
    } else {
        printf("(Invalid stream)\n");
    }
    printf("===============================\n");
    
    return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code ,
                             void *user_data ) {
    printf("Stream %d closed\n", stream_id);
    struct Request *req;
    req = (Request *)nghttp2_session_get_stream_user_data(session, stream_id);
    
    printf("\n=====STREAM STATE (ID: %d)=====\n", stream_id);
    nghttp2_stream *stream = nghttp2_session_find_stream(session, stream_id);
    if (stream) {
        print_stream_state(stream);
    } else {
        printf("(Invalid stream)\n");
    }
    printf("===============================\n");
    
    return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
int on_data_chunk_recv_callback(nghttp2_session *session,
                                uint8_t flags , int32_t stream_id,
                                const uint8_t *data, size_t len,
                                void *user_data ) {
    struct Request *req;
    req = (Request*)nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        //printf("[INFO] C <---------------------------- S (DATA chunk)\n"
          //     "%lu bytes\n",
           //    (unsigned long int)len);
        //printf(data);
        //fwrite(data, 1, len, stdout);
        //printf("\n");
    }
    return 0;
}

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks) {
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    
    // 当收到 header 键值对时
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    
    // 开始接受 HEADERS 或 PUSH_PROMISE 帧中的header block时
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    
    // 发送一个frame之后
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    
    // 收到frame时
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    
    // stream关闭时
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    
    // 收到DATA frame中的data chunk时
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    
    // frame header收到的时候
    nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks, on_begin_frame_callback);
}


void print_frame_header(const nghttp2_frame_hd *hd) {
    printf("Frame Header\n");
    printf("Length: %lu\n", hd->length);
    printf("Stream ID: %d\n", hd->stream_id);
    printf("Flags: 0x%02x\n", hd->flags);
    if (hd->flags == NGHTTP2_FLAG_NONE) {
        printf("00000000 NONE (0x0)\n");
    }
    if (hd->flags & 0x01) {
        printf("00000001 ");
        // NGHTTP2_FLAG_END_STREAM or NGHTTP2_FLAG_ACK
        if (hd->type == NGHTTP2_PING || hd->type == NGHTTP2_SETTINGS) {
            printf("ACK");
        } else {
            printf("END_STREAM");
        }
        printf(" (0x1)\n");
    }
    if (hd->flags & NGHTTP2_FLAG_END_HEADERS) {
        printf("00000100 END_HEADERS (0x4)\n");
    }
    if (hd->flags & NGHTTP2_FLAG_PADDED) {
        printf("00001000 PADDED (0x8)\n");
    }
    if (hd->flags & NGHTTP2_FLAG_PRIORITY) {
        printf("00100000 PRIORITY (0x20)\n");
    }
}

void print_settings_frame(const nghttp2_settings *settings_frame) {
    print_frame_header(&settings_frame->hd);
    printf("\n");
    for (int i = 0; i < settings_frame->niv; i++) {
        switch (settings_frame->iv[i].settings_id) {
            case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
                printf("HEADER_TABLE_SIZE");
                break;
            case NGHTTP2_SETTINGS_ENABLE_PUSH:
                printf("ENABLE_PUSH");
                break;
            case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                printf("MAX_CONCURRENT_STREAMS");
                default_max_concurrent_streams=settings_frame->iv[i].value;
                break;
            case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                printf("INITIAL_WINDOW_SIZE");
                break;
            case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
                printf("MAX_FRAME_SIZE");
                break;
            case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                printf("MAX_HEADER_LIST_SIZE");
                break;
            default:
                break;
        }
        printf(": %u\n", settings_frame->iv[i].value);
    }
}

void print_window_update_frame(const nghttp2_window_update *window_update_frame) {
    print_frame_header(&window_update_frame->hd);
    printf("\n");
    printf("Window Size Increment: %d\n", window_update_frame->window_size_increment);
}

void print_ping_frame(const nghttp2_ping *ping_frame) {
    print_frame_header(&ping_frame->hd);
    result_out<<"ping:"<<ping_frame->hd.stream_id<<" "<<"Opaque Data:";
    printf("\n");
    printf("Opaque Data: 0x");
    for (int i = 0; i < 8; i++) {
        printf("%x", ping_frame->opaque_data[i]);
        result_out<<ping_frame->opaque_data[i];
    }
    result_out<<endl;
    printf("\n");
}

void print_headers_frame(const nghttp2_headers *headers_frame) {
    print_frame_header(&headers_frame->hd);
    printf("\n");
    const nghttp2_nv *nva = headers_frame->nva;
    for (int i = 0; i < headers_frame->nvlen; i++) {
        fwrite(nva[i].name, nva[i].namelen, 1, stdout);

        printf(": ");
        fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
        printf("\n");
    }
}

void print_goaway_frame(const nghttp2_goaway *goaway_frame) {
    print_frame_header(&goaway_frame->hd);
    printf("\n");
    printf("Last Stream ID: %d\n", goaway_frame->last_stream_id);
    
    printf("Error Code: ");
    print_err_code_string(goaway_frame->error_code);
    
    printf("Additional Debug Data: ");
    fwrite(goaway_frame->opaque_data, goaway_frame->opaque_data_len, 1, stdout);
    printf("\n");
}

void print_rst_stream_frame(const nghttp2_rst_stream *rst_stream_frame) {
    print_frame_header(&rst_stream_frame->hd);
    printf("\n");
    printf("Error Code: ");
    print_err_code_string(rst_stream_frame->error_code);
}

void print_priority_frame(const nghttp2_priority *priority_frame) {
    print_frame_header(&priority_frame->hd);
    printf("\n");
    
    nghttp2_priority_spec priority_spec = priority_frame->pri_spec;
    printf("Depends on: %d\n", priority_spec.stream_id);
    printf("Weight: %d\n", priority_spec.weight);
    printf("Exclusive: ");
    if (priority_spec.exclusive) {
        printf("True");
    } else {
        printf("False");
    }
    printf("\n");
}

void print_push_promise_frame(const nghttp2_push_promise *push_promise_frame) {
    print_frame_header(&push_promise_frame->hd);
    printf("\n");
    if (push_promise_frame->hd.flags & NGHTTP2_FLAG_PADDED) {
        printf("Pad Length: %lu\n", push_promise_frame->padlen);
    }
    printf("Promised Stream ID: %d\n", push_promise_frame->promised_stream_id);
    printf("Header Block Fragment: \n");
    const nghttp2_nv *nva = push_promise_frame->nva;
    for (int i = 0; i < push_promise_frame->nvlen; i++) {
        fwrite(nva[i].name, nva[i].namelen, 1, stdout);
        printf(": ");
        fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
        printf("\n");
    }
}

void print_stream_state(nghttp2_stream *stream) {
    nghttp2_stream_proto_state stream_state = nghttp2_stream_get_state(stream);
    printf("Stream State: ");
    switch (stream_state) {
        case NGHTTP2_STREAM_STATE_IDLE:
            printf("IDLE");
            break;
        case NGHTTP2_STREAM_STATE_OPEN:
            printf("OPEN");
            break;
        case NGHTTP2_STREAM_STATE_RESERVED_LOCAL:
            printf("RESERVED_LOCAL");
            break;
        case NGHTTP2_STREAM_STATE_RESERVED_REMOTE:
            printf("RESERVED_REMOTE");
            break;
        case NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL:
            printf("HALF_CLOSED_LOCAL");
            break;
        case NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:
            printf("HALF_CLOSED_REMOTE");
            break;
        case NGHTTP2_STREAM_STATE_CLOSED:
            printf("CLOSED");
            break;
        default:
            break;
    }
    printf("\n");
}

/**
 * The error code.  See :type:`nghttp2_error_code`.
 */
string print_err_code_string(uint32_t error_code) {
    switch (error_code) {
        case NGHTTP2_NO_ERROR:
            printf("NO_ERROR");
            return("NO ERROR");
            break;
        case NGHTTP2_PROTOCOL_ERROR:
            printf("PROTOCOL_ERROR");
            return("PROTOCOL_ERROR");
            break;
        case NGHTTP2_INTERNAL_ERROR:
            printf("INTERNAL_ERROR");
            return("INTERNAL_ERROR");
            break;
        case NGHTTP2_FLOW_CONTROL_ERROR:
            printf("FLOW_CONTROL_ERROR");
            return("FLOW_CONTROL_ERROR");
            break;
        case NGHTTP2_SETTINGS_TIMEOUT:
            printf("SETTINGS_TIMEOUT");
            return("SETTINGS_TIMEOUT");
            break;
        case NGHTTP2_STREAM_CLOSED:
            printf("STREAM_CLOSED");
            return("STREAM_CLOSED");
            break;
        case NGHTTP2_FRAME_SIZE_ERROR:
            printf("FRAME_SIZE_ERROR");
            return("FRAME_SIZE_ERROR");
            break;
        case NGHTTP2_REFUSED_STREAM:
            printf("REFUSED_STREAM");
            return("REFUSED_STREAM");
            break;
        case NGHTTP2_CANCEL:
            printf("CANCEL");
            return("CANCEL");
            break;
        case NGHTTP2_COMPRESSION_ERROR:
            printf("COMPRESSION_ERROR");
            return("COMPRESSION_ERROR");
            break;
        case NGHTTP2_CONNECT_ERROR:
            printf("CONNECT_ERROR");
            return("CONNECT_ERROR");
            break;
        case NGHTTP2_ENHANCE_YOUR_CALM:
            printf("ENHANCE_YOUR_CALM");
            return("ENHANCE_YOUR_CALM");
            break;
        case NGHTTP2_INADEQUATE_SECURITY:
            printf("INADEQUATE_SECURITY");
            return("INADEQUATE_SECURITY");
            break;
        case NGHTTP2_HTTP_1_1_REQUIRED:
            printf("HTTP_1_1_REQUIRED");
            return("HTTP_1_1_REQUIRED");
            break;
        default:
            break;
    }
    printf(" (0x%x)\n", error_code);
}

void print_header(FILE *f, const uint8_t *name, size_t namelen,
                  const uint8_t *value, size_t valuelen) {
    fwrite(name, namelen, 1, f);
    //server=strcopy(name,namelen);
    //printf("%s\n",server);
    header_name=string(name,name+namelen);
    if(header_name.compare("server")==0){
        server=string(value,value+valuelen);
    }
    fprintf(f, ":");
    fwrite(value, valuelen, 1, f);
    fprintf(f, "\n");
}


static int submit_request(struct Connection *connection, struct Request *req, const nghttp2_priority_spec *pri_spec) {
    int32_t stream_id;
    /* Make sure that the last item is NULL */

    const nghttp2_nv nva[] = {MAKE_NV(":method", "GET"),
        MAKE_NV_CS(":path", req->path),
        MAKE_NV(":scheme", "https"),
        MAKE_NV_CS(":authority", req->hostport),
        MAKE_NV("accept", "*/*"),
        MAKE_NV("sfadsafasfdas", "sadffffsadfasfsdasf"),
        MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION)};
    


        stream_id = nghttp2_submit_request(connection->session, pri_spec, nva,
                                           sizeof(nva) / sizeof(nva[0]), NULL, req);
    
    if (stream_id < 0) {
        diec("nghttp2_submit_request", stream_id);
    }
    
    req->stream_id = stream_id;
    printf("[INFO] Stream ID = %d\n", stream_id);
    
    printf("\n=====STREAM STATE (ID: %d)=====\n", stream_id);
    nghttp2_stream *stream = nghttp2_session_find_stream(connection->session, stream_id);
    if (stream) {
        print_stream_state(stream);
    } else {
        printf("(Invalid stream)\n");
    }
    printf("===============================\n");
    return stream_id;
}

/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection) {
    int rv;
    //cout<<"before cccccc"<<endl;
    rv = nghttp2_session_recv(connection->session);
    //cout<<"rv:"<<rv<<endl;
    if (rv != 0) {
        diec("nghttp2_session_recv", rv);
    }
    rv = nghttp2_session_send(connection->session);
    if (rv != 0) {
        diec("nghttp2_session_send", rv);
    }
}

static void request_init(struct Request *req, const struct URI *uri) {
    req->host = strcopy(uri->host, uri->hostlen);
    req->port = uri->port;
    req->path = strcopy(uri->path, uri->pathlen);
    req->hostport = strcopy(uri->hostport, uri->hostportlen);
    req->stream_id = -1;
}

static void request_free(struct Request *req) {
    free(req->host);
    free(req->path);
    free(req->hostport);
}



int on_begin_frame_callback(nghttp2_session *session,
                            const nghttp2_frame_hd *hd,
                            void *user_data) {
    switch (hd->type) {
        case NGHTTP2_DATA:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (DATA)\n");
            //my_result.received_data = 1;
            print_frame_header(hd);
            break;
        case NGHTTP2_HEADERS:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (HEADERS)\n");
            print_frame_header(hd);
            break;
        case NGHTTP2_PRIORITY:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PRIORITY)\n");
            break;
        case NGHTTP2_RST_STREAM:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (RST_STREAM)\n");
            break;
        case NGHTTP2_SETTINGS:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (SETTINGS)\n");
            break;
        case NGHTTP2_PUSH_PROMISE:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PUSH_PROMISE)\n");
            //my_result.support_server_push=1;
            break;
        case NGHTTP2_PING:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PING)\n");
            break;
        case NGHTTP2_GOAWAY:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (GOAWAY)\n");
            break;
        case NGHTTP2_WINDOW_UPDATE:
            printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (WINDOW_UPDATE)\n");
            break;
    }
    return 0;
}


nghttp2_session_callbacks *callbacks;
int fd;
SSL_CTX *ssl_ctx;
SSL *ssl;
struct Connection connection;
struct pollfd pollfds[1];
struct Request req;
struct Request req2;
struct Request req3;
struct Request req4;
struct Request req5;
struct Request req6;
/*
 * Fetches the resource denoted by |uri|.
 */
static void basic_test(const struct URI *uri) {

    int rv;
    nfds_t npollfds = 1;

    
    request_init(&req, uri);
    request_init(&req2,uri);
    request_init(&req3,uri);
    request_init(&req4,uri);
    request_init(&req5,uri);
    request_init(&req6,uri);
    
    /* Establish connection and setup SSL */
    fd = connect_to(req.host, req.port);

    if (fd == -1) {
        die("Could not open file descriptor");
    }
    
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    
    if (ssl_ctx == NULL) {
        dief("SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));
    }
    
    init_ssl_ctx(ssl_ctx);

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        dief("SSL_new", ERR_error_string(ERR_get_error(), NULL));
    }
    /* To simplify the program, we perform SSL/TLS handshake in blocking
     I/O. */

    ssl_handshake(ssl, fd);
    
    connection.ssl = ssl;
    connection.want_io = IO_NONE;
    
    /* Here make file descriptor non-block */
    make_non_block(fd);
    set_tcp_nodelay(fd);
    
    
    // Create callbacks
    rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        diec("nghttp2_session_callbacks_new", rv);
    }
    // Setup callbacks
    setup_nghttp2_callbacks(callbacks);
    
    // Create session client and copy(set) callbacks
    //rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);
    
    
    nghttp2_option* my_option;
    nghttp2_option_new(&my_option);
    nghttp2_option_set_no_auto_window_update(my_option,0);
    int succeed=nghttp2_session_client_new2(&connection.session,callbacks,&connection,my_option);
    result_out<<"succeed:"<<succeed<<endl;

    
    // Delete callbacks
    nghttp2_session_callbacks_del(callbacks);
    
    if (rv != 0) {
        diec("nghttp2_session_client_new", rv);
    }
    

    //result_out <<"version:"<<NGHTTP2_VERSION<<endl;
    
    // Submit SETTINGS frame
    nghttp2_settings_entry settings[] = {
        //        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096}, // Default: 4096
           //     {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}, // Default enabled
            //  {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1<<30}, // Default: 65535 (2^16-1)
        //      {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1 << 14)} // Default: 2^14  Range: 2^14 ~ 2^24-1
    };
    rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(settings[0]));
    if (rv != 0) {
        diec("nghttp2_submit_settings", rv);
    }
    //nghttp2_submit_window_update(connection.session, NGHTTP2_FLAG_NONE, 0, 1<<30);
    
    
    
    nghttp2_priority_spec pri_spec1;
    nghttp2_priority_spec pri_spec2;
    nghttp2_priority_spec pri_spec3;
    nghttp2_priority_spec pri_spec4;
    nghttp2_priority_spec pri_spec5;
    nghttp2_priority_spec pri_spec6;


    nghttp2_priority_spec_init(&pri_spec1, 0, 1, 0);
    int stream_id_1=submit_request(&connection, &req, NULL);
/*
    nghttp2_priority_spec_init(&pri_spec2, stream_id_1, 1, 0);
    int stream_id_2=submit_request(&connection, &req2, &pri_spec2);

    nghttp2_priority_spec_init(&pri_spec3,stream_id_1,4,0);
    int stream_id_3= submit_request(&connection, &req3, &pri_spec3);

    nghttp2_priority_spec_init(&pri_spec4,stream_id_3,1,0);
    int stream_id_4= submit_request(&connection, &req4, &pri_spec4);

    nghttp2_priority_spec_init(&pri_spec5,stream_id_3,1,0);
    int stream_id_5= submit_request(&connection, &req5, &pri_spec5);

    nghttp2_priority_spec_init(&pri_spec6,stream_id_4,1,0);
    int stream_id_6= submit_request(&connection, &req6, &pri_spec6);    
  

    nghttp2_priority_spec temp_spec;
    nghttp2_priority_spec_init(&temp_spec, 7, 1, 1);
    nghttp2_submit_priority(connection.session, NGHTTP2_FLAG_NONE, 1, &temp_spec);
*/
    pollfds[0].fd = fd;
    ctl_poll(pollfds, &connection);
    
    /* Event loop */
    while (nghttp2_session_want_read(connection.session) ||
           nghttp2_session_want_write(connection.session)) {
        //if()
        
        int nfds = poll(pollfds, npollfds, 8000);//这里阻塞了
    
        if (nfds == -1) {
            dief("poll", strerror(errno));
        }
        if (pollfds[0].revents & (POLLIN | POLLOUT)) {
            //cout<<"errno:"<<errno<<endl;
            timespend=clock()-begTime;
         if((timespend/CLOCKS_PER_SEC)>100){
        die("time used up\n");
      }
            exec_io(&connection);
        }
        if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
            die("Connection error");
        }
        if(nfds == 0)
        {
            break;
        }
        ctl_poll(pollfds, &connection);
    }
    
    request_free(&req);
    request_free(&req2);
    request_free(&req3);
    request_free(&req4);
    request_free(&req5);
    request_free(&req6);

    

}

void clean_resource(){
    
    nghttp2_session_del(connection.session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    shutdown(fd, SHUT_WR);
    close(fd);
    
}



void server_push_disable_test(){
    //struct Request req;
    //request_init(&req, uri);
    int rv;
    nghttp2_settings_entry settings[] = {
        //        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096}, // Default: 4096
             {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}, // Default enabled
        //      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 49}, // Default: 65535 (2^16-1)
        //      {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1 << 14)} // Default: 2^14  Range: 2^14 ~ 2^24-1
    };
    rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(settings[0]));
    if (rv != 0) {
        diec("nghttp2_submit_settings", rv);
    }
    nghttp2_priority_spec pri_spec1;
    
    //nghttp2_priority_spec_init(&pri_spec1, 5, NGHTTP2_DEFAULT_WEIGHT, 0);
    
    submit_request(&connection, &req, &pri_spec1);
    server_push_disable_test_made=1;

}


static int parse_uri(struct URI *res, const char *uri) {
    /* We only interested in https */
    size_t len, i, offset;
    int ipv6addr = 0;
    memset(res, 0, sizeof(struct URI));
    len = strlen(uri);
    if (len < 9 || memcmp("https://", uri, 8) != 0) {
        return -1;
    }
    offset = 8;
    res->host = res->hostport = &uri[offset];
    res->hostlen = 0;
    if (uri[offset] == '[') {
        /* IPv6 literal address */
        ++offset;
        ++res->host;
        ipv6addr = 1;
        for (i = offset; i < len; ++i) {
            if (uri[i] == ']') {
                res->hostlen = i - offset;
                offset = i + 1;
                break;
            }
        }
    } else {
        const char delims[] = ":/?#";
        for (i = offset; i < len; ++i) {
            if (strchr(delims, uri[i]) != NULL) {
                break;
            }
        }
        res->hostlen = i - offset;
        offset = i;
    }
    if (res->hostlen == 0) {
        return -1;
    }
    /* Assuming https */
    res->port = 443;
    if (offset < len) {
        if (uri[offset] == ':') {
            /* port */
            const char delims[] = "/?#";
            int port = 0;
            ++offset;
            for (i = offset; i < len; ++i) {
                if (strchr(delims, uri[i]) != NULL) {
                    break;
                }
                if ('0' <= uri[i] && uri[i] <= '9') {
                    port *= 10;
                    port += uri[i] - '0';
                    if (port > 65535) {
                        return -1;
                    }
                } else {
                    return -1;
                }
            }
            if (port == 0) {
                return -1;
            }
            offset = i;
            res->port = (uint16_t)port;
        }
    }
    res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
    for (i = offset; i < len; ++i) {
        if (uri[i] == '#') {
            break;
        }
    }
    if (i - offset == 0) {
        res->path = "/";
        res->pathlen = 1;
    } else {
        res->path = &uri[offset];
        res->pathlen = i - offset;
    }
    return 0;
}

void print_result()
{
    result_out<<"support http2:"<<support_http2<<endl;
    result_out<<"support_server_push:"<<support_server_push<<endl;
    result_out<<"support_ssl:"<<support_ssl<<endl;
    for(int i =0;i<receive_headers_frames.size();i++){
        result_out<<"received_headers_frame---stream:"<<receive_headers_frames.at(i).stream_id<<"size:"<<receive_headers_frames.at(i).size<<endl;
    }
    for(int i =0;i<receive_push_promises.size();i++){
        result_out<<"received_push_promise_frame---stream:"<<receive_push_promises.at(i).stream_id<<"size:"<<receive_push_promises.at(i).size<<endl;
    }
    for(int i =0;i<receive_data_frames.size();i++){
        result_out<<"received_data_frame---stream:"<<receive_data_frames.at(i).stream_id<<"size:"<<receive_data_frames.at(i).size<<"end:"<<receive_data_frames.at(i).end<<endl;
    }
    for(int i=0;i<send_window_update.size();i++){
        result_out<<"send_window_update_id:"<<send_window_update.at(i).stream_id<<"size:"<<send_window_update.at(i).size_increment<<endl;
    }
    result_out<<"server_push_disable_test_made:"<<server_push_disable_test_made<<endl;
    result_out<<"server_push_disable_test_receive_push_promise:"<<server_push_disable_test_receive_push_promise<<endl;
    result_out<<"recv sequence:";
    for(int i=0;i<recv_sequence.size();i++){
        result_out<<recv_sequence.at(i)<<" ";
    }
    result_out<<endl;
    result_out<<"finish sequence:";
    for(int i=0;i<finish_sequence.size();i++){
        result_out<<finish_sequence.at(i)<<" ";
    }
    result_out<<endl;
    if(1==2){
    if (recv_sequence.at(0)==priority_sequence.at(0)&&
        (recv_sequence.at(1)==priority_sequence.at(3)||recv_sequence.at(2)==priority_sequence.at(3))&&
        finish_sequence.at(0)==priority_sequence.at(0)&&
        (finish_sequence.at(1)==priority_sequence.at(3)||finish_sequence.at(1)==priority_sequence.at(3))) {
        result_out<<"support priority feature: exclusive"<<endl;
    }
    }
    //result_out<<"default_max_concurrent_streams:"<<default_max_concurrent_streams<<endl;
    //  result_out<<"changed_max_concurrent_streams:"<<changed_max_concurrent_streams<<endl;
    result_out<<"rst sequence:"<<rst_sequence.size()<<endl;
    for(int i=0;i<rst_sequence.size();i++){
        result_out<<rst_sequence.at(i)<<" ";
    }
    result_out<<endl;
    //int default_num_should_be_rst = 204-default_max_concurrent_streams-rst_sequence.size();
    //int changed_num_should_be_rst = 204-changed_max_concurrent_streams-rst_sequence.size();
    //result_out<<"default_those should be rst:"<<default_num_should_be_rst<<endl;
    //result_out<<"changed_those should be rst:"<<changed_num_should_be_rst<<endl;
  
    //result_out<<"server side max concurrent protection okay：";
 
    //if (default_num_should_be_rst<10) {
    //    result_out<<1<<endl;
    //}
    //else{
    //    result_out<<0<<endl;
    //}
    //result_out<<"client can change the max concurrent streams num on the server side：";
    //if (changed_num_should_be_rst<10) {
    //    result_out<<1<<endl;
    //}
    //else{
    //    result_out<<0<<endl;
    //}
    for(int i=0;i<recv_sequence.size();i++)
    {
        if (recv_sequence.at(i)==11 && i <5){
            result_out<<"client can send priority frames to change the recv sequence"<<endl;
        }
    }
    result_out<<"support_range:"<<support_range<<endl;
    result_out<<"goaway:"<<recv_go_away<<endl;
}

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

void print_help()
{
    printf("-t target site.\n");
    printf("-d maximum delay\n");
    printf("-p test priority\n");
    printf("-s enable server push\n");
    printf("-h print the help message\n");
    printf("-h test hpack\n");
}


int main(int argc, char **argv) {
    result_out.open("/tmp/text.txt",ios::out);
    
    init_result_parameter();

    struct URI uri;
    struct sigaction act;
   
    if (argc < 2) {
    die("Specify a https URI");
  }
    
    int rv;
    
    
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, 0);
    
#ifndef OPENSSL_IS_BORINGSSL
    OPENSSL_config(NULL);
#endif /* OPENSSL_IS_BORINGSSL */
    SSL_load_error_strings();
    SSL_library_init();
    test_uri=argv[1];
    rv = parse_uri(&uri, argv[1]);
    //free(inputURI);
    if (rv != 0) {
        die("parse_uri failed");
    }
    basic_test(&uri);
    //server_push_disable_test(&uri);
    print_result();
    clean_resource();
    //test2();
    //print_test_result(&my_result);
    return EXIT_SUCCESS;
}
