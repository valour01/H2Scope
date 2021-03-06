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

struct  CONFIG my_config;
FEATURE feature;
nghttp2_priority_spec pri_spec1;
struct Connection connection;
struct Request req;
int hpack_send_num = 0;
int priority_payload_length=0;
int priority_stream_num=0;
int priority_recv_length=0;
int support_server_push;
int support_http2;
int support_ssl;
int support_h2_ping=0;
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
string recv_go_away="";
string recv_go_away_detail;
string fatal;
int default_max_concurrent_streams;
int changed_max_concurrent_streams;
int range_stream_id;
int support_range;
char * test_uri;
string header_name;
string server;
timeval timeout;
clock_t begTime;
clock_t timespend;
struct timeval ping_start;
struct timeval ping_end;


void check_result();
static int submit_request(struct Connection *connection, struct Request *req, const nghttp2_priority_spec *pri_spec);
void print_settings_frame(const nghttp2_settings *settings_frame);
void print_rst_stream_frame(const nghttp2_rst_stream *rst_stream_frame);
void print_header(FILE *f, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
void print_window_update_frame(const nghttp2_window_update *window_update_frame);
void print_priority_frame(const nghttp2_priority *priority_frame) ;
void print_goaway_frame(const nghttp2_goaway *goaway_frame);
void print_stream_state(nghttp2_stream *stream) ;
void print_push_promise_frame(const nghttp2_push_promise *push_promise_frame);
string print_err_code_string(uint32_t error_code);
void print_headers_frame(const nghttp2_headers *headers_frame);
void print_ping_frame(const nghttp2_ping *ping_frame) ;
int on_begin_frame_callback(nghttp2_session *session, const nghttp2_frame_hd *hd, void *user_data);
void print_result();

ofstream result_out;

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

void init_result_parameter(){
	support_server_push=0;
	support_http2=0;
	support_ssl=0;
	support_h2_ping=0;
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
	default_max_concurrent_streams=0;
	changed_max_concurrent_streams=0;
	range_stream_id=0;
	support_range=0;
}

static void die(const char *msg) {
	cout<<"die"<<endl;
	fatal=char_star_to_string(msg);
	if(my_config.debug){
	fprintf(stderr, "FATAL: %s\n", msg);
	}
	check_result();
	print_result();
	exit(EXIT_FAILURE);
}

void cal_hpack_ratio(){
	float ratio;
	int first_size = receive_headers_frames.at(0).size;
	int total_size = 0;
        for(int i =0;i<receive_headers_frames.size();i++){
                total_size +=receive_headers_frames.at(i).size;
        }
	ratio = float(total_size)/(10*first_size);
	printf("The hpack compression ratio is %f%\n",ratio*100);
}

int get_pos(int id,vector<int> & array){
	for (int i=0;i<array.size();i++){
	if (array.at(i) == id){
	return i;
}
	}
return -1;
	
}

void check_priority_support(){
	vector<int> receive_order;
	vector<int> finish_order;
	for(int i =0;i<receive_data_frames.size();i++){
		if (receive_data_frames.at(i).stream_id>2*priority_stream_num){
			printf("receive data from stream %d\n",receive_data_frames.at(i).stream_id-2*priority_stream_num);
			receive_order.push_back(receive_data_frames.at(i).stream_id-2*priority_stream_num);
			if(receive_data_frames.at(i).end == 1){
				finish_order.push_back(receive_data_frames.at(i).stream_id-2*priority_stream_num);
			printf("finish stream %d\n",receive_data_frames.at(i).stream_id-2*priority_stream_num);
			}
		}
	}
	int D_receive_pos = get_pos(7,receive_order); //stream ID:7
	int A_receive_pos = get_pos(1,receive_order); //stream ID:1
	int E_receive_pos = get_pos(9,receive_order); //stream ID:9
	int C_receive_pos = get_pos(5,receive_order); //stream ID:5
	if ((D_receive_pos <A_receive_pos) and (A_receive_pos <C_receive_pos) and (C_receive_pos<E_receive_pos) and (A_receive_pos>=0) and (D_receive_pos>=0) and (E_receive_pos>=0) and (C_receive_pos>=0)){
		printf("Priority Mechanism check pass on Receive Data Order\n");
	}	
	else{
		printf("Priority Mechanism check fail on Receive Data Order\n");
	}

	int D_finish_pos = get_pos(7,finish_order); //stream ID:7
	int A_finish_pos = get_pos(1,finish_order); //stream ID:1
	int E_finish_pos = get_pos(9,finish_order); //stream ID:9
	int C_finish_pos = get_pos(5,finish_order); //stream ID:5
	if ((D_finish_pos <A_finish_pos) and (A_finish_pos <C_finish_pos) and (C_finish_pos<E_finish_pos) and (A_finish_pos>=0) and (D_receive_pos>=0) and (E_receive_pos>=0) and (C_receive_pos>=0)){
		printf("Priority Mechanism check pass on Finish Data Order\n");
	}
	else{
		printf("Priority Mechanism check fail on Finish Data Order\n");
	}	
}
/*
 * Prints error containing the function name |func| and message |msg|
 * and exit.
 */

static void dief(const char *func, const char *msg) {
	cout<<"dief"<<endl;
	fatal=char_star_to_string(func)+":"+char_star_to_string(msg);
	if(my_config.debug){
	fprintf(stderr, "FATAL: %s: %s\n", func, msg);
	}
	check_result();
	print_result();
	exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and error code
 * |error_code| and exit.
 */

static void diec(const char *func, int error_code) {
	if(my_config.debug){
	fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code, nghttp2_strerror(error_code));
	}
	fatal=char_star_to_string(nghttp2_strerror(error_code));
	//print_test_result(&my_result);
	check_result();
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

	if(strcmp(my_config.ssl_connection,"npn")==0)
	{
		SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
	}
	else{
		unsigned char vector[] = {
			NGHTTP2_PROTO_ALPN
		};
		unsigned int length = sizeof(vector);
		SSL_CTX_set_alpn_protos(ssl_ctx, vector, NGHTTP2_PROTO_ALPN_LEN);
	}
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


	//rv = SSL_connect(ssl);

	rv = SSL_connect(ssl);
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	if(rv<0){
		if(select(fd+1, NULL, &fdset, NULL, &timeout)>0){
			lon = sizeof(int);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
			if(valopt==0){
				arg = fcntl(fd, F_GETFL, NULL);
				arg &= (~O_NONBLOCK);
				fcntl(fd, F_SETFL, arg);
				if(my_config.debug){
					printf("[INFO] SSL/TLS handshake completed\n");
				}
				support_ssl=1;
				return;
			}
		} 
		else{
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
	if (rv != 0) {
		dief("getaddrinfo", gai_strerror(rv));
	}

	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
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
		if (rv == 0) {
			break;
		}
		if (rv < 0) {
			if (errno == EINPROGRESS) {
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
	}
	if (nghttp2_session_want_write(connection->session) ||
			connection->want_io == WANT_WRITE) {
		pollfd->events |= POLLOUT;
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
				if(my_config.debug){
					/* Print response headers for the initiated request. */
					print_header(stderr, name, namelen, value, valuelen);
				}
			}
			break;
		case NGHTTP2_PUSH_PROMISE:
			if(my_config.debug){
				print_header(stderr, name, namelen, value, valuelen);
			}
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
				if(my_config.debug){
					fprintf(stderr, "Response headers for stream ID=%d:\n", frame->hd.stream_id);
				}
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
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (DATA)\n");
			}
			break;
		case NGHTTP2_HEADERS:
			if(frame->hd.stream_id==1 && feature == ZERO_WINDOW_UPDATE_STREAM){
				nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, 0);
				printf("The zero window update frame on stream 1 has been sent out\n");
			}
			if(frame->hd.stream_id==1 && feature == ZERO_WINDOW_UPDATE_CONNECTION){
				nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, 0);
				printf("The zero window update frame on the whole session has been sent out\n");
			}
			if(frame->hd.stream_id==1 && feature == LARGE_WINDOW_UPDATE_STREAM){
				nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, (1<<31)-1);
				nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 1, (1<<30)-1);
				printf("Two large window update frame on stream 1 has been sent out\n");
			}
			if(frame->hd.stream_id==1 && feature == SELF_DEPENDENT){
				nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 1, &pri_spec1);
				printf("The self dependent priority frame  has been sent out\n");
			}
			if(feature == PRIORITY_MECHANISM){
				if (frame->hd.stream_id == 2*priority_stream_num+11){
					nghttp2_priority_spec temp_spec;
					nghttp2_priority_spec_init(&temp_spec, 2*priority_stream_num+7, 1, 1);
					nghttp2_submit_priority(session, NGHTTP2_FLAG_NONE, 2*priority_stream_num+1, &temp_spec);
					sleep(2);
					nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, 1<<30);
				}

			}
			if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
				if(my_config.debug){
					printf("[INFO] C ----------------------------> S (FRAME SEND) (HEADERS)\n");
					print_headers_frame(&frame->headers);
				}
			}
			break;
		case NGHTTP2_PRIORITY:
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (PRIORITY)\n");
				print_priority_frame(&frame->priority);
			}
			break;
		case NGHTTP2_RST_STREAM:
			if(my_config.debug){
			printf("[INFO] C ----------------------------> S (FRAME SEND) (RST_STREAM)\n");
			print_rst_stream_frame(&frame->rst_stream);
			}
			break;
		case NGHTTP2_SETTINGS:
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (SETTINGS)\n");
				print_settings_frame(&frame->settings);
			}
			break;
		case NGHTTP2_PUSH_PROMISE:
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (PUSH_PROMISE)\n");
				print_push_promise_frame(&frame->push_promise);
			}
			break;
		case NGHTTP2_PING:
			if (feature == H2_PING){
				gettimeofday(&ping_start,NULL);
			}
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (PING)\n");
				print_ping_frame(&frame->ping);
			}
			break;
		case NGHTTP2_GOAWAY:
			if(my_config.debug){
			printf("[INFO] C ----------------------------> S (FRAME SEND) (GOAWAY)\n");
			print_goaway_frame(&frame->goaway);
			}
			break;
		case NGHTTP2_WINDOW_UPDATE:
			if(my_config.debug){
				printf("[INFO] C ----------------------------> S (FRAME SEND) (WINDOW_UPDATE)\n");
				print_window_update_frame(&frame->window_update);
			}
			window_update window_temp;
			window_temp.stream_id=frame->hd.stream_id;
			window_temp.size_increment=(frame->window_update).window_size_increment;
			send_window_update.push_back(window_temp);
			break;
	}

	if(my_config.debug){
		printf("\n=====STREAM STATE (ID: %d)=====\n", frame->hd.stream_id);
	}
	nghttp2_stream *stream = nghttp2_session_find_stream(session, frame->hd.stream_id);
	if (stream) {
		if(my_config.debug){
			print_stream_state(stream);
		}
	} else {
		if(my_config.debug){
			printf("(Invalid stream)\n");
		}
	}
	//	printf("===============================\n");

	return 0;
}



int on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data ) {
	switch (frame->hd.type) {
		case NGHTTP2_DATA:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (FRAME RECV) (DATA)\n");
				printf("[INFO] LENGTH <---------------------------- %zu",frame->hd.length);
			}
			data_frame data_temp;
			data_temp.stream_id=frame->hd.stream_id;
			data_temp.size = frame->hd.length;
			data_temp.end=frame->data.hd.flags;
			receive_data_frames.push_back(data_temp);

			if (feature == PRIORITY_MECHANISM){
				//if(frame->hd.stream_id == (2*priority_stream_num + 11) and frame->hd.flags == 1){
				//}

				priority_recv_length+=frame->hd.length;
				if (frame->hd.stream_id==1){
					priority_payload_length+=frame->hd.length;
				}

				if(frame->hd.stream_id==1 and frame->hd.flags==1){
					if (priority_payload_length==0){
						die("payload is zero");
					}
					priority_stream_num=65535/priority_payload_length;
					if (65535%priority_payload_length==0){
						priority_stream_num=priority_stream_num;
					}else{
						priority_stream_num++;
					}

					for (int i =0;i<priority_stream_num-1;i++)
					{
						submit_request(&connection, &req, NULL);
					}
				}
				if(priority_payload_length==65535){
					priority_stream_num=1;
				}
				if (priority_recv_length==65535){
					//stream_num=1;
					for (int i=0;i<priority_stream_num;i++){
						nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 2*i+1, NGHTTP2_NO_ERROR);
					}
					sleep(2);
					nghttp2_priority_spec_init(&pri_spec1, 0, 1, 0);
					int stream_id_1=submit_request(&connection, &req, &pri_spec1);
					nghttp2_priority_spec_init(&pri_spec1, stream_id_1, 1, 0);
					int stream_id_2=submit_request(&connection, &req, &pri_spec1);

					nghttp2_priority_spec_init(&pri_spec1,stream_id_1,1,0);
					int stream_id_3= submit_request(&connection, &req, &pri_spec1);

					nghttp2_priority_spec_init(&pri_spec1,stream_id_3,1,0);
					int stream_id_4= submit_request(&connection, &req, &pri_spec1);

					nghttp2_priority_spec_init(&pri_spec1,stream_id_3,1,0);
					int stream_id_5= submit_request(&connection, &req, &pri_spec1);

					nghttp2_priority_spec_init(&pri_spec1,stream_id_4,1,0);
					int stream_id_6= submit_request(&connection, &req, &pri_spec1);

				}


			}


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
			if (frame->data.hd.flags==1 ) {
				finish_sequence.push_back(frame->hd.stream_id);
			}


			if (frame->hd.stream_id==range_stream_id && frame->hd.length==201 && frame->hd.flags==1) {
				support_range=1;
			}
			break;
		case NGHTTP2_HEADERS: {
					      if(hpack_send_num<9 && feature==HPACK){
						      submit_request(&connection, &req, NULL);
						      hpack_send_num++;
						      printf("Send test request %d\n",hpack_send_num+1);
					      }
					      id_size headers_temp;
					      headers_temp.stream_id = frame->hd.stream_id;
					      headers_temp.size = frame->hd.length;
					      receive_headers_frames.push_back(headers_temp);
					      if(receive_headers_frames.size()==10 && feature==HPACK){
						cal_hpack_ratio();
						}

					      struct Request *req = NULL;
					      nghttp2_nv *nva = NULL;
					      if(my_config.debug){
						      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
							      printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: RESPONSE)\n");
							      nva = frame->headers.nva;
							      req = (Request*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
						      } else if (frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
							      printf("[INFO] C <---------------------------- S (FRAME RECV) (HEADER CAT: PUSH_RESPONSE)\n");
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
						      }
					      }			
				      }
				      break;
		case NGHTTP2_PRIORITY:
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (PRIORITY)\n");
					      print_priority_frame(&frame->priority);
				      }
				      break;
		case NGHTTP2_RST_STREAM:
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (RST_STREAM)\n");
					      print_rst_stream_frame(&frame->rst_stream);
					      rst_sequence.push_back(frame->hd.stream_id);
				      }
				      break;
		case NGHTTP2_SETTINGS:
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (SETTINGS)\n");
					      print_settings_frame(&frame->settings);
				      }			
				      break;
		case NGHTTP2_PUSH_PROMISE:
				      if(my_config.debug){
					      printf("[INFO] C <--------------------------- S (FRAME RECV) (PUSH_PROMISE)\n");
				      }				
				      support_server_push=1;
				      id_size push_temp;
				      push_temp.stream_id = frame->push_promise.promised_stream_id;
				      push_temp.size = frame->hd.length;
				      receive_push_promises.push_back(push_temp);
				      break;
		case NGHTTP2_PING:
				      support_h2_ping=1;
				      if (feature == H2_PING){
					      gettimeofday(&ping_end,NULL);
					      unsigned long diff;
					      diff = 1000000 * (ping_end.tv_sec-ping_start.tv_sec)+ ping_end.tv_usec-ping_start.tv_usec;
					      printf ("Ping time is %ldus\n",diff);
				      }
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (PING)\n");				
					      print_ping_frame(&frame->ping);
				      }
				      break;
		case NGHTTP2_GOAWAY:
				      recv_go_away+="LS_ID:"+int_to_string(frame->goaway.last_stream_id)+"|";
				      recv_go_away+="EC:"+print_err_code_string(frame->goaway.error_code)+"|";
				      recv_go_away_detail.assign((char*)frame->goaway.opaque_data,frame->goaway.opaque_data_len);
				      recv_go_away+="Detail:"+recv_go_away_detail+"|";
				      if(my_config.debug){
				      printf("[INFO] C <---------------------------- S (FRAME RECV) (GOAWAY)\n");
				      print_goaway_frame(&frame->goaway);
				      }
				      break;
		case NGHTTP2_WINDOW_UPDATE:
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (WINDOW_UPDATE)\n");
					      print_window_update_frame(&frame->window_update);
				      }				
				      break;
		case NGHTTP2_CONTINUATION:
				      if(my_config.debug){
					      printf("[INFO] C <---------------------------- S (FRAME RECV) (CONTINUATION)\n");
				      }
				      break;
	}

	if(my_config.debug){
		printf("\n=====STREAM STATE (ID: %d)=====\n", frame->hd.stream_id);
	}
	nghttp2_stream *stream = nghttp2_session_find_stream(session, frame->hd.stream_id);
	if (stream) {
		if(my_config.debug){
			print_stream_state(stream);
		}
	} else {
		if(my_config.debug){
			printf("(Invalid stream)\n");
		}
	}
	//	printf("===============================\n");

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
	if(my_config.debug){
		printf("Stream %d closed\n", stream_id);
	}
	struct Request *req;
	req = (Request *)nghttp2_session_get_stream_user_data(session, stream_id);

	if(my_config.debug){
		printf("\n=====STREAM STATE (ID: %d)=====\n", stream_id);
	}
	nghttp2_stream *stream = nghttp2_session_find_stream(session, stream_id);
	if (stream) {
		if(my_config.debug){
			print_stream_state(stream);
		}
	} else {
		if(my_config.debug){
			printf("(Invalid stream)\n");
		}
	}
	//printf("===============================\n");

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
	//printf("[INFO] Stream ID = %d\n", stream_id);

	//printf("\n=====STREAM STATE (ID: %d)=====\n", stream_id);
	nghttp2_stream *stream = nghttp2_session_find_stream(connection->session, stream_id);
	if (stream) {
		if(my_config.debug){
			print_stream_state(stream);
		}
	} else {
		if(my_config.debug){
			printf("(Invalid stream)\n");
		}
	}
	//	printf("===============================\n");
	return stream_id;
}

/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection) {
	int rv;
	rv = nghttp2_session_recv(connection->session);
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
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (DATA)\n");
				print_frame_header(hd);
			}
			break;
		case NGHTTP2_HEADERS:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (HEADERS)\n");
				print_frame_header(hd);
			}
			break;
		case NGHTTP2_PRIORITY:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PRIORITY)\n");
			}
			break;
		case NGHTTP2_RST_STREAM:
			printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (RST_STREAM)\n");
			break;
		case NGHTTP2_SETTINGS:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (SETTINGS)\n");
			}
			break;
		case NGHTTP2_PUSH_PROMISE:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PUSH_PROMISE)\n");
			}
			break;
		case NGHTTP2_PING:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (PING)\n");
			}
			break;
		case NGHTTP2_GOAWAY:
			if(my_config.debug){
			printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (GOAWAY)\n");
			}
			break;
		case NGHTTP2_WINDOW_UPDATE:
			if(my_config.debug){
				printf("[INFO] C <---------------------------- S (BEGIN FRAME RECV) (WINDOW_UPDATE)\n");
			}
			break;
	}
	return 0;
}


nghttp2_session_callbacks *callbacks;
int fd;
SSL_CTX *ssl_ctx;
SSL *ssl;
struct pollfd pollfds[1];
/*
 * Fetches the resource denoted by |uri|.
 */
static void basic_test(const struct URI *uri) {

	int rv;
	nfds_t npollfds = 1;

	request_init(&req, uri);

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


	nghttp2_option* my_option;
	nghttp2_option_new(&my_option);
	if (feature == CONTROL_HEADERS||	\
			feature == CONTROL_DATA||	\
			feature == ZERO_WINDOW_UPDATE_STREAM||		\
			feature == ZERO_WINDOW_UPDATE_CONNECTION||	\
			feature == LARGE_WINDOW_UPDATE_STREAM||		\
			feature == LARGE_WINDOW_UPDATE_CONNECTION||	\
			feature == PRIORITY_MECHANISM	\
	   ){
		nghttp2_option_set_no_auto_window_update(my_option,1);
	}
	else{
		nghttp2_option_set_no_auto_window_update(my_option,0);
	}
	int succeed=nghttp2_session_client_new2(&connection.session,callbacks,&connection,my_option);
	result_out<<"succeed:"<<succeed<<endl;


	// Delete callbacks
	nghttp2_session_callbacks_del(callbacks);

	if (rv != 0) {
		diec("nghttp2_session_client_new", rv);
	}


	//result_out <<"version:"<<NGHTTP2_VERSION<<endl;

	int settings_initial_window_size = 65535;
	int enable_push = 0;
	if (feature == CONTROL_HEADERS){
		settings_initial_window_size=0;
	}
	if (feature == CONTROL_DATA){
		settings_initial_window_size=1;
	}
	if (feature == SERVER_PUSH){
		enable_push = 1;
	}
	if (feature == PRIORITY_MECHANISM){
		settings_initial_window_size = 1<<30;
	}
	nghttp2_settings_entry settings[] = {
		//        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096}, // Default: 4096
		{NGHTTP2_SETTINGS_ENABLE_PUSH, enable_push}, // Default enabled
		  {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, settings_initial_window_size}, // Default: 65535 (2^16-1)
		//      {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1 << 14)} // Default: 2^14  Range: 2^14 ~ 2^24-1
	};
	rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(settings[0]));
	if (rv != 0) {
		diec("nghttp2_submit_settings", rv);
	}






	if (feature == MULTIPLEXING){
		printf("Now It's going to test the multiplexing feature\n");
		submit_request(&connection, &req, NULL);
		submit_request(&connection, &req, NULL);
	}
	if (feature == CONTROL_HEADERS){
		printf("Now It's going to test the control headers feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == CONTROL_DATA){
		printf("Now It's going to test the control data feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == ZERO_WINDOW_UPDATE_STREAM){
		printf("Now It's going to test the zero window update on stream feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == ZERO_WINDOW_UPDATE_CONNECTION){
		printf("Now It's going to test the zero window update on connection feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == LARGE_WINDOW_UPDATE_STREAM){
		printf("Now It's going to test the large window update on stream feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == LARGE_WINDOW_UPDATE_CONNECTION){
		printf("Now It's going to test the large window update on connection feature\n");
		nghttp2_submit_window_update(connection.session, NGHTTP2_FLAG_NONE, 0, (1<<31)-1);	
	}
	if (feature == SERVER_PUSH){
		printf("Now It's going to test the server push feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == PRIORITY_MECHANISM){
		printf("Now It's going to test the priority mechanism feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == SELF_DEPENDENT){
		nghttp2_priority_spec_init(&pri_spec1, 1, 1, 0);
		printf("Now It's going to test the self dependent feature\n");
		submit_request(&connection, &req, NULL);
	}
	if (feature == HPACK){
		printf("Now It's going to test the hpack feature\n");
		submit_request(&connection, &req, NULL);
		printf("Send test request 1\n");
	}
	if (feature == H2_PING){
		printf("Now It's going to test the HTTP/2 ping feature\n");
		nghttp2_submit_ping(connection.session, NGHTTP2_FLAG_NONE, NULL);	
	}

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

		if(feature == PRIORITY_MECHANISM){
		check_priority_support();      
  }
}

void clean_resource(){

	nghttp2_session_del(connection.session);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	shutdown(fd, SHUT_WR);
	close(fd);

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
	result_out<<"rst sequence:"<<rst_sequence.size()<<endl;
	for(int i=0;i<rst_sequence.size();i++){
		result_out<<rst_sequence.at(i)<<" ";
	}
	result_out<<endl;
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
	printf("==================================================================================================\n");
	printf("=======================THIS TOOL IS TO TEST THE FEATURES OF HTTP/2 PROTOCOL=======================\n");
	printf("since there are session conflicts between the methodologies to test different feasures, please    \n");
	printf("specify one feasure for testing every time. Notice: -t(target site) is  mandotory\n");
	printf("==================================================================================================\n");
	printf("-t target site. For example:-t https://www.google.com\n");
	printf("-g Print debug information. For example:-g \n");
	printf("-c TLS connection approach. For example: -c npn/alpn. Default: alpn \n");
	printf("-m Multiplexing. For example: -m number(number <= maximum streams number)\n");
	printf("-f Flow Control on DATA/HEADERS frames. For example: -f data/headers\n");
	printf("-z Zero window update frame detection on Stream/Connection. For exmaple: -z stream/connection\n");
	printf("-l Large window update frame detection on Stream/Connection. For example: -l stream/connection\n");
	printf("-s Server Push. For example: -s\n");
	printf("-p Priority Mechanism. For example: -p\n");
	printf("-e self-dependent For example: -e\n");
	printf("-r Compression ration calculation for HPACK. For example: -r\n");
	printf("-d HTTP2 Ping. For example: -d\n");
	printf("-h Print the help message. For example: -h\n");
	printf("-n Test no features, just make a request. For example: -n\n");
	printf("==================================================================================================\n");
}

void init_config (struct CONFIG * _my_config)
{
	_my_config->uri = NULL;
	_my_config->ssl_connection = "alpn";
	_my_config->multiplexing = 0;
	_my_config->flow_control = NULL;
	_my_config->zero_window_update = NULL;
	_my_config->large_window_update = NULL;
	_my_config->server_push = 0;
	_my_config->priority_mechanism = 0;
	_my_config->self_dependent = 0;
	_my_config->hpack = 0;
	_my_config->h2_ping = 0;
	_my_config->no_feature = 0;
	_my_config->debug = 0;
}

void verify_config(struct CONFIG * _my_config )
{
	if (_my_config->uri == NULL){
		printf("The target URL cannot be NULL. Please specify it with -t target_url;\n");
		exit(0);
	}
	if ( strcmp(_my_config->ssl_connection,"npn") != 0  && strcmp( _my_config->ssl_connection, "alpn")!=0) {
		printf("The SSL connection option can only be npn or alpn. Please specify it with -c npn/alpn Default is alpn\n");
		exit(0);
	}
	if (_my_config->multiplexing == 1){
		feature = MULTIPLEXING;
		return;
	}
	if (_my_config->flow_control!=NULL){
		if ( strcmp(_my_config->flow_control, "headers") == 0){
			feature = CONTROL_HEADERS;
			return;
		}
		if (strcmp(_my_config->flow_control, "data") == 0 ){
			feature = CONTROL_DATA;
			return;
		}
		printf("The flow control option can only be headers or data. Please specify it with -f headers/data\n");
		exit(0);
	}
	if (_my_config->zero_window_update !=NULL){
		if (strcmp(_my_config->zero_window_update, "stream") == 0){
			feature = ZERO_WINDOW_UPDATE_STREAM;
			return;
		}
		if (strcmp(_my_config->zero_window_update, "connection") == 0){
			feature = ZERO_WINDOW_UPDATE_CONNECTION;
			return;
		}
		printf("The zero window update option can only be stream or connection. Please specify it with -z stream/connection\n");
		exit(0);
	}
	if (_my_config->large_window_update !=NULL){
		if (strcmp(_my_config->large_window_update, "stream") == 0){
			feature = LARGE_WINDOW_UPDATE_STREAM;
			return;
		}
		if (strcmp(_my_config->large_window_update, "connection")==0){
			feature = LARGE_WINDOW_UPDATE_CONNECTION;
			return;
		}
		printf("The large window update option can only be stream or connection. Please specify it with -z stream/connection\n");
		exit(0);
	}
	if (_my_config->server_push == 1){
		feature = SERVER_PUSH;
		return;
	}
	if (_my_config->priority_mechanism == 1){
		feature = PRIORITY_MECHANISM;
		return;
	}
	if (_my_config->self_dependent == 1){
		feature = SELF_DEPENDENT;
		return;
	}
	if (_my_config->hpack == 1){
		feature = HPACK;
		return;
	}
	if (_my_config->h2_ping == 1){
		feature = H2_PING;
		return;
	}
}

void check_result()
{
			int data_size=0;
	switch(feature){
		case MULTIPLEXING:
			break;
		case CONTROL_HEADERS:
			if (receive_headers_frames.size() == 0){
				printf("Zero Initial Window can control the headers frame\n"); 
			}
			else{
				printf("Zero Initial Window can not control the headers frame\n");
			}
			break;
		case CONTROL_DATA:
			for(int i =0;i<receive_data_frames.size();i++){
				data_size+=receive_data_frames.at(i).size;
			}				
			if (data_size == 1){
				printf ("One Initial Window receive One size data frames\n");
			}
			break;
		case ZERO_WINDOW_UPDATE_STREAM:
			for (int i=0;i<rst_sequence.size();i++){
				if (rst_sequence.at(i)==1){
				printf("Recevie rst stream due to zero window on stream one\n");
			}
			if (recv_go_away!=""){
				printf("Receive Go Away frame due to zero window update on Window");
			}
			}	
			break;
		case ZERO_WINDOW_UPDATE_CONNECTION:
			if (recv_go_away!=""){
				printf("Receive Go Away frame due to zero window update on Window\n");
			}
			break;
		case LARGE_WINDOW_UPDATE_STREAM:
			for (int i=0;i<rst_sequence.size();i++){
				if (rst_sequence.at(i)==1){
				printf("Recevie rst stream due to zero window on stream one\n");
			}
			if (recv_go_away!=""){
				printf("Receive Go Away frame due to zero window update on Window\n");
			}
			}	
			break;
		case LARGE_WINDOW_UPDATE_CONNECTION:
			if (recv_go_away!=""){
				printf("Receive Go Away frame due to zero window update on Window\n");
			}
			break;
		case PRIORITY_MECHANISM:
			break;
		case SERVER_PUSH:
			if (support_server_push==1){
				printf("We receive the push promise frames\n");		
			}
			break;
		case SELF_DEPENDENT:
			for (int i=0;i<rst_sequence.size();i++){
				if (rst_sequence.at(i)==1){
				printf("Recevie rst stream due to self dependent prioirty frame on stream one\n");
			}
			if (recv_go_away!=""){
				printf("Receive Go Away frame due to self dependent priority frame on stream one\n");
			}
			}	
			break;
		case HPACK:
			break;
		case H2_PING:
			if (support_h2_ping){
				printf("Receive H2 Ping Frames from the server side\n");
			}
			break;
	}


}


int main(int argc, char **argv) {
	int rv;
	int ch;
	int feature_num = 0;
	init_config(&my_config);
	while ((ch = getopt(argc, argv, "t:c:mf:z:l:sperdgnh")) != -1)
	{
		switch (ch) 
		{
			case 't':
				my_config.uri = optarg;
				break;
			case 'g':
				my_config.debug = 1;
				break;
			case 'c':
				my_config.ssl_connection = optarg;
				break;
			case 'm':
				feature_num++;
				my_config.multiplexing = 1;
				break;
			case 'f':
				feature_num++;
				my_config.flow_control = optarg;
				break;
			case 'z':
				feature_num++;
				my_config.zero_window_update = optarg;
				break;
			case 'l':
				feature_num++;
				my_config.large_window_update = optarg;
				break;
			case 's':
				feature_num++;
				my_config.server_push = 1;
				break;
			case 'p':
				feature_num++;
				my_config.priority_mechanism = 1;
				break;
			case 'e':
				feature_num++;
				my_config.self_dependent = 1;
				break;
			case 'r':
				feature_num++;
				my_config.hpack = 1;
				break;
			case 'd':
				feature_num++;
				my_config.h2_ping = 1;
				break;
			case 'n':
				my_config.no_feature = 1;
				break;
			case 'h':
				print_help();
				exit(1);
				break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
		}
	}
	if (feature_num>1){
		printf("Due to the conflicts between the methodoligies for feature testing, please specify one feature every time\n");
		exit(1);
	}
	if (feature_num == 0 && my_config.no_feature==0){
		printf ("Please specify the feature you want to test\n");
		exit(1);
	}
	verify_config(&my_config);
	struct URI uri;
	struct sigaction act;
	rv = parse_uri(&uri, my_config.uri);
	if (rv != 0) {
		die("parse_uri failed");
	}
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, 0);

#ifndef OPENSSL_IS_BORINGSSL
	OPENSSL_config(NULL);
#endif 
	SSL_load_error_strings();
	SSL_library_init();
	basic_test(&uri);
	clean_resource();
	check_result();
	return EXIT_SUCCESS;

}
