# H2Scope

H2scope is a tool to test the features of HTTP/2 protocol

  - Basic Support (NPN/ALPN)
  - Multiplexing
  - Flow Control 
  - Priority Mechanism
  - HPACK
  - HTTP/2 Ping

### Installation

H2Scope use [nghttp2](https://nghttp2.org/) as the core library
So the required packages are similar to what nghttp2 needs

Install the dependencies and devDependencies and start the server.

The following command can install all the required packets if you are using Ubuntu 14.04LTS
```sh
sudo apt-get install g++ make binutils autoconf automake autotools-dev libtool pkg-config \
  zlib1g-dev libcunit1-dev libssl-dev libxml2-dev libev-dev libevent-dev libjansson-dev \
  libc-ares-dev libjemalloc-dev libsystemd-dev libspdylay-dev \
  cython python3-dev python-setuptools libmysqlclient libmysqlclient-dev
```

Clone this repo and compile

```sh
$ https://github.com/valour01/H2Scope
$ cd H2Scope
$ make
```

Tool named h2scope will be installed in the H2Scope directory. Try to type ./h2scope -h for help information
