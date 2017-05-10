# Todo, get libemu from source (may not be uninstalled!)
        # find better solution for libpython3.5 (currently python3-dev must not be uninstalled)

# Dionaea Dockerfile by MO
#
# VERSION 17.06
FROM alpine:edge
MAINTAINER MO

# Include dist
ADD dist/ /root/dist/

# Get and install packages for building dionaea
#RUN echo "http://dl-6.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories && \
RUN apk -U add autoconf automake build-base check cython libev-dev git glib-dev glib-static loudmouth-dev libnetfilter_queue-dev libnl-dev libpcap-dev openssl-dev libtool udns-dev python3-dev \
           ca-certificates python3 py3-yaml wget && \

# Setup user
    addgroup -g 2000 tpot && \
    adduser -S -H -s /bin/bash -u 2000 -D -g 2000 tpot

# Install dionaea and deps 
RUN pip3 install Cython
RUN cd /root && \

    ### curl
    wget https://curl.haxx.se/download/curl-7.54.0.tar.gz && \
    mkdir -p /root/curl/ && \
    tar xvfz curl-7.54.0.tar.gz --strip-components=1 -C /root/curl/ && \
    cd /root/curl && \
    autoreconf -vi && \
    ./configure --prefix=/opt/dionaea && \
    make && \
    make install
    
    ### libemu    
RUN git clone https://github.com/buffer/libemu /root/libemu/ && \
    cd /root/libemu/ && \
    autoreconf -vi && \
    ./configure --prefix=/opt/dionaea && \
    make && \
    make install

    ### dionaea
RUN git clone https://github.com/dinotools/dionaea -b 0.6.0 /root/dionaea/ && \
    cd /root/dionaea/ && \
    autoreconf -vi && \
    ./configure \
      --prefix=/opt/dionaea \
      --with-python=/usr/bin/python3 \
      --with-curl-config=/opt/dionaea/bin \
      --with-cython-dir=/usr/bin \
      --enable-ev \
      --with-ev-include=/usr/include \
      --with-ev-lib=/usr/lib \
      --with-emu-lib=/opt/dionaea/lib \
      --with-emu-include=/opt/dionaea/include \
      --with-nl-include=/usr/include/netlink \
      --with-nl-lib=/usr/lib \
      --enable-netfilter_queue \
      --with-netfilter_queue-include=/usr/include/libnetfilter_queue \
      --with-netfilter_queue-lib=/usr/lib \
      --enable-static && \
    make && \
    make install

# Remove packages used to build dionaea
#    apk del autoconf automake build-base check cython libev-dev git glib-dev glib-static loudmouth-dev libnetfilter_queue-dev libnl-dev libpcap-dev openssl-dev libtool udns-dev python3-dev && \

# Get and install packages for running dionaea
RUN apk -U add ca-certificates python3 py3-yaml && \

# Get and install libs for running dionaea
    apk -U add libcurl libev libnl glib-static libnetfilter_queue libpcap udns && \

# Supply configs
    rm -rf /opt/dionaea/etc/dionaea/* && \
    mv /root/dist/etc/* /opt/dionaea/etc/dionaea/ 

# Clean up
#    rm -rf /root/* && \
#    rm -rf /var/cache/apk/*

# Start cowrie
CMD ["/opt/dionaea/bin/dionaea", "-u", "tpot", "-g", "tpot", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg"]
