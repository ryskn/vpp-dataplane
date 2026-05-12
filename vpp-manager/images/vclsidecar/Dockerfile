FROM ubuntu:22.04

RUN apt update && apt install -y \
    libunwind8 \
    libssh-4 \
    libcurl3-gnutls \
 && apt clean \
 && rm -rf /var/lib/apt/lists/*

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

ADD artifacts/release/libvppcom* /usr/local/lib/
ADD artifacts/release/libvppinfra* /usr/local/lib/
ADD artifacts/release/libvlibmemoryclient* /usr/local/lib/
ADD artifacts/release/libvlibapi* /usr/local/lib/
ADD artifacts/release/libvcl_ldpreload* /usr/local/lib/
ADD artifacts/release/libsvm* /usr/local/lib/
ADD artifacts/release/libmemif.so /usr/local/lib/
ADD artifacts/release/calicovppversion /usr/local/lib/calicovppversion

RUN ARCH=$(uname -m) && \
    cp /usr/lib/${ARCH}-linux-gnu/libunwind.so.8 /usr/local/lib/ && \
    cp /usr/lib/${ARCH}-linux-gnu/libcurl-gnutls.so* /usr/local/lib/
RUN cp /usr/share/lintian/overrides/libssh-4 /usr/local/lib/
