FROM debian:13-slim AS build

ARG DOVECOT_REF=main
ARG IMAPTEST_REF=f50b6807297befe2d3a33f3c39124f3a832520c7

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool pkg-config gettext bison flex \
        build-essential ca-certificates git wget curl python3 \
        libssl-dev zlib1g-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --filter=blob:none https://github.com/dovecot/core.git core \
    && git -C core checkout "$DOVECOT_REF"
RUN cd core && autoreconf -vif && ./configure --disable-dependency-tracking && make -j"$(nproc)"

RUN git clone --filter=blob:none https://github.com/dovecot/imaptest.git imaptest \
    && git -C imaptest checkout "$IMAPTEST_REF"
COPY patches /src/patches
RUN cd imaptest && for p in /src/patches/*.patch; do [ -e "$p" ] || continue; echo "applying $p"; git apply -v "$p"; done
RUN cd imaptest && autoreconf -vif && ./configure --with-dovecot=../core CFLAGS="-g -O0" && make -j"$(nproc)"

FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-32-0 libssl3 zlib1g gdb \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/imaptest/src/imaptest /usr/local/bin/imaptest
CMD ["sleep", "infinity"]
