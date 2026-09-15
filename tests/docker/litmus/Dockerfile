FROM debian:13-slim AS build

ARG LITMUS_REF=58c1c68e8419aebe477fd8a156ff2b6703295133

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool pkg-config build-essential ca-certificates git \
        libssl-dev libexpat1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/notroj/litmus.git litmus \
    && git -C litmus checkout "$LITMUS_REF" \
    && git -C litmus submodule update --init --recursive
RUN cd litmus && ./autogen.sh \
    && ./configure --prefix=/usr/local --with-included-neon --with-ssl=openssl --with-expat \
    && make -j"$(nproc)" \
    && make install

FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libexpat1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/litmus /usr/local/bin/litmus
COPY --from=build /usr/local/libexec/litmus /usr/local/libexec/litmus
WORKDIR /work
CMD ["sleep", "infinity"]
