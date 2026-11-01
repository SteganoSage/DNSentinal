# DNSentinel, built from this checkout (the build context is the repository root).
# Two binaries: the hardened resolver, and the weak-mode one for the poisoning experiment (E5).
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY core core
COPY bench bench
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDNSENTINEL_ENABLE_TESTS=OFF \
    && cmake --build build -j"$(nproc)" --target dnsentinel
RUN cmake -S . -B build-weak -DCMAKE_BUILD_TYPE=Release -DDNSENTINEL_ENABLE_TESTS=OFF -DDNSENTINEL_WEAK_MODE=ON \
    && cmake --build build-weak -j"$(nproc)" --target dnsentinel

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/dnsentinel /usr/local/bin/dnsentinel
COPY --from=build /src/build-weak/dnsentinel /usr/local/bin/dnsentinel-weak
WORKDIR /dnsentinel
ENTRYPOINT ["dnsentinel"]
