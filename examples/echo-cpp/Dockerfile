FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make cmake libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
    libssl-dev nlohmann-json3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY sdk/cpp sdk/cpp
COPY docs/contracts/proto docs/contracts/proto
COPY examples/echo-cpp/main.cc examples/echo-cpp/main.cc
RUN cmake -S sdk/cpp -B /build -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /build --target xelab-echo-cpp --parallel 2

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgrpc++1.51t64 libprotobuf32t64 libssl3t64 && rm -rf /var/lib/apt/lists/*
ARG ARTIFACT_DIR=examples/echo-cpp/generated
COPY --from=builder /build/xelab-echo-cpp /usr/local/bin/xelab-echo-cpp
COPY ${ARTIFACT_DIR}/xelab /xelab
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/xelab-echo-cpp"]
