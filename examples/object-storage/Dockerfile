FROM ubuntu:24.04 AS bindings
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler protobuf-compiler-grpc && rm -rf /var/lib/apt/lists/*
COPY docs/contracts/proto /proto
RUN mkdir /bindings && protoc -I /proto --python_out=/bindings --grpc_python_out=/bindings --plugin=protoc-gen-grpc_python=/usr/bin/grpc_python_plugin \
    /proto/xelab/v1/common.proto /proto/xelab/v1/lifecycle.proto /proto/xelab/v1/capability.proto /proto/xelab/v1/host.proto /proto/xelab/v1/migration.proto

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-grpcio python3-protobuf && rm -rf /var/lib/apt/lists/*
COPY --from=bindings /bindings /opt/plugin
COPY examples/object-storage/model.py examples/object-storage/server.py examples/object-storage/store.py examples/object-storage/transport.py examples/object-storage/volume.py /opt/plugin/
COPY docs/preset-plugins/object-storage/storage.sql /opt/plugin/storage.sql
COPY --chmod=0555 examples/object-storage/plugin /usr/local/bin/plugin
ARG ARTIFACT_DIR=examples/object-storage/generated
COPY ${ARTIFACT_DIR}/xelab /xelab
RUN mkdir -p -m 0755 /data/objects
ENV PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/plugin"]

FROM runtime AS conformance
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY examples/object-storage/test_rpc.py examples/object-storage/physical_rpc.py /tests/
COPY docs/preset-plugins/object-storage/defaults.json /tests/defaults.json
ENV PYTHONPATH=/opt/plugin \
    XELAB_OBJECT_TEST_MANIFEST=/xelab/plugin.json \
    XELAB_OBJECT_TEST_CONFIG=/tests/defaults.json \
    XELAB_OBJECT_TEST_SCHEMA=/opt/plugin/storage.sql
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3", "-m", "unittest", "discover", "-s", "/tests", "-v"]

FROM runtime AS release
