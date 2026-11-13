cmake_minimum_required(VERSION 3.22)
project(xelab_plugin_sdk LANGUAGES CXX)

find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
  find_package(Protobuf REQUIRED)
endif()
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.10 CONFIG REQUIRED)

set(repository "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(proto_root "${repository}/docs/contracts/proto")
set(generated "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(service_names lifecycle capability host migration)
set(proto_files)
set(service_files)
set(proto_outputs)
set(grpc_outputs)
foreach(name common ${service_names})
  set(relative "xelab/v1/${name}")
  list(APPEND proto_files "${proto_root}/${relative}.proto")
  list(APPEND proto_outputs "${generated}/${relative}.pb.cc" "${generated}/${relative}.pb.h")
endforeach()
foreach(name IN LISTS service_names)
  set(relative "xelab/v1/${name}")
  list(APPEND service_files "${proto_root}/${relative}.proto")
  list(APPEND grpc_outputs "${generated}/${relative}.grpc.pb.cc" "${generated}/${relative}.grpc.pb.h")
endforeach()

add_custom_command(
  OUTPUT ${proto_outputs} ${grpc_outputs}
  COMMAND ${CMAKE_COMMAND} -E make_directory "${generated}"
  COMMAND protobuf::protoc "--proto_path=${proto_root}" "--cpp_out=${generated}" ${proto_files}
  COMMAND protobuf::protoc "--proto_path=${proto_root}" "--grpc_out=${generated}"
          "--plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>" ${service_files}
  DEPENDS ${proto_files} protobuf::protoc gRPC::grpc_cpp_plugin
  VERBATIM)

add_library(xelab_plugin_sdk STATIC src/sdk.cc ${proto_outputs} ${grpc_outputs})
target_compile_features(xelab_plugin_sdk PUBLIC cxx_std_17)
target_include_directories(xelab_plugin_sdk PUBLIC include "${generated}")
target_link_libraries(xelab_plugin_sdk PUBLIC gRPC::grpc++ protobuf::libprotobuf PRIVATE OpenSSL::Crypto)
if(gRPC_VERSION VERSION_GREATER_EQUAL "1.84")
  target_compile_definitions(xelab_plugin_sdk PRIVATE XELAB_MODERN_GRPC_CERT_PROVIDER)
endif()

add_executable(xelab-echo-cpp "${repository}/examples/echo-cpp/main.cc")
target_link_libraries(xelab-echo-cpp PRIVATE xelab_plugin_sdk nlohmann_json::nlohmann_json)

include(CTest)
if(BUILD_TESTING)
  add_executable(xelab-sdk-conformance tests/conformance.cc)
  target_link_libraries(xelab-sdk-conformance PRIVATE xelab_plugin_sdk nlohmann_json::nlohmann_json)
endif()
