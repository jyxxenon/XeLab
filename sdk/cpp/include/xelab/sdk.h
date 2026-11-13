#ifndef XELAB_SDK_H
#define XELAB_SDK_H

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>

#include "xelab/v1/capability.grpc.pb.h"
#include "xelab/v1/host.grpc.pb.h"
#include "xelab/v1/lifecycle.grpc.pb.h"

namespace xelab::sdk {

inline constexpr int kMaxMessageBytes = 20 * 1024 * 1024;
inline constexpr char kPluginAddress[] = "0.0.0.0:7000";
using Deadline = std::chrono::system_clock::time_point;

struct RuntimeIdentity {
  std::string deployment_id;
  std::string instance_id;
  uint64_t generation;

  static RuntimeIdentity FromEnvironment();
  bool Matches(const v1::InitializeRequest& request) const;
};

// Adds the fixed workload listener and bounds gRPC message sizes.
void ConfigurePluginServer(grpc::ServerBuilder& builder);

// Dials the injected HostService address with workload mTLS.
std::unique_ptr<v1::HostService::Stub> ConnectHost();

Deadline CallDeadline(const grpc::ServerContext& call, const v1::RpcContext& context,
                      std::chrono::milliseconds method_limit);
std::unique_ptr<grpc::ClientContext> HostCallContext(const grpc::ServerContext& parent,
                                                    const v1::RpcContext& context,
                                                    std::chrono::milliseconds method_limit);
std::optional<v1::ErrorDetail> ReadErrorDetail(const grpc::ClientContext& call);

bool IsUuid(std::string_view value);
std::string ReadManifest();
std::string Digest(std::string_view bytes);

}  // namespace xelab::sdk

#endif
