#include "xelab/sdk.h"

#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <grpc/grpc_security_constants.h>
#include <nlohmann/json.hpp>

namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::system_clock;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;
using Json = nlohmann::json;
namespace rpc = xelab::v1;
namespace sdk = xelab::sdk;

constexpr char kInstance[] = "00000000-0000-4000-8000-000000000003";
constexpr char kDeployment[] = "00000000-0000-4000-8000-000000000004";
constexpr char kRequest[] = "00000000-0000-4000-8000-000000000005";
constexpr char kInstanceName[] = "i-00000000-0000-4000-8000-000000000003-g-1.xelab.local";

void Check(bool passed, const char* message) {
  if (!passed) throw std::runtime_error(message);
}

void CheckStatus(const Status& status, StatusCode expected, const char* stage) {
  if (status.error_code() != expected) {
    throw std::runtime_error(std::string(stage) + " returned gRPC status " +
                             std::to_string(status.error_code()));
  }
}

std::string Pem(const std::string& file) {
  std::ifstream source("/identity/" + file);
  Check(static_cast<bool>(source), "Missing fixture certificate or key");
  std::ostringstream bytes;
  bytes << source.rdbuf();
  return bytes.str();
}

std::unique_ptr<ClientContext> Call(std::chrono::milliseconds timeout = 4s) {
  auto call = std::make_unique<ClientContext>();
  call->set_deadline(Clock::now() + timeout);
  return call;
}

rpc::RpcContext Context() {
  rpc::RpcContext context;
  context.set_request_id(kRequest);
  context.set_idempotency_key("sdk-conformance");
  context.set_delegation_token("sdk-fixture");
  context.set_deadline_unix_ms(
      std::chrono::duration_cast<std::chrono::milliseconds>((Clock::now() + 5s).time_since_epoch())
          .count());
  return context;
}

std::shared_ptr<grpc::Channel> PluginChannel(const std::string& certificate) {
  grpc::SslCredentialsOptions options;
  options.pem_root_certs = Pem("ca.crt");
  if (!certificate.empty()) {
    options.pem_cert_chain = Pem(certificate + ".crt");
    options.pem_private_key = Pem(certificate + ".key");
  }
  grpc::ChannelArguments arguments;
  arguments.SetSslTargetNameOverride(kInstanceName);
  arguments.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
  arguments.SetInt(GRPC_ARG_ENABLE_RETRIES, 0);
  return grpc::CreateCustomChannel("127.0.0.1:7000", grpc::SslCredentials(options), arguments);
}

rpc::ContractRef Contract(const Json& manifest, std::string_view name) {
  for (const auto& capability : manifest.at("capabilities")) {
    const auto& value = capability.at("contract");
    if (value.at("name") == name) {
      rpc::ContractRef result;
      result.set_name(value.at("name").get<std::string>());
      result.set_version(value.at("version").get<std::string>());
      result.set_schema_digest(value.at("schema_digest").get<std::string>());
      return result;
    }
  }
  throw std::runtime_error("Expected contract missing from fixture");
}

rpc::InvokeRequest Invoke(const rpc::ContractRef& contract, int id, const std::string& body) {
  const auto digits = std::to_string(id);
  rpc::InvokeRequest request;
  *request.mutable_context() = Context();
  request.set_call_id("00000000-0000-4000-8000-" + std::string(12 - digits.size(), '0') + digits);
  *request.mutable_contract() = contract;
  request.set_input_json(body);
  request.set_input_digest(sdk::Digest(body));
  return request;
}

void CheckEcho(const rpc::InvokeResponse& response, const std::string& id) {
  Check(response.call_id() == id, "Echo changed Call identity");
  Check(Json::parse(response.output_json()) == Json{{"message", "互操作"}},
        "Echo output violates the shared schema");
  Check(response.output_digest() == sdk::Digest(response.output_json()), "Echo digest differs");
}

void CheckExplicitCancel(rpc::CapabilityService::Stub& stub, const rpc::ContractRef& contract) {
  auto call = Call();
  const auto request = Invoke(contract, 19, R"({"message":"互操作","count":4,"delay_ms":500})");
  auto stream = stub.InvokeStream(call.get(), request);
  rpc::InvokeChunk chunk;
  Check(stream->Read(&chunk) && chunk.has_item_json(), "Cancel fixture did not produce an item");
  rpc::CancelCallRequest cancel;
  *cancel.mutable_context() = Context();
  cancel.set_call_id(request.call_id());
  rpc::Ack ack;
  CheckStatus(stub.Cancel(Call().get(), cancel, &ack), StatusCode::OK, "Cancel RPC");
  Check(ack.accepted(), "Cancel acknowledgement missing");
  Check(stream->Read(&chunk) && chunk.has_canceled() && chunk.sequence() == 2 &&
        chunk.call_id() == request.call_id() && chunk.canceled().accepted(),
        "Explicit cancellation has no matching terminal frame");
  Check(!stream->Read(&chunk), "Canceled stream kept producing");
  CheckStatus(stream->Finish(), StatusCode::OK, "Canceled stream terminal");
}

void RunPlugin() {
  auto channel = PluginChannel("kernel");
  Check(channel->WaitForConnected(Clock::now() + 8s), "Workload did not accept kernel mTLS");
  auto lifecycle = rpc::PluginLifecycle::NewStub(channel);
  auto capability = rpc::CapabilityService::NewStub(channel);

  rpc::DescribeRequest describe;
  *describe.mutable_context() = Context();
  for (const auto* peer : {"", "foreign", "untrusted"}) {
    rpc::DescribeResponse denied;
    const auto status = rpc::PluginLifecycle::NewStub(PluginChannel(peer))->Describe(
        Call(1s).get(), describe, &denied);
    Check(!status.ok() && denied.manifest_json().empty(), "Non-kernel peer obtained a manifest");
  }
  rpc::DescribeResponse description;
  CheckStatus(lifecycle->Describe(Call().get(), describe, &description), StatusCode::OK, "Describe");
  const auto manifest_raw = sdk::ReadManifest();
  Check(description.manifest_json() == manifest_raw &&
        description.manifest_digest() == sdk::Digest(manifest_raw), "Describe changed artifact bytes");
  const auto manifest = Json::parse(manifest_raw);
  const auto unary_contract = Contract(manifest, "org.xelab.echo");
  const auto stream_contract = Contract(manifest, "org.xelab.echo.stream");
  const auto echo = Invoke(unary_contract, 11, R"({"message":"互操作"})");
  rpc::InvokeResponse response;
  CheckStatus(capability->Invoke(Call().get(), echo, &response), StatusCode::UNAVAILABLE,
              "Invoke before Initialize");

  rpc::InitializeRequest initialize;
  *initialize.mutable_context() = Context();
  initialize.set_deployment_id(kDeployment);
  initialize.set_instance_id(kInstance);
  initialize.set_generation(2);
  initialize.set_config_json("{}");
  initialize.set_config_digest(sdk::Digest("{}"));
  initialize.set_approval_revision(1);
  rpc::InitializeResponse initialized;
  CheckStatus(lifecycle->Initialize(Call().get(), initialize, &initialized),
              StatusCode::FAILED_PRECONDITION, "Wrong generation");
  initialize.set_generation(1);
  CheckStatus(lifecycle->Initialize(Call().get(), initialize, &initialized),
              StatusCode::OK, "Initialize");
  Check(initialized.initialized() && initialized.observed_generation() == 1,
        "Initialize did not observe the current generation");
  rpc::HealthRequest health;
  *health.mutable_context() = Context();
  rpc::HealthResponse ready;
  CheckStatus(lifecycle->GetHealth(Call().get(), health, &ready), StatusCode::OK, "GetHealth");
  Check(ready.alive() && ready.observed_generation() == 1 && ready.capabilities_size() >= 2,
        "Health did not advertise the active contracts");
  for (const auto& contract : ready.capabilities()) {
    Check(contract.ready(), "Initialized capability is not ready");
  }
  CheckStatus(capability->Invoke(Call().get(), echo, &response), StatusCode::OK, "Invoke");
  CheckEcho(response, echo.call_id());

  auto wrong_contract = echo;
  wrong_contract.mutable_contract()->set_schema_digest(sdk::Digest("different contract"));
  CheckStatus(capability->Invoke(Call().get(), wrong_contract, &response),
              StatusCode::INVALID_ARGUMENT, "Incompatible contract");
  for (const auto* body : {R"({"message":"a","message":"b"})", R"({"message":1})",
                           R"({"message":"a","other":true})"}) {
    CheckStatus(capability->Invoke(Call().get(), Invoke(unary_contract, 12, body), &response),
                StatusCode::INVALID_ARGUMENT, "Invalid Echo input");
  }

  auto invalid_call = Call();
  auto invalid = capability->InvokeStream(invalid_call.get(), echo);
  rpc::InvokeChunk chunk;
  Check(!invalid->Read(&chunk), "Invalid stream yielded data");
  CheckStatus(invalid->Finish(), StatusCode::INVALID_ARGUMENT, "Stream error status");

  auto normal_call = Call();
  const auto stream_request = Invoke(stream_contract, 13, R"({"message":"互操作","count":2})");
  auto normal = capability->InvokeStream(normal_call.get(), stream_request);
  for (int index = 0; index < 2; ++index) {
    Check(normal->Read(&chunk) && chunk.call_id() == stream_request.call_id() &&
          chunk.sequence() == static_cast<uint64_t>(index + 1) && chunk.has_item_json() &&
          Json::parse(chunk.item_json()) == Json{{"index", index}, {"message", "互操作"}},
          "Stream item or sequence differs");
  }
  Check(normal->Read(&chunk) && chunk.has_completed() && chunk.sequence() == 3 &&
        chunk.call_id() == stream_request.call_id(), "Stream completion missing");
  CheckEcho(chunk.completed(), stream_request.call_id());
  Check(!normal->Read(&chunk), "Stream continued after its terminal frame");
  CheckStatus(normal->Finish(), StatusCode::OK, "Stream EOF");

  auto deadline_call = Call(100ms);
  auto deadline = capability->InvokeStream(
      deadline_call.get(), Invoke(stream_contract, 14, R"({"message":"互操作","delay_ms":700})"));
  Check(!deadline->Read(&chunk), "Expired stream delivered an item");
  CheckStatus(deadline->Finish(), StatusCode::DEADLINE_EXCEEDED, "Stream gRPC deadline");
  auto canceled_call = Call();
  auto canceled = capability->InvokeStream(
      canceled_call.get(), Invoke(stream_contract, 15, R"({"message":"互操作","count":4,"delay_ms":250})"));
  Check(canceled->Read(&chunk) && chunk.has_item_json(), "Cancellation fixture never began");
  canceled_call->TryCancel();
  while (canceled->Read(&chunk)) {
    Check(!chunk.has_completed(), "Canceled stream completed");
  }
  CheckStatus(canceled->Finish(), StatusCode::CANCELLED, "Stream transport cancellation");
  if (manifest.at("plugin_id") == "org.xelab.echo-cpp") {
    CheckExplicitCancel(*capability, stream_contract);
  }

  rpc::DrainRequest drain;
  *drain.mutable_context() = Context();
  drain.set_grace_ms(1000);
  rpc::DrainResponse drained;
  for (int poll = 0; poll < 100; ++poll) {
    CheckStatus(lifecycle->Drain(Call().get(), drain, &drained), StatusCode::OK, "Drain");
    if (drained.drained()) break;
    std::this_thread::sleep_for(10ms);
  }
  Check(drained.drained() && drained.active_calls() == 0 && !drained.accepting_requests(),
        "Stream cancellation did not release the active slot");
  CheckStatus(capability->Invoke(Call().get(), echo, &response),
              StatusCode::UNAVAILABLE, "Invoke after Drain");
  std::cout << manifest.at("plugin_id").get<std::string>()
            << " passed shared mTLS, Lifecycle, Invoke, stream/error, deadline, cancellation and Drain\n";
}

class HostProbe final : public rpc::HostService::Service {
 public:
  explicit HostProbe(std::string workload) : workload_(std::move(workload)) {}

  Status Resolve(grpc::ServerContext* call, const rpc::ResolveRequest* request,
                 rpc::ResolveResponse* response) override {
    const auto auth = call->auth_context();
    if (!auth || !auth->IsPeerAuthenticated()) {
      return {StatusCode::UNAUTHENTICATED, "Missing fixture workload"};
    }
    const auto peer = auth->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    if (peer.size() != 1 ||
        std::string_view(peer.front().data(), peer.front().size()) != workload_) {
      return {StatusCode::UNAUTHENTICATED, "Wrong fixture workload"};
    }
    const auto deadline = sdk::CallDeadline(*call, request->context(), 2s);
    if (deadline > Clock::now() + 2s || deadline <= Clock::now()) {
      return {StatusCode::DEADLINE_EXCEEDED, "Wrong fixture deadline"};
    }
    if (request->context().delegation_token() != "sdk-fixture") {
      rpc::ErrorDetail detail;
      detail.set_code("PERMISSION_DENIED");
      detail.set_message("Fixture delegation rejected");
      call->AddTrailingMetadata("xelab-error-bin", detail.SerializeAsString());
      return {StatusCode::PERMISSION_DENIED, detail.message()};
    }
    if (request->context().idempotency_key() == "child-cancel") {
      const auto remaining = call->deadline() - Clock::now();
      child_started.set_value(remaining > 200ms && remaining < 1600ms);
      while (!call->IsCancelled() && Clock::now() < call->deadline()) {
        std::this_thread::sleep_for(5ms);
      }
      child_canceled.set_value(call->IsCancelled() && Clock::now() + 100ms < call->deadline());
      return {StatusCode::CANCELLED, "Child stopped"};
    }
    response->set_binding_id("00000000-0000-4000-8000-000000000099");
    return Status::OK;
  }

  std::promise<bool> child_started;
  std::promise<bool> child_canceled;

 private:
  std::string workload_;
};

class ParentProbe final : public rpc::CapabilityService::Service {
 public:
  explicit ParentProbe(rpc::HostService::Stub& host) : host_(host) {}

  Status Invoke(grpc::ServerContext* call, const rpc::InvokeRequest* request,
                rpc::InvokeResponse*) override {
    auto child = sdk::HostCallContext(*call, request->context(), 1500ms);
    rpc::ResolveRequest forwarded;
    *forwarded.mutable_context() = request->context();
    rpc::ResolveResponse result;
    return host_.Resolve(child.get(), forwarded, &result);
  }

 private:
  rpc::HostService::Stub& host_;
};

void CheckChildCancellation(rpc::HostService::Stub& host, HostProbe& service) {
  ParentProbe parent(host);
  grpc::ServerBuilder builder;
  sdk::ConfigurePluginServer(builder);
  builder.RegisterService(&parent);
  auto running = builder.BuildAndStart();
  Check(static_cast<bool>(running), "Could not start fixture parent");
  auto client = rpc::CapabilityService::NewStub(PluginChannel("kernel"));
  auto call = Call();
  rpc::InvokeRequest request;
  *request.mutable_context() = Context();
  request.mutable_context()->set_idempotency_key("child-cancel");
  auto started = service.child_started.get_future();
  auto canceled = service.child_canceled.get_future();
  auto result = std::async(std::launch::async, [&] {
    rpc::InvokeResponse response;
    return client->Invoke(call.get(), request, &response);
  });
  const bool deadline_is_clipped =
      started.wait_for(2s) == std::future_status::ready && started.get();
  call->TryCancel();
  CheckStatus(result.get(), StatusCode::CANCELLED, "Parent cancellation");
  Check(deadline_is_clipped, "Child deadline did not inherit its method budget");
  Check(canceled.wait_for(2s) == std::future_status::ready && canceled.get(),
        "Parent cancellation did not reach the HostService child");
  running->Shutdown();
  running->Wait();
}

void RunHost() {
  HostProbe service(Pem("tls.crt"));
  for (const auto* peer : {"wrong-dns", "wrong-uri", "untrusted", "kernel"}) {
    grpc::SslServerCredentialsOptions tls(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    tls.pem_root_certs = Pem("ca.crt");
    tls.pem_key_cert_pairs.push_back({Pem(std::string(peer) + ".key"), Pem(std::string(peer) + ".crt")});
    grpc::ServerBuilder server;
    int port = 0;
    server.AddListeningPort("127.0.0.1:0", grpc::SslServerCredentials(tls), &port);
    server.RegisterService(&service);
    auto running = server.BuildAndStart();
    Check(running && port > 0, "Could not start fixture HostService");
    const std::string endpoint = "https://127.0.0.1:" + std::to_string(port);
    Check(setenv("XELAB_HOST_RPC_ENDPOINT", endpoint.c_str(), 1) == 0, "Fixture address unavailable");
    auto host = sdk::ConnectHost();
    rpc::ResolveRequest request;
    *request.mutable_context() = Context();
    rpc::ResolveResponse result;
    const auto status = host->Resolve(Call(2s).get(), request, &result);
    if (std::string_view(peer) == "kernel") {
      CheckStatus(status, StatusCode::OK, "HostService mTLS Resolve");
      Check(!result.binding_id().empty(), "HostService binding missing");
      request.mutable_context()->set_delegation_token("different-delegation");
      auto denied = Call();
      CheckStatus(host->Resolve(denied.get(), request, &result), StatusCode::PERMISSION_DENIED,
                  "HostService delegation denial");
      const auto detail = sdk::ReadErrorDetail(*denied);
      Check(detail && detail->code() == "PERMISSION_DENIED" && detail->resource_id().empty(),
            "HostService error detail differs");
      CheckChildCancellation(*host, service);
    } else {
      Check(!status.ok() && result.binding_id().empty(), "SDK accepted the wrong host identity");
    }
    running->Shutdown();
    running->Wait();
  }
  std::cout << "C++ HostService client passed mTLS pins, delegated Resolve, error metadata and child cancellation\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "host") {
      RunHost();
    } else {
      RunPlugin();
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "SDK conformance failed: " << error.what() << '\n';
    return 1;
  }
}
