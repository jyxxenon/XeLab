#include "xelab/sdk.h"

#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::system_clock;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using Json = nlohmann::json;
namespace rpc = xelab::v1;
namespace sdk = xelab::sdk;

constexpr std::size_t kInputLimit = 65536;
constexpr std::size_t kConcurrentCalls = 4;

Json StrictJson(std::string_view text) {
  std::vector<std::unordered_set<std::string>> keys;
  return Json::parse(text, [&](int depth, Json::parse_event_t event, Json& parsed) {
    if (depth > 32) {
      throw std::invalid_argument("JSON nesting exceeds its limit");
    }
    if (event == Json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == Json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == Json::parse_event_t::key &&
               !keys.back().insert(parsed.get<std::string>()).second) {
      throw std::invalid_argument("Duplicate JSON field");
    }
    return true;
  });
}

bool SameContract(const rpc::ContractRef& left, const rpc::ContractRef& right) {
  return left.name() == right.name() && left.version() == right.version() &&
         left.schema_digest() == right.schema_digest();
}

rpc::ContractRef Contract(const Json& manifest, const std::string& name) {
  for (const auto& capability : manifest.at("capabilities")) {
    const auto& entry = capability.at("contract");
    if (entry.at("name") == name && entry.at("version") == "1.0.0" &&
        capability.at("side_effect") == "none") {
      rpc::ContractRef result;
      result.set_name(name);
      result.set_version("1.0.0");
      result.set_schema_digest(entry.at("schema_digest").get<std::string>());
      return result;
    }
  }
  throw std::runtime_error("Echo contract is missing from the manifest");
}

Status CheckContext(const ServerContext& call, const rpc::RpcContext& context,
                    std::chrono::milliseconds limit, bool business = false) {
  if (!sdk::IsUuid(context.request_id()) || (business && context.delegation_token().empty())) {
    return {StatusCode::INVALID_ARGUMENT, "Invalid request context"};
  }
  if (sdk::CallDeadline(call, context, limit) <= Clock::now()) {
    return {StatusCode::DEADLINE_EXCEEDED, "Call deadline expired"};
  }
  if (call.IsCancelled()) {
    return {StatusCode::CANCELLED, "Call canceled"};
  }
  return Status::OK;
}

struct EchoInput {
  std::string message;
  int count = 3;
  std::chrono::milliseconds delay{0};
};

int Integer(const Json& body, const char* key, int default_value, int low, int high) {
  if (!body.contains(key)) {
    return default_value;
  }
  const auto& field = body.at(key);
  if (!field.is_number()) {
    throw std::invalid_argument("Expected a bounded integer");
  }
  const double value = field.get<double>();
  if (value < low || value > high || std::trunc(value) != value) {
    throw std::invalid_argument("Expected a bounded integer");
  }
  return static_cast<int>(value);
}

Status ParseInput(const rpc::InvokeRequest& request, const rpc::ContractRef& contract,
                  bool stream, EchoInput& result) {
  if (!sdk::IsUuid(request.call_id()) || !SameContract(request.contract(), contract) ||
      request.input_json().size() > kInputLimit ||
      sdk::Digest(request.input_json()) != request.input_digest()) {
    return {StatusCode::INVALID_ARGUMENT, "Call contract or digest differs"};
  }
  try {
    const auto input = StrictJson(request.input_json());
    if (!input.is_object() || !input.contains("message") || !input.at("message").is_string()) {
      return {StatusCode::INVALID_ARGUMENT, "Invalid Echo input"};
    }
    for (auto field = input.begin(); field != input.end(); ++field) {
      const auto& name = field.key();
      if (name != "message" &&
          !(stream && (name == "count" || name == "delay_ms" || name == "fault"))) {
        return {StatusCode::INVALID_ARGUMENT, "Unknown Echo input field"};
      }
    }
    result.message = input.at("message").get<std::string>();
    if (std::count_if(result.message.begin(), result.message.end(),
                      [](unsigned char byte) { return (byte & 0xc0) != 0x80; }) > 1024) {
      return {StatusCode::INVALID_ARGUMENT, "Echo message exceeds its limit"};
    }
    if (stream) {
      result.count = Integer(input, "count", 3, 1, 64);
      result.delay = std::chrono::milliseconds(Integer(input, "delay_ms", 0, 0, 1000));
      if (input.contains("fault") && input.at("fault") != "none") {
        return {StatusCode::INVALID_ARGUMENT, "Rust acceptance fault is unavailable"};
      }
    }
  } catch (const Json::exception&) {
    return {StatusCode::INVALID_ARGUMENT, "Invalid Echo JSON"};
  } catch (const std::invalid_argument&) {
    return {StatusCode::INVALID_ARGUMENT, "Invalid Echo JSON"};
  }
  return Status::OK;
}

void Complete(const std::string& id, const EchoInput& input, rpc::InvokeResponse& response) {
  response.set_call_id(id);
  response.set_output_json(Json{{"message", input.message}}.dump());
  response.set_output_digest(sdk::Digest(response.output_json()));
}

class Echo final : public rpc::PluginLifecycle::Service, public rpc::CapabilityService::Service {
 public:
  Echo()
      : identity_(sdk::RuntimeIdentity::FromEnvironment()),
        manifest_(sdk::ReadManifest()),
        digest_(sdk::Digest(manifest_)) {
    const auto manifest = StrictJson(manifest_);
    if (manifest.at("plugin_id") != "org.xelab.echo-cpp" || manifest.at("manifest_version") != "1" ||
        manifest.at("capabilities").size() != 2) {
      throw std::runtime_error("Unexpected C++ Echo manifest");
    }
    unary_ = Contract(manifest, "org.xelab.echo");
    streaming_ = Contract(manifest, "org.xelab.echo.stream");
  }

  Status Describe(ServerContext* call, const rpc::DescribeRequest* request,
                  rpc::DescribeResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 2s);
    if (!status.ok()) return status;
    response->set_manifest_json(manifest_);
    response->set_manifest_digest(digest_);
    return Status::OK;
  }

  Status Initialize(ServerContext* call, const rpc::InitializeRequest* request,
                    rpc::InitializeResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 60s);
    if (!status.ok()) return status;
    if (!identity_.Matches(*request) || request->config_json().size() > 1024 * 1024 ||
        sdk::Digest(request->config_json()) != request->config_digest()) {
      return {StatusCode::FAILED_PRECONDITION, "Workload identity or configuration differs"};
    }
    try {
      if (StrictJson(request->config_json()) != Json::object()) {
        return {StatusCode::INVALID_ARGUMENT, "Echo expects an empty configuration"};
      }
    } catch (const Json::exception&) {
      return {StatusCode::INVALID_ARGUMENT, "Invalid Echo configuration"};
    } catch (const std::invalid_argument&) {
      return {StatusCode::INVALID_ARGUMENT, "Invalid Echo configuration"};
    }
    std::lock_guard lock(mutex_);
    if (config_digest_ && *config_digest_ != request->config_digest()) {
      return {StatusCode::FAILED_PRECONDITION, "Configuration already fixed for this generation"};
    }
    config_digest_ = request->config_digest();
    response->set_initialized(true);
    response->set_observed_generation(identity_.generation);
    return Status::OK;
  }

  Status GetHealth(ServerContext* call, const rpc::HealthRequest* request,
                   rpc::HealthResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 2s);
    if (!status.ok()) return status;
    std::lock_guard lock(mutex_);
    response->set_alive(true);
    response->set_observed_generation(identity_.generation);
    for (const auto* contract : {&unary_, &streaming_}) {
      auto* health = response->add_capabilities();
      *health->mutable_contract() = *contract;
      health->set_ready(Ready());
    }
    return Status::OK;
  }

  Status Drain(ServerContext* call, const rpc::DrainRequest* request,
               rpc::DrainResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 302s);
    if (!status.ok()) return status;
    std::lock_guard lock(mutex_);
    draining_ = true;
    response->set_accepting_requests(false);
    response->set_active_calls(static_cast<uint32_t>(active_.size()));
    response->set_drained(active_.empty());
    return Status::OK;
  }

  Status Shutdown(ServerContext* call, const rpc::ShutdownRequest* request,
                  rpc::Ack* response) override {
    const auto status = CheckContext(*call, request->context(), 302s);
    if (!status.ok()) return status;
    std::lock_guard lock(mutex_);
    draining_ = true;
    for (auto& entry : active_) entry.second = true;
    changed_.notify_all();
    response->set_request_id(request->context().request_id());
    response->set_accepted(true);
    return Status::OK;
  }

  Status Invoke(ServerContext* call, const rpc::InvokeRequest* request,
                rpc::InvokeResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 300s, true);
    if (!status.ok()) return status;
    EchoInput input;
    const auto parsed = ParseInput(*request, unary_, false, input);
    if (!parsed.ok()) return parsed;
    std::lock_guard lock(mutex_);
    if (!Ready()) return {StatusCode::UNAVAILABLE, "Echo is not accepting calls"};
    if (active_.size() >= kConcurrentCalls) {
      return {StatusCode::RESOURCE_EXHAUSTED, "Echo call capacity is unavailable"};
    }
    Complete(request->call_id(), input, *response);
    return Status::OK;
  }

  Status InvokeStream(ServerContext* call, const rpc::InvokeRequest* request,
                      grpc::ServerWriter<rpc::InvokeChunk>* writer) override {
    const auto status = CheckContext(*call, request->context(), 300s, true);
    if (!status.ok()) return status;
    EchoInput input;
    const auto parsed = ParseInput(*request, streaming_, true, input);
    if (!parsed.ok()) return parsed;
    {
      std::lock_guard lock(mutex_);
      if (!Ready()) return {StatusCode::UNAVAILABLE, "Echo is not accepting calls"};
      if (active_.size() >= kConcurrentCalls || !active_.emplace(request->call_id(), false).second) {
        return {StatusCode::RESOURCE_EXHAUSTED, "Echo stream capacity is unavailable"};
      }
    }
    const auto result = Produce(*call, *request, input, *writer);
    std::lock_guard lock(mutex_);
    active_.erase(request->call_id());
    return result;
  }

  Status Cancel(ServerContext* call, const rpc::CancelCallRequest* request,
                rpc::Ack* response) override {
    const auto status = CheckContext(*call, request->context(), 2s, true);
    if (!status.ok()) return status;
    if (!sdk::IsUuid(request->call_id())) return {StatusCode::INVALID_ARGUMENT, "Invalid Call ID"};
    std::lock_guard lock(mutex_);
    const auto found = active_.find(request->call_id());
    if (found != active_.end()) {
      found->second = true;
      changed_.notify_all();
    }
    response->set_request_id(request->context().request_id());
    response->set_accepted(true);
    return Status::OK;
  }

  Status QueryResult(ServerContext* call, const rpc::QueryResultRequest* request,
                     rpc::QueryResultResponse* response) override {
    const auto status = CheckContext(*call, request->context(), 2s, true);
    if (!status.ok()) return status;
    if (!sdk::IsUuid(request->call_id()) || request->idempotency_key().empty() ||
        request->idempotency_key() != request->context().idempotency_key()) {
      return {StatusCode::INVALID_ARGUMENT, "Invalid result reference"};
    }
    response->set_state(rpc::EXECUTION_STATE_UNKNOWN);
    return Status::OK;
  }

 private:
  bool Ready() const { return config_digest_.has_value() && !draining_; }

  Status Produce(ServerContext& call, const rpc::InvokeRequest& request, const EchoInput& input,
                 grpc::ServerWriter<rpc::InvokeChunk>& writer) {
    const auto deadline = sdk::CallDeadline(call, request.context(), 300s);
    for (int index = 0; index <= input.count; ++index) {
      bool canceled = false;
      {
        const auto ready = Clock::now() + (index < input.count ? input.delay : 0ms);
        std::unique_lock lock(mutex_);
        auto& cancel_flag = active_.at(request.call_id());
        while (!cancel_flag && !call.IsCancelled() && Clock::now() < std::min(ready, deadline)) {
          changed_.wait_until(lock, std::min({ready, deadline, Clock::now() + 10ms}));
        }
        canceled = cancel_flag;
      }
      if (Clock::now() >= deadline) {
        return {StatusCode::DEADLINE_EXCEEDED, "Echo stream deadline expired"};
      }
      if (call.IsCancelled()) return {StatusCode::CANCELLED, "Echo stream canceled"};
      rpc::InvokeChunk chunk;
      chunk.set_call_id(request.call_id());
      chunk.set_sequence(static_cast<uint64_t>(index + 1));
      if (canceled) {
        auto* terminal = chunk.mutable_canceled();
        terminal->set_request_id(request.context().request_id());
        terminal->set_accepted(true);
      } else if (index == input.count) {
        Complete(request.call_id(), input, *chunk.mutable_completed());
      } else {
        chunk.set_item_json(Json{{"index", index}, {"message", input.message}}.dump());
      }
      if (!writer.Write(chunk)) return {StatusCode::CANCELLED, "Echo stream closed"};
      if (canceled) break;
    }
    return Status::OK;
  }

  const sdk::RuntimeIdentity identity_;
  const std::string manifest_;
  const std::string digest_;
  rpc::ContractRef unary_;
  rpc::ContractRef streaming_;
  std::mutex mutex_;
  std::condition_variable changed_;
  std::optional<std::string> config_digest_;
  bool draining_ = false;
  std::map<std::string, bool> active_;
};

}  // namespace

int main() {
  try {
    Echo echo;
    grpc::ServerBuilder builder;
    sdk::ConfigurePluginServer(builder);
    builder.RegisterService(static_cast<rpc::PluginLifecycle::Service*>(&echo));
    builder.RegisterService(static_cast<rpc::CapabilityService::Service*>(&echo));
    const auto server = builder.BuildAndStart();
    if (!server) throw std::runtime_error("Could not start the workload listener");
    server->Wait();
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Echo startup failed: " << error.what() << '\n';
    return 1;
  }
}
