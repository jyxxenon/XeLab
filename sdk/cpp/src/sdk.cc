#include "xelab/sdk.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include <arpa/inet.h>
#include <grpc/grpc_security_constants.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_certificate_verifier.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace xelab::sdk {
namespace {

constexpr char kKernelName[] = "kernel.xelab.local";
constexpr char kKernelUri[] = "spiffe://xelab.local/kernel";
constexpr char kErrorMetadata[] = "xelab-error-bin";

std::string RequiredEnvironment(const char* name) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    throw std::runtime_error(std::string("Missing runtime variable ") + name);
  }
  return value;
}

std::string HostAddress() {
  const std::string endpoint = RequiredEnvironment("XELAB_HOST_RPC_ENDPOINT");
  constexpr std::string_view scheme = "https://";
  const std::string_view value(endpoint);
  const auto invalid = [] { return std::runtime_error("Expected an HTTPS HostService socket address"); };
  if (value.substr(0, scheme.size()) != scheme) {
    throw invalid();
  }
  const auto address = value.substr(scheme.size());
  const auto colon = address.rfind(':');
  if (colon == std::string_view::npos) {
    throw invalid();
  }
  auto ip = address.substr(0, colon);
  int family = AF_INET;
  if (ip.size() > 2 && ip.front() == '[' && ip.back() == ']') {
    ip = ip.substr(1, ip.size() - 2);
    family = AF_INET6;
  }
  const std::string ip_text(ip);
  const auto port = address.substr(colon + 1);
  unsigned number = 0;
  const auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
  std::array<unsigned char, 16> binary{};
  if (parsed.ec != std::errc{} || parsed.ptr != port.data() + port.size() || number == 0 ||
      number > 65535 || inet_pton(family, ip_text.c_str(), binary.data()) != 1) {
    throw invalid();
  }
  return std::string(address);
}

bool KernelCertificate(grpc::string_ref pem, bool verify_name) {
  if (pem.empty() || pem.size() > 65536) {
    return false;
  }
  std::unique_ptr<BIO, decltype(&BIO_free)> input(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  if (!input) {
    return false;
  }
  std::unique_ptr<X509, decltype(&X509_free)> cert(
      PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
  if (!cert || (verify_name && X509_check_host(cert.get(), kKernelName, 0,
          X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_WILDCARDS, nullptr) != 1)) {
    return false;
  }
  std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
      static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)),
      GENERAL_NAMES_free);
  if (!names) {
    return false;
  }
  for (int index = 0; index < sk_GENERAL_NAME_num(names.get()); ++index) {
    const auto* name = sk_GENERAL_NAME_value(names.get(), index);
    if (name->type == GEN_URI) {
      const auto* uri = name->d.uniformResourceIdentifier;
      const std::string_view value(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                                   ASN1_STRING_length(uri));
      if (value == kKernelUri) {
        return true;
      }
    }
  }
  return false;
}

class KernelVerifier final : public grpc::experimental::ExternalCertificateVerifier {
 public:
  explicit KernelVerifier(bool verify_name) : verify_name_(verify_name) {}

  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)>, grpc::Status* result) override {
    *result = KernelCertificate(request->peer_cert(), verify_name_)
                  ? grpc::Status::OK
                  : grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Kernel identity required");
    return true;
  }

  void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest*) override {}

 private:
  bool verify_name_;
};

std::shared_ptr<grpc::experimental::CertificateProviderInterface> WorkloadCertificates() {
  const auto key = RequiredEnvironment("XELAB_TLS_KEY_PATH");
  const auto cert = RequiredEnvironment("XELAB_TLS_CERT_PATH");
  const auto ca = RequiredEnvironment("XELAB_TLS_CA_PATH");
  return std::make_shared<grpc::experimental::FileWatcherCertificateProvider>(key, cert, ca, 1);
}

void ConfigureVerifier(grpc::experimental::TlsCredentialsOptions& options, bool verify_name) {
  options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<KernelVerifier>(verify_name));
}

}  // namespace

RuntimeIdentity RuntimeIdentity::FromEnvironment() {
  auto deployment = RequiredEnvironment("XELAB_DEPLOYMENT_ID");
  auto instance = RequiredEnvironment("XELAB_INSTANCE_ID");
  const auto value = RequiredEnvironment("XELAB_GENERATION");
  uint64_t generation = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), generation);
  if (!IsUuid(deployment) || !IsUuid(instance) || parsed.ec != std::errc{} ||
      parsed.ptr != value.data() + value.size() || generation == 0 || generation > 9007199254740991ULL) {
    throw std::runtime_error("Invalid injected workload identity");
  }
  return {std::move(deployment), std::move(instance), generation};
}

bool RuntimeIdentity::Matches(const v1::InitializeRequest& request) const {
  return request.generation() == generation && request.deployment_id() == deployment_id &&
         request.instance_id() == instance_id;
}

void ConfigurePluginServer(grpc::ServerBuilder& builder) {
  auto certificates = WorkloadCertificates();
#ifdef XELAB_MODERN_GRPC_CERT_PROVIDER
  auto configured = grpc::experimental::TlsServerCredentialsOptions::Create(certificates);
  if (!configured.ok()) {
    throw std::runtime_error("Could not configure workload identity");
  }
  auto& options = configured.value();
  options.set_root_certificate_provider(certificates);
#else
  grpc::experimental::TlsServerCredentialsOptions options(certificates);
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
#endif
  options.set_cert_request_type(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  ConfigureVerifier(options, false);
  builder.AddListeningPort(kPluginAddress, grpc::experimental::TlsServerCredentials(options));
  builder.SetMaxReceiveMessageSize(kMaxMessageBytes);
  builder.SetMaxSendMessageSize(kMaxMessageBytes);
}

std::unique_ptr<v1::HostService::Stub> ConnectHost() {
  const auto address = HostAddress();
  auto certificates = WorkloadCertificates();
  grpc::experimental::TlsChannelCredentialsOptions options;
#ifdef XELAB_MODERN_GRPC_CERT_PROVIDER
  options.set_root_certificate_provider(certificates);
  options.set_identity_certificate_provider(certificates);
#else
  options.set_certificate_provider(certificates);
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
#endif
  options.set_verify_server_certs(true);
  // The verifier checks the fixed kernel DNS SAN as well as its URI SAN.
  options.set_check_call_host(false);
  ConfigureVerifier(options, true);
  grpc::ChannelArguments arguments;
  arguments.SetSslTargetNameOverride(kKernelName);
  arguments.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
  arguments.SetInt(GRPC_ARG_ENABLE_RETRIES, 0);
  arguments.SetMaxReceiveMessageSize(kMaxMessageBytes);
  arguments.SetMaxSendMessageSize(kMaxMessageBytes);
  return v1::HostService::NewStub(
      grpc::CreateCustomChannel(address, grpc::experimental::TlsCredentials(options), arguments));
}

Deadline CallDeadline(const grpc::ServerContext& call, const v1::RpcContext& context,
                      std::chrono::milliseconds method_limit) {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto upper = std::min(call.deadline(), now + std::clamp(
      method_limit, milliseconds(0), duration_cast<milliseconds>(hours(24))));
  const auto body = context.deadline_unix_ms();
  if (body <= duration_cast<milliseconds>(now.time_since_epoch()).count()) {
    return std::min(now, upper);
  }
  if (body >= duration_cast<milliseconds>(upper.time_since_epoch()).count()) {
    return upper;
  }
  return Deadline(milliseconds(body));
}

std::unique_ptr<grpc::ClientContext> HostCallContext(const grpc::ServerContext& parent,
                                                    const v1::RpcContext& context,
                                                    std::chrono::milliseconds method_limit) {
  auto child = grpc::ClientContext::FromServerContext(parent);
  child->set_deadline(CallDeadline(parent, context, method_limit));
  return child;
}

std::optional<v1::ErrorDetail> ReadErrorDetail(const grpc::ClientContext& call) {
  const auto& metadata = call.GetServerTrailingMetadata();
  const auto range = metadata.equal_range(kErrorMetadata);
  if (range.first == range.second || std::next(range.first) != range.second) {
    return std::nullopt;
  }
  const auto& bytes = range.first->second;
  v1::ErrorDetail result;
  if (bytes.empty() || bytes.size() > 8192 ||
      !result.ParseFromArray(bytes.data(), static_cast<int>(bytes.size())) || result.code().empty()) {
    return std::nullopt;
  }
  return result;
}

bool IsUuid(std::string_view value) {
  if (value.size() != 36) {
    return false;
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    const char ch = value[index];
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (ch != '-') return false;
    } else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
      return false;
    }
  }
  return true;
}

std::string ReadManifest() {
  constexpr std::size_t maximum = 1024 * 1024;
  std::ifstream input("/xelab/plugin.json", std::ios::binary);
  if (!input) {
    throw std::runtime_error("Could not open artifact file");
  }
  std::string bytes(maximum + 1, '\0');
  input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  if (input.bad() || static_cast<std::size_t>(input.gcount()) > maximum) {
    throw std::runtime_error("Could not read bounded artifact file");
  }
  bytes.resize(static_cast<std::size_t>(input.gcount()));
  return bytes;
}

std::string Digest(std::string_view bytes) {
  std::array<unsigned char, 32> hash{};
  if (EVP_Digest(bytes.data(), bytes.size(), hash.data(), nullptr, EVP_sha256(), nullptr) != 1) {
    throw std::runtime_error("Could not compute SHA-256");
  }
  constexpr char digits[] = "0123456789abcdef";
  std::string result("sha256:");
  result.reserve(71);
  for (unsigned char byte : hash) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 0xf]);
  }
  return result;
}

}  // namespace xelab::sdk
