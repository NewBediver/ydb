#include <iostream>
#include <library/cpp/json/json_writer.h>
#include <library/cpp/protobuf/json/proto2json.h>
#include <string>

#include <library/cpp/threading/future/core/future.h>
#include <util/system/env.h>
#include <ydb/core/protos/auth.pb.h>
#include <ydb/core/protos/config.pb.h>
#include <ydb/core/util/pb.h>
#include <ydb/library/yaml_config/yaml_config_parser.h>
#include <ydb/public/api/client/yc_private/servicecontrol/access_service.grpc.pb.h>
#include <ydb/public/sdk/cpp/src/library/grpc/client/grpc_client_low.h>
#include <ydb/public/sdk/cpp/src/library/grpc/client/grpc_common.h>

using yandex::cloud::priv::servicecontrol::v1::AccessService;
using yandex::cloud::priv::servicecontrol::v1::AuthorizeRequest;
using yandex::cloud::priv::servicecontrol::v1::AuthorizeResponse;

namespace {

void InitializeXdsBootstrapConfig(const NKikimrConfig::TAppConfig& config) {
    class TXdsBootstrapConfigBuilder {
    private:
        ::NKikimrConfig::TGRpcConfig::TXdsBootstrap ConfigYaml;
        TString JsonConfig;

    public:
        TXdsBootstrapConfigBuilder(const ::NKikimrConfig::TGRpcConfig::TXdsBootstrap& config)
            : ConfigYaml(config)
        {
            NJson::TJsonValue xdsBootstrapConfigJson;
            NProtobufJson::Proto2Json(ConfigYaml, xdsBootstrapConfigJson, {.FieldNameMode = NProtobufJson::TProto2JsonConfig::FldNameMode::FieldNameSnakeCaseDense});
            BuildFieldNode(&xdsBootstrapConfigJson);
            BuildFieldXdsServers(&xdsBootstrapConfigJson);
            JsonConfig = NJson::WriteJson(xdsBootstrapConfigJson, false);
        }

        TString Build() const {
            return JsonConfig;
        }

    private:
        void BuildFieldNode(NJson::TJsonValue* const json) const {
            NJson::TJsonValue& nodeJson = (*json)["node"];
            if (ConfigYaml.GetNode().HasMeta()) {
                // Message in protobuf can not contain field with name "metadata", so
                // Create field "meta" with string in JSON format
                // Convert string from field "meta" to JsonValue struct and write to field "metadata"
                ConvertStringToJsonValue(nodeJson["meta"].GetString(), &nodeJson["metadata"]);
                nodeJson.EraseValue("meta");
            }
        }

        void BuildFieldXdsServers(NJson::TJsonValue* const json) const {
            NJson::TJsonValue& xdsServersJson = *json;
            NJson::TJsonValue::TArray xdsServers;
            xdsServersJson["xds_servers"].GetArray(&xdsServers);
            xdsServersJson.EraseValue("xds_servers");
            for (auto& xdsServerJson : xdsServers) {
                NJson::TJsonValue::TArray channelCreds;
                xdsServerJson["channel_creds"].GetArray(&channelCreds);
                xdsServerJson.EraseValue("channel_creds");
                for (auto& channelCredJson : channelCreds) {
                    if (channelCredJson.Has("config")) {
                        ConvertStringToJsonValue(channelCredJson["config"].GetString(), &channelCredJson["config"]);
                    }
                    xdsServerJson["channel_creds"].AppendValue(channelCredJson);
                }
                xdsServersJson["xds_servers"].AppendValue(xdsServerJson);
            }
        }

        void ConvertStringToJsonValue(const TString& jsonString, NJson::TJsonValue* const out) const {
            NJson::TJsonReaderConfig jsonConfig;
            if (!NJson::ReadJsonTree(jsonString, &jsonConfig, out)) {
                Cerr << "Warning: Failed to parse JSON string in ConvertStringToJsonValue: \"" << jsonString << "\"" << Endl;
                *out = NJson::TJsonValue();
            }
        }
    };

    static const TString XDS_BOOTSTRAP_ENV = "GRPC_XDS_BOOTSTRAP";
    static const TString XDS_BOOTSTRAP_CONFIG_ENV = "GRPC_XDS_BOOTSTRAP_CONFIG";
    if (GetEnv(XDS_BOOTSTRAP_ENV).empty() && GetEnv(XDS_BOOTSTRAP_CONFIG_ENV).empty() && config.GetGRpcConfig().HasXdsBootstrap()) {
        const auto bootstrap_config = TXdsBootstrapConfigBuilder(config.GetGRpcConfig().GetXdsBootstrap()).Build();
        Cout << bootstrap_config << Endl;
        SetEnv(XDS_BOOTSTRAP_CONFIG_ENV, bootstrap_config);
    }
}

struct grpc_client_settings {
    TString Endpoint;
    TString CertificateRootCA; // root CA certificate PEM/x509
    ui32 GrpcKeepAliveTimeMs = 10000;
    ui32 GrpcKeepAliveTimeoutMs = 1000;
    ui32 GrpcKeepAlivePingInterval = 5000;
    bool EnableSsl = false;
    ui64 RequestTimeoutMs = 10000; // 10 seconds
    std::unordered_map<TString, TString> Headers;
    TString SslTargetNameOverride;
};

NYdbGrpc::TGRpcClientConfig InitGrpcConfig(const grpc_client_settings& settings) {
        const TDuration requestTimeout = TDuration::MilliSeconds(settings.RequestTimeoutMs);
        NYdbGrpc::TGRpcClientConfig config(settings.Endpoint, requestTimeout, NYdb::NGrpc::DEFAULT_GRPC_MESSAGE_SIZE_LIMIT, 0, settings.CertificateRootCA);
        config.EnableSsl = settings.EnableSsl;
        config.IntChannelParams[GRPC_ARG_KEEPALIVE_TIME_MS] = settings.GrpcKeepAliveTimeMs;
        config.IntChannelParams[GRPC_ARG_KEEPALIVE_TIMEOUT_MS] = settings.GrpcKeepAliveTimeoutMs;
        config.IntChannelParams[GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS] = 1;
        config.IntChannelParams[GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA] = 0;
        config.IntChannelParams[GRPC_ARG_HTTP2_MIN_SENT_PING_INTERVAL_WITHOUT_DATA_MS] = settings.GrpcKeepAlivePingInterval;
        config.IntChannelParams[GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS] = settings.GrpcKeepAlivePingInterval;
        if (!settings.SslTargetNameOverride.empty()) {
            config.SslTargetNameOverride = settings.SslTargetNameOverride;
        }
        return config;
    }

class SimpleGrpcClient {
public:
    SimpleGrpcClient(NKikimrConfig::TAppConfig config) : grpc_config{InitGrpcConfig(grpc_client_settings{
        .Endpoint = config.GetAuthConfig().GetAccessServiceEndpoint(),
        .CertificateRootCA = TUnbufferedFileInput(config.GetAuthConfig().GetPathToRootCA()).ReadAll(),
        .GrpcKeepAliveTimeMs = 10000,
        .GrpcKeepAliveTimeoutMs = 1000,
        .GrpcKeepAlivePingInterval = 5000,
        .EnableSsl = config.GetAuthConfig().GetUseAccessServiceTLS(),
        .RequestTimeoutMs = 10000,
        .Headers = {
            // {"x-request-id", "simple-test-client-12345"},
            {"user-agent", "simple-grpc-client/1.0"}
        },
        .SslTargetNameOverride = config.GetAuthConfig().GetAccessServiceSslTargetNameOverride(),
    })} {}

    // Простой метод для аутентификации
    std::string Authorize(const std::string& iam_token) {
        static constexpr auto Request = &AccessService::Stub::AsyncAuthorize;
        using TRequestType = yandex::cloud::priv::servicecontrol::v1::AuthorizeRequest;
        using TResponseType = yandex::cloud::priv::servicecontrol::v1::AuthorizeResponse;

        if (!connection) {
          connection = grpc_client.CreateGRpcServiceConnection<yandex::cloud::priv::servicecontrol::v1::AccessService>(grpc_config);
        }

        TRequestType request;
        request.set_iam_token(iam_token);

        // {
        //     auto* resource_path = request.add_resource_path();
        //     resource_path->set_type("resource-manager.cloud");
        //     resource_path->set_id();
        // }

        // {
        //     auto* resource_path = request.add_resource_path();
        //     resource_path->set_type("resource-manager.folder");
        //     resource_path->set_id();
        // }

        // {
        //     auto* resource_path = request.add_resource_path();
        //     resource_path->set_type("ydb.database");
        //     resource_path->set_id("/testing_global/bat804cu8huiscp0i4il/j3cceu7uvlgshfd03t94");
        // }

        {
            request.set_permission("compute.instances.list");
            auto* resource_path = request.add_resource_path();
            resource_path->set_type("resource-manager.folder");
            resource_path->set_id("batcfrdb6fauarko319o");
        }

        AuthorizeResponse response;
        grpc::ClientContext context;

        std::cout << "Sending Authorize request with token: " << request.DebugString() << std::endl;

        auto promise = NThreading::NewPromise<TString>();
        NYdbGrpc::TResponseCallback<TResponseType> callback =
            [promise](NYdbGrpc::TGrpcStatus&& status, TResponseType&& response) mutable -> void {
                promise.SetValue(status.Ok() ? ("Response: " + response.DebugString()) : ("Status: " + status.ToDebugString()));
            };

        NYdbGrpc::TCallMeta meta;
        meta.Timeout = grpc_config.Timeout ? NYdb::TDeadline::SafeDurationCast(grpc_config.Timeout) : NYdb::TDeadline::Duration::max();
        connection->DoRequest(request, std::move(callback), Request, meta);
        return promise.GetFuture().GetValueSync();
        // return "Empty";
    }

private:
    NYdbGrpc::TGRpcClientLow grpc_client;
    NYdbGrpc::TGRpcClientConfig grpc_config;
    std::unique_ptr<NYdbGrpc::TServiceConnection<AccessService>> connection;
};

}  // namespace

int main(int argc, char** argv) {
    std::cout << "GRPC verion: " << grpc::Version() << std::endl;

    if (argc < 3) {
        std::cerr << argv[0] << " <yaml_config> <iam_token>" << std::endl;
        return 1;
    }

    const TString yaml_config = argv[1];
    const TString iam_token = argv[2];

    TAutoPtr<TMappedFileInput> fileInput(new TMappedFileInput(yaml_config));
    NKikimrConfig::TAppConfig config(NKikimr::NYaml::Parse(fileInput->ReadAll()));
    InitializeXdsBootstrapConfig(config);

    std::cout << "Starting simple gRPC client..." << std::endl;
    std::cout << "Token: " << iam_token << std::endl;

    try {
        SimpleGrpcClient client(config);
        while (true) {
            std::cout << client.Authorize(iam_token) << std::endl;
            sleep(5);
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}