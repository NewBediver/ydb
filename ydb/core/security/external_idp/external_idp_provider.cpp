#include "external_idp_provider.h"

#include "external_idp_log.h"

#include <ydb/library/actors/core/actor_bootstrapped.h>
#include <ydb/library/actors/core/hfunc.h>
#include <ydb/library/actors/core/log.h>
#include <ydb/library/actors/http/http.h>
#include <ydb/library/actors/http/http_proxy.h>
#include <ydb/library/services/services.pb.h>

#include <library/cpp/json/json_reader.h>
#include <library/cpp/string_utils/base64/base64.h>

#include <util/datetime/base.h>
#include <util/generic/hash.h>
#include <util/generic/string.h>
#include <util/string/builder.h>
#include <util/string/split.h>
#include <util/string/strip.h>

#include <contrib/libs/jwt-cpp/include/jwt-cpp/jwt.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <chrono>
#include <exception>

// TODO(vlad-serikov): Fix logs in ticket_parser base on auth_conf

namespace NKikimr {

namespace {

////////////////////////////////////////////////////////////////////////////////

static constexpr TDuration REFRESH_PERIOD = TDuration::Minutes(1);
static constexpr TDuration HTTP_TIMEOUT = TDuration::Seconds(15);
static constexpr TDuration PEDING_REQUEST_TIMEOUT = TDuration::Seconds(30);

static constexpr TStringBuf JWKS_URI = "jwks_uri";
static constexpr TStringBuf ISSUER = "issuer";
static constexpr TStringBuf KEYS = "keys";
static constexpr TStringBuf KID = "kid";
static constexpr TStringBuf X5C = "x5c";

template <typename TVerifier>
requires requires (TVerifier v) {
    { v.allow_algorithm(std::declval<jwt::algorithm::es256>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::es384>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::es512>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::hs256>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::hs384>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::hs512>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::ps256>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::ps384>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::ps512>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::rs256>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::rs384>) } -> std::template same_as<TVerifier&>;
    { v.allow_algorithm(std::declval<jwt::algorithm::rs512>) } -> std::template same_as<TVerifier&>;
}
static const std::unordered_map<TString, std::function<void(TVerifier&, const TString&)>> SUPPORTED_ALGORITHMS = {
    {"ES256", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::es256(pubkey.c_str())); }},
    {"ES384", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::es384(pubkey.c_str())); }},
    {"ES512", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::es512(pubkey.c_str())); }},
    {"HS256", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::hs256(pubkey.c_str())); }},
    {"HS384", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::hs384(pubkey.c_str())); }},
    {"HS512", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::hs512(pubkey.c_str())); }},
    {"PS256", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::ps256(pubkey.c_str())); }},
    {"PS384", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::ps384(pubkey.c_str())); }},
    {"PS512", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::ps512(pubkey.c_str())); }},
    {"RS256", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::rs256(pubkey.c_str())); }},
    {"RS384", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::rs384(pubkey.c_str())); }},
    {"RS512", [](TVerifier& v, const TString& pubkey) { return v.allow_algorithm(jwt::algorithm::rs512(pubkey.c_str())); }},
};


////////////////////////////////////////////////////////////////////////////////

struct TSslDestroy {
    static void Destroy(BIO* bio) {
        BIO_free(bio);
    }

    static void Destroy(X509* x509) {
        X509_free(x509);
    }

    static void Destroy(EVP_PKEY* pkey) {
        EVP_PKEY_free(pkey);
    }
};

using TBioHolder = THolder<BIO, TSslDestroy>;
using TX509Holder = THolder<X509, TSslDestroy>;
using TEvpPkeyHolder = THolder<EVP_PKEY, TSslDestroy>;

// Decode an x5c entry (base64-standard DER cert) and turn it into a PEM cert.
TString GetPublicKeyFromX5C(TStringBuf b64) {
    const auto cert = std::invoke([&]() -> TX509Holder {
        const auto decodedCert = Base64Decode(b64);
        const ui8* ptr = reinterpret_cast<const ui8*>(decodedCert.data());
        auto* x509 = d2i_X509(NULL, &ptr, decodedCert.size());
        if (x509 == nullptr) {
            ythrow yexception() << "d2i_X509 failed to read cert";
        }
        return TX509Holder{x509};
    });

    const auto pubkey = std::invoke([&]() -> TEvpPkeyHolder {
        auto* rawPubkey = X509_get_pubkey(cert.Get());
        if (rawPubkey == nullptr) {
            ythrow yexception() << "X509_get_pubkey failed";
        }
        return TEvpPkeyHolder{rawPubkey};
    });

    const auto pubkeyBio = std::invoke([&]() -> TBioHolder {
        auto* rawPubkeyBio = BIO_new(BIO_s_mem());
        if (rawPubkeyBio == nullptr) {
            ythrow yexception() << "BIO_new failed";
        }
        return TBioHolder{rawPubkeyBio};
    });

    if (PEM_write_bio_PUBKEY(pubkeyBio.Get(), pubkey.Get()) != 1) {
        ythrow yexception() << "PEM_write_bio_PUBKEY failed";
    }

    const char* pubkeyBuf = nullptr;
    const auto pubkeyLen = BIO_get_mem_data(pubkeyBio.Get(), &pubkeyBuf);
    if (pubkeyLen <= 0) {
        ythrow yexception() << "BIO_get_mem_data failed";
    }
    TString pubkeyStr(pubkeyBuf, pubkeyLen);

    return pubkeyStr;
}

TString GetPublicKey(const NJson::TJsonValue& jwk) {
    if (jwk.Has(X5C) && jwk[X5C].GetArray().size() > 0) {
        return GetPublicKeyFromX5C(jwk[X5C].GetArray()[0].GetString());
    }

    // TODO(vlad-serikov): think about building keys from algo params
    return "";
}

////////////////////////////////////////////////////////////////////////////////

TDuration RandomizeJitter(const TDuration& jitter) {
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<ui64> dist(jitter.MilliSeconds() / 2, jitter.MilliSeconds());

    const ui64 randomMs = dist(rng);
    return TDuration::MilliSeconds(randomMs);
}

// Decode the JWT *without* verifying signature to extract `iss` and `kid`.
bool PeekTokenHeader(const TString& token, TString& issuer, TString& kid) {
    try {
        auto decoded = jwt::decode(token);
        if (decoded.has_issuer()) {
            issuer = TString{decoded.get_issuer()};
        }
        if (decoded.has_key_id()) {
            kid = TString{decoded.get_key_id()};
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

////////////////////////////////////////////////////////////////////////////////
/// Actor implementation
////////////////////////////////////////////////////////////////////////////////

class TExternalIdpProvider : public NActors::TActorBootstrapped<TExternalIdpProvider> {
public:
    static constexpr NKikimrServices::TActivity::EType ActorActivityType() {
        return NKikimrServices::TActivity::EXTERNAL_IDP_PROVIDER_ACTOR;
    }

    TExternalIdpProvider(const NKikimrProto::TExternalIdpConfig::TExternalIdpSettings& config,
                         const NActors::TActorId& httpProxyId)
        : Config(config)
        , HttpProxyId(httpProxyId)
    {}

    void Bootstrap() {
        if (!HttpProxyId) {
            // Allow construction without an external proxy id - register one.
            HttpProxyId = Register(NHttp::CreateHttpProxy());
        }

        const auto jitter = TDuration::Parse(Config.GetJitter());
        DiscoveryRefresh = TRecurringPeriod{
            .Jitter = jitter,
            .Period = TDuration::Parse(Config.GetDiscoveryRefreshPeriod()),
            .Next = TInstant::Zero(),
            .InFlight = false,
        };
        JwksRefresh = TRecurringPeriod{
            .Jitter = jitter,
            .Period = TDuration::Parse(Config.GetJwksRefreshPeriod()),
            .Next = TInstant::Zero(),
            .InFlight = false,
        };
        AllowedClockSkew = TDuration::Parse(Config.GetAllowedClockSkew());

        BLOG_D("Initializing ExternalIdp"
                << " domain=" << Config.GetDomain()
                << " issuer=" << Config.GetIssuer()
                << " audience=" << Config.GetAudience()
                << " subjectClaimName=" << Config.GetSubjectClaimName()
                << " groupsClaimName=" << Config.GetGroupsClaimName()
                << " jitter=" << jitter.ToString()
                << " discoveryRfreshPeriod=" << DiscoveryRefresh.Period.ToString()
                << " jwksRefreshPeriod=" << JwksRefresh.Period.ToString()
                << " allowedClockSkew=" << AllowedClockSkew.ToString());

        // Fire initial discovery fetch.
        StartDiscoveryFetch();

        // Schedule periodic refresh.
        Schedule(REFRESH_PERIOD, new NActors::TEvents::TEvWakeup());

        Become(&TThis::StateWork);
    }

private:
    using TThis = TExternalIdpProvider;

    struct TPendingRequest {
        TString Key;
        TString Token;
        TString Database;

        TActorId Sender;
        TInstant Deadline;
    };

    struct TRecurringPeriod {
        TDuration Jitter;
        TDuration Period;
        TInstant Next;
        bool InFlight;
    };

    void StateWork(TAutoPtr<NActors::IEventHandle>& ev) {
        switch (ev->GetTypeRewrite()) {
            hFunc(TEvExternalIdpProvider::TEvAuthenticateRequest, Handle);
            hFunc(NHttp::TEvHttpProxy::TEvHttpIncomingResponse, Handle);
            cFunc(TEvents::TSystem::Wakeup, HandleWakeup);
        }
    }

////////////////////////////////////////////////////////////////////////////////
/// Authenticate request flow
////////////////////////////////////////////////////////////////////////////////

    void Handle(TEvExternalIdpProvider::TEvAuthenticateRequest::TPtr& ev) {
        const auto* msg = ev->Get();
        BLOG_T("Authenticate request key=" << msg->Key);

        TString issuer;
        TString kid;
        if (!PeekTokenHeader(msg->Token, issuer, kid)) {
            ReplyError(ev->Sender, msg->Key,
                       TEvExternalIdpProvider::EStatus::BAD_REQUEST,
                       "Token is not in correct format");
            return;
        }

        if (!Config.HasIssuer() || Config.GetIssuer().empty() || Config.GetIssuer() != issuer) {
            ReplyError(ev->Sender, msg->Key,
                       TEvExternalIdpProvider::EStatus::BAD_REQUEST,
                       TStringBuilder() << "No configured IdP matches issuer '" << issuer << "'");
            return;
        }

        if (kid.empty()) {
            ReplyError(ev->Sender, msg->Key,
                       TEvExternalIdpProvider::EStatus::BAD_REQUEST,
                       TStringBuilder() << "No kid was found in token for issuer '" << issuer << "'");
            return;
        }

        // If we don't yet know the JWKS URL or have no key for kid, queue request and refresh.
        if (JwksUrl.empty() || Keys.empty() || !Keys.contains(kid)) {
            BLOG_D("Queue authenticate request for IdP domain=" << Config.GetDomain()
                   << " key=" << msg->Key
                   << " (jwksUrl='" << JwksUrl << "',"
                   << " keys=" << Keys.size() << ","
                   << " kid='" << kid << "')");
            Pending.push_back(TPendingRequest{
                .Key = msg->Key,
                .Token = msg->Token,
                .Database = msg->Database,
                .Sender = ev->Sender,
                .Deadline = TActivationContext::Now() + PEDING_REQUEST_TIMEOUT,
            });

            if (JwksUrl.empty()) {
                StartDiscoveryFetch();
            } else {
                StartJwksFetch();
            }

            return;
        }

        DoValidate(ev->Sender, msg->Key, msg->Token, msg->Database);
    }

    void DoValidate(const TActorId& sender, const TString& key,
                    const TString& token, const TString& database) {
        try {
            auto decoded = jwt::decode(token);

            if (!decoded.has_key_id()) {
                ReplyError(sender, key,
                           TEvExternalIdpProvider::EStatus::UNAUTHORIZED,
                           TStringBuilder() << "No kid was found in token for issuer '" << Config.GetIssuer() << "'");
                return;
            }
            const TString kid = TString{decoded.get_key_id()};

            const TString* pem = nullptr;
            if (auto it = Keys.find(kid); it != Keys.end()) {
                pem = &it->second;
            }
            if (pem == nullptr) {
                ReplyError(sender, key,
                           TEvExternalIdpProvider::EStatus::UNAUTHORIZED,
                           TStringBuilder() << "No matching key for kid '" << kid << "'");
                return;
            }

            if (!decoded.has_algorithm()) {
                ReplyError(sender, key,
                           TEvExternalIdpProvider::EStatus::UNAUTHORIZED,
                           TStringBuilder() << "No algorightm was found in token for issuer '" << Config.GetIssuer() << "'");
                return;
            }
            const TString algorithm = TString{decoded.get_algorithm()};

            auto verifier = jwt::verify();
            verifier.leeway(AllowedClockSkew.Seconds());
            if (const auto it = SUPPORTED_ALGORITHMS<decltype(verifier)>.find(algorithm);
                it != SUPPORTED_ALGORITHMS<decltype(verifier)>.end()) {
                it->second(verifier, pem->c_str());
            } else {
                ReplyError(sender, key,
                           TEvExternalIdpProvider::EStatus::UNAUTHORIZED,
                           TStringBuilder() << "Unsupported JWT algorithm '" << algorithm << "'");
                return;
            }
            verifier.with_issuer(Config.GetIssuer());
            if (Config.HasAudience() && !Config.GetAudience().empty()) {
                verifier.with_audience(std::set<std::string>{database, Config.GetAudience()});
            } else {
                verifier.with_audience(database);
            }

            verifier.verify(decoded);

            // Build response.
            auto resp = MakeHolder<TEvExternalIdpProvider::TEvAuthenticateResponse>(key);
            resp->Status = TEvExternalIdpProvider::EStatus::SUCCESS;

            const TString subject = std::invoke([&]() {
                if (!Config.HasSubjectClaimName() || Config.GetSubjectClaimName().empty()) {
                    return TString{decoded.get_subject()};
                }
                if (!decoded.has_payload_claim(Config.GetSubjectClaimName())) {
                    return TString{};
                }
                const auto& claim = decoded.get_payload_claim(Config.GetSubjectClaimName());
                return (claim.get_type() == jwt::claim::type::string) ? TString{claim.as_string()} : TString{};
            });
            if (subject.empty()) {
                ReplyError(sender, key,
                           TEvExternalIdpProvider::EStatus::UNAUTHORIZED,
                           TStringBuilder() << "Token does not contain a custom subject claim '" << Config.GetSubjectClaimName() << "'");
                return;
            }
            resp->User = subject + "@" + Config.GetDomain();

            const TString groupsClaim = Config.GetGroupsClaimName();
            if (Config.HasGroupsClaimName() && !Config.GetGroupsClaimName().empty() && decoded.has_payload_claim(Config.GetGroupsClaimName())) {
                const auto& claim = decoded.get_payload_claim(Config.GetGroupsClaimName());
                if (claim.get_type() == jwt::claim::type::array) {
                    for (const auto& v : claim.as_array()) {
                        if (v.is<std::string>()) {
                            resp->Groups.push_back(TString{v.get<std::string>()} + "@" + Config.GetDomain());
                        }
                    }
                }
            }

            const auto exp = decoded.get_expires_at();
            resp->ExpiresAt = TInstant::Seconds(
                std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count());

            BLOG_T("Authenticate ok key=" << key << " user=" << resp->User);
            Send(sender, resp.Release());
        } catch (const jwt::token_verification_exception& e) {
            ReplyError(sender, key,
                       TEvExternalIdpProvider::EStatus::UNAUTHORIZED, e.what());
        } catch (const jwt::signature_verification_exception& e) {
            ReplyError(sender, key,
                       TEvExternalIdpProvider::EStatus::UNAUTHORIZED, e.what());
        } catch (const std::invalid_argument&) {
            ReplyError(sender, key,
                       TEvExternalIdpProvider::EStatus::BAD_REQUEST,
                       "Token is not in correct format");
        } catch (const std::exception& e) {
            ReplyError(sender, key,
                       TEvExternalIdpProvider::EStatus::UNAUTHORIZED, e.what());
        }
    }

////////////////////////////////////////////////////////////////////////////////
/// Discovery / JWKS HTTP fetches
////////////////////////////////////////////////////////////////////////////////

    void StartDiscoveryFetch() {
        if (DiscoveryRefresh.InFlight || Config.GetDiscoveryUrl().empty()) {
            return;
        }

        DiscoveryRefresh.InFlight = true;

        BLOG_D("Discovery fetch IdP domain=" << Config.GetDomain()
               << " url=" << Config.GetDiscoveryUrl());
        auto request = NHttp::THttpOutgoingRequest::CreateRequestGet(Config.GetDiscoveryUrl());
        Send(HttpProxyId, new NHttp::TEvHttpProxy::TEvHttpOutgoingRequest(request, HTTP_TIMEOUT));
    }

    void StartJwksFetch() {
        if (JwksRefresh.InFlight || JwksUrl.empty()) {
            return;
        }

        JwksRefresh.InFlight = true;

        BLOG_D("JWKS fetch IdP domain=" << Config.GetDomain() << " url=" << JwksUrl);
        auto request = NHttp::THttpOutgoingRequest::CreateRequestGet(JwksUrl);
        Send(HttpProxyId, new NHttp::TEvHttpProxy::TEvHttpOutgoingRequest(request, HTTP_TIMEOUT));
    }

    void Handle(NHttp::TEvHttpProxy::TEvHttpIncomingResponse::TPtr& ev) {
        const TString url = ev->Get()->Request ? TString{ev->Get()->Request->URL} : TString{};

        // Locate which IdP this response belongs to.
        if (DiscoveryRefresh.InFlight && Config.GetDiscoveryUrl() == url) {
            DiscoveryRefresh.InFlight = false;
            HandleDiscoveryResponse(ev->Get());
            return;
        }

        if (JwksRefresh.InFlight && !JwksUrl.empty() && JwksUrl == url) {
            JwksRefresh.InFlight = false;
            HandleJwksResponse(ev->Get());
            return;
        }

        BLOG_W("Got unexpected HTTP response for domain=" << Config.GetDomain() << " url=" << url);
    }

    void HandleDiscoveryResponse(NHttp::TEvHttpProxy::TEvHttpIncomingResponse* ev) {
        if (const auto err = ev->GetError(); !err.empty()) {
            const TString msg = TStringBuilder() << "Discovery fetch failed: " << err;
            BLOG_W("IdP domain=" << Config.GetDomain() << " " << msg);
            FailPending(msg);
            return;
        }

        try {
            NJson::TJsonValue json;
            if (!NJson::ReadJsonTree(TString{ev->Response->Body}, &json)) {
                ythrow yexception() << "Invalid JSON in discovery response";
            }

            if (!Config.HasIssuer() || Config.GetIssuer().empty()) {
                ythrow yexception() << "Discovery failed with empty issuer in config";
            }

            if (!json.Has(JWKS_URI)) {
                ythrow yexception() << "Discovery document missing '" << JWKS_URI << "'";
            }
            JwksUrl = json[JWKS_URI].GetString();

            if (!json.Has(ISSUER) || Config.GetIssuer() != json[ISSUER].GetString()) {
                ythrow yexception() << "Discovery document mismatch '" << ISSUER << "'";
            }

            BLOG_D("Discovery ok IdP domain=" << Config.GetDomain()
                << " jwks_uri=" << JwksUrl
                << " issuer=" << Config.GetIssuer());

            DiscoveryRefresh.Next = TActivationContext::Now() + RandomizeJitter(DiscoveryRefresh.Jitter);
            StartJwksFetch();
        } catch (const std::exception& e) {
            const TString msg = TStringBuilder() << "Discovery parse error: " << e.what();
            BLOG_W("IdP domain=" << Config.GetDomain() << " " << msg);
            FailPending(msg);
        }
    }

    void HandleJwksResponse(NHttp::TEvHttpProxy::TEvHttpIncomingResponse* ev) {
        if (const auto err = ev->GetError(); !err.empty()) {
            const TString msg = TStringBuilder() << "JWKS fetch failed: " << err;
            BLOG_W("IdP domain=" << Config.GetDomain() << " " << msg);
            FailPending(msg);
            return;
        }

        try {
            NJson::TJsonValue json;
            if (!NJson::ReadJsonTree(TString{ev->Response->Body}, &json)) {
                ythrow yexception() << "Invalid JSON in JWKS response";
            }

            if (!json.Has(KEYS)) {
                ythrow yexception() << "JWKS document missing '" << KEYS << "'";
            }
            const auto& arr = json[KEYS].GetArray();

            // TODO(vlad-serikov): Think about parsing
            THashMap<TString, TString> newKeys;
            for (const auto& key : arr) {
                try {
                    if (!key.Has(KID)) {
                        BLOG_I("Skipping JWKS key without kid");
                        continue;
                    }
                    const TString kid = key[KID].GetString();
                    auto pubkey = GetPublicKey(key);
                    newKeys[kid] = std::move(pubkey);
                } catch (const std::exception& e) {
                    BLOG_W("Failed to parse JWKS key: " << e.what());
                }
            }
            if (newKeys.empty()) {
                ythrow yexception() << "No supported keys in JWKS response";
            }
            Keys = std::move(newKeys);
            JwksRefresh.Next = TActivationContext::Now() + RandomizeJitter(JwksRefresh.Jitter);
            BLOG_D("JWKS refreshed IdP domain=" << Config.GetDomain() << " keys=" << Keys.size());
            DrainPending();
        } catch (const std::exception& e) {
            const TString msg = TStringBuilder() << "JWKS parse error: " << e.what();
            BLOG_W("IdP domain=" << Config.GetDomain() << " " << msg);
            FailPending(msg);
        }
    }

////////////////////////////////////////////////////////////////////////////////
/// Periodic refresh
////////////////////////////////////////////////////////////////////////////////

    void HandleWakeup() {
        const TInstant now = TActivationContext::Now();

        if (JwksUrl.empty() || DiscoveryRefresh.Next >= now) {
            StartDiscoveryFetch();
        }

        if (JwksRefresh.Next >= now) {
            StartJwksFetch();
        }

        Schedule(REFRESH_PERIOD, new NActors::TEvents::TEvWakeup());
    }

////////////////////////////////////////////////////////////////////////////////
/// Request/Response handling
////////////////////////////////////////////////////////////////////////////////

    void DrainPending() {
        TVector<TPendingRequest> pending;
        pending.swap(Pending);
        const TInstant now = TActivationContext::Now();
        for (auto& p : pending) {
            if (p.Deadline < now) {
                ReplyError(p.Sender, p.Key,
                           TEvExternalIdpProvider::EStatus::UNAVAILABLE,
                           "Timeout while waiting for IdP keys", /*retryable=*/true);
                continue;
            }
            DoValidate(p.Sender, p.Key, p.Token, p.Database);
        }
    }

    void FailPending(const TString& message) {
        TVector<TPendingRequest> pending;
        pending.swap(Pending);
        for (auto& p : pending) {
            ReplyError(p.Sender, p.Key,
                       TEvExternalIdpProvider::EStatus::UNAVAILABLE,
                       message, /*retryable=*/true);
        }
    }

    void ReplyError(const TActorId& sender, const TString& key,
                    TEvExternalIdpProvider::EStatus status,
                    const TString& message, bool retryable = false) {
        auto resp = MakeHolder<TEvExternalIdpProvider::TEvAuthenticateResponse>(key);
        resp->Status = status;
        resp->Error.Message = message;
        resp->Error.Retryable = retryable;
        Send(sender, resp.Release());
    }

////////////////////////////////////////////////////////////////////////////////

    NKikimrProto::TExternalIdpConfig::TExternalIdpSettings Config;
    NActors::TActorId HttpProxyId;

    TRecurringPeriod DiscoveryRefresh;
    TRecurringPeriod JwksRefresh;
    TDuration AllowedClockSkew;

    TString JwksUrl;

    // kid -> PEM public key.
    THashMap<TString, TString> Keys;

    // Pending authentication requests waiting for keys.
    TVector<TPendingRequest> Pending;
};

} // namespace

////////////////////////////////////////////////////////////////////////////////

NActors::IActor* CreateExternalIdpProvider(const NKikimrProto::TExternalIdpConfig::TExternalIdpSettings& config,
                                           const NActors::TActorId& httpProxyId) {
    return new TExternalIdpProvider(config, httpProxyId);
}

} // namespace NKikimr
