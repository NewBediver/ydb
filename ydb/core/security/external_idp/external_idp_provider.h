#pragma once

#include <ydb/core/base/defs.h>
#include <ydb/core/base/events.h>
#include <ydb/core/base/ticket_parser.h>
#include <ydb/core/protos/auth.pb.h>

#include <util/generic/string.h>
#include <util/generic/vector.h>

namespace NKikimr {

// TEvExternalIdpProvider is the public events interface for the ExternalIdpProvider actor.
//
// The actor is the analogue of AccessServiceValidator/LdapAuthProvider, but for external
// OIDC/OAuth2 IdPs. It owns the cache of OIDC discovery metadata and JSON Web Key Sets
// (JWKs) per configured IdP and performs JWT signature & claim validation entirely
// in-process (without contacting the IdP for every request).
//
// Typical flow inside TicketParser:
//   1. Bearer JWT arrives -> TicketParser sends TEvAuthenticateRequest
//   2. ExternalIdpProvider decodes token, picks the matching IdP by `iss` claim,
//      validates signature against cached JWKs (fetching them if missing/stale)
//      and validates standard claims (exp, nbf, aud, iss).
//   3. Provider replies with TEvAuthenticateResponse containing the user subject
//      and group claims.
//   4. On periodic refresh TicketParser issues another TEvAuthenticateRequest
//      with the same Ticket; the same validation runs (cache hot-path).
struct TEvExternalIdpProvider {
    enum EEv {
        // requests
        EvAuthenticateRequest = EventSpaceBegin(TKikimrEvents::ES_EXTERNAL_IDP_PROVIDER),

        // replies
        EvAuthenticateResponse = EventSpaceBegin(TKikimrEvents::ES_EXTERNAL_IDP_PROVIDER) + 512,

        EvEnd
    };

    static_assert(EvEnd < EventSpaceEnd(TKikimrEvents::ES_EXTERNAL_IDP_PROVIDER),
                  "expect EvEnd < EventSpaceEnd(TKikimrEvents::ES_EXTERNAL_IDP_PROVIDER)");

    enum class EStatus {
        SUCCESS,
        UNAVAILABLE,     // network or JWKS fetch error (retryable)
        UNAUTHORIZED,    // signature mismatch / invalid claims (permanent)
        BAD_REQUEST,     // malformed token / no matching IdP (permanent)
    };

    using TError = TEvTicketParser::TError;

    struct TEvAuthenticateRequest : TEventLocal<TEvAuthenticateRequest, EvAuthenticateRequest> {
        // Caller-provided opaque key used to correlate request with the
        // TTokenRecord stored inside TicketParser.
        TString Key;
        // The raw Bearer token.
        TString Token;
        // Optional database name (used for additional aud check).
        TString Database;

        TEvAuthenticateRequest(TString key, TString token, TString database)
            : Key(std::move(key))
            , Token(std::move(token))
            , Database(std::move(database))
        {}
    };

    struct TEvAuthenticateResponse : TEventLocal<TEvAuthenticateResponse, EvAuthenticateResponse> {
        TString Key;
        EStatus Status = EStatus::SUCCESS;
        TError Error;

        // Populated on success.
        TString User;            // SID built as "<sub>@<domain>"
        TVector<TString> Groups; // SIDs built as "<group>@<domain>"
        TInstant ExpiresAt;      // value of `exp` claim

        TEvAuthenticateResponse(TString key)
            : Key(std::move(key))
        {}

        TEvAuthenticateResponse(TString key, EStatus status, TError error)
            : Key(std::move(key))
            , Status(status)
            , Error(std::move(error))
        {}
    };
};

// Service id of the ExternalIdpProvider actor. Mirrors MakeLdapAuthProviderID().
inline NActors::TActorId MakeExternalIdpProviderID() {
    static const char name[12] = "extidp_prv\0";
    return NActors::TActorId(0, TStringBuf(name, 12));
}

// Factory function. Returns an actor that listens on TEvAuthenticateRequest and
// internally maintains discovery/JWKS caches per configured IdP.
//
// `httpProxyId` is the actor id of the http proxy used to fetch JWKS/discovery
// documents. It must remain alive for the life-time of the provider.
NActors::IActor* CreateExternalIdpProvider(const NKikimrProto::TExternalIdpConfig::TExternalIdpSettings& config,
                                           const NActors::TActorId& httpProxyId);

}
