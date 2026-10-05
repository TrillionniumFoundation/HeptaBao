//! Service is the serialization/commit owner for both auth and engine state.
//! Every request sees one post-ReadIndex identity snapshot; successful login
//! publishes the token and its alias/entity association in the same transaction.
use super::*;
use crate::auth::{AuthError, AuthResponse};

impl State {
    /// Retained/pending/all-namespace owners can carry private batch precision
    /// even when no corresponding service-token record remains.
    pub(super) fn has_token_api_precision_state(&self) -> bool {
        self.auth.has_token_api_precision_state()
            || self
                .engines
                .all_lease_owners()
                .into_iter()
                .chain(self.database.all_lease_owners())
                .any(|(_, owner)| {
                    owner
                        .batch_claims()
                        .is_some_and(|claims| claims.precision().is_some())
                })
    }

    /// Preserve unknown schemas for admission to reject; never normalize them
    /// into an older supported format. The all-namespace scan also finds safe
    /// material introduced by the current candidate before its first commit.
    pub(super) fn writer_schema(&self) -> u32 {
        if !supported_reader_schema(self.schema) {
            return self.schema;
        }
        let required = if self.engines.has_full_dn_crl_state() {
            EXTERNAL_PKI_FULL_DN_CRL_STATE_SCHEMA
        } else if self.engines.has_pki_url_state() {
            PKI_URLS_STATE_SCHEMA
        } else if self.engines.has_external_pki_signer_history() {
            EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA
        } else if self.engines.has_pki_role_names_state() {
            PKI_ROLE_NAMES_STATE_SCHEMA
        } else if self.has_namespace_batch_state() {
            NAMESPACE_BATCH_STATE_SCHEMA
        } else if self.engines.has_pki_signed_role_time_state() {
            PKI_SIGNED_ROLE_TIME_STATE_SCHEMA
        } else if self.engines.has_pki_role_time_state() {
            PKI_ROLE_TIME_STATE_SCHEMA
        } else if self.engines.has_pki_role_leaf_profile_state() {
            PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
        } else if self.engines.has_kubernetes_opaque_artifact_state() {
            KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA
        } else if self.auth.has_public_origin_state() {
            AUTH_PUBLIC_ORIGIN_STATE_SCHEMA
        } else if self.engines.has_pki_role_wildcard_state() {
            PKI_ROLE_WILDCARD_STATE_SCHEMA
        } else if self.engines.has_pki_role_bare_domain_state() {
            PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
        } else if self.engines.has_pki_role_any_name_state() {
            PKI_ROLE_ANY_NAME_STATE_SCHEMA
        } else if self.has_token_api_precision_state() {
            TOKEN_API_PRECISION_STATE_SCHEMA
        } else if self.namespaces.has_custody_state() || self.engines.has_namespace_record_custody()
        {
            NAMESPACE_CUSTODY_STATE_SCHEMA
        } else if self.auth.has_token_api_schema80_state() {
            TOKEN_ROLE_STATE_SCHEMA
        } else if self.engines.has_local_pki_intermediate_state() {
            LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA
        } else if self.engines.has_local_pki_crl_state() {
            LOCAL_PKI_CRL_STATE_SCHEMA
        } else if self.engines.has_local_pki_multi_issuer_state() {
            LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA
        } else if self.engines.has_local_pki_root_fields_state() {
            LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA
        } else if self.engines.has_local_pki_identifier_state() {
            LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
        } else if self.auth.has_indexed_recovery_wire() {
            INDEXED_RECOVERY_WIRE_STATE_SCHEMA
        } else if self.auth.has_recovery_state() {
            RECOVERY_CREDENTIAL_STATE_SCHEMA
        } else if self.engines.has_local_typed_pki_state() {
            LOCAL_TYPED_PKI_STATE_SCHEMA
        } else if self.engines.has_issuer_path_pki_state() {
            PKI_ISSUER_PATH_STATE_SCHEMA
        } else if self.engines.has_transit_byok_state() {
            TRANSIT_BYOK_STATE_SCHEMA
        } else if self.auth.has_jwt_pem_keyset_state() {
            JWT_PEM_KEYSET_STATE_SCHEMA
        } else if self.auth.has_jwt_user_claim_state() {
            JWT_USER_CLAIM_STATE_SCHEMA
        } else if self.engines.has_typed_external_pki_state() {
            TYPED_PKI_STATE_SCHEMA
        } else if self.engines.has_aad_bound_convergent_state() {
            AAD_BOUND_STATE_SCHEMA
        } else {
            CURRENT_STATE_SCHEMA
        };
        let required = if self.engines.has_sdk_state() {
            required.max(SDK_STORAGE_STATE_SCHEMA)
        } else {
            required
        };
        let required = if self.engines.has_sdk_response_header_state() {
            required.max(SDK_RESPONSE_HEADERS_STATE_SCHEMA)
        } else {
            required
        };
        let required = if self.engines.has_sdk_lease_state() {
            required.max(SDK_SECRET_LEASE_STATE_SCHEMA)
        } else {
            required
        };
        self.schema.max(required)
    }

    pub(super) fn validate_publication_schema(
        &self,
        previous: Option<&State>,
    ) -> Result<(), Response> {
        self.namespace_leases.validate()?;
        self.validate_namespace_batch_state()?;
        self.protected_state()?
            .auth
            .validate_public_origin_state()
            .map_err(|_| Response::error(503, "invalid public origin protected owner"))?;
        if let Some(previous) = previous {
            self.protected_state()?
                .auth
                .validate_namespace_batch_successor(&previous.protected_state()?.auth)
                .map_err(|error| Response::error(error.status, &error.message))?;
            self.protected_state()?
                .auth
                .validate_public_origin_successor(&previous.protected_state()?.auth)
                .map_err(|_| Response::error(503, "public origin floor cannot retire"))?;
            self.protected_state()?
                .namespaces
                .validate_custody_successor(&previous.protected_state()?.namespaces)?;
        }

        if !supported_reader_schema(self.schema) {
            return Err(Response::error(
                503,
                "unsupported or downgraded identity state schema",
            ));
        }
        self.engines
            .validate_sdk_lease_clock(previous.map(|state| &*state.engines))
            .map_err(|error| Response::error(503, &error.message))?;
        self.engines
            .validate_kubernetes_artifact_clock(previous.map(|state| &*state.engines))
            .map_err(|error| Response::error(503, &error.message))?;
        self.auth
            .validate_token_api_clock_floor(previous.map(|state| &*state.auth))
            .map_err(|error| Response::error(503, &error.message))?;
        if self.schema < NAMESPACE_BATCH_STATE_SCHEMA
            && (self.has_namespace_batch_state()
                || previous.is_some_and(|old| old.schema >= NAMESPACE_BATCH_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "namespace batch lifecycle requires schema 91",
            ));
        }
        if self.schema < TOKEN_API_PRECISION_STATE_SCHEMA
            && (self.has_token_api_precision_state()
                || previous.is_some_and(|state| {
                    state.has_token_api_precision_state()
                        || state.schema >= TOKEN_API_PRECISION_STATE_SCHEMA
                }))
        {
            return Err(Response::error(
                503,
                "Token API precise lease publication requires schema 82",
            ));
        }
        if self.schema < KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA
            && (self.engines.has_kubernetes_opaque_artifact_state()
                || previous
                    .is_some_and(|state| state.schema >= KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "opaque Kubernetes artifact ownership requires schema 87",
            ));
        }
        if self.schema < PKI_URLS_STATE_SCHEMA
            && (self.engines.has_pki_url_state()
                || previous.is_some_and(|state| state.schema >= PKI_URLS_STATE_SCHEMA))
        {
            return Err(Response::error(503, "PKI URL ownership requires schema 97"));
        }
        if self.schema < EXTERNAL_PKI_FULL_DN_CRL_STATE_SCHEMA
            && (self.engines.has_full_dn_crl_state()
                || previous
                    .is_some_and(|state| state.schema >= EXTERNAL_PKI_FULL_DN_CRL_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "external full-DN CRL semantics require schema 98",
            ));
        }
        if self.schema < EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA
            && (self.engines.has_external_pki_signer_history()
                || previous
                    .is_some_and(|state| state.schema >= EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "external PKI signer history requires schema 94",
            ));
        }
        if self.schema < PKI_ROLE_NAMES_STATE_SCHEMA
            && (self.engines.has_pki_role_names_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_NAMES_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI role name ownership requires schema 93",
            ));
        }
        if self.schema < SDK_SECRET_LEASE_STATE_SCHEMA
            && (self.engines.has_sdk_lease_state()
                || previous.is_some_and(|state| state.schema >= SDK_SECRET_LEASE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "SDK secret lease ownership requires schema 96",
            ));
        }
        if self.schema < SDK_RESPONSE_HEADERS_STATE_SCHEMA
            && (self.engines.has_sdk_response_header_state()
                || previous.is_some_and(|state| state.schema >= SDK_RESPONSE_HEADERS_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "SDK response header ownership requires schema 95",
            ));
        }
        if self.schema < SDK_STORAGE_STATE_SCHEMA
            && (self.engines.has_sdk_state()
                || previous.is_some_and(|state| state.schema >= SDK_STORAGE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "SDK catalog and storage ownership requires schema 92",
            ));
        }
        if self.schema < PKI_SIGNED_ROLE_TIME_STATE_SCHEMA
            && (self.engines.has_pki_signed_role_time_state()
                || previous.is_some_and(|state| state.schema >= PKI_SIGNED_ROLE_TIME_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI signed role time ownership requires schema 90",
            ));
        }
        if self.schema < PKI_ROLE_TIME_STATE_SCHEMA
            && (self.engines.has_pki_role_time_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_TIME_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI role time ownership requires schema 89",
            ));
        }
        if self.schema < PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
            && (self.engines.has_pki_role_leaf_profile_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI role leaf profiles require schema 88",
            ));
        }
        if self.schema < PKI_ROLE_WILDCARD_STATE_SCHEMA
            && (self.engines.has_pki_role_wildcard_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_WILDCARD_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI wildcard ownership requires schema 85",
            ));
        }
        if self.schema < PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
            && (self.engines.has_pki_role_bare_domain_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI base-domain ownership requires schema 84",
            ));
        }
        if self.schema < PKI_ROLE_ANY_NAME_STATE_SCHEMA
            && (self.engines.has_pki_role_any_name_state()
                || previous.is_some_and(|state| state.schema >= PKI_ROLE_ANY_NAME_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI allow_any_name ownership requires schema 83",
            ));
        }
        if self.schema < AUTH_PUBLIC_ORIGIN_STATE_SCHEMA
            && (self.auth.has_public_origin_state()
                || previous.is_some_and(|state| state.schema >= AUTH_PUBLIC_ORIGIN_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "native public origin requires schema 86",
            ));
        }
        if self.schema < NAMESPACE_CUSTODY_STATE_SCHEMA
            && (self.namespaces.has_custody_state()
                || self.engines.has_namespace_record_custody()
                || previous.is_some_and(|state| state.schema >= NAMESPACE_CUSTODY_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "independent namespace custody requires schema 81",
            ));
        }
        if self.schema < TOKEN_ROLE_STATE_SCHEMA
            && (self.auth.has_token_api_schema80_state()
                || previous.is_some_and(|state| state.schema >= TOKEN_ROLE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "Token API role ownership requires schema 80",
            ));
        }
        if self.schema < LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA
            && (self.engines.has_local_pki_intermediate_state()
                || previous
                    .is_some_and(|state| state.schema >= LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "local PKI intermediate ownership requires schema 79",
            ));
        }
        if self.schema < LOCAL_PKI_CRL_STATE_SCHEMA
            && (self.engines.has_local_pki_crl_state()
                || previous.is_some_and(|state| state.schema >= LOCAL_PKI_CRL_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "local PKI CRL state requires schema 78",
            ));
        }
        if self.schema < LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA
            && (self.engines.has_local_pki_multi_issuer_state()
                || previous
                    .is_some_and(|state| state.schema >= LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "local PKI issuer ownership requires schema 77",
            ));
        }
        if self.schema < LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA
            && (self.engines.has_local_pki_root_fields_state()
                || previous.is_some_and(|state| state.schema >= LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "local PKI root fields require schema 76",
            ));
        }
        if self.schema < RECOVERY_CREDENTIAL_STATE_SCHEMA
            && (self.auth.has_recovery_state()
                || previous.is_some_and(|state| state.schema >= RECOVERY_CREDENTIAL_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "protected recovery credential requires schema 73",
            ));
        }
        if self.schema < LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && (self.engines.has_local_pki_identifier_state()
                || previous.is_some_and(|state| state.schema >= LOCAL_PKI_IDENTIFIER_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "local PKI identifiers require schema 75",
            ));
        }
        if self.schema < INDEXED_RECOVERY_WIRE_STATE_SCHEMA
            && (self.auth.has_indexed_recovery_wire()
                || previous.is_some_and(|state| state.schema >= INDEXED_RECOVERY_WIRE_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "indexed recovery wire requires schema 74",
            ));
        }
        self.auth
            .validate_recovery_credential(&self.cluster_id)
            .map_err(|_| Response::error(503, "invalid protected recovery credential"))?;
        if let Some(previous) = previous {
            self.auth
                .validate_recovery_publication(&previous.auth, &self.cluster_id)
                .map_err(|_| Response::error(503, "recovery authority publication rejected"))?;
        }
        if self.schema < LOCAL_TYPED_PKI_STATE_SCHEMA
            && (self.engines.has_local_typed_pki_state()
                || previous.is_some_and(|state| state.schema >= LOCAL_TYPED_PKI_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "typed local PKI keys require schema 72",
            ));
        }
        if self.schema < PKI_ISSUER_PATH_STATE_SCHEMA
            && (self.engines.has_issuer_path_pki_state()
                || previous.is_some_and(|state| state.schema >= PKI_ISSUER_PATH_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "PKI issuer-path leases require schema 71",
            ));
        }
        if self.schema < TRANSIT_BYOK_STATE_SCHEMA
            && (self.engines.has_transit_byok_state()
                || previous.is_some_and(|state| state.schema >= TRANSIT_BYOK_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "Transit imports and wrapping keys require schema 70",
            ));
        }
        if self.schema < JWT_PEM_KEYSET_STATE_SCHEMA
            && (self.auth.has_jwt_pem_keyset_state()
                || previous.is_some_and(|state| state.schema >= JWT_PEM_KEYSET_STATE_SCHEMA))
        {
            return Err(Response::error(503, "JWT PEM keyset requires schema 69"));
        }
        if self.schema < JWT_USER_CLAIM_STATE_SCHEMA
            && (self.auth.has_jwt_user_claim_state()
                || previous.is_some_and(|state| state.schema >= JWT_USER_CLAIM_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "custom JWT identity claims require schema 68",
            ));
        }
        if self.schema < TYPED_PKI_STATE_SCHEMA
            && (self.engines.has_typed_external_pki_state()
                || previous.is_some_and(|state| state.schema >= TYPED_PKI_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "typed external PKI public keys require schema 67",
            ));
        }
        if self.schema < AAD_BOUND_STATE_SCHEMA
            && (self.engines.has_aad_bound_convergent_state()
                || previous.is_some_and(|state| state.schema >= AAD_BOUND_STATE_SCHEMA))
        {
            return Err(Response::error(
                503,
                "AAD-bound convergent keys require schema 66",
            ));
        }
        if previous.is_some_and(|state| {
            !supported_reader_schema(state.schema) || self.schema < state.schema
        }) {
            return Err(Response::error(
                503,
                "identity state schema cannot decrease",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_format(&self) -> Result<(), Response> {
        self.validate_namespace_batch_state()?;
        self.engines
            .validate_sdk_lease_cluster(&self.cluster_id)
            .map_err(|e| Response::error(503, &e.message))?;
        self.engines
            .validate_sdk_leases()
            .map_err(|e| Response::error(503, &e.message))?;
        if self.schema < SDK_SECRET_LEASE_STATE_SCHEMA && self.engines.has_sdk_lease_state() {
            return Err(Response::error(
                503,
                "SDK secret lease ownership requires schema 96",
            ));
        }
        if self
            .engines
            .sdk_lease_owners()
            .iter()
            .any(|(namespace, owner)| {
                owner.batch_claims().is_some_and(|claims| {
                    self.auth
                        .validate_batch_lease_owner(claims, namespace)
                        .is_err()
                })
            })
        {
            return Err(Response::error(503, "SDK lease issuer rejected"));
        }

        self.engines
            .validate_sdk_state()
            .map_err(|e| Response::error(503, &e.message))?;
        if self.schema < SDK_RESPONSE_HEADERS_STATE_SCHEMA
            && self.engines.has_sdk_response_header_state()
        {
            return Err(Response::error(
                503,
                "SDK response header ownership requires schema 95",
            ));
        }
        if self.schema < SDK_STORAGE_STATE_SCHEMA && self.engines.has_sdk_state() {
            return Err(Response::error(
                503,
                "SDK catalog and storage ownership requires schema 92",
            ));
        }
        self.auth
            .validate_public_origin_state()
            .map_err(|_| Response::error(503, "invalid public origin owner"))?;
        if self.schema == AUTH_PUBLIC_ORIGIN_STATE_SCHEMA && !self.auth.has_public_origin_state() {
            return Err(Response::error(
                503,
                "public origin retirement floor is missing",
            ));
        }
        if self.schema < AUTH_PUBLIC_ORIGIN_STATE_SCHEMA && self.auth.has_public_origin_state() {
            return Err(Response::error(
                503,
                "native public origin requires schema 86",
            ));
        }
        if !supported_reader_schema(self.schema) {
            return Err(Response::error(
                503,
                "unsupported or downgraded identity state schema",
            ));
        }
        if self.schema < PKI_URLS_STATE_SCHEMA && self.engines.has_pki_url_state() {
            return Err(Response::error(503, "PKI URL ownership requires schema 97"));
        }
        if self.schema < EXTERNAL_PKI_FULL_DN_CRL_STATE_SCHEMA
            && self.engines.has_full_dn_crl_state()
        {
            return Err(Response::error(
                503,
                "external full-DN CRL semantics require schema 98",
            ));
        }
        if self.schema < EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA
            && self.engines.has_external_pki_signer_history()
        {
            return Err(Response::error(
                503,
                "external PKI signer history requires schema 94",
            ));
        }
        if self.schema < PKI_ROLE_NAMES_STATE_SCHEMA && self.engines.has_pki_role_names_state() {
            return Err(Response::error(
                503,
                "PKI role name ownership requires schema 93",
            ));
        }
        if self.schema < PKI_SIGNED_ROLE_TIME_STATE_SCHEMA
            && self.engines.has_pki_signed_role_time_state()
        {
            return Err(Response::error(
                503,
                "PKI signed role time ownership requires schema 90",
            ));
        }
        if self.schema < PKI_ROLE_TIME_STATE_SCHEMA && self.engines.has_pki_role_time_state() {
            return Err(Response::error(
                503,
                "PKI role time ownership requires schema 89",
            ));
        }
        if self.schema < PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
            && self.engines.has_pki_role_leaf_profile_state()
        {
            return Err(Response::error(
                503,
                "PKI role leaf profiles require schema 88",
            ));
        }
        if self.schema < PKI_ROLE_WILDCARD_STATE_SCHEMA
            && self.engines.has_pki_role_wildcard_state()
        {
            return Err(Response::error(
                503,
                "PKI wildcard ownership requires schema 85",
            ));
        }
        if self.schema < PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
            && self.engines.has_pki_role_bare_domain_state()
        {
            return Err(Response::error(
                503,
                "PKI base-domain ownership requires schema 84",
            ));
        }
        if self.schema < PKI_ROLE_ANY_NAME_STATE_SCHEMA
            && self.engines.has_pki_role_any_name_state()
        {
            return Err(Response::error(
                503,
                "PKI allow_any_name ownership requires schema 83",
            ));
        }
        self.auth
            .validate_token_api_precision_state()
            .map_err(|error| Response::error(503, &error.message))?;
        if self.has_token_api_precision_state() && !self.auth.has_token_api_precision_state() {
            return Err(Response::error(
                503,
                "private precise lease owners require an observation floor",
            ));
        }
        if self.schema < TOKEN_API_PRECISION_STATE_SCHEMA && self.has_token_api_precision_state() {
            return Err(Response::error(
                503,
                "Token API precise lease reader requires schema 82",
            ));
        }
        if self.schema < NAMESPACE_CUSTODY_STATE_SCHEMA
            && (self.namespaces.has_custody_state() || self.engines.has_namespace_record_custody())
        {
            return Err(Response::error(
                503,
                "independent namespace custody requires schema 81",
            ));
        }
        self.auth
            .validate_token_role_state()
            .map_err(|error| Response::error(503, &error.message))?;
        if self.schema < KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA
            && self.engines.has_kubernetes_opaque_artifact_state()
        {
            return Err(Response::error(
                503,
                "opaque Kubernetes artifact ownership requires schema 87",
            ));
        }
        if self.schema < TOKEN_ROLE_STATE_SCHEMA && self.auth.has_token_api_schema80_state() {
            return Err(Response::error(
                503,
                "Token API role ownership requires schema 80",
            ));
        }
        if self.schema < LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA
            && self.engines.has_local_pki_intermediate_state()
        {
            return Err(Response::error(
                503,
                "local PKI intermediate ownership requires schema 79",
            ));
        }
        if self.schema < LOCAL_PKI_CRL_STATE_SCHEMA && self.engines.has_local_pki_crl_state() {
            return Err(Response::error(
                503,
                "local PKI CRL state requires schema 78",
            ));
        }
        if self.schema < LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA
            && self.engines.has_local_pki_multi_issuer_state()
        {
            return Err(Response::error(
                503,
                "local PKI issuer ownership requires schema 77",
            ));
        }
        if self.schema < LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA
            && self.engines.has_local_pki_root_fields_state()
        {
            return Err(Response::error(
                503,
                "local PKI root fields require schema 76",
            ));
        }
        if self.schema < RECOVERY_CREDENTIAL_STATE_SCHEMA && self.auth.has_recovery_state() {
            return Err(Response::error(
                503,
                "protected recovery credential requires schema 73",
            ));
        }
        if self.schema < LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && self.engines.has_local_pki_identifier_state()
        {
            return Err(Response::error(
                503,
                "local PKI identifiers require schema 75",
            ));
        }
        if self.schema < INDEXED_RECOVERY_WIRE_STATE_SCHEMA && self.auth.has_indexed_recovery_wire()
        {
            return Err(Response::error(
                503,
                "indexed recovery wire requires schema 74",
            ));
        }
        self.auth
            .validate_recovery_credential(&self.cluster_id)
            .map_err(|_| Response::error(503, "invalid protected recovery credential"))?;
        if self.schema < LOCAL_TYPED_PKI_STATE_SCHEMA && self.engines.has_local_typed_pki_state() {
            return Err(Response::error(
                503,
                "typed local PKI keys require schema 72",
            ));
        }
        if self.schema < PKI_ISSUER_PATH_STATE_SCHEMA && self.engines.has_issuer_path_pki_state() {
            return Err(Response::error(
                503,
                "PKI issuer-path leases require schema 71",
            ));
        }
        if self.schema < TRANSIT_BYOK_STATE_SCHEMA && self.engines.has_transit_byok_state() {
            return Err(Response::error(
                503,
                "Transit imports and wrapping keys require schema 70",
            ));
        }
        self.engines
            .validate_transit_byok_state()
            .map_err(|_| Response::error(503, "invalid Transit imported key state"))?;
        if self.schema < JWT_PEM_KEYSET_STATE_SCHEMA && self.auth.has_jwt_pem_keyset_state() {
            return Err(Response::error(503, "JWT PEM keyset requires schema 69"));
        }
        self.auth
            .validate_jwt_pem_keyset_state()
            .map_err(|_| Response::error(503, "invalid JWT PEM keyset state"))?;
        if self.schema < JWT_USER_CLAIM_STATE_SCHEMA && self.auth.has_jwt_user_claim_state() {
            return Err(Response::error(
                503,
                "custom JWT identity claims require schema 68",
            ));
        }
        self.auth
            .validate_jwt_user_claim_state()
            .map_err(|_| Response::error(503, "invalid JWT identity claim state"))?;
        if self.schema < TYPED_PKI_STATE_SCHEMA && self.engines.has_typed_external_pki_state() {
            return Err(Response::error(
                503,
                "typed external PKI public keys require schema 67",
            ));
        }
        if self.schema < AAD_BOUND_STATE_SCHEMA && self.engines.has_aad_bound_convergent_state() {
            return Err(Response::error(
                503,
                "AAD-bound convergent keys require schema 66",
            ));
        }
        self.engines
            .validate_aad_bound_convergent_state()
            .map_err(|_| Response::error(503, "invalid AAD-bound convergent key state"))?;
        if self.schema < 65 && self.engines.has_asymmetric_state() {
            return Err(Response::error(
                503,
                "asymmetric Transit keys require schema 65",
            ));
        }
        if self.schema < 65 && self.engines.has_external_pki_state() {
            return Err(Response::error(
                503,
                "PKI external roots and CSR keys require schema 65",
            ));
        }
        if self.schema < 64 && self.engines.has_external_transit_state() {
            return Err(Response::error(
                503,
                "Transit external keys require schema 64",
            ));
        }
        self.engines
            .validate_external_transit_state()
            .map_err(|_| Response::error(503, "invalid Transit external key state"))?;
        if self.schema < 63 && self.engines.has_external_key_state() {
            return Err(Response::error(
                503,
                "External Keys registry requires schema 63",
            ));
        }
        self.engines
            .validate_external_key_state()
            .map_err(|_| Response::error(503, "invalid External Keys registry"))?;

        if self.schema < 62 && self.engines.has_mldsa_state() {
            return Err(Response::error(
                503,
                "Transit ML-DSA keys require schema 62",
            ));
        }
        self.engines
            .validate_mldsa_state()
            .map_err(|_| Response::error(503, "invalid Transit ML-DSA state"))?;

        self.engines
            .validate_record_mode()
            .map_err(|e| Response::error(503, &e.message))?;
        if self.schema < 36 && self.engines.record_root().is_some() {
            return Err(Response::error(503, "record KV1 requires schema 36"));
        }

        if self.schema < 37 && self.engines.has_packed_kv1_records() {
            return Err(Response::error(503, "packed KV1 records require schema 37"));
        }

        if self.schema < 42 && self.engines.has_kubernetes_typed_lease_owners() {
            return Err(Response::error(
                503,
                "Kubernetes typed lease ownership requires schema 42",
            ));
        }

        if self.schema < 50 && self.auth.has_kerberos_state() {
            return Err(Response::error(
                503,
                "Kerberos authentication state requires schema 50",
            ));
        }
        if self.schema < 51 && self.auth.has_oidc_userinfo_state() {
            return Err(Response::error(
                503,
                "OIDC UserInfo session state requires schema 51",
            ));
        }
        self.auth
            .validate_acl_wrapping_ttl_state()
            .map_err(|_| Response::error(503, "invalid ACL wrapping TTL state"))?;
        if self.schema < 61 && self.auth.has_acl_wrapping_ttl_state() {
            return Err(Response::error(
                503,
                "ACL wrapping TTL constraints require schema 61",
            ));
        }
        self.auth
            .validate_acl_template_state()
            .map_err(|_| Response::error(503, "invalid ACL Identity template state"))?;
        if self.schema < 60 && self.auth.has_acl_template_state() {
            return Err(Response::error(
                503,
                "ACL Identity templates require schema 60",
            ));
        }
        self.auth
            .validate_acl_parameter_state()
            .map_err(|_| Response::error(503, "invalid ACL parameter policy state"))?;
        if self.schema < 58 && self.auth.has_acl_parameter_state() {
            return Err(Response::error(
                503,
                "ACL parameter constraints require schema 58",
            ));
        }

        self.auth
            .validate_password_policy_state()
            .map_err(|_| Response::error(503, "invalid password policy state"))?;
        if self.schema < 56 && self.auth.has_password_policy_state() {
            return Err(Response::error(
                503,
                "password policy state requires schema 56",
            ));
        }

        if self.schema < 48 && self.auth.has_cert_batch_state() {
            return Err(Response::error(
                503,
                "native certificate token state requires schema 48",
            ));
        }
        if self.schema < 48 && self.auth.has_token_api_creation_ttl() {
            return Err(Response::error(
                503,
                "Token API creation TTL requires schema 48",
            ));
        }

        self.auth
            .validate_system_lease_defaults()
            .map_err(|_| Response::error(503, "invalid system or Token API lease state"))?;
        self.auth
            .validate_batch_issuance_state()
            .map_err(|_| Response::error(503, "invalid batch token key authority"))?;
        if self.schema < 41
            && (self.auth.has_batch_authority() || self.auth.has_batch_issuance_state())
        {
            return Err(Response::error(
                503,
                "batch token authority requires schema 41",
            ));
        }
        self.auth
            .validate_approle_batch_state()
            .map_err(|_| Response::error(503, "invalid AppRole batch configuration"))?;
        if self.schema < 42 && self.auth.has_approle_batch_state() {
            return Err(Response::error(
                503,
                "AppRole batch configuration requires schema 42",
            ));
        }
        self.auth
            .validate_approle_token_bound_cidrs()
            .map_err(|_| Response::error(503, "invalid AppRole token source constraints"))?;
        if self.schema < 43 && self.auth.has_approle_token_bound_cidrs() {
            return Err(Response::error(
                503,
                "AppRole token source constraints require schema 43",
            ));
        }
        if self.schema < 45 && self.auth.has_approle_secret_bound_cidrs() {
            return Err(Response::error(
                503,
                "AppRole SecretID login source constraints require schema 45",
            ));
        }
        if self.schema < 46 && self.auth.has_approle_secret_id_cidrs() {
            return Err(Response::error(
                503,
                "AppRole per-SecretID CIDR constraints require schema 46",
            ));
        }
        if self.schema < 47
            && (self.auth.has_approle_metadata()
                || self.engines.has_approle_login_alias_metadata_state()
                || self.engines.has_extended_login_alias_metadata_state())
        {
            return Err(Response::error(
                503,
                "AppRole credential or alias metadata requires schema 47",
            ));
        }
        self.auth
            .validate_approle_metadata()
            .map_err(|_| Response::error(503, "invalid AppRole credential metadata"))?;
        if self.schema < 47 && self.engines.has_nullable_identity_metadata_state() {
            return Err(Response::error(
                503,
                "nullable Identity metadata requires schema 47",
            ));
        }
        self.auth
            .validate_approle_native_defaults()
            .map_err(|_| Response::error(503, "invalid native AppRole state"))?;
        self.auth
            .validate_jwt_batch_state()
            .map_err(|_| Response::error(503, "invalid JWT batch configuration"))?;
        if self.schema < 44
            && (self.auth.has_jwt_batch_state() || self.engines.has_login_alias_metadata_state())
        {
            return Err(Response::error(
                503,
                "JWT token type or login alias metadata requires schema 44",
            ));
        }
        self.auth
            .validate_userpass_name_modes()
            .map_err(|_| Response::error(503, "invalid userpass name mode"))?;
        if self.schema < 40 && self.auth.has_userpass_name_modes() {
            return Err(Response::error(
                503,
                "userpass name modes require schema 40",
            ));
        }
        self.auth
            .validate_userpass_password_semantics()
            .map_err(|_| Response::error(503, "invalid userpass password comparison semantics"))?;
        if self.schema < 38 && self.auth.has_userpass_password_semantics() {
            return Err(Response::error(
                503,
                "userpass password comparison semantics require schema 38",
            ));
        }
        self.auth
            .validate_userpass_no_default_policy()
            .map_err(|_| Response::error(503, "invalid userpass default-policy state"))?;
        if self.schema < 39 && self.auth.has_userpass_no_default_policy() {
            return Err(Response::error(
                503,
                "userpass default-policy semantics require schema 39",
            ));
        }
        self.auth
            .validate_userpass_token_bound_cidrs()
            .map_err(|_| Response::error(503, "invalid userpass source constraints"))?;
        if self.schema < 39 && self.auth.has_userpass_token_bound_cidrs() {
            return Err(Response::error(
                503,
                "userpass source constraints require schema 39",
            ));
        }
        self.auth
            .validate_userpass_native_tokens()
            .map_err(|_| Response::error(503, "invalid native userpass state"))?;
        self.auth
            .validate_userpass_lockout_state()
            .map_err(|_| Response::error(503, "invalid userpass lockout state"))?;
        if self.schema < 52 && self.auth.has_userpass_lockout_state() {
            return Err(Response::error(
                503,
                "userpass lockout state requires schema 52",
            ));
        }
        self.engines
            .validate_identity_alias_state()
            .map_err(|e| Response::error(503, &e.message))?;
        self.engines
            .validate_lease_state()
            .map_err(|e| Response::error(503, &e.message))?;
        self.auth
            .validate_wrapping_state()
            .map_err(|_| Response::error(503, "invalid wrapping state"))?;
        self.database.validate_scope(&self.cluster_id)?;
        // Retained, expired and pending owners must also be admitted. Liveness
        // belongs to reconciliation; a missing key or foreign namespace is a
        // state-integrity error even when no lease is currently active.
        for (namespace, owner) in self
            .engines
            .all_lease_owners()
            .into_iter()
            .chain(self.database.all_lease_owners())
        {
            if let Some(claims) = owner.batch_claims() {
                if self.schema < 41 {
                    return Err(Response::error(
                        503,
                        "batch lease ownership requires schema 41",
                    ));
                }
                self.auth
                    .validate_batch_lease_owner(claims, &namespace)
                    .map_err(|_| Response::error(503, "invalid batch lease authority"))?;
            }
        }
        self.raft_admin.validate()?;
        self.auth
            .validate_online_auth()
            .map_err(|_| Response::error(503, "invalid online authentication state"))?;
        self.auth
            .validate_plugin_auth_state()
            .map_err(|_| Response::error(503, "invalid authentication plugin state"))?;
        self.auth
            .validate_radius_renewal_state()
            .map_err(|_| Response::error(503, "invalid RADIUS renewal state"))?;
        self.auth
            .validate_ldap_renewal_state()
            .map_err(|_| Response::error(503, "invalid LDAP renewal state"))?;
        self.auth
            .validate_jwt_renewal_state()
            .map_err(|_| Response::error(503, "invalid JWT renewal state"))?;
        self.auth
            .validate_native_jwt_state()
            .map_err(|_| Response::error(503, "invalid native JWT state"))?;
        self.auth
            .validate_kubernetes_renewal_state()
            .map_err(|_| Response::error(503, "invalid Kubernetes renewal state"))?;
        self.auth
            .validate_oidc_renewal_state()
            .map_err(|_| Response::error(503, "invalid OIDC renewal state"))?;
        if self.schema < 5 && self.auth.has_online_auth_state() {
            return Err(Response::error(
                503,
                "online authentication requires schema 5",
            ));
        }
        if self.schema < 5 && self.replay_epoch != 0 {
            return Err(Response::error(503, "replay epoch state requires schema 5"));
        }
        if self.schema < 6 && self.database.has_provider_fence() {
            return Err(Response::error(
                503,
                "database provider fencing requires schema 6",
            ));
        }
        if self.schema < 53 && self.database.has_credential_rotation_state() {
            return Err(Response::error(
                503,
                "database credential rotation requires schema 53",
            ));
        }
        if self.schema < 54 && self.database.has_statement_template_state() {
            return Err(Response::error(
                503,
                "database statement templates require schema 54",
            ));
        }
        if self.schema < 55 && self.database.has_scram_password_authentication() {
            return Err(Response::error(
                503,
                "PostgreSQL SCRAM password authentication requires schema 55",
            ));
        }
        if self.schema < 56 && self.database.has_password_generation_state() {
            return Err(Response::error(
                503,
                "database password policies and username templates require schema 56",
            ));
        }
        if self.schema < 57 && self.database.has_root_rotation_statement_state() {
            return Err(Response::error(
                503,
                "database root rotation statements require schema 57",
            ));
        }
        if self.schema < 59 && self.engines.has_pki_extension_state() {
            return Err(Response::error(
                503,
                "PKI cluster or ACME configuration requires schema 59",
            ));
        }
        if self.schema < 7 && self.auth.has_ldap_group_state() {
            return Err(Response::error(
                503,
                "LDAP group synchronization requires schema 7",
            ));
        }
        if self.schema < 8 && self.engines.has_kubernetes_mount() {
            return Err(Response::error(
                503,
                "Kubernetes TokenRequest secrets state requires schema 8",
            ));
        }
        self.engines
            .validate_kubernetes_state()
            .map_err(|error| Response::error(503, &error.message))?;
        self.engines
            .validate_openldap_state()
            .map_err(|error| Response::error(503, &error.message))?;
        if self.schema < 9 && !self.namespaces.is_empty() {
            return Err(Response::error(
                503,
                "explicit namespace catalog requires schema 9",
            ));
        }
        if self.schema < 49 && self.namespaces.workflows.has_workflows() {
            return Err(Response::error(
                503,
                "authenticated workflow state requires schema 49",
            ));
        }
        self.namespaces.validate(&self.cluster_id)?;
        self.engines
            .visit_namespace_record_owner_bindings(|binding| {
                self.namespaces
                    .validate_record_custody_binding(binding)
                    .map_err(|_| crate::engines::EngineError {
                        status: 503,
                        message: "namespace record floor binding rejected".into(),
                    })
            })
            .map_err(|_| Response::error(503, "namespace record floor binding rejected"))?;
        if self.schema < 10 && self.auth.has_plugin_auth_state() {
            return Err(Response::error(
                503,
                "authentication plugin state requires schema 10",
            ));
        }
        if self.schema < 11 && self.auth.has_approle_token_provenance() {
            return Err(Response::error(
                503,
                "AppRole renewal provenance requires schema 11",
            ));
        }
        if self.schema < 12 && self.auth.has_radius_state() {
            return Err(Response::error(
                503,
                "RADIUS authentication state requires schema 12",
            ));
        }
        if self.schema < 13 && self.namespaces.has_sealed_state() {
            return Err(Response::error(
                503,
                "namespace seal state requires schema 13",
            ));
        }
        if self.schema < 14 && self.engines.has_openldap_mount() {
            return Err(Response::error(
                503,
                "OpenLDAP dynamic credential state requires schema 14",
            ));
        }
        if self.schema < 15 && self.engines.has_metadata_cas_state() {
            return Err(Response::error(
                503,
                "KV metadata CAS state requires schema 15",
            ));
        }
        if self.schema < 16 && self.auth.has_v16_token_provenance() {
            return Err(Response::error(
                503,
                "RADIUS renewal and token API provenance require schema 16",
            ));
        }
        if self.schema < 17
            && (self.auth.has_ldap_renewal_provenance()
                || self.engines.has_external_group_membership())
        {
            return Err(Response::error(
                503,
                "LDAP renewal and external group evidence require schema 17",
            ));
        }
        if self.schema < 18 && self.auth.has_jwt_renewal_state() {
            return Err(Response::error(
                503,
                "JWT renewal provenance and role limits require schema 18",
            ));
        }
        if self.schema < 19 && self.auth.has_native_jwt_state() {
            return Err(Response::error(
                503,
                "native JWT claim semantics require schema 19",
            ));
        }
        if self.schema < 20 && self.auth.has_kubernetes_renewal_state() {
            return Err(Response::error(
                503,
                "Kubernetes renewal provenance and role limits require schema 20",
            ));
        }
        if self.schema < 21 && self.auth.has_oidc_renewal_state() {
            return Err(Response::error(
                503,
                "OIDC renewal provenance and role limits require schema 21",
            ));
        }
        if self.schema < 22 && self.auth.has_radius_native_parameters() {
            return Err(Response::error(
                503,
                "RADIUS native token parameters require schema 22",
            ));
        }
        if self.schema < 23
            && (self.auth.has_native_ldap_state() || self.engines.has_opaque_identity_aliases())
        {
            return Err(Response::error(
                503,
                "native LDAP authority and opaque identity aliases require schema 23",
            ));
        }
        if self.schema < 24 && self.auth.has_native_radius_state() {
            return Err(Response::error(
                503,
                "native RADIUS configuration and provenance require schema 24",
            ));
        }
        if self.schema < 25
            && (self.auth.has_native_ldap_transport() || self.auth.has_radius_no_default_policy())
        {
            return Err(Response::error(
                503,
                "native LDAP transport or RADIUS default-policy semantics require schema 25",
            ));
        }
        if self.schema < 26 && self.auth.has_radius_api_transport() {
            return Err(Response::error(
                503,
                "RADIUS API transport authority requires schema 26",
            ));
        }
        if self.schema < 27 && self.auth.has_token_bound_cidrs() {
            return Err(Response::error(
                503,
                "token source address constraints require schema 27",
            ));
        }
        if self.schema < 28
            && (self.auth.has_jwt_api_https_state() || self.auth.has_oidc_api_https_state())
        {
            return Err(Response::error(
                503,
                "JWT/OIDC API HTTPS authority requires schema 28",
            ));
        }
        if self.schema < 29
            && (self.auth.has_ldap_token_bound_cidrs()
                || self.auth.has_kubernetes_api_https_state())
        {
            return Err(Response::error(
                503,
                "LDAP source constraints or Kubernetes API HTTPS authority require schema 29",
            ));
        }
        if self.schema < 30
            && (self.auth.has_jwt_bound_claims_state() || self.auth.has_ldap_no_default_policy())
        {
            return Err(Response::error(
                503,
                "JWT claim predicates or native LDAP default-policy semantics require schema 30",
            ));
        }
        if self.schema < 31 && self.auth.has_kube_role_bound_cidrs() {
            return Err(Response::error(
                503,
                "Kubernetes role and issued-token source constraints require schema 31",
            ));
        }
        if self.schema < 32 && self.auth.has_jwt_native_ttl_defaults() {
            return Err(Response::error(
                503,
                "JWT role TTL inheritance requires schema 32",
            ));
        }
        if self.schema < 33 && self.auth.has_system_lease_defaults() {
            return Err(Response::error(
                503,
                "system lease defaults and Token API grant metadata require schema 33",
            ));
        }
        if self.schema < 34 && self.auth.has_approle_native_defaults() {
            return Err(Response::error(
                503,
                "AppRole TTL inheritance or SecretID issuance metadata requires schema 34",
            ));
        }
        if self.schema < 35 && self.auth.has_userpass_native_tokens() {
            return Err(Response::error(
                503,
                "userpass native token limits, configured policies or issuer provenance require schema 35",
            ));
        }
        self.auth
            .validate_jwt_api_https_state()
            .map_err(|_| Response::error(503, "invalid JWT HTTPS authority"))?;
        let pre_database = self.database.is_empty()
            && !self.engines.has_database_mount()
            && self.raft_admin.is_default();
        match self.schema {
            1 if pre_database
                && !self.auth.has_remote_jwt_state()
                && !self.auth.has_live_identity_state()
                && !self.auth.has_wrapping_state()
                && !self.engines.has_lease_state() =>
            {
                Ok(())
            }
            2 if pre_database
                && !self.auth.has_remote_jwt_state()
                && !self.auth.has_wrapping_state()
                && !self.engines.has_lease_state() =>
            {
                Ok(())
            }
            3 if pre_database && !self.auth.has_remote_jwt_state() => Ok(()),
            4
            | 5
            | 6
            | 7
            | 8
            | 9
            | 10
            | 11
            | 12
            | 13
            | 14
            | 15
            | 16
            | 17
            | 18
            | 19
            | 20
            | 21
            | 22
            | 23
            | 24
            | 25
            | 26
            | 27
            | 28
            | 29
            | 30
            | 31
            | 32
            | 33
            | 34
            | 35
            | 36
            | 37
            | 38
            | 39
            | 40
            | 41
            | 42
            | 43
            | 44
            | 45
            | 46
            | 47
            | 48
            | 49
            | 50
            | 51
            | 52
            | 53
            | 54
            | 55
            | 56
            | 57
            | 58
            | 59
            | 60
            | 61
            | 62
            | 63
            | 64
            | CURRENT_STATE_SCHEMA
            | AAD_BOUND_STATE_SCHEMA
            | TYPED_PKI_STATE_SCHEMA
            | JWT_USER_CLAIM_STATE_SCHEMA
            | JWT_PEM_KEYSET_STATE_SCHEMA
            | TRANSIT_BYOK_STATE_SCHEMA
            | PKI_ISSUER_PATH_STATE_SCHEMA
            | LOCAL_TYPED_PKI_STATE_SCHEMA
            | RECOVERY_CREDENTIAL_STATE_SCHEMA
            | INDEXED_RECOVERY_WIRE_STATE_SCHEMA
            | LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            | LOCAL_PKI_ROOT_FIELDS_STATE_SCHEMA
            | LOCAL_PKI_MULTI_ISSUER_STATE_SCHEMA
            | LOCAL_PKI_CRL_STATE_SCHEMA
            | LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA
            | TOKEN_ROLE_STATE_SCHEMA
            | TOKEN_API_PRECISION_STATE_SCHEMA
            | KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA
            | PKI_ROLE_ANY_NAME_STATE_SCHEMA
            | PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
            | PKI_ROLE_WILDCARD_STATE_SCHEMA
            | PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
            | PKI_ROLE_TIME_STATE_SCHEMA
            | PKI_SIGNED_ROLE_TIME_STATE_SCHEMA
            | PKI_ROLE_NAMES_STATE_SCHEMA
            | EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA
            | SDK_RESPONSE_HEADERS_STATE_SCHEMA
            | SDK_SECRET_LEASE_STATE_SCHEMA
            | PKI_URLS_STATE_SCHEMA
            | EXTERNAL_PKI_FULL_DN_CRL_STATE_SCHEMA
            | NAMESPACE_BATCH_STATE_SCHEMA
            | SDK_STORAGE_STATE_SCHEMA
            | NAMESPACE_CUSTODY_STATE_SCHEMA
            | AUTH_PUBLIC_ORIGIN_STATE_SCHEMA => Ok(()),
            _ => Err(Response::error(
                503,
                "unsupported or downgraded identity state schema",
            )),
        }
    }
}

impl Service {
    pub(super) fn bind_identity_principal(
        state: &State,
        principal: &mut Principal,
        namespace: &str,
    ) -> Result<(), Response> {
        let Some(id) = principal.entity_id() else {
            return Ok(());
        };
        let projection = state
            .engines
            .identity_projection(namespace, id)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if projection.disabled {
            return Err(Response::error(403, "permission denied"));
        }
        let selectors = state
            .auth
            .principal_template_selectors(principal, namespace, &projection.policies)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let values = state
            .engines
            .identity_template_values(namespace, &projection, &selectors, |accessor| {
                state.auth.has_mount_accessor(namespace, accessor)
            })
            .map_err(|error| Response::error(error.status, &error.message))?;
        principal.bind_identity_policies(projection.policies);
        principal.bind_identity_templates(values);
        Ok(())
    }

    pub(super) fn finish_identity_response(
        auth: &mut AuthState,
        engines: &mut EngineState,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
    ) -> Result<(), Response> {
        Self::finish_identity_response_observed(
            auth,
            engines,
            response,
            namespace,
            now,
            AuthorityTime::Coarse(now),
        )
    }
    pub(super) fn finish_identity_response_observed(
        auth: &mut AuthState,
        engines: &mut EngineState,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let auth_error = |error: AuthError| Response::error(error.status, &error.message);
        if let Some(login) = response.login_identity.take() {
            let accessor = auth
                .mount_accessor(namespace, &login.mount)
                .map_err(auth_error)?;
            if let Some(metadata) = login.metadata.as_ref() {
                engines
                    .validate_login_alias_metadata(namespace, &accessor, &login.alias, metadata)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            let projection = engines
                .bind_login_identity(namespace, &accessor, &login.alias, now)
                .map_err(|error| Response::error(error.status, &error.message))?;
            if projection.disabled {
                return Err(Response::error(
                    403,
                    if login.token_api_alias {
                        "entity from given entity alias is disabled"
                    } else {
                        "permission denied"
                    },
                ));
            }
            auth.bind_issued_entity(response, namespace, &login.mount, &projection.entity_id)
                .map_err(auth_error)?;
            if let Some(metadata) = login.metadata.as_ref() {
                engines
                    .update_login_alias_metadata(namespace, &accessor, &login.alias, metadata, now)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
        }
        let is_auth = response.body.get("auth").is_some();
        let envelope = if is_auth { "auth" } else { "data" };
        let Some(id) = response.body[envelope]["entity_id"]
            .as_str()
            .filter(|id| !id.is_empty())
        else {
            if response.external_groups.is_some() {
                return Err(Response::error(
                    503,
                    "provider identity binding is unavailable",
                ));
            }
            return auth
                .finish_pending_batch_observed(response, namespace, now, time)
                .map_err(auth_error);
        };
        if let Some(groups) = response.external_groups.take() {
            let accessor = auth
                .mount_accessor(namespace, &groups.mount)
                .map_err(auth_error)?;
            engines
                .verify_external_group_identity(namespace, id, &accessor, &groups.alias)
                .map_err(|error| Response::error(error.status, &error.message))?;
            engines
                .refresh_external_group_membership(namespace, id, &accessor, &groups.names, now)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        let projection = engines
            .identity_projection(namespace, id)
            .map_err(|error| Response::error(error.status, &error.message))?;
        // Administrative token lookup can describe a disabled identity. Its
        // token is still unusable: admission checks disabled before dispatch.
        if is_auth && projection.disabled {
            return Err(Response::error(403, "permission denied"));
        }
        response.body[envelope]["entity_id"] = Value::String(projection.entity_id);
        response.body[envelope]["identity_policies"] = json!(projection.policies);
        if is_auth {
            let mut all = projection.policies;
            if let Some(token_policies) = response.body["auth"]["token_policies"].as_array() {
                for policy in token_policies {
                    let name = policy
                        .as_str()
                        .ok_or_else(|| Response::error(500, "invalid token policy"))?;
                    all.insert(name.to_owned());
                }
            }
            response.body["auth"]["policies"] = json!(all);
        }
        auth.finish_pending_batch_observed(response, namespace, now, time)
            .map_err(auth_error)
    }

    pub(super) fn validate_identity_alias_mount(
        auth: &AuthState,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> Result<(), Response> {
        let alias_route = path == "identity/entity-alias"
            || path.starts_with("identity/entity-alias/id/")
            || path == "identity/group-alias"
            || path.starts_with("identity/group-alias/id/");
        if alias_route && let Some(accessor) = body.get("mount_accessor") {
            let accessor = accessor
                .as_str()
                .ok_or_else(|| Response::error(400, "invalid mount accessor"))?;
            if !auth.has_mount_accessor(namespace, accessor) {
                return Err(Response::error(400, "unknown auth mount accessor"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "identity_service_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_alias_metadata_tests.rs"]
mod alias_metadata_tests;

#[cfg(test)]
mod recovery_state_tests {
    use super::*;

    fn state() -> Result<State, crate::auth::AuthError> {
        let (auth, _) = AuthState::bootstrap(1)?;
        Ok(State {
            namespace_protected: None,
            namespace_leases: namespace_runtime::Leases::default(),
            schema: CURRENT_STATE_SCHEMA,
            cluster_id: "recovery-test-cluster".into(),
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: EngineState::initialized_empty().into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
        })
    }

    #[test]
    fn recovery_staging_defeats_owner_reuse_and_forces_monotonic_floor()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous = state().map_err(|_| std::io::Error::other("test bootstrap failed"))?;
        let old_bytes = owner_store::serialize_owner(&previous.auth)?;
        assert!(!String::from_utf8_lossy(&old_bytes).contains("recovery_credential"));
        let mut candidate = previous.clone();
        let fragments = candidate
            .auth
            .initialize_recovery_credential(&candidate.cluster_id, 5, 3)
            .map_err(|_| std::io::Error::other("test recovery generation failed"))?;
        assert_eq!(fragments.len(), 5);
        assert!(!previous.auth.has_recovery_credential());
        assert!(!OwnerReuseHint::between(Some(&previous), &candidate).auth);
        assert_eq!(
            candidate.writer_schema(),
            INDEXED_RECOVERY_WIRE_STATE_SCHEMA
        );
        assert!(candidate.validate_format().is_err());
        candidate.schema = candidate.writer_schema();
        assert!(candidate.validate_format().is_ok());
        assert!(candidate.validate_publication_schema(None).is_ok());
        assert!(
            candidate
                .validate_publication_schema(Some(&previous))
                .is_err()
        );
        let mut downgraded = candidate.clone();
        downgraded.schema = LOCAL_TYPED_PKI_STATE_SCHEMA;
        assert!(
            downgraded
                .validate_publication_schema(Some(&candidate))
                .is_err()
        );
        assert_eq!(old_bytes, owner_store::serialize_owner(&previous.auth)?);
        Ok(())
    }

    #[test]
    fn recovery_roundtrip_binds_cluster_and_rejects_old_schema_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut candidate = state().map_err(|_| std::io::Error::other("test bootstrap failed"))?;
        candidate
            .auth
            .initialize_recovery_credential(&candidate.cluster_id, 3, 2)
            .map_err(|_| std::io::Error::other("test recovery generation failed"))?;
        candidate.schema = candidate.writer_schema();
        let bytes = owner_store::serialize_owner(&candidate)?;
        let mut loaded: State = serde_json::from_slice(&bytes)?;
        assert!(loaded.validate_format().is_ok());
        loaded.cluster_id = "unrelated-cluster".into();
        assert!(loaded.validate_format().is_err());
        assert!(
            loaded
                .validate_publication_schema(Some(&candidate))
                .is_err()
        );
        loaded.cluster_id = candidate.cluster_id.clone();
        loaded.schema = LOCAL_TYPED_PKI_STATE_SCHEMA;
        assert!(loaded.validate_format().is_err());
        assert!(
            loaded
                .auth
                .initialize_recovery_credential(&loaded.cluster_id, 3, 2)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn snapshot_floor_cannot_replay_same_schema_recovery_credentials_or_challenges()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut current = state().map_err(|_| std::io::Error::other("test bootstrap failed"))?;
        current
            .auth
            .initialize_recovery_credential(&current.cluster_id, 5, 3)
            .map_err(|_| std::io::Error::other("recovery generation failed"))?;
        current.schema = current.writer_schema();
        let mut stale = current.clone();
        let (unrelated, _) = crate::auth::RecoveryCredential::generate(
            crypto::digest(stale.cluster_id.as_bytes()),
            1,
            5,
            3,
        )
        .map_err(|_| std::io::Error::other("recovery generation failed"))?;
        stale.auth.recovery_credential = Some(unrelated);
        assert_eq!(current.schema, stale.schema);
        assert!(Service::validate_snapshot_protected_floor(&current, &stale).is_err());
        let mut stale_challenge = current.clone();
        stale_challenge.auth.recovery_attempt = Some(
            crate::auth::RecoveryAttempt::new(
                crypto::digest(current.cluster_id.as_bytes()),
                current.auth.recovery_credential.as_ref(),
                3,
                2,
                true,
            )
            .map_err(|_| std::io::Error::other("challenge generation failed"))?,
        );
        assert!(Service::validate_snapshot_protected_floor(&current, &stale_challenge).is_err());
        assert!(Service::validate_snapshot_protected_floor(&current, &current).is_ok());
        Ok(())
    }
    #[test]
    fn indexed_attempt_raises_reader_before_candidate_and_cancel_does_not_lower_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut previous = state().map_err(|_| std::io::Error::other("bootstrap failed"))?;
        let (legacy, _) = crate::auth::RecoveryCredential::generate_with_codec(
            crypto::digest(previous.cluster_id.as_bytes()),
            1,
            5,
            3,
            None,
        )
        .map_err(|_| std::io::Error::other("legacy generation failed"))?;
        previous.auth.recovery_credential = Some(legacy);
        previous.schema = RECOVERY_CREDENTIAL_STATE_SCHEMA;
        assert!(previous.validate_format().is_ok());
        let mut active = previous.clone();
        active.auth.recovery_attempt = Some(
            crate::auth::RecoveryAttempt::new(
                crypto::digest(active.cluster_id.as_bytes()),
                active.auth.recovery_credential.as_ref(),
                255,
                2,
                true,
            )
            .map_err(|_| std::io::Error::other("challenge failed"))?,
        );
        assert!(active.validate_format().is_err());
        assert_eq!(active.writer_schema(), INDEXED_RECOVERY_WIRE_STATE_SCHEMA);
        active.schema = active.writer_schema();
        assert!(active.validate_publication_schema(Some(&previous)).is_ok());
        let mut canceled = active.clone();
        canceled.auth.recovery_attempt = None;
        assert_eq!(canceled.writer_schema(), INDEXED_RECOVERY_WIRE_STATE_SCHEMA);
        let mut downgraded = canceled.clone();
        downgraded.schema = RECOVERY_CREDENTIAL_STATE_SCHEMA;
        assert!(
            downgraded
                .validate_publication_schema(Some(&canceled))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&canceled, &downgraded).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod kubernetes_artifact_floor_tests {
    use super::*;
    #[test]
    fn kube_opaque_artifact_floor_survives_empty_retirement_and_refuses_snapshot_downgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let (auth, _) = AuthState::bootstrap(1).map_err(|_| "bootstrap")?;
        let current = State {
            schema: KUBERNETES_OPAQUE_ARTIFACT_STATE_SCHEMA,
            cluster_id: "opaque-artifact-floor-test".into(),
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: EngineState::initialized_empty().into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
            namespace_protected: None,
            namespace_leases: namespace_runtime::Leases::default(),
        };
        current
            .validate_format()
            .map_err(|_| "schema87 supported reader")?;
        assert_eq!(current.writer_schema(), 87);
        let mut older = current.clone();
        older.schema = TOKEN_ROLE_STATE_SCHEMA;
        assert!(older.validate_publication_schema(Some(&current)).is_err());
        let rejected = Service::validate_snapshot_protected_floor(&current, &older)
            .err()
            .ok_or("missing snapshot rejection")?;
        assert_eq!(rejected.status, 400);
        assert_eq!(
            rejected.body["errors"],
            json!(["snapshot would downgrade opaque Kubernetes artifact ownership"])
        );
        let mut unknown = current.clone();
        unknown.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
        assert!(unknown.validate_format().is_err());
        assert_eq!(unknown.writer_schema(), MAX_SUPPORTED_STATE_SCHEMA + 1);
        let mut precise = current.clone();
        precise.schema = 82;
        assert!(
            precise.validate_format().is_ok(),
            "explicit reader82 admits a historical whole-second graph"
        );
        assert!(
            precise.validate_publication_schema(Some(&current)).is_err(),
            "an admitted reader82 shape cannot overwrite the actual retired87 floor"
        );
        assert!(Service::validate_snapshot_protected_floor(&current, &precise).is_err());
        // The integrated reader admits PKI88 while retaining the prior87 floor.
        let mut integrated = current.clone();
        integrated.schema = PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA;
        assert!(integrated.validate_format().is_ok());
        assert!(
            integrated
                .validate_publication_schema(Some(&current))
                .is_ok()
        );
        assert!(Service::validate_snapshot_protected_floor(&integrated, &current).is_err());
        Ok(())
    }
}
