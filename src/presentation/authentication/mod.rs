use std::collections::BTreeMap;

use crate::presentation::device::RequestedItems;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Module containing functions to perform mdoc authentication.
pub mod mdoc;

/// The outcome of the holder device authenticating the device request.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RequestAuthenticationOutcome {
    /// The requested items from the mDL namespace.
    pub items_request: RequestedItems,
    /// The common name from the certificate that signed this request, if available.
    /// This value can be used to display to the user who the reader is, however
    /// caution should be exercised if reader authentication was not successful.
    pub common_name: Option<String>,
    /// Outcome of reader authentication.
    pub reader_authentication: AuthenticationStatus,
    /// Errors that occurred during request processing.
    pub errors: Errors,
}

/// The outcome of the reader device authenticating the device response.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ResponseAuthenticationOutcome {
    /// The values sent back from the holder device, serialized as JSON.
    pub response: BTreeMap<String, Value>,
    /// Outcome of issuer authentication.
    pub issuer_authentication: AuthenticationStatus,
    /// Outcome of device authentication.
    pub device_authentication: AuthenticationStatus,
    /// Errors that occurred during response processing.
    pub errors: Errors,
    /// Raw JWS string from the document's signedIssuerMetadata field, if present.
    pub signed_issuer_metadata: Option<String>,
    /// Whether the signed issuer metadata JWS signature was verified. None = not attempted.
    pub issuer_metadata_signature_verified: Option<bool>,
    /// Serial number (hex-encoded) of the leaf certificate that signed the issuer-signed
    /// data, for CRL-based revocation checking downstream. Present regardless of whether
    /// issuer/chain validation succeeded, since revocation is an orthogonal check.
    pub leaf_certificate_serial_number: Option<String>,
    /// CRL distribution point URI from the leaf certificate's own CRLDistributionPoints
    /// extension (OID 2.5.29.31), if present and well-formed. This is the CRL location
    /// baked directly into the certificate, as opposed to a pre-synced/cached URL - used
    /// as a fallback source when no local trust data is available for this CA. `None` if
    /// the extension is absent or malformed, which is a normal, valid state (the
    /// extension is optional per RFC 5280), not an error.
    pub leaf_certificate_crl_distribution_point: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ResponseAuthenticationOutcomes {
    pub responses: Vec<ResponseAuthenticationOutcome>,
    pub errors: Errors,
}

/// The outcome of authenticity checks.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy)]
pub enum AuthenticationStatus {
    #[default]
    Unchecked,
    Invalid,
    Valid,
}

/// Errors that occur during request/response processing.
pub type Errors = BTreeMap<String, serde_json::Value>;
