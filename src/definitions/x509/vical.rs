//! Verification of a VICAL (Verified Issuer Certificate Authority List, ISO/IEC 18013-5
//! Annex C) — a COSE_Sign1-signed CBOR document, published by a VICAL Provider, listing the
//! IACA certificates of every mDL issuer that provider vouches for.
//!
//! This is a Rust port of the verification half of `@aq/vical` (TypeScript), scoped to what
//! gc_verifier's trust check actually needs: verify the VICAL's signature against its own
//! embedded x5chain header (the presented signer certificate, plus any intermediates), confirm
//! that chain links back to an independently-supplied trust anchor, reject an expired VICAL
//! (`nextUpdate` in the past), then hand back the listed IACA certificates — optionally filtered
//! to the ones that cover a given `docType` — for folding directly into a trust anchor registry.
//! Other informational `VICALData` fields (provider name, issue date, ...) are deliberately not
//! modelled here.
//!
//! An earlier version of this module required the caller to supply the VICAL's *entire* signing
//! chain (signer included) as `trust_anchor_chain_pems`, and never consulted the VICAL's own
//! embedded x5chain at all. That was backwards relative to how every other PKI check in this
//! codebase works (see `validation/mod.rs`'s `find_trust_anchor_candidates`, used for mdoc's own
//! document-signer/IACA check): the party being verified presents its own leaf certificate, and
//! the verifier's job is only to confirm that leaf chains up to something it independently trusts.

use ciborium::Value as CborValue;
use coset::{CoseSign1, Label};
use der::{Decode, DecodePem, EncodePem};
use p256::ecdsa::{Signature, VerifyingKey};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use x509_cert::Certificate;

use crate::cbor;
use crate::cose::MaybeTagged;

use super::util::{common_name_or_unknown, public_key};
use super::validation::signature::issuer_signed_subject;
use super::validation::validity::check_validity_period;
use super::x5chain::X5CHAIN_COSE_HEADER_LABEL;

/// Errors that can occur while verifying a VICAL. Every variant means the VICAL must not be
/// trusted — there is no partial-success case.
#[derive(Debug, thiserror::Error)]
pub enum VicalError {
    #[error("VICAL's embedded x5chain COSE header is missing or empty - no candidate signer certificate to check")]
    MissingEmbeddedX5Chain,
    #[error("could not parse a certificate in the VICAL's embedded x5chain: {0}")]
    MalformedEmbeddedCertificate(String),
    #[error("could not parse trust anchor certificate: {0}")]
    MalformedTrustAnchorCertificate(String),
    #[error("VICAL's embedded certificate chain could not be linked to a trusted anchor: {0}")]
    InvalidTrustAnchorChain(String),
    #[error("could not parse VICAL as a COSE_Sign1 structure: {0}")]
    MalformedCoseSign1(String),
    #[error("VICAL signature could not be verified: {0}")]
    SignatureNotVerified(String),
    #[error("VICAL has no attached payload")]
    NoPayload,
    #[error("VICAL payload is not valid CBOR: {0}")]
    MalformedPayload(String),
    #[error("VICAL payload has no `certificateInfos` array")]
    MissingCertificateInfos,
    #[error("could not re-encode a listed certificate as PEM: {0}")]
    MalformedListedCertificate(String),
    #[error("VICAL has expired (nextUpdate is in the past)")]
    Expired,
}

pub type Result<T, E = VicalError> = std::result::Result<T, E>;

/// One entry from a verified VICAL's `certificateInfos` array: an IACA certificate, plus the
/// docTypes it covers (per ISO/IEC 18013-5 Annex C.1.7.1, `CertificateInfo.docType`).
#[derive(Debug, Clone)]
struct CertificateEntry {
    der: Vec<u8>,
    doc_types: Vec<String>,
}

/// A VICAL whose signature and expiry have already been verified against an independently-
/// supplied trust anchor chain. Holds the listed IACA certificates alongside the docTypes each
/// one covers.
#[derive(Debug, Clone, Default)]
pub struct VerifiedVical {
    certificates: Vec<CertificateEntry>,
}

impl VerifiedVical {
    /// Returns the listed certificates, PEM-encoded, for folding directly into a PEM-based trust
    /// anchor registry (e.g. mobile-sdk-rs's `establish_session`, fed by gc_verifier's
    /// `ProofManager.getCerts()`, which already builds one from directly-synced
    /// X509Trust/MdocIssuersTrust certs in this same PEM shape).
    ///
    /// When `doc_type` is `Some`, only certificates whose `docType` array lists that value are
    /// returned; `None` returns every listed certificate.
    pub fn certificates_as_pem(&self, doc_type: Option<&str>) -> Result<Vec<String>> {
        let matching: Vec<&CertificateEntry> = self
            .certificates
            .iter()
            .filter(|entry| match doc_type {
                None => true,
                Some(doc_type) => entry.doc_types.iter().any(|d| d == doc_type),
            })
            .collect();
        // Counts only - no cert/PEM content and no per-entry docType values, so a "0 matched"
        // downstream of a non-zero listed-count is still visible without logging anything
        // specific about the certificates themselves.
        log::info!(
            "[verify_vical] certificates_as_pem: {} of {} listed certificate(s) match doc_type={}",
            matching.len(),
            self.certificates.len(),
            doc_type.is_some()
        );

        matching
            .into_iter()
            .map(|entry| {
                let certificate = Certificate::from_der(&entry.der)
                    .map_err(|e| VicalError::MalformedListedCertificate(e.to_string()))?;
                certificate
                    .to_pem(Default::default())
                    .map_err(|e| VicalError::MalformedListedCertificate(e.to_string()))
            })
            .collect()
    }
}

/// Determines the public key `verify_vical` should check the VICAL's COSE_Sign1 signature
/// against, by walking the VICAL's own embedded x5chain (untrusted claims about who signed it,
/// leaf first) until reaching a certificate that an independently-supplied trust anchor actually
/// signed. Mirrors `find_trust_anchor_candidates`'s pattern in `validation/mod.rs` (mdoc's own
/// document-signer/IACA check): `trust_anchors` is a flat, individually-trusted pool - none of
/// its members need to be self-signed or sign each other, the same way `TrustAnchorRegistry`
/// treats every other trust anchor elsewhere in this crate.
///
/// Every hop from the leaf up to (and including) the matched anchor is independently
/// cryptographically verified via `issuer_signed_subject` - this never blindly trusts the
/// embedded chain's own claim about where it terminates. Returns the *leaf's* public key on
/// success, since that's the certificate that actually produced the VICAL's signature; trust in
/// the leaf comes from a fully-verified signature chain connecting it to a certificate an
/// independent anchor actually signed, not from the leaf appearing in `trust_anchors` itself.
fn verifying_key_for_signature(embedded_chain: &[Certificate], trust_anchors: &[Certificate]) -> Result<VerifyingKey> {
    let (leaf, rest) = embedded_chain.split_first().ok_or(VicalError::MissingEmbeddedX5Chain)?;

    let leaf_errors = check_validity_period(leaf);
    if !leaf_errors.is_empty() {
        return Err(VicalError::InvalidTrustAnchorChain(format!(
            "VICAL signer certificate \"{}\" is outside its validity period: {leaf_errors:?}",
            common_name_or_unknown(leaf)
        )));
    }

    let mut subject = leaf;
    let mut remaining = rest.iter();
    loop {
        let trusted = trust_anchors
            .iter()
            .any(|anchor| check_validity_period(anchor).is_empty() && issuer_signed_subject(subject, anchor));
        if trusted {
            return public_key::<p256::NistP256>(leaf)
                .map_err(|e| VicalError::MalformedTrustAnchorCertificate(e.to_string()));
        }

        let Some(next) = remaining.next() else {
            return Err(VicalError::InvalidTrustAnchorChain(format!(
                "no certificate in the VICAL's embedded chain (starting from \"{}\") chains to any \
                 supplied trust anchor",
                common_name_or_unknown(leaf)
            )));
        };

        if !issuer_signed_subject(subject, next) {
            return Err(VicalError::InvalidTrustAnchorChain(format!(
                "certificate \"{}\" in the VICAL's embedded chain was not signed by the next \
                 certificate in that chain (\"{}\")",
                common_name_or_unknown(subject),
                common_name_or_unknown(next)
            )));
        }
        let next_errors = check_validity_period(next);
        if !next_errors.is_empty() {
            return Err(VicalError::InvalidTrustAnchorChain(format!(
                "certificate \"{}\" in the VICAL's embedded chain is outside its validity period: {next_errors:?}",
                common_name_or_unknown(next)
            )));
        }
        subject = next;
    }
}

/// Extracts the DER-encoded `certificate` field, plus the `docType` array, from each entry of a
/// `certificateInfos` CBOR array. Entries missing a `certificate` field, or with the wrong CBOR
/// type, are skipped rather than failing the whole VICAL; a missing/malformed `docType` array is
/// treated as "no docTypes listed" rather than an error, since the field only matters to callers
/// that filter by it.
fn extract_certificate_entries(certificate_infos: &[CborValue]) -> Vec<CertificateEntry> {
    let entries: Vec<CertificateEntry> = certificate_infos
        .iter()
        .filter_map(|info| {
            let map = info.as_map()?;
            let der = map
                .iter()
                .find(|(key, _)| key.as_text() == Some("certificate"))
                .and_then(|(_, value)| value.as_bytes())?
                .to_vec();
            let doc_types = map
                .iter()
                .find(|(key, _)| key.as_text() == Some("docType"))
                .and_then(|(_, value)| value.as_array())
                .map(|entries| entries.iter().filter_map(|v| v.as_text().map(String::from)).collect())
                .unwrap_or_default();
            Some(CertificateEntry { der, doc_types })
        })
        .collect();
    // Count only - no cert/PEM content and no per-entry docType values.
    log::info!(
        "[verify_vical] certificateInfos: {} of {} raw entrie(s) parsed successfully",
        entries.len(),
        certificate_infos.len()
    );
    entries
}

/// Extracts the DER bytes of every certificate in the VICAL's own embedded x5chain COSE header
/// (label 0x21), if present, leaf first. `None` if the header is absent or the wrong CBOR shape -
/// not itself an error here, callers decide what that means (`verifying_key_for_signature`
/// requires at least one; nothing else does).
fn embedded_x5chain_der(cose_sign1: &CoseSign1) -> Option<Vec<&[u8]>> {
    // A plain fn, not a closure, so the borrow below works uniformly across both call sites -
    // closures can't have their return-value lifetime re-inferred per call the way a generic fn
    // can.
    fn find_label(rest: &[(Label, CborValue)]) -> Option<&CborValue> {
        rest.iter()
            .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
            .map(|(_, value)| value)
    }
    let raw = find_label(&cose_sign1.unprotected.rest).or_else(|| find_label(&cose_sign1.protected.header.rest))?;

    // Per the mdoc/x5chain COSE convention, the header value is either a single bstr (one DER
    // certificate) or an array of bstr (multiple, leaf first).
    match raw {
        CborValue::Bytes(bytes) => Some(vec![bytes.as_slice()]),
        CborValue::Array(items) => Some(items.iter().filter_map(|item| item.as_bytes().map(Vec::as_slice)).collect()),
        _ => None,
    }
}

/// Decodes the VICAL's own embedded x5chain into parsed certificates, leaf first - the candidate
/// signer/intermediate chain `verifying_key_for_signature` walks. Strict: a missing header or any
/// entry that fails to parse is an error, not silently skipped, since silently dropping a
/// certificate here could make an incomplete chain look complete.
fn embedded_x5chain_certs(cose_sign1: &CoseSign1) -> Result<Vec<Certificate>> {
    let der_certs = embedded_x5chain_der(cose_sign1).ok_or(VicalError::MissingEmbeddedX5Chain)?;
    if der_certs.is_empty() {
        return Err(VicalError::MissingEmbeddedX5Chain);
    }
    der_certs
        .into_iter()
        .map(|der| Certificate::from_der(der).map_err(|e| VicalError::MalformedEmbeddedCertificate(e.to_string())))
        .collect()
}

/// Extracts the VICAL payload's optional `nextUpdate` field as an RFC 3339 date-time string.
/// Per ISO/IEC 18013-5 Annex C, `nextUpdate` is a `tdate` (CBOR tag 0 wrapping an RFC 3339
/// string) — this accepts either the tagged or a bare-text encoding, since encoders vary.
fn extract_next_update(payload: &CborValue) -> Option<String> {
    let map = payload.as_map()?;
    let (_, raw) = map.iter().find(|(key, _)| key.as_text() == Some("nextUpdate"))?;
    match raw {
        CborValue::Text(text) => Some(text.clone()),
        CborValue::Tag(_, inner) => inner.as_text().map(String::from),
        _ => None,
    }
}

/// Parses and verifies a VICAL against an independently-supplied set of trust anchors — mirrors
/// `@aq/vical`'s `VICAL.initializeVerifier(chainPems, true)` + `parseAndVerify(vicalBytes)`.
///
/// The VICAL's own embedded x5chain COSE header supplies the candidate signer certificate (and
/// any intermediates) — see `verifying_key_for_signature`'s own doc comment for why trusting it
/// this way, rather than requiring the caller to pre-supply the signer, is the correct model, not
/// a weaker one: the embedded chain is never trusted on its own, only once
/// `verifying_key_for_signature` proves it cryptographically links to a member of
/// `trust_anchor_chain_pems`.
///
/// TEMPORARY: if `trust_anchor_chain_pems` is empty - i.e. no trust anchor at all was available
/// to check against, as opposed to one being present but the chain failing to link to it -
/// signature verification is skipped entirely and the VICAL is treated as trusted, with a warning
/// logged. This is a deliberate short-term relaxation for `VicalTrust` docs synced without any
/// trust anchor yet; anchors that ARE present must still result in a verified chain, same as
/// always.
///
/// If the payload carries a `nextUpdate`, it is checked against the current time and an expired
/// VICAL is rejected with [`VicalError::Expired`].
///
/// TEMPORARY TESTING OVERRIDE: when `allow_unverified_signature_for_testing`
/// is `true`, a VICAL whose embedded chain links to a trust anchor but whose COSE_Sign1 signature
/// still doesn't actually verify is logged and treated as trusted anyway, instead of returning
/// [`VicalError::SignatureNotVerified`]. Every real caller must pass `false` here - the one call
/// site that currently passes `true` is flagged just as loudly at its own definition
/// (`mobile-sdk-rs`'s `TEMP_VICAL_ALLOW_UNVERIFIED_SIGNATURE_FOR_TESTING`).
pub fn verify_vical(
    vical_bytes: &[u8],
    trust_anchor_chain_pems: &[String],
    allow_unverified_signature_for_testing: bool,
) -> Result<VerifiedVical> {
    // Count only - no cert/PEM content.
    log::info!(
        "[verify_vical] trust_anchor_chain_pems={}",
        trust_anchor_chain_pems.len()
    );

    let cose_sign1: MaybeTagged<CoseSign1> =
        cbor::from_slice(vical_bytes).map_err(|e| VicalError::MalformedCoseSign1(e.to_string()))?;

    if trust_anchor_chain_pems.is_empty() {
        // TEMPORARY (see this function's own doc comment) - no trust anchor was available for
        // this VICAL, so there's nothing to link its embedded chain to. Log it clearly and fall
        // through to parsing the payload unverified, rather than hard-failing.
        log::warn!(
            "[verify_vical] no trust anchor supplied for this VICAL - skipping signature \
             verification and treating it as trusted for now (TEMPORARY)"
        );
    } else {
        let trust_anchors = trust_anchor_chain_pems
            .iter()
            .map(|pem| Certificate::from_pem(pem.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| VicalError::MalformedTrustAnchorCertificate(e.to_string()))?;

        let embedded_chain = embedded_x5chain_certs(&cose_sign1.inner)?;
        // Count only - no cert/PEM content. (trust_anchors.len() is already reported by the
        // vical_bytes/trust_anchor_chain_pems count logged on entry - not restated here.)
        log::info!("[verify_vical] embedded x5chain has {} cert(s)", embedded_chain.len());

        let verifying_key = verifying_key_for_signature(&embedded_chain, &trust_anchors)?;

        let verification = cose_sign1
            .verify::<VerifyingKey, Signature>(&verifying_key, None, None)
            .into_result();
        match verification {
            Ok(()) => {}
            Err(reason) if allow_unverified_signature_for_testing => {
                log::warn!(
                    "[verify_vical] TESTING OVERRIDE ACTIVE: signature verification FAILED ({reason}) \
                     but proceeding anyway because allow_unverified_signature_for_testing=true. \
                     THIS MUST NOT SHIP - see verify_vical's own doc comment and \
                     mobile-sdk-rs's TEMP_VICAL_ALLOW_UNVERIFIED_SIGNATURE_FOR_TESTING."
                );
            }
            Err(reason) => return Err(VicalError::SignatureNotVerified(reason)),
        }
    }

    let payload = cose_sign1.inner.payload.as_ref().ok_or(VicalError::NoPayload)?;

    let value: CborValue =
        ciborium::from_reader(payload.as_slice()).map_err(|e| VicalError::MalformedPayload(e.to_string()))?;

    if let Some(next_update) = extract_next_update(&value) {
        let deadline = OffsetDateTime::parse(&next_update, &Rfc3339)
            .map_err(|e| VicalError::MalformedPayload(format!("invalid `nextUpdate`: {e}")))?;
        if deadline < OffsetDateTime::now_utc() {
            return Err(VicalError::Expired);
        }
    }

    let certificate_infos = value
        .as_map()
        .and_then(|map| map.iter().find(|(key, _)| key.as_text() == Some("certificateInfos")))
        .and_then(|(_, value)| value.as_array())
        .ok_or(VicalError::MissingCertificateInfos)?;

    let certificates = extract_certificate_entries(certificate_infos);

    Ok(VerifiedVical { certificates })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use coset::{iana, HeaderBuilder};
    use der::{Encode, EncodePem};
    use p256::ecdsa::{Signature, SigningKey};
    use sha1::{Digest, Sha1};
    use signature::Signer;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, Profile},
        der::asn1::OctetString,
        ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier},
        name::Name,
        spki::{SignatureBitStringEncoding, SubjectPublicKeyInfoOwned},
        time::Validity,
    };

    use crate::cose::sign1::PreparedCoseSign1;

    use super::*;

    /// Builds a minimal, valid self-signed root and one signer certificate issued by it,
    /// generated fresh at test time (no external fixtures needed) — mirrors the technique
    /// `x509/mod.rs`'s own test module already uses for chain-validation tests.
    fn root_and_signer() -> (Certificate, Certificate, SigningKey) {
        let root_key = SigningKey::random(&mut rand::thread_rng());
        let signer_key = SigningKey::random(&mut rand::thread_rng());
        let issuer: Name = "CN=Test VICAL Root,C=US".parse().unwrap();

        let root_spki = SubjectPublicKeyInfoOwned::from_key(*root_key.verifying_key()).unwrap();
        let root_ski = OctetString::new(Sha1::digest(root_spki.subject_public_key.raw_bytes()).to_vec()).unwrap();
        let mut root_builder = CertificateBuilder::new(
            Profile::Manual { issuer: None },
            1u64.into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            issuer.clone(),
            root_spki,
            &root_key,
        )
        .unwrap();
        root_builder.add_extension(&SubjectKeyIdentifier(root_ski)).unwrap();
        root_builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign.into()))
            .unwrap();
        root_builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .unwrap();
        let root_tbs = root_builder.finalize().unwrap();
        let root_sig: Signature = root_key.sign(&root_tbs);
        let root: Certificate = root_builder.assemble(root_sig.to_der().to_bitstring().unwrap()).unwrap();

        let signer_spki = SubjectPublicKeyInfoOwned::from_key(*signer_key.verifying_key()).unwrap();
        let mut signer_builder = CertificateBuilder::new(
            Profile::Manual { issuer: Some(issuer) },
            2u64.into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            "CN=Test VICAL Signer,C=US".parse().unwrap(),
            signer_spki,
            &root_key,
        )
        .unwrap();
        signer_builder
            .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
            .unwrap();
        let signer_tbs = signer_builder.finalize().unwrap();
        let signer_sig: Signature = root_key.sign(&signer_tbs);
        let signer: Certificate = signer_builder
            .assemble(signer_sig.to_der().to_bitstring().unwrap())
            .unwrap();

        (root, signer, signer_key)
    }

    /// Same idea as `root_and_signer()`, but with an extra intermediate tier
    /// (root -> intermediate -> signer) - for tests proving `verifying_key_for_signature`'s walk
    /// actually advances past the first embedded certificate, not just matches trivially at the
    /// leaf.
    fn root_intermediate_and_signer() -> (Certificate, Certificate, Certificate, SigningKey) {
        let root_key = SigningKey::random(&mut rand::thread_rng());
        let intermediate_key = SigningKey::random(&mut rand::thread_rng());
        let signer_key = SigningKey::random(&mut rand::thread_rng());
        let root_name: Name = "CN=Test VICAL Root,C=US".parse().unwrap();
        let intermediate_name: Name = "CN=Test VICAL Intermediate,C=US".parse().unwrap();

        let root_spki = SubjectPublicKeyInfoOwned::from_key(*root_key.verifying_key()).unwrap();
        let root_ski = OctetString::new(Sha1::digest(root_spki.subject_public_key.raw_bytes()).to_vec()).unwrap();
        let mut root_builder = CertificateBuilder::new(
            Profile::Manual { issuer: None },
            1u64.into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            root_name.clone(),
            root_spki,
            &root_key,
        )
        .unwrap();
        root_builder.add_extension(&SubjectKeyIdentifier(root_ski)).unwrap();
        root_builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign.into()))
            .unwrap();
        root_builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .unwrap();
        let root_tbs = root_builder.finalize().unwrap();
        let root_sig: Signature = root_key.sign(&root_tbs);
        let root: Certificate = root_builder.assemble(root_sig.to_der().to_bitstring().unwrap()).unwrap();

        let intermediate_spki = SubjectPublicKeyInfoOwned::from_key(*intermediate_key.verifying_key()).unwrap();
        let mut intermediate_builder = CertificateBuilder::new(
            Profile::Manual { issuer: Some(root_name) },
            2u64.into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            intermediate_name.clone(),
            intermediate_spki,
            &root_key,
        )
        .unwrap();
        intermediate_builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign.into()))
            .unwrap();
        intermediate_builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            })
            .unwrap();
        let intermediate_tbs = intermediate_builder.finalize().unwrap();
        let intermediate_sig: Signature = root_key.sign(&intermediate_tbs);
        let intermediate: Certificate = intermediate_builder
            .assemble(intermediate_sig.to_der().to_bitstring().unwrap())
            .unwrap();

        let signer_spki = SubjectPublicKeyInfoOwned::from_key(*signer_key.verifying_key()).unwrap();
        let mut signer_builder = CertificateBuilder::new(
            Profile::Manual { issuer: Some(intermediate_name) },
            3u64.into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            "CN=Test VICAL Signer,C=US".parse().unwrap(),
            signer_spki,
            &intermediate_key,
        )
        .unwrap();
        signer_builder
            .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
            .unwrap();
        let signer_tbs = signer_builder.finalize().unwrap();
        let signer_sig: Signature = intermediate_key.sign(&signer_tbs);
        let signer: Certificate = signer_builder
            .assemble(signer_sig.to_der().to_bitstring().unwrap())
            .unwrap();

        (root, intermediate, signer, signer_key)
    }

    fn x5chain_cbor(certs: &[&Certificate]) -> CborValue {
        let ders: Vec<Vec<u8>> = certs.iter().map(|cert| cert.to_der().unwrap()).collect();
        match ders.as_slice() {
            [single] => CborValue::Bytes(single.clone()),
            many => CborValue::Array(many.iter().cloned().map(CborValue::Bytes).collect()),
        }
    }

    /// Builds a COSE_Sign1-wrapped VICAL payload (a CBOR map with one `certificateInfos` entry
    /// per listed certificate) signed by `signer_key`, using the crate's own `PreparedCoseSign1`
    /// (the same helper `cose/sign1.rs`'s tests use to build real, verifiable COSE_Sign1
    /// structures). `embedded_chain` (leaf first) is embedded in the unprotected header's x5chain
    /// entry (label 0x21) - `verify_vical` reads the actual signer/intermediates from there, not
    /// from the trust anchor input. Each listed certificate's `docType` array is included only
    /// when non-empty; `next_update` is included only when `Some`.
    fn build_signed_vical(
        signer_key: &SigningKey,
        embedded_chain: &[&Certificate],
        certificate_infos: &[(Vec<u8>, Vec<&str>)],
        next_update: Option<&str>,
    ) -> Vec<u8> {
        let certificate_info_values: Vec<CborValue> = certificate_infos
            .iter()
            .map(|(der, doc_types)| {
                let mut fields = vec![(
                    CborValue::Text("certificate".to_string()),
                    CborValue::Bytes(der.clone()),
                )];
                if !doc_types.is_empty() {
                    fields.push((
                        CborValue::Text("docType".to_string()),
                        CborValue::Array(doc_types.iter().map(|d| CborValue::Text(d.to_string())).collect()),
                    ));
                }
                CborValue::Map(fields)
            })
            .collect();

        let mut payload_fields = vec![
            (CborValue::Text("version".to_string()), CborValue::Text("1.0".to_string())),
            (
                CborValue::Text("certificateInfos".to_string()),
                CborValue::Array(certificate_info_values),
            ),
        ];
        if let Some(next_update) = next_update {
            payload_fields.push((
                CborValue::Text("nextUpdate".to_string()),
                CborValue::Text(next_update.to_string()),
            ));
        }
        let payload_value = CborValue::Map(payload_fields);
        let mut payload = Vec::new();
        ciborium::into_writer(&payload_value, &mut payload).unwrap();

        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
        let unprotected = HeaderBuilder::new()
            .value(X5CHAIN_COSE_HEADER_LABEL, x5chain_cbor(embedded_chain))
            .build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload);
        let prepared = PreparedCoseSign1::new(builder, None, None, false).unwrap();
        let signature: Signature = signer_key.sign(prepared.signature_payload());
        let cose_sign1 = prepared.finalize(signature.to_vec());
        cbor::to_vec(&cose_sign1).unwrap()
    }

    fn pem(cert: &Certificate) -> String {
        cert.to_pem(Default::default()).unwrap()
    }

    #[test]
    fn returns_every_listed_certificate_as_pem() {
        let (root, signer, signer_key) = root_and_signer();
        let (_other_root, other_signer, _other_signer_key) = root_and_signer();
        let certificate_infos = vec![
            (signer.to_der().unwrap(), vec![]),
            (other_signer.to_der().unwrap(), vec![]),
        ];
        let vical_bytes = build_signed_vical(&signer_key, &[&signer], &certificate_infos, None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        let verified = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).expect("VICAL should verify");
        let pems = verified
            .certificates_as_pem(None)
            .expect("listed certificates should re-encode as PEM");

        assert_eq!(pems, vec![pem(&signer), pem(&other_signer)]);
    }

    #[test]
    fn filters_certificates_by_doc_type() {
        let (root, signer, signer_key) = root_and_signer();
        let (_other_root, other_signer, _other_signer_key) = root_and_signer();
        let certificate_infos = vec![
            (signer.to_der().unwrap(), vec!["org.iso.18013.5.1.mDL"]),
            (other_signer.to_der().unwrap(), vec!["com.example.other"]),
        ];
        let vical_bytes = build_signed_vical(&signer_key, &[&signer], &certificate_infos, None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        let verified = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).expect("VICAL should verify");
        let pems = verified
            .certificates_as_pem(Some("org.iso.18013.5.1.mDL"))
            .expect("matching certificate should re-encode as PEM");

        assert_eq!(pems, vec![pem(&signer)]);
    }

    // A root-only trust anchor, with the VICAL's own embedded x5chain supplying the actual
    // signer - which used to be rejected (the caller was required to supply the signer itself)
    // and now succeeds.
    #[test]
    fn accepts_a_root_only_trust_anchor_when_the_embedded_chain_supplies_the_signer() {
        let (root, signer, signer_key) = root_and_signer();
        let vical_bytes = build_signed_vical(&signer_key, &[&signer], &[(signer.to_der().unwrap(), vec![])], None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).expect("VICAL should verify");
    }

    // Proves verifying_key_for_signature's walk actually advances past the first embedded
    // certificate: the trust anchor (root) didn't sign the leaf (signer) directly, only the
    // intermediate the embedded chain also carries.
    #[test]
    fn accepts_a_multi_hop_embedded_chain_that_eventually_reaches_the_trust_anchor() {
        let (root, intermediate, signer, signer_key) = root_intermediate_and_signer();
        let vical_bytes = build_signed_vical(
            &signer_key,
            &[&signer, &intermediate],
            &[(signer.to_der().unwrap(), vec![])],
            None,
        );
        let trust_anchor_chain_pems = vec![pem(&root)];

        verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).expect("VICAL should verify");
    }

    #[test]
    fn rejects_a_vical_signed_by_a_key_not_matching_its_embedded_leaf_certificate() {
        let (root, signer, _signer_key) = root_and_signer();
        let (_other_root, _other_signer, wrong_key) = root_and_signer();
        let vical_bytes = build_signed_vical(&wrong_key, &[&signer], &[(signer.to_der().unwrap(), vec![])], None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        let err = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).unwrap_err();
        assert!(matches!(err, VicalError::SignatureNotVerified(_)));
    }

    #[test]
    fn rejects_when_the_embedded_chain_does_not_link_to_any_trust_anchor() {
        let (_root_a, signer_a, signer_key_a) = root_and_signer();
        let (root_b, _signer_b, _signer_key_b) = root_and_signer();
        let vical_bytes = build_signed_vical(&signer_key_a, &[&signer_a], &[(signer_a.to_der().unwrap(), vec![])], None);
        // signer_a was not issued by root_b - not a valid chain.
        let trust_anchor_chain_pems = vec![pem(&root_b)];

        let err = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).unwrap_err();
        assert!(matches!(err, VicalError::InvalidTrustAnchorChain(_)));
    }

    #[test]
    fn rejects_a_vical_with_no_embedded_x5chain() {
        let (root, signer, signer_key) = root_and_signer();
        let vical_bytes = build_signed_vical(&signer_key, &[], &[(signer.to_der().unwrap(), vec![])], None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        let err = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).unwrap_err();
        assert!(matches!(err, VicalError::MissingEmbeddedX5Chain));
    }

    // TEMPORARY (see verify_vical's own doc comment) - no trust anchor at all is treated as
    // trusted-but-unverified rather than rejected, since there's nothing to check the embedded
    // chain against.
    #[test]
    fn treats_a_vical_with_no_trust_anchor_as_trusted_but_unverified() {
        let (_root, signer, signer_key) = root_and_signer();
        let vical_bytes = build_signed_vical(&signer_key, &[&signer], &[(signer.to_der().unwrap(), vec![])], None);

        let verified = verify_vical(&vical_bytes, &[], false).expect("VICAL should be treated as trusted");
        let pems = verified
            .certificates_as_pem(None)
            .expect("listed certificate should re-encode as PEM");
        assert_eq!(pems, vec![pem(&signer)]);
    }

    // TEMPORARY TESTING OVERRIDE (see verify_vical's own doc comment) - proves
    // allow_unverified_signature_for_testing=true actually lets a bad signature through instead
    // of silently doing nothing. The embedded chain still needs to link to a trust anchor first -
    // this override only covers the final signature check failing, not the chain-linking step.
    #[test]
    fn testing_override_lets_a_bad_signature_through_when_requested() {
        let (root, signer, _signer_key) = root_and_signer();
        let (_other_root, _other_signer, wrong_key) = root_and_signer();
        let vical_bytes = build_signed_vical(&wrong_key, &[&signer], &[(signer.to_der().unwrap(), vec![])], None);
        let trust_anchor_chain_pems = vec![pem(&root)];

        let verified = verify_vical(&vical_bytes, &trust_anchor_chain_pems, true)
            .expect("override should let an unverified signature through");
        let pems = verified
            .certificates_as_pem(None)
            .expect("listed certificate should re-encode as PEM");
        assert_eq!(pems, vec![pem(&signer)]);
    }

    #[test]
    fn rejects_a_vical_past_its_next_update() {
        let (root, signer, signer_key) = root_and_signer();
        let vical_bytes = build_signed_vical(
            &signer_key,
            &[&signer],
            &[(signer.to_der().unwrap(), vec![])],
            Some("2000-01-01T00:00:00Z"),
        );
        let trust_anchor_chain_pems = vec![pem(&root)];

        let err = verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).unwrap_err();
        assert!(matches!(err, VicalError::Expired));
    }

    #[test]
    fn accepts_a_vical_with_a_future_next_update() {
        let (root, signer, signer_key) = root_and_signer();
        let vical_bytes = build_signed_vical(
            &signer_key,
            &[&signer],
            &[(signer.to_der().unwrap(), vec![])],
            Some("2999-01-01T00:00:00Z"),
        );
        let trust_anchor_chain_pems = vec![pem(&root)];

        verify_vical(&vical_bytes, &trust_anchor_chain_pems, false).expect("VICAL should verify");
    }
}
