use crate::cbor;
use crate::cose;
use crate::definitions::device_response::LdpVcDocument;
use crate::definitions::device_response::MdocDocument;
use crate::definitions::device_response::W3cVcDocument;
use crate::definitions::issuer_signed;
use crate::definitions::x509::X5Chain;
use crate::definitions::DeviceAuth;
use crate::definitions::Mso;
use crate::definitions::{
    device_signed::{DeviceAuthentication, W3CDeviceAuthentication}, helpers::Tag24, SessionTranscript180135,
};
use crate::presentation::reader::Error;
use anyhow::Result;
use elliptic_curve::generic_array::GenericArray;
use issuer_signed::IssuerSigned;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use ssi_jwk::Params;
use ssi_jwk::JWK as SsiJwk;
use time::OffsetDateTime;
use std::str::FromStr;
use jsonwebtokens as jwts;
use jwts::{raw::{self, TokenSlices}};

// ── ecdsa-rdfc-2019 holder-binding verification ───────────────────────────────

/// Manual ecdsa-rdfc-2019 VP holder-binding proof verification.
///
/// ssi's DataIntegrity framework fails with "invalid signature" despite the proof
/// being cryptographically valid (same pattern as ecdsa-sd-2023). This manual
/// implementation directly computes the verifyData:
///
///   verifyData = SHA256(RDFC(proofConfig_nquads)) || SHA256(RDFC(VP_nquads_without_proof))
///   ECDSA-P256-SHA256.verify(holder_key, verifyData, proofValue)
fn verify_ecdsa_rdfc_2019_vp(vp_json: &str) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier;
    use sha2::{Digest, Sha256};
    use ssi_json_ld::{CompactJsonLd, ContextLoader, Expandable};
    use ssi_rdf::{LdEnvironment, IntoNQuads, urdna2015};
    use json_syntax::Value as JsonSyntaxValue;

    let vp: serde_json::Value = serde_json::from_str(vp_json)
        .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: parse VP JSON: {e}")))?;
    let proof = vp.get("proof").ok_or(Error::MdocAuth("ecdsa-rdfc-2019: no proof".to_string()))?;
    let proof_value_str = proof.get("proofValue").and_then(|v| v.as_str())
        .ok_or(Error::MdocAuth("ecdsa-rdfc-2019: no proofValue".to_string()))?;
    let vm = proof.get("verificationMethod").and_then(|v| v.as_str())
        .ok_or(Error::MdocAuth("ecdsa-rdfc-2019: no verificationMethod".to_string()))?;
    let created = proof.get("created").and_then(|v| v.as_str()).unwrap_or("");
    let challenge = proof.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
    let cryptosuite = proof.get("cryptosuite").and_then(|v| v.as_str()).unwrap_or("ecdsa-rdfc-2019");

    // Decode proofValue (multibase base58btc, z prefix)
    if !proof_value_str.starts_with('z') {
        return Err(Error::MdocAuth("ecdsa-rdfc-2019: proofValue must be multibase z".to_string()));
    }
    let sig_bytes = bs58::decode(&proof_value_str[1..]).into_vec()
        .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: decode proofValue: {e}")))?;

    // Extract holder P-256 key from did:jwk:
    let did_part = vm.split('#').next().unwrap_or(vm);
    if !did_part.starts_with("did:jwk:") {
        return Err(Error::MdocAuth(format!("ecdsa-rdfc-2019: VM must be did:jwk, got {vm}")));
    }
    let jwk_bytes = base64_url::decode(&did_part[8..])
        .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: decode did:jwk: {e}")))?;
    let holder_jwk: ssi_jwk::JWK = serde_json::from_slice(&jwk_bytes)
        .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: parse holder JWK: {e}")))?;
    let holder_vk = match holder_jwk.params {
        ssi_jwk::Params::EC(ref p) => {
            let x = p.x_coordinate.as_ref().ok_or(Error::ParsingError)?;
            let y = p.y_coordinate.as_ref().ok_or(Error::ParsingError)?;
            let pt = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            VerifyingKey::from_encoded_point(&pt).map_err(|_| Error::ParsingError)?
        }
        _ => return Err(Error::MdocAuth("ecdsa-rdfc-2019: holder key must be P-256 EC".to_string())),
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: runtime build: {e}")))?
        .block_on(async {
            let loader = ContextLoader::empty().with_static_loader();

            // ── Step 1: proofConfig N-Quads (DI-v2 pattern, all contexts produce identical output) ──
            let proof_config_nquads = [
                format!("_:c14n0 <http://purl.org/dc/terms/created> \"{}\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n", created),
                "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n".to_string(),
                format!("_:c14n0 <https://w3id.org/security#challenge> \"{}\" .\n", challenge),
                format!("_:c14n0 <https://w3id.org/security#cryptosuite> \"{}\"^^<https://w3id.org/security#cryptosuiteString> .\n", cryptosuite),
                "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> .\n".to_string(),
                format!("_:c14n0 <https://w3id.org/security#verificationMethod> <{}> .\n", vm),
            ];
            let proof_hash: [u8; 32] = Sha256::digest(
                proof_config_nquads.iter().flat_map(|s| s.as_bytes()).cloned().collect::<Vec<_>>()
            ).into();

            // ── Step 2: VP document N-Quads (without proof) ───────────────────────────────────────
            let mut vp_no_proof = vp.clone();
            vp_no_proof.as_object_mut().map(|o| o.remove("proof"));
            let json_str = serde_json::to_string(&vp_no_proof)
                .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: serialize VP: {e}")))?;
            let json: JsonSyntaxValue = json_str.parse()
                .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: json_syntax VP: {e}")))?;
            let mut ld = LdEnvironment::default();
            let mut expanded = CompactJsonLd(json).expand_with(&mut ld, &loader).await
                .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: expand VP: {e}")))?;
            expanded.canonicalize();
            let quads = linked_data::to_lexical_quads_with(
                &mut ld.vocabulary, &mut ld.interpretation, &expanded,
            ).map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: VP quads: {e:?}")))?;
            let doc_lines: Vec<String> = urdna2015::normalize(
                quads.iter().map(|q| q.as_lexical_quad_ref())
            ).into_nquads_lines();
            let doc_hash: [u8; 32] = Sha256::digest(
                doc_lines.iter().flat_map(|s| s.as_bytes()).cloned().collect::<Vec<_>>()
            ).into();

            log::info!("[rdfc2019] proof_hash={} doc_hash={}", hex::encode(&proof_hash), hex::encode(&doc_hash));

            // ── Step 3: verifyData = SHA256(proofConfig) || SHA256(doc)  (W3C spec) ─────────────
            let mut verify_data = Vec::with_capacity(64);
            verify_data.extend_from_slice(&proof_hash);
            verify_data.extend_from_slice(&doc_hash);

            // ── Step 4: ECDSA-P256-SHA256 verify ─────────────────────────────────────────────────
            let sig = if sig_bytes.len() == 64 {
                p256::ecdsa::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: sig parse (P1363): {e}")))?
            } else {
                p256::ecdsa::Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::MdocAuth(format!("ecdsa-rdfc-2019: sig parse (DER): {e}")))?
            };
            holder_vk.verify(&verify_data, &sig)
                .map_err(|e| Error::MdocAuth(format!("VP holder proof (ecdsa-rdfc-2019) verification failed: {e}")))
        })
}

pub fn issuer_authentication(x5chain: X5Chain, issuer_signed: &IssuerSigned) -> Result<(), Error> {
    let signer_key = x5chain
        .end_entity_public_key()
        .map_err(Error::IssuerPublicKey)?;
    let verification_result: cose::sign1::VerificationResult =
        issuer_signed
            .issuer_auth
            .verify::<VerifyingKey, Signature>(&signer_key, None, None);
    verification_result
        .into_result()
        .map_err(Error::IssuerAuthentication)
}

pub fn w3c_device_authentication(
    document: &W3cVcDocument,
    session_transcript: SessionTranscript180135,
) -> Result<(), Error> {
    let jwt = document.jwt.clone();
    // SD-JWT format: base_jwt~disclosure1~...~kb_jwt — extract only the base JWT.
    let base_jwt = jwt.split('~').next().unwrap_or(&jwt);

    let TokenSlices{claims,..} = raw::split_token(base_jwt).map_err(|e| {
        log::info!("[w3c_device_auth] failed to split JWT: {e:?}");
        Error::ParsingError
    })?;
    let raw_claim = raw::decode_json_token_slice(claims).map_err(|e| {
        log::info!("[w3c_device_auth] failed to decode JWT payload: {e:?}");
        Error::ParsingError
    })?;
    let payload_object = raw_claim.as_object().ok_or_else(|| {
        log::info!("[w3c_device_auth] JWT payload is not a JSON object");
        Error::ParsingError
    })?;

    // Support two key-binding formats:
    //  - SD-JWT VC (draft-ietf-oauth-sd-jwt-vc): device key in cnf.jwk (RFC 7800)
    //  - VCDM 1.1 JWT-VC: device key in vc.credentialSubject.id as a did:jwk URI
    let binding_key_jwk: SsiJwk = if let Some(cnf) = payload_object.get("cnf") {
        let jwk_val = cnf.get("jwk").ok_or_else(|| {
            log::info!("[w3c_device_auth] cnf present but no jwk field; cnf={cnf}");
            Error::ParsingError
        })?;
        serde_json::from_value(jwk_val.clone()).map_err(|e| {
            log::info!("[w3c_device_auth] failed to parse cnf.jwk as SsiJwk: {e:?}");
            Error::ParsingError
        })?
    } else {
        let vc = payload_object.get("vc").and_then(|v| v.as_object()).ok_or_else(|| {
            log::info!("[w3c_device_auth] no cnf and no vc claim in payload");
            Error::ParsingError
        })?;
        let credential_subject = vc.get("credentialSubject").and_then(|v| v.as_object()).ok_or_else(|| {
            log::info!("[w3c_device_auth] no credentialSubject in vc");
            Error::ParsingError
        })?;
        let jwk_did = credential_subject.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
            log::info!("[w3c_device_auth] no id in credentialSubject");
            Error::ParsingError
        })?;
        let key_part = jwk_did.get(8..).ok_or_else(|| {
            log::info!("[w3c_device_auth] id does not start with did:jwk:");
            Error::ParsingError
        })?;
        let jwk_bytes = base64_url::decode(key_part).map_err(|e| {
            log::info!("[w3c_device_auth] base64url decode of did:jwk key failed: {e:?}");
            Error::ParsingError
        })?;
        let jwk_str = String::from_utf8(jwk_bytes).map_err(|e| {
            log::info!("[w3c_device_auth] did:jwk bytes are not valid utf-8: {e:?}");
            Error::ParsingError
        })?;
        SsiJwk::from_str(&jwk_str).map_err(|e| {
            log::info!("[w3c_device_auth] failed to parse did:jwk JWK: {e:?}");
            Error::ParsingError
        })?
    };


    match binding_key_jwk.params {
        Params::EC(p) => {
            let x_coordinate = p.x_coordinate.clone();
            let y_coordinate = p.y_coordinate.clone();
            let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                log::info!("[w3c_device_auth] EC key missing x or y coordinate");
                return Err(Error::MdocAuth(
                    "device key jwk is missing coordinates".to_string(),
                ));
            };
            let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).map_err(|e| {
                log::info!("[w3c_device_auth] failed to build P-256 verifying key: {e:?}");
                Error::from(e)
            })?;
            let device_auth: &DeviceAuth = &document.device_auth;
            match device_auth {
                DeviceAuth::DeviceSignature(device_signature) => {
                    let detached_payload = Tag24::new(W3CDeviceAuthentication::new(
                        session_transcript,
                        document.doc_type.clone(),
                    ))
                    .map_err(|_| Error::CborDecodingError)?;
                    let external_aad = None;
                    let cbor_payload = cbor::to_vec(&detached_payload)?;
                    log::info!(
                        "[w3c_device_auth] doc_type={:?}, detached_payload_hex={}",
                        document.doc_type,
                        hex::encode(&cbor_payload)
                    );
                    let result = device_signature.verify::<VerifyingKey, Signature>(
                        &verifying_key,
                        Some(&cbor_payload),
                        external_aad,
                    );
                    if !result.is_success() {
                        log::info!("[w3c_device_auth] COSE signature verification failed");
                        Err(Error::ParsingError)?
                    } else {
                        Ok(())
                    }
                }
                DeviceAuth::DeviceMac(_) => {
                    log::info!("[w3c_device_auth] DeviceMac not supported");
                    Err(Error::Unsupported)
                }
            }
        }
        _ => {
            log::info!("[w3c_device_auth] binding key is not EC type");
            Err(Error::MdocAuth("Unsupported device_key type".to_string()))
        }
    }
}

/// Recursively sort all JSON object keys in Unicode code-point order,
/// producing a value suitable for JCS (RFC 8785) canonicalization.
fn jcs_sort(value: &serde_json::Value) -> serde_json::Value {
    use std::collections::BTreeMap;
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), jcs_sort(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(jcs_sort).collect())
        }
        other => other.clone(),
    }
}

pub fn ldp_vc_device_authentication(
    document: &LdpVcDocument,
    session_transcript: SessionTranscript180135,
) -> Result<(), Error> {
    use sha2::{Sha256, Digest};

    // Step 1: CBOR-encode the session transcript.
    // Clone before consuming so we can reuse it when building DeviceAuthentication (ecdsa-rdfc-2019).
    let session_transcript_cbor = crate::cbor::to_vec(&session_transcript)
        .map_err(|_| Error::CborDecodingError)?;
    // transcript_cbor = CBOR(Tag24(SessionTranscript)) — used by ecdsa-jcs-2019 SHA-256 challenge.
    let transcript_cbor = crate::cbor::to_vec(
        &Tag24::new(session_transcript).map_err(|_| Error::CborDecodingError)?
    ).map_err(|_| Error::CborDecodingError)?;

    // Step 2: Parse the VP JSON stored in ldp_vc.
    let vp: serde_json::Value = serde_json::from_str(&document.ldp_vc)
        .map_err(|_| Error::ParsingError)?;

    // Step 3: Extract the outer VP proof.
    let proof = vp.get("proof").ok_or(Error::ParsingError)?;

    // Step 3a: Read cryptosuite early — needed to pick the right challenge format.
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            log::info!("[ldp_vc_device_auth] ParsingError: proof.cryptosuite missing — proof keys: {:?}",
                proof.as_object().map(|o| o.keys().collect::<Vec<_>>()));
            Error::ParsingError
        })?;
    log::info!("[ldp_vc_device_auth] cryptosuite: {cryptosuite}");

    // Step 3b: Compute expected challenge based on cryptosuite.
    //
    //   ecdsa-jcs-2019: hex(SHA-256(CBOR(Tag24(SessionTranscript))))
    //
    //   ecdsa-rdfc-2019: hex(CBOR(Tag24(DeviceAuthentication))) per ISO 18013-7 §9.1.3
    //     DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, Tag24(CBOR({}))]
    //     DeviceNamespacesBytes is an empty map (no namespaces in W3C credentials).
    let expected_challenge = match cryptosuite {
        "ecdsa-jcs-2019" => hex::encode(Sha256::digest(&transcript_cbor)),
        _ => {
            // Parse the raw session transcript CBOR bytes into a ciborium Value so it
            // can be embedded inside the DeviceAuthentication array.
            let transcript_value: ciborium::value::Value =
                ciborium::de::from_reader(session_transcript_cbor.as_slice())
                    .map_err(|_| Error::CborDecodingError)?;

            // Tag24(bstr(CBOR({}))) — empty DeviceNamespacesBytes placeholder.
            // CBOR({}) = 0xa0 (empty map), so the bstr payload is a single byte.
            let device_namespaces_tag24 = ciborium::value::Value::Tag(
                24,
                Box::new(ciborium::value::Value::Bytes(vec![0xa0])),
            );

            // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, Tag24(CBOR({}))]
            let device_authentication = ciborium::value::Value::Array(vec![
                ciborium::value::Value::Text("DeviceAuthentication".to_string()),
                transcript_value,
                ciborium::value::Value::Text(document.doc_type.clone()),
                device_namespaces_tag24,
            ]);

            let device_auth_tag24_cbor = crate::cbor::to_vec(
                &Tag24::new(device_authentication).map_err(|_| Error::CborDecodingError)?
            ).map_err(|_| Error::CborDecodingError)?;

            hex::encode(&device_auth_tag24_cbor)
        }
    };

    // Step 3c: Validate challenge.
    let challenge = proof.get("challenge").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
    if challenge != expected_challenge {
        return Err(Error::MdocAuth(format!(
            "VP challenge mismatch: got {challenge}, expected {expected_challenge}"
        )));
    }

    // Step 4: Extract the holder DID from the verificationMethod (always did:jwk:).
    let vm = proof.get("verificationMethod").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
    let did_part = vm.split('#').next().ok_or(Error::ParsingError)?;
    if !did_part.starts_with("did:jwk:") {
        return Err(Error::MdocAuth("VP verificationMethod must be a did:jwk DID".to_string()));
    }

    // Step 4b: Holder binding — the VP signer must be the credential's subject.
    let inner_vc = vp
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| {
            log::info!("[ldp_vc_device_auth] ParsingError: verifiableCredential[0] missing or not an array");
            Error::ParsingError
        })?;
    let subject_id = inner_vc
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            log::info!("[ldp_vc_device_auth] ParsingError: credentialSubject.id missing — inner_vc credentialSubject: {:?}",
                inner_vc.get("credentialSubject"));
            Error::ParsingError
        })?;
    if did_part != subject_id {
        return Err(Error::MdocAuth(format!(
            "Holder binding failed: verificationMethod ({did_part}) != credentialSubject.id ({subject_id})"
        )));
    }

    // Step 5: Dispatch on cryptosuite for signature verification (read in step 3a).

    match cryptosuite {
        "ecdsa-jcs-2019" => {
            // Step 5a: Build P-256 verifying key from the holder JWK embedded in did:jwk:.
            let key_b64 = &did_part[8..];
            let jwk_bytes = base64_url::decode(key_b64).map_err(|_| Error::ParsingError)?;
            let jwk_str = String::from_utf8(jwk_bytes).map_err(|_| Error::ParsingError)?;
            let holder_jwk: SsiJwk = SsiJwk::from_str(&jwk_str).map_err(|_| Error::ParsingError)?;

            let verifying_key = match holder_jwk.params {
                Params::EC(ref p) => {
                    let x = p.x_coordinate.as_ref().ok_or(Error::ParsingError)?;
                    let y = p.y_coordinate.as_ref().ok_or(Error::ParsingError)?;
                    let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                        GenericArray::from_slice(x.0.as_slice()),
                        GenericArray::from_slice(y.0.as_slice()),
                        false,
                    );
                    VerifyingKey::from_encoded_point(&encoded_point)
                        .map_err(|_| Error::ParsingError)?
                }
                _ => return Err(Error::MdocAuth("VP holder key must be P-256 EC".to_string())),
            };

            // Step 5b: JCS canonicalization + SHA-256 + ECDSA verify.
            let mut proof_config = proof.clone();
            if let Some(obj) = proof_config.as_object_mut() {
                obj.remove("proofValue");
            }
            let mut unsigned_vp = vp.clone();
            if let Some(obj) = unsigned_vp.as_object_mut() {
                obj.remove("proof");
            }

            let canonical_proof_config = serde_json::to_string(&jcs_sort(&proof_config))
                .map_err(|_| Error::ParsingError)?;
            let canonical_document = serde_json::to_string(&jcs_sort(&unsigned_vp))
                .map_err(|_| Error::ParsingError)?;


            let hash_proof_config = Sha256::digest(canonical_proof_config.as_bytes());
            let hash_document = Sha256::digest(canonical_document.as_bytes());


            let mut verify_data = Vec::with_capacity(64);
            verify_data.extend_from_slice(&hash_proof_config);
            verify_data.extend_from_slice(&hash_document);


            let proof_value = proof.get("proofValue").and_then(|v| v.as_str())
                .ok_or(Error::ParsingError)?;
            if !proof_value.starts_with('z') {
                return Err(Error::MdocAuth(
                    "proofValue must use multibase base58btc (z prefix)".to_string(),
                ));
            }
            let sig_bytes = bs58::decode(&proof_value[1..]).into_vec()
                .map_err(|_| Error::ParsingError)?;


            use p256::ecdsa::signature::Verifier;
            let signature = if sig_bytes.len() == 64 {
                p256::ecdsa::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| Error::ParsingError)?
            } else {
                p256::ecdsa::Signature::from_der(&sig_bytes)
                    .map_err(|_| Error::ParsingError)?
            };

            verifying_key.verify(&verify_data, &signature)
                .map_err(|_| Error::MdocAuth("VP holder proof signature verification failed".to_string()))
        }
        "ecdsa-rdfc-2019" => {
            verify_ecdsa_rdfc_2019_vp(&document.ldp_vc)
        }
        other => Err(Error::MdocAuth(format!(
            "Unsupported holder binding cryptosuite: {other}"
        ))),
    }
}

pub fn check_expiry(document: &MdocDocument) -> Result<(), Error> {
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(Error::DetachedIssuerAuth)?;
    let mso: Tag24<Mso> = cbor::from_slice(mso_bytes).map_err(|_| Error::MSOParsing)?;
    let validity_info = mso.into_inner().validity_info;
    if validity_info.valid_until.to_utc().gt(&OffsetDateTime::now_utc()) {
        return Ok(());
    } else {
        return Err(Error::CredentialExpired);
    }
}

pub fn device_authentication(
    document: &MdocDocument,
    session_transcript: SessionTranscript180135,
) -> Result<(), Error> {
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(Error::DetachedIssuerAuth)?;
    let mso: Tag24<Mso> = cbor::from_slice(mso_bytes).map_err(|_| Error::MSOParsing)?;
    let device_key = mso.into_inner().device_key_info.device_key;
    let jwk = SsiJwk::try_from(device_key)?;
    match jwk.params {
        Params::EC(p) => {
            let x_coordinate = p.x_coordinate.clone();
            let y_coordinate = p.y_coordinate.clone();
            let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                return Err(Error::MdocAuth(
                    "device key jwk is missing coordinates".to_string(),
                ));
            };
            let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;
            let namespaces_bytes = &document.device_signed.namespaces;
            let device_auth: &DeviceAuth = &document.device_signed.device_auth;
            
            match device_auth {
                DeviceAuth::DeviceSignature(device_signature) => {
                    let detached_payload = Tag24::new(DeviceAuthentication::new(
                        session_transcript,
                        document.doc_type.clone(),
                        namespaces_bytes.clone(),
                    ))
                    .map_err(|_| Error::CborDecodingError)?;
                    let external_aad = None;
                    let cbor_payload = cbor::to_vec(&detached_payload)?;
                    let result = device_signature.verify::<VerifyingKey, Signature>(
                        &verifying_key,
                        Some(&cbor_payload),
                        external_aad,
                    );
                    if !result.is_success() {
                        Err(Error::ParsingError)?
                    } else {
                        Ok(())
                    }
                }
                DeviceAuth::DeviceMac(_) => {
                    Err(Error::Unsupported)
                    // send not yet supported error
                }
            }
        }
        _ => Err(Error::MdocAuth("Unsupported device_key type".to_string())),
    }
}
