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

    let TokenSlices{claims,..} = raw::split_token(base_jwt).map_err(|_| Error::ParsingError)?;
    let raw_claim = raw::decode_json_token_slice(claims).map_err(|_| Error::ParsingError)?;
    
    let payload_object= raw_claim.as_object().ok_or(Error::ParsingError)?;

    // Support two key-binding formats:
    //  - SD-JWT VC (draft-ietf-oauth-sd-jwt-vc): device key in cnf.jwk (RFC 7800)
    //  - VCDM 1.1 JWT-VC: device key in vc.credentialSubject.id as a did:jwk URI
    let binding_key_jwk: SsiJwk = if let Some(cnf) = payload_object.get("cnf") {
        let jwk_val = cnf.get("jwk").ok_or(Error::ParsingError)?;
        serde_json::from_value(jwk_val.clone()).map_err(|_| Error::ParsingError)?
    } else {
        let vc = payload_object.get("vc").and_then(|v| v.as_object()).ok_or(Error::ParsingError)?;
        let credential_subject = vc.get("credentialSubject").and_then(|v| v.as_object()).ok_or(Error::ParsingError)?;
        let jwk_did = credential_subject.get("id").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
        let key_part = jwk_did.get(8..).ok_or(Error::ParsingError)?; // strip "did:jwk:"
        let jwk_bytes = base64_url::decode(key_part).map_err(|_| Error::ParsingError)?;
        let jwk_str = String::from_utf8(jwk_bytes).map_err(|_| Error::ParsingError)?;
        SsiJwk::from_str(&jwk_str).map_err(|_| Error::ParsingError)?
    };
    
    match binding_key_jwk.params {
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
            //let namespaces_bytes = &document.device_signed.namespaces;
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

    // Step 1: Compute expected challenge = hex(SHA-256(Tag24(session_transcript))).
    // The wallet holds the session transcript as Tag24-encoded CBOR bytes (the form
    // used throughout ISO 18013-5), so we must wrap in Tag24 before hashing.
    let transcript_cbor = crate::cbor::to_vec(
        &Tag24::new(session_transcript).map_err(|_| Error::CborDecodingError)?
    ).map_err(|_| Error::CborDecodingError)?;
    let expected_challenge = hex::encode(Sha256::digest(&transcript_cbor));

    // Step 2: Parse the VP JSON stored in ldp_vc.
    let vp: serde_json::Value = serde_json::from_str(&document.ldp_vc)
        .map_err(|_| Error::ParsingError)?;

    // Step 3: Extract the outer VP proof and validate the challenge.
    let proof = vp.get("proof").ok_or(Error::ParsingError)?;
    let challenge = proof.get("challenge").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
    if challenge != expected_challenge {
        return Err(Error::MdocAuth(format!(
            "VP challenge mismatch: got {challenge}, expected {expected_challenge}"
        )));
    }

    // Step 4: Extract the holder JWK from the did:jwk: verificationMethod.
    // Format: "did:jwk:<base64url-JWK>#0"
    let vm = proof.get("verificationMethod").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
    let did_part = vm.split('#').next().ok_or(Error::ParsingError)?;
    if !did_part.starts_with("did:jwk:") {
        return Err(Error::MdocAuth("VP verificationMethod must be a did:jwk DID".to_string()));
    }
    let key_b64 = &did_part[8..];
    let jwk_bytes = base64_url::decode(key_b64).map_err(|_| Error::ParsingError)?;
    let jwk_str = String::from_utf8(jwk_bytes).map_err(|_| Error::ParsingError)?;
    let holder_jwk: SsiJwk = SsiJwk::from_str(&jwk_str).map_err(|_| Error::ParsingError)?;

    // Step 5: Build a P-256 verifying key from the holder JWK.
    let verifying_key = match holder_jwk.params {
        Params::EC(ref p) => {
            let x = p.x_coordinate.as_ref().ok_or(Error::ParsingError)?;
            let y = p.y_coordinate.as_ref().ok_or(Error::ParsingError)?;
            let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| Error::ParsingError)?
        }
        _ => return Err(Error::MdocAuth("VP holder key must be P-256 EC".to_string())),
    };

    // Step 6: Build verification data per ecdsa-jcs-2019 spec.
    // proofConfig = proof object without proofValue, plus @context from the VP.
    // unsecuredDocument = VP without proof field.
    // hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
    //
    // serde_json without the preserve_order feature uses BTreeMap, giving
    // alphabetically sorted keys — which satisfies JCS canonicalization.
    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
    }
    let mut unsigned_vp = vp.clone();
    if let Some(obj) = unsigned_vp.as_object_mut() {
        obj.remove("proof");
    }

    let canonical_proof_config = serde_json::to_string(&jcs_sort(&proof_config)).map_err(|_| Error::ParsingError)?;
    let canonical_document = serde_json::to_string(&jcs_sort(&unsigned_vp)).map_err(|_| Error::ParsingError)?;

    println!("[ldp_vc_device_auth] canonical_proof_config: {canonical_proof_config}");
    println!("[ldp_vc_device_auth] canonical_document: {canonical_document}");

    let hash_proof_config = Sha256::digest(canonical_proof_config.as_bytes());
    let hash_document = Sha256::digest(canonical_document.as_bytes());

    println!("[ldp_vc_device_auth] SHA-256(proofConfig): {}", hex::encode(&hash_proof_config));
    println!("[ldp_vc_device_auth] SHA-256(document):    {}", hex::encode(&hash_document));

    let mut verify_data = Vec::with_capacity(64);
    verify_data.extend_from_slice(&hash_proof_config);
    verify_data.extend_from_slice(&hash_document);

    println!("[ldp_vc_device_auth] verify_data (hex): {}", hex::encode(&verify_data));

    // Step 7: Decode the proofValue (multibase base58btc, 'z' prefix).
    let proof_value = proof.get("proofValue").and_then(|v| v.as_str()).ok_or(Error::ParsingError)?;
    if !proof_value.starts_with('z') {
        return Err(Error::MdocAuth("proofValue must use multibase base58btc (z prefix)".to_string()));
    }
    let sig_bytes = bs58::decode(&proof_value[1..]).into_vec().map_err(|_| Error::ParsingError)?;

    println!("[ldp_vc_device_auth] sig_bytes len: {}, hex: {}", sig_bytes.len(), hex::encode(&sig_bytes));

    // Step 8: Verify the P-256 ECDSA signature.
    // ecdsa-jcs-2019 uses IEEE P1363 format (64-byte R||S); fall back to DER.
    use p256::ecdsa::signature::Verifier;
    let signature = if sig_bytes.len() == 64 {
        println!("[ldp_vc_device_auth] parsing signature as IEEE P1363 (R||S)");
        p256::ecdsa::Signature::try_from(sig_bytes.as_slice()).map_err(|_| Error::ParsingError)?
    } else {
        println!("[ldp_vc_device_auth] parsing signature as DER ({} bytes)", sig_bytes.len());
        p256::ecdsa::Signature::from_der(&sig_bytes).map_err(|_| Error::ParsingError)?
    };

    verifying_key.verify(&verify_data, &signature)
        .map_err(|_| Error::MdocAuth("VP holder proof signature verification failed".to_string()))
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
