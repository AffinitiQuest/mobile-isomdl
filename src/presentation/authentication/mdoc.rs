use crate::cbor;
use crate::cose;
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
