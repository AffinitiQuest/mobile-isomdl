use crate::cbor;
use crate::cose;
use crate::definitions::device_response::Document;
use crate::definitions::device_response::W3CDocument;
use crate::definitions::device_signed::DeviceNamespacesBytes;
use crate::definitions::issuer_signed;
use crate::definitions::x509::X5Chain;
use crate::definitions::CoseKey;
use crate::definitions::DeviceAuth;
use crate::definitions::EC2Curve;
use crate::definitions::Mso;
use crate::definitions::EC2Y;
use crate::definitions::{
    device_signed::{DeviceAuthentication, W3CDeviceAuthentication}, helpers::Tag24, SessionTranscript180135,
};
use crate::presentation::reader::Error;
use anyhow::Result;
use coset::iana;
use coset::CoseKeyBuilder;
use elliptic_curve::generic_array::GenericArray;
use issuer_signed::IssuerSigned;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use serde::Serialize;
use ssi_jwk::Params;
use ssi_jwk::JWK as SsiJwk;
use std::collections::BTreeMap;

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
    document: &W3CDocument,
    session_transcript: SessionTranscript180135,
) -> Result<(), Error> {
    let jwt = document.jwt.clone();
    let mut device_jwk = BTreeMap::new();
    device_jwk.insert("alg", "ES256");
    device_jwk.insert("kty", "EC");
    //device_jwk.insert("use", "sig");
    device_jwk.insert("x", "kNYnHB2Mxald17CScUyumLGMUmh_Iy1k0IllLHWJviw");
    device_jwk.insert("y", "YbnKNspahbv7dJbEAHRh-zUQKIDqTTuMxQjv4MQJftY");
    //let device_key = CoseKey::EC2 { crv: EC2Curve::P256, x: base64_url::decode("kNYnHB2Mxald17CScUyumLGMUmh_Iy1k0IllLHWJviw").unwrap(), y: EC2Y::Value(base64_url::decode("YbnKNspahbv7dJbEAHRh-zUQKIDqTTuMxQjv4MQJftY").unwrap())};
                
    let jwk: SsiJwk = serde_json::json!(device_jwk).try_into().unwrap();//SsiJwk::try_from(device_jwk)?;
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
            //let namespaces_bytes = &document.device_signed.namespaces;
            let device_auth: &DeviceAuth = &document.device_auth;
            match device_auth {
                DeviceAuth::DeviceSignature(device_signature) => {
                    println!("{:#?}", device_signature);
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
                    println!("{:#?}", result);
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
    // let device_auth: &DeviceAuth = &document.device_auth;
    // match device_auth {
    //     DeviceAuth::DeviceSignature(device_signature) => {
    //         let detached_payload = Tag24::new(W3CDeviceAuthentication::new(
    //             session_transcript,
    //             document.doc_type.clone()
    //         ))
    //         .map_err(|_| Error::CborDecodingError)?;
    //         let cbor_payload = cbor::to_vec(&detached_payload)?;
    //         Ok(cbor_payload)
    //     }
    //     DeviceAuth::DeviceMac(_) => {
    //         Err(Error::Unsupported)
    //         // send not yet supported error
    //     }
    // }
}

pub fn device_authentication(
    document: &Document,
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
