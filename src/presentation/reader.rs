//! This module is responsible for the reader's interaction with the device.
//!
//! It handles this through [SessionManager] state
//! which is responsible for handling the session with the device.
//!
//! From the reader's perspective, the flow is as follows:
//!
//! ```ignore
#![doc = include_str!("../../docs/on_simulated_reader.txt")]
//! ```
//!
//! ### Example
//!
//! You can view examples in `tests` directory in `simulated_device_and_reader.rs`, for a basic example and
//! `simulated_device_and_reader_state.rs` which uses `State` pattern, `Arc` and `Mutex`.
use std::collections::BTreeMap;

use anyhow::Context;
use anyhow::{anyhow, Result};
use coset::Label;
use ecdsa::SignatureEncoding;
use sec1::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use signature::{Signer};
use uuid::Uuid;

use coset::iana;
use p256::ecdsa::{Signature, SigningKey};
use p256::{SecretKey};

use super::authentication::{
    mdoc::{device_authentication, ldp_vc_device_authentication, w3c_device_authentication, issuer_authentication},
    AuthenticationStatus, ResponseAuthenticationOutcome,
};

use crate::definitions::x509;
use crate::cose::sign1::PreparedCoseSign1;
use crate::cose::SignatureAlgorithm;
use crate::definitions::device_request::ReaderAuth;
use crate::presentation::authentication::mdoc::check_expiry;
use crate::presentation::authentication::ResponseAuthenticationOutcomes;
use crate::{
    cbor::{self, CborError},
    definitions::{
        device_engagement::DeviceRetrievalMethod,
        device_key::cose_key::Error as CoseError,
        device_request::{self, DeviceRequest, DocRequest, ItemsRequest},
        device_response::{Document, MdocDocument},
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret, Handover,
            SessionEstablishment,
        },
        x509::{trust_anchor::TrustAnchorRegistry, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain},
        DeviceEngagement, DeviceResponse, SessionData, SessionTranscript180135,
    },
    presentation::reader::{device_request::ItemsRequestBytes, Error as ReaderError},
};

/// The main state of the reader.
///
/// The reader's [SessionManager] state machine is responsible
/// for handling the session with the device.
///
/// The transition to this state is made by [SessionManager::establish_session].
#[derive(Serialize, Deserialize, Clone)]
pub struct SessionManager {
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    trust_anchor_registry: TrustAnchorRegistry,
    doc_type: String,
    format: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthentication(
    pub String,
    pub SessionTranscript180135,
    pub ItemsRequestBytes,
);

/// Various errors that can occur during the interaction with the device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Received IssuerAuth had a detached payload.")]
    DetachedIssuerAuth,
    #[error("Could not parse MSO.")]
    MSOParsing,
    /// The QR code had the wrong prefix or the contained data could not be decoded.
    #[error("the qr code had the wrong prefix or the contained data could not be decoded: {0}")]
    InvalidQrCode(anyhow::Error),
    /// Device did not transmit any data.
    #[error("Device did not transmit any data.")]
    DeviceTransmissionError,
    /// Device did not transmit an mDL.
    #[error("Device did not transmit an mDL.")]
    DocumentTypeError,
    /// The device did not transmit any mDL data.
    #[error("the device did not transmit any mDL data.")]
    NoMdlDataTransmission,
    /// Device did not transmit any data in the `org.iso.18013.5.1` namespace.
    #[error("device did not transmit any data in the org.iso.18013.5.1 namespace.")]
    IncorrectNamespace,
    /// The Device responded with an error.
    #[error("device responded with an error.")]
    HolderError,
    /// Could not decrypt the response.
    #[error("could not decrypt the response.")]
    DecryptionError,
    /// Unexpected CBOR type for offered value.
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    /// Not a valid JSON input.
    #[error("not a valid JSON input.")]
    JsonError,
    /// Unexpected data type for data element.
    #[error("Unexpected data type for data element.")]
    ParsingError,
    /// Request for data is invalid.
    #[error("Request for data is invalid.")]
    InvalidRequest,
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
    #[error("No x5chain found for issuer authentication")]
    X5ChainMissing,
    #[error("Failed to parse x5chain: {0}")]
    X5ChainParsing(anyhow::Error),
    #[error("issuer authentication failed: {0}")]
    IssuerAuthentication(String),
    #[error("Unable to parse issuer public key")]
    IssuerPublicKey(anyhow::Error),
    #[error("Credential is expired")]
    CredentialExpired,
    #[error("Returned credential format does not match requested format")]
    UnexpectedFormat,
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborDecodingError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::JsonError
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<CoseError> for Error {
    fn from(value: CoseError) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<non_empty_vec::Error> for Error {
    fn from(value: non_empty_vec::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<asn1_rs::Error> for Error {
    fn from(value: asn1_rs::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl SessionManager {
    /// Establish a session with the device.
    ///
    /// Internally it generates the ephemeral keys,
    /// derives the shared secret, and derives the session keys
    /// (using **Diffie–Hellman key exchange**).
    pub fn establish_session(
        qr_code: String,
        doc_type: String,
        format: String,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: TrustAnchorRegistry,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code)
            .context("failed to construct QR code")?;

        //generate own keys
        let key_pair = create_p256_ephemeral_keys().context("failed to generate ephemeral key")?;
        let e_reader_key_private = key_pair.0;
        let e_reader_key_public =
            Tag24::new(key_pair.1).context("failed to encode public cose key")?;

        //decode device_engagement
        let device_engagement = device_engagement_bytes.as_ref();
        let e_device_key = &device_engagement.security.1;

        // calculate ble Ident value
        let ble_ident =
            super::calculate_ble_ident(e_device_key).context("failed to calculate BLE Ident")?;

        // derive shared secret
        let shared_secret = get_shared_secret(
            e_device_key.clone().into_inner(),
            &e_reader_key_private.into(),
        )
        .context("failed to derive shared session secret")?;
        let a = shared_secret.raw_secret_bytes().as_slice();
        let mut shared_secret_hex_string = String::with_capacity(a.len() * 2);
        //println!("Shared secret: {:#?}", a);

        let session_transcript = SessionTranscript180135(
            device_engagement_bytes,
            e_reader_key_public.clone(),
            Handover::QR,
        );

        let session_transcript_bytes = Tag24::new(session_transcript.clone())
            .context("failed to encode session transcript")?;

        //derive session keys
        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)
            .context("failed to derive reader session key")?
            .into();
        let sk_device = derive_session_key(&shared_secret, &session_transcript_bytes, false)
            .context("failed to derive device session key")?
            .into();

        let mut session_manager = Self {
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            trust_anchor_registry,
            doc_type: doc_type.clone(),
            format: format.clone(),
        };

        let request = session_manager
            .build_request(doc_type, format, namespaces)
            .context("failed to build device request")?;
        let session = SessionEstablishment {
            data: request.into(),
            e_reader_key: e_reader_key_public,
        };
        let session_request =
            cbor::to_vec(&session).context("failed to encode session establishment")?;

        Ok((session_manager, session_request, ble_ident))
    }

    pub fn first_peripheral_server_uuid(&self) -> Option<&Uuid> {
        self.session_transcript
            .0
            .as_ref()
            .device_retrieval_methods
            .as_ref()
            .and_then(|ms| {
                ms.as_ref()
                    .iter()
                    .filter_map(|m| match m {
                        DeviceRetrievalMethod::BLE(opt) => {
                            opt.peripheral_server_mode.as_ref().map(|cc| &cc.uuid)
                        }
                        _ => None,
                    })
                    .next()
            })
    }

    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.session_transcript
            .0
            .as_ref()
            .device_retrieval_methods
            .as_ref()
            .and_then(|ms| {
                ms.as_ref()
                    .iter()
                    .filter_map(|m| match m {
                        DeviceRetrievalMethod::BLE(opt) => {
                            opt.central_client_mode.as_ref().map(|cc| &cc.uuid)
                        }
                        _ => None,
                    })
                    .next()
            })
    }

    /// Creates a new request with specified elements to request.
    pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let request = self.build_request("".into(), "mdoc".to_string(), namespaces)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        cbor::to_vec(&session).map_err(Into::into)
    }
    
    fn sign<S, Sig>(signature_payload: &[u8], s: &S) -> anyhow::Result<Vec<u8>>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        Ok(s.try_sign(signature_payload)?
            .to_vec())
    }
    
    fn generate_reader_auth(session_transcript: SessionTranscript180135, item_request: ItemsRequest) -> Result<ReaderAuth> {
        let private_key: &str = include_str!("../definitions/ReaderAuthFiles/private.pem");
        let x5c_file = include_bytes!("../definitions/ReaderAuthFiles/chain.x5c");

        let x5c_vec: Vec<String> = serde_json::from_slice(x5c_file)?;
        let x5chain = X5Chain::builder().with_der_chain(x5c_vec)?.build()?;

        let signer: SigningKey = SecretKey::from_pkcs8_pem(private_key)?.into();
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let unprotected = coset::HeaderBuilder::new().value(33, x5chain.into_cbor()).build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected);
        let detached_payload = Tag24::new(ReaderAuthentication(
            "ReaderAuthentication".into(),
            session_transcript.clone(),
            Tag24::new(item_request)?
        ))?;

        let detached_payload_bytes = cbor::to_vec(&detached_payload)?;
        let prepared = PreparedCoseSign1::new(builder, Some(&detached_payload_bytes), None, false)?;
        let signature_payload = prepared.signature_payload();
        
        let signature = Self::sign::<SigningKey, Signature>(signature_payload, &signer)?
            .to_vec();
        let cose_sign1 = prepared.finalize(signature);

        return Ok(cose_sign1)
    }

    fn build_request(&mut self, doc_type: String, format: String, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        // if !validate_request(namespaces.clone()).is_ok() {
        //     return Err(anyhow::Error::msg(
        //         "At least one of the namespaces contain an invalid combination of fields to request",
        //     ));
        // }
        let mut request_info = BTreeMap::new();
        request_info.insert("format".to_string(), ciborium::Value::Text(format));
        let items_request = ItemsRequest {
            doc_type: doc_type.into(),
            namespaces,
            request_info: Some(request_info),
        };

        let reader_auth = Self::generate_reader_auth(self.session_transcript.clone(), items_request.clone())?;

        let doc_request = DocRequest {
            reader_auth: Some(reader_auth),
            items_request: Tag24::new(items_request)?,
        };
        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
        };
        let device_request_bytes = cbor::to_vec(&device_request)?;
        session::encrypt_reader_data(
            &self.sk_reader.into(),
            &device_request_bytes,
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    }

    fn decrypt_response(&mut self, response: &[u8]) -> Result<DeviceResponse, Error> {
        log::info!("[decrypt_response] input bytes: {}", response.len());
        let session_data: SessionData = cbor::from_slice(response).map_err(|e| {
            log::info!("[decrypt_response] failed to parse SessionData: {e:?}");
            Error::CborDecodingError
        })?;
        log::info!("[decrypt_response] SessionData parsed, data present: {}", session_data.data.is_some());
        let encrypted_response = match session_data.data {
            None => return Err(Error::HolderError),
            Some(r) => r,
        };
        log::info!("[decrypt_response] encrypted payload bytes: {}", encrypted_response.as_ref().len());
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| {
            log::info!("[decrypt_response] decryption failed: {_e:?}");
            Error::DecryptionError
        })?;
        log::info!("[decrypt_response] decrypted {} bytes", decrypted_response.len());
        let decrypted_response = decompress_metadata_images(decrypted_response)?;
        let device_response: DeviceResponse = cbor::from_slice(&decrypted_response).map_err(|e| {
            log::info!("[decrypt_response] failed to parse DeviceResponse: {e:?}");
            log::info!("[decrypt_response] raw decrypted hex: {}", hex::encode(&decrypted_response));
            Error::CborDecodingError
        })?;
        log::info!(
            "[decrypt_response] DeviceResponse parsed: version={:?}, documents={}, status={:?}",
            device_response.version,
            device_response.documents.as_ref().map_or(0, |d| d.len()),
            device_response.status,
        );
        Ok(device_response)
    }

    pub fn handle_response(&mut self, response: &[u8]) -> ResponseAuthenticationOutcomes {
        let mut validated_responses = ResponseAuthenticationOutcomes::default();

        let device_response = match self.decrypt_response(response) {
            Ok(device_response) => device_response,
            Err(e) => {
                log::error!("[handle_response] decrypt_response failed: {e:?}");
                validated_responses.errors.insert(
                    "decryption_errors".to_string(),
                    json!(vec![format!("{e:?}")]),
                );
                return validated_responses;
            }
        };

        let documents = match device_response.documents.as_ref() {
            Some(docs) => docs,
            None => {
                log::warn!("[handle_response] DeviceResponse contained no documents");
                validated_responses.errors.insert(
                    "parsing_errors".to_string(),
                    json!(vec![format!("{:?}", Error::DeviceTransmissionError)]),
                );
                return validated_responses;
            }
        };

        log::info!("[handle_response] processing {} document(s), requested format={:?} doc_type={:?}", documents.len(), self.format, self.doc_type);
        for document in documents.iter() {
            log::info!(
                "[handle_response] document variant={}, doc_type={}",
                match document {
                    Document::MsoMdoc(_) => "MsoMdoc",
                    Document::W3cVc(_) => "W3cVc",
                    Document::LdpVc(_) => "LdpVc",
                },
                document.doc_type(),
            );
            if !format_matches_document(&self.format, document) {
                log::warn!(
                    "[handle_response] format mismatch: requested={:?}, received={}",
                    self.format,
                    match document {
                        Document::MsoMdoc(_) => "MsoMdoc",
                        Document::W3cVc(_) => "W3cVc",
                        Document::LdpVc(_) => "LdpVc",
                    }
                );
                validated_responses.errors.insert(
                    "format_errors".to_string(),
                    json!(vec![format!("{:?}", Error::UnexpectedFormat)]),
                );
                continue;
            }
            match document {
                Document::MsoMdoc(mdoc) if mdoc.doc_type == self.doc_type => {
                    match parse_mdoc_document(mdoc) {
                        Ok((x5chain, namespaces)) => {
                            let validated = self.validate_mdoc_response(x5chain, mdoc, namespaces);
                            validated_responses.responses.push(validated);
                        }
                        Err(e) => {
                            validated_responses.errors.insert(
                                "parsing_errors".to_string(),
                                json!(vec![format!("{e:?}")]),
                            );
                        }
                    }
                }
                Document::MsoMdoc(mdoc) => {
                    log::warn!("[handle_response] mdoc doc_type mismatch: received={:?}, requested={:?}", mdoc.doc_type, self.doc_type);
                }
                Document::W3cVc(w3c) => {
                    let mut validated_response = ResponseAuthenticationOutcome {
                        signed_issuer_metadata: w3c.signed_issuer_metadata.clone(),
                        ..Default::default()
                    };
                    let mut response_fields = BTreeMap::new();
                    response_fields.insert("doc_type".to_string(), w3c.doc_type.clone());
                    response_fields.insert("jwt".to_string(), w3c.jwt.clone());

                    match w3c_device_authentication(w3c, self.session_transcript.clone()) {
                        Ok(()) => {
                            validated_response.device_authentication = AuthenticationStatus::Valid;
                        }
                        Err(e) => {
                            validated_response.device_authentication = AuthenticationStatus::Invalid;
                            validated_response.errors.insert(
                                "device_authentication_errors".to_string(),
                                json!(vec![format!("{e:?}")]),
                            );
                        }
                    }
                    validated_response.response.insert("document".to_string(), json!(response_fields));
                    validated_responses.responses.push(validated_response);
                }
                Document::LdpVc(ldp_vc_doc) => {
                    let mut validated_response = ResponseAuthenticationOutcome {
                        signed_issuer_metadata: ldp_vc_doc.signed_issuer_metadata.clone(),
                        ..Default::default()
                    };
                    let mut response_fields = BTreeMap::new();
                    response_fields.insert("doc_type".to_string(), ldp_vc_doc.doc_type.clone());
                    response_fields.insert("ldp_vc".to_string(), ldp_vc_doc.ldp_vc.clone());

                    match ldp_vc_device_authentication(ldp_vc_doc, self.session_transcript.clone()) {
                        Ok(()) => {
                            validated_response.device_authentication = AuthenticationStatus::Valid;
                        }
                        Err(e) => {
                            validated_response.device_authentication = AuthenticationStatus::Invalid;
                            validated_response.errors.insert(
                                "device_authentication_errors".to_string(),
                                json!(vec![format!("{e:?}")]),
                            );
                        }
                    }
                    validated_response.response.insert("document".to_string(), json!(response_fields));
                    validated_responses.responses.push(validated_response);
                }
            }
        }

        validated_responses
    }

    fn validate_mdoc_response(
        &mut self,
        x5chain: X5Chain,
        document: &MdocDocument,
        namespaces: BTreeMap<String, serde_json::Value>,
    ) -> ResponseAuthenticationOutcome {
        log::info!("[validate_mdoc_response] signed_issuer_metadata present: {}", document.signed_issuer_metadata.is_some());

        let leaf_cert = x5chain.end_entity_certificate();
        let mut validated_response = ResponseAuthenticationOutcome {
            response: namespaces,
            signed_issuer_metadata: document.signed_issuer_metadata.clone(),
            leaf_certificate_serial_number: Some(hex::encode(
                leaf_cert.tbs_certificate.serial_number.as_bytes(),
            )),
            leaf_certificate_crl_distribution_point: leaf_certificate_crl_distribution_point(leaf_cert),
            ..Default::default()
        };

        if let Err(_) = check_expiry(document) {
            validated_response.errors.insert("expired".to_string(), serde_json::Value::Bool(true));
        }

        match device_authentication(document, self.session_transcript.clone()) {
            Ok(_) => {
                validated_response.device_authentication = AuthenticationStatus::Valid;
            }
            Err(e) => {
                validated_response.device_authentication = AuthenticationStatus::Invalid;
                validated_response.errors.insert(
                    "device_authentication_errors".to_string(),
                    json!(vec![format!("{e:?}")]),
                );
            }
        }

        let validation_errors = x509::validation::ValidationRuleset::Mdl
            .validate(&x5chain, &self.trust_anchor_registry)
            .errors;
        if validation_errors.is_empty() {
            match issuer_authentication(x5chain, &document.issuer_signed) {
                Ok(_) => {
                    validated_response.issuer_authentication = AuthenticationStatus::Valid;
                }
                Err(e) => {
                    validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                    validated_response.errors.insert(
                        "issuer_authentication_errors".to_string(),
                        serde_json::json!(vec![format!("{e:?}")]),
                    );
                }
            }
        } else {
            validated_response
                .errors
                .insert("certificate_errors".to_string(), json!(validation_errors));
            validated_response.issuer_authentication = AuthenticationStatus::Invalid
        };
        validated_response
    }
}

/// Extracts the URI from a leaf certificate's own CRLDistributionPoints extension
/// (OID 2.5.29.31), if present and well-formed. Returns `None` rather than erroring
/// when the extension is absent - it's optional per RFC 5280, so a missing/malformed
/// extension is a normal state here, not a validation failure (validity of this
/// extension when required is checked separately, see
/// `x509::validation::extensions::CrlDistributionPointsValidator`).
fn leaf_certificate_crl_distribution_point(leaf_cert: &x509_cert::Certificate) -> Option<String> {
    use const_oid::AssociatedOid;
    use der::Decode;
    use x509_cert::ext::pkix::{
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints,
    };

    leaf_cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == CrlDistributionPoints::OID)
        .and_then(|ext| CrlDistributionPoints::from_der(ext.extn_value.as_bytes()).ok())
        .and_then(|crl_dps| {
            crl_dps.0.into_iter().find_map(|dp| match dp.distribution_point {
                Some(DistributionPointName::FullName(names)) => {
                    names.into_iter().find_map(|gn| match gn {
                        GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_string()),
                        _ => None,
                    })
                }
                _ => None,
            })
        })
}

fn format_matches_document(format: &str, document: &Document) -> bool {
    match (format, document) {
        ("mdoc", Document::MsoMdoc(_)) => true,
        ("w3cjwt", Document::W3cVc(d)) => !d.jwt.contains('~'),
        ("sd-jwt", Document::W3cVc(d)) => d.jwt.contains('~'),
        ("ldp_vc", Document::LdpVc(_)) => true,
        _ => false,
    }
}

fn parse_mdoc_document(
    document: &MdocDocument,
) -> Result<(X5Chain, BTreeMap<String, Value>), Error> {
    let header = document.issuer_signed.issuer_auth.unprotected.clone();
    let x5chain = header
        .rest
        .iter()
        .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
        .map(|(_, value)| value.to_owned())
        .map(X5Chain::from_cbor)
        .ok_or(Error::X5ChainMissing)?
        .map_err(Error::X5ChainParsing)?;
    let namespaces = parse_namespaces_for_doc(document)?;
    Ok((x5chain, namespaces))
}

fn parse_response(value: ciborium::Value) -> Result<Value, Error> {
    match value {
        ciborium::Value::Text(s) => Ok(Value::String(s)),
        ciborium::Value::Tag(_t, v) => {
            if let ciborium::Value::Text(d) = *v {
                Ok(Value::String(d))
            } else {
                Err(Error::ParsingError)
            }
        }
        ciborium::Value::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        ciborium::Value::Map(m) => {
            let mut map_response = serde_json::Map::<String, Value>::new();
            for (key, value) in m {
                if let ciborium::Value::Text(k) = key {
                    let parsed = parse_response(value)?;
                    map_response.insert(k, parsed);
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        ciborium::Value::Bytes(b) => Ok(json!(b)),
        ciborium::Value::Bool(b) => Ok(json!(b)),
        ciborium::Value::Integer(i) => Ok(json!(<ciborium::value::Integer as Into<i128>>::into(i))),
        _ => Err(Error::ParsingError),
    }
}

fn _validate_request(namespaces: device_request::Namespaces) -> Result<bool, Error> {
    // TODO: Check country name of certificate matches mdl

    // Check if request follows ISO18013-5 restrictions
    // A valid mdoc request can contain a maximum of 2 age_over_NN fields
    let age_over_nn_requested: Vec<(String, bool)> = namespaces
        .get("org.iso.18013.5.1")
        .map(|k| k.clone().into_inner())
        //To Do: get rid of unwrap
        .unwrap()
        .into_iter()
        .filter(|x| x.0.contains("age_over"))
        .collect();

    if age_over_nn_requested.len() > 2 {
        //To Do: Decide what should happen when more than two age_over_nn are requested
        return Err(Error::InvalidRequest);
    }

    Ok(true)
}

fn parse_namespaces_for_doc(
    document: &MdocDocument,
) -> Result<BTreeMap<String, serde_json::Value>, Error> {
    let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
    let mut namespaces = document
        .issuer_signed
        .namespaces
        .as_ref()
        .ok_or(Error::NoMdlDataTransmission)?
        .clone()
        .into_inner();

    let keys: Vec<String> = namespaces.keys().cloned().collect();

    for namespace_name in keys {
        let mut namespace_fields = BTreeMap::<String, serde_json::Value>::new();
        if let Some(namespace) = namespaces.remove(&namespace_name) {
            namespace
                .into_iter() // COMPILE FIX: was .into_inner().into_iter() when namespace was NonEmptyVec; now plain Vec
                .map(|item| item.into_inner())
                .for_each(|item| {
                    let value = parse_response(item.element_value.clone());
                    if let Ok(val) = value {
                        namespace_fields.insert(item.element_identifier, val);
                    }
                });            
        }

        parsed_response.insert(
            namespace_name.to_string(),
            serde_json::to_value(namespace_fields)?,
        );
    }

    if(parsed_response.is_empty()) {
        return Err(Error::IncorrectNamespace);
    }

    Ok(parsed_response)
}

/// Expand `imageRefs` injected by the wallet's `compressMetadataImages` step.
///
/// The wallet replaces duplicate logo/background data URIs in each document's
/// `signedIssuerMetadata` JWT payload with `__ref:N__` tokens, then appends an
/// `imageRefs` map to the top-level CBOR.  Here we reverse that: restore the
/// tokens and remove the `imageRefs` key before the typed `DeviceResponse` parse.
///
/// Returns the original bytes unchanged if `imageRefs` is absent (pre-compression
/// wallets).  Returns `CborDecodingError` only if the bytes are not valid CBOR at
/// all, which would cause the subsequent typed parse to fail anyway.
fn decompress_metadata_images(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    let value: ciborium::Value = cbor::from_slice(&bytes).map_err(|_| Error::CborDecodingError)?;

    let mut map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Ok(bytes),
    };

    let image_refs_idx = map.iter().position(|(k, _)| {
        matches!(k, ciborium::Value::Text(s) if s == "imageRefs")
    });
    let image_refs_idx = match image_refs_idx {
        None => return Ok(bytes),
        Some(i) => i,
    };

    let (_, image_refs_val) = map.remove(image_refs_idx);

    let ref_pairs: Vec<(String, String)> = match image_refs_val {
        ciborium::Value::Map(m) => m
            .into_iter()
            .filter_map(|(k, v)| {
                let key = match k {
                    ciborium::Value::Text(s) => s,
                    _ => return None,
                };
                let arr = match v {
                    ciborium::Value::Array(a) if a.len() == 2 => a,
                    _ => return None,
                };
                let mime = match &arr[0] {
                    ciborium::Value::Text(s) => s.clone(),
                    _ => return None,
                };
                let data = match &arr[1] {
                    ciborium::Value::Bytes(b) => b.clone(),
                    ciborium::Value::Tag(_, inner) => match inner.as_ref() {
                        ciborium::Value::Bytes(b) => b.clone(),
                        _ => return None,
                    },
                    _ => return None,
                };
                let uri = format!("data:{};base64,{}", mime, base64::encode(&data));
                Some((format!("__ref:{}__", key), uri))
            })
            .collect(),
        _ => return Ok(bytes),
    };

    if ref_pairs.is_empty() {
        return Ok(bytes);
    }

    for (key, val) in map.iter_mut() {
        if matches!(key, ciborium::Value::Text(s) if s == "documents") {
            if let ciborium::Value::Array(docs) = val {
                for doc in docs.iter_mut() {
                    restore_signed_issuer_metadata(doc, &ref_pairs);
                }
            }
            break;
        }
    }

    let restored = cbor::to_vec(&ciborium::Value::Map(map)).map_err(|_| Error::CborDecodingError)?;
    log::info!(
        "[decompress_metadata_images] restored {} image ref(s), {} -> {} bytes",
        ref_pairs.len(), bytes.len(), restored.len()
    );
    Ok(restored)
}

fn restore_signed_issuer_metadata(doc: &mut ciborium::Value, ref_pairs: &[(String, String)]) {
    if let ciborium::Value::Map(doc_map) = doc {
        for (key, val) in doc_map.iter_mut() {
            if matches!(key, ciborium::Value::Text(s) if s == "signedIssuerMetadata") {
                if let ciborium::Value::Text(jwt_str) = val {
                    let restored = restore_refs_in_jwt(jwt_str.as_str(), ref_pairs);
                    *jwt_str = restored;
                }
                break;
            }
        }
    }
}

fn restore_refs_in_jwt(jwt: &str, ref_pairs: &[(String, String)]) -> String {
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return jwt.to_string();
    }
    let payload_bytes = match base64_url::decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return jwt.to_string(),
    };
    let payload_text = match String::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => return jwt.to_string(),
    };
    let mut restored = payload_text;
    for (ref_key, image_uri) in ref_pairs {
        restored = restored.replace(ref_key.as_str(), image_uri.as_str());
    }
    let new_payload = base64_url::encode(restored.as_bytes());
    format!("{}.{}.{}", parts[0], new_payload, parts[2])
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn nested_response_values() {
        let domestic_driving_privileges = crate::cbor::from_slice(&hex::decode("81A276646F6D65737469635F76656869636C655F636C617373A46A69737375655F64617465D903EC6A323032342D30322D31346B6578706972795F64617465D903EC6A323032382D30332D3131781B646F6D65737469635F76656869636C655F636C6173735F636F64656243207822646F6D65737469635F76656869636C655F636C6173735F6465736372697074696F6E76436C6173732043204E4F4E2D434F4D4D45524349414C781D646F6D65737469635F76656869636C655F7265737472696374696F6E7381A27821646F6D65737469635F76656869636C655F7265737472696374696F6E5F636F64656230317828646F6D65737469635F76656869636C655F7265737472696374696F6E5F6465736372697074696F6E78284D555354205745415220434F5252454354495645204C454E534553205748454E2044524956494E47").unwrap()).unwrap();
        let json = parse_response(domestic_driving_privileges).unwrap();
        let expected = serde_json::json!(
          [
            {
              "domestic_vehicle_class": {
                "issue_date": "2024-02-14",
                "expiry_date": "2028-03-11",
                "domestic_vehicle_class_code": "C ",
                "domestic_vehicle_class_description": "Class C NON-COMMERCIAL"
              },
              "domestic_vehicle_restrictions": [
                {
                  "domestic_vehicle_restriction_code": "01",
                  "domestic_vehicle_restriction_description": "MUST WEAR CORRECTIVE LENSES WHEN DRIVING"
                }
              ]
            }
          ]
        );
        assert_eq!(json, expected)
    }
}
