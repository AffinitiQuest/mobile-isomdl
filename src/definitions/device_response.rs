//! This module contains the definition of the `DeviceResponse` struct and related types.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned, DeviceAuth,
};

/// Represents a device response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    /// The version of the response.
    pub version: String,

    /// The documents associated with the response, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Documents>,

    /// The errors associated with the documents, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<DocumentErrors>,

    /// The status of the response.
    pub status: Status,
}

pub type Documents = NonEmptyVec<Document>;

/// A unified document covering all supported credential formats.
///
/// Serializes untagged (inner struct bytes only). Deserializes by inspecting
/// the CBOR map for the `"jwt"` key to pick the right variant, since ciborium
/// does not support `#[serde(untagged)]` deserialization.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Document {
    MsoMdoc(MdocDocument),
    W3cVc(W3cVcDocument),
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        // Capture the full CBOR value so we can inspect keys before picking a variant.
        let value = ciborium::Value::deserialize(deserializer)?;
        let has_jwt = if let ciborium::Value::Map(ref map) = value {
            map.iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "jwt" || s == "sdJwt"))
        } else {
            return Err(D::Error::custom("expected a CBOR map for Document"));
        };
        // Re-encode to bytes so we can deserialize into the concrete type.
        let bytes = crate::cbor::to_vec(&value).map_err(|e| D::Error::custom(e.to_string()))?;
        if has_jwt {
            crate::cbor::from_slice::<W3cVcDocument>(&bytes)
                .map(Document::W3cVc)
                .map_err(|e| D::Error::custom(e.to_string()))
        } else {
            crate::cbor::from_slice::<MdocDocument>(&bytes)
                .map(Document::MsoMdoc)
                .map_err(|e| D::Error::custom(e.to_string()))
        }
    }
}

impl Document {
    pub fn doc_type(&self) -> &str {
        match self {
            Document::MsoMdoc(d) => &d.doc_type,
            Document::W3cVc(d) => &d.doc_type,
        }
    }
}

/// An ISO mDL / MSOMDOC credential.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MdocDocument {
    /// A string representing the type of the document.
    pub doc_type: String,

    /// Issuer-signed data.
    pub issuer_signed: IssuerSigned,

    /// Device-signed data (not serialized in responses).
    #[serde(skip_serializing)]
    pub device_signed: DeviceSigned,

    /// Errors associated with the document, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

/// A W3C VC / SD-JWT credential.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct W3cVcDocument {
    /// A string representing the type of the document.
    pub doc_type: String,

    /// The JWT string carrying the credential.
    /// Accepts both "jwt" (JWT-VC) and "sdJwt" (SD-JWT) as the CBOR key name.
    #[serde(alias = "sdJwt")]
    pub jwt: String,

    /// Device authentication data (not serialized in responses).
    #[serde(skip_serializing)]
    pub device_auth: DeviceAuth,

    /// Errors associated with the document, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

/// Errors mapped by namespace and element identifier.
pub type Errors = NonEmptyMap<String, NonEmptyMap<String, DocumentErrorCode>>;
/// A list of document errors.
pub type DocumentErrors = NonEmptyVec<DocumentError>;
/// A map of document type to document error for them.
pub type DocumentError = BTreeMap<String, DocumentErrorCode>;

/// Document specific errors.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "i128", into = "i128")]
pub enum DocumentErrorCode {
    DataNotReturned,
    ApplicationSpecific(i128),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    OK,
    GeneralError,
    CborDecodingError,
    CborValidationError,
}

impl DeviceResponse {
    pub const VERSION: &'static str = "1.0";
}

impl From<DocumentErrorCode> for i128 {
    fn from(c: DocumentErrorCode) -> i128 {
        match c {
            DocumentErrorCode::DataNotReturned => 0,
            DocumentErrorCode::ApplicationSpecific(i) => i,
        }
    }
}

impl TryFrom<i128> for DocumentErrorCode {
    type Error = String;

    fn try_from(n: i128) -> Result<DocumentErrorCode, String> {
        match n {
            0 => Ok(DocumentErrorCode::DataNotReturned),
            i if i < 0 => Ok(DocumentErrorCode::ApplicationSpecific(i)),
            _ => Err(format!("unsupported or RFU error code used: {n}")),
        }
    }
}

impl From<Status> for u64 {
    fn from(s: Status) -> u64 {
        match s {
            Status::OK => 0,
            Status::GeneralError => 10,
            Status::CborDecodingError => 11,
            Status::CborValidationError => 12,
        }
    }
}

impl TryFrom<u64> for Status {
    type Error = String;

    fn try_from(n: u64) -> Result<Status, String> {
        match n {
            0 => Ok(Status::OK),
            10 => Ok(Status::GeneralError),
            11 => Ok(Status::CborDecodingError),
            12 => Ok(Status::CborValidationError),
            _ => Err(format!("unrecognised error code: {n}")),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::cbor;
    use crate::cose::MaybeTagged;
    use crate::definitions::device_signed::{
        DeviceNamespaces, DeviceNamespacesBytes, DeviceSignedItems,
    };
    use crate::definitions::helpers::NonEmptyVec;
    use crate::definitions::issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes};
    use crate::definitions::{
        DeviceAuth, DeviceSigned, DigestId, Document, IssuerSigned, IssuerSignedItem,
    };
    use super::MdocDocument;
    use coset::{CoseMac0, CoseSign1};
    use hex::FromHex;

    use super::{
        DeviceResponse, DocumentError, DocumentErrorCode, DocumentErrors, Documents, Status,
    };

    static DEVICE_RESPONSE_CBOR: &str = include_str!("../../test/definitions/device_response.cbor");

    #[test]
    fn device_response() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse =
            cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes =
            cbor::to_vec(&response).expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }

    #[test]
    fn device_response_roundtrip() {
        static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
        static COSE_MAC0: &str = include_str!("../../test/definitions/cose/mac0/serialized.cbor");

        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_Sign1 from bytes");
        let bytes = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        let cose_mac0: MaybeTagged<CoseMac0> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");

        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId::new(42),
            random: vec![42_u8].into(),
            element_identifier: "42".to_string(),
            element_value: ciborium::Value::Null,
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces = IssuerNamespaces::new("a".to_string(), vec);
        let device_signed_items = DeviceSignedItems::new("a".to_string(), ciborium::Value::Null);
        let mut device_namespaces = DeviceNamespaces::new();
        device_namespaces.insert("a".to_string(), device_signed_items);
        let device_namespaces_bytes = DeviceNamespacesBytes::new(device_namespaces).unwrap();
        let doc = Document::MsoMdoc(MdocDocument {
            doc_type: "aaa".to_string(),
            issuer_signed: IssuerSigned {
                namespaces: Some(issuer_namespaces),
                issuer_auth: cose_sign1.clone(),
            },
            device_signed: DeviceSigned {
                namespaces: device_namespaces_bytes,
                device_auth: DeviceAuth::DeviceMac(cose_mac0),
            },
            errors: None,
        });
        let docs = Documents::new(doc);
        let document_error_code = DocumentErrorCode::DataNotReturned;
        let mut error = DocumentError::new();
        error.insert("a".to_string(), document_error_code);
        let errors = DocumentErrors::new(error);
        let res = DeviceResponse {
            version: "1.0".to_string(),
            documents: Some(docs),
            document_errors: Some(errors),
            status: Status::OK,
        };
        let bytes = cbor::to_vec(&res).unwrap();
        let res: DeviceResponse = cbor::from_slice(&bytes).unwrap();
        let roundtripped_bytes = cbor::to_vec(&res).unwrap();
        assert_eq!(
            bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }
}
