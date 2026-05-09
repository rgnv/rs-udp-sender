use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{AsyncStreamCipher, BlockEncryptMut, KeyIvInit};
use des::Des;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use md5::Md5;
use rasn::ber;
use rasn::types::ObjectIdentifier;
use rasn_smi::v1::ToOpaque;
use rasn_snmp::v3::SecurityParameters;
use rasn_snmp::{v1, v2, v2c, v3};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use thiserror::Error;

use crate::constants::{DEFAULT_SNMP_ENGINE_ID, SNMP_SYS_UP_TIME_OID};

const SNMP_TRAP_OID_ZERO: &str = "1.3.6.1.6.3.1.1.4.1.0";
const DEFAULT_SNMP_COMMUNITY: &str = "public";

#[derive(Debug, Clone)]
pub struct SNMPVarbind {
    pub oid: String,
    pub asn_type: SNMPType,
    pub value: SNMPValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SNMPType {
    Integer,
    OctetString,
    ObjectIdentifier,
    TimeTicks,
    IpAddress,
    Counter32,
    Gauge32,
    Null,
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SNMPValue {
    Int(i64),
    Str(String),
    Oid(String),
    Uint(u32),
    Ip(Ipv4Addr),
    Bytes(Vec<u8>),
    Null,
}

#[derive(Debug, Clone)]
pub struct SNMPV1TrapConfig {
    pub community: String,
    pub enterprise_oid: String,
    pub agent_addr: Ipv4Addr,
    pub generic_trap: i32,
    pub specific_trap: i32,
    pub timestamp: Option<u32>,
    pub varbinds: Vec<SNMPVarbind>,
}

#[derive(Debug, Clone)]
pub struct SNMPV2cTrapConfig {
    pub community: String,
    pub trap_oid: String,
    pub timestamp: Option<u32>,
    pub varbinds: Vec<SNMPVarbind>,
}

#[derive(Debug, Clone)]
pub struct SNMPV3TrapConfig {
    pub username: String,
    pub engine_id: Option<String>,
    pub auth_protocol: AuthProtocol,
    pub auth_password: String,
    pub priv_protocol: PrivProtocol,
    pub priv_password: String,
    pub engine_boots: u32,
    pub engine_time: u32,
    pub trap_oid: String,
    pub timestamp: Option<u32>,
    pub varbinds: Vec<SNMPVarbind>,
    pub is_inform: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    NoAuth,
    MD5,
    SHA,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    NoPriv,
    DES,
    AES,
    AES192,
    AES256,
    AES192C,
    AES256C,
}

#[derive(Error, Debug)]
pub enum SnmpError {
    #[error("ASN.1 encoding error: {0}")]
    EncodingError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Key initialization failed: {0}")]
    KeyInitFailed(String),
    #[error("Invalid OID: {0}")]
    InvalidOid(String),
}

pub fn build_snmpv1_trap_pdu(config: SNMPV1TrapConfig) -> Result<Vec<u8>, SnmpError> {
    if config.enterprise_oid.trim().is_empty() {
        return Err(SnmpError::MissingField("enterprise_oid".to_string()));
    }

    let enterprise = parse_oid(&config.enterprise_oid)?;
    let time_stamp = rasn_smi::v1::TimeTicks(config.timestamp.unwrap_or_else(current_unix_seconds));

    let variable_bindings = config
        .varbinds
        .into_iter()
        .map(v1_varbind_from_config)
        .collect::<Result<Vec<_>, _>>()?;

    let trap = v1::Trap {
        enterprise,
        agent_addr: rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(
            config.agent_addr.octets().into(),
        )),
        generic_trap: config.generic_trap.into(),
        specific_trap: config.specific_trap.into(),
        time_stamp,
        variable_bindings,
    };

    let community = if config.community.is_empty() {
        DEFAULT_SNMP_COMMUNITY.to_string()
    } else {
        config.community
    };

    let message = v1::Message {
        version: v1::Message::<v1::Trap>::VERSION_1.into(),
        community: community.as_bytes().to_vec().into(),
        data: trap,
    };

    ber::encode(&message).map_err(|e| SnmpError::EncodingError(Box::new(e)))
}

pub fn build_snmpv2c_trap_pdu(config: SNMPV2cTrapConfig) -> Result<Vec<u8>, SnmpError> {
    if config.trap_oid.trim().is_empty() {
        return Err(SnmpError::MissingField("trap_oid".to_string()));
    }

    let mut variable_bindings = Vec::with_capacity(config.varbinds.len() + 2);
    variable_bindings.push(v2::VarBind {
        name: parse_oid(SNMP_SYS_UP_TIME_OID)?,
        value: v2::VarBindValue::Value(v2::ObjectSyntax::from(rasn_smi::v1::TimeTicks(
            config.timestamp.unwrap_or_else(current_unix_seconds),
        ))),
    });
    variable_bindings.push(v2::VarBind {
        name: parse_oid(SNMP_TRAP_OID_ZERO)?,
        value: v2::VarBindValue::Value(v2::ObjectSyntax::from(parse_oid(&config.trap_oid)?)),
    });
    variable_bindings.extend(
        config
            .varbinds
            .into_iter()
            .map(v2_varbind_from_config)
            .collect::<Result<Vec<_>, _>>()?,
    );

    let trap_pdu = v2::Trap(v2::Pdu {
        request_id: request_id(),
        error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
        error_index: 0,
        variable_bindings,
    });

    let message = v2c::Message {
        version: v2c::Message::<v2::Trap>::VERSION.into(),
        community: config.community.as_bytes().to_vec().into(),
        data: trap_pdu,
    };

    ber::encode(&message).map_err(|e| SnmpError::EncodingError(Box::new(e)))
}

pub fn build_snmpv3_trap_pdu(config: SNMPV3TrapConfig) -> Result<Vec<u8>, SnmpError> {
    if config.trap_oid.trim().is_empty() {
        return Err(SnmpError::MissingField("trap_oid".to_string()));
    }
    if config.username.trim().is_empty() {
        return Err(SnmpError::MissingField("username".to_string()));
    }
    if config.auth_protocol == AuthProtocol::NoAuth && config.priv_protocol != PrivProtocol::NoPriv
    {
        return Err(SnmpError::InvalidConfig(
            "privacy requires authentication".to_string(),
        ));
    }

    let engine_id = config
        .engine_id
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SNMP_ENGINE_ID.to_string());
    let engine_id_bytes = parse_engine_id(&engine_id)?;

    if config.engine_boots > i32::MAX as u32 {
        return Err(SnmpError::InvalidConfig(
            "engine_boots exceeds 2^31-1".to_string(),
        ));
    }
    if config.engine_time > i32::MAX as u32 {
        return Err(SnmpError::InvalidConfig(
            "engine_time exceeds 2^31-1".to_string(),
        ));
    }

    let (auth_key, priv_key) = derive_usm_keys(
        &config.auth_protocol,
        &config.auth_password,
        &config.priv_protocol,
        &config.priv_password,
        &engine_id_bytes,
    )?;

    let mut variable_bindings = Vec::with_capacity(config.varbinds.len() + 2);
    variable_bindings.push(v2::VarBind {
        name: parse_oid(SNMP_SYS_UP_TIME_OID)?,
        value: v2::VarBindValue::Value(v2::ObjectSyntax::from(rasn_smi::v1::TimeTicks(
            config.timestamp.unwrap_or_else(current_unix_seconds),
        ))),
    });
    variable_bindings.push(v2::VarBind {
        name: parse_oid(SNMP_TRAP_OID_ZERO)?,
        value: v2::VarBindValue::Value(v2::ObjectSyntax::from(parse_oid(&config.trap_oid)?)),
    });
    variable_bindings.extend(
        config
            .varbinds
            .into_iter()
            .map(v2_varbind_from_config)
            .collect::<Result<Vec<_>, _>>()?,
    );

    let scoped_pdu = v3::ScopedPdu {
        engine_id: engine_id_bytes.clone().into(),
        name: Vec::<u8>::new().into(),
        data: if config.is_inform {
            v2::Pdus::InformRequest(v2::InformRequest(v2::Pdu {
                request_id: request_id(),
                error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                error_index: 0,
                variable_bindings,
            }))
        } else {
            v2::Pdus::Trap(v2::Trap(v2::Pdu {
                request_id: request_id(),
                error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                error_index: 0,
                variable_bindings,
            }))
        },
    };

    let base_flags = match (config.auth_protocol, config.priv_protocol) {
        (AuthProtocol::NoAuth, PrivProtocol::NoPriv) => 0x00,
        (_, PrivProtocol::NoPriv) => 0x01,
        _ => 0x03,
    };
    let flags = base_flags | if config.is_inform { 0x04 } else { 0x00 };

    let auth_placeholder_len = auth_parameter_len(&config.auth_protocol);
    let mut auth_placeholder = vec![0u8; auth_placeholder_len];

    let scoped_data = if config.priv_protocol == PrivProtocol::NoPriv {
        v3::ScopedPduData::CleartextPdu(scoped_pdu)
    } else {
        let scoped_pdu_bytes =
            ber::encode(&scoped_pdu).map_err(|e| SnmpError::EncodingError(Box::new(e)))?;
        let (encrypted_pdu, privacy_parameters) = encrypt_scoped_pdu(
            &config.priv_protocol,
            &priv_key,
            config.engine_boots,
            config.engine_time,
            &scoped_pdu_bytes,
        )?;
        auth_placeholder = vec![0u8; auth_placeholder_len];
        let security = v3::USMSecurityParameters {
            authoritative_engine_id: engine_id_bytes.clone().into(),
            authoritative_engine_boots: config.engine_boots.into(),
            authoritative_engine_time: config.engine_time.into(),
            user_name: config.username.as_bytes().to_vec().into(),
            authentication_parameters: auth_placeholder.clone().into(),
            privacy_parameters: privacy_parameters.into(),
        };

        let mut message = v3::Message {
            version: 3.into(),
            global_data: v3::HeaderData {
                message_id: request_id().into(),
                max_size: 65_507.into(),
                flags: vec![flags].into(),
                security_model: v3::USMSecurityParameters::ID.into(),
            },
            security_parameters: Vec::<u8>::new().into(),
            scoped_data: v3::ScopedPduData::EncryptedPdu(encrypted_pdu.into()),
        };

        message
            .encode_security_parameters(rasn::Codec::Ber, &security)
            .map_err(|e| {
                SnmpError::EncodingError(Box::new(std::io::Error::other(e.to_string())))
            })?;

        return finalize_v3_message_with_auth(message, &config.auth_protocol, &auth_key);
    };

    let security = v3::USMSecurityParameters {
        authoritative_engine_id: engine_id_bytes.into(),
        authoritative_engine_boots: config.engine_boots.into(),
        authoritative_engine_time: config.engine_time.into(),
        user_name: config.username.as_bytes().to_vec().into(),
        authentication_parameters: auth_placeholder.into(),
        privacy_parameters: Vec::<u8>::new().into(),
    };

    let mut message = v3::Message {
        version: 3.into(),
        global_data: v3::HeaderData {
            message_id: request_id().into(),
            max_size: 65_507.into(),
            flags: vec![flags].into(),
            security_model: v3::USMSecurityParameters::ID.into(),
        },
        security_parameters: Vec::<u8>::new().into(),
        scoped_data,
    };

    message
        .encode_security_parameters(rasn::Codec::Ber, &security)
        .map_err(|e| SnmpError::EncodingError(Box::new(std::io::Error::other(e.to_string()))))?;

    finalize_v3_message_with_auth(message, &config.auth_protocol, &auth_key)
}

fn finalize_v3_message_with_auth(
    message: v3::Message,
    auth_protocol: &AuthProtocol,
    auth_key: &[u8],
) -> Result<Vec<u8>, SnmpError> {
    let mut packet = ber::encode(&message).map_err(|e| SnmpError::EncodingError(Box::new(e)))?;
    if *auth_protocol == AuthProtocol::NoAuth {
        return Ok(packet);
    }

    let auth_len = auth_parameter_len(auth_protocol);
    if auth_len == 0 {
        return Ok(packet);
    }

    let usm_encoded = message.security_parameters.as_ref();
    let auth_offset_in_usm =
        find_auth_placeholder_offset(usm_encoded, auth_len).ok_or_else(|| {
            SnmpError::KeyInitFailed("failed locating auth parameters in USM blob".to_string())
        })?;
    let usm_start = find_subsequence(&packet, usm_encoded).ok_or_else(|| {
        SnmpError::KeyInitFailed("failed locating encoded USM security parameters".to_string())
    })?;

    let digest = compute_message_auth_digest(auth_protocol, auth_key, &packet)?;
    if digest.len() < auth_len {
        return Err(SnmpError::KeyInitFailed(
            "auth digest shorter than required auth parameter length".to_string(),
        ));
    }

    let auth_start = usm_start + auth_offset_in_usm + 2;
    packet[auth_start..auth_start + auth_len].copy_from_slice(&digest[..auth_len]);
    Ok(packet)
}

fn derive_usm_keys(
    auth_protocol: &AuthProtocol,
    auth_password: &str,
    priv_protocol: &PrivProtocol,
    priv_password: &str,
    engine_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SnmpError> {
    let auth_key = if *auth_protocol == AuthProtocol::NoAuth {
        Vec::new()
    } else {
        if auth_password.len() < 8 {
            return Err(SnmpError::InvalidConfig(
                "auth passphrase must be at least 8 octets (RFC 3414)".to_string(),
            ));
        }
        localized_key(*auth_protocol, auth_password.as_bytes(), engine_id)?
    };

    let priv_key = if *priv_protocol == PrivProtocol::NoPriv {
        Vec::new()
    } else {
        if priv_password.len() < 8 {
            return Err(SnmpError::InvalidConfig(
                "priv passphrase must be at least 8 octets (RFC 3414)".to_string(),
            ));
        }
        derive_priv_key(
            *auth_protocol,
            *priv_protocol,
            priv_password.as_bytes(),
            engine_id,
        )?
    };

    Ok((auth_key, priv_key))
}

fn derive_priv_key(
    auth_protocol: AuthProtocol,
    priv_protocol: PrivProtocol,
    priv_password: &[u8],
    engine_id: &[u8],
) -> Result<Vec<u8>, SnmpError> {
    if auth_protocol == AuthProtocol::NoAuth {
        return Err(SnmpError::InvalidConfig(
            "privacy requires authentication".to_string(),
        ));
    }

    let key_len = match priv_protocol {
        PrivProtocol::DES => 16,
        PrivProtocol::AES => 16,
        PrivProtocol::AES192 | PrivProtocol::AES192C => 24,
        PrivProtocol::AES256 | PrivProtocol::AES256C => 32,
        PrivProtocol::NoPriv => 0,
    };
    if key_len == 0 {
        return Ok(Vec::new());
    }

    let base = localized_key(auth_protocol, priv_password, engine_id)?;
    let extended = match priv_protocol {
        PrivProtocol::AES | PrivProtocol::AES192C | PrivProtocol::AES256C => {
            let second = localized_key(auth_protocol, &base, engine_id)?;
            [base, second].concat()
        }
        PrivProtocol::AES192 | PrivProtocol::AES256 => {
            let mut ext = base.clone();
            ext.extend_from_slice(&hash_bytes(auth_protocol, &base)?);
            ext
        }
        _ => base,
    };

    if extended.len() < key_len {
        return Err(SnmpError::KeyInitFailed(format!(
            "derived privacy key too short for {:?}: {} < {}",
            priv_protocol,
            extended.len(),
            key_len
        )));
    }

    Ok(extended[..key_len].to_vec())
}

fn localized_key(
    auth_protocol: AuthProtocol,
    password: &[u8],
    engine_id: &[u8],
) -> Result<Vec<u8>, SnmpError> {
    if password.is_empty() {
        return Err(SnmpError::MissingField("auth/priv password".to_string()));
    }

    let ku = hash_password_1mb(auth_protocol, password)?;
    let mut local_input = Vec::with_capacity(ku.len() * 2 + engine_id.len());
    local_input.extend_from_slice(&ku);
    local_input.extend_from_slice(engine_id);
    local_input.extend_from_slice(&ku);
    hash_bytes(auth_protocol, &local_input)
}

fn hash_password_1mb(auth_protocol: AuthProtocol, password: &[u8]) -> Result<Vec<u8>, SnmpError> {
    if password.is_empty() {
        return Err(SnmpError::MissingField("password".to_string()));
    }

    let mut data = Vec::with_capacity(1_048_576);
    while data.len() < 1_048_576 {
        let need = 1_048_576 - data.len();
        if need >= password.len() {
            data.extend_from_slice(password);
        } else {
            data.extend_from_slice(&password[..need]);
        }
    }
    hash_bytes(auth_protocol, &data)
}

fn hash_bytes(auth_protocol: AuthProtocol, data: &[u8]) -> Result<Vec<u8>, SnmpError> {
    match auth_protocol {
        AuthProtocol::NoAuth => Err(SnmpError::InvalidConfig(
            "NoAuth does not define a hash function".to_string(),
        )),
        AuthProtocol::MD5 => {
            use md5::Digest;
            Ok(Md5::digest(data).to_vec())
        }
        AuthProtocol::SHA => {
            use sha1::Digest;
            Ok(Sha1::digest(data).to_vec())
        }
        AuthProtocol::SHA224 => {
            use sha2::Digest;
            Ok(Sha224::digest(data).to_vec())
        }
        AuthProtocol::SHA256 => {
            use sha2::Digest;
            Ok(Sha256::digest(data).to_vec())
        }
        AuthProtocol::SHA384 => {
            use sha2::Digest;
            Ok(Sha384::digest(data).to_vec())
        }
        AuthProtocol::SHA512 => {
            use sha2::Digest;
            Ok(Sha512::digest(data).to_vec())
        }
    }
}

fn auth_parameter_len(auth_protocol: &AuthProtocol) -> usize {
    match auth_protocol {
        AuthProtocol::NoAuth => 0,
        AuthProtocol::MD5 | AuthProtocol::SHA => 12,
        AuthProtocol::SHA224 => 16,
        AuthProtocol::SHA256 => 24,
        AuthProtocol::SHA384 => 32,
        AuthProtocol::SHA512 => 48,
    }
}

fn compute_message_auth_digest(
    auth_protocol: &AuthProtocol,
    auth_key: &[u8],
    packet: &[u8],
) -> Result<Vec<u8>, SnmpError> {
    match auth_protocol {
        AuthProtocol::NoAuth => Ok(Vec::new()),
        AuthProtocol::MD5 | AuthProtocol::SHA => {
            compute_rfc3414_digest(*auth_protocol, auth_key, packet)
        }
        AuthProtocol::SHA224 => {
            let mut mac = <Hmac<Sha224> as Mac>::new_from_slice(auth_key)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
            mac.update(packet);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        AuthProtocol::SHA256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_key)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
            mac.update(packet);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        AuthProtocol::SHA384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(auth_key)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
            mac.update(packet);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        AuthProtocol::SHA512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
            mac.update(packet);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn compute_rfc3414_digest(
    auth_protocol: AuthProtocol,
    auth_key: &[u8],
    packet: &[u8],
) -> Result<Vec<u8>, SnmpError> {
    let mut ext_key = [0u8; 64];
    let copy_len = auth_key.len().min(64);
    ext_key[..copy_len].copy_from_slice(&auth_key[..copy_len]);

    let mut k1 = [0u8; 64];
    let mut k2 = [0u8; 64];
    for i in 0..64 {
        k1[i] = ext_key[i] ^ 0x36;
        k2[i] = ext_key[i] ^ 0x5c;
    }

    match auth_protocol {
        AuthProtocol::MD5 => {
            use md5::Digest;
            let mut h1 = Md5::new();
            h1.update(k1);
            h1.update(packet);
            let d1 = h1.finalize();

            let mut h2 = Md5::new();
            h2.update(k2);
            h2.update(d1);
            Ok(h2.finalize().to_vec())
        }
        AuthProtocol::SHA => {
            use sha1::Digest;
            let mut h1 = Sha1::new();
            h1.update(k1);
            h1.update(packet);
            let d1 = h1.finalize();

            let mut h2 = Sha1::new();
            h2.update(k2);
            h2.update(d1);
            Ok(h2.finalize().to_vec())
        }
        _ => Err(SnmpError::InvalidConfig(
            "RFC3414 digest only valid for MD5/SHA1".to_string(),
        )),
    }
}

fn encrypt_scoped_pdu(
    priv_protocol: &PrivProtocol,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    scoped_pdu: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SnmpError> {
    static SALT_COUNTER: OnceLock<AtomicU64> = OnceLock::new();
    let counter = SALT_COUNTER.get_or_init(|| {
        let mut seed = [0u8; 8];
        let _ = getrandom(&mut seed);
        AtomicU64::new(u64::from_be_bytes(seed))
    });
    let salt64 = counter.fetch_add(1, Ordering::Relaxed);

    match priv_protocol {
        PrivProtocol::NoPriv => Ok((scoped_pdu.to_vec(), Vec::new())),
        PrivProtocol::AES
        | PrivProtocol::AES192
        | PrivProtocol::AES256
        | PrivProtocol::AES192C
        | PrivProtocol::AES256C => {
            let privacy_parameters = salt64.to_be_bytes().to_vec();
            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
            iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
            iv[8..].copy_from_slice(&privacy_parameters);

            let mut ciphertext = scoped_pdu.to_vec();
            match priv_protocol {
                PrivProtocol::AES => {
                    let cipher = cfb_mode::Encryptor::<Aes128>::new_from_slices(priv_key, &iv)
                        .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
                    cipher.encrypt(&mut ciphertext);
                }
                PrivProtocol::AES192 | PrivProtocol::AES192C => {
                    let cipher = cfb_mode::Encryptor::<Aes192>::new_from_slices(priv_key, &iv)
                        .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
                    cipher.encrypt(&mut ciphertext);
                }
                PrivProtocol::AES256 | PrivProtocol::AES256C => {
                    let cipher = cfb_mode::Encryptor::<Aes256>::new_from_slices(priv_key, &iv)
                        .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
                    cipher.encrypt(&mut ciphertext);
                }
                _ => unreachable!(),
            }

            Ok((ciphertext, privacy_parameters))
        }
        PrivProtocol::DES => {
            if priv_key.len() < 16 {
                return Err(SnmpError::KeyInitFailed(
                    "DES privacy key must be at least 16 bytes".to_string(),
                ));
            }
            let salt32 = (salt64 & 0xffff_ffff) as u32;
            let mut privacy_parameters = vec![0u8; 8];
            privacy_parameters[..4].copy_from_slice(&engine_boots.to_be_bytes());
            privacy_parameters[4..].copy_from_slice(&salt32.to_be_bytes());

            let mut iv = [0u8; 8];
            for i in 0..8 {
                iv[i] = priv_key[8 + i] ^ privacy_parameters[i];
            }

            let mut plaintext = scoped_pdu.to_vec();
            let rem = plaintext.len() % 8;
            if rem != 0 {
                plaintext.extend(std::iter::repeat_n(0u8, 8 - rem));
            }
            let msg_len = plaintext.len();
            let cipher = cbc::Encryptor::<Des>::new_from_slices(&priv_key[..8], &iv)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;
            cipher
                .encrypt_padded_mut::<NoPadding>(&mut plaintext, msg_len)
                .map_err(|e| SnmpError::KeyInitFailed(e.to_string()))?;

            Ok((plaintext, privacy_parameters))
        }
    }
}

fn find_auth_placeholder_offset(usm_bytes: &[u8], auth_len: usize) -> Option<usize> {
    if auth_len == 0 {
        return None;
    }
    let mut needle = Vec::with_capacity(auth_len + 2);
    needle.push(0x04);
    needle.push(auth_len as u8);
    needle.extend(std::iter::repeat_n(0u8, auth_len));
    find_subsequence(usm_bytes, &needle)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_engine_id(engine_id: &str) -> Result<Vec<u8>, SnmpError> {
    let bytes = if let Some(decoded) = decode_hex(engine_id) {
        decoded
    } else {
        engine_id.as_bytes().to_vec()
    };
    if bytes.len() < 5 || bytes.len() > 32 {
        return Err(SnmpError::InvalidConfig(format!(
            "engine ID must be 5-32 octets per RFC 3411, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed.len().is_multiple_of(2)
        || !trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }

    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let to_nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };

    for i in (0..bytes.len()).step_by(2) {
        let hi = to_nibble(bytes[i])?;
        let lo = to_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn parse_oid(oid: &str) -> Result<ObjectIdentifier, SnmpError> {
    let oid = oid.trim();
    if oid.is_empty() {
        return Err(SnmpError::InvalidOid("empty OID".to_string()));
    }

    let mut arcs = Vec::new();
    for part in oid.split('.') {
        if part.is_empty() {
            return Err(SnmpError::InvalidOid(oid.to_string()));
        }
        let arc = part
            .parse::<u32>()
            .map_err(|_| SnmpError::InvalidOid(oid.to_string()))?;
        arcs.push(arc);
    }

    ObjectIdentifier::new(arcs).ok_or_else(|| SnmpError::InvalidOid(oid.to_string()))
}

fn v1_varbind_from_config(varbind: SNMPVarbind) -> Result<v1::VarBind, SnmpError> {
    let name = parse_oid(&varbind.oid)?;
    let value = match (varbind.asn_type, varbind.value) {
        (SNMPType::Integer, SNMPValue::Int(v)) => rasn_smi::v1::ObjectSyntax::from(v),
        (SNMPType::OctetString, SNMPValue::Str(v)) => {
            rasn_smi::v1::ObjectSyntax::from(rasn::types::OctetString::from(v.into_bytes()))
        }
        (SNMPType::ObjectIdentifier, SNMPValue::Oid(v)) => {
            rasn_smi::v1::ObjectSyntax::from(parse_oid(&v)?)
        }
        (SNMPType::TimeTicks, SNMPValue::Uint(v)) => {
            rasn_smi::v1::ObjectSyntax::from(rasn_smi::v1::TimeTicks(v))
        }
        (SNMPType::IpAddress, SNMPValue::Ip(v)) => {
            rasn_smi::v1::ObjectSyntax::from(rasn_smi::v1::IpAddress(v.octets().into()))
        }
        (SNMPType::Counter32, SNMPValue::Uint(v)) => {
            rasn_smi::v1::ObjectSyntax::from(rasn_smi::v1::Counter(v))
        }
        (SNMPType::Gauge32, SNMPValue::Uint(v)) => {
            rasn_smi::v1::ObjectSyntax::from(rasn_smi::v1::Gauge(v))
        }
        (SNMPType::Null, SNMPValue::Null) => rasn_smi::v1::SimpleSyntax::Empty.into(),
        (SNMPType::Opaque, SNMPValue::Bytes(v)) => {
            let octets: rasn::types::OctetString = v.into();
            rasn_smi::v1::ObjectSyntax::from(
                octets
                    .to_opaque()
                    .map_err(|e| SnmpError::EncodingError(Box::new(e)))?,
            )
        }
        (t, v) => {
            return Err(SnmpError::InvalidConfig(format!(
                "varbind type/value mismatch for OID {name}: {:?} / {:?}",
                t, v
            )));
        }
    };

    Ok(v1::VarBind { name, value })
}

fn v2_varbind_from_config(varbind: SNMPVarbind) -> Result<v2::VarBind, SnmpError> {
    let name = parse_oid(&varbind.oid)?;
    let value = match (varbind.asn_type, varbind.value) {
        (SNMPType::Integer, SNMPValue::Int(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(v))
        }
        (SNMPType::OctetString, SNMPValue::Str(v)) => v2::VarBindValue::Value(
            rasn_smi::v2::ObjectSyntax::from(rasn::types::OctetString::from(v.into_bytes())),
        ),
        (SNMPType::ObjectIdentifier, SNMPValue::Oid(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(parse_oid(&v)?))
        }
        (SNMPType::TimeTicks, SNMPValue::Uint(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::TimeTicks(v)))
        }
        (SNMPType::IpAddress, SNMPValue::Ip(v)) => v2::VarBindValue::Value(
            rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::IpAddress(v.octets().into())),
        ),
        (SNMPType::Counter32, SNMPValue::Uint(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::Counter(v)))
        }
        (SNMPType::Gauge32, SNMPValue::Uint(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::Gauge(v)))
        }
        (SNMPType::Null, SNMPValue::Null) => v2::VarBindValue::Unspecified,
        (SNMPType::Opaque, SNMPValue::Bytes(v)) => {
            let octets: rasn::types::OctetString = v.into();
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(
                octets
                    .to_opaque()
                    .map_err(|e| SnmpError::EncodingError(Box::new(e)))?,
            ))
        }
        (t, v) => {
            return Err(SnmpError::InvalidConfig(format!(
                "varbind type/value mismatch for OID {name}: {:?} / {:?}",
                t, v
            )));
        }
    };

    Ok(v2::VarBind { name, value })
}

fn current_unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn request_id() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u64 & 0x7fff_ffff) as i32)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_snmpv2c_trap_pdu_success_non_empty() {
        let config = SNMPV2cTrapConfig {
            community: "public".to_string(),
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: Some(123),
            varbinds: vec![SNMPVarbind {
                oid: "1.3.6.1.2.1.1.5.0".to_string(),
                asn_type: SNMPType::OctetString,
                value: SNMPValue::Str("udp-sender".to_string()),
            }],
        };

        let pdu = build_snmpv2c_trap_pdu(config).expect("v2c trap should encode");
        assert!(!pdu.is_empty());
    }

    #[test]
    fn test_build_snmpv2c_trap_pdu_empty_trap_oid() {
        let config = SNMPV2cTrapConfig {
            community: "public".to_string(),
            trap_oid: String::new(),
            timestamp: None,
            varbinds: vec![],
        };

        let err = build_snmpv2c_trap_pdu(config).expect_err("must fail on empty trap_oid");
        assert!(matches!(err, SnmpError::MissingField(field) if field == "trap_oid"));
    }

    #[test]
    fn test_build_snmpv3_trap_pdu_empty_username() {
        let config = SNMPV3TrapConfig {
            username: String::new(),
            engine_id: None,
            auth_protocol: AuthProtocol::NoAuth,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::NoPriv,
            priv_password: String::new(),
            engine_boots: 0,
            engine_time: 0,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };

        let err = build_snmpv3_trap_pdu(config).expect_err("must fail on empty username");
        assert!(matches!(err, SnmpError::MissingField(field) if field == "username"));
    }

    #[test]
    fn test_build_snmpv3_trap_pdu_priv_without_auth() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::NoAuth,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::AES,
            priv_password: "secret".to_string(),
            engine_boots: 0,
            engine_time: 0,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };

        let err = build_snmpv3_trap_pdu(config).expect_err("must fail on priv without auth");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_build_snmpv3_trap_pdu_empty_trap_oid() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::NoAuth,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::NoPriv,
            priv_password: String::new(),
            engine_boots: 0,
            engine_time: 0,
            trap_oid: String::new(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };

        let err = build_snmpv3_trap_pdu(config).expect_err("must fail on empty trap_oid");
        assert!(matches!(err, SnmpError::MissingField(field) if field == "trap_oid"));
    }

    #[test]
    fn test_derive_usm_keys_sha_and_aes_lengths() {
        let engine_id = parse_engine_id("800000020109840301").expect("valid engine ID");
        let (auth_key, priv_key) = derive_usm_keys(
            &AuthProtocol::SHA,
            "authpass123",
            &PrivProtocol::AES,
            "privpass123",
            &engine_id,
        )
        .expect("key derivation must succeed");

        assert_eq!(auth_key.len(), 20, "SHA localized key must be 20 bytes");
        assert_eq!(priv_key.len(), 16, "AES-128 privacy key must be 16 bytes");
    }

    #[test]
    fn test_build_snmpv3_trap_pdu_auth_priv_succeeds() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: Some("udp-sender".to_string()),
            auth_protocol: AuthProtocol::SHA256,
            auth_password: "authpass123".to_string(),
            priv_protocol: PrivProtocol::AES,
            priv_password: "privpass123".to_string(),
            engine_boots: 1,
            engine_time: 100,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: Some(123),
            varbinds: vec![SNMPVarbind {
                oid: "1.3.6.1.2.1.1.5.0".to_string(),
                asn_type: SNMPType::OctetString,
                value: SNMPValue::Str("udp-sender".to_string()),
            }],
            is_inform: false,
        };

        let pdu = build_snmpv3_trap_pdu(config).expect("auth+priv v3 trap should encode");
        assert!(!pdu.is_empty());
    }

    #[test]
    fn test_build_snmpv1_trap_pdu_success() {
        let config = SNMPV1TrapConfig {
            community: "public".to_string(),
            enterprise_oid: "1.3.6.1.4.1.99999".to_string(),
            agent_addr: std::net::Ipv4Addr::new(127, 0, 0, 1),
            generic_trap: 6,
            specific_trap: 1,
            timestamp: Some(123),
            varbinds: vec![SNMPVarbind {
                oid: "1.3.6.1.2.1.1.5.0".to_string(),
                asn_type: SNMPType::OctetString,
                value: SNMPValue::Str("udp-sender".to_string()),
            }],
        };
        let pdu = build_snmpv1_trap_pdu(config).expect("v1 trap should encode");
        assert!(!pdu.is_empty());
    }

    #[test]
    fn test_build_snmpv1_trap_pdu_empty_enterprise_oid() {
        let config = SNMPV1TrapConfig {
            community: "public".to_string(),
            enterprise_oid: String::new(),
            agent_addr: std::net::Ipv4Addr::new(127, 0, 0, 1),
            generic_trap: 6,
            specific_trap: 1,
            timestamp: None,
            varbinds: vec![],
        };
        let err = build_snmpv1_trap_pdu(config).expect_err("must fail on empty enterprise_oid");
        assert!(matches!(err, SnmpError::MissingField(field) if field == "enterprise_oid"));
    }

    #[test]
    fn test_build_snmpv1_trap_pdu_empty_community_uses_default() {
        // gosnmp parity: empty community defaults to "public".
        let config = SNMPV1TrapConfig {
            community: String::new(),
            enterprise_oid: "1.3.6.1.4.1.99999".to_string(),
            agent_addr: std::net::Ipv4Addr::new(127, 0, 0, 1),
            generic_trap: 6,
            specific_trap: 1,
            timestamp: Some(0),
            varbinds: vec![],
        };
        let pdu = build_snmpv1_trap_pdu(config).expect("empty community must default to public");
        assert!(!pdu.is_empty());
    }

    #[test]
    fn test_parse_engine_id_valid_hex() {
        let bytes = parse_engine_id("800000020109840301").expect("valid hex engine ID");
        assert_eq!(
            bytes,
            vec![0x80, 0x00, 0x00, 0x02, 0x01, 0x09, 0x84, 0x03, 0x01]
        );
    }

    #[test]
    fn test_parse_engine_id_plain_ascii_fallback() {
        // Non-hex strings fall back to raw bytes (must be 5..=32 octets per RFC 3411).
        let bytes = parse_engine_id("udp-sender").expect("plain ASCII engine ID");
        assert_eq!(bytes, b"udp-sender".to_vec());
    }

    #[test]
    fn test_parse_engine_id_too_short() {
        // 4 ASCII bytes is below the RFC 3411 minimum of 5.
        let err = parse_engine_id("abcd").expect_err("must reject <5 octet engine ID");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_parse_engine_id_too_long() {
        // 33-byte ASCII engine ID exceeds the RFC 3411 maximum of 32.
        let too_long = "a".repeat(33);
        let err = parse_engine_id(&too_long).expect_err("must reject >32 octet engine ID");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_decode_hex_variants() {
        assert_eq!(decode_hex("ab"), Some(vec![0xab]));
        assert_eq!(decode_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex(""), None, "empty string must not decode");
        assert_eq!(decode_hex("abc"), None, "odd length must not decode");
        assert_eq!(decode_hex("zz"), None, "non-hex must not decode");
    }

    #[test]
    fn test_parse_oid_valid_and_invalid() {
        parse_oid("1.3.6.1.6.3.1.1.5.1").expect("valid OID");
        let err = parse_oid("").expect_err("empty OID must fail");
        assert!(matches!(err, SnmpError::InvalidOid(_)));
        let err = parse_oid("1..2").expect_err("OID with empty arc must fail");
        assert!(matches!(err, SnmpError::InvalidOid(_)));
    }

    #[test]
    fn test_build_snmpv3_short_auth_passphrase() {
        // RFC 3414 mandates auth/priv passphrases of at least 8 octets.
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::SHA,
            auth_password: "short".to_string(),
            priv_protocol: PrivProtocol::NoPriv,
            priv_password: String::new(),
            engine_boots: 0,
            engine_time: 0,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };
        let err = build_snmpv3_trap_pdu(config).expect_err("must reject <8 octet auth passphrase");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_build_snmpv3_short_priv_passphrase() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::SHA,
            auth_password: "authpass123".to_string(),
            priv_protocol: PrivProtocol::AES,
            priv_password: "tiny".to_string(),
            engine_boots: 0,
            engine_time: 0,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };
        let err = build_snmpv3_trap_pdu(config).expect_err("must reject <8 octet priv passphrase");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_build_snmpv3_engine_boots_overflow() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::NoAuth,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::NoPriv,
            priv_password: String::new(),
            engine_boots: u32::MAX,
            engine_time: 0,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };
        let err = build_snmpv3_trap_pdu(config).expect_err("must reject engine_boots > 2^31-1");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_build_snmpv3_engine_time_overflow() {
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::NoAuth,
            auth_password: String::new(),
            priv_protocol: PrivProtocol::NoPriv,
            priv_password: String::new(),
            engine_boots: 0,
            engine_time: u32::MAX,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: None,
            varbinds: vec![],
            is_inform: false,
        };
        let err = build_snmpv3_trap_pdu(config).expect_err("must reject engine_time > 2^31-1");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_hash_password_1mb_md5_and_sha1_lengths() {
        let md5 = hash_password_1mb(AuthProtocol::MD5, b"authpass123").expect("MD5 hash");
        assert_eq!(md5.len(), 16, "MD5 digest must be 16 bytes");
        let sha1 = hash_password_1mb(AuthProtocol::SHA, b"authpass123").expect("SHA-1 hash");
        assert_eq!(sha1.len(), 20, "SHA-1 digest must be 20 bytes");
    }

    #[test]
    fn test_hash_bytes_noauth_rejected() {
        let err = hash_bytes(AuthProtocol::NoAuth, b"data").expect_err("NoAuth has no hash fn");
        assert!(matches!(err, SnmpError::InvalidConfig(_)));
    }

    #[test]
    fn test_auth_parameter_len_per_protocol() {
        // RFC 7860 / RFC 3414 truncation lengths.
        assert_eq!(auth_parameter_len(&AuthProtocol::NoAuth), 0);
        assert_eq!(auth_parameter_len(&AuthProtocol::MD5), 12);
        assert_eq!(auth_parameter_len(&AuthProtocol::SHA), 12);
        assert_eq!(auth_parameter_len(&AuthProtocol::SHA224), 16);
        assert_eq!(auth_parameter_len(&AuthProtocol::SHA256), 24);
        assert_eq!(auth_parameter_len(&AuthProtocol::SHA384), 32);
        assert_eq!(auth_parameter_len(&AuthProtocol::SHA512), 48);
    }

    #[test]
    fn test_build_snmpv3_inform_succeeds() {
        // INFORM PDU sets the Reportable flag (0x04). End-to-end encode check.
        let config = SNMPV3TrapConfig {
            username: "user".to_string(),
            engine_id: None,
            auth_protocol: AuthProtocol::SHA,
            auth_password: "authpass123".to_string(),
            priv_protocol: PrivProtocol::AES,
            priv_password: "privpass123".to_string(),
            engine_boots: 1,
            engine_time: 100,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: Some(123),
            varbinds: vec![],
            is_inform: true,
        };
        let pdu = build_snmpv3_trap_pdu(config).expect("v3 INFORM must encode");
        assert!(!pdu.is_empty());
    }

    #[test]
    fn test_build_snmpv2c_empty_community_accepted() {
        // v2c does not enforce a non-empty community (unlike v1 which defaults to "public").
        let config = SNMPV2cTrapConfig {
            community: String::new(),
            trap_oid: "1.3.6.1.6.3.1.1.5.1".to_string(),
            timestamp: Some(0),
            varbinds: vec![],
        };
        let pdu = build_snmpv2c_trap_pdu(config).expect("v2c with empty community must encode");
        assert!(!pdu.is_empty());
    }
}
