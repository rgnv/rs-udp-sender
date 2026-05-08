use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::ber;
use rasn::types::ObjectIdentifier;
use rasn_smi::v1::ToOpaque;
use rasn_snmp::{v1, v2, v2c, v3};
use rasn_snmp::v3::SecurityParameters;
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

    let message = v1::Message {
        version: v1::Message::<v1::Trap>::VERSION_1.into(),
        community: DEFAULT_SNMP_COMMUNITY.as_bytes().to_vec().into(),
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
    if config.auth_protocol == AuthProtocol::NoAuth && config.priv_protocol != PrivProtocol::NoPriv {
        return Err(SnmpError::InvalidConfig(
            "privacy requires authentication".to_string(),
        ));
    }

    if config.auth_protocol != AuthProtocol::NoAuth || config.priv_protocol != PrivProtocol::NoPriv {
        return Err(SnmpError::KeyInitFailed(
            "v3 key derivation not yet fully implemented — requires manual AES/DES key gen"
                .to_string(),
        ));
    }

    let engine_id = config
        .engine_id
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SNMP_ENGINE_ID.to_string());

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
        engine_id: engine_id.as_bytes().to_vec().into(),
        name: Vec::<u8>::new().into(),
        data: v2::Pdus::Trap(v2::Trap(v2::Pdu {
            request_id: request_id(),
            error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
            error_index: 0,
            variable_bindings,
        })),
    };

    let flags = match (config.auth_protocol, config.priv_protocol) {
        (AuthProtocol::NoAuth, PrivProtocol::NoPriv) => 0x00,
        (_, PrivProtocol::NoPriv) => 0x01,
        _ => 0x03,
    };

    let security = v3::USMSecurityParameters {
        authoritative_engine_id: engine_id.as_bytes().to_vec().into(),
        authoritative_engine_boots: config.engine_boots.into(),
        authoritative_engine_time: config.engine_time.into(),
        user_name: config.username.as_bytes().to_vec().into(),
        authentication_parameters: Vec::<u8>::new().into(),
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
        scoped_data: v3::ScopedPduData::CleartextPdu(scoped_pdu),
    };

    message
        .encode_security_parameters(rasn::Codec::Ber, &security)
        .map_err(|e| {
            SnmpError::EncodingError(Box::new(std::io::Error::other(e.to_string())))
        })?;

    ber::encode(&message).map_err(|e| SnmpError::EncodingError(Box::new(e)))
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

    ObjectIdentifier::new(arcs)
        .ok_or_else(|| SnmpError::InvalidOid(oid.to_string()))
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
        (SNMPType::OctetString, SNMPValue::Str(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(
                rasn::types::OctetString::from(v.into_bytes()),
            ))
        }
        (SNMPType::ObjectIdentifier, SNMPValue::Oid(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(parse_oid(&v)?))
        }
        (SNMPType::TimeTicks, SNMPValue::Uint(v)) => {
            v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::TimeTicks(v)))
        }
        (SNMPType::IpAddress, SNMPValue::Ip(v)) => v2::VarBindValue::Value(
            rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::IpAddress(v.octets().into())),
        ),
        (SNMPType::Counter32, SNMPValue::Uint(v)) => v2::VarBindValue::Value(
            rasn_smi::v2::ObjectSyntax::from(rasn_smi::v1::Counter(v)),
        ),
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
        };

        let err = build_snmpv3_trap_pdu(config).expect_err("must fail on empty trap_oid");
        assert!(matches!(err, SnmpError::MissingField(field) if field == "trap_oid"));
    }
}
