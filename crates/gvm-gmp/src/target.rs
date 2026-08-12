// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Validated target-host specifications.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A validated host specification accepted by gvmd target commands.
///
/// A target host may be an IPv4 or IPv6 address, a CIDR network, a full or
/// abbreviated address range, or an ASCII hostname. Surrounding whitespace and
/// IPv4 leading zeroes are normalized like gvmd before GMP serialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetHost {
    value: String,
    kind: TargetHostKind,
    identity: TargetHostIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TargetHostIdentity {
    Ip(IpAddr),
    Network { start: IpAddr, end: IpAddr },
    Range { start: IpAddr, end: IpAddr },
    Hostname(String),
}

/// A validated target host selection.
///
/// gvmd treats included and excluded hosts as one value: included hosts must
/// be non-empty, and modifications replace both lists atomically. This type
/// makes those request-shape invariants impossible to represent incorrectly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHosts {
    included: Vec<TargetHost>,
    excluded: Vec<TargetHost>,
}

impl TargetHosts {
    /// Build a target host selection from included and excluded hosts.
    ///
    /// Canonically identical specifications are de-duplicated while retaining
    /// the order of their first occurrence.
    ///
    /// # Errors
    /// Returns [`TargetHostsError::EmptyIncludedHosts`] when no included host
    /// remains, or [`TargetHostsError::EmptyEffectiveHosts`] when exclusions
    /// statically cover the entire included selection.
    pub fn new(
        included: impl IntoIterator<Item = TargetHost>,
        excluded: impl IntoIterator<Item = TargetHost>,
    ) -> Result<Self, TargetHostsError> {
        let included = deduplicate_hosts(included);
        if included.is_empty() {
            return Err(TargetHostsError::EmptyIncludedHosts);
        }
        let hosts = Self {
            included,
            excluded: deduplicate_hosts(excluded),
        };
        if !hosts.has_effective_hosts() {
            return Err(TargetHostsError::EmptyEffectiveHosts);
        }
        Ok(hosts)
    }

    /// Borrow the non-empty included-host list.
    #[must_use]
    pub fn included(&self) -> &[TargetHost] {
        &self.included
    }

    /// Borrow the excluded-host list.
    #[must_use]
    pub fn excluded(&self) -> &[TargetHost] {
        &self.excluded
    }

    /// Return whether at least one included host remains after exclusions.
    ///
    /// Address, network, and range coverage is evaluated without expanding
    /// large networks. Hostnames use their canonical ASCII identity; DNS
    /// resolution and deployment-specific maximum-host limits remain gvmd
    /// responsibilities.
    #[must_use]
    pub fn has_effective_hosts(&self) -> bool {
        self.included
            .iter()
            .any(|included| !identity_is_covered(&included.identity, &self.excluded))
    }
}

/// Errors raised while constructing a [`TargetHosts`] selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TargetHostsError {
    /// A manual target must contain at least one included host specification.
    #[error("a target host selection requires at least one included host")]
    EmptyIncludedHosts,
    /// Every included host is covered by the exclusion list.
    #[error("a target host selection must contain at least one effective host")]
    EmptyEffectiveHosts,
}

/// The required port source for a newly created target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetPortSelection {
    /// Reuse an existing gvmd port list.
    PortList(crate::types::EntityId),
    /// Ask gvmd to create a target-specific port list from a validated range.
    PortRange(TargetPortRange),
}

/// A validated GMP port-range list such as `T:22, U:53, T:80-443`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetPortRange(String);

impl TargetPortRange {
    /// Parse and normalize a GMP port-range list.
    ///
    /// # Errors
    /// Returns [`TargetPortRangeError`] for an empty expression, an invalid
    /// protocol/range shape, ports outside `1..=65535`, or a descending range.
    pub fn new(value: impl AsRef<str>) -> Result<Self, TargetPortRangeError> {
        let input = value.as_ref();
        let mut normalized = Vec::new();
        let mut protocol = 'T';
        for item in input.split([',', '\n']) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let ports = match item.chars().next() {
                Some(candidate @ ('T' | 'U')) => {
                    let remainder = item[candidate.len_utf8()..].trim_start();
                    let Some(remainder) = remainder.strip_prefix(':') else {
                        return Err(TargetPortRangeError::InvalidSyntax);
                    };
                    protocol = candidate;
                    remainder.trim()
                }
                _ => item,
            };
            if ports.is_empty() {
                continue;
            }
            if ports.contains(':') {
                return Err(TargetPortRangeError::InvalidSyntax);
            }
            let ports = ports
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let (start, end) = match ports.split_once('-') {
                Some((start, end)) if !end.contains('-') => {
                    (parse_target_port(start)?, Some(parse_target_port(end)?))
                }
                Some(_) => return Err(TargetPortRangeError::InvalidSyntax),
                None => (parse_target_port(&ports)?, None),
            };
            if end.is_some_and(|end| start > end) {
                return Err(TargetPortRangeError::DescendingRange);
            }
            normalized.push(match end {
                Some(end) => format!("{protocol}:{start}-{end}"),
                None => format!("{protocol}:{start}"),
            });
        }
        if normalized.is_empty() {
            return Err(TargetPortRangeError::InvalidSyntax);
        }
        Ok(Self(normalized.join(", ")))
    }

    /// Borrow the normalized GMP wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetPortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TargetPortRange {
    type Err = TargetPortRangeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Errors raised while validating a target port-range list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TargetPortRangeError {
    /// The list does not match GMP's port-range syntax.
    #[error("invalid GMP port-range syntax")]
    InvalidSyntax,
    /// A port is zero, larger than 65535, or not decimal.
    #[error("target ports must be decimal values in 1..=65535")]
    InvalidPort,
    /// A range's first port is larger than its last port.
    #[error("a target port range must not descend")]
    DescendingRange,
}

fn parse_target_port(value: &str) -> Result<u16, TargetPortRangeError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TargetPortRangeError::InvalidPort);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| TargetPortRangeError::InvalidPort)?;
    (port != 0)
        .then_some(port)
        .ok_or(TargetPortRangeError::InvalidPort)
}

fn deduplicate_hosts(hosts: impl IntoIterator<Item = TargetHost>) -> Vec<TargetHost> {
    let mut seen = HashSet::new();
    hosts
        .into_iter()
        .filter(|host| seen.insert(host.identity.clone()))
        .collect()
}

fn identity_is_covered(identity: &TargetHostIdentity, excluded: &[TargetHost]) -> bool {
    match identity {
        TargetHostIdentity::Hostname(hostname) => excluded.iter().any(|excluded| {
            matches!(&excluded.identity, TargetHostIdentity::Hostname(value) if value == hostname)
        }),
        TargetHostIdentity::Ip(address) => {
            let interval = IpInterval::from_address(*address);
            interval_is_covered(interval, excluded)
        }
        TargetHostIdentity::Network { start, end }
        | TargetHostIdentity::Range { start, end } => {
            let interval = IpInterval::from_bounds(*start, *end);
            interval_is_covered(interval, excluded)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpInterval {
    version: u8,
    start: u128,
    end: u128,
}

impl IpInterval {
    fn from_address(address: IpAddr) -> Self {
        Self::from_bounds(address, address)
    }

    fn from_bounds(start: IpAddr, end: IpAddr) -> Self {
        match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => Self {
                version: 4,
                start: u128::from(u32::from(start)),
                end: u128::from(u32::from(end)),
            },
            (IpAddr::V6(start), IpAddr::V6(end)) => Self {
                version: 6,
                start: u128::from(start),
                end: u128::from(end),
            },
            _ => unreachable!("validated interval bounds use one IP version"),
        }
    }
}

fn interval_is_covered(included: IpInterval, excluded: &[TargetHost]) -> bool {
    let mut intervals = excluded
        .iter()
        .filter_map(|host| match &host.identity {
            TargetHostIdentity::Ip(address) => Some(IpInterval::from_address(*address)),
            TargetHostIdentity::Network { start, end }
            | TargetHostIdentity::Range { start, end } => {
                Some(IpInterval::from_bounds(*start, *end))
            }
            TargetHostIdentity::Hostname(_) => None,
        })
        .filter(|interval| {
            interval.version == included.version
                && interval.end >= included.start
                && interval.start <= included.end
        })
        .collect::<Vec<_>>();
    intervals.sort_unstable_by_key(|interval| interval.start);

    let mut cursor = included.start;
    for excluded in intervals {
        if excluded.start > cursor {
            return false;
        }
        if excluded.end >= included.end {
            return true;
        }
        cursor = cursor.max(excluded.end.saturating_add(1));
    }
    false
}

impl TargetHost {
    /// Parse and validate a target-host specification.
    ///
    /// # Errors
    /// Returns [`TargetHostError`] when `value` is not one complete host
    /// specification accepted by gvmd.
    pub fn new(value: impl Into<String>) -> Result<Self, TargetHostError> {
        let input = value.into();
        let value = input.trim();
        if value.is_empty() {
            return Err(TargetHostError::new(input, TargetHostErrorKind::Empty));
        }
        if value.contains([',', '\n', '\r']) {
            return Err(TargetHostError::new(
                input,
                TargetHostErrorKind::MultipleSpecifications,
            ));
        }
        let value = normalize_ipv4_specification(value).unwrap_or_else(|| value.to_string());

        let kind = classify(&value).map_err(|kind| TargetHostError::new(input, kind))?;
        let identity = target_host_identity(&value, kind);
        Ok(Self {
            value,
            kind,
            identity,
        })
    }

    /// Borrow the validated wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Return the host-specification category.
    #[must_use]
    pub const fn kind(&self) -> TargetHostKind {
        self.kind
    }
}

impl fmt::Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TargetHost {
    type Err = TargetHostError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for TargetHost {
    type Error = TargetHostError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for TargetHost {
    type Error = TargetHostError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TargetHost {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TargetHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The syntax category of a validated [`TargetHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetHostKind {
    /// A single IPv4 or IPv6 address.
    IpAddress,
    /// An IPv4 or IPv6 CIDR network.
    Network,
    /// A full or abbreviated IPv4 or IPv6 address range.
    Range,
    /// A DNS-style hostname accepted by gvmd.
    Hostname,
}

/// Errors raised while validating a [`TargetHost`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid target host specification {input:?}: {kind}")]
pub struct TargetHostError {
    input: String,
    kind: TargetHostErrorKind,
}

impl TargetHostError {
    fn new(input: String, kind: TargetHostErrorKind) -> Self {
        Self { input, kind }
    }

    /// Return the rejected input.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Return the validation failure category.
    #[must_use]
    pub const fn kind(&self) -> TargetHostErrorKind {
        self.kind
    }
}

/// Classification of a target-host validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TargetHostErrorKind {
    /// The specification is empty after trimming surrounding whitespace.
    #[error("the specification is empty")]
    Empty,
    /// A single value contains a GMP host-list separator.
    #[error("expected one specification, not a comma or newline separated list")]
    MultipleSpecifications,
    /// A CIDR address or prefix is invalid for its IP version.
    #[error("invalid CIDR network")]
    InvalidNetwork,
    /// An address range is malformed, mixes IP versions, or is reversed.
    #[error("invalid address range")]
    InvalidRange,
    /// The value does not match any host form accepted by gvmd.
    #[error("unsupported host syntax")]
    InvalidSyntax,
}

fn classify(value: &str) -> Result<TargetHostKind, TargetHostErrorKind> {
    if value.parse::<IpAddr>().is_ok() {
        return Ok(TargetHostKind::IpAddress);
    }
    if value.contains('/') {
        return validate_network(value).map(|()| TargetHostKind::Network);
    }
    if let Some(result) = classify_range(value) {
        return result.map(|()| TargetHostKind::Range);
    }
    if is_valid_hostname(value) {
        return Ok(TargetHostKind::Hostname);
    }
    Err(TargetHostErrorKind::InvalidSyntax)
}

fn target_host_identity(value: &str, kind: TargetHostKind) -> TargetHostIdentity {
    match kind {
        TargetHostKind::IpAddress => TargetHostIdentity::Ip(
            value
                .parse()
                .expect("validated IP address must remain parseable"),
        ),
        TargetHostKind::Network => {
            let (address, prefix) = value
                .split_once('/')
                .expect("validated network must contain a prefix");
            let address = address
                .parse()
                .expect("validated network address must remain parseable");
            let prefix = prefix
                .parse()
                .expect("validated network prefix must remain parseable");
            let (start, end) = network_bounds(address, prefix);
            TargetHostIdentity::Network { start, end }
        }
        TargetHostKind::Range => {
            let (start, end) = range_bounds(value);
            TargetHostIdentity::Range { start, end }
        }
        TargetHostKind::Hostname => TargetHostIdentity::Hostname(value.to_ascii_lowercase()),
    }
}

fn network_bounds(address: IpAddr, prefix: u16) -> (IpAddr, IpAddr) {
    match address {
        IpAddr::V4(address) => {
            let prefix = u32::from(prefix);
            let mask = u32::MAX << (32 - prefix);
            let network = u32::from(address) & mask;
            let broadcast = network | !mask;
            (
                IpAddr::V4(Ipv4Addr::from(network + 1)),
                IpAddr::V4(Ipv4Addr::from(broadcast - 1)),
            )
        }
        IpAddr::V6(address) => {
            let prefix = u32::from(prefix);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = u128::from(address) & mask;
            let last = network | !mask;
            let (start, end) = if prefix >= 127 {
                (network, last)
            } else {
                (network + 1, last - 1)
            };
            (
                IpAddr::V6(Ipv6Addr::from(start)),
                IpAddr::V6(Ipv6Addr::from(end)),
            )
        }
    }
}

fn range_bounds(value: &str) -> (IpAddr, IpAddr) {
    let (start, end) = value
        .split_once('-')
        .expect("validated range must contain a separator");
    let start: IpAddr = start
        .parse()
        .expect("validated range start must remain parseable");
    if let Ok(end) = end.parse() {
        return (start, end);
    }
    match start {
        IpAddr::V4(start) => {
            let mut octets = start.octets();
            octets[3] = end
                .parse()
                .expect("validated short IPv4 range must remain parseable");
            (IpAddr::V4(start), IpAddr::V4(Ipv4Addr::from(octets)))
        }
        IpAddr::V6(start) => {
            let mut segments = start.segments();
            segments[7] = u16::from_str_radix(end, 16)
                .expect("validated short IPv6 range must remain parseable");
            (IpAddr::V6(start), IpAddr::V6(Ipv6Addr::from(segments)))
        }
    }
}

fn normalize_ipv4_specification(value: &str) -> Option<String> {
    if let Some((address, prefix)) = value.split_once('/') {
        if prefix.is_empty()
            || prefix.contains(['/', '-'])
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        return Some(format!(
            "{}/{}",
            normalize_ipv4_address(address)?,
            normalize_decimal(prefix)
        ));
    }
    if let Some((start, end)) = value.split_once('-') {
        if end.is_empty()
            || end.contains(['/', '-'])
            || !end
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return None;
        }
        let start = normalize_ipv4_address(start)?;
        let end = if end.contains('.') {
            normalize_ipv4_address(end)?
        } else {
            normalize_decimal(end)
        };
        return Some(format!("{start}-{end}"));
    }
    normalize_ipv4_address(value)
}

fn normalize_ipv4_address(value: &str) -> Option<String> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() != 4
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some(
        components
            .into_iter()
            .map(normalize_decimal)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn normalize_decimal(value: &str) -> String {
    let value = value.trim_start_matches('0');
    if value.is_empty() {
        "0".to_string()
    } else {
        value.to_string()
    }
}

fn validate_network(value: &str) -> Result<(), TargetHostErrorKind> {
    let (address, prefix) = value
        .split_once('/')
        .filter(|(_, prefix)| !prefix.contains('/'))
        .ok_or(TargetHostErrorKind::InvalidNetwork)?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| TargetHostErrorKind::InvalidNetwork)?;
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TargetHostErrorKind::InvalidNetwork);
    }
    let prefix = prefix
        .parse::<u16>()
        .map_err(|_| TargetHostErrorKind::InvalidNetwork)?;
    let valid = match address {
        IpAddr::V4(_) => (1..=30).contains(&prefix),
        IpAddr::V6(_) => (1..=128).contains(&prefix),
    };
    valid
        .then_some(())
        .ok_or(TargetHostErrorKind::InvalidNetwork)
}

fn classify_range(value: &str) -> Option<Result<(), TargetHostErrorKind>> {
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<IpAddr>().ok()?;
    if let Ok(end) = end.parse::<IpAddr>() {
        return Some(match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => Ok(()),
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => Ok(()),
            _ => Err(TargetHostErrorKind::InvalidRange),
        });
    }

    match start {
        IpAddr::V4(start) => classify_short_ipv4_range(start, end),
        IpAddr::V6(start) => classify_short_ipv6_range(start, end),
    }
}

fn classify_short_ipv4_range(
    start: Ipv4Addr,
    end: &str,
) -> Option<Result<(), TargetHostErrorKind>> {
    if end.is_empty() || !end.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let end = end.parse::<u8>().ok()?;
    Some(
        (start.octets()[3] <= end)
            .then_some(())
            .ok_or(TargetHostErrorKind::InvalidRange),
    )
}

fn classify_short_ipv6_range(
    start: Ipv6Addr,
    end: &str,
) -> Option<Result<(), TargetHostErrorKind>> {
    if end.is_empty() || end.len() > 4 || !end.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let end = u16::from_str_radix(end, 16).ok()?;
    Some(
        (start.segments()[7] <= end)
            .then_some(())
            .ok_or(TargetHostErrorKind::InvalidRange),
    )
}

fn is_valid_hostname(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    let mut labels = value.split('.').peekable();
    while let Some(label) = labels.next() {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return false;
        }
        if labels.peek().is_none() && label.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> TargetHost {
        value.parse().expect("valid target host")
    }

    #[test]
    fn target_hosts_requires_included_hosts_and_deduplicates_canonically() {
        assert_eq!(
            TargetHosts::new([], []).expect_err("empty included hosts"),
            TargetHostsError::EmptyIncludedHosts
        );

        let hosts = TargetHosts::new(
            [
                host("001.002.003.004"),
                host("1.2.3.4"),
                host("2001:0db8:0:0:0:0:0:1"),
                host("2001:db8::1"),
                host("2001:db8:1::1/64"),
                host("2001:0db8:0001::ffff/64"),
                host("2001:db8::10-001f"),
                host("2001:0db8:0:0:0:0:0:10-2001:db8::1f"),
                host("Scanner.Example."),
                host("scanner.example."),
                host("scanner.example"),
            ],
            [host("2001:0db8::2"), host("2001:db8::2")],
        )
        .expect("valid target hosts");
        assert_eq!(
            hosts
                .included()
                .iter()
                .map(TargetHost::as_str)
                .collect::<Vec<_>>(),
            [
                "1.2.3.4",
                "2001:0db8:0:0:0:0:0:1",
                "2001:db8:1::1/64",
                "2001:db8::10-001f",
                "Scanner.Example.",
                "scanner.example",
            ]
        );
        assert_eq!(hosts.excluded(), [host("2001:0db8::2")]);
    }

    #[test]
    fn target_hosts_rejects_empty_effective_address_sets_without_expansion() {
        for (included, excluded) in [
            (&["192.0.2.1"][..], &["192.0.2.1"][..]),
            (&["192.0.2.0/30"][..], &["192.0.2.1-192.0.2.2"][..]),
            (&["2001:db8::/126"][..], &["2001:db8::1", "2001:db8::2"][..]),
            (&["Scanner.Example."][..], &["scanner.example."][..]),
            (&["2001:db8::/127"][..], &["2001:db8::-0001"][..]),
            (&["2001:db8::1/128"][..], &["2001:db8::1"][..]),
        ] {
            let error = TargetHosts::new(
                included.iter().map(|value| host(value)),
                excluded.iter().map(|value| host(value)),
            )
            .expect_err("fully excluded target hosts");
            assert_eq!(
                error,
                TargetHostsError::EmptyEffectiveHosts,
                "{included:?} - {excluded:?}"
            );
        }

        let hosts = TargetHosts::new([host("192.0.2.0/30")], [host("192.0.2.1")])
            .expect("valid target hosts");
        assert!(hosts.has_effective_hosts());

        let hosts = TargetHosts::new([host("Scanner.Example.")], [host("scanner.example")])
            .expect("valid target hosts");
        assert!(hosts.has_effective_hosts());
    }

    #[test]
    fn target_port_ranges_validate_and_normalize_gmp_syntax() {
        assert_eq!(
            TargetPortRange::new(" T:00022, U:53, T:80-00443 ")
                .expect("valid port range")
                .as_str(),
            "T:22, U:53, T:80-443"
        );
        assert_eq!(
            TargetPortRange::new(" T  : 1 -5, 7,9,\nU:1-3, 5,,\n,7,9 ")
                .expect("gvmd-compatible port range")
                .as_str(),
            "T:1-5, T:7, T:9, U:1-3, U:5, U:7, U:9"
        );
        assert_eq!(
            TargetPortRange::new("6-9,7,7,10-20,20")
                .expect("implicit TCP port range")
                .as_str(),
            "T:6-9, T:7, T:7, T:10-20, T:20"
        );

        for (value, error) in [
            ("", TargetPortRangeError::InvalidSyntax),
            ("U:,T:", TargetPortRangeError::InvalidSyntax),
            ("tcp:22", TargetPortRangeError::InvalidSyntax),
            ("T,U", TargetPortRangeError::InvalidSyntax),
            ("T:0", TargetPortRangeError::InvalidPort),
            ("U:65536", TargetPortRangeError::InvalidPort),
            ("T:443-80", TargetPortRangeError::DescendingRange),
            ("T:1-2-3", TargetPortRangeError::InvalidSyntax),
        ] {
            assert_eq!(TargetPortRange::new(value), Err(error), "{value}");
        }
    }

    #[test]
    fn classifies_supported_host_forms() {
        for (value, kind) in [
            ("192.0.2.1", TargetHostKind::IpAddress),
            ("2001:db8::1", TargetHostKind::IpAddress),
            ("192.0.2.0/30", TargetHostKind::Network),
            ("2001:db8::/64", TargetHostKind::Network),
            ("192.0.2.1-20", TargetHostKind::Range),
            ("192.0.2.1-192.0.3.20", TargetHostKind::Range),
            ("2001:db8::1-00ff", TargetHostKind::Range),
            ("2001:db8::1-2001:db8::ff", TargetHostKind::Range),
            ("scanner_example.test.", TargetHostKind::Hostname),
        ] {
            assert_eq!(host(value).kind(), kind, "{value}");
        }
    }

    #[test]
    fn enforces_ip_version_specific_cidr_limits() {
        for value in [
            "192.0.2.0/1",
            "192.0.2.0/30",
            "2001:db8::/1",
            "2001:db8::/127",
            "2001:db8::1/128",
        ] {
            assert_eq!(host(value).kind(), TargetHostKind::Network, "{value}");
        }
        for value in [
            "192.0.2.0/0",
            "192.0.2.0/31",
            "192.0.2.0/32",
            "192.0.2.0/+24",
            "2001:db8::/0",
            "2001:db8::/+64",
            "2001:db8::/129",
        ] {
            assert_eq!(
                value
                    .parse::<TargetHost>()
                    .expect_err("invalid network")
                    .kind(),
                TargetHostErrorKind::InvalidNetwork,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_invalid_ranges_and_syntax() {
        for value in [
            "192.0.2.20-1",
            "192.0.2.20-192.0.2.1",
            "192.0.2.1-2001:db8::1",
            "2001:db8::20-0001",
            "2001:db8::20-2001:db8::1",
        ] {
            assert_eq!(
                value
                    .parse::<TargetHost>()
                    .expect_err("invalid range")
                    .kind(),
                TargetHostErrorKind::InvalidRange,
                "{value}"
            );
        }
        for value in [
            "",
            "   ",
            "bad host",
            "-host.example",
            "host-.example",
            "example.123",
            "192.0.2.1-+20",
            "ſ.example",
            "K.example",
        ] {
            assert!(value.parse::<TargetHost>().is_err(), "{value:?}");
        }
        assert_eq!(
            "192.0.2.1,192.0.2.2"
                .parse::<TargetHost>()
                .expect_err("multiple specifications")
                .kind(),
            TargetHostErrorKind::MultipleSpecifications
        );
    }

    #[test]
    fn trims_and_preserves_supported_wire_spelling() {
        let host = host("  Scanner_One.Example.  ");
        assert_eq!(host.as_str(), "Scanner_One.Example.");
        assert_eq!(host.to_string(), "Scanner_One.Example.");
    }

    #[test]
    fn normalizes_ipv4_leading_zeroes_like_gvmd() {
        for (input, normalized, kind) in [
            ("000.001.002.003", "0.1.2.3", TargetHostKind::IpAddress),
            ("000.001.002.003/024", "0.1.2.3/24", TargetHostKind::Network),
            ("000.001.002.003-004", "0.1.2.3-4", TargetHostKind::Range),
            (
                "000.001.002.003-000.001.002.004",
                "0.1.2.3-0.1.2.4",
                TargetHostKind::Range,
            ),
            (
                "000000000000000000192.000168.000001.000001",
                "192.168.1.1",
                TargetHostKind::IpAddress,
            ),
        ] {
            let host = host(input);
            assert_eq!(host.as_str(), normalized, "{input}");
            assert_eq!(host.kind(), kind, "{input}");
        }

        for input in [
            "000.001.002.999",
            "000.001.002.003/000",
            "000.001.002.003/031",
        ] {
            assert!(input.parse::<TargetHost>().is_err(), "{input}");
        }
    }

    #[test]
    fn ip_prefixed_hostname_falls_through_range_classification() {
        let host = host("192.0.2.1-example.com");
        assert_eq!(host.kind(), TargetHostKind::Hostname);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_validated_string_representation() {
        let host = host("192.0.2.0/30");
        assert_eq!(
            serde_json::to_string(&host).expect("serialize host"),
            "\"192.0.2.0/30\""
        );
        assert_eq!(
            serde_json::from_str::<TargetHost>("\"2001:db8::1/128\"")
                .expect("deserialize valid host")
                .as_str(),
            "2001:db8::1/128"
        );
        assert!(serde_json::from_str::<TargetHost>("\"192.0.2.0/31\"").is_err());
        assert_eq!(
            serde_json::from_str::<TargetHost>("\"000.001.002.003/030\"")
                .expect("deserialize normalized host")
                .as_str(),
            "0.1.2.3/30"
        );
        for value in [
            "\"192.0.2.0/+24\"",
            "\"2001:db8::/+64\"",
            "\"192.0.2.1-+20\"",
        ] {
            assert!(
                serde_json::from_str::<TargetHost>(value).is_err(),
                "{value}"
            );
        }
    }
}
