//! Native LDAP search/bind profile over one host-enrolled TLS connection.
//! Filters are parsed before I/O; template values enter BER assertion values,
//! never LDAP filter syntax. No referrals, controls, paging, retries, or new CA.
use super::*;

const MAX_FILTER_INPUT: usize = 4096;
const MAX_FILTER_WIRE: usize = 16 * 1024;
const MAX_FILTER_VALUE: usize = 4096;
const MAX_FILTER_DEPTH: usize = 12;
const MAX_FILTER_NODES: usize = 128;
const MAX_RESPONSE_TOTAL: usize = 256 * 1024;
const MAX_GROUPS: usize = 128;
const DEFAULT_USER_FILTER: &str = "({{.UserAttr}}={{.Username}})";

pub(crate) struct LdapNativeOptions<'a> {
    pub(crate) bind_dn: &'a str,
    pub(crate) bind_password: &'a str,
    pub(crate) user_dn: &'a str,
    pub(crate) user_attr: &'a str,
    pub(crate) user_filter: &'a str,
    pub(crate) group_dn: &'a str,
    pub(crate) group_attr: &'a str,
    pub(crate) group_filter: &'a str,
    pub(crate) username_as_alias: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LdapNativeObservation {
    pub(crate) alias: String,
    pub(crate) groups: BTreeSet<String>,
}

#[derive(Clone, Copy)]
struct Context<'a> {
    username: &'a str,
    user_attr: &'a str,
    user_dn: &'a str,
    group: bool,
}

impl LdapNativeOptions<'_> {
    /// Check this bounded profile before storing configuration, without I/O or
    /// any caller credential. Actual assertion sizes are checked again at login.
    pub(crate) fn validate_configuration(&self) -> Result<(), &'static str> {
        self.validate("configuration-validation", "synthetic-validation-password")
    }

    fn validate(&self, username: &str, password: &str) -> Result<(), &'static str> {
        // This profile supports authenticated manager discovery, not accidental
        // anonymous/unauthenticated binds when either credential is missing.
        if !valid_dn(self.bind_dn)
            || !valid_dn(self.user_dn)
            || !valid_password(self.bind_password)
            || !valid_password(password)
            || username.is_empty()
            || username.len() > 1024
            || username.chars().any(char::is_control)
            || !valid_ldap_attribute(self.user_attr)
            || !valid_ldap_attribute(self.group_attr)
            || (!self.group_dn.is_empty() && !valid_dn(self.group_dn))
        {
            return Err("invalid native LDAP options or credential bounds");
        }
        let context = Context {
            username,
            user_attr: self.user_attr,
            user_dn: self.user_dn,
            group: false,
        };
        let _ = compile_filter(self.user_filter_or_default(), context)?;
        // Validate configured syntax even when group search is disabled. Empty
        // groupfilter is the explicit no-search setting, as in OpenBao.
        if !self.group_filter.is_empty() {
            let _ = compile_filter(
                self.group_filter,
                Context {
                    group: true,
                    ..context
                },
            )?;
        }
        Ok(())
    }

    fn user_filter_or_default(&self) -> &str {
        if self.user_filter.is_empty() {
            DEFAULT_USER_FILTER
        } else {
            self.user_filter
        }
    }
}

fn valid_dn(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn valid_password(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.as_bytes().contains(&0)
}

impl Outbound {
    pub(crate) fn ldap_authenticate_native(
        &self,
        url: &str,
        options: &LdapNativeOptions<'_>,
        username: &str,
        password: &str,
    ) -> Result<Option<LdapNativeObservation>, &'static str> {
        options.validate(username, password)?;
        let (endpoint, target) = self.endpoint(url, "ldaps")?;
        if target.path != "/" {
            return Err("native LDAP target must be an enrolled origin");
        }
        // One absolute connect/TLS/operation deadline for the entire exchange.
        // No query, message or bind refreshes it.
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        authenticate_exchange(&mut stream, options, username, password)
    }
}

fn authenticate_exchange(
    stream: &mut (impl Read + Write),
    options: &LdapNativeOptions<'_>,
    username: &str,
    password: &str,
) -> Result<Option<LdapNativeObservation>, &'static str> {
    options.validate(username, password)?;
    let mut remaining = MAX_RESPONSE_TOTAL;
    ldap_write(
        stream,
        &bind_request(1, options.bind_dn, options.bind_password)?,
    )?;
    if read_bind_result(stream, 1, &mut remaining)? != 0 {
        return Err("LDAP manager bind rejected");
    }
    let context = Context {
        username,
        user_attr: options.user_attr,
        user_dn: "",
        group: false,
    };
    let filter = compile_filter(options.user_filter_or_default(), context)?;
    ldap_write(
        stream,
        &search_request(2, options.user_dn, options.user_attr, &filter, 2)?,
    )?;
    let mut users = read_search(stream, 2, options.user_attr, 2, &mut remaining)?;
    if users.len() != 1 {
        return Ok(None);
    }
    let user = users.pop().ok_or("LDAP user observation missing")?;
    let alias = if options.username_as_alias {
        username.to_owned()
    } else {
        if user.values.len() != 1 {
            return Err("LDAP user alias attribute is missing or ambiguous");
        }
        user.values
            .into_iter()
            .next()
            .ok_or("LDAP user alias missing")?
    };
    ldap_write(stream, &bind_request(3, &user.dn, password)?)?;
    match read_bind_result(stream, 3, &mut remaining)? {
        0 => {}
        49 => return Ok(None), // invalidCredentials is an authentication denial.
        _ => return Err("LDAP user bind failed"),
    }
    // Group authority is the explicitly configured manager, never whichever
    // ACLs happen to be available to the authenticated user.
    ldap_write(
        stream,
        &bind_request(4, options.bind_dn, options.bind_password)?,
    )?;
    if read_bind_result(stream, 4, &mut remaining)? != 0 {
        return Err("LDAP manager rebind rejected");
    }
    let mut groups = BTreeSet::new();
    if !options.group_dn.is_empty() && !options.group_filter.is_empty() {
        let filter = compile_filter(
            options.group_filter,
            Context {
                user_dn: &user.dn,
                group: true,
                ..context
            },
        )?;
        ldap_write(
            stream,
            &search_request(5, options.group_dn, options.group_attr, &filter, 128)?,
        )?;
        for entry in read_search(stream, 5, options.group_attr, MAX_GROUPS, &mut remaining)? {
            if entry.values.is_empty() {
                return Err("LDAP group name attribute missing");
            }
            for value in entry.values {
                if value.len() > 256 || (groups.len() >= MAX_GROUPS && !groups.contains(&value)) {
                    return Err("LDAP group names exceed bound");
                }
                groups.insert(value);
            }
        }
    }
    Ok(Some(LdapNativeObservation { alias, groups }))
}

fn bind_request(id: u8, dn: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if id == 0 || id > 127 || !valid_dn(dn) || !valid_password(password) {
        return Err("invalid native LDAP bind input");
    }
    // Reuse the parent's fully preallocated, zeroizing password encoder. Only
    // replace its fixed one-byte message id in place; do not duplicate secrets.
    let mut message = ldap_bind_request(dn.as_bytes(), password.as_bytes())?;
    let mut offset = 1;
    let _ = ber_take_length(&message, &mut offset)?;
    if message.get(offset..offset + 3) != Some(&[0x02, 0x01, 0x01]) {
        return Err("invalid native LDAP bind envelope");
    }
    message[offset + 2] = id;
    Ok(message)
}

fn append_bounded(out: &mut Vec<u8>, input: &[u8], bound: usize) -> Result<(), &'static str> {
    if input.len() > bound.saturating_sub(out.len()) {
        return Err("LDAP encoded value exceeds bound");
    }
    out.extend_from_slice(input);
    Ok(())
}

fn append_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8], bound: usize) -> Result<(), &'static str> {
    let encoded = Zeroizing::new(ber_value(tag, value)?);
    append_bounded(out, &encoded, bound)
}

fn search_request(
    id: u8,
    base: &str,
    attribute: &str,
    filter: &[u8],
    limit: u8,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if !valid_dn(base) || !valid_ldap_attribute(attribute) || filter.len() > MAX_FILTER_WIRE {
        return Err("invalid native LDAP search input");
    }
    let bound = MAX_FILTER_WIRE + 2048;
    let mut search = Zeroizing::new(Vec::with_capacity(bound));
    for (tag, value) in [
        (0x04, base.as_bytes()),
        (0x0a, &[2][..]), // whole subtree
        (0x0a, &[0][..]), // never dereference aliases
    ] {
        append_tlv(&mut search, tag, value, bound)?;
    }
    let size = if limit >= 128 {
        vec![0, limit]
    } else {
        vec![limit]
    };
    append_tlv(&mut search, 0x02, &size, bound)?;
    append_tlv(&mut search, 0x02, &[3], bound)?;
    append_tlv(&mut search, 0x01, &[0], bound)?;
    append_bounded(&mut search, filter, bound)?;
    let attribute = Zeroizing::new(ber_value(0x04, attribute.as_bytes())?);
    append_tlv(&mut search, 0x30, &attribute, bound)?;
    let operation = Zeroizing::new(ber_value(0x63, &search)?);
    let mut message = Zeroizing::new(Vec::with_capacity(operation.len() + 3));
    message.extend_from_slice(&[0x02, 0x01, id]);
    message.extend_from_slice(&operation);
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

struct FilterParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
    context: Context<'a>,
}

fn compile_filter(input: &str, context: Context<'_>) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if input.is_empty() || input.len() > MAX_FILTER_INPUT {
        return Err("LDAP filter input exceeds bound");
    }
    let mut parser = FilterParser {
        bytes: input.as_bytes(),
        offset: 0,
        nodes: 0,
        context,
    };
    let encoded = parser.parse(0)?;
    if parser.offset != parser.bytes.len() {
        return Err("LDAP filter has trailing syntax");
    }
    Ok(encoded)
}

impl FilterParser<'_> {
    fn take(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.bytes.get(self.offset) != Some(&expected) {
            return Err("invalid LDAP filter syntax");
        }
        self.offset += 1;
        Ok(())
    }

    fn parse(&mut self, depth: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if depth >= MAX_FILTER_DEPTH || self.nodes >= MAX_FILTER_NODES {
            return Err("LDAP filter complexity exceeds bound");
        }
        self.nodes += 1;
        self.take(b'(')?;
        match self.bytes.get(self.offset).copied() {
            Some(op @ (b'&' | b'|' | b'!')) => {
                self.offset += 1;
                let mut children = Zeroizing::new(Vec::with_capacity(MAX_FILTER_WIRE));
                let mut count = 0;
                while self.bytes.get(self.offset) == Some(&b'(') {
                    let child = self.parse(depth + 1)?;
                    append_bounded(&mut children, &child, MAX_FILTER_WIRE)?;
                    count += 1;
                }
                if count == 0 || (op == b'!' && count != 1) {
                    return Err("LDAP filter boolean arity invalid");
                }
                self.take(b')')?;
                let tag = match op {
                    b'&' => 0xa0,
                    b'|' => 0xa1,
                    _ => 0xa2,
                };
                let encoded = Zeroizing::new(ber_value(tag, &children)?);
                if encoded.len() > MAX_FILTER_WIRE {
                    return Err("LDAP filter wire length exceeds bound");
                }
                Ok(encoded)
            }
            Some(_) => self.assertion(),
            None => Err("LDAP filter is truncated"),
        }
    }

    fn assertion(&mut self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(|v| *v != b'=') {
            if matches!(
                self.bytes[self.offset],
                b'(' | b')' | b':' | b'~' | b'<' | b'>'
            ) {
                return Err("unsupported LDAP filter operator");
            }
            self.offset += 1;
        }
        let bytes = self.bytes;
        let raw = bytes
            .get(start..self.offset)
            .ok_or("LDAP filter attribute missing")?;
        let attribute = if raw == b"{{.UserAttr}}" && !self.context.group {
            self.context.user_attr
        } else {
            std::str::from_utf8(raw).map_err(|_| "LDAP filter attribute is not UTF-8")?
        };
        if !valid_ldap_attribute(attribute) {
            return Err("invalid LDAP filter attribute");
        }
        self.take(b'=')?;
        if self.bytes.get(self.offset..self.offset + 2) == Some(b"*)") {
            self.offset += 2;
            return Ok(Zeroizing::new(ber_value(0x87, attribute.as_bytes())?));
        }
        let mut value = Zeroizing::new(Vec::with_capacity(MAX_FILTER_VALUE));
        while self.bytes.get(self.offset) != Some(&b')') {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or("LDAP filter is truncated")?;
            match byte {
                b'(' | b'*' | 0 => return Err("unsupported LDAP filter substring or syntax"),
                b'\\' => {
                    let high = hex(*self
                        .bytes
                        .get(self.offset + 1)
                        .ok_or("LDAP filter escape truncated")?)?;
                    let low = hex(*self
                        .bytes
                        .get(self.offset + 2)
                        .ok_or("LDAP filter escape truncated")?)?;
                    append_bounded(&mut value, &[high * 16 + low], MAX_FILTER_VALUE)?;
                    self.offset += 3;
                }
                b'{' if self.bytes.get(self.offset + 1) == Some(&b'{') => {
                    let tail = &self.bytes[self.offset..];
                    let (length, replacement) = if tail.starts_with(b"{{.Username}}") {
                        (13, self.context.username)
                    } else if tail.starts_with(b"{{.UserDN}}") && self.context.group {
                        (11, self.context.user_dn)
                    } else {
                        return Err("unsupported LDAP filter template");
                    };
                    append_bounded(&mut value, replacement.as_bytes(), MAX_FILTER_VALUE)?;
                    self.offset += length;
                }
                b'{' | b'}' => return Err("unsupported LDAP filter template syntax"),
                _ => {
                    append_bounded(&mut value, &[byte], MAX_FILTER_VALUE)?;
                    self.offset += 1;
                }
            }
        }
        self.take(b')')?;
        let mut equality = Zeroizing::new(Vec::with_capacity(MAX_FILTER_VALUE + 72));
        append_tlv(
            &mut equality,
            0x04,
            attribute.as_bytes(),
            MAX_FILTER_VALUE + 72,
        )?;
        append_tlv(&mut equality, 0x04, &value, MAX_FILTER_VALUE + 72)?;
        Ok(Zeroizing::new(ber_value(0xa3, &equality)?))
    }
}

fn hex(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid LDAP filter hex escape"),
    }
}

fn response_body(
    stream: &mut impl Read,
    remaining: &mut usize,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header[..2])
        .map_err(|_| "LDAP response header truncated")?;
    if header[0] != 0x30 {
        return Err("LDAP response envelope invalid");
    }
    let extra = if header[1] & 0x80 == 0 {
        0
    } else {
        usize::from(header[1] & 0x7f)
    };
    if header[1] == 0x80 || extra > 2 {
        return Err("LDAP response length unsupported");
    }
    if extra > 0 {
        stream
            .read_exact(&mut header[2..2 + extra])
            .map_err(|_| "LDAP response length truncated")?;
    }
    let mut offset = 1;
    let length = ber_take_length(&header[..2 + extra], &mut offset)?;
    if length == 0 || length > 64 * 1024 {
        return Err("LDAP response frame exceeds bound");
    }
    *remaining = remaining
        .checked_sub(length + 2 + extra)
        .ok_or("LDAP total response budget exhausted")?;
    // Protect partially read buffers too: a hostile diagnostic can contain a
    // credential even when the frame is truncated before read_exact completes.
    let mut body = Zeroizing::new(vec![0u8; length]);
    stream
        .read_exact(&mut body)
        .map_err(|_| "LDAP response body truncated")?;
    Ok(body)
}

fn response_operation(body: &[u8], id: u8, tag: u8) -> Result<&[u8], &'static str> {
    let mut cursor = 0;
    if ber_take(body, &mut cursor, 0x02)? != [id] {
        return Err("unexpected native LDAP response message id");
    }
    let operation = ber_take(body, &mut cursor, tag)?;
    if cursor != body.len() {
        return Err("native LDAP controls or trailing bytes unsupported");
    }
    Ok(operation)
}

fn result_code(operation: &[u8]) -> Result<u8, &'static str> {
    let mut inner = 0;
    let result = ber_take(operation, &mut inner, 0x0a)?;
    if result.len() != 1 || result[0] >= 128 {
        return Err("invalid native LDAP result code");
    }
    let _ = ber_take(operation, &mut inner, 0x04)?;
    let _ = ber_take(operation, &mut inner, 0x04)?;
    if inner != operation.len() {
        return Err("native LDAP referrals or SASL credentials unsupported");
    }
    Ok(result[0])
}

fn read_bind_result(
    stream: &mut impl Read,
    id: u8,
    remaining: &mut usize,
) -> Result<u8, &'static str> {
    let body = response_body(stream, remaining)?;
    result_code(response_operation(&body, id, 0x61)?)
}

struct Entry {
    dn: String,
    values: Vec<String>,
}

fn read_search(
    stream: &mut impl Read,
    id: u8,
    attribute: &str,
    entry_limit: usize,
    remaining: &mut usize,
) -> Result<Vec<Entry>, &'static str> {
    let mut entries = Vec::with_capacity(entry_limit);
    for _ in 0..=entry_limit {
        let body = response_body(stream, remaining)?;
        let mut cursor = 0;
        if ber_take(&body, &mut cursor, 0x02)? != [id] {
            return Err("unexpected native LDAP search message id");
        }
        let tag = *body.get(cursor).ok_or("LDAP search operation missing")?;
        let operation = response_operation(&body, id, tag)?;
        match tag {
            0x64 => {
                if entries.len() >= entry_limit {
                    return Err("native LDAP search entry count exceeds bound");
                }
                let mut inner = 0;
                let dn = std::str::from_utf8(ber_take(operation, &mut inner, 0x04)?)
                    .map_err(|_| "LDAP entry DN is not UTF-8")?;
                if !valid_dn(dn) {
                    return Err("LDAP entry DN exceeds bound");
                }
                let attributes = ber_take(operation, &mut inner, 0x30)?;
                if inner != operation.len() {
                    return Err("LDAP entry has trailing bytes");
                }
                let mut attr_cursor = 0;
                let mut values = Vec::with_capacity(32);
                let mut seen = false;
                while attr_cursor < attributes.len() {
                    let attr = ber_take(attributes, &mut attr_cursor, 0x30)?;
                    let mut part = 0;
                    let name = ber_take(attr, &mut part, 0x04)?;
                    if seen || !name.eq_ignore_ascii_case(attribute.as_bytes()) {
                        return Err("unexpected or duplicate native LDAP attribute");
                    }
                    seen = true;
                    let encoded = ber_take(attr, &mut part, 0x31)?;
                    if part != attr.len() {
                        return Err("LDAP attribute has trailing bytes");
                    }
                    let mut value_cursor = 0;
                    while value_cursor < encoded.len() {
                        if values.len() >= 32 {
                            return Err("LDAP attribute value count exceeds bound");
                        }
                        let value =
                            std::str::from_utf8(ber_take(encoded, &mut value_cursor, 0x04)?)
                                .map_err(|_| "LDAP attribute is not UTF-8")?;
                        if value.is_empty()
                            || value.len() > 1024
                            || value.chars().any(char::is_control)
                        {
                            return Err("LDAP attribute value exceeds bound");
                        }
                        values.push(value.to_owned());
                    }
                }
                entries.push(Entry {
                    dn: dn.to_owned(),
                    values,
                });
            }
            0x65 => {
                if result_code(operation)? != 0 {
                    return Err("native LDAP search was rejected");
                }
                return Ok(entries);
            }
            _ => return Err("native LDAP referral or search operation unsupported"),
        }
    }
    Err("native LDAP search completion missing")
}

#[cfg(test)]
#[path = "outbound_ldap_native_tests.rs"]
mod tests;
