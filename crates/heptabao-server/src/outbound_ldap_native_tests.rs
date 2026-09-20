#![allow(clippy::unwrap_used)]
use super::*;
use std::io::Cursor;

const GROUP_FILTER: &str =
    "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))";

fn options() -> LdapNativeOptions<'static> {
    LdapNativeOptions {
        bind_dn: "cn=manager,dc=test",
        bind_password: "synthetic-manager-password",
        user_dn: "ou=people,dc=test",
        user_attr: "uid",
        user_filter: DEFAULT_USER_FILTER,
        group_dn: "ou=groups,dc=test",
        group_attr: "cn",
        group_filter: GROUP_FILTER,
        username_as_alias: false,
    }
}

fn context<'a>(username: &'a str, user_dn: &'a str, group: bool) -> Context<'a> {
    Context {
        username,
        user_attr: "uid",
        user_dn,
        group,
    }
}

fn message(id: u8, tag: u8, content: &[u8]) -> Vec<u8> {
    let body = [
        ber_value(0x02, &[id]).unwrap(),
        ber_value(tag, content).unwrap(),
    ]
    .concat();
    ber_value(0x30, &body).unwrap()
}

fn result(id: u8, tag: u8, code: u8) -> Vec<u8> {
    message(
        id,
        tag,
        &[
            ber_value(0x0a, &[code]).unwrap(),
            ber_value(0x04, b"").unwrap(),
            ber_value(0x04, b"").unwrap(),
        ]
        .concat(),
    )
}

fn entry(id: u8, dn: &str, attrs: &[(&str, &[&str])]) -> Vec<u8> {
    let mut attributes = Vec::new();
    for (name, values) in attrs {
        let values: Vec<u8> = values
            .iter()
            .flat_map(|value| ber_value(0x04, value.as_bytes()).unwrap())
            .collect();
        attributes.extend(
            ber_value(
                0x30,
                &[
                    ber_value(0x04, name.as_bytes()).unwrap(),
                    ber_value(0x31, &values).unwrap(),
                ]
                .concat(),
            )
            .unwrap(),
        );
    }
    message(
        id,
        0x64,
        &[
            ber_value(0x04, dn.as_bytes()).unwrap(),
            ber_value(0x30, &attributes).unwrap(),
        ]
        .concat(),
    )
}

struct Exchange {
    input: Cursor<Vec<u8>>,
    written: Zeroizing<Vec<u8>>,
}
impl Exchange {
    fn new(messages: &[Vec<u8>]) -> Self {
        Self {
            input: Cursor::new(messages.concat()),
            written: Zeroizing::new(Vec::with_capacity(128 * 1024)),
        }
    }
    fn requests(&self) -> Vec<(u8, u8)> {
        let mut offset = 0;
        let mut requests = Vec::new();
        while offset < self.written.len() {
            let body = ber_take(&self.written, &mut offset, 0x30).unwrap();
            let mut inner = 0;
            let id = ber_take(body, &mut inner, 0x02).unwrap()[0];
            requests.push((id, body[inner]));
        }
        requests
    }
}
impl Read for Exchange {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.input.read(out)
    }
}
impl Write for Exchange {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.written.capacity() - self.written.len() {
            return Err(io::Error::other("test write bound exceeded"));
        }
        self.written.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn success() -> Vec<Vec<u8>> {
    vec![
        result(1, 0x61, 0),
        entry(
            2,
            "uid=directory-alias,ou=people,dc=test",
            &[("uid", &["DirectoryAlias"])],
        ),
        result(2, 0x65, 0),
        result(3, 0x61, 0),
        result(4, 0x61, 0),
        entry(
            5,
            "cn=Engineering,ou=groups,dc=test",
            &[("cn", &["Engineering"])],
        ),
        result(5, 0x65, 0),
    ]
}

#[test]
fn user_template_encodes_untrusted_username_as_one_value() {
    let username = "*)(uid=*)(|(objectClass=*))";
    let encoded = compile_filter(DEFAULT_USER_FILTER, context(username, "", false)).unwrap();
    let mut cursor = 0;
    let assertion = ber_take(&encoded, &mut cursor, 0xa3).unwrap();
    assert_eq!(cursor, encoded.len());
    let mut inner = 0;
    assert_eq!(ber_take(assertion, &mut inner, 0x04).unwrap(), b"uid");
    assert_eq!(
        ber_take(assertion, &mut inner, 0x04).unwrap(),
        username.as_bytes()
    );
    assert_eq!(inner, assertion.len());
}

#[test]
fn default_groups_and_boolean_presence_filters_are_supported() {
    let group = compile_filter(GROUP_FILTER, context("alice", "uid=alice,dc=test", true)).unwrap();
    assert_eq!(group[0], 0xa1);
    let encoded = compile_filter(
        "(&(objectClass=person)(!(uid=blocked))(|(cn=*)(uid={{.Username}})))",
        context("alice", "", false),
    )
    .unwrap();
    assert_eq!(encoded[0], 0xa0);
    let escaped = compile_filter(r"(uid=alice\2a\28\29\5c\00)", context("", "", false)).unwrap();
    assert!(escaped.windows(10).any(|bytes| bytes == b"alice*()\\\0"));
}

#[test]
fn unsupported_templates_filters_and_extra_syntax_are_rejected() {
    for input in [
        "(uid=a*)",
        "(uid=*a)",
        "(uid=a*b)",
        "(uid>=a)",
        "(uid~=a)",
        "(member:1.2.3:=a)",
        "(uid={{.Password}})",
        "(uid={{.UserDN}})",
        "(uid={{printf .Username}})",
        "({{.Username}}=a)",
        "(uid={{.UserAttr}})",
        "(uid=alice)(uid=bob)",
        "(&)",
        "(|)",
        "(!(uid=a)(uid=b))",
        r"(uid=\xx)",
        "(uid=a",
    ] {
        assert!(
            compile_filter(input, context("alice", "", false)).is_err(),
            "{input}"
        );
    }
    assert!(compile_filter("({{.UserAttr}}=alice)", context("alice", "", true)).is_err());
}

#[test]
fn filter_depth_nodes_wire_and_expansion_have_bounds() {
    let deep = format!(
        "{}(uid=x){}",
        "(!".repeat(MAX_FILTER_DEPTH),
        ")".repeat(MAX_FILTER_DEPTH)
    );
    assert!(compile_filter(&deep, context("a", "", false)).is_err());
    let broad = format!("(|{})", "(uid=x)".repeat(MAX_FILTER_NODES));
    assert!(compile_filter(&broad, context("a", "", false)).is_err());
    let expanded = format!("(uid={})", "{{.Username}}".repeat(5));
    let username = "x".repeat(1024);
    assert!(compile_filter(&expanded, context(&username, "", false)).is_err());
    let wire = format!("(|{})", "(uid={{.Username}})".repeat(17));
    assert!(compile_filter(&wire, context(&username, "", false)).is_err());
    assert!(compile_filter(&"x".repeat(MAX_FILTER_INPUT + 1), context("a", "", false)).is_err());
}

#[test]
fn full_exchange_binds_user_then_manager_and_preserves_directory_case() {
    let mut exchange = Exchange::new(&success());
    let observed = authenticate_exchange(
        &mut exchange,
        &options(),
        "requested-name",
        "synthetic-user-password",
    )
    .unwrap()
    .unwrap();
    assert_eq!(observed.alias, "DirectoryAlias");
    assert_eq!(observed.groups, BTreeSet::from(["Engineering".to_owned()]));
    assert_eq!(
        exchange.requests(),
        vec![(1, 0x60), (2, 0x63), (3, 0x60), (4, 0x60), (5, 0x63)]
    );
    assert_eq!(
        exchange.input.position() as usize,
        exchange.input.get_ref().len()
    );
}

#[test]
fn username_alias_and_empty_user_filter_preserve_requested_values() {
    let mut options = options();
    options.username_as_alias = true;
    options.user_filter = "";
    let observed = authenticate_exchange(
        &mut Exchange::new(&success()),
        &options,
        "RequestedName",
        "synthetic",
    )
    .unwrap()
    .unwrap();
    assert_eq!(observed.alias, "RequestedName");
}

#[test]
fn empty_manager_or_user_credentials_do_not_send_anonymous_bind() {
    for field in 0..4 {
        let mut config = options();
        let mut username = "alice";
        let mut password = "synthetic-user-password";
        match field {
            0 => config.bind_dn = "",
            1 => config.bind_password = "",
            2 => username = "",
            _ => password = "",
        }
        let mut exchange = Exchange::new(&[]);
        assert!(authenticate_exchange(&mut exchange, &config, username, password).is_err());
        assert!(exchange.written.is_empty());
    }
    let mut config = options();
    config.group_filter = "(member:unsupported:={{.UserDN}})";
    let mut exchange = Exchange::new(&[]);
    assert!(authenticate_exchange(&mut exchange, &config, "alice", "synthetic").is_err());
    assert!(exchange.written.is_empty());
}

#[test]
fn zero_or_multiple_users_never_reach_user_bind() {
    for count in [0, 2] {
        let mut responses = vec![result(1, 0x61, 0)];
        for n in 0..count {
            responses.push(entry(
                2,
                &format!("uid=user{n},dc=test"),
                &[("uid", &["alice"])],
            ));
        }
        responses.push(result(2, 0x65, 0));
        let mut exchange = Exchange::new(&responses);
        assert_eq!(
            authenticate_exchange(&mut exchange, &options(), "alice", "synthetic").unwrap(),
            None
        );
        assert_eq!(exchange.requests(), vec![(1, 0x60), (2, 0x63)]);
    }
}

#[test]
fn missing_multivalue_or_duplicate_user_attribute_is_rejected() {
    for attrs in [
        vec![],
        vec![("uid", &["a", "b"][..])],
        vec![("uid", &["a"][..]), ("UID", &["a"][..])],
        vec![("cn", &["a"][..])],
    ] {
        let responses = vec![
            result(1, 0x61, 0),
            entry(2, "uid=alice,dc=test", &attrs),
            result(2, 0x65, 0),
        ];
        let mut exchange = Exchange::new(&responses);
        assert!(authenticate_exchange(&mut exchange, &options(), "alice", "synthetic").is_err());
        assert_eq!(exchange.requests(), vec![(1, 0x60), (2, 0x63)]);
    }
}

#[test]
fn authentication_denial_is_distinct_from_protocol_or_manager_failure() {
    let mut responses = success();
    responses[3] = result(3, 0x61, 49);
    let mut exchange = Exchange::new(&responses);
    assert_eq!(
        authenticate_exchange(&mut exchange, &options(), "alice", "synthetic").unwrap(),
        None
    );
    assert_eq!(exchange.requests().len(), 3);
    for index in [0, 3, 4] {
        let mut responses = success();
        responses[index] = result(
            if index == 0 {
                1
            } else {
                u8::try_from(index).unwrap()
            },
            0x61,
            53,
        );
        assert!(
            authenticate_exchange(
                &mut Exchange::new(&responses),
                &options(),
                "alice",
                "synthetic"
            )
            .is_err()
        );
    }
}

#[test]
fn absent_group_base_or_filter_skips_search_but_rebinds_manager() {
    for empty_base in [true, false] {
        let mut config = options();
        if empty_base {
            config.group_dn = "";
        } else {
            config.group_filter = "";
        }
        let mut exchange = Exchange::new(&success()[..5]);
        let observed = authenticate_exchange(&mut exchange, &config, "alice", "synthetic")
            .unwrap()
            .unwrap();
        assert!(observed.groups.is_empty());
        assert_eq!(
            exchange.requests(),
            vec![(1, 0x60), (2, 0x63), (3, 0x60), (4, 0x60)]
        );
    }
}

#[test]
fn wrong_message_ids_controls_referrals_and_rejected_search_fail_closed() {
    let good = result(2, 0x65, 0);
    let mut cursor = 0;
    let mut body = ber_take(&good, &mut cursor, 0x30).unwrap().to_vec();
    body.extend(ber_value(0xa0, b"").unwrap());
    let controlled = ber_value(0x30, &body).unwrap();
    for response in [
        result(7, 0x65, 0),
        result(2, 0x65, 4),
        message(2, 0x73, b"referral"),
        controlled,
        vec![0x30, 0x80],
        vec![0x30, 0x03, 0x02],
    ] {
        let mut remaining = MAX_RESPONSE_TOTAL;
        assert!(read_search(&mut Cursor::new(response), 2, "uid", 2, &mut remaining).is_err());
    }
    let mut response = result(1, 0x61, 0);
    response.pop();
    let mut remaining = MAX_RESPONSE_TOTAL;
    assert!(read_bind_result(&mut Cursor::new(response), 1, &mut remaining).is_err());
}

#[test]
fn response_entry_value_and_cumulative_byte_limits_are_enforced() {
    let too_many = [
        entry(2, "uid=a,dc=test", &[("uid", &["a"])]),
        entry(2, "uid=b,dc=test", &[("uid", &["b"])]),
        result(2, 0x65, 0),
    ]
    .concat();
    let mut remaining = MAX_RESPONSE_TOTAL;
    assert!(read_search(&mut Cursor::new(too_many), 2, "uid", 1, &mut remaining).is_err());
    let names = ["x"; 33];
    let too_many_values = entry(2, "uid=a,dc=test", &[("uid", &names)]);
    let mut remaining = MAX_RESPONSE_TOTAL;
    assert!(
        read_search(
            &mut Cursor::new(too_many_values),
            2,
            "uid",
            2,
            &mut remaining
        )
        .is_err()
    );
    let mut remaining = 10;
    assert!(read_bind_result(&mut Cursor::new(result(1, 0x61, 0)), 1, &mut remaining).is_err());
    let mut remaining = 18;
    assert_eq!(
        read_bind_result(&mut Cursor::new(result(1, 0x61, 0)), 1, &mut remaining).unwrap(),
        0
    );
    assert!(read_bind_result(&mut Cursor::new(result(4, 0x61, 0)), 4, &mut remaining).is_err());
}

#[test]
fn bind_message_id_changes_in_place_in_zeroizing_request() {
    let password = "p".repeat(1024);
    let request: Zeroizing<Vec<u8>> = bind_request(4, "cn=manager,dc=test", &password).unwrap();
    let mut outer = 0;
    let body = ber_take(&request, &mut outer, 0x30).unwrap();
    let mut inner = 0;
    assert_eq!(ber_take(body, &mut inner, 0x02).unwrap(), &[4]);
    let bind = ber_take(body, &mut inner, 0x60).unwrap();
    let mut part = 0;
    assert_eq!(ber_take(bind, &mut part, 0x02).unwrap(), &[3]);
    assert_eq!(
        ber_take(bind, &mut part, 0x04).unwrap(),
        b"cn=manager,dc=test"
    );
    assert_eq!(
        ber_take(bind, &mut part, 0x80).unwrap(),
        password.as_bytes()
    );
}

#[test]
fn unenrolled_origin_cannot_enable_native_ldap_network_access() {
    let outbound = Outbound::default();
    assert!(
        outbound
            .ldap_authenticate_native(
                "ldaps://untrusted.invalid:636",
                &options(),
                None,
                "alice",
                "synthetic"
            )
            .is_err()
    );
    assert!(
        outbound
            .ldap_authenticate_native(
                "ldap://127.0.0.1:389",
                &options(),
                None,
                "alice",
                "synthetic"
            )
            .is_err()
    );
}

#[test]
fn username_alias_does_not_require_directory_alias_attribute() {
    let mut config = options();
    config.username_as_alias = true;
    config.user_filter = "(cn={{.Username}})";
    for attrs in [vec![], vec![("uid", &["first", "second"][..])]] {
        let mut responses = success();
        responses[1] = entry(2, "uid=alice,dc=test", &attrs);
        let mut exchange = Exchange::new(&responses);
        let observed = authenticate_exchange(&mut exchange, &config, "RequestedName", "synthetic")
            .unwrap()
            .unwrap();
        assert_eq!(observed.alias, "RequestedName");
        assert_eq!(exchange.requests().len(), 5);
    }
    // Username aliases do not make ambiguous directory identities acceptable.
    let mut responses = success();
    responses.insert(2, entry(2, "uid=other,dc=test", &[]));
    let mut exchange = Exchange::new(&responses);
    assert_eq!(
        authenticate_exchange(&mut exchange, &config, "RequestedName", "synthetic").unwrap(),
        None
    );
    assert_eq!(exchange.requests(), vec![(1, 0x60), (2, 0x63)]);
}

#[test]
fn configuration_validation_rejects_unsupported_filters_without_credentials_or_io() {
    let mut config = options();
    assert!(config.validate_configuration().is_ok());
    config.user_filter = "";
    assert!(config.validate_configuration().is_ok());
    config.group_filter = "";
    config.group_dn = "";
    assert!(config.validate_configuration().is_ok());
    for filter in [
        "(uid=a*)",
        "(uid:unsupported:=a)",
        "(uid={{.Unknown}})",
        "(&(uid=a)",
    ] {
        config.user_filter = filter;
        assert!(config.validate_configuration().is_err());
    }
    config.user_filter = DEFAULT_USER_FILTER;
    config.bind_password = "";
    assert!(config.validate_configuration().is_err());
}

#[test]
fn legacy_transport_remains_enrollment_only_and_explicit_transport_never_falls_back() {
    let outbound = Outbound::default();
    assert_eq!(
        outbound.ldap_authenticate_native(
            "ldaps://untrusted.invalid:636",
            &options(),
            None,
            "alice",
            "synthetic"
        ),
        Err("outbound origin is not host-enrolled")
    );
    let transport = LdapTransportConfig {
        certificate: "broken CA".into(),
        ..Default::default()
    };
    assert_eq!(
        outbound.ldap_authenticate_native(
            "ldaps://untrusted.invalid",
            &options(),
            Some(&transport),
            "alice",
            "synthetic"
        ),
        Err("invalid LDAP CA PEM contents")
    );
}
