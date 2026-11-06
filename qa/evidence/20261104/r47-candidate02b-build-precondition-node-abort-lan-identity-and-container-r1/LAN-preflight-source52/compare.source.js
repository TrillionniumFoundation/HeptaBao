function compareFinalLanRoutes(pairs, approvedModels) {
  const roles = ["mac", "rog", "pocket4"];
  const expected = {
    mac: ["Darwin", "arm64", "192.168.0.8"],
    rog: ["Linux", "x86_64", "192.168.0.10"],
    pocket4: ["Linux", "x86_64", "192.168.0.9"]
  };
  const must = (ok, code) => { if (!ok) throw new Error(code); };
  const canon = value => JSON.stringify(value, (_, x) =>
    x && typeof x === "object" && !Array.isArray(x)
      ? Object.fromEntries(Object.keys(x).sort().map(k => [k, x[k]])) : x);
  const digest = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  must(pairs && Object.keys(pairs).sort().join(",") === roles.slice().sort().join(","), "exact_three_roles");
  const rows = [];
  for (const role of roles) {
    const pair = pairs[role];
    must(pair && Object.keys(pair).sort().join(",") === "native,ssh", "exact_two_routes");
    const a = pair.native, b = pair.ssh;
    for (const [route, r] of Object.entries(pair)) {
      must(r && r.schema === "heptabao.final-lan-endpoint-identity.v1"
        && r.role === role && r.status === "passed" && r.failure === null, "incomplete_probe_" + role + "_" + route);
      must(r.all_probe_resources_closed === true && r.identity_stable_before_after === true
        && Array.isArray(r.signals) && r.signals.length === 0, "closure_or_identity_" + role);
      must(r.filesystem_writes === 0 && r.listen_calls === 0 && r.connect_calls === 0
        && r.probe_process.children_started_by_probe === 0
        && r.machine_or_boot_identifier_raw_emitted === false
        && r.hardware_serial_or_hardware_uuid_read === false, "probe_scope_" + role);
      must(BigInt(r.finished_monotonic_ns) < BigInt(r.absolute_deadline_monotonic_ns)
        && BigInt(r.started_monotonic_ns) < BigInt(r.finished_monotonic_ns)
        && BigInt(r.absolute_deadline_monotonic_ns) - BigInt(r.started_monotonic_ns) === 15000000000n,
        "absolute_clock_" + role);
      const id = r.identity, [os, architecture, ip] = expected[role];
      must(id && id.os === os && id.architecture === architecture && id.declared_lan_ipv4 === ip,
        "declared_endpoint_" + role);
      must(typeof id.model?.name === "string" && id.model.name.length > 0 && id.model.name.length <= 128
        && digest(id.boot_identity?.hmac_sha256), "model_or_boot_" + role);
      if (os === "Linux") must(id.machine_identity?.source === "/etc/machine-id"
        && digest(id.machine_identity.hmac_sha256)
        && id.boot_identity.source === "/proc/sys/kernel/random/boot_id"
        && id.model.source === "/sys/devices/virtual/dmi/id/product_name"
        && id.machine_identity_not_requested_on_darwin === false, "linux_identity_" + role);
      else must(id.machine_identity === null && id.machine_identity_not_requested_on_darwin === true
        && id.model.source === "sysctl:hw.model" && id.boot_identity.source === "sysctl:kern.bootsessionuuid",
        "darwin_identity");
      must(Array.isArray(r.local_ports) && r.local_ports.length === 2
        && r.local_ports.every((x, i) => x.address === ip && x.port === [46230, 46231][i]
          && x.bound === true && x.closed === true && x.listen_called === false
          && x.connect_called === false && x.reservation_retained === false), "fixed_ports_" + role);
    }
    must(canon(a.identity) === canon(b.identity), "native_ssh_identity_mismatch_" + role);
    must(BigInt(b.started_monotonic_ns) >= BigInt(a.finished_monotonic_ns), "ordered_same_boot_observations_" + role);
    rows.push({role, identity: a.identity, routes_equal: true,
      model_label_verified: Array.isArray(approvedModels?.[role])
        && approvedModels[role].includes(a.identity.model.name),
      available_ports_at_observation: [46230, 46231], live_port_reservation: false});
  }
  must(new Set(rows.map(x => x.identity.hostname)).size === 3, "duplicate_hostname");
  must(new Set(rows.map(x => x.identity.boot_identity.hmac_sha256)).size === 3, "duplicate_boot_identity");
  must(rows[1].identity.machine_identity.hmac_sha256 !== rows[2].identity.machine_identity.hmac_sha256,
    "duplicate_linux_machine_identity");
  return {
    schema: "heptabao.final-lan-route-comparison.v1",
    route_identity_binding: true, rows,
    physical_model_labels_verified: rows.every(x => x.model_label_verified),
    final_candidate_binary_qualified: false,
    final_LAN_98_plus_12_qualified: false,
    cryptographic_hardware_attestation: false,
    kernel_reported_model_only: true
  };
}
