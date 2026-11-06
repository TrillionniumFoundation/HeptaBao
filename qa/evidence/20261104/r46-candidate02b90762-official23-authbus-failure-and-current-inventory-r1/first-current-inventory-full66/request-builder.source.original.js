"use strict";
/* Pure request-data builder. No tools, filesystem, process, timer or network calls.
   Returning a proposal is not Runtime authorization. */
function buildConsumerBackupInventoryProposal() {
  const exclusions = [
    "**/.git/**", "**/.ssh/**", "**/.gnupg/**", "**/.cache/**",
    "**/node_modules/**", "**/target/**", "**/target-*/**",
    "**/*token*", "**/*credential*", "**/*capsule*",
    "**/*.key", "**/*.pem",
    "heptabao-same-root-publication-normal-20261105-r1/**"
  ];
  const nameSearch = query => ({
    host: "x230", root: "/home/qian", kind: "files",
    query, query_mode: "regex", ignore_case: true,
    include_hidden: true, early_termination: false, context_lines: 0,
    exclude_patterns: exclusions.slice(),
    max_entries: 4096, max_results: 128, max_bytes: 1048576,
    timeout_seconds: 15
  });
  return {
    schema: "heptabao.consumer-backup.inventory-request-proposal.v1",
    runtime_authorized: false,
    replays_or_mutations_authorized: false,
    requests: [
      {
        role: "configured-host-alias-discovery",
        tool: "mcp__codex_apps__heptaruntime_mac_controller_host_list",
        arguments: {}
      },
      {
        role: "x230-first-process-page",
        tool: "mcp__codex_apps__heptaruntime_mac_controller_host_processes",
        arguments: { host: "x230", after_pid: 0, limit: 128 }
      },
      {
        role: "x230-consumer-name-discovery",
        tool: "mcp__codex_apps__heptaruntime_mac_controller_search_start",
        arguments: nameSearch("(heptabao|openbao|vault|(^|[._-])bao([._-]|$))")
      },
      {
        role: "x230-backup-name-discovery",
        tool: "mcp__codex_apps__heptaruntime_mac_controller_search_start",
        arguments: nameSearch("(backup|snapshot|[.]snap([.]|$)|[.]bak$)")
      }
    ],
    pocket4: {
      previously_observed_ssh_alias: "pocket4-ts",
      runtime_host_alias: null,
      exact_native_requests: [],
      binding_required: "An actual configured-host DTO plus an explicit Pocket4 identity mapping; never infer a Native alias from the SSH string."
    },
    continuation: {
      process_pages_per_host_maximum: 4,
      process_records_per_page: 128,
      process_next_after_pid: "Only from the preceding actual returned PID page; exact successor data must be recorded before submission.",
      search_results_tool: "mcp__codex_apps__heptaruntime_mac_controller_search_results",
      search_id: null,
      search_result_limit: 32,
      terminal_result_pages_per_search_maximum: 4,
      progressive_observations_per_search_maximum: 4,
      serial_one_native_call_and_owned_future: true,
      no_search_start_retry_on_missing_ack: true,
      no_complete_inventory_claim_from_process_pagination: true
    }
  };
}
