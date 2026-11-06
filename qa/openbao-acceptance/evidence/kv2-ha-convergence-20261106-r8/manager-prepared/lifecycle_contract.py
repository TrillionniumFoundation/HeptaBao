"""Interfaces for a future normal, manager-owned private KV2 instance.

DRAFT ONLY: this module performs no I/O, starts no service and grants no admission.
A concrete adapter must consume exact independent generation, binary, TLS and
manager receipts. Dataclass construction and Protocol conformance are not proof.
Private locators and content commitments must never enter public serialization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

CONTRACT_SCHEMA = "heptabao.normal-kv2-manager-lifecycle.v1"


@dataclass(frozen=True)
class Deadline:
    """One phase's original monotonic clock; an adapter cannot renew it."""
    original_entry: float
    work_end: float
    total_end: float
    phase: str


@dataclass(frozen=True, repr=False)
class EndpointHandle:
    origin: str
    ca_file: Path
    root_token_file: Path
    leaf_sha256: str
    data_dir: Path
    label: str
    manager_domain: str


@dataclass(frozen=True, repr=False)
class ManagerIdentity:
    domain: str
    label: str
    plist_file_identity: Mapping[str, Any]
    pid: int
    uid: int
    pgid: int
    session: int
    executable_identity: Mapping[str, Any]
    data_directory_identity: Mapping[str, Any]
    process_birth_observation: Mapping[str, Any]
    # Darwin ps birth seconds are diagnostic, never a signalling authority.
    birth_is_sole_authority: bool = False
    observation_private_ref: Path | None = None


@dataclass(frozen=True, repr=False)
class CommandChildReceipt:
    """Only a child actually spawned and waited by our bounded controller."""
    operation: str
    pid: int
    pgid: int
    session: int
    returncode: int
    original_wait_count: int
    remaining_live_members: Sequence[int]
    custody_gaps: Sequence[str]
    original_receipt_private_ref: Path


@dataclass(frozen=True, repr=False)
class ManagerRetirement:
    original: ManagerIdentity
    stop_operation: str
    command_children: Sequence[CommandChildReceipt]
    label_absence_observation: Mapping[str, Any]
    original_process_retirement_observation: Mapping[str, Any]
    # launchd owns/reaps the server; our controller cannot assert waitpid=1.
    server_waitpid_performed_by_this_controller: bool
    writer_release_observation: Mapping[str, Any]
    # Exclusive fence is present only when a later seed/storage operation
    # actually acquires it; a manager stop alone must leave this field None.
    exclusive_writer_fence_observation: Mapping[str, Any] | None
    outcome_unknown: bool
    original_receipt_private_ref: Path


@dataclass(frozen=True, repr=False)
class RestartObservation:
    before: ManagerIdentity
    retirement: ManagerRetirement
    after: ManagerIdentity
    start_command_children: Sequence[CommandChildReceipt]
    tls_observation: Mapping[str, Any]
    sealed_before_unseal_observation: Mapping[str, Any]
    one_share_still_sealed_observation: Mapping[str, Any]
    two_shares_unsealed_observation: Mapping[str, Any]
    seal_identity_equal: bool
    original_receipt_private_ref: Path


@dataclass(frozen=True, repr=False)
class PreActivationSeedBinding:
    directory: Path
    export_receipt_file: Path
    export_receipt_sha256: str
    source_directory_identity: Mapping[str, Any]
    artifacts_private: Sequence[Mapping[str, Any]]
    actual_shares: int
    actual_threshold: int
    ack_durably_completed: bool
    v6_not_yet_activated: bool
    no_business_versions_written: bool
    export_retirement: ManagerRetirement
    # The seed is four-file bootstrap only, never current written history.
    current_history_backup: bool = False


@dataclass(frozen=True, repr=False)
class RestoreTarget:
    endpoint: EndpointHandle
    manager: ManagerIdentity
    fresh_directory_identity: Mapping[str, Any]
    seed_binding_private_ref: Path
    current_history_restored: bool
    original_receipt_private_ref: Path


@dataclass(frozen=True, repr=False)
class PersistentHandoff:
    manager: ManagerIdentity
    endpoint: EndpointHandle
    state_observation: Mapping[str, Any]
    long_lived_manager_ownership_observation: Mapping[str, Any]
    command_children: Sequence[CommandChildReceipt]
    operator_custody_private_ref: Path
    service_left_running: bool
    original_receipt_private_ref: Path


class Lifecycle(Protocol):
    """Narrow adapter consumed by the separate KV2 protocol/backup module.

    Methods use the caller's original Deadline. Each mutation is single-shot;
    unknown results return/raise a retained unknown outcome for read-only
    reconciliation. They must not silently retry bootstraps, init, imports,
    restores, or extend the caller's phase. No method receives share values.
    Only the concrete private custody adapter obtains two approved shares.
    """
    def source_handle(self) -> EndpointHandle: ...

    def cold_restart(self, *, deadline: Deadline) -> RestartObservation: ...

    def fresh_restore_target(
        self, *, seed: PreActivationSeedBinding, deadline: Deadline
    ) -> RestoreTarget: ...

    def cold_restart_restore(
        self, target: RestoreTarget, *, deadline: Deadline
    ) -> RestartObservation: ...

    def retire_restore_target(
        self, target: RestoreTarget, *, deadline: Deadline
    ) -> ManagerRetirement: ...

    def preserve_source_handoff(
        self, *, deadline: Deadline
    ) -> PersistentHandoff: ...
