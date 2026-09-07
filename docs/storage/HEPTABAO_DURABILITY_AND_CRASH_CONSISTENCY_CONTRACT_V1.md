# HeptaBao Durability 与 Crash-Consistency Contract V1

## 1. 术语

- **accepted**：接口接收请求，不代表 durable；
- **persisted**：bytes 已提交到 profile 声明的持久层接口；
- **published**：新的 generation 成为唯一 current state；
- **committed**：满足 profile 的 quorum/transaction/fsync 条件且可在 crash 后恢复；
- **applied**：deterministic state machine 已应用 committed command；
- **acknowledged**：客户端或 callback 已收到成功。

必须满足 `committed HB acknowledged`。内存可见 candidate state 必须在 `published` 后更新。

## 2. 文件型 generation protocol

推荐布局：

```text
generations/<N>/log
                    /state
                    /snapshot
                    /membership
                    /manifest
CURRENT.tmp → fsync → atomic replace CURRENT → parent fsync
```

`manifest` 包含 format version、generation、component length/digest、previous generation、cluster ID、last log、applied index 和 membership epoch。恢复只接受 CURRENT 指向且所有 component 完整匹配的 generation；可回退到明确 previous generation，但不得静默初始化为空。

单一 bundle 文件可以替代多文件 generation，但同样必须 versioned、bounded、checksummed/authenticated、atomic replace 并 parent sync。

## 3. 原子写要求

1. 创建同目录唯一 temp file；
2. write-all，拒绝 partial success；
3. flush + file sync；
4. atomic replace；
5. parent directory sync（平台支持时）；
6. 重新读取 header/generation/digest 可选验证；
7. 更新内存 authoritative state；
8. 才能 callback/ack。

Windows/其他平台如不能证明 replace + directory durability，profile 必须明确降级为 `UNQUALIFIED`，并提供 crash recovery journal/manifest；不得把 no-op parent sync 写成跨平台证明。

## 4. 必测故障

- short/partial/torn write；
- lost/unordered fsync；
- disk full、quota、read-only、permission change；
- I/O delay/hang/cancel；
- temp/previous/current file crash points；
- corruption、truncation、bit flip、component swap；
- process kill、host reboot、VM power cut；
- snapshot build/install 与 concurrent apply；
- schema upgrade/downgrade interruption；
- clock rollback/forward 与 monotonic discontinuity；
- multi-process node restart 与 per-node directory isolation。

程序主动 sleep 或主动 truncate 只能叫 logical fault simulation，不能替代 kernel/filesystem power-cut evidence。

## 5. RPO/RTO

生产 committed-write 目标为 RPO=0。RTO 必须按 profile/规模测量。任何无法证明的 backend/platform 组合保持 unsupported。恢复过程不能调用外部 effect，也不能在 integrity failure 时默认为空数据库。

## 6. Raft 特定要求

vote、committed index、log append/truncate/purge、state apply、snapshot 与 membership 都有独立 crash point。`IOFlushed` 只能在所声明 durable point 后完成；state-machine responder 只能在 state generation durable publish 后发送。snapshot install 不允许 state/snapshot 交叉 generation。

## 7. Initialized-store authoritative generation loss

A storage directory has two distinct states: never initialized, and initialized. The
implementation MUST persist a versioned initialization marker only after the first
authoritative generation has been durably published. The marker binds its domain and
expected authoritative filename. On every later open:

1. interrupted replacement recovery is attempted for both marker and generation before classification;
2. a valid marker plus a missing authoritative generation is corruption and fails closed;
3. a corrupt, unsupported, wrong-domain or wrong-filename marker fails closed;
4. a non-regular authoritative path is corruption, not an empty store;
5. a present legacy authoritative generation without a marker may be adopted only after full envelope, schema and invariant validation, followed by durable marker publication;
6. neither a deleted log generation nor a deleted state/snapshot bundle may be interpreted as a fresh empty store;
7. tests cover fresh initialization, legacy adoption, missing-generation rejection, marker corruption, domain/file drift and interrupted marker replacement.

The in-directory marker cannot prove that an attacker or storage failure deleted the entire
directory including both marker and generation. Production qualification therefore requires
a separately persisted rollback anchor or signed external inventory. This repository-level
guard does not claim storage-controller cache persistence, kernel power-cut safety or
filesystem-specific crash consistency; those remain external laboratory requirements.

## 8. Explicit create/reopen/adopt lifecycle and rollback-safe replacement

A durable domain exposes three separate caller-selected operations:

1. `create-new` is permitted only for a real, empty directory and durably publishes the
   first authoritative generation before a versioned, domain-bound initialization marker;
2. `reopen-existing` requires a valid marker and a valid authoritative generation and never
   creates directories, adopts legacy data, or initializes defaults;
3. `adopt-legacy` validates the complete legacy envelope, schema and domain invariants before
   publishing the initialization marker, and is never invoked implicitly by the reopen path.

Interrupted replacement and rollback handling obeys the following rules:

- a missing current file plus exactly one regular `.previous` candidate may recover it;
- multiple previous candidates are ambiguous and fail closed;
- a present current generation is fully validated before one stale previous file is retired;
- a corrupt current generation never falls back silently to an older generation;
- unresolved marker temporary artifacts block legacy adoption;
- symlinked roots, markers, authoritative generations and replacement candidates are rejected;
- missing initialized generations and deleted initialized directories fail closed.

The implementation and validation suites must bind the lifecycle routing at the cluster call
site: bootstrap uses `CreateNew`, restart uses `ReopenExisting`, and tests that copy durable
state for recovery or corruption checks use `open_existing`. Repository-level lifecycle
proof does not establish kernel power-cut, storage-controller cache, filesystem-specific
crash consistency, independent reproduction, qualification, candidate selection or authority.
