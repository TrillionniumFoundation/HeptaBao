#!/usr/bin/env node
/** Reproducer, not an acceptance test. No provider calls or real credentials. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { AdmissionAuthority, digest } from "../authbus-admission-clock-r3/authbus_admission_authority_candidate.mjs";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "authbus-cold-window-"));
fs.chmodSync(directory, 0o700);
try {
  const scope = { hostId: "synthetic-cold-host", agentId: "main", provider: "google", agentDir: path.join(directory, "agent") };
  const credential = { type: "api_key", provider: "google", key: "synthetic-cold-key" };
  const grant = { epoch: 11, status: "ASSIGNED", mode: "enforce", model: "synthetic-model", profileId: "google:synthetic",
    digest: digest(credential), expiresAt: 11000, leaseId: "synthetic-cold-lease" };
  const warmClock = { wall: 1000, mono: 0 };
  const warm = new AdmissionAuthority({ directory, scope, wallNow: () => warmClock.wall, monotonicNow: () => warmClock.mono });
  await warm.apply(grant, { updateStore: () => true, verifyStore: () => true });
  Object.assign(warmClock, { wall: 9000, mono: 8000 });
  const warmAllowed = warm.inspect().allowed;
  const persistedBeforeRestart = JSON.parse(fs.readFileSync(warm.filename));
  // A fresh instance has the same reset monotonic origin as performance.now()
  // after process restart. The original process cannot publish another floor.
  const coldClock = { wall: 6000, mono: 0 };
  const cold = new AdmissionAuthority({ directory, scope, wallNow: () => coldClock.wall, monotonicNow: () => coldClock.mono });
  const closedBeforeControl = !cold.inspect().allowed;
  await cold.reconcileCommitted(grant, { verifyStore: () => true });
  const allowedAfterSameGrant = cold.inspect().allowed;
  console.log(JSON.stringify({ schema: "authbus-cold-reconcile-window-audit-v1", syntheticCredentials: true,
    fakeClocks: true, realDurableFilesystem: true, actualColdProcess: false, actualTrustedControlRead: false,
    authoritySha256: crypto.createHash("sha256").update(fs.readFileSync(new URL("../authbus-admission-clock-r3/authbus_admission_authority_candidate.mjs", import.meta.url))).digest("hex"),
    warmAllowed, lastWarmObservedWall: warmClock.wall, persistedObservationFloor: persistedBeforeRestart.observedAt,
    coldWall: coldClock.wall, closedBeforeControl, allowedAfterSameGrant,
    coldReplayWindowDemonstrated: warmAllowed && closedBeforeControl && allowedAfterSameGrant && coldClock.wall < warmClock.wall,
    productionBootstrapQualified: false, productionMutation: false }));
} finally { fs.rmSync(directory, { recursive: true, force: true }); }
