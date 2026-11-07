import { TRANSPORT, stable, digest, hashText, initialSlot, initialAck, slotKey, reportKey, validatePair } from './transport/bounded-outbox.js';
import { OutboxError } from './transport/private-outbox-store.js';

export { TRANSPORT, stable, digest, hashText, initialSlot, initialAck, slotKey, reportKey, validatePair };
export const PROTOCOL = 'heptabao-authbus-coordinator-v1';
export const SHA = /^[a-f0-9]{64}$/;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export const HOST = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const AGENT = /^[a-z0-9][a-z0-9_-]{0,127}$/;
export const MAX_DOCUMENT = 128 * 1024;
export class CoordinatorError extends OutboxError { constructor(code, options = {}) { super(code, options); this.code = code; } }
export const need = (value, code) => { if (!value) throw new CoordinatorError(code); };
export const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const integer = value => Number.isSafeInteger(value) && value >= 0 && value < 9007199254740000;
export const exact = (value, keys) => object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
export const clone = value => JSON.parse(JSON.stringify(value));
export const equal = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
export const profileId = value => typeof value === 'string' && value.length >= 1 && value.length <= 240 && [...value].every(c => c.codePointAt(0) >= 32);
export function bounded(value, limit = MAX_DOCUMENT, depth = 0) {
  need(depth <= 12, 'coordinator_json_depth_exceeded');
  if (Array.isArray(value)) { need(value.length <= 1024, 'coordinator_json_array_bound'); for (const item of value) bounded(item, limit, depth + 1); }
  else if (object(value)) { const keys = Object.keys(value); need(keys.length <= 256, 'coordinator_json_object_bound'); for (const key of keys) bounded(value[key], limit, depth + 1); }
  else need(value === null || typeof value === 'string' || typeof value === 'boolean' || Number.isSafeInteger(value), 'coordinator_json_value_shape');
  if (depth === 0) need(Buffer.byteLength(JSON.stringify(stable(value))) <= limit, 'coordinator_document_bound');
  return value;
}
export function normalizeTopology(rows) {
  need(Array.isArray(rows) && rows.length >= 1 && rows.length <= 16, 'coordinator_topology_bound');
  const out = rows.map(row => {
    need(exact(row, ['host_id', 'epoch', 'slots', 'agents']) && typeof row.host_id === 'string' && HOST.test(row.host_id)
      && typeof row.epoch === 'string' && UUID.test(row.epoch) && Number.isInteger(row.slots) && row.slots >= 1 && row.slots <= 32
      && Array.isArray(row.agents) && row.agents.length >= 1 && row.agents.length <= 128
      && row.agents.every(a => typeof a === 'string' && AGENT.test(a)) && new Set(row.agents).size === row.agents.length, 'coordinator_topology_entry');
    return { host_id: row.host_id, epoch: row.epoch, slots: row.slots, agents: [...row.agents].sort() };
  }).sort((a,b) => a.host_id < b.host_id ? -1 : a.host_id > b.host_id ? 1 : 0);
  need(new Set(out.map(r => r.host_id)).size === out.length && new Set(out.map(r => r.epoch)).size === out.length, 'coordinator_topology_duplicates');
  return out;
}
export function controlDocument(config) {
  need(typeof config.ownerId === 'string' && UUID.test(config.ownerId)
    && Number.isInteger(config.bootstrapProfileCount) && config.bootstrapProfileCount >= 1 && config.bootstrapProfileCount <= 64, 'coordinator_owner_bootstrap_binding');
  return { schema: TRANSPORT + '.control', ownerId: config.ownerId, retainedSlotVersions: 2,
    bootstrapProfileCount: config.bootstrapProfileCount, topology: normalizeTopology(config.topology) };
}
export const sourceFor = (row, ownerId) => ({ hostId: row.host_id, epoch: row.epoch, slots: row.slots, agents: row.agents, ownerId });
export const credentialIdentity = value => digest(Object.fromEntries(['provider','type','email','accountId','projectId'].map(k => [k, value[k] ?? null])));
export function validateCredential(value) {
  need(object(value) && typeof value.provider === 'string' && value.provider.length >= 1 && value.provider.length <= 100, 'credential_provider_shape');
  need(['oauth','token','api_key'].includes(value.type), 'credential_type_shape');
  const keys = value.type === 'oauth' ? ['access','refresh'] : value.type === 'api_key' ? ['key'] : ['token'];
  need(keys.every(key => typeof value[key] === 'string' && value[key].length >= 8), 'credential_secret_shape');
  need(['keyRef','tokenRef','accessRef','refreshRef'].every(key => !Object.hasOwn(value, key)), 'unresolved_secret_reference');
  if (value.type === 'oauth') need(Number.isSafeInteger(value.expires) && value.expires > 0, 'oauth_expiry_shape');
  bounded(value); return value;
}
export function parseEvent(host, eventId, value) {
  need(typeof host === 'string' && HOST.test(host) && typeof eventId === 'string' && UUID.test(eventId)
    && object(value) && value.sourceHost === host && value.eventId === eventId, 'event_source_identity');
  bounded(value);
  if (value.schemaVersion === 2 && value.kind === 'health-observation') {
    need(!Object.hasOwn(value, 'credential'), 'health_event_credential_refused');
    return { kind: 'health', sha256: digest(value) };
  }
  if (value.schemaVersion === 2 && value.kind === 'agent-report') {
    need(!Object.hasOwn(value, 'credential') && Array.isArray(value.profiles) && value.profiles.length <= 64, 'agent_report_shape');
    return { kind: 'report', sha256: digest(value) };
  }
  need(value.schemaVersion === 1 && ['new-profile','manual-login','leader-refresh'].includes(value.reason), 'unsupported_credential_event');
  need(profileId(value.profileId), 'event_profile_id_shape'); validateCredential(value.credential);
  need(value.digest === digest(value.credential) && value.identity === credentialIdentity(value.credential), 'event_credential_digest_mismatch');
  return { kind: 'credential', sha256: digest(value) };
}
export function validateGrant(grant, hosts) {
  need(exact(grant, ['authorizationId','profileId','sourceHost','provider','identityDigest','expectedCurrentDigest','nextDigest'])
    && typeof grant.authorizationId === 'string' && UUID.test(grant.authorizationId), 'operator_authorization_shape');
  need(profileId(grant.profileId) && hosts.includes(grant.sourceHost) && typeof grant.provider === 'string'
    && grant.provider.length >= 1 && grant.provider.length <= 100, 'operator_authorization_source_scope');
  need(typeof grant.identityDigest === 'string' && SHA.test(grant.identityDigest) && typeof grant.nextDigest === 'string' && SHA.test(grant.nextDigest)
    && (grant.expectedCurrentDigest === null || typeof grant.expectedCurrentDigest === 'string' && SHA.test(grant.expectedCurrentDigest))
    && grant.nextDigest !== grant.expectedCurrentDigest, 'operator_authorization_digest_shape');
  return grant;
}
export function validateManifest(value, ownerId, hosts) {
  need(object(value) && value.schemaVersion === 1 && integer(value.generation) && Array.isArray(value.profiles) && value.profiles.length <= 64, 'manifest_shape');
  const control = value.coordinator;
  need(object(control) && control.protocol === PROTOCOL && control.ownerId === ownerId && Array.isArray(control.authorizations) && control.authorizations.length <= 32, 'manifest_coordinator_binding');
  const ids = [];
  for (const entry of value.profiles) {
    need(object(entry) && profileId(entry.profileId) && typeof entry.key === 'string' && /^sha256-[a-f0-9]{64}$/.test(entry.key)
      && typeof entry.digest === 'string' && SHA.test(entry.digest) && !Object.hasOwn(entry, 'credential'), 'manifest_profile_shape');
    ids.push(entry.profileId);
  }
  need(new Set(ids).size === ids.length, 'manifest_duplicate_profile');
  for (const grant of control.authorizations) validateGrant(grant, hosts);
  need(new Set(control.authorizations.map(g => g.authorizationId)).size === control.authorizations.length
    && new Set(control.authorizations.map(g => g.profileId)).size === control.authorizations.length, 'manifest_duplicate_authorization');
  bounded(value); return value;
}
export const receiptKey = (host, id) => 'coordinator-receipts/' + hashText(host + '\0' + id);
export function expectedProfile(event) {
  return { schemaVersion:1, profileId:event.profileId, credential:event.credential, digest:event.digest, identity:event.identity };
}
export function validateReceipt(receipt, ownerId, event, parsed) {
  need(object(receipt) && receipt.ownerId === ownerId && receipt.sourceHost === event.sourceHost
    && receipt.eventId === event.eventId && receipt.eventDigest === parsed.sha256, 'canonical_receipt_event_binding');
  if (parsed.kind === 'credential') {
    need(receipt.schema === PROTOCOL + '.receipt' && receipt.status === 'committed'
      && receipt.profileIdSha256 === hashText(event.profileId) && receipt.credentialDigest === event.digest
      && receipt.profileKey === 'sha256-' + digest(expectedProfile(event)) && typeof receipt.authorizationId === 'string' && UUID.test(receipt.authorizationId)
      && integer(receipt.manifestVersion) && receipt.manifestVersion > 0, 'canonical_credential_receipt_binding');
  } else need(parsed.kind === 'health' && receipt.schema === PROTOCOL + '.health-receipt'
    && receipt.status === 'observed_health_no_scheduler_action', 'canonical_health_receipt_binding');
  bounded(receipt); return receipt;
}
export function credentialTransition(snapshot, event, ownerId, hosts) {
  const parsed = parseEvent(event.sourceHost, event.eventId, event);
  need(parsed.kind === 'credential', 'credential_transition_event_kind');
  const manifest = clone(validateManifest(snapshot.data, ownerId, hosts));
  const grant = manifest.coordinator.authorizations.find(g => g.profileId === event.profileId);
  need(grant && grant.sourceHost === event.sourceHost && grant.provider === event.credential.provider
    && grant.identityDigest === event.identity && grant.nextDigest === event.digest, 'credential_transition_not_authorized');
  const current = manifest.profiles.find(p => p.profileId === event.profileId);
  need((current?.digest ?? null) === grant.expectedCurrentDigest, 'authorized_transition_source_changed');
  const profile = expectedProfile(event), key = 'sha256-' + digest(profile);
  const receipt = { schema:PROTOCOL+'.receipt', ownerId, status:'committed', sourceHost:event.sourceHost,
    eventId:event.eventId, eventDigest:parsed.sha256, profileIdSha256:hashText(event.profileId), credentialDigest:event.digest,
    profileKey:key, authorizationId:grant.authorizationId, manifestVersion:snapshot.version+1 };
  const entry = { profileId:event.profileId, key, digest:event.digest, identity:event.identity,
    provider:event.credential.provider, type:event.credential.type,
    sourceEvent:Object.fromEntries(['sourceHost','eventId','eventDigest','authorizationId'].map(k => [k,receipt[k]])) };
  if (Object.hasOwn(event.credential,'expires')) entry.expires = event.credential.expires;
  manifest.profiles = [...manifest.profiles.filter(p => p.profileId !== event.profileId), entry]
    .sort((a,b) => a.profileId < b.profileId ? -1 : a.profileId > b.profileId ? 1 : 0);
  manifest.generation += 1;
  manifest.coordinator.authorizations = manifest.coordinator.authorizations.filter(g => g !== grant);
  manifest.coordinator.lastReceipt = receipt;
  validateManifest(manifest, ownerId, hosts);
  return { profile, profileKey:'profiles/'+key, manifest, receipt, receiptKey:receiptKey(event.sourceHost,event.eventId), parsed };
}
export function acknowledgement(source, index, slot, receipt) {
  return { schema:TRANSPORT+'.ack', sourceHost:source.hostId, epoch:source.epoch, slot:index,
    sequence:slot.data.sequence, slotVersion:slot.version, slotDocumentDigest:digest(slot.data),
    eventId:slot.data.eventId, eventDigest:slot.data.eventDigest, status:receipt.status,
    receiptDigest:digest(receipt), receipt };
}
export const reportDocument = (source, agent) => ({ schema:TRANSPORT+'.report', sourceHost:source.hostId,
  epoch:source.epoch, agentId:agent, sequence:0, event:null });
