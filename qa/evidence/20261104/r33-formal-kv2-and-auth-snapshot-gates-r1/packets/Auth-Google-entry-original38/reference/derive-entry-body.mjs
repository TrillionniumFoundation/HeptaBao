// Pure derivation; this source does not authorize or perform any I/O.
export const FILE={
  "id": "google-declared-entry",
  "path": "/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/index.js",
  "metadataKey": "heptabao-mac-google-declared-entry-metadata-eca1335c-20261105-r1",
  "bodyKey": "heptabao-mac-google-declared-entry-body-eca1335c-20261105-r1"
};
export function deriveEntryBody(value) {
  const need=(ok,code)=>{if(!ok)throw new Error(code);};
  need(value && typeof value==='object' && !Array.isArray(value),'metadata_object');
  need(value.path===FILE.path && typeof value.sha256==='string'
    && /^[0-9a-f]{64}$/.test(value.sha256),'declared_fixed_path_and_current_whole_sha');
  need(Number.isSafeInteger(value.size) && value.size>0 && value.size<=65536,'entry_body_size_bound');
  need(typeof value.version==='string' && /^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(value.version)
    && BigInt(value.version.split(':')[2])===BigInt(value.size),'actual_version_size');
  const meta=value.metadata;
  need(meta && meta.metadata_platform==='darwin' && meta.link_count===1
    && Number.isSafeInteger(meta.uid) && [0,501].includes(meta.uid)
    && Number.isSafeInteger(meta.gid) && meta.gid>=0
    && Number.isSafeInteger(value.mode) && value.mode>=0 && value.mode<=4095
    && value.mode===meta.mode && (value.mode & 0o022)===0,'regular_single_link_public_entry');
  return {request:{idempotency_key:FILE.bodyKey,operation:{tool:'binary_read',arguments:{
    host:'mac',path:FILE.path,expected_version:value.version,offset:0,limit:value.size}}},
    expectedSha256:value.sha256,expectedBytes:value.size,previousBodyBytes:382975,
    newBodyBytes:value.size,cumulativeBodyBytes:382975+value.size};
}
