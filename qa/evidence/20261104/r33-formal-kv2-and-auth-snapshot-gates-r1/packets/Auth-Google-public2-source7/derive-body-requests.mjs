// Pure request derivation only. No I/O, import, SDK or execution admission.
export const FILES = [
  {
    "id": "google-manifest",
    "path": "/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/openclaw.plugin.json",
    "sha256": "518e8e071c1e5720c9fe621ac84c8b550df93af14dac0d96d788d73917835301",
    "metadataKey": "heptabao-mac-google-manifest-metadata-518e8e07-20261105-r1",
    "bodyKey": "heptabao-mac-google-manifest-body-518e8e07-20261105-r1"
  },
  {
    "id": "google-package",
    "path": "/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/package.json",
    "sha256": "398f73305017a1d3813610825814c6e1dd93b683da088cb6df068a31c639fcc3",
    "metadataKey": "heptabao-mac-google-package-metadata-398f7330-20261105-r1",
    "bodyKey": "heptabao-mac-google-package-body-398f7330-20261105-r1"
  }
];
export function deriveBodyRequests(originalMetadataById) {
  const fail = code => { throw new Error(code); };
  const need = (ok, code) => { if (!ok) fail(code); };
  need(originalMetadataById && typeof originalMetadataById === 'object'
    && !Array.isArray(originalMetadataById), 'metadata_map');
  const requests = []; let total = 0;
  for (const item of FILES) {
    const value = originalMetadataById[item.id];
    need(value && typeof value === 'object' && !Array.isArray(value), 'metadata_object');
    need(value.path === item.path && value.sha256 === item.sha256, 'fixed_path_and_historical_sha');
    need(Number.isSafeInteger(value.size) && value.size > 0 && value.size <= 65536, 'per_file_body_bound');
    need(typeof value.version === 'string' && /^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(value.version),
      'opaque_version_shape');
    const version = value.version.split(':');
    need(BigInt(version[2]) === BigInt(value.size), 'version_size_binding');
    const meta = value.metadata;
    need(meta && meta.metadata_platform === 'darwin' && meta.link_count === 1
      && Number.isSafeInteger(meta.uid) && [0, 501].includes(meta.uid)
      && Number.isSafeInteger(meta.gid) && meta.gid >= 0
      && Number.isSafeInteger(value.mode) && value.mode >= 0 && value.mode <= 4095
      && value.mode === meta.mode && (value.mode & 0o022) === 0, 'regular_single_link_public_file');
    // Regular/non-symlink is the purpose-built file_info API guarantee.
    // This helper does not infer type from path, simulate file_info or authorize execution.
    total += value.size;
    need(total <= 131072, 'new_body_total_bound');
    requests.push({idempotency_key:item.bodyKey, operation:{tool:'binary_read',arguments:{
      host:'mac',path:item.path,expected_version:value.version,offset:0,limit:value.size}}});
  }
  return {requests,newBodyBytes:total,newBodyChunks:2,previousBodyBytes:353689,
    cumulativeBodyBytes:353689+total};
}
