/* Pure SOURCE binding only; never calls a tool or imports/executes Python. */
function deriveOwnedLogHelp({templateRaw, expectedTemplate, metadataRequestRaw,
    expectedMetadataRequest, ackNativeRaw, statusNativeRaw, infoNativeRaw}) {
  const need=(value,code)=>{if(!value)throw Error(code);};
  need(gitBlobMeta(templateRaw).blob===expectedTemplate.blob
    && gitBlobMeta(templateRaw).sha256===expectedTemplate.sha256,'exact_template');
  need(gitBlobMeta(metadataRequestRaw).blob===expectedMetadataRequest.blob
    && gitBlobMeta(metadataRequestRaw).sha256===expectedMetadataRequest.sha256,'exact_metadata_request');
  const request=JSON.parse(metadataRequestRaw),ack=JSON.parse(ackNativeRaw),
    status=JSON.parse(statusNativeRaw),info=JSON.parse(infoNativeRaw);
  need(request.operation.tool==='file_info' && request.operation.arguments.host==='mac'
    && request.operation.arguments.path==='/usr/bin/log'
    && Object.keys(request.operation.arguments).length===2,'fixed_info_arguments');
  need(typeof ack.operation_id==='string' && /^[a-f0-9]{64}$/.test(ack.operation_id)
    && ack.tool_name==='file_info' && ack.automatic_retry===false
    && ack.idempotency_binding_retained===true,'original_info_ack');
  need(status.operation_id===ack.operation_id && status.tool_name==='file_info'
    && status.async_state==='completed' && status.result_state==='stored_observed'
    && status.owned_future_active===false && status.payload_available===true,'original_info_closed');
  need(info.path==='/usr/bin/log' && Number.isSafeInteger(info.size)
    && info.size>0 && info.size<=8388608
    && typeof info.sha256==='string' && /^[a-f0-9]{64}$/.test(info.sha256),'observed_log_size_sha');
  const m=info.metadata;
  need(m && m.metadata_platform==='darwin' && m.uid===0 && Number.isSafeInteger(m.gid)
    && m.gid>=0 && Number.isSafeInteger(info.mode) && info.mode>=0 && info.mode<=4095
    && m.mode===info.mode && !(info.mode&0o7022) && !!(info.mode&0o111)
    && Number.isSafeInteger(m.link_count) && m.link_count>=1,'observed_root_log_mode_owner_nlink');
  need(typeof info.version==='string' && /^[0-9]{1,24}(?::[0-9]{1,24}){4}$/.test(info.version),'exact_version_shape');
  const v=info.version.split(':');
  need(BigInt(v[2])===BigInt(info.size),'version_size_match');
  const metadataOriginal=gitBlobMeta(infoNativeRaw);
  need(metadataOriginal.bytes>0 && metadataOriginal.bytes<=8192,'bounded_metadata_original');
  const binding={path:info.path,version:info.version,size:info.size,sha256:info.sha256,
    identity:[v[0],v[1],String(m.uid),String(m.gid),String(0o100000|info.mode),
      String(m.link_count),String(info.size),v[3],v[4]],metadataOriginal};
  const old='BINDING_READY = False\nLOG_BINDING = None\n';
  need(templateRaw.split(old).length===2,'one_binding_site');
  const source=templateRaw.replace(old,'BINDING_READY = True\nLOG_BINDING = '+JSON.stringify(binding)+'\n');
  const sourcePin=gitBlobMeta(source);
  const runtime={host:'mac',
    executable:'/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14',
    args:['-I','-S','-B','-'],cwd:'/Users/qianqi',timeout_seconds:60,
    idempotency_key:'heptabao-mac-owned-launchd-log-help-'+sourcePin.sha256.slice(0,8)+'-20261106-r1',
    stdin:source};
  const requestRaw=JSON.stringify(runtime,null,2)+'\n';
  return {binding,source,sourcePin,requestRaw,requestPin:gitBlobMeta(requestRaw),
    metadataOperation:ack.operation_id,metadataAckPin:gitBlobMeta(ackNativeRaw),
    metadataStatusPin:gitBlobMeta(statusNativeRaw),sourceOnly:true,runtimeAuthorized:false,
    rootMustVerifyOriginalImmutablePayloadToInfoChain:true};
}
