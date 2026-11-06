import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1')
SRC=ROOT
SOURCE=Path('/home/qian-qi/heptabao-native-snapshot-forward-source-2379d02b-20261106-r1/source')
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={"authenticated_peer_frame.rs":["02b1f11284b1463a3bbd2f35b2f7173a7a4d42758214b4cb73db7f497964caab","cd3c37ffaaaada293f3ab31727cfcd99206f551d9851fbfc6ab5ef06ccb4fac4"],"lib.rs":["f7eac8103954260134e244a1d5d5bf0045ed74f0d7123a01ac5f0b6b7089e7b8","9719e910990ebabe8d4d84e940ec942d1a92f13cec6f1a776934ae66f0d61521"],"native_snapshot_body.rs":[None,"c5371d4d81da56be70655bd618d7fbe321ca52df531cd30f33b92dd014a903a5"],"native_snapshot_body_tests.rs":[None,"c656de0f4ef9b627210e46323f2436adc4b3392d8097cfddcfdc29f2661054dc"],"native_snapshot_peer.rs":[None,"0981114047274df0e10fb986e8db70abd04a1f3a3efa2e3fb0ab2020005a1d14"],"native_snapshot_peer_tests.rs":[None,"aad72978eebeb7183c422cce15786049e860141a3526320b34f1f5f2d8fc7674"],"auth_forward_actor.rs":["8daeaf6bb0336eb1515479d69d6549fdd808b3d982940c53e4a36f6f67e9bdad","c14d38acecd53ecd6583556bcf5d0caf1e799a1a85c59bb77ef5ed09c88048c6"],"auth_snapshot_forward_actor_tests.rs":[None,"8bdf60ffd25054dc02c87e017c79801599ed7f37b8ce437455305e5a6bc5ff61"],"ha.rs":["a56ab6524b658b204cd998fc054ae5124ed615420ded443517bbf49988d6fd1c","b3cd73a6b008189838d131626fec259e498c865e8965d8cb4eede9d702b8f99d"],"ha_snapshot_forward.rs":[None,"d82de887f32993f0db1c0269bd44579f09673c431d4421a5b88c97fe5b432c0f"],"http.rs":["6d90383db0dabca25b6f6806e2b5923352976f4c4a69b2cce9a0a2dde7d727eb","47911a458e22757f47349ef1ca85124ea005d6de30055d456483772f2b577eb2"],"http_snapshot.rs":["1cc98a78d6a037a47456b7c6b93dc13647a261e8217f12a6a4edff3d91fe41e2","c97b724772726f15464abb39539136e3630afa9ffd7aba1e0210396aaee09bc1"],"service.rs":["6df7278a7b90363fe25a563e10e29db35f47868a2d1d1ea225c91c1b9b6add7d","152d79076104755a522ad972e020be3f9efad47cfc0b20692dc3190169ebf276"],"service_forward_delivery.rs":["8581fa455395fcdf3933e67360c677d2f53bdcefa8c86c4199d6c7948cad5e26","097371c6ec8a41d95b727fb41be00524dac6a39bdd41f991cbab51b7055d438a"],"service_snapshot_forward.rs":[None,"6db3cd4b9c8d115779b59282aef59755556099491f517985e453c1bd5b41586b"],"service_snapshot_forward_client.rs":[None,"0007a55d455493318cb2e606d5a19b94438e67b2b52cc0ab98465a240f74aa6c"],"service_snapshot_forward_file.rs":[None,"36256ca40029f4bdd57d961f4c75d020fa089aa59ebc624d8271d28ff6b8c14e"],"service_snapshot_forward_source.rs":[None,"3f37df8a3ad5d4cc535127b2c286b32a2c633ec7c4295a2525367a91099ec560"],"service_snapshot_forward_wire.rs":[None,"458dc1a5c54dd9ee128030012c48e6a800b5e886233392894e485fdfc42fade7"],"service_snapshot_forward_wire_tests.rs":[None,"c189b6999fef57fe2a5c6fc221c49647323c609f31f6d65a2eda6bcb682668cb"],"service_snapshot_transfer.rs":["022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9","fb6440b75feddef609a5ddf54de163f3ec4ad5ddb9d607c19586cfb000a0d223"],"service_snapshot_v6_ha.rs":["d3d6da2c49338d51565b381444cd91c8c4c7b7458b509189c8115087aff8d29a","43dcba00a64eb1602aa84c7c753199db6a4f748a90426f46a6aa9ea44f29d855"],"service_snapshot_v6_ha_restore.rs":["3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff","f0849c391e82b82a195779db8519245b7f27446680458b58b39ba9d034d2876c"],"service_native_controlgroups_271_namespace_ha_tests.rs":["cd6b816820ba3c0c1582beb9b4372f714c5ab99d0f781969c089db7702c3fe93","02cc09feba880d80bfc9372b0f86260518e260d52bbc3fa7c7e5fe17b80967a2"],"service_native_controlgroups_271_namespace_tests.rs":["a7731b47769e18291ba04b367ce64e3b76b871e272c067f6cce41d21a5ce4198","3a9581e97497703fd5f8ace778b53ccf91fe2e0da1a93c9a31bf8fbb2bf73ce6"],"service_native_file_gc_tests.rs":["90a321cda1b75f1f1c9237163cb06bbd18634fb5560bda909f2e09dfd21dffc9","018091c1d8da3ef996825cadba3508c46a843628e52d2f32e29517fe22b0631c"],"service_native_flat_retirement_tests.rs":["0bb9a97cca491fc1e143932433615dc54e3170c2a80696af82dd9a1048d8f367","d27e317371371497ca30b31c176a08cf30a05163e07658149d5361cf61943d56"],"service_native_kv2_import_tests.rs":["6f5803231f89409efe49a945bce37a4553d0176348f9d947d608f120960a3498","9f8842428f00eba24477bc163259ca0a48df3e676b07676eed31310284f10bcb"],"service_native_kv2_large_ha_tests.rs":["a70c683365f241efb2ed0f7178d5f2de8c62856e47dea5a2c70f0b46c06fce4c","8c15a718354afb9e180024fa90dd219cdba9d4369d72746364cd039d9f5e4097"],"service_native_kv2_mount_tests.rs":["3202825cef69680ac3c16fbb384fac301328612c9cd2a142e1f60f2ecd417888","9980cd10348eee2c4bf894e090f2f41383bbe0d1de13578b5e83f1497ab07472"],"service_native_kv2_storage_witness_tests.rs":["3427455ec8faa114a55a8e93fb2b0c2156ff3344e1d90d81994988396dfc88c0","3d39c810a3c0655f6aadc8ab620f71c88b9f325d4e78c2fdd6a1b562634406f0"],"service_native_namespace_tree_tests.rs":["f55b817be16c3f0858c9517c37948d326141d3db6f1e94a0c1fb7c248105d5a8","6117d5e314f10ce1df0b10c84159222cb37b3a90edef9fa7580d1b01ccbf81c7"],"service_native_pki_archive_tests.rs":["ae12c40896fe3c3624375b592edccf05755d796cb61b7b95d053334e32f2a4b4","e5666d96cc2bf4e32b13821cb2786da5f2f192b8fe418c945cdb1ba2ab613231"],"service_native_remount_v6_tests.rs":["1e8b72e33dd4b0b5e137168f1a3a3ec36c5b15765bc753d30b7088e57d1f1e6f","96aef7794bcdfba3ab6cc544c608ffd26b48ffafed0fcba6563943c310a9f74a"],"service_native_ssh_archive_tests.rs":["beea55ceb21643f144f7a664c3366d9957c95338fe4a7c3c33c3aac2dc361371","5d70e8c205b6ac5dd8f59d36e8a11d27d5483ce68a9a2240b1bfbd67b1c9dbc8"],"service_native_storage_tests.rs":["51e436b705f720fac56fab6cc9a047a99567b3f2f172bc842c030de355d842a0","9e27624cbcc31c32a739b708e134ec8022ced307d681051e26854eb167730d7e"],"service_native_transit_tests.rs":["f1f6beca7cbf01ba2f1411646ec9a744d58e85e42937311d5d264780e0573299","cd6cfe5785f95cb8f2cd50f156f3c790fcdb9c4787a1acd5bee9a22100d2b4ed"],"service_native_v6_ha_cold_restore_tests.rs":["8ed048c97e624d81ce3ff2478e776b461c81013173821d20ea3faf795e5345bd","bbbd43e5fd049b193da9fc092bc6feec314263f62dc7859b35e2b018afbbeff4"],"service_native_v6_ha_historical_restore_tests.rs":["a0f79c19eaccba34651510f7286dbb478fcab162182e89409e857547296d144a","ff6cc53a65ea25bcb9d4817f5875d1de950c4814b54bd7eafdff6b95ad8ed69d"],"service_native_v6_ha_restore_borrowed_tests.rs":["e698a994b8d99726b7bf375cc827ebd88724a91bb2b00d6b84db6facb93289c9","39d87fbdaa26716890b2bb9c4d12577224400bdd1c9611a073c616fd78847e97"],"service_native_v6_ha_snapshot_repair_tests.rs":["162d02f64aa177eaccc8e9751a404827ee58dee2ea038fd46d17687b8f4fd538","0cbc4d8e5855cd6726d6673b860ae514c9042f3788f8016e0fcb9403c0445814"],"service_native_v6_ha_snapshot_tests.rs":["0f65f9268096a6c5e7781a3c43266aeedd22bb7b3cf7369a8ab57f5371d8573c","a7999ef4dc72fbc3b776ad9e86d6fd19ccabfba7cdfc839b6d91dab4a988e404"],"service_native_v6_migration_tests.rs":["1a8f445ca9f101de429c3050af49bc2c0f89389b3c7016e589bc8c9270f0653b","291c2e023eb4213f15cc7214ae5ca988db6af63744cc8bc06c0e51bfba276b32"],"service_rate_limit_quota_139_tests.rs":["18bea53206969c8086ae0623a88912e4a120a927057a43468164e0c5f888a07f","b80ea54e67134fdcba6b329e4d8f283c40461256d6e9657f61178f93479fd685"],"service_snapshot_lossless_export_tests.rs":["9589c8d8e157a411515ee38389f4d2a17bfc35668f0defd88aca248be35c2bc7","9f222edca204bd1b325d1d520ee927338d587d14f5df95fd085017f9943d5072"],"service_snapshot_v6_tests.rs":["5a10c1c4d46e38d8f49a029445408ecda5b12fc2754ea8af5d8389f4511fcc32","293a7c730a279633b32054bde007be59275370a8c2b6d56f0e5d07ba4b07d769"],"service_native_v6_ha_pipeline_tests.rs":["2bfa098fe3ad0a5a6bf27eaf0c92269a0766dd1e9e2917bec6df6b96f8e565eb","0e204bfd4f2a2b5640e1da6611014f5a87799b099c9b2f6c861283e60c57c2ea"],"service_snapshot_forward_test_faults.rs":[None,"51cbdba0849307d58e3631994a9d2fe0ecaacda7f69617becb2b8b698e65bb29"],"service_native_snapshot_forward_audit_tests.rs":[None,"83b76edc5b8cc05de7ea748766c045d8dc67d487f82ed43d0fc614878f747c4e"]}
SOURCE_SIZES={"authenticated_peer_frame.rs":6204,"lib.rs":85408,"native_snapshot_body.rs":15545,"native_snapshot_body_tests.rs":7450,"native_snapshot_peer.rs":23126,"native_snapshot_peer_tests.rs":24050,"auth_forward_actor.rs":5048,"auth_snapshot_forward_actor_tests.rs":2135,"ha.rs":171691,"ha_snapshot_forward.rs":6330,"http.rs":232657,"http_snapshot.rs":38272,"service.rs":519577,"service_forward_delivery.rs":29010,"service_snapshot_forward.rs":8891,"service_snapshot_forward_client.rs":18850,"service_snapshot_forward_file.rs":1811,"service_snapshot_forward_source.rs":17522,"service_snapshot_forward_wire.rs":15616,"service_snapshot_forward_wire_tests.rs":9844,"service_snapshot_transfer.rs":52444,"service_snapshot_v6_ha.rs":13609,"service_snapshot_v6_ha_restore.rs":46836,"service_native_controlgroups_271_namespace_ha_tests.rs":16080,"service_native_controlgroups_271_namespace_tests.rs":16003,"service_native_file_gc_tests.rs":13274,"service_native_flat_retirement_tests.rs":40451,"service_native_kv2_import_tests.rs":34188,"service_native_kv2_large_ha_tests.rs":41292,"service_native_kv2_mount_tests.rs":26981,"service_native_kv2_storage_witness_tests.rs":23721,"service_native_namespace_tree_tests.rs":32704,"service_native_pki_archive_tests.rs":13352,"service_native_remount_v6_tests.rs":25915,"service_native_ssh_archive_tests.rs":8280,"service_native_storage_tests.rs":25215,"service_native_transit_tests.rs":27508,"service_native_v6_ha_cold_restore_tests.rs":33328,"service_native_v6_ha_historical_restore_tests.rs":53166,"service_native_v6_ha_restore_borrowed_tests.rs":21227,"service_native_v6_ha_snapshot_repair_tests.rs":23538,"service_native_v6_ha_snapshot_tests.rs":12836,"service_native_v6_migration_tests.rs":19758,"service_rate_limit_quota_139_tests.rs":40558,"service_snapshot_lossless_export_tests.rs":13457,"service_snapshot_v6_tests.rs":17988,"service_native_v6_ha_pipeline_tests.rs":70780,"service_snapshot_forward_test_faults.rs":5345,"service_native_snapshot_forward_audit_tests.rs":14875}
FORMAT_OUTPUT_CAPS={"authenticated_peer_frame.rs":262144,"lib.rs":262144,"native_snapshot_body.rs":262144,"native_snapshot_body_tests.rs":262144,"native_snapshot_peer.rs":262144,"native_snapshot_peer_tests.rs":262144,"auth_forward_actor.rs":262144,"auth_snapshot_forward_actor_tests.rs":262144,"ha.rs":262144,"ha_snapshot_forward.rs":262144,"http.rs":262144,"http_snapshot.rs":262144,"service.rs":655360,"service_forward_delivery.rs":262144,"service_snapshot_forward.rs":262144,"service_snapshot_forward_client.rs":262144,"service_snapshot_forward_file.rs":262144,"service_snapshot_forward_source.rs":262144,"service_snapshot_forward_wire.rs":262144,"service_snapshot_forward_wire_tests.rs":262144,"service_snapshot_transfer.rs":262144,"service_snapshot_v6_ha.rs":262144,"service_snapshot_v6_ha_restore.rs":262144,"service_native_controlgroups_271_namespace_ha_tests.rs":262144,"service_native_controlgroups_271_namespace_tests.rs":262144,"service_native_file_gc_tests.rs":262144,"service_native_flat_retirement_tests.rs":262144,"service_native_kv2_import_tests.rs":262144,"service_native_kv2_large_ha_tests.rs":262144,"service_native_kv2_mount_tests.rs":262144,"service_native_kv2_storage_witness_tests.rs":262144,"service_native_namespace_tree_tests.rs":262144,"service_native_pki_archive_tests.rs":262144,"service_native_remount_v6_tests.rs":262144,"service_native_ssh_archive_tests.rs":262144,"service_native_storage_tests.rs":262144,"service_native_transit_tests.rs":262144,"service_native_v6_ha_cold_restore_tests.rs":262144,"service_native_v6_ha_historical_restore_tests.rs":262144,"service_native_v6_ha_restore_borrowed_tests.rs":262144,"service_native_v6_ha_snapshot_repair_tests.rs":262144,"service_native_v6_ha_snapshot_tests.rs":262144,"service_native_v6_migration_tests.rs":262144,"service_rate_limit_quota_139_tests.rs":262144,"service_snapshot_lossless_export_tests.rs":262144,"service_snapshot_v6_tests.rs":262144,"service_native_v6_ha_pipeline_tests.rs":262144,"service_snapshot_forward_test_faults.rs":262144,"service_native_snapshot_forward_audit_tests.rs":262144}
SOURCE_RELATIVE={"authenticated_peer_frame.rs":"crates/heptabao-ha-service/src/authenticated_peer_frame.rs","lib.rs":"crates/heptabao-ha-service/src/lib.rs","native_snapshot_body.rs":"crates/heptabao-ha-service/src/native_snapshot_body.rs","native_snapshot_body_tests.rs":"crates/heptabao-ha-service/src/native_snapshot_body_tests.rs","native_snapshot_peer.rs":"crates/heptabao-ha-service/src/native_snapshot_peer.rs","native_snapshot_peer_tests.rs":"crates/heptabao-ha-service/src/native_snapshot_peer_tests.rs","auth_forward_actor.rs":"crates/heptabao-server/src/auth_forward_actor.rs","auth_snapshot_forward_actor_tests.rs":"crates/heptabao-server/src/auth_snapshot_forward_actor_tests.rs","ha.rs":"crates/heptabao-server/src/ha.rs","ha_snapshot_forward.rs":"crates/heptabao-server/src/ha_snapshot_forward.rs","http.rs":"crates/heptabao-server/src/http.rs","http_snapshot.rs":"crates/heptabao-server/src/http_snapshot.rs","service.rs":"crates/heptabao-server/src/service.rs","service_forward_delivery.rs":"crates/heptabao-server/src/service_forward_delivery.rs","service_snapshot_forward.rs":"crates/heptabao-server/src/service_snapshot_forward.rs","service_snapshot_forward_client.rs":"crates/heptabao-server/src/service_snapshot_forward_client.rs","service_snapshot_forward_file.rs":"crates/heptabao-server/src/service_snapshot_forward_file.rs","service_snapshot_forward_source.rs":"crates/heptabao-server/src/service_snapshot_forward_source.rs","service_snapshot_forward_wire.rs":"crates/heptabao-server/src/service_snapshot_forward_wire.rs","service_snapshot_forward_wire_tests.rs":"crates/heptabao-server/src/service_snapshot_forward_wire_tests.rs","service_snapshot_transfer.rs":"crates/heptabao-server/src/service_snapshot_transfer.rs","service_snapshot_v6_ha.rs":"crates/heptabao-server/src/service_snapshot_v6_ha.rs","service_snapshot_v6_ha_restore.rs":"crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs","service_native_controlgroups_271_namespace_ha_tests.rs":"crates/heptabao-server/src/service_native_controlgroups_271_namespace_ha_tests.rs","service_native_controlgroups_271_namespace_tests.rs":"crates/heptabao-server/src/service_native_controlgroups_271_namespace_tests.rs","service_native_file_gc_tests.rs":"crates/heptabao-server/src/service_native_file_gc_tests.rs","service_native_flat_retirement_tests.rs":"crates/heptabao-server/src/service_native_flat_retirement_tests.rs","service_native_kv2_import_tests.rs":"crates/heptabao-server/src/service_native_kv2_import_tests.rs","service_native_kv2_large_ha_tests.rs":"crates/heptabao-server/src/service_native_kv2_large_ha_tests.rs","service_native_kv2_mount_tests.rs":"crates/heptabao-server/src/service_native_kv2_mount_tests.rs","service_native_kv2_storage_witness_tests.rs":"crates/heptabao-server/src/service_native_kv2_storage_witness_tests.rs","service_native_namespace_tree_tests.rs":"crates/heptabao-server/src/service_native_namespace_tree_tests.rs","service_native_pki_archive_tests.rs":"crates/heptabao-server/src/service_native_pki_archive_tests.rs","service_native_remount_v6_tests.rs":"crates/heptabao-server/src/service_native_remount_v6_tests.rs","service_native_ssh_archive_tests.rs":"crates/heptabao-server/src/service_native_ssh_archive_tests.rs","service_native_storage_tests.rs":"crates/heptabao-server/src/service_native_storage_tests.rs","service_native_transit_tests.rs":"crates/heptabao-server/src/service_native_transit_tests.rs","service_native_v6_ha_cold_restore_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_cold_restore_tests.rs","service_native_v6_ha_historical_restore_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_historical_restore_tests.rs","service_native_v6_ha_restore_borrowed_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_restore_borrowed_tests.rs","service_native_v6_ha_snapshot_repair_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_snapshot_repair_tests.rs","service_native_v6_ha_snapshot_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_snapshot_tests.rs","service_native_v6_migration_tests.rs":"crates/heptabao-server/src/service_native_v6_migration_tests.rs","service_rate_limit_quota_139_tests.rs":"crates/heptabao-server/src/service_rate_limit_quota_139_tests.rs","service_snapshot_lossless_export_tests.rs":"crates/heptabao-server/src/service_snapshot_lossless_export_tests.rs","service_snapshot_v6_tests.rs":"crates/heptabao-server/src/service_snapshot_v6_tests.rs","service_native_v6_ha_pipeline_tests.rs":"crates/heptabao-server/src/service_native_v6_ha_pipeline_tests.rs","service_snapshot_forward_test_faults.rs":"crates/heptabao-server/src/service_snapshot_forward_test_faults.rs","service_native_snapshot_forward_audit_tests.rs":"crates/heptabao-server/src/service_native_snapshot_forward_audit_tests.rs"}
FORMAT_CONFIG=b'edition = "2024"\n'
FORMAT_CONFIG_SHA='f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584'
os.umask(0o077)
def remain():
 r=LIMIT-(time.monotonic()-START)
 if r<=0: raise RuntimeError('format_total_deadline')
 return r
def sha(b): return hashlib.sha256(b).hexdigest()
def read_pin(p,expected_bytes=None):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1 or not 0<a.st_size<=8*1024*1024: raise RuntimeError('input_custody')
  if expected_bytes is not None and a.st_size!=expected_bytes: raise RuntimeError('source_size_pin')
  out=bytearray()
  while True:
   remain();part=os.read(fd,65536)
   if not part: break
   out.extend(part)
  b=os.fstat(fd);n=os.lstat(p)
  keys=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
  if keys(a)!=keys(b) or keys(a)!=keys(n): raise RuntimeError('input_changed')
  return bytes(out),{'path':str(p),'sha256':sha(out),'bytes':len(out),'identity':list(keys(a))}
 finally: os.close(fd)
def write_new(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:
   remain();n=os.write(fd,view)
   if n<=0: raise RuntimeError('short_write')
   view=view[n:]
  os.fsync(fd)
 finally: os.close(fd)
def sync_dir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
report={'schema':'heptabao.native-snapshot-forward-input-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'2379d02ba1ee3e88989815d5a978f998822bac4f',
 'sourceTree':'fc933c18a0415730e3658c17ff021db9b2df2caa','sourceIdentityIsBaseOnly':False,
 'uncommittedCandidateInputs':False,'edition':'2024',
 'sourcePath':str(SOURCE),'sourceInputTotalBytes':2023746,
 'fixedFormattedOutputCaps':FORMAT_OUTPUT_CAPS,
 'fixedSourceRelativePaths':SOURCE_RELATIVE,
 'sourceIdentityFields':['dev','ino','size','mtime_ns','ctime_ns','full_mode','uid','gid','nlink'],
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;tool_before=None;config_before=None;source_before={}
try:
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144: raise RuntimeError('input_size')
 carrier=json.loads(raw)
 if set(carrier)!=set(EXPECTED): raise RuntimeError('input_names')
 if SOURCE.resolve(strict=True)!=SOURCE: raise RuntimeError('source_parent_symlink')
 data={}
 for name in EXPECTED:
  if carrier[name]!={'bytes':SOURCE_SIZES[name],'sha256':EXPECTED[name][1]}: raise RuntimeError('source_manifest_pin')
  path=SOURCE/SOURCE_RELATIVE[name]
  if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
  original,pin=read_pin(path,SOURCE_SIZES[name])
  if len(original)!=SOURCE_SIZES[name] or sha(original)!=EXPECTED[name][1]: raise RuntimeError('candidate_input_pin')
  source_before[name]=pin
  data[name]=original.decode('utf-8')
 report['sourceInputsBefore']=source_before
 report['inputCarrierSha256']=sha(raw)
 if FMT.resolve(strict=True)!=FMT: raise RuntimeError('rustfmt_parent_symlink')
 tool_bytes,tool_before=read_pin(FMT)
 if sha(tool_bytes)!=FMT_SHA: raise RuntimeError('rustfmt_pin')
 report['rustfmtBefore']=tool_before
 report['originalSourceProvenance']='Forty-nine fixed files from exact independent 2379d02b checkout in two crates; source is only read, formatting writes owned copies'
 report['inputOriginalAndCandidatePins']=EXPECTED
 ROOT.mkdir(mode=0o700);created=True
 (ROOT/'candidate').mkdir(mode=0o700);(ROOT/'formatted').mkdir(mode=0o700)
 write_new(ROOT/'rustfmt.toml',FORMAT_CONFIG)
 config_bytes,config_before=read_pin(ROOT/'rustfmt.toml')
 if config_bytes!=FORMAT_CONFIG or sha(config_bytes)!=FORMAT_CONFIG_SHA: raise RuntimeError('format_config_pin')
 report['formatConfigurationBefore']=config_before
 report['repositoryRustfmtConfigPresent']=False
 report['ownedConfiguration']='Edition 2024 only; all other rustfmt defaults; explicit config path excludes ambient parent configuration'
 for name in EXPECTED:
  text=data[name];write_new(ROOT/'candidate'/name,text.encode())
  argv=[str(FMT),'--config-path',str(ROOT/'rustfmt.toml'),'--edition','2024','--emit','stdout']
  p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      cwd=str(SRC),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=False)
  child={'pid':p.pid,'argv':argv,'cwd':str(SRC),'timeoutSeconds':10,'stopped':False,'newProcessGroupCreated':False}
  report['children'].append(child)
  try:
   child['pgid']=os.getpgid(p.pid)
   child['supervisorGroup']=os.getpgrp()
   if child['pgid']!=child['supervisorGroup']: raise RuntimeError('child_escaped_supervisor_group')
   out,err=p.communicate(text.encode(),timeout=min(10.0,remain()))
  except BaseException:
   if p.poll() is None:
    p.kill()
    p.wait(timeout=min(5.0,remain()))
   child.update(exitCode=p.returncode,reaped=p.returncode is not None)
   child['stopped']=child['reaped']
   raise
  child.update(exitCode=p.returncode,reaped=True)
  child['stopped']=True
  if len(err)>65536: raise RuntimeError('formatted_stderr_bound')
  write_new(ROOT/(name+'.rustfmt.stderr'),err)
  if p.returncode!=0 or not child['stopped']: raise RuntimeError('rustfmt_failed_or_group_remaining')
  write_new(ROOT/(name+'.rustfmt.stdout'),out)
  if len(out)>FORMAT_OUTPUT_CAPS[name] or not out.startswith(text.splitlines()[0].encode()+b'\n'): raise RuntimeError('formatted_output_shape')
  write_new(ROOT/'formatted'/name,out)
  report['files'].append({'name':name,'beforeSha256':sha(text.encode()),'beforeBytes':len(text.encode()),
      'afterSha256':sha(out),'afterBytes':len(out),'stderrBytes':len(err),'stderrSha256':sha(err)})
 sync_dir(ROOT/'candidate');sync_dir(ROOT/'formatted');sync_dir(ROOT)
 remain();report['status']='passed'
except BaseException as e:
 report['errorType']=type(e).__name__;report['error']=str(e)
finally:
 report['sourceInputsAfter']={}
 for name,before_pin in source_before.items():
  try:
   path=SOURCE/SOURCE_RELATIVE[name]
   if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
   original,after_pin=read_pin(path,SOURCE_SIZES[name])
   report['sourceInputsAfter'][name]=after_pin
   if sha(original)!=EXPECTED[name][1] or after_pin!=before_pin: raise RuntimeError('source_changed')
  except BaseException as e:
   report['sourceFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 report['allFixedSourceInputsUnchanged']=len(source_before)==len(EXPECTED) and report['sourceInputsAfter']==source_before
 if not report['allFixedSourceInputsUnchanged']: report['status']='failed'
 if tool_before is not None:
  try:
   report['rustfmtAfter']=read_pin(FMT)[1]
   if report['rustfmtAfter']!=tool_before: raise RuntimeError('rustfmt_changed')
  except BaseException as e:
   report['fenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 if config_before is not None:
  try:
   config_bytes,report['formatConfigurationAfter']=read_pin(ROOT/'rustfmt.toml')
   if config_bytes!=FORMAT_CONFIG or report['formatConfigurationAfter']!=config_before: raise RuntimeError('format_config_changed')
  except BaseException as e:
   report['configFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 report['elapsedSeconds']=time.monotonic()-START
 report['withinDeadline']=report['elapsedSeconds']<LIMIT
 report['allOwnedStopped']=all(x.get('stopped') is True for x in report['children'])
 if not report['withinDeadline'] or not report['allOwnedStopped']: report['status']='failed'
 if created:
  try:
   write_new(ROOT/'result.public.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
   sync_dir(ROOT)
  except BaseException as e:
   report['publicationError']=type(e).__name__;report['status']='failed'
 print(json.dumps({'status':report['status'],'root':str(ROOT),'files':report['files'],
   'allOwnedStopped':report['allOwnedStopped'],'elapsedSeconds':time.monotonic()-START,
   'withinDeadline':time.monotonic()-START<LIMIT,'error':report.get('error'),'publicationError':report.get('publicationError')},sort_keys=True),flush=True)
sys.exit(0 if report['status']=='passed' and time.monotonic()-START<LIMIT else 1)
