/* SOURCE ONLY: fixed23 changed formatter outputs, fresh read-only context.
 * No process/file write, formatter/Cargo, old report reread, or old context reset.
 * Per file: exact metadata once, then its fixed ranges once; close each observer.
 * Every original SDK and payload is Git-whole before interpretation.
 * Retain chunks as bytes/base64; UTF-8 only after whole-file SHA.
 * No Native action is authorized by this SOURCE file itself.
 */
const GF_SLOT = "snapshot_2379_formatted23_readonly_gitfirst_r1";
const GF_OUTPUTS = [{"index":0,"reportIndex":1,"name":"lib.rs","canonicalPath":"crates/heptabao-ha-service/src/lib.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/lib.rs","bytes":85408,"sha256":"2bddfb1eff7527f273c9c81f7ed90456de34cdcb71ae1fd1aed60e155ea9040d","source":{"blob":"504b1b18757bdd4bf013e7ee27029c0cc9044d37","bytes":85408,"sha256":"9719e910990ebabe8d4d84e940ec942d1a92f13cec6f1a776934ae66f0d61521"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info00\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/lib.rs\"\n    }\n  }\n}\n","info":{"blob":"26617aa41fbb9bc76644d1e7d0cf9d8fcc39c23a","bytes":286,"sha256":"eda749317078e4ba4671048a9a5bc44825dc2d0005234b79e36676772e92001b"},"ranges":[{"index":0,"offset":0,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body00-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/lib.rs\",\n      \"offset\": 0,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"9bffd8e80199c018be823d9a4cb97fc227524a19","bytes":364,"sha256":"126cd9a0c2c2224a794a714639ff516c493a67925c577ac0598d6de552cb2f46"}},{"index":1,"offset":65536,"limit":19872,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body00-01\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/lib.rs\",\n      \"offset\": 65536,\n      \"limit\": 19872,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"286e9cd1e9de509e73c0c1889cb1857769b79072","bytes":368,"sha256":"47a292309953cb0a00c54c22c0cda5458f0cdeb1c1356174058cfc9a1277672c"}}]},{"index":1,"reportIndex":2,"name":"native_snapshot_body.rs","canonicalPath":"crates/heptabao-ha-service/src/native_snapshot_body.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body.rs","bytes":15502,"sha256":"e250aadc92a5e114aabafd04de2578750c8291c483829f7d25ee249f6ccd5e26","source":{"blob":"bbf14e2500ffbfe36a0ef24ca0e19240e88d319e","bytes":15545,"sha256":"c5371d4d81da56be70655bd618d7fbe321ca52df531cd30f33b92dd014a903a5"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info01\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body.rs\"\n    }\n  }\n}\n","info":{"blob":"f7ff58715367d015aeaf6d99ab334cc203974dde","bytes":303,"sha256":"81aefacae6d732ce5ad7ef4a35350e265809d36a2d6fc3128a9f1c22148ce0d7"},"ranges":[{"index":0,"offset":0,"limit":15502,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body01-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body.rs\",\n      \"offset\": 0,\n      \"limit\": 15502,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"947006f9b910fe89f6458568da2d91855cb17864","bytes":381,"sha256":"8ccd0ea04db111d5a7fc3db4dabf1d578a57731b9343691bef5c9c9d5aeb2138"}}]},{"index":2,"reportIndex":3,"name":"native_snapshot_body_tests.rs","canonicalPath":"crates/heptabao-ha-service/src/native_snapshot_body_tests.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body_tests.rs","bytes":7525,"sha256":"02cf32110c8a70a0e05a9f492ab9b6811bb4eecd5db5e44da30886c4422766c8","source":{"blob":"fbaa67b64fd10377039096f04072868efdf88542","bytes":7450,"sha256":"c656de0f4ef9b627210e46323f2436adc4b3392d8097cfddcfdc29f2661054dc"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info02\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body_tests.rs\"\n    }\n  }\n}\n","info":{"blob":"79ce3feb1a603404432738a3f20565b45967a6a5","bytes":309,"sha256":"58a0b79b85f58140b165ed1e944510e0cb43d8cd0b6379ab79a57cd02921f741"},"ranges":[{"index":0,"offset":0,"limit":7525,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body02-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_body_tests.rs\",\n      \"offset\": 0,\n      \"limit\": 7525,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"3ea6291c2a1f2be74d68012bb9b80cfb46c293f6","bytes":386,"sha256":"b3d4ccb23c4a5496c393f9bfea13c23caaf62832bf57306eb5eef2e267813269"}}]},{"index":3,"reportIndex":4,"name":"native_snapshot_peer.rs","canonicalPath":"crates/heptabao-ha-service/src/native_snapshot_peer.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer.rs","bytes":23025,"sha256":"4381447e1b8d5e0861c8f2ca88e9e550dc7494a1cbeb752008167b9700438c85","source":{"blob":"2aae6e8a7f5bc459e19240fec8c622bdf115b8e2","bytes":23126,"sha256":"0981114047274df0e10fb986e8db70abd04a1f3a3efa2e3fb0ab2020005a1d14"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info03\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer.rs\"\n    }\n  }\n}\n","info":{"blob":"1bf0990abe0180631a3127898a0a3ff155c7e6f2","bytes":303,"sha256":"35ccf9e42cac2ff7f10f100fdcee33d91fdb0581d191dbda26902ae8384a7491"},"ranges":[{"index":0,"offset":0,"limit":23025,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body03-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer.rs\",\n      \"offset\": 0,\n      \"limit\": 23025,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"f426820bc2bf62af56cfabee5085c58782977e57","bytes":381,"sha256":"3791e262ffa461a3f24de00785e0c873196cc5ba9dfa5f174acf719c4e351a1c"}}]},{"index":4,"reportIndex":5,"name":"native_snapshot_peer_tests.rs","canonicalPath":"crates/heptabao-ha-service/src/native_snapshot_peer_tests.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer_tests.rs","bytes":24476,"sha256":"bdbb95b385de092a4c4a9bcae2d7a282d627654aa0bb608e743b7f61b9591589","source":{"blob":"e4d16a8baabe02fa172232792850f291c5cdd1d5","bytes":24050,"sha256":"aad72978eebeb7183c422cce15786049e860141a3526320b34f1f5f2d8fc7674"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info04\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer_tests.rs\"\n    }\n  }\n}\n","info":{"blob":"85ecc1c127dd58f843972141bd835e0290c76c18","bytes":309,"sha256":"5c32e05f390951ee726e58d3a30687b4d73aaf4612dd33d25f8a03d33b7161d1"},"ranges":[{"index":0,"offset":0,"limit":24476,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body04-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/native_snapshot_peer_tests.rs\",\n      \"offset\": 0,\n      \"limit\": 24476,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"a23dbc1079edb51dceac596d91dba7709f309b79","bytes":387,"sha256":"1c95e690e439f24cf5fdad0efd8f5866f871c398e8f08e5b33f7da2c51de97a5"}}]},{"index":5,"reportIndex":6,"name":"auth_forward_actor.rs","canonicalPath":"crates/heptabao-server/src/auth_forward_actor.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_forward_actor.rs","bytes":5060,"sha256":"7c11c0b16c7c61b25620462b005be9b88f9ab27b962df2d8f117cf1576cfbdcb","source":{"blob":"84d925badf31803b76d0f008bb7605d2c5c15d88","bytes":5048,"sha256":"c14d38acecd53ecd6583556bcf5d0caf1e799a1a85c59bb77ef5ed09c88048c6"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info05\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_forward_actor.rs\"\n    }\n  }\n}\n","info":{"blob":"255434e359f29cd432b69a48bcbe65f1ec71a12d","bytes":301,"sha256":"e08ff300ab9b42882475a1bc58394b1971a3a47fbfb710cfa21dfa65c4b6f7d5"},"ranges":[{"index":0,"offset":0,"limit":5060,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body05-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_forward_actor.rs\",\n      \"offset\": 0,\n      \"limit\": 5060,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"efc18e2edd44fb30a00e0a4f0aa9b5c01ca9c555","bytes":378,"sha256":"484507789518f4d27d9abc34901e1a67b8065e1fad66c3f56b1beb0fdcb5775e"}}]},{"index":6,"reportIndex":7,"name":"auth_snapshot_forward_actor_tests.rs","canonicalPath":"crates/heptabao-server/src/auth_snapshot_forward_actor_tests.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_snapshot_forward_actor_tests.rs","bytes":2392,"sha256":"75be958fe598965828c339acb3ace93de69664a452ba8219b25cdd73f583ca41","source":{"blob":"468a6808a7b910fe5c3489f9afeaa21fa8354d13","bytes":2135,"sha256":"8bdf60ffd25054dc02c87e017c79801599ed7f37b8ce437455305e5a6bc5ff61"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info06\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_snapshot_forward_actor_tests.rs\"\n    }\n  }\n}\n","info":{"blob":"6d1a93b2af2792b36738075c7281d0d32fdd6cbe","bytes":316,"sha256":"e763bacbb59e18999f37967e1cba20c33de173cf704fc86f3c826106c5624fcd"},"ranges":[{"index":0,"offset":0,"limit":2392,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body06-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/auth_snapshot_forward_actor_tests.rs\",\n      \"offset\": 0,\n      \"limit\": 2392,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"51ed16a4cd8d8e3ad0ad3e9c4402c6220b597741","bytes":393,"sha256":"a5fca2b76946cd38db0b8c3815b3010a763a67976f58681e98ba1466164115af"}}]},{"index":7,"reportIndex":8,"name":"ha.rs","canonicalPath":"crates/heptabao-server/src/ha.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha.rs","bytes":171763,"sha256":"619692557bfb072e9aab8a820bdd41ac453184460c6ff177c9a81820d5d2a284","source":{"blob":"19a28bccef243c221a89841209245527252a9b21","bytes":171691,"sha256":"b3cd73a6b008189838d131626fec259e498c865e8965d8cb4eede9d702b8f99d"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info07\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha.rs\"\n    }\n  }\n}\n","info":{"blob":"0606ab5ee8fc74938e7a268d14c798a19d393d69","bytes":285,"sha256":"999eadcd0542e629320e2350146461c3ba3a705881b56c7f12ef4cf74377b661"},"ranges":[{"index":0,"offset":0,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body07-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha.rs\",\n      \"offset\": 0,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"0c2c8cf5ab2710f7506fc72b6d51216dfee014b2","bytes":363,"sha256":"931375781678723d7aa6e30a3b5fe4d6bd3f9e679a21b519b6d7ae687761e79b"}},{"index":1,"offset":65536,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body07-01\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha.rs\",\n      \"offset\": 65536,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"27b352a357475cfbad7c28abe7f8dcbb9c90055f","bytes":367,"sha256":"5e33927e7d54f160243b255ce97e9803f6f073815e915b65c9d83f0bfaac5aed"}},{"index":2,"offset":131072,"limit":40691,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body07-02\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha.rs\",\n      \"offset\": 131072,\n      \"limit\": 40691,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"67df3595891a33c15de6f49db143aaa7ec43621e","bytes":368,"sha256":"25aedb8d95cb449cc046055f6c69817b16ed4ef6c7ef23654b1a8f3c9d088eb1"}}]},{"index":8,"reportIndex":9,"name":"ha_snapshot_forward.rs","canonicalPath":"crates/heptabao-server/src/ha_snapshot_forward.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha_snapshot_forward.rs","bytes":6680,"sha256":"feebc80e9f2e4f8cc3f9c70756ce2384aa308070b0b1e418bb7fc02d79be1ffd","source":{"blob":"fdc4ddc517cb7919375e05ae18ba7ae87267c8f0","bytes":6330,"sha256":"d82de887f32993f0db1c0269bd44579f09673c431d4421a5b88c97fe5b432c0f"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info08\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha_snapshot_forward.rs\"\n    }\n  }\n}\n","info":{"blob":"d63a3f8393d90b7c7224144fe2912be52ad542a2","bytes":302,"sha256":"b2fe538b100b1f5d50dd0f7c9f4feedae0d3284e750faec2b3463ccce8c46e50"},"ranges":[{"index":0,"offset":0,"limit":6680,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body08-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/ha_snapshot_forward.rs\",\n      \"offset\": 0,\n      \"limit\": 6680,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"95c0a9540f1b05c899349e6516c699066d571a1b","bytes":379,"sha256":"9a99d5ecdcb976b207d7a49293705d18a5d00b6762f1f1eaa567f76084484c63"}}]},{"index":9,"reportIndex":10,"name":"http.rs","canonicalPath":"crates/heptabao-server/src/http.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs","bytes":232691,"sha256":"42f2650a55a9d9cd6aaf47b9f3a3d7e424a5b5e807cb87f1786dfb1eb838ec9e","source":{"blob":"2f3843615e5432b311eeb438c238d9222434310d","bytes":232657,"sha256":"47911a458e22757f47349ef1ca85124ea005d6de30055d456483772f2b577eb2"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info09\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs\"\n    }\n  }\n}\n","info":{"blob":"68d6e7b4b15ab17b9cd8b61c74f467638ce59bd6","bytes":287,"sha256":"045b2a68dcef92707bd43625391698126550eee3a7da5e25a91ed72b2ca2da19"},"ranges":[{"index":0,"offset":0,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body09-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs\",\n      \"offset\": 0,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"efadd6201a42fe0ce8d9371ebde09d7f1c458105","bytes":365,"sha256":"70661dac898f70ef40f97ae0073fbe902fbcdf86d0f139e01beb782e531a235d"}},{"index":1,"offset":65536,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body09-01\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs\",\n      \"offset\": 65536,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"3afeae6214b67375b82a83e907944d72e74a74a7","bytes":369,"sha256":"2711d06bf7dbe870d385b466056f5b725aad67f014da060c1a948cbc0c6309c9"}},{"index":2,"offset":131072,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body09-02\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs\",\n      \"offset\": 131072,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"a71c4fc969b3b820d44c158b43a7405c7bbaff96","bytes":370,"sha256":"5a68c42e8b82b4adbf4bf1e87b026b629f0f1de7333d54e1b4c4835ffc22f6a6"}},{"index":3,"offset":196608,"limit":36083,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body09-03\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http.rs\",\n      \"offset\": 196608,\n      \"limit\": 36083,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"ddf9e365e8ab72e2891eaf2b48f8851881cc3110","bytes":370,"sha256":"ea4b2ed303d9f8949c4e66cd137725cf59f7e71ae90f441c2299a8e50e5ed96b"}}]},{"index":10,"reportIndex":11,"name":"http_snapshot.rs","canonicalPath":"crates/heptabao-server/src/http_snapshot.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http_snapshot.rs","bytes":38482,"sha256":"d3ece20279fd3e225736b9138e892d28dc766112d1de94f8882c9117fe1eb93c","source":{"blob":"c3740f0a2e55281b72a05f1b6c8e527618f3d65a","bytes":38272,"sha256":"c97b724772726f15464abb39539136e3630afa9ffd7aba1e0210396aaee09bc1"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info10\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http_snapshot.rs\"\n    }\n  }\n}\n","info":{"blob":"56cf238998c68e0a08dfe02194147ee30ff0ae94","bytes":296,"sha256":"f3a1a47718236444da060d12c091808d4ed73e8572f688b80007c196b52255da"},"ranges":[{"index":0,"offset":0,"limit":38482,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body10-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/http_snapshot.rs\",\n      \"offset\": 0,\n      \"limit\": 38482,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"7f3f3bfc9435a065f98675d6e8ef00594066d8ff","bytes":374,"sha256":"fbf002dfa8713c78f5bbf1a3337562e2668fcc5d6f626cb996d68428e54584a0"}}]},{"index":11,"reportIndex":12,"name":"service.rs","canonicalPath":"crates/heptabao-server/src/service.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs","bytes":519619,"sha256":"4ad6ea76e43a14a073843400b12f516175d46ed103610a6f7202b82a09d7c919","source":{"blob":"63bacb537a17cc060239a1793f8ac526e15df158","bytes":519577,"sha256":"152d79076104755a522ad972e020be3f9efad47cfc0b20692dc3190169ebf276"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info11\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\"\n    }\n  }\n}\n","info":{"blob":"5176a0dc62e21ff057c43aaf6e6ba12ed9b893f6","bytes":290,"sha256":"572370e8ff4f5cefc5430b3d58723c04aacfbcaf5c85b9d1210f7faec2319816"},"ranges":[{"index":0,"offset":0,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 0,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"bfccff801001f98525f1975a1b58889177e234b3","bytes":368,"sha256":"e76910ce5795c4664695774cea01578dba3e07f5046e11440bc7ff29dd7e4dba"}},{"index":1,"offset":65536,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-01\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 65536,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"e47347a4e3395af45e04c2a2ede76765382abca4","bytes":372,"sha256":"b228e01e3a0534da1e7fd16709ad889ddd9a618d5caeb827e7f8db61cf454a59"}},{"index":2,"offset":131072,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-02\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 131072,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"1439664a4da740788bd2720022ff3c8932d2941f","bytes":373,"sha256":"85f05d45b3a2a4e04366f4ff97173cfe589674249778623943e896fd0e1741d3"}},{"index":3,"offset":196608,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-03\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 196608,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"875d1bec9e0ad3e0ced049cebe3a7a0f60449bbb","bytes":373,"sha256":"69265524ab633d57409f0bcee8cf3e163f023bb686623969ec60bba3ca14c329"}},{"index":4,"offset":262144,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-04\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 262144,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"4738366b6d23c9bc0b17f0c745ab1dc7f645bb51","bytes":373,"sha256":"dcbb24bd44b309ff58d7ddfe0ffebf87db7a4547e53e903dff8a767465860659"}},{"index":5,"offset":327680,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-05\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 327680,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"f0fe6410ef22aa272bfc74f40f5c2a067dbbab29","bytes":373,"sha256":"4be64b5667f5ac39c00fe48f7a362d7a12a84c6bceb76dbfa031522231f213c5"}},{"index":6,"offset":393216,"limit":65536,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-06\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 393216,\n      \"limit\": 65536,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"f65276cb7af9bffdfbc265aa0316f20e240ff8d0","bytes":373,"sha256":"0946363716ee6249ace09e569044ed0f70f6e2bda9e9c86febbe6d13c5e36d73"}},{"index":7,"offset":458752,"limit":60867,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body11-07\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service.rs\",\n      \"offset\": 458752,\n      \"limit\": 60867,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"747548685cb630292ee957308daa6a437d333153","bytes":373,"sha256":"9a1d76ee518bac4d1b5390d079e1643bd5939cfab07972cb7cf6e1aa361ed02f"}}]},{"index":12,"reportIndex":14,"name":"service_snapshot_forward.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward.rs","bytes":9837,"sha256":"db3bef7b2108468f5ce6a2a720cf16eebc5815d83e0e269469137ee6836f42eb","source":{"blob":"622770cca42dbbc1bd7c82dbd2fc0178180cfa42","bytes":8891,"sha256":"6db3cd4b9c8d115779b59282aef59755556099491f517985e453c1bd5b41586b"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info12\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward.rs\"\n    }\n  }\n}\n","info":{"blob":"9de7c490fd5b81c483a9570bc2212e918ffb42df","bytes":307,"sha256":"d081dbc5a9923002265f816939a45e4f59abfb3f9b2d29fb32d62b30df737057"},"ranges":[{"index":0,"offset":0,"limit":9837,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body12-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward.rs\",\n      \"offset\": 0,\n      \"limit\": 9837,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"745faa80d10f934bb9d056d8d84162af869b22ca","bytes":384,"sha256":"872b1bf28f29975621ca9dadf34c9bdb333b9ed6ef313c7dee3646f106284a09"}}]},{"index":13,"reportIndex":15,"name":"service_snapshot_forward_client.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_client.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_client.rs","bytes":20232,"sha256":"f76bdf9fc65fcf99b0a214c00df7660436509036c107f5486b3226981635004f","source":{"blob":"694edf2abe8a8f61dc887469e2dcc963dfc58fca","bytes":18850,"sha256":"0007a55d455493318cb2e606d5a19b94438e67b2b52cc0ab98465a240f74aa6c"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info13\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_client.rs\"\n    }\n  }\n}\n","info":{"blob":"c531adfea3dde88011fd6783d726492c60766307","bytes":314,"sha256":"b042a0d78c531dd61d03f62900f9a38b5d74039ff86fc23d480114b238569618"},"ranges":[{"index":0,"offset":0,"limit":20232,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body13-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_client.rs\",\n      \"offset\": 0,\n      \"limit\": 20232,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"8c4fbb0556f266f357693c0b01007d913d827b8a","bytes":392,"sha256":"35ee7e6b6d5661a6fcce1c2d688301c267b8736bbd30e052233b309e48206e39"}}]},{"index":14,"reportIndex":16,"name":"service_snapshot_forward_file.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_file.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_file.rs","bytes":1957,"sha256":"e77aa9448bf431328da0500dc7dad21d515fa87b142350cdaf3eef6610d19b19","source":{"blob":"cc96349fe49fa0ffa067971f2cbda21839804410","bytes":1811,"sha256":"36256ca40029f4bdd57d961f4c75d020fa089aa59ebc624d8271d28ff6b8c14e"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info14\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_file.rs\"\n    }\n  }\n}\n","info":{"blob":"eea7da5769858453f8a8a637b25414ff9854dc59","bytes":312,"sha256":"a5c248dca3da4529958e972bb24df9d282a6c0cac6e97d5dffa617030f2db308"},"ranges":[{"index":0,"offset":0,"limit":1957,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body14-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_file.rs\",\n      \"offset\": 0,\n      \"limit\": 1957,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"e275cd05e1fc4e9b61db0c5059e3cdc4b8316687","bytes":389,"sha256":"87f316b1e59bcb9021bce7e65d099c0c981a56d5f525d4d336e7bce24e38cfff"}}]},{"index":15,"reportIndex":17,"name":"service_snapshot_forward_source.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_source.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_source.rs","bytes":19516,"sha256":"2644931919fdafdc2d68d8e9927ebca77647e7ce8839cec1abef3e7563635c73","source":{"blob":"ca9962d39f90cdf6ebbc06d04a9cc6c0fa7aa0a1","bytes":17522,"sha256":"3f37df8a3ad5d4cc535127b2c286b32a2c633ec7c4295a2525367a91099ec560"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info15\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_source.rs\"\n    }\n  }\n}\n","info":{"blob":"dfb04a240d020c474379a3cb73778d2e3ffe10d0","bytes":314,"sha256":"7d330cb882efd83133db3ea61ca3ce0d139a004e0026e8ac6aecec51c62538aa"},"ranges":[{"index":0,"offset":0,"limit":19516,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body15-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_source.rs\",\n      \"offset\": 0,\n      \"limit\": 19516,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"558282880953d85b91d73873f3773764de548627","bytes":392,"sha256":"ade37ff5066fab8520db4930b1cfc220362efc9d6180e860f4bd7162b483dad8"}}]},{"index":16,"reportIndex":18,"name":"service_snapshot_forward_wire.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_wire.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire.rs","bytes":16474,"sha256":"865e1c316cec0890b3a28076b95a00eedff366bae9d0949899afe23fa044fa75","source":{"blob":"e7d14fb4237c4e2638068c91f7cb421fdc3e9f85","bytes":15616,"sha256":"458dc1a5c54dd9ee128030012c48e6a800b5e886233392894e485fdfc42fade7"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info16\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire.rs\"\n    }\n  }\n}\n","info":{"blob":"f9235ae4d4d15739a3b814566ce548984b65d8b3","bytes":312,"sha256":"e12ea61c8a97bcac5320b810253715121d3bbd26b1ea10a06fe31b9033fa831a"},"ranges":[{"index":0,"offset":0,"limit":16474,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body16-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire.rs\",\n      \"offset\": 0,\n      \"limit\": 16474,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"fb026a69fd06829da89df54ab5b4bf7ef2f13e58","bytes":390,"sha256":"f11de3416f2417b8d6fba238a17be15b31ab87d62253c8ab83f39a305faef494"}}]},{"index":17,"reportIndex":19,"name":"service_snapshot_forward_wire_tests.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_wire_tests.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire_tests.rs","bytes":11119,"sha256":"231fa3d71173939acc1316716dc2b1f27523bbd9d2da40e9a410a095a0a65ae8","source":{"blob":"7dd45fb0219ea92ad7debb45f534977875ebef9a","bytes":9844,"sha256":"c189b6999fef57fe2a5c6fc221c49647323c609f31f6d65a2eda6bcb682668cb"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info17\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire_tests.rs\"\n    }\n  }\n}\n","info":{"blob":"65f14caa8ecc00b34b554b7b84211fd2445c1c3c","bytes":318,"sha256":"3723c4915a36800837aa708e9074805fd94a51f2843d3ef055815b82f6b584ca"},"ranges":[{"index":0,"offset":0,"limit":11119,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body17-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_wire_tests.rs\",\n      \"offset\": 0,\n      \"limit\": 11119,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"2726d7e6948b919889b189f64348ac4db0ace75f","bytes":396,"sha256":"d1a016524cb42b2b06ffc9fc4798ddc9ff4dd7f9a376a17e724e081ea539ffa4"}}]},{"index":18,"reportIndex":20,"name":"service_snapshot_transfer.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_transfer.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_transfer.rs","bytes":52444,"sha256":"bfb45bc6254782644b104dbb50f9cbfc887918812f84720af09941b38d73fa1d","source":{"blob":"9dcea728cd9afd0ba9f78a65537e7cac6ccadf55","bytes":52444,"sha256":"fb6440b75feddef609a5ddf54de163f3ec4ad5ddb9d607c19586cfb000a0d223"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info18\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_transfer.rs\"\n    }\n  }\n}\n","info":{"blob":"ae25619c36dc11b8a0733e60048b85fb8beff019","bytes":308,"sha256":"0058e49959b930341d725b10959df1910d3511928eadf3eaaac011ddd92ef71c"},"ranges":[{"index":0,"offset":0,"limit":52444,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body18-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_transfer.rs\",\n      \"offset\": 0,\n      \"limit\": 52444,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"2d4aceede88fa0307a814e835311a20f537cb5d1","bytes":386,"sha256":"01aac3819d76bb3691f1a81da9080c75ca132e68af6cca1563cc0ba4e15422ae"}}]},{"index":19,"reportIndex":21,"name":"service_snapshot_v6_ha.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_v6_ha.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha.rs","bytes":13772,"sha256":"8857ecf9aa7a18ff13128c408708f1e9691cfeb84d185f77015504340c197b33","source":{"blob":"4c111e446031fda7ac88f673298ddfa6322ecc83","bytes":13609,"sha256":"43dcba00a64eb1602aa84c7c753199db6a4f748a90426f46a6aa9ea44f29d855"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info19\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha.rs\"\n    }\n  }\n}\n","info":{"blob":"b862a2683060ed60ace5d4ebda3475d680851e96","bytes":305,"sha256":"7c7bb46452675da720d9f3e4af8c7a8c3ea8560041fe9304637fcb29516de2fb"},"ranges":[{"index":0,"offset":0,"limit":13772,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body19-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha.rs\",\n      \"offset\": 0,\n      \"limit\": 13772,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"b0744c36f03abe5b8d88c625903d11c7a0033e5b","bytes":383,"sha256":"b2e4202338d577b6dbe41cc230a7695a04c2ce9d66bb1df3c05ade05df5b8d7b"}}]},{"index":20,"reportIndex":22,"name":"service_snapshot_v6_ha_restore.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha_restore.rs","bytes":47093,"sha256":"3027326105fd9865bc9dc66b3bd6fe1561de3a9a7f9c7e7efeb16bfa01ed2920","source":{"blob":"100938ae027cc78c3037187b074856b473f9b174","bytes":46836,"sha256":"f0849c391e82b82a195779db8519245b7f27446680458b58b39ba9d034d2876c"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info20\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha_restore.rs\"\n    }\n  }\n}\n","info":{"blob":"88e40b58a1775e403e52aba35ac3d1bae26d6a6a","bytes":313,"sha256":"3161d0187a69c80fa18d0d44a37a86707ab26ddca66514159384ed886050d335"},"ranges":[{"index":0,"offset":0,"limit":47093,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body20-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_v6_ha_restore.rs\",\n      \"offset\": 0,\n      \"limit\": 47093,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"5350a4c50a7f8d7542bfd20bdfcd52eddab0e424","bytes":391,"sha256":"e6dc29145737917c3293db2ede993a812306d0d15a10c7be3501964776a38609"}}]},{"index":21,"reportIndex":47,"name":"service_snapshot_forward_test_faults.rs","canonicalPath":"crates/heptabao-server/src/service_snapshot_forward_test_faults.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_test_faults.rs","bytes":5490,"sha256":"d23d5ce5f94de9906a734497631142ea348032d1bf6b241ab0438e2159378437","source":{"blob":"abc4dbef9044f6105c00fdc290fd053e1d2cbd26","bytes":5345,"sha256":"51cbdba0849307d58e3631994a9d2fe0ecaacda7f69617becb2b8b698e65bb29"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info21\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_test_faults.rs\"\n    }\n  }\n}\n","info":{"blob":"6f3d768bae3878eab116cdd3bdcf3b277da9c967","bytes":319,"sha256":"81673c14d9ca2da840a662b8fb83df0476a6f9209b754b9d808aac743c9a1ad1"},"ranges":[{"index":0,"offset":0,"limit":5490,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body21-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_snapshot_forward_test_faults.rs\",\n      \"offset\": 0,\n      \"limit\": 5490,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"d8a04064300035a00e735986aa79a2943a9f6cb5","bytes":396,"sha256":"58e1b55db9c50cec6d607f68eb06ccc344c5ad05827c64ec3f71918406f4e12a"}}]},{"index":22,"reportIndex":48,"name":"service_native_snapshot_forward_audit_tests.rs","canonicalPath":"crates/heptabao-server/src/service_native_snapshot_forward_audit_tests.rs","path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_native_snapshot_forward_audit_tests.rs","bytes":16080,"sha256":"c0cdbd2a5951991b55ae2a93c22c6585c708f280c56f89d6ff105c0fd808448e","source":{"blob":"43917b4f6547f28c097086533b4fba36ebbddb9c","bytes":14875,"sha256":"83b76edc5b8cc05de7ea748766c045d8dc67d487f82ed43d0fc614878f747c4e"},"infoRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-info22\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_native_snapshot_forward_audit_tests.rs\"\n    }\n  }\n}\n","info":{"blob":"6b4ca126156d56861dafd06cc312096e18de9d53","bytes":326,"sha256":"bce79aa028fd3c834572e733413853c9670a6a1b815a2e6147daa234df59e72f"},"ranges":[{"index":0,"offset":0,"limit":16080,"templateRaw":"{\n  \"idempotency_key\": \"heptabao-snapshot2379-format23-observe-20261106-r1-body22-00\",\n  \"operation\": {\n    \"tool\": \"binary_read\",\n    \"arguments\": {\n      \"host\": \"rog\",\n      \"path\": \"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/formatted/service_native_snapshot_forward_audit_tests.rs\",\n      \"offset\": 0,\n      \"limit\": 16080,\n      \"expected_version\": null\n    }\n  }\n}\n","template":{"blob":"7a7c47593860123c39a95b6d1669dfd0ced6139d","bytes":404,"sha256":"2275c16bc63baef4bc800790f5501b2c04361c7a26657c0694ac209596a59379"}}]}];
const GF_REPORT = {"blob":"b99fe67dc434a0d856a8caff6fe75de597d6d5ed","bytes":118925,"sha256":"5755903ce5696b6745d7af2b27a69a30e0d001697eeb85282df75eb25cea40d8"};
const GF_RELEASE = {"blob":"8f2d2d10591fb59b191378535672dc31c3df2875","bytes":3880,"sha256":"195a5f45127a5c74e965b75e96272caf91eff292f19b71aa618b8bfcbec47dc3"};
const GF_OLD_UNKNOWN = {"blob":"b174296c1b46c119356df90d5c68b6ca5bc4c19c","bytes":1629,"sha256":"8e94eed174a2e88206fb6e27685df93d404eba8512cdb052e6528690656e6f3c"};
const GF_FORMATTER_JOB = "1a1b02771c2-fc05-6e9f";
const GF_TOTAL_BYTES = 1346637;
const GF_TOTAL_RANGES = 36;
const GF_INFO_PAGE_BYTES = 8192;
const GF_BODY_PAGE_BYTES = 16384;
const GF_PAYLOAD_CAP = 1048576;

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,reportRaw,releaseRaw,oldUnknownRaw}) {
 gfNeed(load(GF_SLOT)===undefined,"fresh_context_only_never_reset_any_prior_slot");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && gfMetaEquals(reportRaw,GF_REPORT) && gfMetaEquals(releaseRaw,GF_RELEASE)
   && gfMetaEquals(oldUnknownRaw,GF_OLD_UNKNOWN),"whole_root_GO_and_original_evidence");
 const g=JSON.parse(goRaw),report=parseLosslessIntegers(reportRaw),release=JSON.parse(releaseRaw);
 gfNeed(g.authorization==="GO" && g.scope==="snapshot_formatted23_fixed_metadata_and_bodies"
   && g.slot===GF_SLOT && g.original_job===GF_FORMATTER_JOB
   && g.maximum_file_info_starts===23 && g.maximum_binary_read_starts===36
   && g.maximum_total_body_bytes===GF_TOTAL_BYTES && g.native_payload_cap===GF_PAYLOAD_CAP
   && g.metadata_page_bytes===GF_INFO_PAGE_BYTES && g.body_page_bytes===GF_BODY_PAGE_BYTES
   && g.maximum_status_calls_per_observer===8 && g.maximum_native_futures===1
   && g.process_start_authorized===false && g.old_unknown_preserved===true
   && Array.isArray(g.info_requests) && g.info_requests.length===23
   && g.info_requests.every((p,i)=>p.blob===GF_OUTPUTS[i].info.blob
     && p.bytes===GF_OUTPUTS[i].info.bytes && p.sha256===GF_OUTPUTS[i].info.sha256)
   && Array.isArray(g.body_templates) && g.body_templates.length===36
   && g.body_templates.every((p,i)=>{const n=GF_OUTPUTS.flatMap(x=>x.ranges.map(r=>r.template))[i];
     return p.blob===n.blob && p.bytes===n.bytes && p.sha256===n.sha256;})
   && g.report.blob===GF_REPORT.blob && g.report.sha256===GF_REPORT.sha256
   && g.report.bytes===GF_REPORT.bytes,"exact_root_fixed23_conditional36_scope");
 gfNeed(release.lineBReleased===true && release.currentToolCallsInFlight===0
   && release.currentOwnedFutureObservedActive===false && release.currentPending===null
   && release.currentActiveObserver===null && release.currentPaused===false
   && report.status==="passed" && report.allOwnedStopped===true
   && report.allFixedSourceInputsUnchanged===true && report.withinDeadline===true
   && report.compileExecuted===false && report.productExecuted===false
   && report.sourceCommit==="2379d02ba1ee3e88989815d5a978f998822bac4f"
   && report.sourceTree==="fc933c18a0415730e3658c17ff021db9b2df2caa"
   && report.files.length===49,"original_formatter_report_and_closed_reading");
 const changed=report.files.filter(x=>x.beforeBytes!==x.afterBytes||x.beforeSha256!==x.afterSha256);
 gfNeed(changed.length===23 && changed.reduce((n,x)=>n+x.afterBytes,0)===GF_TOTAL_BYTES
   && changed.every((x,i)=>x.name===GF_OUTPUTS[i].name && x.afterBytes===GF_OUTPUTS[i].bytes
     && x.afterSha256===GF_OUTPUTS[i].sha256
     && x.beforeBytes===GF_OUTPUTS[i].source.bytes && x.beforeSha256===GF_OUTPUTS[i].source.sha256),
   "only_actual_changed_output_set");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,job:GF_FORMATTER_JOB,
   pending:null,activeObserver:null,nativeCallInFlight:false,paused:false,calls:{},
   completedObservers:[],admissionsCalled:0,bodyBytes:0,outputFiles:[],
   outputInfos:Array(23).fill(null),outputRanges:GF_OUTPUTS.map(()=>[]),
   infoStarted:Array(23).fill(false),bodyStarted:GF_OUTPUTS.map(x=>x.ranges.map(()=>false)),
   originalReport:GF_REPORT,originalRelease:GF_RELEASE,oldUnknown:GF_OLD_UNKNOWN,
   localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
 return {slot:GF_SLOT,metadata:23,ranges:GF_TOTAL_RANGES,totalBodyBytes:GF_TOTAL_BYTES,
   noNativeCalled:true,oldUnknownPreserved:true};
}

function gfNextFixedRequest(s) {
 const i=s.outputFiles.length,row=GF_OUTPUTS[i];
 gfNeed(Number.isSafeInteger(i) && i>=0 && i<23,"fixed_output_set_complete_or_invalid");
 if(s.outputInfos[i]===null) {
  gfNeed(s.infoStarted[i]===false,"metadata_already_called_no_retry");
  gfNeed(gfMetaEquals(row.infoRaw,row.info),"fixed_info_request_pin");
  return {fileIndex:i,rangeIndex:null,raw:row.infoRaw,pin:row.info,tool:"file_info"};
 }
 const j=s.outputRanges[i].length,range=row.ranges[j],info=s.outputInfos[i];
 gfNeed(range && s.bodyStarted[i][j]===false && info.path===row.path
   && info.size===row.bytes && info.sha256===row.sha256
   && typeof info.version==="string","qualified_current_info_before_next_fixed_range");
 const template=JSON.parse(range.templateRaw);
 gfNeed(gfMetaEquals(range.templateRaw,range.template)
   && template.operation.arguments.expected_version===null,"frozen_null_version_template");
 template.operation.arguments.expected_version=info.version;
 const raw=JSON.stringify(template,null,2)+"\n";
 return {fileIndex:i,rangeIndex:j,raw,pin:gitBlobMeta(raw),template:range.template,tool:"binary_read"};
}
function gfVerifyOutputInfo(row,v,operationId) {
 const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
 gfNeed(v.path===row.path && v.size===row.bytes && v.sha256===row.sha256 && v.mode===384
   && md?.metadata_platform==="linux" && md.mode===384
   && md.uid===1000 && md.gid===1000 && md.link_count===1
   && parts.length===5 && parts.every(x=>/^(0|[1-9][0-9]*)$/.test(x))
   && parts[2]===String(v.size),"fixed_output_actual_metadata_and_exact_content");
 const full9=[parts[0],parts[1],"1000","1000","33152","1",String(v.size),parts[3],parts[4]];
 return {index:row.index,path:v.path,size:v.size,sha256:v.sha256,version:v.version,
   originalOperation:operationId,full9Strings:full9,firstOutputIdentityObservation:true,
   originalSourceInputIdentityReused:false,regularFileFromNativeFileInfoContract:true};
}
function gfVerifyOutputChunk(row,info,ranges,request,v,operationId,nativePin) {
 const j=ranges.length,range=row.ranges[j],args=request.operation.arguments;
 gfNeed(range && request.operation.tool==="binary_read" && args.host==="rog"
   && args.path===row.path && args.offset===range.offset && args.limit===range.limit
   && args.expected_version===info.version && v.path===row.path && v.version===info.version
   && v.size===row.bytes && v.offset===range.offset
   && v.next_offset===range.offset+range.limit && v.eof===(v.next_offset===row.bytes)
   && typeof v.data_base64==="string" && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
   "exact_output_range_path_version_extent");
 const bytes=unb64(v.data_base64);
 gfNeed(bytes.length===range.limit && bytes.length<=65536
   && sha256Latin1(byteString(bytes))===v.chunk_sha256
   && (j===0?range.offset===0:ranges[j-1].next===range.offset),
   "exact_output_chunk_bytes_and_SHA_no_UTF8_decode");
 return {index:j,offset:range.offset,next:v.next_offset,limit:range.limit,
   base64:v.data_base64,chunkSha256:v.chunk_sha256,operationId,nativeText:nativePin,
   sourceFileVersion:v.version};
}
function gfVerifyWholeOutput(row,ranges) {
 gfNeed(ranges.length===row.ranges.length,"all_fixed_file_ranges_before_decode");
 let bytes=[],next=0;
 for(const range of ranges) {
  gfNeed(range.offset===next,"whole_file_range_continuity");
  const chunk=unb64(range.base64);
  gfNeed(chunk.length===range.limit && sha256Latin1(byteString(chunk))===range.chunkSha256,
    "retained_chunk_bytes_unchanged");
  bytes=bytes.concat(chunk);next=range.next;
 }
 gfNeed(next===row.bytes && bytes.length===row.bytes
   && sha256Latin1(byteString(bytes))===row.sha256,"whole_file_bytes_SHA_before_UTF8");
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 gfNeed(pin.bytes===row.bytes && pin.sha256===row.sha256,"whole_UTF8_lossless_roundtrip");
 return {raw,pin};
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="operation_start") {
  gfNeed(s.activeObserver===null && s.admissionsCalled<59,"one_unclosed_observer_and_total59");
  const next=gfNextFixedRequest(s);
  gfNeed(raw===next.raw && gfMetaEquals(raw,next.pin)
    && Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && typeof q.idempotency_key==="string" && q.idempotency_key.length<=128
    && Object.keys(q.operation).sort().join(",")==="arguments,tool"
    && q.operation.tool===next.tool && q.operation.arguments.host==="rog",
    "only_exact_next_fixed_info_or_conditionally_bound_body");
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && s.activeObserver.statusCalled<8 && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status_max8");
 } else if(kind==="operation_result") {
  const a=s.activeObserver,width=a?.tool==="binary_read"?GF_BODY_PAGE_BYTES:GF_INFO_PAGE_BYTES;
  gfNeed(a?.futureClosed===true && a.pageCalled<(a.tool==="binary_read"?64:128)
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===a.id && q.limit===width && q.offset===a.nextPageOffset && !a.eof,
   "same_closed_original_operation_next_bounded_page");
 } else throw new Error("read_only_closed_native_tool_set");
}
/* Explicit root-directed retrieval of one failed delivery from a closed operation.
 * This never reissues file_info or creates a Native future. The failed call stays
 * called=true with its original SDK; a separate recovery call records the new read.
 */
async function gfPrepareClosedInfo10Page0Recovery({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),oldKey="sf23-r1-f10-info-p0",callKey=oldKey+"-recovery1";
 const old=s.calls[oldKey],a=s.activeObserver;
 const requestPin={blob:"916332b53c58b018404b00324cb5aa1588975b52",bytes:121,
  sha256:"17f7fcfad72f016c11d8d7b0be379eb4f2043b20b9c33cc4698bb78d74173edd"};
 const errorPin={blob:"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011",bytes:248,
  sha256:"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"};
 const operationId="37a07e380c8f74019d9b6c20c86cfa339d409e3b6d01b42b3a4230cb767777dc";
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"whole_separate_page_recovery_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="snapshot_formatted23_info10_page0_retrieval_recovery"
  && g.slot===GF_SLOT && g.original_operation===operationId
  && g.failed_call_key===oldKey && g.recovery_call_key===callKey
  && g.request?.blob===requestPin.blob && g.request?.bytes===requestPin.bytes
  && g.request?.sha256===requestPin.sha256
  && g.failed_sdk?.blob===errorPin.blob && g.failed_sdk?.bytes===errorPin.bytes
  && g.failed_sdk?.sha256===errorPin.sha256
  && g.maximum_recovery_page_calls===1 && g.page_bytes===8192
  && g.native_payload_cap===1048576 && g.operation_start_authorized===false
  && g.operation_status_authorized===false && g.failed_call_preserved===true
  && g.continue_original_table_only_after_info_closed===true
  && g.original_go==="25ea12c4406a12ba5ce263b10a2723f73276d74b",
  "exact_closed_info_page_only_scope");
 gfNeed(s.paused===true && s.pending===oldKey && !s.nativeCallInFlight
  && s.info10Page0Recovery===undefined && !s.calls[callKey]
  && s.goPin.blob===g.original_go && old?.kind==="operation_result"
  && old.called===true && old.phase==="native_interpretation_refused"
  && old.sdkArchive?.whole===true && gfMetaEquals(old.requestRaw,requestPin)
  && old.sdkPin.blob===errorPin.blob
  && gfMetaEquals(load(GF_SLOT+":original_sdk_raw:"+oldKey),errorPin),
  "unchanged_original_failed_delivery_and_once_recovery");
 const request=JSON.parse(old.requestRaw);
 gfNeed(Object.keys(request).sort().join(",")==="limit,offset,operation_id"
  && request.operation_id===operationId && request.offset===0 && request.limit===8192
  && a?.id===operationId && a.tool==="file_info" && a.futureClosed===true
  && a.nextPageOffset===0 && a.eof===false && a.pages.length===0
  && a.total===null && a.digest===null && a.statusCalled===1 && a.pageCalled===1
  && s.outputFiles.length===10 && s.completedObservers.length===26
  && s.admissionsCalled===27 && s.bodyBytes===574522
  && s.infoStarted[10]===true && s.outputInfos[10]===null
  && s.bodyStarted[10].every(x=>x===false) && s.infoStarted[11]===false,
  "actual_closed_info10_before_any_body_or_later_file");
 const statusKey="sf23-r1-f10-info-s0",statusCall=s.calls[statusKey];
 const statusPin={blob:"4e720931e08072dc1d769dcd3e5dd5fccb69e6d1",bytes:800,
  sha256:"f31c15d37576e29ccedaefa2d38e3eb9cc631b7d768a8fa7b70306d1d7c8d1e3"};
 const statusRaw=load(GF_SLOT+":native_raw:"+statusKey);
 gfNeed(statusCall?.called===true && statusCall.phase==="accepted"
  && statusCall.sdkArchive?.whole===true && gfMetaEquals(statusRaw,statusPin),
  "original_completed_status_identity");
 const status=parseLosslessIntegers(statusRaw);
 gfNeed(status.operation_id===operationId && status.async_state==="completed"
  && status.result_state==="stored_observed" && status.owned_future_active===false
  && status.payload_available===true,"original_future_already_closed");
 const failedCallRaw=JSON.stringify(old,null,2)+"\n";
 const before={pending:s.pending,paused:s.paused,failedCall:gitBlobMeta(failedCallRaw),
  admissionsCalled:s.admissionsCalled,bodyBytes:s.bodyBytes,pageCalled:a.pageCalled,
  completedObservers:s.completedObservers.length,wholeFiles:s.outputFiles.length};
 const intent={schema:"heptabao.gitfirst.closed-immutable-page-recovery-intent.r1",
  callKey,kind:"operation_result",request:requestPin,rootRecoveryGo:goPin,
  originalRootGo:s.goPin,originalOperation:operationId,originalFailedSDK:errorPin,
  originalFailedCall:before.failedCall,originalCompletedStatus:statusPin,
  maximumNativeCalls:1,nativeNotYetCalled:true,noNativeAdmission:true,
  notRecoveryOfOriginalSDK:true,originalFailureRemains:true,before};
 const armed={...intent,schema:"heptabao.gitfirst.closed-immutable-page-recovery-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,automaticRetry:false};
 s.info10Page0Recovery={phase:"arming",goRaw,goPin,before,oldKey,callKey,
  oldFailureUnchanged:true,request:requestPin};
 s.calls[callKey]={kind:"operation_result",requestRaw:old.requestRaw,requestPin,
  phase:"arming",called:false,recoveryOfDelivery:oldKey};
 gfSave(s);
 const archive=await archiveFlatPublicTextsOnce({
  key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"request.json":old.requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
   "armed.json":JSON.stringify(armed,null,2)+"\n","original-failed-call.json":failedCallRaw}});
 gfNeed(archive.whole===true && s.pending===oldKey && s.paused===true
  && !s.nativeCallInFlight && JSON.stringify(s.calls[oldKey],null,2)+"\n"===failedCallRaw,
  "whole_arm_and_original_failure_preserved");
 s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";
 s.info10Page0Recovery.phase="armed_whole";
 s.pending=callKey;s.paused=false;gfSave(s);
 return {callKey,request:requestPin,armedTree:archive.tree,nativeCalled:false,
  originalFailedCallPreserved:true,originalFutureAlreadyClosed:true};
}

/* Exact BODY16 page0 delivery recovery only; no binary_read/status admission.
 * Original failed call, prior INFO10 recovery and all counters remain preserved.
 * A successful first payload page may be non-EOF; original continuation uses the
 * resulting actual offset and monotonically advanced pageCalled (next label p2).
 */
async function gfPrepareClosedBody16Page0Recovery({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),oldKey="sf23-r1-f16-b00-p0",callKey=oldKey+"-recovery1";
 const old=s.calls[oldKey],a=s.activeObserver;
 const requestPin={blob:"bfd96536330ccc3704a2ba596203edf3680a0702",bytes:122,
  sha256:"ede3d944c75b34dbcc7cf3b644e9d8374496f8348d375e792d565141c92b2ef5"};
 const errorPin={blob:"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011",bytes:248,
  sha256:"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"};
 const operationId="9037480fbf014345c1d2bbe1894020e30602a9adb2d8c1a864f6eff35368f1b0";
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"whole_separate_page_recovery_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="snapshot_formatted23_body16_page0_retrieval_recovery"
  && g.slot===GF_SLOT && g.original_operation===operationId
  && g.failed_call_key===oldKey && g.recovery_call_key===callKey
  && g.request?.blob===requestPin.blob && g.request?.bytes===requestPin.bytes
  && g.request?.sha256===requestPin.sha256
  && g.failed_sdk?.blob===errorPin.blob && g.failed_sdk?.bytes===errorPin.bytes
  && g.failed_sdk?.sha256===errorPin.sha256
  && g.maximum_recovery_page_calls===1 && g.page_bytes===16384
  && g.native_payload_cap===1048576 && g.operation_start_authorized===false
  && g.operation_status_authorized===false && g.failed_call_preserved===true
  && g.continue_original_observer_after_recovered_page===true
  && g.continue_original_table_only_after_file_whole===true
  && g.original_go==="25ea12c4406a12ba5ce263b10a2723f73276d74b",
  "exact_closed_body16_page_only_scope");
 gfNeed(s.paused===true && s.pending===oldKey && !s.nativeCallInFlight
  && s.body16Page0Recovery===undefined && !s.calls[callKey]
  && s.goPin.blob===g.original_go && old?.kind==="operation_result"
  && old.called===true && old.phase==="native_interpretation_refused"
  && old.sdkArchive?.whole===true && gfMetaEquals(old.requestRaw,requestPin)
  && old.sdkPin.blob===errorPin.blob
  && gfMetaEquals(load(GF_SLOT+":original_sdk_raw:"+oldKey),errorPin),
  "unchanged_original_failed_delivery_and_once_recovery");
 const failedCallPin={blob:"593f02daca6b8ac9511ed460af8919eed0b7bc32",bytes:2066,
  sha256:"f70e2ae9bac4c87df0faac3a2fbd4e507a64db29d4d1b010b3771028465d7776"};
 const infoPin={blob:"49c3c0f34cf3a033a8fea1f6b0a8c3fb8132c133",bytes:1078,
  sha256:"bc8d572b9f7bcfcbe0ce1d7f98692c2ca3430aa35ec34b181db50fbf84de6086"};
 const bodyRequestPin={blob:"143e9be276d829ff48959b3b43f2e886deab6a9b",bytes:448,
  sha256:"b175517b8290a3d3b3f835d839d3abe72ef55f7fa13dcbcd5353e57eeee349e2"};
 gfNeed(g.failed_call?.blob===failedCallPin.blob && g.failed_call?.bytes===failedCallPin.bytes
  && g.failed_call?.sha256===failedCallPin.sha256
  && gfMetaEquals(JSON.stringify(old,null,2)+"\n",failedCallPin)
  && gfMetaEquals(JSON.stringify(s.outputInfos[16],null,2)+"\n",infoPin),
  "exact_original_failed_call_and_actual_INFO16");
 const bodyCall=s.calls["sf23-r1-f16-b00-admit"];
 gfNeed(bodyCall?.phase==="accepted" && bodyCall.called===true
  && bodyCall.sdkArchive?.whole===true && gfMetaEquals(bodyCall.requestRaw,bodyRequestPin)
  && JSON.stringify(a?.request)===JSON.stringify(JSON.parse(bodyCall.requestRaw)),
  "exact_already_submitted_version_bound_body_only");
 const priorInfo10Raw=JSON.stringify(s.calls["sf23-r1-f10-info-p0"],null,2)+"\n";
 const priorInfo10RecoveryRaw=JSON.stringify(s.info10Page0Recovery);
 gfNeed(gfMetaEquals(priorInfo10Raw,{blob:"2b64176574dbb70da660cb4ec8eee657b1969eae",bytes:2065,
  sha256:"1d91200c87b3f9ae88631471212dae416cf697d341d0436ed7b8ea1db9ebc84b"})
  && s.calls["sf23-r1-f10-info-p0-recovery1"]?.phase==="accepted"
  && s.info10Page0Recovery?.oldFailureUnchanged===true,
  "prior_INFO10_failure_and_recovery_unchanged");
 const request=JSON.parse(old.requestRaw);
 gfNeed(Object.keys(request).sort().join(",")==="limit,offset,operation_id"
  && request.operation_id===operationId && request.offset===0 && request.limit===16384
  && a?.id===operationId && a.tool==="binary_read" && a.futureClosed===true
  && a.nextPageOffset===0 && a.eof===false && a.pages.length===0
  && a.total===null && a.digest===null && a.statusCalled===1 && a.pageCalled===1
  && s.outputFiles.length===16 && s.completedObservers.length===46
  && s.admissionsCalled===47 && s.bodyBytes===1184165
  && s.infoStarted[16]===true && s.outputInfos[16]!==null
  && s.bodyStarted[16].length===1 && s.bodyStarted[16][0]===true
  && s.outputRanges[16].length===0 && s.infoStarted[17]===false,
  "actual_closed_body16_before_any_later_file");
 const statusKey="sf23-r1-f16-b00-s0",statusCall=s.calls[statusKey];
 const statusPin={blob:"237b2709d1ca13c6b56fdd4be8012920bac38b7a",bytes:802,
  sha256:"9b667dd791f4fb7a67710f127b0b4475d9c15ca9b5e09b45c67f22410bc769b3"};
 const statusRaw=load(GF_SLOT+":native_raw:"+statusKey);
 gfNeed(statusCall?.called===true && statusCall.phase==="accepted"
  && statusCall.sdkArchive?.whole===true && gfMetaEquals(statusRaw,statusPin),
  "original_completed_status_identity");
 const status=parseLosslessIntegers(statusRaw);
 gfNeed(status.operation_id===operationId && status.async_state==="completed"
  && status.result_state==="stored_observed" && status.owned_future_active===false
  && status.payload_available===true,"original_future_already_closed");
 const failedCallRaw=JSON.stringify(old,null,2)+"\n";
 const before={pending:s.pending,paused:s.paused,failedCall:gitBlobMeta(failedCallRaw),
  admissionsCalled:s.admissionsCalled,bodyBytes:s.bodyBytes,pageCalled:a.pageCalled,
  completedObservers:s.completedObservers.length,wholeFiles:s.outputFiles.length};
 const intent={schema:"heptabao.gitfirst.closed-immutable-page-recovery-intent.r1",
  callKey,kind:"operation_result",request:requestPin,rootRecoveryGo:goPin,
  originalRootGo:s.goPin,originalOperation:operationId,originalFailedSDK:errorPin,
  originalFailedCall:before.failedCall,originalCompletedStatus:statusPin,
  maximumNativeCalls:1,nativeNotYetCalled:true,noNativeAdmission:true,
  notRecoveryOfOriginalSDK:true,originalFailureRemains:true,before};
 const armed={...intent,schema:"heptabao.gitfirst.closed-immutable-page-recovery-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,automaticRetry:false};
 s.body16Page0Recovery={phase:"arming",goRaw,goPin,before,oldKey,callKey,
  oldFailureUnchanged:true,request:requestPin};
 s.calls[callKey]={kind:"operation_result",requestRaw:old.requestRaw,requestPin,
  phase:"arming",called:false,recoveryOfDelivery:oldKey};
 gfSave(s);
 const archive=await archiveFlatPublicTextsOnce({
  key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"request.json":old.requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
   "armed.json":JSON.stringify(armed,null,2)+"\n","original-failed-call.json":failedCallRaw}});
 gfNeed(archive.whole===true && s.pending===oldKey && s.paused===true
  && !s.nativeCallInFlight && JSON.stringify(s.calls[oldKey],null,2)+"\n"===failedCallRaw,
  "whole_arm_and_original_failure_preserved");
 gfNeed(JSON.stringify(s.calls["sf23-r1-f10-info-p0"],null,2)+"\n"===priorInfo10Raw
  && JSON.stringify(s.info10Page0Recovery)===priorInfo10RecoveryRaw,
  "prior_INFO10_history_unchanged_after_new_arm");
 s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";
 s.body16Page0Recovery.phase="armed_whole";
 s.pending=callKey;s.paused=false;gfSave(s);
 return {callKey,request:requestPin,armedTree:archive.tree,nativeCalled:false,
  originalFailedCallPreserved:true,originalFutureAlreadyClosed:true};
}

async function gfPrepareOne({callKey,kind,requestRaw}) {
 const s=gfState();
 gfNeed(/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey) && !s.calls[callKey],"fresh_call_record");
 const q=JSON.parse(requestRaw); // Public exact request, no native response.
 gfValidateRequest(s,kind,q,requestRaw);
 const requestPin=gitBlobMeta(requestRaw);
 const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",
  callKey,kind,request:requestPin,
  rootGo:s.goPin,
  originalJob:s.job,
  originalOperation:s.activeObserver?.id??null,maximumNativeCalls:1,
  nativeNotYetCalled:true,lossOfAcknowledgmentNeverGrantsReplay:true,
  localFirstExplicitlyReplacedByExactRootGO:true};
 const armed={...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,
  recovery:"Read exact original job/operation only; absence of later ACK is UNKNOWN."};
 s.pending=callKey;
 s.calls[callKey]={kind,requestRaw,requestPin,phase:"arming",called:false};
 gfSave(s);
 try {
  const archive=await archiveFlatPublicTextsOnce({
   key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"request.json":requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
          "armed.json":JSON.stringify(armed,null,2)+"\n"}});
  s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";gfSave(s);
  return {callKey,armedTree:archive.tree,request:requestPin,nativeCalled:false};
 } catch(error) {
  s.paused=true;s.calls[callKey].archiveFailure=String(error);gfSave(s);throw error;
 }
}
async function gfInvokePreparedOnce(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===callKey
  && c?.phase==="armed_whole" && c.armed?.whole===true && !c.called,
  "completed_external_arm_before_once_call");
 const q=JSON.parse(c.requestRaw);
 gfNeed(gfMetaEquals(c.requestRaw,c.requestPin),"armed_request_unchanged");
 let fixedNext=null;
 if(c.kind==="operation_start") {
  fixedNext=gfNextFixedRequest(s);
  gfNeed(fixedNext.raw===c.requestRaw,"armed_fixed_request_still_current");
 }
 c.called=true;c.phase="native_call_entered";s.nativeCallInFlight=true;
 if(c.kind==="operation_start") {
  if(fixedNext.tool==="file_info")s.infoStarted[fixedNext.fileIndex]=true;
  else s.bodyStarted[fixedNext.fileIndex][fixedNext.rangeIndex]=true;
  s.admissionsCalled+=1;
 }
 if(c.kind==="operation_status")s.activeObserver.statusCalled+=1;
 if(c.kind==="operation_result")s.activeObserver.pageCalled+=1;
 gfSave(s); // No await or second dispatch between this marker and the one call.
 let sdk;
 try {
  if(c.kind==="operation_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q);
  else if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);
  else if(c.kind==="operation_result")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);
  else throw new Error("unreachable_closed_dispatch_kind");
 } catch(error) {
  const record={name:error.name,message:String(error.message),nativeCallMayHaveCompleted:true,
    originalRequest:c.requestPin,replayAllowed:false};
  store(GF_SLOT+":native_exception:"+callKey,record); // Preserve before any Git operation.
  s.nativeCallInFlight=false;s.paused=true;c.phase="transport_unknown";gfSave(s);
  try {c.exceptionArchive=await archiveFlatPublicTextsOnce({
   key:"gfx-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"transport-exception.json":JSON.stringify(record,null,2)+"\n"}});gfSave(s);}
  catch(archiveError){store(GF_SLOT+":exception_archive_error:"+callKey,String(archiveError));}
  throw error;
 }
 store(GF_SLOT+":original_sdk:"+callKey,sdk); // First operation on the returned SDK.
 recordGitSDKImmutable(GF_SLOT+":native:"+callKey,"original_return",sdk);
 s.nativeCallInFlight=false;c.phase="sdk_returned_uninterpreted";gfSave(s);
 const raw=JSON.stringify(sdk,null,2)+"\n";
 store(GF_SLOT+":original_sdk_raw:"+callKey,raw);
 c.sdkPin=gitBlobMeta(raw);gfSave(s);
 try {
  c.sdkArchive=await archiveFlatPublicTextsOnce({
   key:"gfs-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"original.sdk.json":raw}});
  c.phase="sdk_whole_uninterpreted";gfSave(s);
  return {callKey,sdk:c.sdkPin,tree:c.sdkArchive.tree,interpreted:false};
 } catch(error) {
  // The native response remains in store. Recover only the identical Git objects.
  s.paused=true;c.phase="sdk_git_archive_unresolved";c.archiveFailure=String(error);
  gfSave(s);throw error;
 }
}
function gfAcceptArchivedSDK(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && s.pending===callKey && !s.nativeCallInFlight
  && c?.phase==="sdk_whole_uninterpreted" && c.sdkArchive?.whole===true,
  "SDK_whole_before_isError");
 const raw=load(GF_SLOT+":original_sdk_raw:"+callKey);
 gfNeed(gfMetaEquals(raw,c.sdkPin),"whole_SDK_unchanged");
 const sdk=JSON.parse(raw); // Only now interpret isError/shape/native contents.
 try {
  gfNeed(sdk.isError!==true,"native_tool_error_preserved_stop");
  gfNeed(sdk.content?.length===1 && sdk.content[0].type==="text",
         "single_original_native_text");
  const nativeRaw=sdk.content[0].text;
  store(GF_SLOT+":native_raw:"+callKey,nativeRaw);
  const v=parseLosslessIntegers(nativeRaw),q=JSON.parse(c.requestRaw);
  if(c.kind==="operation_start") {
   gfNeed(/^[a-f0-9]{64}$/.test(v.operation_id) && v.tool_name===q.operation.tool
     && v.reused===false && v.automatic_retry===false,"original_observer_admission");
   s.activeObserver={id:v.operation_id,request:q,tool:v.tool_name,futureClosed:false,
    nextPageOffset:0,eof:false,pages:[],total:null,digest:null,statusCalled:0,pageCalled:0};
  } else if(c.kind==="operation_status") {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.tool_name===a.tool && v.automatic_retry===false,
          "same_original_status");
   if(v.async_state==="completed") {
    gfNeed(v.owned_future_active===false && v.result_state==="stored_observed"
      && v.payload_available===true,"completed_original_payload_available");
    a.futureClosed=true;
   } else gfNeed(v.async_state==="running" || v.async_state==="queued",
                 "unexpected_original_status_stop");
  } else {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.offset===q.offset && v.immutable_snapshot===true
    && v.payload_kind==="native_result"
    && v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
    && Number.isSafeInteger(v.total_bytes) && v.total_bytes>=0 && v.total_bytes<=1048576
    && /^[a-f0-9]{64}$/.test(v.result_sha256),"exact_original_immutable_payload");
   const b=unb64(v.data_base64);
   gfNeed(b.length<=(a.tool==="binary_read"?16384:8192) && v.next_offset===q.offset+b.length
     && v.next_offset<=v.total_bytes && v.eof===(v.next_offset===v.total_bytes)
     && (b.length>0||v.eof),"exact_original_page_extent");
   gfNeed(a.total===null || (a.total===v.total_bytes && a.digest===v.result_sha256),
          "one_original_payload_identity");
   if(c.recoveryOfDelivery==="sf23-r1-f10-info-p0")
    gfNeed(v.eof===true && q.offset===0 && v.total_bytes===b.length,
           "single_recovery_page_must_complete_original_info_payload");
   a.total=v.total_bytes;a.digest=v.result_sha256;
   a.pages.push({offset:q.offset,next:v.next_offset,base64:v.data_base64,
                 originalSDK:c.sdkPin,nativeText:gitBlobMeta(nativeRaw)});
   a.nextPageOffset=v.next_offset;a.eof=v.eof;
  }
  c.nativePin=gitBlobMeta(nativeRaw);c.phase="accepted";
  s.pending=null;gfSave(s);
  return {callKey,nativeRaw,value:v,job:s.job,operation:s.activeObserver?.id??null,
          nativeCallInFlight:false};
 } catch(error) {
  s.paused=true;c.phase="native_interpretation_refused";c.interpretationFailure=String(error);
  gfSave(s);throw error;
 }
}
async function gfCloseOriginalObserver() {
 const s=gfState(),a=s.activeObserver;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && a?.futureClosed===true && a.eof,"closed_whole_original_observer_boundary");
 let bytes=[],next=0;
 for(const page of a.pages) {
  gfNeed(page.offset===next,"page_continuity");
  bytes=bytes.concat(unb64(page.base64));next=page.next;
 }
 gfNeed(next===a.total && bytes.length===a.total,"complete_original_payload_length");
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 gfNeed(pin.bytes===a.total && pin.sha256===a.digest,"complete_original_payload_hash");
 let archive;
 try {
  archive=await archiveFlatPublicTextsOnce({
   key:"gfc-"+a.id,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"payload.original.json":raw}});
 } catch(error) {
  s.paused=true;s.originalPayloadArchiveFailure=String(error);gfSave(s);throw error;
 }
 const p=parseLosslessIntegers(raw);
 try {
  gfNeed(p.resultType==="complete" && p.isError===false
    && p.content?.length===1 && p.content[0].type==="text","original_native_result_success");
  const nativeRaw=p.content[0].text,v=parseLosslessIntegers(nativeRaw),nativePin=gitBlobMeta(nativeRaw);
  const i=s.outputFiles.length,row=GF_OUTPUTS[i];
  gfNeed(row && i<23,"fixed_output_index");
  let wholeFile=null;
  if(a.tool==="file_info") {
   gfNeed(s.infoStarted[i]===true && s.outputInfos[i]===null
     && a.request.operation.arguments.path===row.path,"once_current_output_info");
   const info=gfVerifyOutputInfo(row,v,a.id);
   info.nativeText=nativePin;info.originalPayload=pin;
   s.outputInfos[i]=info;
  } else {
   gfNeed(a.tool==="binary_read" && s.outputInfos[i]!==null,"metadata_before_output_body");
   const j=s.outputRanges[i].length;
   gfNeed(s.bodyStarted[i][j]===true,"once_current_output_range");
   const range=gfVerifyOutputChunk(row,s.outputInfos[i],s.outputRanges[i],
     a.request,v,a.id,nativePin);
   s.outputRanges[i].push(range);s.bodyBytes+=range.limit;
   gfNeed(s.bodyBytes<=GF_TOTAL_BYTES,"fixed_total_body_bytes");
   if(s.outputRanges[i].length===row.ranges.length) {
    const complete=gfVerifyWholeOutput(row,s.outputRanges[i]);
    store(GF_SLOT+":whole_output_raw:"+i,complete.raw);
    gfSave(s); // Retain complete bytes and all original ranges before Git mutation.
    let fileArchive;
    try {
     fileArchive=await archiveFlatPublicTextsOnce({
      key:"gfo23-"+a.id,repository:"TrillionniumFoundation/HeptaBao",
      texts:{"formatted-output.rs":complete.raw}});
    } catch(error) {
     s.paused=true;s.wholeFileArchiveFailure={index:i,pin:complete.pin,error:String(error)};
     gfSave(s);throw error;
    }
    gfNeed(fileArchive.whole===true,"whole_output_Git_before_next_file");
    wholeFile={index:i,name:row.name,path:row.path,body:complete.pin,
      bodyTree:fileArchive.tree,version:s.outputInfos[i].version,
      full9Strings:s.outputInfos[i].full9Strings,
      metadataOperation:s.outputInfos[i].originalOperation,
      ranges:s.outputRanges[i].map(r=>({offset:r.offset,next:r.next,limit:r.limit,
        chunkSha256:r.chunkSha256,originalOperation:r.operationId,nativeText:r.nativeText})),
      wholeUTF8DecodedAfterByteSHA:true,semanticQualification:false};
    s.outputFiles.push(wholeFile);
   }
  }
  const original={id:a.id,tool:a.tool,payload:pin,payloadTree:archive.tree,
    nativeText:nativePin,pages:a.pages.length,completedInactive:true};
  s.completedObservers.push(original);s.activeObserver=null;
  store(GF_SLOT+":closed_native:"+a.id,nativeRaw);
  if(s.outputFiles.length===23) {
   gfNeed(s.admissionsCalled===59 && s.completedObservers.length===59
     && s.bodyBytes===GF_TOTAL_BYTES && s.infoStarted.every(x=>x===true)
     && s.bodyStarted.every(x=>x.every(v=>v===true))
     && s.outputInfos.every(x=>x!==null),"exact59_observers23_whole_files_total_bytes");
   s.allFixedOutputReadingClosed=true;
  }
  gfSave(s);
  return {original,nativeRaw,value:v,wholeFile,completedFiles:s.outputFiles.length,
    totalBodyBytes:s.bodyBytes,allFixedOutputReadingClosed:s.allFixedOutputReadingClosed===true};
 } catch(error) {
  s.paused=true;gfSave(s);throw error;
 }
}
/* Recovery rule (not automatic):
 * If any Git mutation ACK is unclear, use its stored expectedTree/entries/texts
 * only for immutable Git GET and exact whole comparison. Never call create_tree
 * again. If a native ACK is unclear, keep the armed record UNKNOWN; never rerun
 * gfInvokePreparedOnce or create a new native key. Root directs same-ID/job reads.
 * A cache loss requires restoring the external armed/SDK objects and call map.
 * Initialization from an empty store must not replace such an earlier context.
 */


/* Git-only recovery, never a second mutation or native call. The caller retains
 * the original prepared-state map; it may inspect the returned completion and
 * request root review. This function does not unpause or dispatch anything. */
async function gfReconcileSameGitArchiveReadOnly(archiveKey) {
 const prefix="pure_git_once:"+archiveKey,prior=load(prefix);
 gfNeed(prior && prior.expectedTree && prior.entries && prior.texts,
        "original_git_admission_required_no_guessed_content");
 const treeSDK=await tools.mcp__codex_apps__github_fetch({
  url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"
      +prior.expectedTree+"?recursive=1"});
 recordGitSDKImmutable(prefix,"recovery_tree",treeSDK);
 store(prefix+":recovery_tree_sdk",treeSDK);
 gfNeed(treeSDK.isError!==true,"original_expected_tree_not_observed");
 const treeText=treeSDK.structuredContent?.content;
 gfNeed(typeof treeText==="string","original_tree_text");
 const tree=JSON.parse(treeText);
 const audit=gitTreeAudit(tree);
 gfNeed(audit.root_sha===prior.expectedTree && audit.leaf_count===prior.entries.length,
        "original_expected_tree_complete");
 const expected=new Map(prior.entries.map(x=>[x.path,x]));
 gfNeed(tree.tree.filter(x=>x.type==="blob").every(x=>expected.get(x.path)?.blob===x.sha
   && x.mode==="100644"),"original_exact_tree_members");
 const verified=[];
 for(const x of prior.entries) {
  const sdk=await tools.mcp__codex_apps__github_fetch_blob({
   repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:x.blob});
  recordGitSDKImmutable(prefix,"recovery_whole:"+x.path,sdk);
  store(prefix+":recovery_whole_sdk:"+x.path,sdk);
  gfNeed(sdk.isError!==true && typeof sdk.structuredContent?.content==="string",
         "original_blob_not_observed");
  const raw=sdk.structuredContent.content;
  gfNeed(raw===prior.texts[x.path] && gfMetaEquals(raw,x),"original_same_bytes_only");
  verified.push({...x,whole:true});
 }
 const record={tree:prior.expectedTree,entries:verified,count:verified.length,
  bytes:verified.reduce((a,x)=>a+x.bytes,0),whole:true,
  recoveryReadOnly:true,mutationRepeated:false,nativeCalled:false};
 store(prefix+":recovery_complete",record);
 return record;
}


/* The only invocation entry point. It always returns normally after retaining
 * failures, so a failed cell cannot roll back V8 state by an uncaught throw.
 * Internal functions may throw; they must only be invoked through gfRun.
 */
async function gfRun(action,args) {
 try {
  let value;
  if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);
  else if(action==="next_request")value=gfNextFixedRequest(gfState());
  else if(action==="prepare_closed_info10_page0_recovery")value=await gfPrepareClosedInfo10Page0Recovery(args);
  else if(action==="prepare_closed_body16_page0_recovery")value=await gfPrepareClosedBody16Page0Recovery(args);
  else if(action==="prepare")value=await gfPrepareOne(args);
  else if(action==="invoke")value=await gfInvokePreparedOnce(args.callKey);
  else if(action==="accept")value=gfAcceptArchivedSDK(args.callKey);
  else if(action==="close_observer")value=await gfCloseOriginalObserver();
  else if(action==="git_readonly_reconcile")value=await gfReconcileSameGitArchiveReadOnly(args.archiveKey);
  else throw new Error("closed_gfRun_action");
  return {ok:true,action,value:value===undefined?null:value};
 } catch(error) {
  const record={schema:"heptabao.gitfirst.outer-caught-failure.r1",action,
   name:error?.name??"Error",message:String(error?.message??error),
   automaticRetry:false,newAdmissionAllowed:false,returnedNormally:true};
  try {
   const state=load(GF_SLOT);
   if(state){state.paused=true;state.outerFailure=record;store(GF_SLOT,state);}
   const raw=JSON.stringify(record,null,2)+"\n",pin=gitBlobMeta(raw);
   const key="gitfirst-failure-by-blob:"+pin.blob,old=load(key);
   if(old===undefined)store(key,raw);
   const history=load(GF_SLOT+":outer_failures")||[];
   history.push({ordinal:history.length+1,pin,immutableStoreKey:key});
   store(GF_SLOT+":outer_failures",history);
   store(GF_SLOT+":latest_outer_failure",record);
   return {ok:false,action,failure:record,pin};
  } catch(recordError) {
   store(GF_SLOT+":last_resort_caught_failure",
      {record,recordError:String(recordError?.message??recordError),newAdmissionAllowed:false});
   return {ok:false,action,failure:record,recordingIncomplete:true};
  }
 }
}
