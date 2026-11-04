import fs from 'node:fs';import path from 'node:path';import {createHash}from'node:crypto';import {pathToFileURL,fileURLToPath}from'node:url';
const sha=b=>createHash('sha256').update(b).digest('hex');
const m=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));if(m.schema!=='heptabao.native-fixed-overlay-esm-map.v1')throw Error('map_schema');
const parent=pathToFileURL(m.parent).href,base=path.resolve(path.dirname(process.argv[2]));
if(path.dirname(path.dirname(path.dirname(m.parent)))!==base||m.candidateMode!=='fixed')throw Error('overlay_parent_scope');
const records=[];
for(const expected of m.expectedModules){const resolved=import.meta.resolve(expected.specifier,parent);if(!resolved.startsWith('file:'))throw Error('file_resolution_required');const real=fs.realpathSync(fileURLToPath(resolved));if(real!==expected.real||resolved!==expected.resolved)throw Error('dependency_resolution_changed');const b=fs.readFileSync(real);if(b.length!==expected.bytes||sha(b)!==expected.sha256)throw Error('dependency_bytes_changed');records.push({specifier:expected.specifier,real,sha256:expected.sha256,bytes:expected.bytes});}
for(const expected of m.expectedPackages){const b=fs.readFileSync(expected.path);if(b.length!==expected.bytes||sha(b)!==expected.sha256)throw Error('package_changed');}
const nodeModules=path.join(base,'factory-overlay/node_modules');for(const[name,target]of Object.entries(m.links)){const p=path.join(nodeModules,name);if(!fs.lstatSync(p).isSymbolicLink()||fs.readlinkSync(p)!==target||fs.realpathSync(p)!==target)throw Error('owned_dependency_symlink_changed');}
console.log(JSON.stringify({schema:'heptabao.native-fixed-overlay-esm-verification.v1',ok:true,providerCalled:false,nativeStarted:false,productionChanged:false,moduleCount:records.length,packageCount:m.expectedPackages.length,records}));
