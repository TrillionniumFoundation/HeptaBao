import fs from 'node:fs';import path from 'node:path';import {createHash} from 'node:crypto';import {createRequire} from 'node:module';
const base='/home/qian-qi/.openclaw/runtime/openai-codex-0.159.2',command=base+'/node_modules/.bin/codex',launcher=fs.realpathSync(command);
function need(v,c){if(!v)throw new Error(c);}const hash=b=>createHash('sha256').update(b).digest('hex');
function under(p){return p.startsWith(base+'/')&&!path.relative(base,p).startsWith('..');}
need(process.platform==='linux'&&process.arch==='x64'&&under(launcher),'platform_or_command_scope');
const launchBytes=fs.readFileSync(launcher),packagePath=path.resolve(path.dirname(launcher),'../package.json'),packageBytes=fs.readFileSync(packagePath),pkg=JSON.parse(packageBytes);
need(hash(launchBytes)==='61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70'&&hash(packageBytes)==='d4e69a623f79ede30c5abb2a4a4bef8b7ff71dbda1362ebe198676ab56113c15'&&pkg.version==='0.159.2'&&pkg.bin.codex==='bin/codex.js','exact_launcher_contract');
const require=createRequire(launcher);let platformPackagePath=null,vendorRoot,resolution;
try{platformPackagePath=require.resolve('@openai/codex-linux-x64/package.json');vendorRoot=path.join(path.dirname(platformPackagePath),'vendor');resolution='installed_platform_optional_dependency';}
catch{vendorRoot=path.join(path.dirname(launcher),'..','vendor');resolution='launcher_bundled_vendor_fallback';}
need(under(path.resolve(vendorRoot)),'vendor_scope');
const selected=path.join(vendorRoot,'x86_64-unknown-linux-musl','bin','codex'),actual=fs.realpathSync(selected);need(under(actual),'native_binary_scope');
const fd=fs.openSync(actual,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let s,digest;try{s=fs.fstatSync(fd);need(s.isFile()&&s.size<=536870912&&(s.mode&0o111)!==0,'bounded_regular_executable');const h=createHash('sha256'),buffer=Buffer.alloc(1048576);let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))!==0)h.update(buffer.subarray(0,n));digest=h.digest('hex');const t=fs.fstatSync(fd),u=fs.lstatSync(actual);need([t,u].every(x=>x.ino===s.ino&&x.dev===s.dev&&x.size===s.size&&x.mtimeMs===s.mtimeMs&&x.ctimeMs===s.ctimeMs),'native_binary_stable');}finally{fs.closeSync(fd);}
let platformPackage=null;if(platformPackagePath){const real=fs.realpathSync(platformPackagePath);need(under(real),'platform_package_scope');const b=fs.readFileSync(real);need(b.length<65536,'bounded_platform_metadata');platformPackage={path:platformPackagePath,realpath:real,bytes:b.length,sha256:hash(b),text:b.toString('utf8')};}
console.log(JSON.stringify({schema:'heptabao.rog-native-command-exact-launcher-resolution-readonly.v1',nativeStarted:false,providerCalled:false,productionChanged:false,command,launcher,launcherSha256:hash(launchBytes),packageVersion:pkg.version,resolution,platformPackage,nativeBinary:{path:selected,realpath:actual,bytes:s.size,sha256:digest},platform:process.platform,architecture:process.arch}));
