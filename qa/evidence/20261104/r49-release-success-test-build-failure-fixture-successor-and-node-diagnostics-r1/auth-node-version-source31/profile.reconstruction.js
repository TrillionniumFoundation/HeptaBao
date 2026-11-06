function reconstructOriginalPublicConsumerProfile(source) {
 const decode=name=>JSON.parse(utf8Text(unb64(source.match(new RegExp("^"+name+"=json\\.loads\\(base64\\.b64decode\\('([^']+)'\\)\\)","m"))[1])));
 const roots=decode("HARNESS_ROOTS"),pins=decode("PUBLIC_SOURCE_PINS");
 const root=JSON.parse(source.match(/^ROOT=Path\(("[^"]+")\)$/m)[1]);
 const codex=JSON.parse(source.match(/^CODEX=Path\(("[^"]+")\)$/m)[1]);
 const phase=root+"/initial",q=JSON.stringify;
 const lines=["(version 1)","(deny default)","(allow process*)","(allow signal (target children))","(allow sysctl-read)","(allow mach-lookup)","(allow file-read-metadata)"];
 for(const path of ["/System","/usr","/bin","/sbin","/Library","/private/etc","/opt/homebrew","/dev/fd"])lines.push("(allow file-read* (subpath "+q(path)+"))");
 for(const path of [root+"/qa",root+"/installed-plugin-copy",phase])lines.push("(allow file-read* (subpath "+q(path)+"))");
 for(const path of [...new Set([codex,...roots])].sort())lines.push("(allow file-read* (subpath "+q(path)+"))");
 for(const path of Object.keys(pins).sort())lines.push("(allow file-read* (literal "+q(path)+"))");
 for(const name of ["ca.crt","role_id","secret_id"])lines.push("(allow file-read* (literal "+q(root+"/credentials-consumer/"+name)+"))");
 lines.push('(allow file-read* (literal "/dev/urandom"))','(allow file-read* (literal "/dev/random"))',
  "(allow file-write* (subpath "+q(phase)+"))",'(allow file-write* (literal "/dev/null"))',
  '(allow network-outbound (remote ip "localhost:63611"))');
 return lines.join("\n")+"\n";
}
