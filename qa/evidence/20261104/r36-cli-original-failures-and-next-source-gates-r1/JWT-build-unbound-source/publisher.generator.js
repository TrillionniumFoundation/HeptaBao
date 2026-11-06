function makeJwtControlsPublisher(before,rows){
 let s=before;const replacements=[];
 function one(label,a,b){if(s.split(a).length!==2)throw Error(label);s=s.replace(a,b);replacements.push({label,before:a,after:b,count:1});}
 one("purpose",'"""Create-only distribution and compile-check of the three reviewed shared artifact controls."""','"""Create-only distribution and compile-check of the three separately reviewed JWT build controls."""');
 one("inactive source draft","os.umask(0o077)","BINDING_READY = False\nassert BINDING_READY, 'final formatted source and build control pins are not yet bound'\nos.umask(0o077)");
 one("fixed parent","PARENT = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')","PARENT = Path('/home/qian-qi')");
 one("owned fresh controls root","BASE = PARENT / 'normal-cold-h2-x230-transfer-controls-r1'","BASE = PARENT / 'heptabao-native-jwt-r2-controls-20261106-r1'");
 const i=s.indexOf("PINS = {"),j=s.indexOf("\ndef sha(",i);if(i<0||j<0)throw Error("pin map");
 const pinText="PINS = "+JSON.stringify(rows,null,4)+"\n";one("exact three reviewed payloads",s.slice(i,j),pinText);
 one("new receipt schema","heptabao.df026-x230-normal7-inert-carrier.v1","heptabao.native-jwt-build-controls-inert.v1");
 one("new input schema","heptabao.df026-x230-normal7-inputs.v1","heptabao.native-jwt-build-control-inputs.v1");
 return{source:s,replacements};
}