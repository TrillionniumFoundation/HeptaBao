function reproduceFixed4Conditional(files) {
 const j=name=>JSON.parse(files[name]);
 const pure=files["pure.original.js"],archive=files["archive.original.js"];
 const h=new Function(pure+"\nreturn {gitBlobMeta,parseLosslessIntegers};")();
 const d=new Function(files["strict-diff.helpers.js"]+"\nreturn {makeStrictUnified,applyStrictUnified};")();
 const info=j("info-binding.public.json");
 info.source=files["journal.info4.current.js"];info.expectedReceipt=files["receipt.expected-derived.json"];
 info.stdout=files["publication.stdout.original.json"];
 info.requests=Array.from({length:4},(_,i)=>files["info"+i+".PROPOSED.request.json"]);
 const closedState=j("original-closed-state.public.json"),originalNativeTexts={};
 originalNativeTexts[closedState.completedObservers[0].id]=files["authority.native.original.json"];
 originalNativeTexts[closedState.completedObservers[1].id]=files["streams.native.original.json"];
 const input={infoBefore:files["journal.info4.original.js"],bodyBefore:files["journal.body4.original.js"],info,
  infoDiff:files["journal.info4.strict.diff"],bodyTemplate:files["journal.body4.conditional-template.js"],
  bodyDiff:files["journal.body4.strict.diff"],bodyReplacements:j("body-replacements.public.json"),
  templates:Array.from({length:4},(_,i)=>files["body"+i+".NULL-VERSION.template.json"]),
  deriver:files["body-deriver.source.js"],slot:j("PLAN.public.json").slot,closedState,originalNativeTexts,pure,archive};
 return new Function(files["verifier.source.js"]+"\nreturn verifyFixed4ConditionalSource;")()(input,h,d);
}
