// Reproduction recipe; not an original execution transcript. Expects the exact packet text map f.
const h = new Function(f["pure.original.js"] + "\n" + f["typed-binding.correct.js"] + "\nreturn {gitBlobMeta,parseLosslessIntegers,utf8Bytes,utf8Text,unb64,encodeBase64Bytes,processStartBinding};")();
const d = new Function(f["strict-diff.helpers.js"] + "\nreturn {makeStrictUnified,applyStrictUnified};")();
const run = new Function(f["verifier.source.js"] + "\nreturn verifyReadyControlsSource;")();
const actual = run(f,h,d,h.processStartBinding);
if (JSON.stringify(actual) !== JSON.stringify(JSON.parse(f["verifier.actual.json"]))) throw Error("exact_recorded_result");
