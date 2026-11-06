/* Pure V8 only; input is this packet's path -> exact UTF-8 text map. */
function execute(files) { return new Function(files['pure_helpers.js']+'\n'+files['verifier.source.js']+'\nreturn verifyBody02Recovery;')()(files); }
