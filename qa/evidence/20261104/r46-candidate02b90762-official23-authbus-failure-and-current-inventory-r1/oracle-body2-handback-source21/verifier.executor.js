/* V8-only SOURCE checker; exact path -> original text map input. */
function execute(files) { return new Function(files['pure_helpers.js']+'\n'+files['verifier.source.js']+'\nreturn verifyOracleBody02HandbackSource;')()(files); }
