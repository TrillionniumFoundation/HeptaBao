const verify = new Function(files['pure.original.js'] + '\n' + files['binding.correct.original.js'] + '\n' + files['verifier.source.js'] + '\nreturn verifyOfficialAcl23OriginalChain;')();
return verify(files);
