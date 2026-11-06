return new Function(files['pure.original.js']+'\n'+files['verifier.source.js']+'\nreturn verifyOracleInfoReconciliationActual;')()(files);
