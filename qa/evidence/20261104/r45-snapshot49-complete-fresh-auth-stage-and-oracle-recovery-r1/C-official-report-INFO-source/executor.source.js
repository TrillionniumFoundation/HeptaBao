return await new Function(files['pure.original.js']+'\n'+files['strict-diff.original.js']+'\n'+files['verifier.source.js']+'\nreturn verifyOracleReportInfoSource;')()(files);
