const verify=new Function(files['pure.original.js']+'\n'+files['strict-diff.original.js']+'\n'+files['verifier.source.js']+'\nreturn verifyOracleReportBodySource;')();
return await verify(files);
