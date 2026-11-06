function executePublicNodeStartupSourceVerification({pureSource,diffSource,verifierSource,files}) {
 const verify=eval(pureSource+"\n"+diffSource+"\n"+verifierSource+";verifyPublicNodeStartupSource");
 return verify(files);
}
