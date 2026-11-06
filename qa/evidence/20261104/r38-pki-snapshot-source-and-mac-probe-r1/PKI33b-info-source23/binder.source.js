function bindFinalStageInfoOnly({oldInfoJournal,baseStageReplacements,resultPath,infoRequestPin,originalJob,prerequisites,stdoutBytes},h) {
 function need(x,c){if(!x)throw Error(c);}function one(s,a,b){need(s.split(a).length===2,"once:"+a.slice(0,80));return s.replace(a,b);}
 need(/^[0-9a-z-]+$/.test(originalJob)&&Array.isArray(prerequisites)&&prerequisites.length===2,"two_original_closed_observers");
 need(prerequisites[0].tool==="process_status"&&prerequisites[1].tool==="process_read"&&prerequisites.every(x=>/^[0-9a-f]{64}$/.test(x.id)&&/^[0-9a-f]{40}$/.test(x.nativeText.blob)),"actual_observer_pins");
 need(Number.isSafeInteger(stdoutBytes)&&stdoutBytes>0&&stdoutBytes<=16384,"one_complete_summary");
 let source=oldInfoJournal;const replacements=[...baseStageReplacements];
 const oldPath=/^const GF_STAGE_RESULT_PATH = "([^"]+)";$/m.exec(source)[1];
 const oldRequest=/^const GF_STAGE_INFO_REQUEST = (.*);$/m.exec(source)[1];
 const oldPrereqs=/^const GF_STAGE_INFO_PREREQUISITES = (.*);$/m.exec(source)[1];
 replacements.push([oldPath,resultPath],[oldRequest,JSON.stringify(infoRequestPin)],[oldPrereqs,JSON.stringify(prerequisites)],['s.job==="1a1aed43ac9-fc05-62ec"','s.job==="'+originalJob+'"'],["s.nextStdout===370","s.nextStdout==="+stdoutBytes]);
 for(const[a,b]of replacements)source=one(source,a,b);
 let inv=source;for(const[a,b]of [...replacements].reverse())inv=one(inv,b,a);need(inv===oldInfoJournal,"inverse_whole_original_info");
 return {source,pin:h.gitBlobMeta(source),replacements,originalJob,resultPath,infoRequestPin,prerequisites,stdoutBytes,maximumReportBytes:150000,bodyAuthorized:false,Runtime:false};
}