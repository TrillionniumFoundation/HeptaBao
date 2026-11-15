import { openFixture } from './fixture.mjs';
const [root,wanted]=process.argv.slice(2);
process.on('message',()=>{});
let coordinator;
try{
  coordinator=openFixture(root,{phaseHook:async(phase,details)=>{
    if(phase===wanted&&details.kind==='slot'&&details.role==='ack'){
      process.send({phase,role:'ack',waitingForOwnedParent:true});
      await new Promise(()=>{});
    }
  }});
  await coordinator.once();process.send({unexpectedComplete:true});
}catch(error){process.send({failed:true,code:error?.code??'child_error'});process.exitCode=1;}
finally{if(coordinator)await coordinator.close();}
