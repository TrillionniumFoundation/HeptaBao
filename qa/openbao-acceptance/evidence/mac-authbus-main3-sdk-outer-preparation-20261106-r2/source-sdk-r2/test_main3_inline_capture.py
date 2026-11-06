#!/usr/bin/env python3
"""Synthetic refusal gates for the new capture-to-service admission seam."""
import copy
import unittest
import main3_inline_capture as c
import main3_source_fence as f

PARENT=4444
CAPTURE=5555

def valid_authority():
    command={'label':'current-main3-inline-capture','exitCode':0,'completeBeforeDeadline':True,
        'outcomeUnknown':False,'streamsClosed':True,'errorType':None,'errorCode':None,
        'stderrBytes':0,'stdoutBytes':20000,'pid':CAPTURE,'commandDeadlineMonotonic':12345.0,
        'argv':[c.PYTHON,'-I','-S','-B',str(c.QA/'main3_capture_launcher.py'),'12345.0'],
        'cleanup':{'ok':True,'outcomeUnknown':False,'directChildReaped':True,
            'allGroupRowsEmptyAfterReap':True,'ownedLiveGroupEmptyBeforeReap':True,
            'remainingGroupRows':[],'signals':[],'postReapSignalSent':False,
            'pid':CAPTURE,'pgid':CAPTURE,
            'custody':{'ps':{'pid':CAPTURE,'ppid':PARENT,'pgid':CAPTURE,'uid':501},
                       'sid_observed_while_live':CAPTURE},
            'retainedExit':{'pid':CAPTURE,'code':1,'status':0}}}
    closure={key:True for key in ('allOwnedDescriptorsClosed','allHeldDescriptorsClosed',
        'allReturnedConnectionsClosed','allExplicitCursorsClosed','allPublicCodeDescriptorsClosed')}
    closure['closeErrors']=[]
    children=[]
    for pid in (6001,6002,6003):
        children.append({'pid':pid,'birth':{'pid':pid,'ppid':CAPTURE,'pgid':pid,'sid':pid,'uid':501},
            'exec_admitted':True,'original_wait_completed':True,'original_wait_count':1,
            'returncode':0,'no_live_members_before_reap':True,'gaps':[],'signals':[]})
    result={'schema':'heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r2',
        'ok':True,'childExitCode':0,'stderrBytes':0,'sharedSeconds':45,'parentCommandSeconds':45,
        'applicationRetries':0,'serviceActions':0,
        'workerSourceSha256':c.CAPTURE_WORKER_SHA,'guardSourceSha256':c.CAPTURE_GUARD_SHA,
        'registryReaderSourceSha256':c.CAPTURE_REGISTRY_SHA,'sdkPins':dict(c.SDK_SOURCE_PINS),
        'privateSelectedCredentialCapsule':str(c.CAPSULE),'registeredMetadataFilesVerified':145,
        'sourceGuardClosure':copy.deepcopy(closure),'registryGuardClosure':copy.deepcopy(closure),
        'custody':{'passed_process_custody':True,'finished':True,'failed':False,'interrupted':False,
            'original_count':3,'controls':[],'platform':'darwin','unreaped_original_is_signal_anchor':True,
            'children':children},
        'observation':{'ok':True,'actualSdkOwnershipFunctionsExecuted':True,'selectionOrderExecuted':True,
            'actualSdkSelectedOwnerCount':3,'effectiveProfileReferenceCount':15,'allSelectedOwnersAreMain':True,
            'allEffectiveOwnersMatch':True,'currentGenerationRecapturedAndSdkSelectionRevalidated':True,
            'exactPreviousSdkSelectedAllowlistRetained':True,'privateSelectedOwnerCredentialCount':3,
            'privateSelectedCredentialCapsulePublished':True,'sdkSourcePins':dict(c.SDK_SOURCE_PINS),
            'unexpectedJsMutationNetworkChildAttempts':0,'unexpectedSqliteOpenAttempts':0,
            'selectedOwnerAllowlistSyntheticCasesPassed':12,
            'sqliteReadScope':{'allReturnedHandlesClosedOnce':True,'returnedHandleCount':119,
                'memoryOpenCount':1,'readOnlyFileOpenCount':118},
            'agents':[{'agent':agent,'allEffectiveOwnersMatch':True,'effectiveProfileCount':3,
                'persistedOwnerMatchesEffectiveCount':3,'selection':{'actualSdkFunctionExecuted':True,
                'sourceStoreObjectUnchanged':True}} for agent in c.AGENTS]}}
    for key in ('credentialValuesOrDigestsIncluded','rawClientConfigHashIncluded','profileIdsPublished',
        'providerCalled','refreshDispatched','j3160Contacted','productionConfigurationChanged',
        'productionDatabaseChanged','credentialExportedOffHost','productBinaryExecuted',
        'providerValidityQualified','full9GenerationComparisonWeakened'):result[key]=False
    for key in ('originalDeadlineAfterClosure','freshSourceGenerationCapture',
        'currentConfigAndAllFiveSourceGenerationsStillExact','actualRegistryGenerationStillExact',
        'closedSourceNamesAndAbsencesReverified','privateSelectedCredentialCapsuleQualified'):result[key]=True
    return {'schema':'heptabao.main3-inline-capture-authority.public.r5','operationKey':c.OPERATION_KEY,
        'parentPid':PARENT,'authorityKind':'original_direct_child_wait_and_closed_owned_inner_children',
        'runtimeJobTerminalAssumed':False,'ok':True,'captureLauncherSourceSha256':c.CAPTURE_LAUNCHER_SHA,
        'capturePayloadSha256':c.CAPTURE_PAYLOAD_SHA,'command':command,'result':result}

class InlineCaptureGuards(unittest.TestCase):
    def reject(self,change):
        value=valid_authority();change(value)
        with self.assertRaises(c.CaptureRefused):c.validate_authority(value,parent_pid=PARENT)
    def test_exact_original_zero_closed_report_admitted(self):
        value=valid_authority();self.assertIs(c.validate_authority(value,parent_pid=PARENT),value)
    def test_running_runtime_is_not_capture_authority(self):
        self.reject(lambda v:v.update(runtimeJobTerminalAssumed=True))
    def test_other_operation_key_is_not_replay_authority(self):
        self.reject(lambda v:v.update(operationKey='different-operation'))
    def test_different_parent_pid_is_rejected(self):
        self.reject(lambda v:v.update(parentPid=PARENT+1))
    def test_other_launcher_source_is_rejected(self):
        self.reject(lambda v:v.update(captureLauncherSourceSha256='f'*64))
    def test_other_public_payload_is_rejected(self):
        self.reject(lambda v:v.update(capturePayloadSha256='f'*64))
    def test_nonzero_original_exit_is_rejected(self):
        self.reject(lambda v:v['command'].update(exitCode=1))
    def test_boolean_is_not_a_known_integer_exit(self):
        self.reject(lambda v:v['command'].update(exitCode=False))
    def test_unknown_original_outcome_is_rejected(self):
        self.reject(lambda v:v['command'].update(outcomeUnknown=True))
    def test_unreaped_direct_child_is_rejected(self):
        self.reject(lambda v:v['command']['cleanup'].update(directChildReaped=False))
    def test_foreign_direct_child_parent_is_rejected(self):
        self.reject(lambda v:v['command']['cleanup']['custody']['ps'].update(ppid=PARENT+1))
    def test_retained_wait_must_be_original_zero(self):
        self.reject(lambda v:v['command']['cleanup']['retainedExit'].update(status=9))
    def test_nonfinite_deadline_is_rejected(self):
        self.reject(lambda v:v['command']['argv'].__setitem__(5,'nan'))
    def test_actual_deadline_must_match_argv(self):
        self.reject(lambda v:v['command'].update(commandDeadlineMonotonic=12346.0))
    def test_inner_wait_cannot_be_missing(self):
        self.reject(lambda v:v['result']['custody']['children'][0].update(original_wait_completed=False))
    def test_inner_wait_cannot_be_replayed(self):
        self.reject(lambda v:v['result']['custody']['children'][0].update(original_wait_count=2))
    def test_inner_child_session_must_remain_owned(self):
        self.reject(lambda v:v['result']['custody']['children'][0]['birth'].update(sid=9999))
    def test_four_inner_children_are_not_the_qualified_denominator(self):
        self.reject(lambda v:v['result']['custody'].update(original_count=4))
    def test_unclosed_source_descriptor_is_rejected(self):
        self.reject(lambda v:v['result']['registryGuardClosure'].update(allOwnedDescriptorsClosed=False))
    def test_unclosed_sdk_sqlite_handle_is_rejected(self):
        self.reject(lambda v:v['result']['observation']['sqliteReadScope'].update(allReturnedHandlesClosedOnce=False))
    def test_changed_full9_generation_is_rejected(self):
        self.reject(lambda v:v['result'].update(actualRegistryGenerationStillExact=False))
    def test_missing_post_close_namespace_observation_is_rejected(self):
        self.reject(lambda v:v['result'].pop('closedSourceNamesAndAbsencesReverified'))
    def test_provider_effect_is_rejected(self):
        self.reject(lambda v:v['result'].update(providerCalled=True))
    def test_credential_digest_publication_is_rejected(self):
        self.reject(lambda v:v['result'].update(credentialValuesOrDigestsIncluded=True))
    def test_fourth_selected_owner_is_rejected(self):
        self.reject(lambda v:v['result']['observation'].update(privateSelectedOwnerCredentialCount=4))
    def test_changed_worker_source_is_rejected(self):
        self.reject(lambda v:v['result'].update(workerSourceSha256='f'*64))
    def test_missing_actual_sdk_pin_is_rejected(self):
        self.reject(lambda v:v['result']['sdkPins'].pop(next(iter(c.SDK_SOURCE_PINS))))
    def test_other_capsule_path_is_rejected(self):
        self.reject(lambda v:v['result'].update(privateSelectedCredentialCapsule='/different/private.json'))
    def test_other_authority_cannot_rebind_qualified_capsule(self):
        identity=['1','2','501','20','33152','1','4096','100','100']
        value=f.CapsuleFence.expected_binding(identity,'a'*64)
        with self.assertRaises(f.Refused):f.CapsuleFence.validate_binding(value,identity,'b'*64)

if __name__=='__main__':unittest.main()
