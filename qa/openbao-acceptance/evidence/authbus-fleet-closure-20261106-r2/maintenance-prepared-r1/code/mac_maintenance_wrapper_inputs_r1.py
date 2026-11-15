#!/usr/bin/env python3
"""Explicit ownership handoff of wrapper FDs to one original maintenance parent.

The original source capture still finishes within its own 45-second deadline.
This object then retains those same non-database descriptors under the already
declared maintenance deadline, at most 600 seconds from construction. It never
claims the capture returned closed FDs and never extends a child/API deadline.
"""
from __future__ import annotations

import time

from mac_current_parameter_wrapper_inputs_r1 import CurrentParameterWrapperInputs, need


class MaintenanceWrapperInputs(CurrentParameterWrapperInputs):
    def __init__(self, *, capture_until, maintenance_until, source_fence, private_write,
                 clock=time.monotonic):
        started = clock()
        need(started < capture_until <= min(maintenance_until, started + 45)
             and started < maintenance_until <= started + 600,
             'maintenance_wrapper_two_original_absolute_budgets')
        super().__init__(until=capture_until, source_fence=source_fence,
                         private_write=private_write, clock=clock)
        self.capture_until, self.maintenance_until = capture_until, maintenance_until
        self.maintenance_handoff = False
        self.report.update(schema='heptabao.maintenance-wrapper-inputs.public.r1',
                           captureMaximumSeconds=45, maintenanceMaximumSeconds=600,
                           capturePhaseCompletedBeforeOriginalDeadline=False,
                           maintenanceHandoffPerformed=False,
                           originalCaptureDescriptorsDeclaredClosed=False)

    def handoff_to_maintenance(self):
        need(not self.maintenance_handoff and not self.closed and not self.failed
             and self.prepared is not None and self.report['ok'] is True,
             'maintenance_wrapper_completed_capture_handoff_once')
        # This verify uses the unchanged original capture deadline. Failure
        # does not switch lifetime or make previously expired authority valid.
        self.verify()
        need(self.clock() < self.capture_until and self.clock() < self.maintenance_until,
             'maintenance_wrapper_handoff_before_both_deadlines')
        self.maintenance_handoff = True
        self.until = self.maintenance_until
        self.report.update(capturePhaseCompletedBeforeOriginalDeadline=True,
                           maintenanceHandoffPerformed=True,
                           sameOriginalDescriptorsRetained=True,
                           retainedDescriptorCount=len(self.rows))
        return self

    def close(self):
        report = super().close()
        report['maintenanceRetainedDescriptorsClosedOnce'] = (
            self.maintenance_handoff and report['allOriginalDescriptorsClosedOnce'])
        return report
