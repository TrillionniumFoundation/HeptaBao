"""Cancellation closes an entered request's owner without retrying it."""
import ssl
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import heptabao.agent as agent_module

from heptabao.deadline_transport import DeadlineClient, _RequestOwner
from heptabao.transport import BaoError, Client


class ManagedDeadlineCancellationTests(unittest.TestCase):
    def client(self, event):
        client = DeadlineClient.__new__(DeadlineClient)
        client.timeout = 5
        client.deadline = time.monotonic() + 5
        client.cancellation = event
        client.context = ssl.create_default_context()
        return client

    def test_already_cancelled_owner_never_enters_transport(self):
        event = threading.Event()
        event.set()
        with patch.object(Client, 'request') as request:
            with self.assertRaises(BaoError) as caught:
                self.client(event).request('GET', '/v1/database/creds/private')
        self.assertEqual(caught.exception.code, 'transport_outcome_unknown')
        request.assert_not_called()

    def test_entered_request_cancelled_promptly_and_never_retried(self):
        event, entered, release, worker_done = (threading.Event() for _ in range(4))
        result = []

        def blocked(*args, **kwargs):
            entered.set()
            release.wait(2)
            worker_done.set()
            return object()

        def invoke(client):
            try:
                client.request('GET', '/v1/database/creds/private')
                result.append('delivered')
            except BaoError as error:
                result.append(error.code)

        client = self.client(event)
        with patch.object(Client, 'request', side_effect=blocked) as request:
            thread = threading.Thread(target=invoke, args=(client,))
            thread.start()
            self.assertTrue(entered.wait(1))
            event.set()
            thread.join(1)
            try:
                self.assertFalse(thread.is_alive())
                self.assertEqual(result, ['transport_outcome_unknown'])
                self.assertEqual(request.call_count, 1)
            finally:
                release.set()
                self.assertTrue(worker_done.wait(1))
                thread.join(1)

    def test_socket_owner_checks_external_cancellation_before_sending(self):
        event = threading.Event()
        owner = _RequestOwner(time.monotonic() + 10, event)
        owner.check()
        event.set()
        with self.assertRaises(TimeoutError):
            owner.check()


    def test_agent_global_runtime_cannot_extend_one_request_budget(self):
        captured = {}
        def factory(*args, **kwargs):
            captured.update(kwargs)
            return object()
        config = SimpleNamespace(address='https://localhost:8200', ca_file='/unused',
            namespace='', timeout=.2, binding=lambda: 'same-binding')
        agent = agent_module.Agent.__new__(agent_module.Agent)
        agent.config, agent.binding, agent._trusted_ca = config, 'same-binding', b'unused'
        agent.factory = factory
        agent.cancellation = threading.Event()
        before = time.monotonic()
        agent.owner_deadline = before + 90
        with patch.object(agent_module, 'DeadlineClient', factory):
            agent._client('synthetic-unit-token')
        self.assertGreater(captured['deadline'], before)
        self.assertLessEqual(captured['deadline'], before + .25)
        self.assertIs(captured['cancellation'], agent.cancellation)


if __name__ == '__main__':
    unittest.main()
