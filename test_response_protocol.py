"""Portable response-reader regressions. All peers and clocks are simulated."""
import unittest
from unittest.mock import patch

import client
import performance_test as benchmark


class ReplySocket:
    def __init__(self, data=b'', chunks=None, clock=None):
        self.data = data
        self.chunks = iter(chunks) if chunks is not None else None
        self.clock = clock
        self.timeouts = []
        self.reads = 0
        self.sent = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.sent = True

    def recv(self, size):
        self.reads += 1
        if self.clock is not None:
            if self.reads > 5:
                raise AssertionError('Reader did not enforce an absolute deadline')
            self.clock[0] += 2
            return b'x'
        if self.chunks is not None:
            return next(self.chunks, b'')
        part, self.data = self.data[:size], self.data[size:]
        return part


class ResponseProtocolTests(unittest.TestCase):
    auth_readers = (client.send_auth_request, benchmark.auth_request)
    service_readers = (client.access_protected_service, benchmark.service_request)

    def invoke(self, function, reply):
        with patch('socket.create_connection', return_value=reply):
            return function({}) if function in self.auth_readers else function()

    def test_auth_replies_are_strict_json_objects(self):
        for function in self.auth_readers:
            for payload in (b'{"ok":false,"ok":true}\n', b'{"n":NaN}\n',
                            b'{"n":Infinity}\n', b'[]\n', b'null\n', b'\xff\n'):
                with self.subTest(reader=function.__module__, payload_kind=payload[:8]):
                    with self.assertRaises(ValueError):
                        self.invoke(function, ReplySocket(payload))

    def test_fragmented_valid_replies(self):
        for function in self.auth_readers:
            result = self.invoke(function, ReplySocket(chunks=[b'{"ok":', b'true}', b'\n']))
            self.assertEqual(result, {'ok': True})
        for function in self.service_readers:
            result = self.invoke(function, ReplySocket(chunks=[b'ACCESS ', b'GRANTED: demo', b'\n']))
            if function is client.access_protected_service:
                self.assertEqual(result, 'ACCESS GRANTED: demo')
            else:
                self.assertGreaterEqual(result, 0)

    def test_oversized_service_replies_rejected(self):
        for function in self.service_readers:
            with self.subTest(reader=function.__module__), self.assertRaises(ValueError):
                self.invoke(function, ReplySocket(b'ACCESS GRANTED: ' + b'x' * 5000 + b'\n'))

    def test_oversized_auth_replies_rejected(self):
        for function in self.auth_readers:
            with self.subTest(reader=function.__module__), self.assertRaises(ValueError):
                self.invoke(function, ReplySocket(b'{"value":"' + b'x' * 5000 + b'"}\n'))

    def test_all_readers_keep_one_absolute_receive_budget(self):
        for function in self.auth_readers + self.service_readers:
            clock = [100.0]
            reply = ReplySocket(clock=clock)
            with self.subTest(reader=function.__qualname__), \
                 patch('time.monotonic', side_effect=lambda: clock[0]), \
                 self.assertRaises(TimeoutError):
                self.invoke(function, reply)
            self.assertLessEqual(reply.reads, 3)

    def test_receive_budget_includes_connection_time(self):
        for function in self.auth_readers + self.service_readers:
            clock = [100.0]
            reply = ReplySocket(b'{"ok":true}\n' if function in self.auth_readers
                                else b'ACCESS GRANTED: demo\n')
            def connect(*args, **kwargs):
                clock[0] += 10
                return reply
            with self.subTest(reader=function.__qualname__), \
                 patch('time.monotonic', side_effect=lambda: clock[0]), \
                 patch('socket.create_connection', side_effect=connect), \
                 self.assertRaises(TimeoutError):
                function({}) if function in self.auth_readers else function()
            self.assertEqual(reply.reads, 0)
            self.assertFalse(reply.sent)

    def test_two_frames_only_first_reply_handled(self):
        for function in self.auth_readers:
            self.assertEqual(self.invoke(function, ReplySocket(b'{"ok":true}\nextra\n')),
                             {'ok': True})
        for function in self.service_readers:
            result = self.invoke(function, ReplySocket(b'ACCESS GRANTED: demo\nextra\n'))
            if function is client.access_protected_service:
                self.assertEqual(result, 'ACCESS GRANTED: demo')
            else:
                self.assertGreaterEqual(result, 0)

    def test_benchmark_bad_response_logs_out_without_appending(self):
        reply = ReplySocket(b'ACCESS GRANTED: ' + b'x' * 5000 + b'\n')
        with patch.object(benchmark, 'TRIALS', 1), \
             patch.object(benchmark, 'auth_request', side_effect=[
                 {'ok': True, 'session_id': 'synthetic-test-token'}, {'ok': True}]) as auth, \
             patch.object(benchmark, 'append_result') as append, \
             patch('socket.create_connection', return_value=reply):
            with self.assertRaises(ValueError):
                benchmark.run_dynamic()
            self.assertEqual(auth.call_count, 2)
            self.assertEqual(auth.call_args.args[0]['action'], 'LOGOUT')
            append.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
