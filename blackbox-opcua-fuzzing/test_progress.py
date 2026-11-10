import importlib.util
import logging
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import MagicMock, patch

from fuzzer.progress import ProgressTracker
from test_target_validation import load_fuzzer


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.tracker = ProgressTracker(clock=lambda: self.now)

    def test_reports_observations_and_phases(self):
        with self.assertLogs(level=logging.INFO) as logs:
            self.tracker.start()
            self.now = 900
            self.tracker.report()
            self.tracker.phase('fuzzing')
            self.tracker.report()
            self.tracker.post_test_case(session=types.SimpleNamespace(total_mutant_index=3))
            self.tracker.post_test_case(session=types.SimpleNamespace(total_mutant_index=17))
            self.tracker.report()
            self.tracker.report()
            self.tracker.phase('result collection')
            self.tracker.report()
            self.tracker.phase('replay')
            self.tracker.report()
            self.tracker.phase('completed')
            self.tracker.stop()
        output = '\n'.join(logs.output)
        self.assertIn('[FUZZ-PROBE]', output)
        self.assertIn('phase=startup elapsed=900s', output)
        self.assertIn('post_test_count=0 delta=0 last_case_index=unknown progress unknown', output)
        self.assertIn('post_test_count=2 delta=2 last_case_index=17 progress observed', output)
        self.assertIn('post_test_count=2 delta=0 last_case_index=17 no observed progress / possible stall', output)
        for phase in ('result collection', 'replay', 'completed'):
            self.assertIn('phase=' + phase, output)
        for line in logs.output:
            if 'phase=result collection' in line or 'phase=replay' in line:
                self.assertNotIn('stall', line)

    def test_missing_index_and_probe_logging_failure_are_safe(self):
        with patch('fuzzer.progress.logging.info', side_effect=RuntimeError('broken log')):
            self.tracker.start()
            self.tracker.phase('fuzzing')
            self.tracker.post_test_case(session=object())
            self.tracker.report()
            self.tracker.stop()
        with self.assertLogs(level=logging.INFO) as logs:
            self.tracker.report()
        self.assertIn('post_test_count=1', logs.output[0])
        self.assertIn('last_case_index=unknown', logs.output[0])

    def test_reporter_runs_while_fuzzing_is_blocked(self):
        tracker = ProgressTracker(interval=0.01)
        observed = threading.Event()
        with patch.object(tracker, 'report', side_effect=observed.set):
            tracker.start()
            self.addCleanup(tracker.stop)
            tracker.phase('fuzzing')
            self.assertTrue(observed.wait(2))
        tracker.stop()
        self.assertFalse(tracker._thread.is_alive())

    def test_monitor_and_reporter_cleanup_on_fuzz_exception(self):
        fuzzer = load_fuzzer()
        tracker = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.touch(mode=0o755)
            with patch.object(fuzzer, 'Process') as process:
                fuzzer.fuzz_opcua.side_effect = RuntimeError('fuzz failed')
                with self.assertRaisesRegex(RuntimeError, 'fuzz failed'):
                    fuzzer.run_fuzzing(target, tracker)
                process.return_value.start.assert_called_once()
                tracker.start.assert_called_once()
                process.return_value.terminate.assert_called_once()
                process.return_value.join.assert_called_once()

        with patch.object(fuzzer, 'parse_arguments', return_value=types.SimpleNamespace(target=target, reproduce=True)), \
                patch.object(fuzzer, 'create_logger'), patch.object(fuzzer, 'ProgressTracker', return_value=tracker), \
                patch.object(fuzzer, 'run_fuzzing', side_effect=RuntimeError('setup failed')):
            with self.assertRaisesRegex(RuntimeError, 'setup failed'):
                fuzzer.main()
        tracker.phase.assert_called_with('failed')
        tracker.stop.assert_called_once()

    def test_short_run_and_replay_failure_are_reported(self):
        fuzzer = load_fuzzer()
        arguments = types.SimpleNamespace(target=Path('/target'), reproduce=True)
        for failure in (None, RuntimeError('replay failed')):
            tracker = ProgressTracker()
            with self.subTest(failure=failure), \
                    patch.object(fuzzer, 'parse_arguments', return_value=arguments), \
                    patch.object(fuzzer, 'create_logger'), \
                    patch.object(fuzzer, 'ProgressTracker', return_value=tracker), \
                    patch.object(fuzzer, 'run_fuzzing', return_value='run'), \
                    patch.object(fuzzer, 'kill_still_running_server'), \
                    patch.object(fuzzer, 'replay_crash_log', side_effect=failure), \
                    self.assertLogs(level=logging.INFO) as logs:
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'replay failed'):
                        fuzzer.main()
                else:
                    self.assertEqual(fuzzer.main(), 0)
            self.assertIn('phase=replay', '\n'.join(logs.output))
            self.assertIn('phase=' + ('failed' if failure else 'completed'), '\n'.join(logs.output))

    def test_session_receives_callback_and_collection_follows_fuzzing(self):
        names = ('s_initialize', 's_bytes', 's_dword', 'Session', 's_get', 's_block', 'Target',
                 's_size', 's_qword', 'exception', 'ProcessMonitor', 'TCPSocketConnection', 's_byte')
        boofuzz = types.ModuleType('boofuzz')
        for name in names:
            setattr(boofuzz, name, MagicMock())
        path = Path(__file__).parent / 'fuzzer' / 'boofuzz_definition.py'
        spec = importlib.util.spec_from_file_location('definition_under_test', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'boofuzz': boofuzz}):
            spec.loader.exec_module(module)
        tracker = MagicMock()
        module.setup_session('127.0.0.1', 4840, '', tracker)
        self.assertEqual(boofuzz.Session.call_args.kwargs['post_test_case_callbacks'], [tracker.post_test_case])
        session = MagicMock(_run_id='run')
        with patch.object(module, 'setup_session', return_value=session), \
                patch.object(module, 'hello_definition'), patch.object(module, 'open_channel_definition'), \
                patch.object(module, 'close_channel_definition'), patch.object(module, 'create_session_definition'), \
                patch.object(module, 'activate_session_definition'), patch.object(module, 'discovery_service_definition'), \
                patch.object(module, 'find_servers_on_network_definition'), \
                patch.object(module, 'register_server_2_definition'), \
                patch.object(module, 'convert_boofuzz_sqlite_to_dict'), \
                patch.object(module, 'merge_boofuzz_data'), patch.object(module, 'store_crash_information'):
            module.fuzz_opcua(Path('/target'), tracker)
        self.assertEqual([call.args[0] for call in tracker.phase.call_args_list], ['fuzzing', 'result collection'])


if __name__ == '__main__':
    unittest.main()
