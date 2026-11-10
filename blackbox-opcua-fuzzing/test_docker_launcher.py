import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


class BuildError(Exception):
    def __init__(self, message, build_log):
        super().__init__(message)
        self.build_log = build_log


docker = types.ModuleType('docker')
docker.from_env = mock.Mock()
errors = types.ModuleType('docker.errors')
errors.BuildError = BuildError
with mock.patch.dict(sys.modules, {'docker': docker, 'docker.errors': errors}):
    spec = importlib.util.spec_from_file_location(
        'launcher', Path(__file__).with_name('run_docker_fuzzing.py'))
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)


class DockerLauncherTests(unittest.TestCase):
    def setUp(self):
        self.client = mock.Mock()
        docker.from_env.return_value = self.client
        docker.from_env.reset_mock()
        self.client.images.build.return_value = (object(), [])
        self.container = self.client.containers.run.return_value
        self.container.id = 'container123'
        self.container.logs.return_value = iter(())
        self.container.wait.return_value = {'StatusCode': 0}

    def test_builds_base_then_target_before_container(self):
        self.client.images.build.side_effect = [
            (object(), [{'stream': 'base output\n'}]),
            (object(), [{'stream': 'target output\n'}]),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            launcher.run_container('java', '/tmp/results')
        calls = self.client.images.build.call_args_list
        self.assertEqual(calls[0].kwargs['dockerfile'], 'Dockerfile.pre')
        self.assertEqual(calls[0].kwargs['tag'], launcher.BASE_TAG)
        self.assertTrue(calls[1].kwargs['tag'].startswith('blackbox-fuzzer/java-'))
        self.client.containers.run.assert_called_once()
        self.assertTrue(self.client.containers.run.call_args.kwargs['detach'])
        self.assertTrue(self.client.containers.run.call_args.kwargs['remove'])
        self.container.logs.assert_called_once_with(stream=True, follow=True, stdout=True, stderr=True)
        self.container.wait.assert_called_once_with()
        self.container.stop.assert_not_called()
        self.assertIn('container123', output.getvalue())
        self.assertIn('only while', output.getvalue())
        self.assertIn('base output', output.getvalue())
        self.assertIn('target output', output.getvalue())

    def test_stream_filters_split_lines_redacts_and_flushes_final_partial(self):
        self.container.logs.return_value = iter([
            b'normal output\n2026 [FUZZ-',
            b'PROBE] https://user:secret@example.org/\nnoise\n',
            b'[FUZZ-PROBE] final partial',
        ])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            launcher.run_container('java', '/tmp/results')
        text = output.getvalue()
        self.assertIn('2026 [FUZZ-PROBE] https://[redacted]@example.org/', text)
        self.assertIn('[FUZZ-PROBE] final partial\n', text)
        self.assertNotIn('normal output', text)
        self.assertNotIn('noise', text)
        self.assertNotIn('secret', text)

    def test_nonzero_exit_reports_bounded_redacted_diagnostics(self):
        self.container.logs.return_value = iter([
            b'old line\n' * 25,
            b'failure https://user:secret@example.org/\n',
        ])
        self.container.wait.return_value = {'StatusCode': 7}
        output, errors_output = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors_output):
            with self.assertRaisesRegex(RuntimeError, 'status 7'):
                launcher.run_container('java', '/tmp/results')
        self.assertNotIn('Finished fuzzing', output.getvalue())
        self.assertEqual(errors_output.getvalue().count('old line'), 19)
        self.assertIn('https://[redacted]@example.org/', errors_output.getvalue())
        self.assertNotIn('secret', errors_output.getvalue())
        self.container.stop.assert_not_called()

    def test_oversized_lines_are_discarded_without_forwarding_fragments(self):
        self.container.logs.return_value = iter([
            b'x' * launcher.MAX_LOG_LINE, b'[FUZZ-PROBE] hidden\n',
            b'[FUZZ-PROBE] visible\n',
        ])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            launcher.run_container('java', '/tmp/results')
        self.assertNotIn('hidden', output.getvalue())
        self.assertIn('[FUZZ-PROBE] visible', output.getvalue())

    def test_stream_wait_and_interruption_errors_stop_container(self):
        for operation, failure in (
            ('logs', RuntimeError('stream failure')),
            ('wait', RuntimeError('wait failure')),
            ('logs', KeyboardInterrupt()),
        ):
            with self.subTest(operation=operation, failure=type(failure)):
                self.container.reset_mock(side_effect=True, return_value=True)
                self.container.logs.return_value = iter(())
                self.container.wait.return_value = {'StatusCode': 0}
                getattr(self.container, operation).side_effect = failure
                self.container.stop.side_effect = RuntimeError('cleanup failure')
                output, errors_output = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors_output):
                    with self.assertRaises(type(failure)) as caught:
                        launcher.run_container('java', '/tmp/results')
                self.assertIs(caught.exception, failure)
                self.container.stop.assert_called_once_with()
                self.assertIn('cleanup failure', errors_output.getvalue())
                self.assertNotIn('Finished fuzzing', output.getvalue())

    def test_stream_iteration_error_reports_prior_output(self):
        def failing_stream():
            yield b'failure detail\n'
            raise RuntimeError('stream failure')

        self.container.logs.return_value = failing_stream()
        errors_output = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors_output):
            with self.assertRaisesRegex(RuntimeError, 'stream failure'):
                launcher.run_container('java', '/tmp/results')
        self.assertIn('failure detail', errors_output.getvalue())
        self.container.stop.assert_called_once_with()

    def test_build_failures_show_logs_and_skip_container(self):
        for failed_stage in (0, 1):
            with self.subTest(stage=failed_stage):
                self.client.reset_mock()
                failure = BuildError('original reason', [
                    {'stream': 'earlier output\n'},
                    {'errorDetail': {'message': 'failed https://user:secret@example.org/'}},
                ])
                self.client.images.build.side_effect = (
                    [(object(), [])] * failed_stage + [failure])
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(BuildError) as caught:
                    launcher.run_container('java', '/tmp/results')
                self.assertIs(caught.exception, failure)
                self.assertIn('earlier output', output.getvalue())
                self.assertIn('https://[redacted]@example.org/', output.getvalue())
                self.assertNotIn('secret', output.getvalue())
                self.client.containers.run.assert_not_called()

    def test_working_directory_restored_on_exception(self):
        before = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(launcher, '__file__', str(Path(tmp) / 'launcher.py')):
                with mock.patch.object(launcher, 'run_container', side_effect=RuntimeError('fail')):
                    with self.assertRaises(RuntimeError):
                        launcher.start_fuzzing('java', '/tmp/results')
            self.assertEqual(os.getcwd(), before)

    def test_main_reports_failure_without_running_container(self):
        failure = BuildError('original reason', [{'error': 'build failed'}])
        self.client.images.build.side_effect = failure
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(path=Path(tmp), target='java')
            output = io.StringIO()
            with mock.patch.object(launcher, 'setup_argparse', return_value=args):
                with mock.patch.object(launcher, '__file__', str(Path(tmp) / 'launcher.py')):
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(launcher.main(), 255)
        self.assertIn('build failed', output.getvalue())
        self.assertIn('original reason', output.getvalue())
        self.client.containers.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
