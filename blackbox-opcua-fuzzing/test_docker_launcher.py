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
        self.assertIn('base output', output.getvalue())
        self.assertIn('target output', output.getvalue())

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
