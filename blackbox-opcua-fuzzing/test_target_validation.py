import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).parent


def load_fuzzer():
    modules = {
        name: types.ModuleType(name)
        for name in (
            'boofuzz',
            'boofuzz.constants',
            'boofuzz.utils',
            'boofuzz.utils.debugger_thread_simple',
            'boofuzz.utils.process_monitor_pedrpc_server',
            'fuzzer.boofuzz_definition',
            'replay.replay',
        )
    }
    modules['boofuzz'].helpers = MagicMock()
    modules['boofuzz.constants'].DEFAULT_PROCMON_PORT = 26002
    modules['boofuzz.utils.debugger_thread_simple'].DebuggerThreadSimple = MagicMock()
    modules['boofuzz.utils.process_monitor_pedrpc_server'].ProcessMonitorPedrpcServer = MagicMock()
    modules['fuzzer.boofuzz_definition'].fuzz_opcua = MagicMock()
    modules['replay.replay'].replay_crash_log = MagicMock()
    spec = importlib.util.spec_from_file_location('fuzz_opcua_server_under_test', ROOT / 'fuzz_opcua_server.py')
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class TargetValidationTests(unittest.TestCase):
    def setUp(self):
        self.fuzzer = load_fuzzer()
        self.tracker = MagicMock()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_invalid_targets_do_not_start_monitor(self):
        nonexecutable = self.root / 'nonexecutable'
        nonexecutable.write_text('target')
        nonexecutable.chmod(0o644)
        dangling = self.root / 'dangling'
        dangling.symlink_to(self.root / 'missing')

        for target in (self.root / 'missing', nonexecutable, dangling, self.root):
            with self.subTest(target=target), patch.object(self.fuzzer, 'Process') as process:
                with self.assertRaisesRegex(ValueError, 'Target must be an executable file') as error:
                    self.fuzzer.run_fuzzing(target, self.tracker)
                self.assertIn(str(target), str(error.exception))
                process.assert_not_called()
                self.fuzzer.fuzz_opcua.assert_not_called()

    def test_executable_file_and_symlink_start_monitor(self):
        target = self.root / 'target'
        target.write_text('target')
        target.chmod(0o755)
        link = self.root / 'link'
        link.symlink_to(target)

        for path in (target, link):
            with self.subTest(target=path), patch.object(self.fuzzer, 'Process') as process:
                self.fuzzer.run_fuzzing(path, self.tracker)
                process.assert_called_once_with(target=self.fuzzer.process_monitor)
                process.return_value.start.assert_called_once_with()
                self.fuzzer.fuzz_opcua.assert_called_with(path, self.tracker)
                process.return_value.terminate.assert_called_once_with()
                process.return_value.join.assert_called_once_with()

    def test_dockerfile_checks_target_after_installation(self):
        dockerfile = (ROOT / 'Dockerfile').read_text()
        install = 'RUN ./setup_target_auto.sh'
        check = 'RUN test -f /opt/app/target && test -x /opt/app/target'
        self.assertIn(install, dockerfile)
        self.assertIn(check, dockerfile)
        self.assertLess(dockerfile.index(install), dockerfile.index(check))
        self.assertLess(dockerfile.index(check), dockerfile.index('ENTRYPOINT'))


if __name__ == '__main__':
    unittest.main()
