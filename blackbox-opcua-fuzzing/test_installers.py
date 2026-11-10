import ast
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / 'run_docker_fuzzing.py').read_text()
SETUP_SH = next(ast.literal_eval(node.value) for node in ast.parse(SOURCE).body
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == 'SETUP_SH'
                    for target in node.targets))


class InstallerTests(unittest.TestCase):
    def test_apt_update_failure_stops_installers(self):
        for target, script in (('java', 'install.sh'), ('node-opc', 'install.sh'),
                               ('open62541', 'install.sh'), ('open62541', 'tls_install.sh')):
            with self.subTest(target=target, script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bindir = root / 'bin'
                bindir.mkdir()
                apt = bindir / 'apt-get'
                apt.write_text('#!/bin/sh\nexit 42\n')
                apt.chmod(0o755)
                installer = root / 'targets' / target / 'install.sh'
                installer.parent.mkdir(parents=True)
                installer.symlink_to(ROOT / 'targets' / target / script)
                wrapper = root / 'setup.sh'
                wrapper.write_text(SETUP_SH.format(target=target))
                env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}')
                result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env)
                self.assertEqual(result.returncode, 42)

    def test_generated_wrapper_preserves_installer_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installer = root / 'targets/example/install.sh'
            installer.parent.mkdir(parents=True)
            wrapper = root / 'setup.sh'
            wrapper.write_text(SETUP_SH.format(target='example'))
            for status in (0, 23):
                installer.write_text(f'#!/bin/sh\nexit {status}\n')
                installer.chmod(0o755)
                result = subprocess.run(['bash', str(wrapper)], cwd=root)
                self.assertEqual(result.returncode, status)

    def test_cmake_failure_stops_both_open62541_installers(self):
        for script in ('install.sh', 'tls_install.sh'):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bindir = root / 'bin'
                bindir.mkdir()
                commands = {
                    'apt-get': 'exit 0',
                    'git': 'if [ "$1" = clone ]; then mkdir open62541; fi',
                    'cmake': 'exit 31',
                    'make': 'touch "$TEST_MARKER"',
                }
                for name, body in commands.items():
                    command = bindir / name
                    command.write_text(f'#!/bin/sh\n{body}\n')
                    command.chmod(0o755)
                installer = root / 'targets/open62541/install.sh'
                installer.parent.mkdir(parents=True)
                installer.symlink_to(ROOT / 'targets/open62541' / script)
                wrapper = root / 'setup.sh'
                wrapper.write_text(SETUP_SH.format(target='open62541'))
                env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}',
                           TEST_MARKER=str(root / 'make-ran'))
                result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env)
                self.assertEqual(result.returncode, 31)
                self.assertFalse((root / 'make-ran').exists())

    def test_node_checkout_failure_stops_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            commands = {
                'apt-get': 'exit 0',
                'curl': 'exit 0',
                'npm': 'exit 0',
                'git': 'if [ "$1" = clone ]; then mkdir node-opcua; else exit 33; fi',
                'cp': 'touch "$TEST_MARKER"',
            }
            for name, body in commands.items():
                command = bindir / name
                command.write_text(f'#!/bin/sh\n{body}\n')
                command.chmod(0o755)
            installer = root / 'targets/node-opc/install.sh'
            installer.parent.mkdir(parents=True)
            installer.symlink_to(ROOT / 'targets/node-opc/install.sh')
            wrapper = root / 'setup.sh'
            wrapper.write_text(SETUP_SH.format(target='node-opc'))
            env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}',
                       TEST_MARKER=str(root / 'copy-ran'))
            result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Cannot check out node-opcua revision', result.stderr)
            self.assertFalse((root / 'copy-ran').exists())

    def test_open62541_checkout_failure_stops_installers(self):
        for script in ('install.sh', 'tls_install.sh'):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bindir = root / 'bin'
                bindir.mkdir()
                for name, body in (('apt-get', 'exit 0'),
                                   ('git', 'if [ "$1" = clone ]; then mkdir open62541; else exit 33; fi')):
                    command = bindir / name
                    command.write_text(f'#!/bin/sh\n{body}\n')
                    command.chmod(0o755)
                installer = root / 'targets/open62541/install.sh'
                installer.parent.mkdir(parents=True)
                installer.symlink_to(ROOT / 'targets/open62541' / script)
                wrapper = root / 'setup.sh'
                wrapper.write_text(SETUP_SH.format(target='open62541'))
                env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}')
                result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot check out open62541 revision', result.stderr)
                self.assertFalse((root / 'target_build').exists())

    def test_node_download_failure_stops_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            for name, status in (('apt-get', 0), ('curl', 22)):
                command = bindir / name
                command.write_text(f'#!/bin/sh\nexit {status}\n')
                command.chmod(0o755)
            installer = root / 'targets/node-opc/install.sh'
            installer.parent.mkdir(parents=True)
            installer.symlink_to(ROOT / 'targets/node-opc/install.sh')
            wrapper = root / 'setup.sh'
            wrapper.write_text(SETUP_SH.format(target='node-opc'))
            env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}')
            result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env)
            self.assertEqual(result.returncode, 22)

    def test_java_unexpected_initialization_failure_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            for name in ('apt-get', 'wget', 'unzip', 'timeout'):
                command = bindir / name
                command.write_text('#!/bin/sh\nexit {}\n'.format(37 if name == 'timeout' else 0))
                command.chmod(0o755)
            installer = root / 'targets/java/install.sh'
            installer.parent.mkdir(parents=True)
            installer.symlink_to(ROOT / 'targets/java/install.sh')
            wrapper = root / 'setup.sh'
            wrapper.write_text(SETUP_SH.format(target='java'))
            env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}')
            result = subprocess.run(['bash', str(wrapper)], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 37)
            self.assertIn('initialization failed with status 37', result.stderr)


if __name__ == '__main__':
    unittest.main()
