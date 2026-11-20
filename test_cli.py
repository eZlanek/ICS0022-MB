"""Integration/security tests. Only synthetic secrets and temporary vaults are used."""
import errno
import fcntl
import json
import os
import pty
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXE = str(Path(os.environ.get('PM_EXE', ROOT / 'pm')).resolve())
TEST_EXE = str(Path(os.environ.get('PM_TEST_EXE', ROOT / 'pm-test')).resolve())
MASTER = 'test master phrase 2026'
PASSWORD = 'Secret-entry-123'


def child_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class Session:
    def __init__(self, command, path, exe=EXE, env=None, extra=()):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.process = subprocess.Popen(
            [exe, command, str(path), *extra], stdin=self.slave, stdout=self.slave,
            stderr=self.slave, preexec_fn=child_terminal,
            env={**os.environ, **(env or {})})
        self.output = b''
        self.cursor = 0

    def read(self, timeout=0.05):
        if select.select([self.master], [], [], timeout)[0]:
            try:
                self.output += os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise

    def expect(self, prompt):
        expected = prompt.encode()
        deadline = time.monotonic() + 20
        while expected not in self.output[self.cursor:]:
            self.read()
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError((prompt, self.output, self.process.poll()))
        self.cursor = len(self.output)

    def answer(self, prompt, answer):
        self.expect(prompt)
        data = answer.encode() if isinstance(answer, str) else answer
        os.write(self.master, data + b'\n')

    def stopped(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG | os.WUNTRACED)
            if pid:
                assert os.WIFSTOPPED(status), (status, self.output)
                return
            self.read()
        raise AssertionError(('test pause did not occur', self.output))

    def finish(self, expected=0):
        deadline = time.monotonic() + 20
        while self.process.poll() is None:
            self.read()
            if time.monotonic() > deadline:
                raise AssertionError(('hung process', self.output))
        for _ in range(3):
            self.read(0.01)
        assert self.process.returncode == expected, (self.process.returncode, self.output)
        # macOS revokes the slave when its controlling session exits; the master
        # retains the same terminal settings and remains queryable.
        assert termios.tcgetattr(self.master) == self.before, 'terminal mode was not restored'
        assert MASTER.encode() not in self.output, self.output
        assert PASSWORD.encode() not in self.output, self.output
        assert b'AddressSanitizer' not in self.output and b'runtime error:' not in self.output, self.output
        return self.output

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        os.close(self.master)
        os.close(self.slave)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PasswordManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_directory = tempfile.TemporaryDirectory(prefix='pm-base-')
        cls.base = Path(cls.base_directory.name).resolve() / 'base.vault'
        with Session('init', cls.base) as session:
            session.answer('Master password: ', MASTER)
            session.answer('Confirm master password: ', MASTER)
            session.finish()
        with Session('add', cls.base) as session:
            session.answer('Master password: ', MASTER)
            session.answer('Service: ', 'mail')
            session.answer('Username: ', 'alice')
            session.answer('Entry password: ', PASSWORD)
            session.finish()
        cls.original = cls.base.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.base_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='pm-case-')
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / 'test.vault'
        self.path.write_bytes(self.original)
        self.path.chmod(0o600)

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, command, fields=(), expected=0, master=MASTER, path=None, env=None, exe=EXE):
        with Session(command, path or self.path, exe, env) as session:
            session.answer('Master password: ', master)
            for prompt, value in fields:
                session.answer(prompt, value)
            return session.finish(expected)

    def no_prompt(self, command='list', path=None, **kwargs):
        with Session(command, path or self.path, **kwargs) as session:
            output = session.finish(1)
            self.assertNotIn(b'Master password:', output)
            self.assertIn(b'Operation failed.', output)

    def assert_unchanged(self):
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(list(self.root.glob('*.tmp.*')), [])

    def test_01_persistence_and_hidden_output(self):
        self.assertIn(b'mail | alice | [hidden]', self.invoke('list'))
        self.assert_unchanged()
        for secret in [b'mail', b'alice', PASSWORD.encode(), MASTER.encode()]:
            self.assertNotIn(secret, self.original)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_02_add_update_delete(self):
        self.invoke('add', [('Service: ', 'other'), ('Username: ', 'bob'), ('Entry password: ', PASSWORD)])
        first = self.path.read_bytes()
        self.assertNotEqual(first[38:62], self.original[38:62])
        self.invoke('update', [('Service: ', 'other'), ('Username: ', 'carol'), ('Entry password: ', 'New-secret-456')])
        self.assertNotEqual(first[38:62], self.path.read_bytes()[38:62])
        self.assertIn(b'other | carol | [hidden]', self.invoke('list'))
        self.invoke('delete', [('Service: ', 'other')])
        self.assertNotIn(b'other |', self.invoke('list'))

    def test_03_wrong_password_denied_for_every_operation(self):
        for command in ['list', 'add', 'update', 'delete']:
            with self.subTest(command=command):
                result = self.invoke(command, expected=1, master='wrong-password')
                self.assertNotIn(b'mail', result)
                self.assertNotIn(b'Service:', result)
                self.assert_unchanged()

    def test_04_init_refuses_overwrite(self):
        self.no_prompt('init')
        self.assert_unchanged()

    def test_05_init_confirmation_and_minimum(self):
        new = self.root / 'new.vault'
        self.invoke('init', expected=1, master='short', path=new)
        self.assertFalse(new.exists())
        self.invoke('init', [('Confirm master password: ', 'different-pass')], expected=1, path=new)
        self.assertFalse(new.exists())

    def test_06_tampering_and_header_cost_bounds(self):
        for offset in [0, 4, 5, 6, 14, 22, 38, 62, len(self.original) - 1]:
            with self.subTest(offset=offset):
                changed = bytearray(self.original)
                changed[offset] ^= 1
                self.path.write_bytes(changed)
                if offset < 22:
                    self.no_prompt()
                else:
                    self.invoke('list', expected=1)
                self.assertEqual(self.path.read_bytes(), changed)

    def test_07_file_size_limits(self):
        for data in [b'', b'broken', b'x' * (1024 * 1024 + 1)]:
            self.path.write_bytes(data)
            self.no_prompt()
            self.assertEqual(self.path.read_bytes(), data)

    def test_08_invalid_service_fields(self):
        invalid = [b'', b'x' * 257, b' leading', b'trailing ', b'a|b',
                   b'a\x00b', b'\x1b[31mred', b'\xc0\xaf', b'\xe2\x80\xaeabc']
        for value in invalid:
            with self.subTest(value=value[:12]):
                self.invoke('add', [('Service: ', value)], expected=1)
                self.assert_unchanged()

    def test_09_invalid_username_and_password(self):
        self.invoke('add', [('Service: ', 'new'), ('Username: ', b'a\x00b')], expected=1)
        for value in [b'', b'x' * 4097, b'\x1b[31m', b'\xc0\xaf']:
            with self.subTest(password_length=len(value)):
                self.invoke('add', [('Service: ', 'new'), ('Username: ', 'bob'),
                                    ('Entry password: ', value)], expected=1)
                self.assert_unchanged()

    def test_10_limits_unicode_and_metacharacters(self):
        self.invoke('add', [('Service: ', 'x' * 256), ('Username: ', 'почта-é-😀'),
                            ('Entry password: ', 'p' * 4096)])
        marker = self.root / 'injection-marker'
        malicious = f'$(touch {marker});`id`'
        self.invoke('add', [('Service: ', malicious), ('Username: ', 'alice'), ('Entry password: ', PASSWORD)])
        self.assertFalse(marker.exists())
        output = self.invoke('list')
        self.assertIn('почта-é-😀'.encode(), output)
        self.assertIn(malicious.encode(), output)

    def test_11_duplicate_and_missing_services(self):
        self.invoke('add', [('Service: ', 'mail')], expected=1)
        for command in ['update', 'delete']:
            self.invoke(command, [('Service: ', 'missing')], expected=1)
        self.assert_unchanged()

    def test_12_vault_permissions_enforced_on_every_operation(self):
        for mode in [0o644, 0o660, 0o400, 0o700]:
            self.path.chmod(mode)
            for command in ['list', 'add', 'update', 'delete']:
                with self.subTest(mode=oct(mode), command=command):
                    self.no_prompt(command)
        self.path.chmod(0o600)
        self.assert_unchanged()

    def test_13_symlinks_hardlinks_and_fifo(self):
        for kind in ['symlink', 'hardlink', 'fifo']:
            with self.subTest(kind=kind):
                alternate = self.root / 'alternate.vault'
                if kind == 'symlink': alternate.symlink_to(self.path)
                elif kind == 'hardlink': os.link(self.path, alternate)
                else: os.mkfifo(alternate, 0o600)
                self.no_prompt(path=alternate)
                alternate.unlink()
        self.assert_unchanged()

    def test_14_paths_and_directory_permissions(self):
        for path in [str(self.root / '../escape.vault'), str(self.root) + '//test.vault',
                     str(self.root / 'bad\x1bname'), str(self.root / ('a' * 181)),
                     str(self.root / 'test.vault') + '/']:
            self.no_prompt('init', path=path)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.no_prompt(path=alias / 'test.vault')
        self.root.chmod(0o777)
        try: self.no_prompt()
        finally: self.root.chmod(0o700)
        self.assert_unchanged()

    def test_15_lock_and_audit_file_safety(self):
        for suffix in ['.lock', '.audit.jsonl']:
            target = self.root / ('test.vault' + suffix)
            if target.exists(): target.unlink()
            target.symlink_to(self.path)
            self.no_prompt()
            target.unlink()
            target.write_text('')
            target.chmod(0o644)
            self.no_prompt()
            target.unlink()
        self.assert_unchanged()

    def test_16_busy_vault(self):
        with Session('list', self.path) as holder:
            holder.expect('Master password: ')
            self.no_prompt()
            os.write(holder.master, b'\x03')
            holder.finish(130)
        self.assertIn(b'mail', self.invoke('list'))

    def test_17_eof_and_interruption_during_hidden_input(self):
        for stage, responses in [
            ('Master password: ', []),
            ('Service: ', [('Master password: ', MASTER)]),
            ('Username: ', [('Master password: ', MASTER), ('Service: ', 'new')]),
            ('Entry password: ', [('Master password: ', MASTER), ('Service: ', 'new'), ('Username: ', 'bob')])]:
            for byte, expected in [(b'\x03', 130), (b'\x04', 1)]:
                with self.subTest(stage=stage, byte=byte):
                    with Session('add', self.path) as session:
                        for prompt, value in responses: session.answer(prompt, value)
                        session.expect(stage)
                        os.write(session.master, b'partial-secret' + byte)
                        output = session.finish(expected)
                        self.assertNotIn(b'partial-secret', output)
                    self.assert_unchanged()
        self.assertIn(b'mail', self.invoke('list'))

    def test_18_init_confirmation_ctrl_c(self):
        new = self.root / 'new.vault'
        with Session('init', new) as session:
            session.answer('Master password: ', MASTER)
            session.expect('Confirm master password: ')
            os.write(session.master, b'\x03')
            session.finish(130)
        self.assertFalse(new.exists())

    def test_19_signals_before_and_after_commit(self):
        for point in ['before_kdf', 'after_unlock', 'temp_created', 'before_commit', 'after_commit']:
            with self.subTest(point=point):
                self.path.write_bytes(self.original)
                with Session('update', self.path, TEST_EXE, {'PM_TEST_PAUSE': point}) as session:
                    session.answer('Master password: ', MASTER)
                    if point not in ['before_kdf', 'after_unlock']:
                        session.answer('Service: ', 'mail')
                        session.answer('Username: ', 'bob')
                        session.answer('Entry password: ', PASSWORD)
                    session.stopped()
                    os.kill(session.process.pid, signal.SIGINT)
                    os.kill(session.process.pid, signal.SIGCONT)
                    output = session.finish(130)
                self.assertEqual(list(self.root.glob('*.tmp.*')), [])
                if point == 'after_commit':
                    self.assertIn(b'Changes were saved.', output)
                    self.assertIn(b'mail | bob', self.invoke('list'))
                else:
                    self.assert_unchanged()
                    self.assertIn(b'mail | alice', self.invoke('list'))

    def test_20_kdf_interruption(self):
        with Session('list', self.path, TEST_EXE, {'PM_TEST_PAUSE': 'before_kdf'}) as session:
            session.answer('Master password: ', MASTER)
            session.stopped()
            os.kill(session.process.pid, signal.SIGCONT)
            time.sleep(0.04)
            os.kill(session.process.pid, signal.SIGINT)
            session.finish(130)
        self.assert_unchanged()

    def test_21_sigterm_cleanup(self):
        with Session('list', self.path) as session:
            session.expect('Master password: ')
            session.process.send_signal(signal.SIGTERM)
            session.finish(143)
        self.assert_unchanged()

    def test_22_write_failures_preserve_original(self):
        for point in ['temp_created', 'before_sync', 'before_commit']:
            with self.subTest(point=point):
                self.invoke('update', [('Service: ', 'mail'), ('Username: ', 'bob'),
                                      ('Entry password: ', PASSWORD)], expected=1,
                            exe=TEST_EXE, env={'PM_TEST_FAIL': point})
                self.assert_unchanged()

    def test_23_permission_change_before_commit(self):
        with Session('update', self.path, TEST_EXE, {'PM_TEST_PAUSE': 'after_unlock'}) as session:
            session.answer('Master password: ', MASTER)
            session.stopped()
            self.path.chmod(0o644)
            os.kill(session.process.pid, signal.SIGCONT)
            session.finish(1)
        self.path.chmod(0o600)
        self.assert_unchanged()

    def test_24_structured_logs_without_secrets(self):
        self.invoke('list')
        self.invoke('list', expected=1, master='incorrect-secret')
        with Session('list', self.path) as session:
            session.expect('Master password: ')
            os.write(session.master, b'\x03')
            session.finish(130)
        log = self.root / 'test.vault.audit.jsonl'
        data = log.read_text()
        for secret in [MASTER, PASSWORD, 'incorrect-secret', 'mail', 'alice', str(self.path)]:
            self.assertNotIn(secret, data)
        rows = [json.loads(line) for line in data.splitlines()]
        for row in rows:
            self.assertEqual(set(row), {'time', 'uid', 'pid', 'command', 'event', 'outcome'})
            self.assertEqual(row['uid'], os.getuid())
        self.assertTrue(any(row['event'] == 'authentication' and row['outcome'] == 'failure' for row in rows))
        self.assertTrue(any(row['event'] == 'interrupted' for row in rows))
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_25_generic_errors_no_paths_or_internals(self):
        result = self.invoke('list', expected=1, master='wrong-password')
        self.assertIn(b'Operation failed.', result)
        for forbidden in [str(self.path).encode(), b'Argon', b'errno', b'authentication_failed', b'bad_alloc']:
            self.assertNotIn(forbidden, result)
        self.no_prompt(command='unknown-command')
        self.no_prompt(extra=('extra-argument',))

    def test_26_no_terminal_input(self):
        result = subprocess.run([EXE, 'list', str(self.path)], input=MASTER.encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(MASTER.encode(), result.stdout + result.stderr)
        self.assert_unchanged()

    def test_27_test_hooks_not_in_production(self):
        if EXE == TEST_EXE: self.skipTest('sanitizer binary intentionally includes hooks')
        self.invoke('list', env={'PM_TEST_PAUSE': 'after_unlock', 'PM_TEST_FAIL': 'before_kdf'})
        executable = Path(EXE).read_bytes()
        self.assertNotIn(b'PM_TEST_PAUSE', executable)
        self.assertNotIn(b'PM_TEST_FAIL', executable)

    def test_28_failure_after_commit_reports_uncertain_success(self):
        output = self.invoke('update', [('Service: ', 'mail'), ('Username: ', 'bob'),
                            ('Entry password: ', PASSWORD)], expected=1,
                            exe=TEST_EXE, env={'PM_TEST_FAIL': 'after_commit'})
        self.assertIn(b'Operation may have completed.', output)
        self.assertEqual(list(self.root.glob('*.tmp.*')), [])
        self.assertIn(b'mail | bob', self.invoke('list'))

    def test_29_recheck_access_at_commit(self):
        with Session('update', self.path, TEST_EXE, {'PM_TEST_PAUSE': 'before_commit'}) as session:
            session.answer('Master password: ', MASTER)
            session.answer('Service: ', 'mail')
            session.answer('Username: ', 'bob')
            session.answer('Entry password: ', PASSWORD)
            session.stopped()
            self.path.chmod(0o644)
            os.kill(session.process.pid, signal.SIGCONT)
            session.finish(1)
        self.path.chmod(0o600)
        self.assert_unchanged()


if __name__ == '__main__':
    unittest.main(verbosity=2)
