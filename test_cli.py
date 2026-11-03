"""Integration checks using a real pseudo-terminal; only disposable test data."""
import os
import pty
import select
import subprocess
import tempfile
import time
from pathlib import Path

EXE = str(Path(__file__).resolve().parent / 'pm')
MASTER = 'test master phrase 2026'

def run(command, path, answers, success=True):
    master, slave = pty.openpty()
    proc = subprocess.Popen([EXE, command, str(path)], stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    output = b''
    cursor = 0
    try:
        for prompt, answer in answers:
            end = time.monotonic() + 15
            while prompt.encode() not in output[cursor:]:
                assert time.monotonic() < end, output
                if select.select([master], [], [], 0.1)[0]:
                    output += os.read(master, 65536)
            cursor = len(output)
            os.write(master, (answer + '\n').encode())
        end = time.monotonic() + 15
        while proc.poll() is None:
            assert time.monotonic() < end, output
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    break
        assert (proc.wait(timeout=15) == 0) == success, output
        assert MASTER.encode() not in output and b'Secret-entry-123' not in output, output
        return output
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'test.vault'
    auth = [('Master password: ', MASTER)]
    run('init', path, auth + [('Confirm master password: ', MASTER)])
    run('add', path, auth + [('Service: ', 'mail'), ('Username: ', 'alice'), ('Entry password: ', 'Secret-entry-123')])
    original = path.read_bytes()
    assert all(x not in original for x in [b'mail', b'alice', b'Secret-entry-123', MASTER.encode()])
    assert path.stat().st_mode & 0o777 == 0o600
    assert b'mail | alice | [hidden]' in run('list', path, auth)
    assert path.read_bytes() == original
    run('list', path, [('Master password: ', 'wrong')], False)
    assert path.read_bytes() == original
    run('init', path, auth + [('Confirm master password: ', MASTER)], False)
    assert path.read_bytes() == original
    run('update', path, auth + [('Service: ', 'mail'), ('Username: ', 'bob'), ('Entry password: ', 'Secret-entry-123')])
    assert b'mail | bob | [hidden]' in run('list', path, auth)
    run('delete', path, auth + [('Service: ', 'mail')])
    assert b'0 entries' in run('list', path, auth)
    damaged = bytearray(original)
    damaged[-1] ^= 1
    path.write_bytes(damaged)
    run('list', path, auth, False)
    assert path.read_bytes() == damaged
    path.write_bytes(b'broken')
    run('list', path, auth, False)
print('PASS: create, encrypted persistence, hidden output, wrong password, no overwrite, update, delete, tamper, truncation, permissions')
