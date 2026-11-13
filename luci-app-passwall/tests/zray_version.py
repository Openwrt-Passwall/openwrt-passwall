#!/usr/bin/env python3
"""Replay integer-only OpenWrt sleep, slow startup and probe cleanup."""
import os
import pathlib
import subprocess
import tempfile
import time

probe = pathlib.Path('root/usr/share/passwall/zray_check.sh').resolve()

with tempfile.TemporaryDirectory(prefix='passwall-zray-version-test-') as directory:
    directory = pathlib.Path(directory)

    def script(name, body):
        path = directory / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)
        return path

    script('sleep', '''case "$1" in
    ''|*[!0-9]*) echo "sleep: invalid number '$1'" >&2; exit 1 ;;
esac
exec /bin/sleep "$@"
''')
    env = dict(os.environ, LC_ALL='C', PATH=str(directory) + ':' + os.environ['PATH'])
    pid_file = directory / 'pid'
    env['ZRAY_TEST_PID_FILE'] = str(pid_file)

    for delay, banner, expected in [(0, True, 0), (1, True, 0), (0, False, 1)]:
        binary = script('zray', '''echo $$ > "$ZRAY_TEST_PID_FILE"
sleep %s
%s
exec /bin/sleep 30
''' % (delay, "printf 'zray 0.4.0 socks5/http [127.0.0.1:0]\\n'" if banner else ':'))
        start = time.monotonic()
        result = subprocess.run([str(probe), str(binary)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
        assert result.returncode == expected, result.stderr
        assert result.stdout == (b'0.4.0\n' if banner else b''), result.stdout
        assert b'invalid number' not in result.stderr, result.stderr
        assert time.monotonic() - start < 6
        try:
            os.kill(int(pid_file.read_text()), 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('probe process was left running')

print('Zray version probe: integer-only sleep, delayed banner, timeout and process cleanup passed')
