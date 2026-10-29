import json
import sys
import threading
from unittest.mock import patch

import pytest

from sbom_lens.core import Cancelled, acquire, run


def test_subprocess_is_not_a_shell():
    result = run([sys.executable, '-c', 'import sys;print(sys.argv[1])', '$(not executed)'],
                 threading.Event(), lambda _: None)
    assert result.strip() == '$(not executed)'


def test_cancel_before_subprocess():
    event = threading.Event()
    event.set()
    with pytest.raises(Cancelled):
        run([sys.executable, '-c', 'print("not run")'], event, lambda _: None)


def test_image_scan_uses_exact_ref_and_architecture(tmp_path):
    def scan(args, *unused):
        target = args[-1].split('=', 1)[1]
        with open(target, 'w') as file:
            json.dump({'source': {'name': 'r/image', 'version': 'v1'}, 'artifacts': []}, file)
        return ''
    with patch('sbom_lens.core.run', side_effect=scan) as command:
        result = acquire('image', 'r/image:v1', 'arm64', tmp_path, threading.Event(), lambda _: None)
    args = command.call_args.args[0]
    assert 'registry:r/image:v1' in args
    assert 'linux/arm64' in args
    assert result[0].version == 'v1'


def test_keyless_requires_both_identity_and_issuer(tmp_path):
    with pytest.raises(ValueError, match='both'):
        acquire('package', 'oci://r/package:v1', 'amd64', tmp_path,
                threading.Event(), lambda _: None, identity='trusted')
