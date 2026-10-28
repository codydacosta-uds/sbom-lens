import json
import threading
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sbom_lens.core import Component, DependencyTrack, acquire, load_sbom, search, validate_ref


def test_exact_search_avoids_paths():
    rows = [Component('node', '22.23.2', 'binary'), Component('/opt/node_modules/lib', '', 'file')]
    assert search(rows, 'NODE') == rows[:1]
    assert len(search(rows, 'node', False)) == 2
    assert search(rows, '') == rows


def test_syft_and_locations(tmp_path):
    p = tmp_path / 'sbom.json'
    p.write_text(json.dumps({'source': {'name': 'image', 'version': 'v1'}, 'artifacts': [
        {'name': 'node', 'version': '22', 'type': 'binary', 'locations': [{'path': '/bin/node'}]}]}))
    sbom = load_sbom(p)
    assert sbom.components[0].locations == ('/bin/node',)
    assert sbom.format == 'syft'


def test_cyclonedx_nested(tmp_path):
    p = tmp_path / 'sbom.json'
    p.write_text(json.dumps({'bomFormat': 'CycloneDX', 'components': [
        {'name': 'parent', 'components': [{'name': 'node', 'version': '22'}]}]}))
    assert [c.name for c in load_sbom(p).components] == ['parent', 'node']


def test_unsupported_format(tmp_path):
    p = tmp_path / 'spdx.json'
    p.write_text('{"spdxVersion":"SPDX-2.3"}')
    with pytest.raises(ValueError, match='Unsupported'):
        load_sbom(p)


@pytest.mark.parametrize('ref', ['--bad', 'image with spaces', 'https://registry/image'])
def test_invalid_refs(ref):
    with pytest.raises(ValueError):
        validate_ref(ref)


def test_packages_need_oci():
    with pytest.raises(ValueError):
        validate_ref('r/package:1', package=True)


def test_local_files_need_no_zarf(tmp_path):
    p = tmp_path / 'sbom.json'
    p.write_text('{"bomFormat":"CycloneDX","components":[]}')
    with patch('sbom_lens.core.run') as run:
        assert len(acquire('file', str(p), 'amd64', tmp_path, threading.Event(), lambda _: None)) == 1
        run.assert_not_called()


@pytest.mark.parametrize('url', ['http://remote.example', 'https://user:password@example.com',
                                'https://example.com?key=secret', 'file:///tmp/test'])
def test_safe_tracker_urls(url):
    with pytest.raises(ValueError):
        DependencyTrack(url, 'secret')


def test_component_lookup_paginates_exactly():
    client = DependencyTrack('http://localhost:8080', 'secret')
    page = [{'name': '/node_modules/package'}] * 100
    with patch.object(client, 'request', side_effect=[page, [{'name': 'node', 'version': '22'}]]) as request:
        rows = client.exact_component('project', 'node', threading.Event())
    assert rows == [{'name': 'node', 'version': '22'}]
    assert request.call_count == 2
    client.close()


def test_cancel_lookup():
    client = DependencyTrack('http://localhost:8080', 'secret')
    event = threading.Event()
    event.set()
    from sbom_lens.core import Cancelled
    with pytest.raises(Cancelled):
        client.exact_component('project', 'node', event)
    client.close()


def test_no_redirect_with_api_key():
    client = DependencyTrack('http://localhost:8080', 'secret')
    response = Mock(status_code=302)
    with patch.object(client.session, 'request', return_value=response) as request:
        with pytest.raises(RuntimeError, match='302'):
            client.request('GET', '/api/v1/project')
        assert request.call_args.kwargs['allow_redirects'] is False
    client.close()
