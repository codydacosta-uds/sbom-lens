import json
from pathlib import Path

import pytest
from textual.widgets import Input, Select, DataTable
from sbom_lens.app import Lens


@pytest.mark.asyncio
async def test_load_and_exact_search(tmp_path):
    file = tmp_path / 'test.json'
    file.write_text(json.dumps({'bomFormat': 'CycloneDX', 'metadata': {'component': {'name': 'example', 'version': '1'}},
        'components': [{'name': 'node', 'version': '22.23.2'}, {'name': '/opt/node_modules/package'}]}))
    app = Lens()
    async with app.run_test(size=(130, 52)) as pilot:
        app.query_one('#reference', Input).value = str(file)
        await pilot.click('#load')
        for _ in range(80):
            await pilot.pause(.03)
            if app.current and not app.busy:
                break
        assert app.current
        app.query_one('#search', Input).value = 'node'
        await pilot.pause()
        assert len(app.filtered_components) == 1
        assert app.filtered_components[0].version == '22.23.2'
        assert app.query_one(DataTable).row_count == 1
        app.query_one(DataTable).focus()
        await pilot.press('enter')
