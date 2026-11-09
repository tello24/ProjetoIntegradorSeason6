from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.dependencies import CurrentUser
from app.api.routes.scans import remove_scan
from app.services.scan_deletion import delete_scan


@pytest.mark.parametrize("role", ["analista", "gestor", "visualizador"])
async def test_only_administrators_can_delete_scans(role):
    session = AsyncMock()
    user = CurrentUser(uuid4(), "Teste", "test@example.com", 12, "Teste", role)
    with pytest.raises(HTTPException) as exc:
        await remove_scan(scan_id=99, current_user=user, session=session)
    assert exc.value.status_code == 403
    session.execute.assert_not_called()


@pytest.mark.parametrize("row,expected", [
    (None, 404),
    ({"id": 99, "nome": "Processando", "status": "processando"}, 409),
])
async def test_missing_foreign_or_processing_scan_is_not_deleted(row, expected):
    result = MagicMock()
    result.mappings.return_value.one_or_none.return_value = row
    session = AsyncMock()
    session.execute.return_value = result
    with pytest.raises(HTTPException) as exc:
        await delete_scan(session=session, client_id=12, user_id=uuid4(), scan_id=99)
    assert exc.value.status_code == expected
    query, params = session.execute.call_args_list[1].args
    assert "cliente_id = :client_id" in str(query)
    assert params == {"client_id": 12, "scan_id": 99}
    assert session.execute.call_count == 2
    session.commit.assert_not_called()
