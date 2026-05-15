from __future__ import annotations

from datetime import datetime

import httpx

from guardian_br.api.schemas import AuditQueryResponse
from guardian_br.core.redact_store import AuditRow


class DashboardAuthError(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}")


class AuditClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_s: float = 10.0,
    ) -> None:
        self._http = httpx.Client(
            base_url=base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout_s,
        )

    def fetch(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        max_rows: int = 5000,
    ) -> list[AuditRow]:
        seen_ids: set[str] = set()
        out: list[AuditRow] = []
        cursor_until = until

        while len(out) < max_rows:
            params: dict[str, str | int] = {"limit": min(1000, max_rows - len(out))}
            if since is not None:
                params["since"] = since.isoformat()
            if cursor_until is not None:
                params["until"] = cursor_until.isoformat()

            resp = self._http.get("/v1/audit", params=params)
            if resp.status_code in (401, 403):
                raise DashboardAuthError(resp.status_code)
            resp.raise_for_status()

            page = AuditQueryResponse.model_validate(resp.json())
            new_rows = [r for r in page.rows if r.id not in seen_ids]
            out.extend(new_rows)
            seen_ids.update(r.id for r in new_rows)

            if page.next_since is None or len(page.rows) == 0:
                break
            cursor_until = page.next_since

        return out

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> AuditClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
