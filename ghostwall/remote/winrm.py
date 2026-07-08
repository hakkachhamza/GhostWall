"""Thin WinRM session wrapper around pywinrm."""

from __future__ import annotations

from typing import Any, Dict, Optional

try:
    import winrm as winrm_module  # type: ignore
except ImportError:  # pragma: no cover
    winrm_module = None  # type: ignore


class WinRMSession:
    """Encapsulate a single WinRM session.

    Args:
        host: Target hostname or IP address.
        username: Administrative username.
        password: Administrative password.
        transport: WinRM auth transport (ntlm, kerberos, basic, credssp).
        use_ssl: If True, connect over HTTPS on port 5986; otherwise HTTP 5985.
        server_cert_validation: How to validate the remote TLS certificate.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        transport: str = "ntlm",
        use_ssl: bool = True,
        server_cert_validation: str = "ignore",
    ) -> None:
        if winrm_module is None:
            raise RuntimeError("pywinrm is required for remote orchestration (pip install pywinrm).")
        self.host = host
        self.username = username
        self.password = password
        self.transport = transport
        self.use_ssl = use_ssl
        self.server_cert_validation = server_cert_validation
        self._session: Optional[Any] = None

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        port = 5986 if self.use_ssl else 5985
        return f"{scheme}://{self.host}:{port}/wsman"

    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = winrm_module.Session(
                self.endpoint,
                auth=(self.username, self.password),
                transport=self.transport,
                server_cert_validation=self.server_cert_validation,
            )
        return self._session

    def run_ps(self, script: str) -> Dict[str, Any]:
        """Execute a PowerShell script on the remote host."""
        result = self.session.run_ps(script)
        return {
            "status_code": result.status_code,
            "stdout": result.std_out.decode("utf-8", errors="ignore").strip(),
            "stderr": result.std_err.decode("utf-8", errors="ignore").strip(),
        }
