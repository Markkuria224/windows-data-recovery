from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
SHARES_DIR = DATA_DIR / "shares"
INDEX_FILE = DATA_DIR / "index.json"


def ensure_storage() -> None:
    SHARES_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text("{}", encoding="utf-8")


def load_index() -> dict[str, dict]:
    ensure_storage()
    return json.loads(INDEX_FILE.read_text(encoding="utf-8"))


def save_index(index: dict[str, dict]) -> None:
    INDEX_FILE.write_text(json.dumps(index, indent=2), encoding="utf-8")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_expired(share: dict) -> bool:
    expires_at = share.get("expires_at")
    if not expires_at:
        return False
    return datetime.fromisoformat(expires_at) <= utc_now()


def read_body(handler: SimpleHTTPRequestHandler) -> dict:
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw_body = handler.rfile.read(content_length)
    if not raw_body:
        return {}
    return json.loads(raw_body.decode("utf-8"))


class ShareHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(APP_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/shares":
            self.handle_list_shares()
            return
        if parsed.path.startswith("/api/share/"):
            token = parsed.path.split("/")[-1]
            self.handle_get_share(token)
            return
        if parsed.path == "/download":
            self.path = "/download.html"
        elif parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/share":
            self.handle_create_share()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Route not found")

    def log_message(self, format: str, *args) -> None:
        return

    def json_response(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_create_share(self) -> None:
        payload = read_body(self)

        required_fields = [
            "filename",
            "mimeType",
            "ciphertext",
            "salt",
            "iv",
            "iterations",
            "expiresInHours",
            "maxDownloads",
        ]
        if any(field not in payload for field in required_fields):
            self.json_response({"error": "Missing fields for encrypted share upload."}, HTTPStatus.BAD_REQUEST)
            return

        try:
            ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
            base64.b64decode(payload["salt"], validate=True)
            base64.b64decode(payload["iv"], validate=True)
            iterations = int(payload["iterations"])
            expires_in_hours = int(payload["expiresInHours"])
            max_downloads = int(payload["maxDownloads"])
            if iterations < 100000 or expires_in_hours < 1 or max_downloads < 1:
                raise ValueError("Unsafe or invalid share parameters.")
        except Exception:
            self.json_response({"error": "Invalid encoded payload."}, HTTPStatus.BAD_REQUEST)
            return

        token = secrets.token_urlsafe(9)
        share_path = SHARES_DIR / f"{token}.bin"
        share_path.write_bytes(ciphertext)

        expires_at = (utc_now() + timedelta(hours=expires_in_hours)).isoformat()
        index = load_index()
        index[token] = {
            "filename": payload["filename"],
            "mime_type": payload["mimeType"],
            "salt": payload["salt"],
            "iv": payload["iv"],
            "iterations": iterations,
            "expires_at": expires_at,
            "created_at": utc_now().isoformat(),
            "max_downloads": max_downloads,
            "download_count": 0,
            "file_size": len(ciphertext),
        }
        save_index(index)

        share_url = f"http://{self.headers.get('Host', '127.0.0.1:8000')}/download?token={token}"
        self.json_response(
            {
                "token": token,
                "shareUrl": share_url,
                "expiresAt": expires_at,
            },
            HTTPStatus.CREATED,
        )

    def handle_get_share(self, token: str) -> None:
        index = load_index()
        share = index.get(token)
        if not share:
            self.json_response({"error": "Share token not found."}, HTTPStatus.NOT_FOUND)
            return

        if is_expired(share):
            self.delete_share(token)
            self.json_response({"error": "This share has expired."}, HTTPStatus.GONE)
            return

        if share["download_count"] >= share["max_downloads"]:
            self.delete_share(token)
            self.json_response({"error": "Download limit reached."}, HTTPStatus.GONE)
            return

        share_path = SHARES_DIR / f"{token}.bin"
        if not share_path.exists():
            self.delete_share(token)
            self.json_response({"error": "Encrypted file data is missing."}, HTTPStatus.NOT_FOUND)
            return

        ciphertext = base64.b64encode(share_path.read_bytes()).decode("utf-8")
        share["download_count"] += 1
        remaining_downloads = max(share["max_downloads"] - share["download_count"], 0)

        if share["download_count"] >= share["max_downloads"]:
            self.delete_share(token)
        else:
            index[token] = share
            save_index(index)

        self.json_response(
            {
                "token": token,
                "filename": share["filename"],
                "mimeType": share["mime_type"],
                "salt": share["salt"],
                "iv": share["iv"],
                "iterations": share["iterations"],
                "ciphertext": ciphertext,
                "expiresAt": share["expires_at"],
                "remainingDownloads": remaining_downloads,
            }
        )

    def handle_list_shares(self) -> None:
        index = load_index()
        active = []
        removed = False

        for token, share in list(index.items()):
            if is_expired(share) or share["download_count"] >= share["max_downloads"]:
                self.delete_share(token, index=index, persist=False)
                removed = True
                continue

            active.append(
                {
                    "token": token,
                    "filename": share["filename"],
                    "expiresAt": share["expires_at"],
                    "downloadCount": share["download_count"],
                    "maxDownloads": share["max_downloads"],
                    "fileSize": share["file_size"],
                }
            )

        if removed:
            save_index(index)

        self.json_response({"shares": active})

    def delete_share(self, token: str, index: dict[str, dict] | None = None, persist: bool = True) -> None:
        active_index = index if index is not None else load_index()
        share_path = SHARES_DIR / f"{token}.bin"
        if share_path.exists():
            share_path.unlink()
        if token in active_index:
            del active_index[token]
        if persist:
            save_index(active_index)


if __name__ == "__main__":
    ensure_storage()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), ShareHandler)
    print("Secure Share running on http://127.0.0.1:8000")
    server.serve_forever()
