"""Small, testable log uploader; no Enigma2 imports and no shared API token."""
import gzip
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_WIRE_BYTES = 4 * 1024 * 1024
MAX_DECODED_BYTES = 20 * 1024 * 1024
STATE_PATH = "/etc/enigma2/crashreport-state.json"
CRASH_PATTERN = re.compile(r"(?:-enigma\d?-crash|^enigma2_crash(?:_[\w-]+)?)\.log$")
DEBUG_PATTERN = re.compile(r"-enigma\d?-debug\.log$")


class ReportError(Exception):

	def __str__(self):
		return self.args[0] % self.args[1:] if len(self.args) > 1 else self.args[0]


class NoRedirect(HTTPRedirectHandler):

	def redirect_request(self, req, fp, code, msg, headers, newurl):
		raise ReportError("The server redirected the upload. Check the configured server URL.")


def validate_endpoint(url, allow_lan_http=False):
	if not isinstance(url, str) or any(ord(char) < 32 for char in url):
		raise ReportError("Enter a valid server URL without control characters.")
	try:
		parts = urlsplit(url.strip())
		parts.port  # Validate port and IPv6 syntax before sending any logs.
	except ValueError:
		raise ReportError("The server URL has an invalid address or port.") from None
	if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
		raise ReportError("Enter the server origin only, for example https://reports.example.org.")
	if parts.scheme == "http":
		try:
			address = ipaddress.ip_address(parts.hostname)
			private = any(address in ipaddress.ip_network(net) for net in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8", "::1/128"))
		except ValueError:
			private = False
		if not allow_lan_http or not private:
			raise ReportError("HTTPS is required. HTTP is only allowed for an explicitly enabled LAN test using a private IP address.")
	return url.strip().rstrip("/")


def read_state(path=STATE_PATH):
	try:
		with open(path, encoding="utf-8") as source:
			data = json.loads(source.read(65537))
		return data if isinstance(data, dict) else {}
	except (OSError, ValueError):
		return {}


def save_state(data, path=STATE_PATH):
	target = Path(path)
	temporary = target.with_name(target.name + ".tmp")
	fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
	with os.fdopen(fd, "w", encoding="utf-8") as output:
		json.dump(data, output)
		output.flush()
		os.fsync(output.fileno())
	os.replace(temporary, target)


def scan_logs(directories):
	crashes, debug = [], []
	seen = set()
	for directory in directories:
		try:
			with os.scandir(directory) as entries:
				for index, entry in enumerate(entries):
					if index >= 2000:
						break
					if not entry.is_file(follow_symlinks=False) or entry.path in seen:
						continue
					kind = "crash" if CRASH_PATTERN.search(entry.name) else "debug" if DEBUG_PATTERN.search(entry.name) else None
					if kind:
						info = entry.stat(follow_symlinks=False)
						seen.add(entry.path)
						item = {"path": entry.path, "name": entry.name, "size": info.st_size, "mtime": info.st_mtime, "kind": kind,
							"device": info.st_dev, "inode": info.st_ino, "mtime_ns": info.st_mtime_ns}
						(crashes if kind == "crash" else debug).append(item)
		except OSError:
			continue
	return sorted(crashes, key=lambda item: item["mtime"], reverse=True)[:30], sorted(debug, key=lambda item: item["mtime"], reverse=True)[:30]


def log_identity(item):
	return "%s:%s:%s" % (item["path"], item["size"], int(item["mtime"]))


def delete_crash_log(item, directories):
	"""Delete one explicitly confirmed local crash log, never related files."""
	path = os.path.abspath(item["path"])
	parent, name = os.path.split(path)
	if item.get("kind") != "crash" or name != item.get("name") or not CRASH_PATTERN.search(name) or parent not in {os.path.abspath(directory) for directory in directories}:
		raise ReportError("Only a selected crash log from the configured log folders can be deleted.")
	# /tmp itself can be a system symlink. Pin its directory descriptor and use
	# no-follow stat/unlink relative to it; never traverse a selected file link.
	fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
	try:
		info = os.stat(name, dir_fd=fd, follow_symlinks=False)
		if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (item.get("device"), item.get("inode"), item.get("size"), item.get("mtime_ns")):
			raise ReportError("The crash log has changed. Reopen the list and select it again. Nothing was deleted.")
		os.unlink(name, dir_fd=fd)
	finally:
		os.close(fd)


def matching_debug(crash, debug):
	# Best-effort time match; the confirmation lists both filenames explicitly.
	candidates = [item for item in debug if abs(item["mtime"] - crash["mtime"]) <= 6 * 3600]
	return min(candidates, key=lambda item: abs(item["mtime"] - crash["mtime"])) if candidates else None


def read_log(item, remaining):
	fd = os.open(item["path"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
	with os.fdopen(fd, "rb") as source:
		info = os.fstat(source.fileno())
		if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
			raise ReportError("The selected log is not a regular, non-empty file.")
		if info.st_size > remaining:
			raise ReportError("The complete logs exceed 16 MiB. No log was truncated or uploaded.")
		# Read the complete snapshot, even if the active debug log is growing.
		raw = source.read(info.st_size)
		if len(raw) != info.st_size:
			raise ReportError("The log changed while it was being read. Please try again.")
	text = raw.decode("utf-8", errors="replace")
	if any(ord(char) < 32 and char not in "\r\n\t\x1b" for char in text):
		raise ReportError("The selected file contains binary data, not a text log.")
	name = re.sub(r"[^A-Za-z0-9_.-]", "_", item["name"])
	if name.startswith(".") or ".." in name or len(name) > 115:
		name = item["kind"] + ".log"
	return {"kind": item["kind"], "name": name, "content": text}


def upload_report(endpoint, model, model_name, image_version, enigma_version, selected, allow_lan_http=False, state_path=STATE_PATH, diagnostics=None, redact=None):
	endpoint = validate_endpoint(endpoint, allow_lan_http)
	if diagnostics is not None:
		# Check before reading configurations: older servers keep accepting v1,
		# but must not silently discard a requested diagnostic package.
		try:
			with build_opener(NoRedirect).open(endpoint + "/api/v1/report-capabilities", timeout=10) as response:
				capabilities = json.loads(response.read(4097))
			if not isinstance(capabilities, dict) or 2 not in capabilities.get("schema_versions", []):
				raise ValueError("unsupported schema")
		except (HTTPError, URLError, OSError, ValueError, TypeError):
			raise ReportError("The report server needs the diagnostics update. No report was uploaded.") from None
	if not any(item["kind"] == "crash" for item in selected):
		raise ReportError("Select a crash log first.")
	logs, total = [], 0
	for item in selected:
		log = read_log(item, MAX_LOG_BYTES - total)
		if redact is not None:
			log["content"] = redact(log["content"])
		total += len(log["content"].encode("utf-8"))
		if total > MAX_LOG_BYTES:
			raise ReportError("The complete logs exceed 16 MiB. No log was truncated or uploaded.")
		logs.append(log)
	payload = {"schema_version": 1, "upload_id": str(uuid4()), "model": model.lower(), "model_name": model_name,
		"image_version": image_version, "enigma_version": enigma_version, "consent": True, "logs": logs}
	if diagnostics is not None:
		payload["schema_version"] = 2
		payload["diagnostics"] = diagnostics()
		total += sum(len(item["content"].encode("utf-8")) for item in payload["diagnostics"])
		if total > MAX_LOG_BYTES:
			raise ReportError("Logs and diagnostics exceed 16 MiB. Disable additional logs or configuration collection and try again. Nothing was uploaded.")
	decoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
	if len(decoded) > MAX_DECODED_BYTES:
		raise ReportError("The report exceeds the server size limit. Nothing was uploaded.")
	wire = gzip.compress(decoded, compresslevel=6)
	if len(wire) > MAX_WIRE_BYTES:
		raise ReportError("The compressed logs exceed 4 MiB. No log was truncated or uploaded.")
	request = Request(endpoint + "/api/v1/reports", data=wire, headers={"Content-Type": "application/gzip", "Accept": "application/json", "User-Agent": "OpenATV-CrashReport/0.1"}, method="POST")
	try:
		with build_opener(NoRedirect).open(request, timeout=20) as response:
			result = json.loads(response.read(8193))
	except HTTPError as error:
		try:
			detail = json.loads(error.read(4096)).get("detail", "")
		except (ValueError, OSError):
			detail = ""
		raise ReportError("Upload rejected (HTTP %d). %s", error.code, str(detail)[:200]) from None
	except (URLError, OSError, ValueError) as error:
		raise ReportError("Upload failed. The local logs have not been deleted. %s", str(error)[:180]) from None
	if not isinstance(result, dict) or not isinstance(result.get("tracking"), str) or not re.fullmatch(r"(?:[0-9]{8}|[0-9A-F]{4}(?:-[0-9A-F]{4}){7})", result["tracking"]) or result.get("model") != model.lower():
		raise ReportError("The server returned an invalid tracking number or model.")
	# Never trust a response URL for redirecting a user to another host.
	result["complete_url"] = endpoint + "/crash-reports"
	result["local_log"] = log_identity(selected[0])
	state = read_state(state_path)
	state["last_report"] = result
	state["last_prompt"] = result["local_log"]
	try:
		save_state(state, state_path)
	except OSError:
		result["save_warning"] = "Tracking details could not be stored on the receiver. Please note the number."
	return result
