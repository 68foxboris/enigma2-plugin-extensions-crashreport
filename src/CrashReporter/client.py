"""Find, read, delete and upload crash logs. No Enigma2 imports, cli.py uses this module too."""
from gzip import compress
from json import dump, dumps, loads
from os import O_CREAT, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, O_TRUNC, O_WRONLY, close, fdopen, fstat, fsync, open as osOpen, replace, scandir, stat, unlink
from os.path import abspath, split as splitPath
from re import compile, sub
from stat import S_ISREG
from time import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4


def _(text):  # Only marks the text for translation, plugin.py translates it.
	return text


class ReportError(Exception):
	def __str__(self):
		return self.args[0] % self.args[1:] if len(self.args) > 1 else self.args[0]


class NoRedirect(HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		raise ReportError(_("The server redirected the upload. Nothing was uploaded."))


class ReportClient:
	VERSION = "0.5"  # (API) version of the report client
	SERVER = "https://bugs.opena.tv"
	USER_AGENT = f"OpenATV-CrashReporter/{VERSION}"
	STATE_PATH = "/etc/enigma2/crashreport-state.json"  # In the settings backup, so a restore brings the reports back.
	MAX_STATE_BYTES = 1024 * 1024
	MAX_REPORTS = 50  # Also the server limit for one status request.
	MAX_LOG_BYTES = 16 * 1024 * 1024  # Logs and diagnostics after the privacy filter.
	MAX_JSON_BYTES = 20 * 1024 * 1024  # Report before compression.
	MAX_UPLOAD_BYTES = 4 * 1024 * 1024  # Compressed report.
	MAX_STATUS_BYTES = 1024 * 1024
	MAX_NOTE_CHARS = 4000
	TRACKING_PATTERN = compile(r"(?:[0-9]{8}|[0-9A-F]{4}(?:-[0-9A-F]{4}){7})")
	UPLOAD_ID_PATTERN = compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
	CRASH_PATTERN = compile(r"(?:-enigma\d?-crash|^enigma2_crash(?:_[\w-]+)?)\.log$")
	DEBUG_PATTERN = compile(r"-enigma\d?-debug\.log$")

	def logDirectories(self, debugPath):
		return list(dict.fromkeys((debugPath, "/home/root/logs/", "/tmp/")))

	def scanLogs(self, directories):
		crashLogs = []
		debugLogs = []
		seenPaths = set()
		for directory in directories:
			try:
				with scandir(directory) as entries:
					for index, entry in enumerate(entries):
						if index >= 2000:  # Don't scan huge folders completely.
							break
						logType = "crash" if self.CRASH_PATTERN.search(entry.name) else "debug" if self.DEBUG_PATTERN.search(entry.name) else None
						if logType and entry.path not in seenPaths and entry.is_file(follow_symlinks=False):
							info = entry.stat(follow_symlinks=False)
							seenPaths.add(entry.path)
							(crashLogs if logType == "crash" else debugLogs).append({
								"path": entry.path,
								"name": entry.name,
								"kind": logType,
								"size": info.st_size,
								"mtime": info.st_mtime,
								"mtime_ns": info.st_mtime_ns,
								"device": info.st_dev,
								"inode": info.st_ino
							})
			except FileNotFoundError:  # Not every log folder exists on every receiver.
				pass
			except OSError as err:
				print(f"[CrashReporter] Error {err.errno}: Unable to scan the directory '{directory}'!  ({err.strerror})")
		return sorted(crashLogs, key=lambda log: log["mtime"], reverse=True)[:30], sorted(debugLogs, key=lambda log: log["mtime"], reverse=True)[:30]

	def selectLogs(self, crashLog, debugLogs, includeDebug):
		selectedLogs = [crashLog]
		if includeDebug:  # Use the debug log closest in time, at most 6 hours apart.
			candidates = [x for x in debugLogs if abs(x["mtime"] - crashLog["mtime"]) <= 6 * 3600]
			if candidates:
				selectedLogs.append(min(candidates, key=lambda log: abs(log["mtime"] - crashLog["mtime"])))
		return selectedLogs

	def logIdentity(self, log):
		return f"{log['path']}:{log['size']}:{int(log['mtime'])}"

	def deleteCrashLog(self, crashLog, directories):
		path = abspath(crashLog["path"])
		directory, name = splitPath(path)
		if crashLog.get("kind") != "crash" or name != crashLog.get("name") or not self.CRASH_PATTERN.search(name) or directory not in {abspath(x) for x in directories}:
			raise ReportError(_("Only a selected crash log from the log folders can be deleted."))
		# The folder itself may be a link, like /tmp. A link at the file name is never followed.
		directoryFd = osOpen(directory, O_RDONLY | O_DIRECTORY)
		try:
			info = stat(name, dir_fd=directoryFd, follow_symlinks=False)
			if not S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (crashLog.get("device"), crashLog.get("inode"), crashLog.get("size"), crashLog.get("mtime_ns")):
				raise ReportError(_("The crash log has changed. Nothing was deleted."))
			unlink(name, dir_fd=directoryFd)
		finally:
			close(directoryFd)

	def readState(self):
		state = {}
		try:
			with open(self.STATE_PATH, encoding="UTF-8") as fd:
				data = loads(fd.read(self.MAX_STATE_BYTES))
			if isinstance(data, dict):
				state = data
		except (OSError, ValueError):
			pass
		return state

	def saveState(self, state):
		state.pop("last_report", None)  # Written by older versions, never read.
		tempPath = f"{self.STATE_PATH}.tmp"
		with fdopen(osOpen(tempPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600), "w", encoding="UTF-8") as fd:
			dump(state, fd)
			fd.flush()
			fsync(fd.fileno())
		replace(tempPath, self.STATE_PATH)

	def readLog(self, log, bytesLeft):
		with fdopen(osOpen(log["path"], O_RDONLY | O_NOFOLLOW | O_NONBLOCK), "rb") as fd:
			info = fstat(fd.fileno())
			if not S_ISREG(info.st_mode) or info.st_size <= 0:
				raise ReportError(_("The selected log is not a regular, non-empty file."))
			if info.st_size > bytesLeft:
				raise ReportError(_("The logs exceed 16 MiB. Nothing was uploaded."))
			data = fd.read(info.st_size)  # Read a complete snapshot, even if the log is still growing.
			if len(data) != info.st_size:
				raise ReportError(_("The log changed while it was read. Please try again."))
		text = data.decode("UTF-8", errors="replace")
		if any(ord(x) < 32 and x not in "\r\n\t\x1b" for x in text):
			raise ReportError(_("The selected file contains binary data, not a text log."))
		name = sub(r"[^A-Za-z0-9_.-]", "_", log["name"])
		if name.startswith(".") or ".." in name or len(name) > 115:
			name = f"{log['kind']}.log"
		return {"kind": log["kind"], "name": name, "content": text}

	def prepareReport(self, receiverInfo, selectedLogs, diagnostics=None, sanitize=None, client=None):
		"""Build the report exactly as it is uploaded. cli.py uses it for --dry-run too."""
		if not any(x["kind"] == "crash" for x in selectedLogs):
			raise ReportError(_("Select a crash log first."))
		logs = []
		totalBytes = 0
		for selectedLog in selectedLogs:
			log = self.readLog(selectedLog, self.MAX_LOG_BYTES - totalBytes)
			if sanitize:
				log["content"] = sanitize(log["content"])
			totalBytes += len(log["content"].encode("UTF-8"))
			if totalBytes > self.MAX_LOG_BYTES:
				raise ReportError(_("The logs exceed 16 MiB. Nothing was uploaded."))
			logs.append(log)
		model, modelName, imageVersion, enigmaVersion = receiverInfo
		report = {
			"schema_version": 1,
			"upload_id": str(uuid4()),
			"model": model.lower(),
			"model_name": modelName,
			"image_version": imageVersion,
			"enigma_version": enigmaVersion,
			"consent": True,
			"logs": logs
		}
		if client:
			report["client"] = client
		if diagnostics:
			report["schema_version"] = 2
			report["diagnostics"] = diagnostics()
			totalBytes += sum(len(x["content"].encode("UTF-8")) for x in report["diagnostics"])
			if totalBytes > self.MAX_LOG_BYTES:
				raise ReportError(_("Logs and diagnostics exceed 16 MiB. Disable additional logs or configuration files and try again. Nothing was uploaded."))
		return report

	def serverCapabilities(self, opener):
		with opener.open(Request(f"{self.SERVER}/api/v1/report-capabilities", headers={"User-Agent": self.USER_AGENT}), timeout=10) as response:
			capabilities = loads(response.read(4097))
		if not isinstance(capabilities, dict):
			raise ValueError("Invalid capabilities")
		return capabilities

	def uploadReport(self, receiverInfo, selectedLogs, diagnostics=None, sanitize=None, client=None):
		opener = build_opener(NoRedirect)
		try:
			capabilities = self.serverCapabilities(opener)
		except (HTTPError, URLError, OSError, ValueError, TypeError):
			capabilities = {}
		if diagnostics and 2 not in capabilities.get("schema_versions", []):  # An old server would accept the report but drop the diagnostics.
			raise ReportError(_("The report server does not support diagnostics yet. Nothing was uploaded."))
		report = self.prepareReport(receiverInfo, selectedLogs, diagnostics, sanitize, client if capabilities.get("client_field") else None)  # An old server rejects unknown fields.
		data = dumps(report, ensure_ascii=False).encode("UTF-8")
		if len(data) > self.MAX_JSON_BYTES:
			raise ReportError(_("The report exceeds the server size limit. Nothing was uploaded."))
		data = compress(data, compresslevel=6)
		if len(data) > self.MAX_UPLOAD_BYTES:
			raise ReportError(_("The compressed report exceeds 4 MiB. Nothing was uploaded."))
		request = Request(f"{self.SERVER}/api/v1/reports", data=data, headers={"Content-Type": "application/gzip", "Accept": "application/json", "User-Agent": self.USER_AGENT}, method="POST")
		try:
			with opener.open(request, timeout=20) as response:
				result = loads(response.read(8193))
		except HTTPError as err:
			try:
				detail = loads(err.read(4096)).get("detail", "")
			except (ValueError, OSError):
				detail = ""
			raise ReportError(_("Upload rejected (HTTP %d). %s"), err.code, str(detail)[:200]) from None
		except (URLError, OSError, ValueError) as err:
			raise ReportError(_("Upload failed. The local logs were not deleted. %s"), str(err)[:180]) from None
		if not isinstance(result, dict) or not isinstance(result.get("tracking"), str) or not self.TRACKING_PATTERN.fullmatch(result["tracking"]) or result.get("model") != report["model"]:
			raise ReportError(_("The server returned an invalid tracking number or model."))
		result["complete_url"] = f"{self.SERVER}/crash-reports"  # Never send the user to a URL from the server.
		result["local_log"] = self.logIdentity(selectedLogs[0])
		result = {"upload_id": report["upload_id"], **result, "client": client or ""}
		state = self.readState()
		reports = [x for x in self.validReports(state) if x["upload_id"] != report["upload_id"]]
		reports.insert(0, {
			"upload_id": report["upload_id"],  # The proof of ownership on the server, never shown or put into the QR code.
			"tracking": result["tracking"],
			"model": report["model"],
			"sent": int(time()),
			"expires_at": result["expires_at"] if isinstance(result.get("expires_at"), int) else int(time()) + 48 * 3600,
			"log": selectedLogs[0]["name"],
			"client": client or "",
			"state": "submitted" if result.get("state") == "submitted" else "pending",
			"seen_note": 0
		})
		state["reports"] = reports[:self.MAX_REPORTS]
		if self.identityTime(result["local_log"]) >= self.identityTime(state.get("last_prompt")):  # Sending an older log must not offer the newest one again.
			state["last_prompt"] = result["local_log"]
		try:
			self.saveState(state)
		except OSError:
			result["save_warning"] = _("The tracking details could not be saved on the receiver. Please write down the number.")
		return result

	def identityTime(self, identity):
		try:
			seconds = int(str(identity).rsplit(":", 1)[1])
		except (IndexError, ValueError):
			seconds = 0
		return seconds

	def validReports(self, state):
		reports = state.get("reports")
		return [x for x in reports if isinstance(x, dict) and isinstance(x.get("upload_id"), str) and self.UPLOAD_ID_PATTERN.fullmatch(x["upload_id"]) and isinstance(x.get("tracking"), str)] if isinstance(reports, list) else []

	def hasNews(self, report):
		return report.get("developer_note", 0) > report.get("seen_note", 0)

	def refreshReports(self, uploadId=None):
		"""Returns the saved reports and the newest public notes per upload id. Asking for one report gives more notes."""
		reports = [x for x in self.validReports(self.readState()) if uploadId in (None, x["upload_id"])]
		notes = {}
		if reports:
			opener = build_opener(NoRedirect)
			try:
				capabilities = self.serverCapabilities(opener)
				if not capabilities.get("report_status"):
					raise ReportError(_("The report server does not support the report status yet."))
				data = dumps({"upload_ids": [x["upload_id"] for x in reports]}).encode("UTF-8")
				request = Request(f"{self.SERVER}/api/v1/reports/status", data=data, headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": self.USER_AGENT}, method="POST")
				with opener.open(request, timeout=20) as response:
					answer = loads(response.read(self.MAX_STATUS_BYTES + 1))
			except HTTPError as err:
				raise ReportError(_("The report status is not available (HTTP %d)."), err.code) from None
			except (URLError, OSError, ValueError, TypeError):
				raise ReportError(_("The report server is not reachable. Please try again later.")) from None
			results = {x["upload_id"]: x for x in answer.get("reports", []) if isinstance(x, dict) and isinstance(x.get("upload_id"), str)} if isinstance(answer, dict) else {}
			now = int(time())
			state = self.readState()  # Read again, an upload may have finished in the meantime.
			reports = []
			for report in self.validReports(state):
				if report["upload_id"] in results:
					notes[report["upload_id"]] = self.updateReport(report, results[report["upload_id"]])
				if report.get("issue") or report.get("expires_at", 0) > now:  # The server deletes uploads that were never submitted on the website.
					reports.append(report)
			state["reports"] = reports
			try:
				self.saveState(state)
			except OSError as err:
				print(f"[CrashReporter] Error {err.errno}: Unable to save the report status!  ({err.strerror})")
		return reports, notes

	def updateReport(self, report, result):
		notes = []
		if result.get("state") == "submitted":
			notes = [x for x in result.get("notes", []) if isinstance(x, dict) and isinstance(x.get("id"), int) and isinstance(x.get("text"), str)]
			report.update({
				"state": "submitted",
				"issue": result.get("issue"),
				"status": str(result.get("status", ""))[:40],
				"closed": bool(result.get("closed")),
				"writable": bool(result.get("writable")),
				"updated_on": result.get("updated_on"),
				"notes_total": result.get("notes_total", len(notes)),
				"developer_note": max([x["id"] for x in notes if x.get("from") == "developer"] + [report.get("developer_note", 0)])
			})
		elif result.get("state") == "pending":
			report["state"] = "pending"
			if isinstance(result.get("expires_at"), int):
				report["expires_at"] = result["expires_at"]
		elif result.get("state") == "unknown":
			report["state"] = "unknown"  # Expired, deleted or moved.
		return notes

	def canFinish(self, report):
		return report.get("state") == "pending" or (report.get("state") == "submitted" and not report.get("closed"))

	def finishReport(self, uploadId, status, text=""):
		"""Resolve or close the ticket, or discard an upload that was never submitted. The text goes to the ticket with the status."""
		opener = build_opener(NoRedirect)
		data = dumps({"upload_id": uploadId, "status": status, "text": text[:self.MAX_NOTE_CHARS]}, ensure_ascii=False).encode("UTF-8")
		request = Request(f"{self.SERVER}/api/v1/reports/close", data=data, headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": self.USER_AGENT}, method="POST")
		try:
			with opener.open(request, timeout=20) as response:
				result = loads(response.read(4097))
		except HTTPError as err:
			if err.code not in (404, 409):  # Unknown, expired or already closed: nothing is open on the server any more.
				raise ReportError(_("The report server rejected the request (HTTP %d)."), err.code) from None
			result = {"state": "unknown" if err.code == 404 else "closed"}
		except (URLError, OSError, ValueError):
			raise ReportError(_("The report server is not reachable. Please try again later.")) from None
		result = result if isinstance(result, dict) else {}
		if result.get("state") == "submitted":
			state = self.readState()
			for report in self.validReports(state):
				if report["upload_id"] == uploadId:
					report.update({"status": str(result.get("status", ""))[:40], "closed": bool(result.get("closed")), "writable": not result.get("closed") and report.get("writable", False)})
			self.saveState(state)
		return result

	def removeReport(self, uploadId, status="closed", text=""):
		"""An open ticket gets the status and a pending upload is discarded on the server first."""
		report = next((x for x in self.validReports(self.readState()) if x["upload_id"] == uploadId), None)
		if report and self.canFinish(report):
			self.finishReport(uploadId, status, text)  # Raises if the server is not reachable, the report stays.
		state = self.readState()
		state["reports"] = [x for x in self.validReports(state) if x["upload_id"] != uploadId]
		self.saveState(state)

	def markSeen(self, uploadId):
		state = self.readState()
		for report in self.validReports(state):
			if report["upload_id"] == uploadId:
				report["seen_note"] = report.get("developer_note", 0)
		self.saveState(state)

	def sendToTicket(self, uploadId, text="", logs=(), diagnostics=None, sanitize=None):
		text = text.strip()
		if len(text) > self.MAX_NOTE_CHARS or any(ord(x) < 32 and x not in "\n\t" for x in text):
			raise ReportError(_("The answer is too long or contains invalid characters."))
		opener = build_opener(NoRedirect)
		try:
			capabilities = self.serverCapabilities(opener)
		except (HTTPError, URLError, OSError, ValueError, TypeError):
			raise ReportError(_("The report server is not reachable. Please try again later.")) from None
		if not capabilities.get("report_additions"):
			raise ReportError(_("The report server does not accept answers from the receiver yet."))
		payload = {"upload_id": uploadId}
		if text:
			payload["text"] = text
		if logs or diagnostics:
			totalBytes = 0
			payload["logs"] = []
			for selectedLog in logs:
				log = self.readLog(selectedLog, self.MAX_LOG_BYTES - totalBytes)
				if sanitize:
					log["content"] = sanitize(log["content"])
				totalBytes += len(log["content"].encode("UTF-8"))
				if totalBytes > self.MAX_LOG_BYTES:
					raise ReportError(_("The logs exceed 16 MiB. Nothing was uploaded."))
				payload["logs"].append(log)
			if diagnostics:
				payload["diagnostics"] = diagnostics()
			path = "attachments"
		elif text:
			path = "note"
		else:
			raise ReportError(_("Enter an answer or select a file."))
		data = dumps(payload, ensure_ascii=False).encode("UTF-8")
		if path == "attachments":
			data = compress(data, compresslevel=6)
			if len(data) > self.MAX_UPLOAD_BYTES:
				raise ReportError(_("The compressed report exceeds 4 MiB. Nothing was uploaded."))
		request = Request(f"{self.SERVER}/api/v1/reports/{path}", data=data, headers={"Content-Type": "application/gzip" if path == "attachments" else "application/json", "Accept": "application/json", "User-Agent": self.USER_AGENT}, method="POST")
		try:
			with opener.open(request, timeout=30) as response:
				result = loads(response.read(4097))
		except HTTPError as err:
			try:
				detail = loads(err.read(4096)).get("detail", "")
			except (ValueError, OSError):
				detail = ""
			raise ReportError(_("Sending rejected (HTTP %d). %s"), err.code, str(detail)[:200]) from None
		except (URLError, OSError, ValueError) as err:
			raise ReportError(_("Sending failed. %s"), str(err)[:180]) from None
		return result if isinstance(result, dict) else {}


reportClient = ReportClient()
