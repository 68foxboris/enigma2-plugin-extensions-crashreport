"""Bounded, consent-only receiver diagnostics; never execute or archive user files."""
from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
from time import monotonic

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_FILES = 256
MAX_SCAN = 2000
MAX_EXTRA_LOGS = 12
TEXT_NAMES = ("settings", "lamedb", "lamedb5", "bouquets.*", "userbouquet.*", "alternatives.*",
	"*.xml", "blacklist", "whitelist", "whitelist_streamrelay")
SECRET_NAME = re.compile(r"password|passwd|secret|token|credential|private|oauth|crashreport|oscam|ncam|cccam|mgcamd|gbox|softcam|\.pem$|\.key$|\.p12$", re.I)
SECRET_KEY = r"[\w.:-]{0,128}(?:password|passwd|passphrase|secret|token|credential|api[_-]?key|authorization|cookie|psk|pin|username|login|email)[\w.:-]{0,128}"
SECRET_HINT = re.compile(r"password|passwd|passphrase|secret|token|credential|api[_-]?key|authorization|cookie|psk|pin|username|login|email|\b(?:user|pass|key|mail|pwd|cw[01]?|aeskey|deskey|boxkey|rsakey)\b", re.I)
SECRET_ASSIGNMENT = re.compile(r"(?i)([\"']?" + SECRET_KEY + r"[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;<>]+)")
SECRET_XML = re.compile(r"(?is)(<(" + SECRET_KEY + r")(?:\s[^>]*)?>).*?(</\2\s*>)")
GENERIC_SECRET = re.compile(r"(?i)((?<![\w])[\"']?(?:user|pass|key|mail|pwd)[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;<>]+)")
GENERIC_XML = re.compile(r"(?is)(<(user|pass|key|mail|pwd)(?:\s[^>]*)?>).*?(</\2\s*>)")
URL = re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s<>\"']+|[a-z][a-z0-9+.-]*%(?:25)*3a[^\s<>\"']+")
LOG_NAME = re.compile(r"(?i)^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.log(?:\.[1-3])?$")
SAFE_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")


def sanitize_text(text, settings=False):
	"""Best effort, not an anonymity guarantee; full log timelines are retained."""
	# Bound regex work even for a malicious or corrupt megabyte-long line. The
	# whole file is rejected, never silently shortened and never sent unfiltered.
	if any(len(line) > 16384 for line in text.splitlines()):
		raise ValueError("A line exceeds the privacy filter limit (16 KiB). The file was not uploaded.")
	text = re.sub(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[PRIVATE KEY REMOVED]", text)
	if "<" in text:
		text = SECRET_XML.sub(lambda match: match[1] + "[REDACTED]" + match[3], text)
		text = GENERIC_XML.sub(lambda match: match[1] + "[REDACTED]" + match[3], text)
	lines = []
	for line in text.splitlines(keepends=True):
		if settings:
			key, separator, value = line.partition("=")
			if separator and (SECRET_NAME.search(key) or re.search(SECRET_KEY, key, re.I) or re.search(r"(?:^|[._])(?:user|pass|key|mail)(?:[._]|$)", key, re.I) or re.match(r"\s*[CNFLR]:", value, re.I)):
				line = key + "=[REDACTED]\n"
		if SECRET_HINT.search(line):
			# Whole unquoted assignments can contain spaces inside passwords.
			line = re.sub(r"(?i)^(\s*(?:" + SECRET_KEY + r"|user|pass|key|mail|pwd)\s*[:=]\s*)[^\r\n]*", r"\1[REDACTED]", line)
			line = SECRET_ASSIGNMENT.sub(lambda match: match[1] + '"[REDACTED]"', line)
			line = GENERIC_SECRET.sub(lambda match: match[1] + '"[REDACTED]"', line)
			line = re.sub(r"(?i)^([^\r\n]*\b(?:control[ -]?word|cw[01]?|aeskey|deskey|boxkey|rsakey)\b\s*[:=])[^\r\n]*", r"\1 [REDACTED]", line)
			line = re.sub(r"(?i)(authorization\s*:\s*|cookie\s*:\s*|set-cookie\s*:\s*)[^\r\n]*", r"\1[REDACTED]", line)
		line = re.sub(r"(?i)((?:^|[\s=])(?:C|N|F|L|R):[ \t]+)[^\r\n]*", r"\1[REDACTED]", line)
		if "://" in line or re.search(r"%(?:25)*3a", line, re.I):
			line = URL.sub("[URL REMOVED]", line)
		lines.append(line)
	return "".join(lines)


def decode_text(raw):
	text = raw.decode("utf-8", errors="replace")
	if any(ord(char) < 32 and char not in "\r\n\t\x1b" for char in text):
		raise ValueError("binary data omitted")
	return text


def read_regular(path, limit=MAX_FILE, virtual=False):
	# Directory descriptors prevent parent replacement / symlink races too.
	path = Path(path)
	flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
	if os.open in os.supports_dir_fd:
		parent = os.open(path.anchor or ".", flags | os.O_DIRECTORY)
		try:
			for part in path.parts[1:-1]:
				child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
				os.close(parent)
				parent = child
			fd = os.open(path.name, flags, dir_fd=parent)
		finally:
			os.close(parent)
	else:  # Host-side tests; receivers have POSIX openat/O_NOFOLLOW.
		if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
			raise ValueError("symbolic link omitted")
		fd = os.open(path, flags)
	with os.fdopen(fd, "rb") as source:
		info = os.fstat(source.fileno())
		if not stat.S_ISREG(info.st_mode):
			raise ValueError("non-regular file omitted")
		if info.st_size > limit:
			raise ValueError("file exceeds diagnostic size limit; omitted, not truncated")
		raw = source.read(limit + 1 if virtual else info.st_size)
		if len(raw) > limit:
			raise ValueError("file exceeds diagnostic size limit; omitted, not truncated")
		if not virtual and len(raw) != info.st_size:
			raise ValueError("file changed during snapshot; omitted")
	return decode_text(raw)


def run_command(arguments, limit=MAX_FILE, timeout=5):
	# Fixed argv only; a bounded pipe avoids both communicate() RAM growth and
	# unbounded temporary files in the receiver's small /tmp filesystem.
	process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
		stdin=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, start_new_session=True)
	output = bytearray()
	try:
		with selectors.DefaultSelector() as selector:
			selector.register(process.stdout, selectors.EVENT_READ)
			deadline = monotonic() + timeout
			while True:
				remaining = deadline - monotonic()
				if remaining <= 0:
					raise ValueError("command timed out; output omitted")
				if not selector.select(remaining):
					continue
				chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
				if not chunk:
					break
				output.extend(chunk)
				if len(output) > limit:
					raise ValueError("command output exceeds limit; omitted, not truncated")
		if process.wait(timeout=max(0.1, deadline - monotonic())):
			raise ValueError("command failed; output omitted")
		return decode_text(output)
	finally:
		if process.poll() is None:
			process.kill()
		process.wait()
		process.stdout.close()


class Collector:

	def __init__(self, root="/", command=run_command, max_total=MAX_TOTAL):
		self.root = Path(root).resolve()
		self.command = command
		self.max_total = max_total
		self.files = []
		self.total = 0
		self.notes = []
		self.names = set()
		self.started = monotonic()

	def note(self, path, reason):
		if len(self.notes) < 300:
			self.notes.append("%s: %s" % (str(path)[:160], reason))

	def add(self, name, text, settings=False):
		if len(name) > 200 or any(not SAFE_PART.fullmatch(part) or ".." in part or SECRET_NAME.search(part) for part in name.split("/")):
			self.note("diagnostic file", "unsafe or overly long archive path omitted")
			return False
		text = sanitize_text(text, settings=settings)
		size = len(text.encode("utf-8"))
		if name in self.names:
			return False
		if len(self.files) >= MAX_FILES - 1 or self.total + size > self.max_total or size > MAX_FILE:
			self.note(name, "diagnostic budget exceeded; omitted, not truncated")
			return False
		self.files.append({"path": name, "content": text})
		self.names.add(name)
		self.total += size
		return True

	def file(self, source, target=None, virtual=False, physical=None):
		if monotonic() - self.started > 20:
			self.note(source, "collection time budget exceeded; omitted")
			return
		try:
			text = read_regular(physical or self.root / source.lstrip("/"), virtual=virtual)
			self.add(target or source.lstrip("/"), text, settings=source == "/etc/enigma2/settings")
		except (OSError, ValueError):
			# Exception text can contain names/command output; do not leak it.
			self.note(source, "missing, unsafe, binary, changed, over 2 MiB or overlong line; omitted")

	def system(self):
		self.add("system/box-info.txt", "Collected UTC: %s\nKernel: %s\nArchitecture: %s\n" % (
			datetime.now(timezone.utc).isoformat(), os.uname().release, os.uname().machine))
		for source in ("/usr/lib/enigma.info", "/etc/image-version", "/etc/os-release", "/proc/stb/info/model",
			"/proc/stb/info/boxtype", "/proc/bus/nim_sockets", "/proc/cpuinfo", "/proc/meminfo", "/proc/uptime", "/proc/modules", "/proc/cmdline"):
			self.file(source, "system/" + source.rsplit("/", 1)[-1] + ".txt", virtual=source.startswith("/proc/"))
		for name, argv in (("packages", ["opkg", "list-installed"]),):
			try:
				text = self.command(argv)
				self.add("system/%s.txt" % name, text)
				if name == "packages":
					self.add("system/plugin-packages.txt", "".join(line + "\n" for line in text.splitlines() if line.startswith("enigma2-plugin-")))
			except (OSError, ValueError, subprocess.SubprocessError):
				self.note(name, "command unavailable, failed, timed out or over 2 MiB; omitted")
		# Also list manually copied plugins, which have no package-manager record.
		plugins = []
		for category in ("Extensions", "SystemPlugins"):
			folder = self.root / "usr/lib/enigma2/python/Plugins" / category
			try:
				with os.scandir(folder) as entries:
					for index, entry in enumerate(entries):
						if index >= MAX_SCAN:
							self.note(category, "plugin scan limit reached")
							break
						if entry.is_dir(follow_symlinks=False) and SAFE_PART.fullmatch(entry.name) and entry.name != "__pycache__":
							plugins.append(category + "/" + entry.name)
			except OSError:
				self.note(category, "plugin directory unavailable")
		self.add("system/plugin-directories.txt", "\n".join(sorted(plugins)) + "\n")

	def configuration(self):
		folder = self.root / "etc/enigma2"
		if folder.is_symlink():
			self.note("/etc/enigma2", "symbolic-link directory omitted")
			return
		count = 0
		for directory, directories, files in os.walk(folder, followlinks=False):
			relative = Path(directory).relative_to(folder)
			directories[:] = sorted(name for name in directories if len(relative.parts) < 2 and SAFE_PART.fullmatch(name)
				and not SECRET_NAME.search(name) and not (Path(directory) / name).is_symlink())[:64]
			for name in sorted(files):
				count += 1
				if count > MAX_SCAN:
					self.note("/etc/enigma2", "configuration scan limit reached")
					return
				path = "/etc/enigma2/" + (relative / name).as_posix()
				if not SAFE_PART.fullmatch(name) or SECRET_NAME.search(name) or not any(fnmatch.fnmatchcase(name, pattern) for pattern in TEXT_NAMES):
					self.note(path, "not an approved E2 text configuration; omitted")
					continue
				self.file(path)

	def logs(self, directories, excluded):
		candidates = []
		seen = set()
		for source in dict.fromkeys(["/tmp", "/home/root/logs", *directories]):
			try:
				# E2 commonly maps /tmp to /var/volatile/tmp. Resolve only the
				# explicitly selected root; links inside it remain forbidden.
				folder = (self.root / source.lstrip("/")).resolve(strict=True)
				folder.relative_to(self.root.resolve())
				with os.scandir(folder) as entries:
					for index, entry in enumerate(entries):
						if index >= MAX_SCAN:
							self.note(source, "log scan limit reached")
							break
						path = source.rstrip("/") + "/" + entry.name
						if SECRET_NAME.search(entry.name):
							self.note(path, "known softcam/key/credential file excluded")
							continue
						if path not in excluded and entry.path not in seen and LOG_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
							seen.add(entry.path)
							candidates.append((entry.stat(follow_symlinks=False).st_mtime, path, entry.name, entry.path))
			except (OSError, ValueError):
				self.note(source, "log directory unavailable")
		for index, (_, path, name, physical) in enumerate(sorted(candidates, reverse=True)):
			if index < MAX_EXTRA_LOGS:
				self.file(path, "logs/%02d-%s.txt" % (index + 1, name), physical=physical)
			else:
				self.note(path, "only the 12 newest additional logs are included")

	def system_logs(self):
		try:
			self.add("system/dmesg.txt", self.command(["dmesg"]))
		except (OSError, ValueError, subprocess.SubprocessError):
			self.note("dmesg", "command unavailable, failed, timed out or over 2 MiB; omitted")
		try:
			folder = (self.root / "var/log").resolve(strict=True)
			folder.relative_to(self.root.resolve())
			for name in ("messages", "messages.1"):
				self.file("/var/log/" + name, "logs/" + name + ".txt", physical=folder / name)
		except (OSError, ValueError):
			self.note("/var/log", "system log directory unavailable")

	def collect(self, directories=(), excluded=(), options=None):
		if options is None:
			options = {"box_info": True, "configuration": True, "system_logs": True, "extra_logs": True}
		for key, collect in (("box_info", self.system), ("configuration", self.configuration),
			("system_logs", self.system_logs), ("extra_logs", lambda: self.logs(directories, excluded))):
			if options.get(key, False):
				collect()
			else:
				self.note(key, "disabled by user")
		manifest = ["OpenATV receiver diagnostics (current state, not necessarily the crash-time state).",
			"Known credential fields, private keys and URLs were removed on the receiver.",
			"Redaction is best effort. Personal data may remain. Do not publish this archive.",
			"No commands from user files were executed. No symlinks/devices/databases/binary files included.",
			"Known softcam/key/credential files are excluded, not backed up.",
			"Limits: 2 MiB/file, 8 MiB diagnostics, 256 files, 12 additional logs; no silent truncation.",
			"Files containing lines over 16 KiB are refused by the privacy filter.",
			"Configuration uses an allowlist: settings, service/bouquet lists, XML, black/whitelists.",
			"Included files:", *(item["path"] for item in self.files), "Omissions / notes:", *self.notes]
		# Reserve the final slot and up to 64 KiB separately for the manifest.
		self.files.append({"path": "system/manifest.txt", "content": "\n".join(manifest) + "\n"})
		return self.files


def collect_diagnostics(directories=(), excluded=(), options=None):
	return Collector().collect(directories, excluded, options)


def diagnostics_for(selected, directories, options):
	"""The collector for upload_report(), None when every option is off."""
	excluded = [item["path"] for item in selected]
	return (lambda: collect_diagnostics(directories, excluded, options)) if any(options.values()) else None
