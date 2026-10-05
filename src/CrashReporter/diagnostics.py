"""Collect receiver diagnostics and remove private data. No Enigma2 imports, cli.py uses this module too."""
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from os import O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, close, fdopen, fstat, open as osOpen, read, scandir, stat, supports_dir_fd, uname, walk
from os.path import basename, join
from pathlib import Path
from re import I, compile, escape, search, sub
from selectors import DefaultSelector, EVENT_READ
from stat import S_ISREG
from subprocess import DEVNULL, PIPE, Popen, STDOUT, SubprocessError
from time import monotonic

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILES = 256
MAX_SCAN = 2000
MAX_EXTRA_LOGS = 12
MAX_NOTES = 300
MAX_SECONDS = 20
MAX_LINE_LENGTH = 16384
CONFIGURATION_NAMES = (  # Only these files from /etc/enigma2 are collected.
	"settings",
	"lamedb",
	"lamedb5",
	"bouquets.*",
	"userbouquet.*",
	"alternatives.*",
	"*.xml",
	"blacklist",
	"whitelist",
	"whitelist_streamrelay"
)
SECRET_NAME = compile(r"password|passwd|secret|token|credential|private|oauth|crashreport|oscam|ncam|cccam|mgcamd|gbox|softcam|\.pem$|\.key$|\.p12$", I)
SECRET_KEY = r"[\w.:-]{0,128}(?:password|passwd|passphrase|secret|token|credential|api[_-]?key|authorization|cookie|psk|pin|username|login|email)[\w.:-]{0,128}"
SECRET_HINT = compile(r"password|passwd|passphrase|secret|token|credential|api[_-]?key|authorization|cookie|psk|pin|username|login|email|\b(?:user|pass|key|mail|pwd|cw[01]?|aeskey|deskey|boxkey|rsakey)\b", I)
SECRET_ASSIGNMENT = compile(r"(?i)([\"']?" + SECRET_KEY + r"[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;<>]+)")
SECRET_XML = compile(r"(?is)(<(" + SECRET_KEY + r")(?:\s[^>]*)?>).*?(</\2\s*>)")
GENERIC_SECRET = compile(r"(?i)((?<![\w])[\"']?(?:user|pass|key|mail|pwd)[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;<>]+)")
GENERIC_XML = compile(r"(?is)(<(user|pass|key|mail|pwd)(?:\s[^>]*)?>).*?(</\2\s*>)")
URL = compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s<>\"']+|[a-z][a-z0-9+.-]*%(?:25)*3a[^\s<>\"']+")
LOG_NAME = compile(r"(?i)^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.log(?:\.[1-3])?$")
SAFE_NAME = compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
LOCATION_KEY = compile(r"(?i)weather(?:city|location)|geocode|latitude|longitude|\.(?:city|location|lat|lon)$")  # Weather plugins store the place and its coordinates.
ECM_SOURCE = compile(r"(\[ePMTClient\] ECM Info [^\r\n]*?\| \d+ms \| )[^\r\n]*")  # Reader, protocol and card server of the softcam.
locationCache = (None, [])


def locationValues():
	"""The places and coordinates from the settings, so they are also removed where a plugin logs them."""
	global locationCache
	try:
		modified = stat("/etc/enigma2/settings").st_mtime
		if locationCache[0] != modified:
			values = set()
			with open("/etc/enigma2/settings", encoding="UTF-8", errors="replace") as fd:
				for line in fd:
					key, separator, value = line.rstrip("\n").partition("=")
					if separator and LOCATION_KEY.search(key):
						values.update(x.strip(" '\"()[]") for x in value.split(","))
			patterns = []
			for place in sorted((x for x in values if search(r"[^\W\d_]{3}", x) or search(r"^-?\d{1,3}\.\d{2,}$", x)), key=len, reverse=True):
				ending = r"\d*" if place[-1].isdigit() else r"(?!\w)"  # Coordinates may be logged with more decimals.
				patterns.append(compile(rf"(?<![\w.]){escape(place)}{ending}"))
			locationCache = (modified, patterns)
	except OSError:
		locationCache = (None, [])
	return locationCache[1]


def sanitizeText(text, settingsFile=False):
	"""Remove known passwords, keys, URLs, weather places and card servers. This is best effort, other private data may remain."""
	# Very long lines would make the regular expressions slow. Refuse the file, never send it unfiltered.
	if any(len(x) > MAX_LINE_LENGTH for x in text.splitlines()):
		raise ValueError("A line exceeds the privacy filter limit (16 KiB). The file was not uploaded.")
	text = sub(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[PRIVATE KEY REMOVED]", text)
	if "<" in text:
		text = SECRET_XML.sub(lambda found: f"{found[1]}[REDACTED]{found[3]}", text)
		text = GENERIC_XML.sub(lambda found: f"{found[1]}[REDACTED]{found[3]}", text)
	lines = []
	for line in text.splitlines(keepends=True):
		if settingsFile:
			key, separator, value = line.partition("=")
			if separator and (SECRET_NAME.search(key) or search(SECRET_KEY, key, I) or search(r"(?:^|[._])(?:user|pass|key|mail)(?:[._]|$)", key, I) or search(r"^\s*[CNFLR]:", value, I) or LOCATION_KEY.search(key)):
				line = f"{key}=[REDACTED]\n"
		if SECRET_HINT.search(line):
			line = sub(r"(?i)^(\s*(?:" + SECRET_KEY + r"|user|pass|key|mail|pwd)\s*[:=]\s*)[^\r\n]*", r"\1[REDACTED]", line)  # Unquoted passwords can contain spaces.
			line = SECRET_ASSIGNMENT.sub(lambda found: f"{found[1]}\"[REDACTED]\"", line)
			line = GENERIC_SECRET.sub(lambda found: f"{found[1]}\"[REDACTED]\"", line)
			line = sub(r"(?i)^([^\r\n]*\b(?:control[ -]?word|cw[01]?|aeskey|deskey|boxkey|rsakey)\b\s*[:=])[^\r\n]*", r"\1 [REDACTED]", line)
			line = sub(r"(?i)(authorization\s*:\s*|cookie\s*:\s*|set-cookie\s*:\s*)[^\r\n]*", r"\1[REDACTED]", line)
		line = sub(r"(?i)((?:^|[\s=])(?:C|N|F|L|R):[ \t]+)[^\r\n]*", r"\1[REDACTED]", line)  # CCcam style lines.
		if "://" in line or search(r"%(?:25)*3a", line, I):
			line = URL.sub("[URL REMOVED]", line)
		if "ECM Info" in line:
			line = ECM_SOURCE.sub(r"\1[REDACTED]", line)
		lines.append(line)
	text = "".join(lines)
	for location in locationValues():
		text = location.sub("[LOCATION]", text)
	return text


def decodeText(data):
	text = data.decode("UTF-8", errors="replace")
	if any(ord(x) < 32 and x not in "\r\n\t\x1b" for x in text):
		raise ValueError("Binary data omitted")
	return text


def readFile(path, virtualFile=False):
	# Open every folder of the path without following links, so no link or replaced folder is used.
	path = Path(path)
	flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK
	if osOpen in supports_dir_fd:
		directoryFd = osOpen(path.anchor or ".", flags | O_DIRECTORY)
		try:
			for part in path.parts[1:-1]:
				childFd = osOpen(part, flags | O_DIRECTORY, dir_fd=directoryFd)
				close(directoryFd)
				directoryFd = childFd
			fileFd = osOpen(path.name, flags, dir_fd=directoryFd)
		finally:
			close(directoryFd)
	else:  # Only for tests on a PC, receivers support dir_fd.
		if path.is_symlink() or any(x.is_symlink() for x in path.parents):
			raise ValueError("Symbolic link omitted")
		fileFd = osOpen(path, flags)
	with fdopen(fileFd, "rb") as fd:
		info = fstat(fd.fileno())
		if not S_ISREG(info.st_mode):
			raise ValueError("Not a regular file")
		if info.st_size > MAX_FILE_BYTES:
			raise ValueError("File too large")
		data = fd.read(MAX_FILE_BYTES + 1 if virtualFile else info.st_size)  # Files in /proc report size 0.
		if len(data) > MAX_FILE_BYTES:
			raise ValueError("File too large")
		if not virtualFile and len(data) != info.st_size:
			raise ValueError("File changed while reading")
	return decodeText(data)


def runCommand(arguments, timeout=5):
	# Read the output through a limited pipe. The receiver has little RAM and a small /tmp.
	process = Popen(arguments, stdout=PIPE, stderr=STDOUT, stdin=DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, start_new_session=True)
	output = bytearray()
	try:
		with DefaultSelector() as selector:
			selector.register(process.stdout, EVENT_READ)
			deadline = monotonic() + timeout
			while True:
				remaining = deadline - monotonic()
				if remaining <= 0:
					raise ValueError("Command timed out")
				if selector.select(remaining):
					data = read(process.stdout.fileno(), min(65536, MAX_FILE_BYTES + 1 - len(output)))
					if not data:
						break
					output.extend(data)
					if len(output) > MAX_FILE_BYTES:
						raise ValueError("Command output too large")
		if process.wait(timeout=max(0.1, deadline - monotonic())):
			raise ValueError("Command failed")
		return decodeText(output)
	finally:
		if process.poll() is None:
			process.kill()
		process.wait()
		process.stdout.close()


class Collector:
	def __init__(self, root="/", command=runCommand):
		self.root = Path(root).resolve()
		self.command = command
		self.files = []
		self.fileNames = set()
		self.totalBytes = 0
		self.notes = []
		self.startTime = monotonic()

	def addNote(self, path, reason):
		if len(self.notes) < MAX_NOTES:
			self.notes.append(f"{str(path)[:160]}: {reason}")

	def addText(self, name, text, settingsFile=False):
		if len(name) > 200 or any(not SAFE_NAME.fullmatch(x) or ".." in x or SECRET_NAME.search(x) for x in name.split("/")):
			self.addNote("diagnostic file", "unsafe or too long archive path; omitted")
		elif name not in self.fileNames:
			text = sanitizeText(text, settingsFile=settingsFile)
			size = len(text.encode("UTF-8"))
			if len(self.files) >= MAX_FILES - 1 or self.totalBytes + size > MAX_TOTAL_BYTES or size > MAX_FILE_BYTES:  # Keep the last slot for the manifest.
				self.addNote(name, "diagnostic limit reached; omitted, not truncated")
			else:
				self.files.append({"path": name, "content": text})
				self.fileNames.add(name)
				self.totalBytes += size

	def addFile(self, source, target=None, virtualFile=False, physicalPath=None):
		if monotonic() - self.startTime > MAX_SECONDS:
			self.addNote(source, "time limit reached; omitted")
		else:
			try:
				text = readFile(physicalPath or self.root / source.lstrip("/"), virtualFile=virtualFile)
				self.addText(target or source.lstrip("/"), text, settingsFile=source == "/etc/enigma2/settings")
			except (OSError, ValueError):  # Don't copy the error text, it can contain private data.
				self.addNote(source, "missing, unsafe, binary, changed, over 2 MiB or line too long; omitted")

	def collectReceiverInfo(self):
		system = uname()
		self.addText("system/box-info.txt", f"Collected UTC: {datetime.now(timezone.utc).isoformat()}\nKernel: {system.release}\nArchitecture: {system.machine}\n")
		for source in ("/usr/lib/enigma.info", "/etc/image-version", "/etc/os-release", "/proc/stb/info/model", "/proc/stb/info/boxtype", "/proc/bus/nim_sockets", "/proc/cpuinfo", "/proc/meminfo", "/proc/uptime", "/proc/modules", "/proc/cmdline"):
			self.addFile(source, join("system", f"{basename(source)}.txt"), virtualFile=source.startswith("/proc/"))
		try:
			packages = self.command(["opkg", "list-installed"])
			self.addText("system/packages.txt", packages)
			self.addText("system/plugin-packages.txt", "".join(f"{x}\n" for x in packages.splitlines() if x.startswith("enigma2-plugin-")))
		except (OSError, ValueError, SubprocessError):
			self.addNote("packages", "command unavailable, failed, timed out or over 2 MiB; omitted")
		plugins = []  # Also list plugins that were copied manually without a package.
		for category in ("Extensions", "SystemPlugins"):
			try:
				with scandir(self.root / "usr/lib/enigma2/python/Plugins" / category) as entries:
					for index, entry in enumerate(entries):
						if index >= MAX_SCAN:
							self.addNote(category, "plugin scan limit reached")
							break
						if entry.is_dir(follow_symlinks=False) and SAFE_NAME.fullmatch(entry.name) and entry.name != "__pycache__":
							plugins.append(join(category, entry.name))
			except OSError:
				self.addNote(category, "plugin folder unavailable")
		self.addText("system/plugin-directories.txt", "\n".join(sorted(plugins)) + "\n")

	def collectConfiguration(self):
		folder = self.root / "etc/enigma2"
		if folder.is_symlink():
			self.addNote("/etc/enigma2", "symbolic link folder omitted")
		else:
			fileCount = 0
			for directory, directories, files in walk(folder, followlinks=False):
				relative = Path(directory).relative_to(folder)
				directories[:] = sorted(x for x in directories if len(relative.parts) < 2 and SAFE_NAME.fullmatch(x) and not SECRET_NAME.search(x) and not (Path(directory) / x).is_symlink())[:64]
				for name in sorted(files):
					fileCount += 1
					if fileCount > MAX_SCAN:
						self.addNote("/etc/enigma2", "configuration scan limit reached")
						return
					path = join("/etc/enigma2", relative / name)
					if SAFE_NAME.fullmatch(name) and not SECRET_NAME.search(name) and any(fnmatchcase(name, x) for x in CONFIGURATION_NAMES):
						self.addFile(path)
					else:
						self.addNote(path, "not an approved configuration file; omitted")

	def collectSystemLogs(self):
		try:
			self.addText("system/dmesg.txt", self.command(["dmesg"]))
		except (OSError, ValueError, SubprocessError):
			self.addNote("dmesg", "command unavailable, failed, timed out or over 2 MiB; omitted")
		try:
			folder = (self.root / "var/log").resolve(strict=True)
			folder.relative_to(self.root)
			for name in ("messages", "messages.1"):
				self.addFile(join("/var/log", name), join("logs", f"{name}.txt"), physicalPath=folder / name)
		except (OSError, ValueError):
			self.addNote("/var/log", "system log folder unavailable")

	def collectExtraLogs(self, directories, excludedPaths):
		candidates = []
		seenPaths = set()
		for source in dict.fromkeys(("/tmp", "/home/root/logs", *directories)):
			try:
				folder = (self.root / source.lstrip("/")).resolve(strict=True)  # /tmp is often a link to /var/volatile/tmp.
				folder.relative_to(self.root)
				with scandir(folder) as entries:
					for index, entry in enumerate(entries):
						if index >= MAX_SCAN:
							self.addNote(source, "log scan limit reached")
							break
						path = join(source, entry.name)
						if SECRET_NAME.search(entry.name):
							self.addNote(path, "known softcam, key or password file excluded")
						elif path not in excludedPaths and entry.path not in seenPaths and LOG_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
							seenPaths.add(entry.path)
							candidates.append((entry.stat(follow_symlinks=False).st_mtime, path, entry.name, entry.path))
			except (OSError, ValueError):
				self.addNote(source, "log folder unavailable")
		for index, (modified, path, name, physicalPath) in enumerate(sorted(candidates, reverse=True)):
			if index < MAX_EXTRA_LOGS:
				self.addFile(path, join("logs", f"{index + 1:02d}-{name}.txt"), physicalPath=physicalPath)
			else:
				self.addNote(path, "only the 12 newest additional logs are included")

	def collect(self, directories, excludedPaths, options):
		sections = (
			("receiverInfo", self.collectReceiverInfo),
			("configuration", self.collectConfiguration),
			("systemLogs", self.collectSystemLogs),
			("extraLogs", lambda: self.collectExtraLogs(directories, excludedPaths))
		)
		for option, collectSection in sections:
			if options.get(option, False):
				collectSection()
			else:
				self.addNote(option, "disabled by user")
		manifest = [
			"OpenATV receiver diagnostics (current state, not necessarily the state at the time of the crash).",
			"Known passwords, private keys and URLs were removed on the receiver.",
			"This is best effort. Personal data may remain. Do not publish this archive.",
			"No commands from user files were run. No links, devices, databases or binary files are included.",
			"Known softcam, key and password files are excluded.",
			"Limits: 2 MiB per file, 8 MiB in total, 256 files, 12 additional logs. Nothing is truncated.",
			"Files with lines over 16 KiB are refused by the privacy filter.",
			"Configuration files are taken from an allowlist: settings, service and bouquet lists, XML files, black and white lists.",
			"Included files:",
			*(x["path"] for x in self.files),
			"Omissions and notes:",
			*self.notes
		]
		self.files.append({"path": "system/manifest.txt", "content": "\n".join(manifest) + "\n"})
		return self.files


def diagnosticsFor(selectedLogs, directories, options):
	"""Return the collector function for uploadReport(), or None when all options are off."""
	excludedPaths = [x["path"] for x in selectedLogs]  # Don't send the selected logs twice.
	return (lambda: Collector().collect(directories, excludedPaths, options)) if any(options.values()) else None
