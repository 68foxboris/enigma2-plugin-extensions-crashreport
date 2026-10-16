"""Collect receiver diagnostics and remove private data. No Enigma2 imports, cli.py uses this module too."""
from collections import deque
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from os import O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, close, fdopen, fstat, getpid, lstat, open as osOpen, read, scandir, stat, statvfs, supports_dir_fd, uname, walk
from os.path import basename, join
from pathlib import Path
from re import I, compile, escape, search, sub
from selectors import DefaultSelector, EVENT_READ
from stat import S_ISDIR, S_ISREG
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
MAX_STORAGE_SECONDS = 10
MAX_LARGEST_FOLDERS = 25
MAX_CRASH_LOGS = 50
MAX_PROCESSES = 15
BACKUP_NAME = compile(r"(?:_org|\.del|\.bak|\.old|~)$")  # Copies of bouquets and lists, they only fill the archive.
CRASH_NAME = compile(r"(?:-enigma\d?-crash|^enigma2_crash(?:_[\w-]+)?)\.log$")  # Same as CRASH_PATTERN in client.py.
PSEUDO_FILE_SYSTEMS = {"autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nfsd", "nsfs", "proc", "pstore", "rootfs", "rpc_pipefs", "securityfs", "selinuxfs", "sysfs", "tracefs"}
NETWORK_FILE_SYSTEMS = ("9p", "ceph", "cifs", "davfs", "fuse.", "glusterfs", "nfs", "smb")  # The share can contain a server and user name, and statvfs() can hang.
STORAGE_PATHS = (  # Settings with a folder that can fill the flash, and the default value.
	("config.usage.default_path", "/media/hdd/movie/"),
	("config.usage.timer_path", ""),
	("config.usage.instantrec_path", ""),
	("config.timeshift.path", "/media/hdd/timeshift/"),
	("config.misc.epgcachepath", "/etc/enigma2/"),
	("config.crash.debug_path", "/home/root/logs/")
)
WATCHED_FOLDERS = ("/etc/enigma2", "/home/root/logs", "/picon", "/usr/lib/enigma2/python/Plugins", "/usr/share/enigma2", "/usr/share/enigma2/picon", "/var/lib/opkg", "/var/log")
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


def formatSize(size):
	units = ("B", "KiB", "MiB", "GiB", "TiB")
	index = 0
	while size >= 1024 and index < len(units) - 1:
		size /= 1024
		index += 1
	return f"{size:.0f} {units[index]}" if index == 0 else f"{size:.1f} {units[index]}"


def formatPercent(used, total):
	return f"{(used * 100 + total - 1) // total}%" if total else "-"  # Rounded up like df.


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
		self.droppedNotes = {}
		self.startTime = monotonic()

	def addNote(self, path, reason):
		if len(self.notes) < MAX_NOTES:
			self.notes.append(f"{str(path)[:160]}: {reason}")
		else:  # Count the rest, so the manifest still shows what was omitted.
			self.droppedNotes[reason] = self.droppedNotes.get(reason, 0) + 1

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
		for source in ("/usr/lib/enigma.info", "/etc/image-version", "/etc/os-release", "/proc/stb/info/model", "/proc/stb/info/boxtype", "/proc/bus/nim_sockets", "/proc/cpuinfo", "/proc/meminfo", "/proc/swaps", "/proc/loadavg", "/proc/uptime", "/proc/modules", "/proc/cmdline"):
			self.addFile(source, join("system", f"{basename(source)}.txt"), virtualFile=source.startswith("/proc/"))
		self.collectProcesses()
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

	def collectProcesses(self):
		# Only the short process name from the kernel, the command line can contain passwords.
		processes = []
		try:
			with scandir(self.root / "proc") as entries:
				for entry in entries:
					if entry.name.isdigit():
						try:
							values = dict(x.split(":", 1) for x in readFile(join(entry.path, "status"), virtualFile=True).splitlines() if ":" in x)
							if "VmRSS" in values:  # Kernel threads have no memory of their own.
								processes.append((int(values["VmRSS"].split()[0]), int(values.get("VmSwap", "0 kB").split()[0]), entry.name, values.get("Name", "").strip(), values.get("State", "").strip()[:1], values.get("Threads", "").strip()))
						except (OSError, ValueError):  # The process has ended.
							pass
		except OSError:
			self.addNote("/proc", "process list unavailable")
		if processes:
			lines = [f"Processes with memory: {len(processes)}, largest {MAX_PROCESSES} by resident memory (RSS).", "", f"{'PID':>6}  {'RSS':>10}  {'Swap':>10}  State  Threads  Name"]
			lines.extend(f"{x[2]:>6}  {formatSize(x[0] * 1024):>10}  {formatSize(x[1] * 1024):>10}  {x[4]:<5}  {x[5]:>7}  {x[3]}" for x in sorted(processes, reverse=True)[:MAX_PROCESSES])
			self.addText("system/processes.txt", "\n".join(lines) + "\n")

	def collectConfiguration(self):
		folder = self.root / "etc/enigma2"
		if folder.is_symlink():
			self.addNote("/etc/enigma2", "symbolic link folder omitted")
		else:
			fileCount = 0
			backupCount = 0
			for directory, directories, files in walk(folder, followlinks=False):
				relative = Path(directory).relative_to(folder)
				directories[:] = sorted(x for x in directories if len(relative.parts) < 2 and SAFE_NAME.fullmatch(x) and not SECRET_NAME.search(x) and not (Path(directory) / x).is_symlink())[:64]
				for name in sorted(files):
					fileCount += 1
					if fileCount > MAX_SCAN:
						self.addNote("/etc/enigma2", "configuration scan limit reached")
						break
					path = join("/etc/enigma2", relative / name)
					if BACKUP_NAME.search(name):
						backupCount += 1
					elif SAFE_NAME.fullmatch(name) and not SECRET_NAME.search(name) and any(fnmatchcase(name, x) for x in CONFIGURATION_NAMES):
						self.addFile(path)
					else:
						self.addNote(path, "not an approved configuration file; omitted")
				if fileCount > MAX_SCAN:
					break
			if backupCount:
				self.addNote("/etc/enigma2", f"{backupCount} backup copies (_org, .del, .bak, .old, ~) omitted")

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

	def readMounts(self):
		mounts = []
		try:  # /proc/mounts and /proc/self are links, readFile() doesn't follow them.
			for line in readFile(self.root / "proc" / str(getpid()) / "mounts", virtualFile=True).splitlines():
				fields = line.split()
				if len(fields) > 2 and fields[2] not in PSEUDO_FILE_SYSTEMS:
					device, mountPoint = (sub(r"\\([0-7]{3})", lambda found: chr(int(found[1], 8)), x) for x in fields[:2])  # A space is written as \040.
					mounts.append((device, mountPoint, fields[2]))
		except (OSError, ValueError):
			self.addNote("/proc/mounts", "unavailable")
		return mounts

	def collectStorage(self, directories):
		mounts = self.readMounts()
		mountNames = {}
		lines = ["File systems (like df -h and df -i):", "", f"{'Filesystem':<24} {'Type':<10} {'Size':>10} {'Used':>10} {'Avail':>10} {'Use%':>5} {'Inodes':>9} {'IUsed':>9} {'IFree':>9} {'IUse%':>5}  Mounted on"]
		for device, mountPoint, fileSystem in mounts:
			if fileSystem.startswith(NETWORK_FILE_SYSTEMS):
				lines.append(f"{'[network share]':<24} {fileSystem:<10} not checked  {mountPoint}")
			else:
				try:
					physicalPath = self.root / mountPoint.lstrip("/")
					info = statvfs(physicalPath)
					used = (info.f_blocks - info.f_bfree) * info.f_frsize
					available = info.f_bavail * info.f_frsize
					usedInodes = info.f_files - info.f_ffree
					inodes = (info.f_files, usedInodes, info.f_ffree) if info.f_files else ("-", "-", "-")  # Some file systems like vfat have no inodes.
					lines.append(f"{device:<24} {fileSystem:<10} {formatSize(info.f_blocks * info.f_frsize):>10} {formatSize(used):>10} {formatSize(available):>10} {formatPercent(used, used + available):>5} {inodes[0]:>9} {inodes[1]:>9} {inodes[2]:>9} {formatPercent(usedInodes, info.f_files):>5}  {mountPoint}")
					mountNames.setdefault(stat(physicalPath).st_dev, f"{mountPoint} ({device})")
				except OSError:
					lines.append(f"{device:<24} {fileSystem:<10} unavailable  {mountPoint}")
		try:
			rootDevice = lstat(self.root).st_dev
		except OSError:
			rootDevice = None
		# Configured folders for recordings, timeshift, EPG and logs. On the flash they can fill it up.
		settings = {}
		try:
			settings = dict(x.split("=", 1) for x in readFile(self.root / "etc/enigma2/settings").splitlines() if "=" in x)
		except (OSError, ValueError):
			self.addNote("/etc/enigma2/settings", "unavailable for the storage paths")
		lines.extend(("", "Configured folders:", ""))
		for key, default in STORAGE_PATHS:
			path = settings.get(key, default)
			if path.startswith("/"):
				try:
					device = stat(self.root / path.lstrip("/")).st_dev
					location = "on the root file system (flash)" if device == rootDevice else f"on {mountNames.get(device, 'another file system')}"
					if device == rootDevice and key not in ("config.misc.epgcachepath", "config.crash.debug_path"):
						location = f"WARNING: {location}"
				except OSError:
					location = "missing"
				lines.append(f"{key} = {path}  {location}")
		epgName = settings.get("config.misc.epgcachefilename", "epg").replace(".dat", "")
		epgPath = join(settings.get("config.misc.epgcachepath", "/etc/enigma2/"), f"{epgName}.dat")
		try:
			lines.append(f"EPG cache file {epgPath}: {formatSize(stat(self.root / epgPath.lstrip('/')).st_size)}")
		except OSError:
			lines.append(f"EPG cache file {epgPath}: missing")
		# Sizes of the folders on the root file system. Mounted devices have another st_dev and are not included.
		usage = {}  # Folder: [bytes on disk, entries inside].
		queue = deque(((self.root, "/", ()),))  # Breadth first, so a stopped scan still covers all top folders.
		deadline = monotonic() + MAX_STORAGE_SECONDS
		complete = rootDevice is not None
		while queue and complete:
			physicalPath, path, keys = queue.popleft()
			try:
				with scandir(physicalPath) as entries:
					for entry in entries:
						try:
							info = entry.stat(follow_symlinks=False)
						except OSError:
							continue
						if info.st_dev == rootDevice:
							entryPath = join(path, entry.name)
							entryKeys = (*keys, entryPath) if entryPath.count("/") <= 2 or entryPath in WATCHED_FOLDERS else keys
							for key in entryKeys:
								usage.setdefault(key, [0, 0])[0] += info.st_blocks * 512
							for key in keys:
								usage[key][1] += 1
							if S_ISDIR(info.st_mode):
								queue.append((entry.path, entryPath, entryKeys))
			except OSError:
				pass
			complete = monotonic() < deadline
		mountPoints = {x[1] for x in mounts}
		hiddenFolders = [x for x in sorted(usage) if x.startswith("/media/") and x.count("/") == 2 and x not in mountPoints and usage[x][1]]
		lines.extend(("", "Folders in /media with data on the root file system (no device mounted):", ""))
		lines.extend([f"WARNING: {x} contains {usage[x][1]} files and folders ({formatSize(usage[x][0])}). Recordings or other files were written to the flash." for x in hiddenFolders] or ["None"])
		lines.extend(("", f"Largest folders on the root file system, {MAX_LARGEST_FOLDERS} of the first two levels (size on disk, entries):", ""))
		lines.extend(f"{formatSize(usage[x][0]):>10} {usage[x][1]:>8}  {x}" for x in sorted((x for x in usage if x.count("/") <= 2), key=lambda x: usage[x][0], reverse=True)[:MAX_LARGEST_FOLDERS])
		lines.extend(("", "Other folders that often fill the flash:", ""))
		lines.extend([f"{formatSize(usage[x][0]):>10} {usage[x][1]:>8}  {x}" for x in WATCHED_FOLDERS if x in usage] or ["None"])
		if not complete:
			lines.extend(("", f"The folder scan stopped after {MAX_STORAGE_SECONDS} seconds, the sizes are incomplete."))
		self.addText("system/storage.txt", "\n".join(lines) + "\n")
		# The number and the times of the crashes show whether the receiver crashes often.
		crashLogs = {}
		for source in dict.fromkeys(("/home/root/logs", "/tmp", *directories)):
			try:
				with scandir(self.root / source.lstrip("/")) as entries:
					for index, entry in enumerate(entries):
						if index >= MAX_SCAN:
							break
						if CRASH_NAME.search(entry.name) and entry.is_file(follow_symlinks=False):
							info = entry.stat(follow_symlinks=False)
							crashLogs[(info.st_dev, info.st_ino)] = (info.st_mtime, info.st_size, join(source, entry.name))
			except OSError:  # Not every log folder exists on every receiver.
				pass
		lines = [f"Crash logs in the log folders: {len(crashLogs)}, newest {MAX_CRASH_LOGS} shown (modification time UTC, size, path).", ""]
		lines.extend(f"{datetime.fromtimestamp(x[0], timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}  {formatSize(x[1]):>10}  {x[2]}" for x in sorted(crashLogs.values(), reverse=True)[:MAX_CRASH_LOGS])
		self.addText("system/crash-history.txt", "\n".join(lines) + "\n")

	def collect(self, directories, excludedPaths, options):
		# The logs come before the storage scan and the configuration, so many bouquets can't push them out of the limits.
		sections = (
			("receiverInfo", self.collectReceiverInfo),
			("systemLogs", self.collectSystemLogs),
			("extraLogs", lambda: self.collectExtraLogs(directories, excludedPaths)),
			("receiverInfo", lambda: self.collectStorage(directories)),
			("configuration", self.collectConfiguration)
		)
		for option in dict.fromkeys(x[0] for x in sections):
			if not options.get(option, False):
				self.addNote(option, "disabled by user")
		for option, collectSection in sections:
			if options.get(option, False):
				collectSection()
		manifest = [
			"OpenATV receiver diagnostics (current state, not necessarily the state at the time of the crash).",
			"Known passwords, private keys and URLs were removed on the receiver.",
			"This is best effort. Personal data may remain. Do not publish this archive.",
			"No commands from user files were run. No links, devices, databases or binary files are included.",
			"Known softcam, key and password files are excluded.",
			"Limits: 2 MiB per file, 8 MiB in total, 256 files, 12 additional logs. Nothing is truncated.",
			"Files with lines over 16 KiB are refused by the privacy filter.",
			"Configuration files are taken from an allowlist: settings, service and bouquet lists, XML files, black and white lists. Backup copies are skipped.",
			"Storage, process and crash summaries only contain folder and process names, sizes, counts and times.",
			"Included files:",
			*(x["path"] for x in self.files),
			"Omissions and notes:",
			*self.notes,
			*(f"{count} more notes: {reason}" for reason, count in self.droppedNotes.items())
		]
		self.files.append({"path": "system/manifest.txt", "content": "\n".join(manifest) + "\n"})
		return self.files


def diagnosticsFor(selectedLogs, directories, options):
	"""Return the collector function for uploadReport(), or None when all options are off."""
	excludedPaths = [x["path"] for x in selectedLogs]  # Don't send the selected logs twice.
	return (lambda: Collector().collect(directories, excludedPaths, options)) if any(options.values()) else None
