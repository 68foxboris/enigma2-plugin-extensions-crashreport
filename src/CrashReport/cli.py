"""crashreport: sends a crash report without Enigma2, e.g. when the GUI does not start."""
from argparse import ArgumentParser
import json
import re
from select import select
from sys import stdin, stdout
from time import time

from client import DEFAULT_SERVER, PRIVACY_NOTICE, ReportError, log_directories, prepare_report, scan_logs, select_logs, server_defaults, upload_report, validate_endpoint  # Next to this file, without the Enigma2 package.
from diagnostics import diagnostics_for, sanitize_text

OPTIONS = ("box_info", "configuration", "system_logs", "extra_logs")
CONFIRM_TIMEOUT = 60


def read_settings():  # config.plugins.crashreport of the plugin, Enigma2 saves only changed values.
	values = {}
	try:
		with open("/etc/enigma2/settings", encoding="utf-8", errors="replace") as source:
			for line in source:
				key, _, value = line.rstrip("\n").partition("=")
				values[key] = value
	except OSError:
		pass
	defaults = server_defaults()

	def flag(name, default=True):
		value = values.get("config.plugins.crashreport." + name)
		return default if value is None else value == "True"

	return {
		"server": values.get("config.plugins.crashreport.server", defaults.get("server", DEFAULT_SERVER)),
		"lan_test": flag("lan_test", bool(defaults.get("lan_test", False))),
		"include_debug": flag("include_debug"),
		"options": {name: flag(name) for name in OPTIONS},
		"directories": log_directories(values.get("config.crash.debug_path", "/home/root/logs/"))
	}


def receiver_info():  # BoxInfo and getE2Rev() of Enigma2.
	info = {}
	try:
		with open("/usr/lib/enigma.info", encoding="utf-8", errors="replace") as source:
			for line in source:
				key, _, value = line.strip().partition("=")
				info[key] = value.strip("'\"")
	except OSError:
		pass
	revision = "unknown"  # 8.0.0+git35564+40994950+4099495853-r1 of the package gives 35564+4099495.
	try:
		with open("/var/lib/opkg/status", encoding="utf-8", errors="replace") as source:
			match = re.search(r"^Package: enigma2\n(?:\w.*\n)*?Version: \S*?\+git(\d+)\+[0-9a-f]+\+([0-9a-f]{7})", source.read(), re.M)
		if match:
			revision = "%s+%s" % match.groups()
	except OSError:
		pass
	name = " ".join(part for part in (info.get("displaybrand"), info.get("displaymodel")) if part)
	return (info.get("model") or info.get("machinebuild") or "unknown", name,
		"%s %s" % (info.get("imageversion", "unknown"), info.get("imagebuild", "")), revision)


def ask(question, timeout):  # A line with y or yes allows, no answer in time does not.
	print(f"{question} [y/N] ({timeout} s) ", end="", flush=True)
	end = time() + timeout
	while time() < end:
		if select([stdin], [], [], 0.5)[0]:
			return stdin.readline().strip().lower() in ("y", "yes", "j", "ja")
	print("no answer")
	return False


def send(settings, options):
	crashes, debug = scan_logs(settings["directories"])
	if options.log:
		crashes = [item for item in crashes if options.log in (item["path"], item["name"])]
	if not crashes:
		print("No crash log found.")
		return 1
	selected = select_logs(crashes[0], debug, settings["include_debug"] and not options.no_debug)
	collect = {name: enabled and not options.no_diagnostics for name, enabled in settings["options"].items()}
	diagnostics = diagnostics_for(selected, settings["directories"], collect)
	print("Logs: %s" % ", ".join(item["path"] for item in selected))
	print("Diagnostics: %s" % (", ".join(name for name, enabled in collect.items() if enabled) or "none"))
	print(PRIVACY_NOTICE)
	if options.dry_run:
		with open(options.dry_run, "w", encoding="utf-8") as output:
			json.dump(prepare_report(*receiver_info(), selected, diagnostics, sanitize_text), output, ensure_ascii=False, indent=1)
		print(f"Nothing was sent, the report is in {options.dry_run}.")
		return 0
	if not options.yes and not (stdin.isatty() and ask("Send these logs to OpenATV?", CONFIRM_TIMEOUT)):
		print("Nothing was sent." if stdin.isatty() else "Nobody can confirm the upload here, use --yes.")
		return 1
	print("Sending the report...")
	result = upload_report(settings["server"], *receiver_info(), selected, allow_lan_http=settings["lan_test"], diagnostics=diagnostics, redact=sanitize_text)
	print(f"Tracking number: {result['tracking']}")
	print(f"Complete the report within 48 hours: {result['complete_url']}#report={result['tracking']}")
	if result.get("save_warning"):
		print(result["save_warning"])
	return 0


def main():
	parser = ArgumentParser(prog="crashreport", description="Sends the newest crash log to OpenATV, also when Enigma2 does not start. The settings of the CrashReport plugin apply.")
	parser.add_argument("--log", metavar="FILE", help="another crash log than the newest one")
	parser.add_argument("--no-debug", action="store_true", help="without the matching debug log")
	parser.add_argument("--no-diagnostics", action="store_true", help="without box information, configuration and other logs")
	parser.add_argument("--dry-run", metavar="FILE", help="writes the report to FILE instead of sending it")
	parser.add_argument("--yes", action="store_true", help="sends without asking")
	options = parser.parse_args()
	stdout.reconfigure(line_buffering=True)  # Also on a pipe, the question waits for an answer.
	settings = read_settings()
	try:
		validate_endpoint(settings["server"], settings["lan_test"])
		return send(settings, options)
	except ReportError as error:
		print(f"Error: {error}")
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
