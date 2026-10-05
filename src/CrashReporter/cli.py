#!/usr/bin/python3

"""Send a crash report without Enigma2, for example when the GUI does not start."""
from argparse import ArgumentParser, ArgumentTypeError
from json import dump
from re import M, fullmatch, search
from select import select
from sys import stdin, stdout
from time import localtime, strftime, time
from client import ReportError, reportClient  # Imported from this folder, without Enigma2.
from diagnostics import diagnosticsFor, sanitizeText

OPTIONS = ("receiverInfo", "configuration", "systemLogs", "extraLogs")  # Same keys as config.plugins.CrashReporter.
CONFIRM_TIMEOUT = 60
PRIVACY_NOTICE = "Known usernames, passwords, API keys, tokens and URLs are removed before upload. Key files and known softcam files are excluded. Other personal information may remain. Reports are private and accessible to you and the OpenATV support team."


def main():
	parser = ArgumentParser(prog="crashreporter", description="Sends the newest crash log to OpenATV when Enigma2 does not start correctly. The settings of the CrashReporter plugin are used.")
	parser.add_argument("--log", metavar="FILE", help="send this crash log instead of the newest one")
	parser.add_argument("--no-debug", action="store_true", help="don't send the matching debug log")
	parser.add_argument("--no-diagnostics", action="store_true", help="don't send receiver information, configuration and other logs")
	parser.add_argument("--dry-run", metavar="FILE", help="write the report to FILE instead of sending it")
	parser.add_argument("--yes", action="store_true", help="send without asking")
	parser.add_argument("--client", metavar="NAME", default="cli", type=clientName, help="name of the program that sends the report, for example orm (default: cli)")
	parser.add_argument("--status", action="store_true", help="show the state of the sent reports instead of sending one")
	arguments = parser.parse_args()
	stdout.reconfigure(line_buffering=True)  # Show the question also when the output is a pipe.
	try:
		result = showStatus() if arguments.status else sendReport(readSettings(), arguments)
	except (ReportError, ValueError) as err:  # ValueError comes from the privacy filter.
		print(f"Error: {err}")
		result = 1
	return result


def clientName(value):
	if not fullmatch(r"[!-~](?:[ -~]{0,30}[!-~])?", value):
		raise ArgumentTypeError("use 1-32 printable ASCII characters")
	return value


def readSettings():
	# Enigma2 only saves values that differ from the default, so a missing value means True.
	values = {}
	try:
		with open("/etc/enigma2/settings", encoding="UTF-8", errors="replace") as fd:
			for line in fd:
				key, separator, value = line.rstrip("\n").partition("=")
				values[key] = value
	except OSError:
		pass

	def isEnabled(name):
		return values.get(f"config.plugins.CrashReporter.{name}", "True") == "True"

	return {
		"includeDebug": isEnabled("includeDebug"),
		"options": {x: isEnabled(x) for x in OPTIONS},
		"directories": reportClient.logDirectories(values.get("config.crash.debug_path", "/home/root/logs/"))
	}


def readReceiverInfo():
	# Same values as BoxInfo and getE2Rev() in Enigma2.
	info = {}
	try:
		with open("/usr/lib/enigma.info", encoding="UTF-8", errors="replace") as fd:
			for line in fd:
				key, separator, value = line.strip().partition("=")
				info[key] = value.strip("'\"")
	except OSError:
		pass
	revision = "unknown"
	try:
		with open("/var/lib/opkg/status", encoding="UTF-8", errors="replace") as fd:  # Version 8.0.0+git35564+4099495+4099495853-r1 gives 35564+4099495.
			found = search(r"^Package: enigma2\n(?:\w.*\n)*?Version: \S*?\+git(\d+)\+[0-9a-f]+\+([0-9a-f]{7})", fd.read(), M)
		if found:
			revision = f"{found[1]}+{found[2]}"
	except OSError:
		pass
	modelName = " ".join(x for x in (info.get("displaybrand"), info.get("displaymodel")) if x)
	return info.get("model") or info.get("machinebuild") or "unknown", modelName, f"{info.get('imageversion', 'unknown')} {info.get('imagebuild', '')}", revision


def sendReport(settings, arguments):
	def askUser(question):  # Only "y" or "yes" allows the upload. No answer in time means no.
		print(f"{question} [y/N] ({CONFIRM_TIMEOUT} s) ", end="", flush=True)
		answer = None
		endTime = time() + CONFIRM_TIMEOUT
		while answer is None and time() < endTime:
			if select([stdin], [], [], 0.5)[0]:
				answer = stdin.readline().strip().lower() in ("y", "yes", "j", "ja")
		if answer is None:
			print("no answer")
		return bool(answer)

	crashLogs, debugLogs = reportClient.scanLogs(settings["directories"])
	if arguments.log:
		crashLogs = [x for x in crashLogs if arguments.log in (x["path"], x["name"])]
	result = 1
	if crashLogs:
		selectedLogs = reportClient.selectLogs(crashLogs[0], debugLogs, settings["includeDebug"] and not arguments.no_debug)
		options = {option: enabled and not arguments.no_diagnostics for option, enabled in settings["options"].items()}
		diagnostics = diagnosticsFor(selectedLogs, settings["directories"], options)
		print(f"Logs: {', '.join(x['path'] for x in selectedLogs)}")
		print(f"Diagnostics: {', '.join(option for option, enabled in options.items() if enabled) or 'none'}")
		print(PRIVACY_NOTICE)
		receiverInfo = readReceiverInfo()
		if arguments.dry_run:
			with open(arguments.dry_run, "w", encoding="UTF-8") as fd:
				dump(reportClient.prepareReport(receiverInfo, selectedLogs, diagnostics, sanitizeText, arguments.client), fd, ensure_ascii=False, indent=1)
			print(f"Nothing was sent, the report is in '{arguments.dry_run}'.")
			result = 0
		elif arguments.yes or (stdin.isatty() and askUser("Send these logs to OpenATV?")):
			print("Sending the report...")
			upload = reportClient.uploadReport(receiverInfo, selectedLogs, diagnostics, sanitizeText, arguments.client)
			print(f"Tracking number: {upload['tracking']}")
			print(f"Complete the report within 48 hours: {upload['complete_url']}#report={upload['tracking']}")
			if upload.get("save_warning"):
				print(upload["save_warning"])
			result = 0
		else:
			print("Nothing was sent." if stdin.isatty() else "Nobody can confirm the upload here, use --yes.")
	else:
		print("No crash log found.")
	return result


def showStatus():
	reports, notes = reportClient.refreshReports()
	if not reports:
		print("No reports were sent from this receiver.")
	for report in reports:
		if report["state"] == "submitted":
			state = f"ticket #{report.get('issue')}, {report.get('status')}"
		elif report["state"] == "pending":
			state = f"not submitted yet, complete it until {strftime('%d.%m.%Y %H:%M', localtime(report.get('expires_at', 0)))}"
		else:
			state = "no longer available"
		print(f"{strftime('%d.%m.%Y %H:%M', localtime(report.get('sent', 0)))}  {report['tracking']}  {state}")
		for note in notes.get(report["upload_id"], []):
			text = " ".join(note["text"].split())
			print(f"    {strftime('%d.%m.%Y %H:%M', localtime(note.get('created_on', 0)))} {note.get('from')}: {text[:200]}{'...' if len(text) > 200 else ''}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
