from os import unlink
from time import strftime, localtime

from enigma import eTimer, getBsodCounter, getDesktop, getE2Rev
from twisted.internet.threads import deferToThread

from Components.ActionMap import ActionMap
from Components.ConfigList import ConfigListScreen
from Components.Label import Label
from Components.MenuList import MenuList
from Components.Pixmap import Pixmap
from Components.SystemInfo import BoxInfo, getBoxDisplayName
from Components.config import config, ConfigSubsection, ConfigText, ConfigYesNo, getConfigListEntry
from Plugins.Plugin import PluginDescriptor
from Screens.MessageBox import MessageBox
from Screens.Screen import Screen
from Tools import Notifications
from Tools.LoadPixmap import LoadPixmap

from . import _
from .client import DEFAULT_SERVER, PRIVACY_NOTICE, ReportError, delete_crash_log, log_directories as client_log_directories, log_identity, read_state, save_state, scan_logs, select_logs, server_defaults, upload_report, validate_endpoint
from .diagnostics import diagnostics_for, sanitize_text
from .qr import create_qr

defaults = server_defaults()

config.plugins.crashreport = ConfigSubsection()
config.plugins.crashreport.server = ConfigText(default=defaults.get("server", DEFAULT_SERVER), fixed_size=False)
config.plugins.crashreport.lan_test = ConfigYesNo(default=bool(defaults.get("lan_test", False)))
config.plugins.crashreport.remind = ConfigYesNo(default=True)
config.plugins.crashreport.include_debug = ConfigYesNo(default=True)
config.plugins.crashreport.box_info = ConfigYesNo(default=True)
config.plugins.crashreport.configuration = ConfigYesNo(default=True)
config.plugins.crashreport.system_logs = ConfigYesNo(default=True)
config.plugins.crashreport.extra_logs = ConfigYesNo(default=True)


def privacy_notice():
	return _(PRIVACY_NOTICE)


def error_message(error):
	if isinstance(error, ReportError):
		text = _(error.args[0])
		return text % error.args[1:] if len(error.args) > 1 else text
	return _(str(error))


def log_directories():
	return client_log_directories(config.crash.debug_path.value)


def receiver_info():
	return (str(BoxInfo.getItem("model") or BoxInfo.getItem("machinebuild")), " ".join(getBoxDisplayName()),
		"%s %s" % (BoxInfo.getItem("imageversion", "unknown"), BoxInfo.getItem("imagebuild", "")),
		getE2Rev())


class CrashReportSettings(ConfigListScreen, Screen):
	skin = """
	<screen name="CrashReportSettings" position="center,center" size="1050,500" resolution="1280,720" title="Crash Report Settings">
		<widget name="config" position="20,20" size="1010,265" itemHeight="40" font="Regular;23" />
		<widget name="help" position="20,300" size="1010,130" font="Regular;21" />
		<widget name="key_red" position="20,445" size="420,35" font="Regular;24" foregroundColor="#ff6060" />
		<widget name="key_green" position="530,445" size="420,35" font="Regular;24" foregroundColor="#60dd80" />
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.setTitle(_("Crash Report Settings"))
		ConfigListScreen.__init__(self, [
			getConfigListEntry(_("Include box, image and installed plugin information"), config.plugins.crashreport.box_info),
			getConfigListEntry(_("Include Enigma2 configuration files"), config.plugins.crashreport.configuration),
			getConfigListEntry(_("Include kernel and system logs"), config.plugins.crashreport.system_logs),
			getConfigListEntry(_("Include the matching debug log"), config.plugins.crashreport.include_debug),
			getConfigListEntry(_("Include additional logs from temporary and log folders"), config.plugins.crashreport.extra_logs),
			getConfigListEntry(_("Offer reporting after a crash"), config.plugins.crashreport.remind),
		], session=session)
		self["key_red"] = Label(_("Cancel"))
		self["key_green"] = Label(_("Save"))
		self["help"] = Label(privacy_notice())
		self["actions"] = ActionMap(["SetupActions", "ColorActions"], {"cancel": self.keyCancel, "red": self.keyCancel, "green": self.save, "save": self.save}, -2)

	def save(self):
		try:
			if config.plugins.crashreport.server.value.strip():
				validate_endpoint(config.plugins.crashreport.server.value, config.plugins.crashreport.lan_test.value)
		except Exception as error:
			self.session.open(MessageBox, error_message(error), type=MessageBox.TYPE_ERROR)
			return
		self.keySave()


class CrashReportScreen(Screen):
	skin = """
	<screen name="CrashReportScreen" position="center,center" size="1100,610" resolution="1280,720" title="OpenATV Crash Reports">
		<widget name="intro" position="25,20" size="1050,65" font="Regular;23" />
		<widget name="list" position="25,105" size="1050,245" itemHeight="42" font="Regular;23" />
		<widget name="status" position="25,375" size="1050,145" font="Regular;22" />
		<widget name="key_red" position="25,555" size="240,35" font="Regular;22" foregroundColor="#ff6060" />
		<widget name="key_green" position="290,555" size="240,35" font="Regular;22" foregroundColor="#60dd80" />
		<widget name="key_yellow" position="555,555" size="240,35" font="Regular;22" foregroundColor="#eeee70" />
		<widget name="key_blue" position="820,555" size="250,35" font="Regular;22" foregroundColor="#709fff" />
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.setTitle(_("OpenATV Crash Reports"))
		self.closed = False
		self.busy = False
		self.crashes, self.debug = [], []
		self["intro"] = Label(_("Select a crash log to send. Then scan the QR code or enter the tracking number on a phone or PC to complete your report."))
		self["list"] = MenuList([])
		self["status"] = Label(_("Looking for crash logs..."))
		for key, label in (("red", _("Close")), ("green", _("Send logs")), ("yellow", _("Settings")), ("blue", _("Delete crash log"))):
			self["key_" + key] = Label(label)
		self["actions"] = ActionMap(["OkCancelActions", "ColorActions"], {"cancel": self.close, "red": self.close,
			"ok": self.send, "green": self.send, "yellow": self.settings, "blue": self.delete_log}, -2)
		self.onClose.append(self.on_closed)
		self.onLayoutFinish.append(self.refresh)

	def on_closed(self):
		self.closed = True

	def refresh(self, *args):
		if not self.closed:
			self.busy = True
			deferToThread(scan_logs, log_directories()).addCallbacks(self.scanned, self.failed)

	def scanned(self, result):
		self.busy = False
		if self.closed:
			return
		self.crashes, self.debug = result
		self["list"].setList(["%s  ·  %d KiB  ·  %s" % (strftime("%d.%m.%Y %H:%M", localtime(item["mtime"])), item["size"] // 1024, item["name"]) for item in self.crashes])
		self["key_blue"].setText(_("Delete crash log") if self.crashes else "")
		self["status"].setText(_("No crash logs found.") if not self.crashes else _("GREEN sends the selected crash log. BLUE deletes only the selected local crash log after confirmation. Uploaded reports are not deleted."))

	def settings(self):
		if not self.busy:
			self.session.openWithCallback(self.refresh, CrashReportSettings)

	def send(self):
		if self.busy or not self.crashes:
			return
		if not config.plugins.crashreport.server.value.strip():
			self.settings()
			return
		selected = select_logs(self.crashes[self["list"].getSelectedIndex()], self.debug, config.plugins.crashreport.include_debug.value)
		options = {key: getattr(config.plugins.crashreport, key).value for key in ("box_info", "configuration", "system_logs", "extra_logs")}
		labels = {"box_info": _("Box, image and installed plugins"), "configuration": _("Enigma2 configuration files"),
			"system_logs": _("Kernel and system logs"), "extra_logs": _("Additional logs")}
		text = _("Send these logs to OpenATV?\n\n%s") % "\n".join(item["name"] for item in selected)
		if any(options.values()):
			text += "\n\n" + _("Diagnostic archive:") + "\n" + ", ".join(labels[key] for key, enabled in options.items() if enabled)
		text += "\n\n" + privacy_notice() + "\n\n" + _("Unsubmitted uploads expire after 48 hours. Your local files are kept.")
		self.session.openWithCallback(lambda answer: self.upload(answer, selected, options), MessageBox, text, type=MessageBox.TYPE_YESNO, default=False)

	def upload(self, answer, selected, options):
		if not answer or self.closed:
			return
		self.busy = True
		self["status"].setText(_("Preparing and sending the report in the background. Please wait..."))
		diagnostics = diagnostics_for(selected, log_directories(), options)
		deferToThread(upload_report, config.plugins.crashreport.server.value, *receiver_info(), selected,
			allow_lan_http=config.plugins.crashreport.lan_test.value, diagnostics=diagnostics, redact=sanitize_text).addCallbacks(self.sent, self.failed)

	def sent(self, result):
		self.busy = False
		if not self.closed:
			self.show_report(result)

	def failed(self, failure):
		self.busy = False
		if not self.closed:
			self["status"].setText(error_message(failure.value))
		return None

	def delete_log(self):
		if self.busy or self.closed or not self.crashes:
			return
		selected = dict(self.crashes[self["list"].getSelectedIndex()])
		text = _("Permanently delete this crash log from the receiver?\n\n%s\n\nThis cannot be undone. Other logs and uploaded reports are kept.") % selected["name"]
		self.session.openWithCallback(lambda answer: self.delete_confirmed(answer, selected), MessageBox, text, type=MessageBox.TYPE_YESNO, default=False)

	def delete_confirmed(self, answer, selected):
		if not answer or self.busy or self.closed:
			return
		self.busy = True
		self["status"].setText(_("Deleting the selected local crash log..."))
		deferToThread(delete_crash_log, selected, log_directories()).addCallbacks(self.refresh, self.failed)

	def show_report(self, result):
		text = _("Tracking: %s\n%s\nSign in and complete the report within 48 hours.") % (result["tracking"], result["complete_url"])
		self["status"].setText(text)
		self.session.open(CrashReportResult, result)


class CrashReportResult(Screen):
	skin = """
	<screen name="CrashReportResult" position="center,center" size="1100,540" resolution="1280,720" title="Complete Your Crash Report">
		<widget name="intro" position="30,25" size="1030,50" font="Regular;26" />
		<widget name="tracking" position="30,95" size="655,70" font="Regular;44" />
		<widget name="details" position="30,185" size="645,245" font="Regular;23" />
		<widget name="qr" position="730,95" size="320,320" alphatest="off" />
		<widget name="qr_status" position="715,425" size="350,65" font="Regular;19" halign="center" />
		<widget name="close" position="30,480" size="600,40" font="Regular;23" />
	</screen>"""

	def __init__(self, session, result):
		Screen.__init__(self, session)
		self.setTitle(_("Complete Your Crash Report"))
		self.closed = False
		self.qr_path = None
		tracking = result["tracking"]
		display = tracking[:4] + " " + tracking[4:] if tracking.isdigit() and len(tracking) == 8 else tracking
		self.url = result["complete_url"] + "#report=" + tracking
		self["intro"] = Label(_("Scan the QR code, or enter the tracking number on the website."))
		self["tracking"] = Label(display)
		self["details"] = Label(_("%s\n\nSign in or register and confirm your email. Then describe the problem and submit the report within 48 hours. The box model is supplied automatically.") % result["complete_url"])
		self["qr"] = Pixmap()
		self["qr_status"] = Label(_("Preparing QR code..."))
		self["close"] = Label(_("OK / EXIT: Close"))
		self["actions"] = ActionMap(["OkCancelActions"], {"ok": self.close, "cancel": self.close}, -2)
		self.onLayoutFinish.append(self.prepare)
		self.onClose.append(self.cleanup)

	def prepare(self):
		deferToThread(create_qr, self.url).addCallbacks(self.qr_ready, self.qr_failed)

	def qr_ready(self, path):
		if self.closed:
			self.remove_qr(path)
			return
		self.qr_path = path
		self["qr"].instance.setPixmap(LoadPixmap(path))
		self["qr_status"].setText(_("The tracking number is filled in automatically."))

	def qr_failed(self, failure):
		if not self.closed:
			self["qr_status"].setText(_("QR code unavailable. Please enter the number manually."))
		return None

	def remove_qr(self, path):
		try:
			unlink(path)
		except OSError:
			pass

	def cleanup(self):
		self.closed = True
		if self.qr_path:
			self.remove_qr(self.qr_path)


_startup = None


class CrashReportReminder:
	def __init__(self, session):
		self.session = session
		self.infobar = None
		self.scanning = False
		self.prompt_identity = None
		self.crash_pending = False
		self.bsod_count = getBsodCounter()
		self.timer = eTimer()
		self.timer.callback.append(self.check)
		# One startup scan for fatal crashes. Recovered Python errors are noticed
		# by the existing InfoBar BSOD timer, without another timer or disk polling.
		self.timer.startLongTimer(10)

	def attach_infobar(self, instance):
		if self.infobar is instance:
			return
		self.detach_infobar()
		self.infobar = instance
		# WHERE_INFOBARLOADED runs before InfoBarHandleBsod is initialized.
		instance.onLayoutFinish.append(self.bind_infobar)

	def bind_infobar(self):
		if self.infobar is None:
			return
		if self.bind_infobar in self.infobar.onLayoutFinish:
			self.infobar.onLayoutFinish.remove(self.bind_infobar)
		timer = getattr(self.infobar, "bsodTimer", None)
		if timer is not None and self.crash_changed not in timer.callback:
			timer.callback.append(self.crash_changed)

	def detach_infobar(self):
		if self.infobar is None:
			return
		if self.bind_infobar in self.infobar.onLayoutFinish:
			self.infobar.onLayoutFinish.remove(self.bind_infobar)
		timer = getattr(self.infobar, "bsodTimer", None)
		if timer is not None and self.crash_changed in timer.callback:
			timer.callback.remove(self.crash_changed)
		self.infobar = None

	def crash_changed(self):
		count = getBsodCounter()
		if count > self.bsod_count:
			self.crash_pending = True
		self.bsod_count = count  # Also follow a user-requested counter reset.
		if self.crash_pending and not self.scanning and self.prompt_identity is None and not getattr(self.infobar, "bsodIsShown", False):
			self.crash_pending = False
			self.check()

	def check(self):
		if self.scanning or self.prompt_identity is not None:
			return
		if config.plugins.crashreport.server.value and config.plugins.crashreport.remind.value:
			if getattr(self.infobar, "bsodIsShown", False):
				self.crash_pending = True
				return
			self.scanning = True
			deferToThread(scan_logs, log_directories()).addCallbacks(self.scanned, self.scan_failed)

	def scan_failed(self, failure):
		self.scanning = False
		print("[CrashReport] Unable to scan crash logs (%s)." % failure.type.__name__)
		return None

	def scanned(self, result):
		self.scanning = False
		if not config.plugins.crashreport.remind.value:
			return
		if getattr(self.infobar, "bsodIsShown", False):
			self.crash_pending = True
			return
		crashes, debug = result
		if not crashes:
			return
		state = read_state()
		identity = log_identity(crashes[0])
		if state.get("last_prompt") == identity:
			return
		if self.prompt_identity is not None:
			return
		self.prompt_identity = identity
		text = _("Enigma2 has created a new crash log. Would you like to report the problem now? No data will be sent without your confirmation.")
		# A modal notification also works while the faulty plugin/menu is open.
		# No short timeout: do not silently consume a report offer after 30 seconds.
		try:
			Notifications.AddModalNotification(text, timeout=-1, default=False, typeIcon=MessageBox.TYPE_YESNO, windowTitle=title(), callback=self.answer)
		except Exception:
			self.prompt_identity = None
			print("[CrashReport] Unable to display the crash report offer.")

	def answer(self, answer):
		identity = self.prompt_identity
		self.prompt_identity = None
		if identity is not None:
			# Mark as handled only after the user has actually answered, not when
			# it is queued. A restart must not lose an unseen notification.
			state = read_state()
			state["last_prompt"] = identity
			try:
				save_state(state)
			except OSError:
				print("[CrashReport] Unable to store the crash reminder state.")
		if answer:
			main(self.session)


def title():
	return _("Crash Reports")


def main(session, **kwargs):
	session.open(CrashReportScreen)


def menu(menuid, **kwargs):
	return [(title(), main, "openatv_crashreports", 30)] if menuid == "support" else []


def sessionstart(reason, session=None, **kwargs):
	global _startup
	if reason == 0 and session is not None:
		_startup = CrashReportReminder(session)


def infobarloaded(reason, session=None, instance=None, typeInfoBar=None, **kwargs):
	if _startup is not None and typeInfoBar == "InfoBar":
		if reason == 1 and instance is not None:
			_startup.attach_infobar(instance)
		elif reason == 0 and _startup.infobar is instance:
			_startup.detach_infobar()


def Plugins(**kwargs):
	icon = "plugin-fhd.png" if getDesktop(0).size().width() >= 1920 else "plugin.png"
	description = _("Send crash logs and track a support report.")
	return [PluginDescriptor(name=title(), description=description, where=PluginDescriptor.WHERE_PLUGINMENU, icon=icon, fnc=main, needsRestart=False),
		PluginDescriptor(name=title(), description=description, where=PluginDescriptor.WHERE_MENU, fnc=menu, needsRestart=False),
		PluginDescriptor(where=PluginDescriptor.WHERE_SESSIONSTART, fnc=sessionstart),
		PluginDescriptor(where=PluginDescriptor.WHERE_INFOBARLOADED, fnc=infobarloaded)]
