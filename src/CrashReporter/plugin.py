from os import close, unlink
from PIL import Image
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_M
from tempfile import mkstemp
from time import localtime, strftime
from twisted.internet.threads import deferToThread

from enigma import eTimer, getBsodCounter, getDesktop, getE2Rev

from Components.ActionMap import HelpableActionMap
from Components.config import ConfigSubsection, ConfigYesNo, config
from Components.Label import Label
from Components.MenuList import MenuList
from Components.Pixmap import Pixmap
from Components.ScrollLabel import ScrollLabel
from Components.Sources.StaticText import StaticText
from Components.SystemInfo import BoxInfo, getBoxDisplayName
from Plugins.Plugin import PluginDescriptor
from Screens.ChoiceBox import ChoiceBox
from Screens.MessageBox import MessageBox
from Screens.Screen import Screen
from Screens.Setup import Setup
from Screens.VirtualKeyBoard import VirtualKeyBoard
from Tools.Notifications import AddModalNotification
from Tools.LoadPixmap import LoadPixmap

from . import PluginLanguageDomain, _, __version__
from .client import ReportError, reportClient
from .diagnostics import diagnosticsFor, sanitizeText

config.plugins.CrashReporter = ConfigSubsection()
config.plugins.CrashReporter.reminder = ConfigYesNo(default=True)
config.plugins.CrashReporter.answerReminder = ConfigYesNo(default=True)
config.plugins.CrashReporter.receiverInfo = ConfigYesNo(default=True)
config.plugins.CrashReporter.includeDebug = ConfigYesNo(default=True)
config.plugins.CrashReporter.configuration = ConfigYesNo(default=True)
config.plugins.CrashReporter.systemLogs = ConfigYesNo(default=True)
config.plugins.CrashReporter.extraLogs = ConfigYesNo(default=True)

crashReminder = None


class ReportHelper:
	QR_SIZE = 320

	def errorText(self, error):
		if isinstance(error, ReportError):
			text = _(error.args[0]) % error.args[1:] if len(error.args) > 1 else _(error.args[0])
		else:
			text = _(str(error))
		return text

	def createQrCode(self, url, size):  # Create the QR code locally, so no QR service gets the tracking number.
		code = QRCode(error_correction=ERROR_CORRECT_M, border=4)
		code.add_data(url)
		code.make(fit=True)
		code.box_size = max(1, min(12, size // (code.modules_count + 8)))
		image = code.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
		if image.width > size:
			raise ValueError("The report URL is too long for the QR code.")
		canvas = Image.new("RGB", (size, size), "white")
		canvas.paste(image, ((size - image.width) // 2, (size - image.height) // 2))
		fd, path = mkstemp(prefix="openatv-report-", suffix=".png")
		close(fd)
		try:
			canvas.save(path, "PNG")
		except Exception:
			self.removeQrFile(path)
			raise
		return path

	def removeQrFile(self, path):
		try:
			unlink(path)
		except OSError:
			pass

	def reportUrl(self, tracking):
		return f"{reportClient.SERVER}/crash-reports#report={tracking}"

	def formatTracking(self, tracking):
		return f"{tracking[:4]} {tracking[4:]}" if tracking.isdigit() and len(tracking) == 8 else tracking

	def formatTime(self, timestamp):
		return strftime("%d.%m.%Y %H:%M", localtime(timestamp or 0))

	def statusName(self, status):
		return {"New": _("New"), "In Progress": _("In Progress"), "Resolved": _("Resolved"), "Feedback": _("Feedback"), "Closed": _("Closed"), "Rejected": _("Rejected")}.get(status, status)

	def lastChange(self, report):
		updated = report.get("updated_on") if report.get("state") == "submitted" else None
		return updated if isinstance(updated, int) else report.get("sent", 0)

	def reportStateText(self, report):
		if report.get("state") == "submitted":
			text = f"#{report.get('issue')}  {self.statusName(report.get('status', ''))}"
		elif report.get("state") == "pending":
			text = _("Not submitted yet")
		else:
			text = _("No longer available")
		return text

	def finishText(self, status):  # Texts for the ticket are always English, for the developers.
		return "Marked as resolved on the receiver." if status == "resolved" else "Closed on the receiver."

	def finishChoices(self, report):
		"""Returns the choices with the status for the server, and the index of No."""
		choices = [(_("Close ticket"), "closed"), (_("No"), None)]
		if report.get("status") != "Resolved":
			choices.insert(0, (_("Problem solved"), "resolved"))
		return choices, len(choices) - 1


reportHelper = ReportHelper()


class QrCodeScreen(Screen):
	def __init__(self, session, qrStatus=""):
		Screen.__init__(self, session, enableHelp=True)
		self["qr"] = Pixmap()
		self["qrStatus"] = Label(qrStatus)
		self.uiClosed = False
		self.qrPath = None
		self.onClose.append(self.qrScreenClosed)

	def showQrCode(self, url, readyText):
		def createQrCallback(path):
			if self.uiClosed:
				reportHelper.removeQrFile(path)
			else:
				self.removeQrCode()
				self.qrPath = path
				self["qr"].instance.setPixmap(LoadPixmap(path))
				self["qr"].show()
				self["qrStatus"].setText(readyText)

		def createQrFailed(failure):
			if not self.uiClosed:
				self["qrStatus"].setText(_("QR code unavailable. Please enter the number manually."))

		if self["qr"].instance:
			widgetSize = self["qr"].instance.size()
			deferToThread(reportHelper.createQrCode, url, min(widgetSize.width(), widgetSize.height()) or reportHelper.QR_SIZE).addCallbacks(createQrCallback, createQrFailed)

	def removeQrCode(self):
		if self.qrPath:
			reportHelper.removeQrFile(self.qrPath)
			self.qrPath = None

	def qrScreenClosed(self):
		self.uiClosed = True
		self.removeQrCode()


class CrashReporter(Screen):
	skin = """
	<screen name="CrashReporter" title="OpenATV Crash Reporter" position="center,center" size="1000,460" resolution="1280,720">
		<widget name="logs" position="10,10" size="e-20,e-180" enableWrapAround="1" font="Regular;25" itemHeight="35" scrollbarMode="showOnDemand" verticalAlignment="center" />
		<widget name="description" position="10,e-160" size="e-20,100" font="Regular;20" padding="10" verticalAlignment="center" widgetBorderColor="#00999999" widgetBorderWidth="1" />
		<widget source="key_red" render="Label" position="10,e-50" size="180,40" backgroundColor="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_green" render="Label" position="200,e-50" size="180,40" backgroundColor="key_green" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_yellow" render="Label" position="390,e-50" size="180,40" backgroundColor="key_yellow" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_blue" render="Label" position="580,e-50" size="180,40" backgroundColor="key_blue" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_menu" render="Label" position="e-200,e-50" size="90,40" backgroundColor="key_back" font="Regular;20" conditional="key_menu" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-100,e-50" size="90,40" backgroundColor="key_back" font="Regular;20" conditional="key_help" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session, enableHelp=True)
		self.setTitle(_("OpenATV Crash Reporter"))
		self["logs"] = MenuList([])
		self["description"] = Label(_("Looking for crash logs..."))
		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText(_("My Reports"))
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText()
		self["key_menu"] = StaticText(_("MENU"))
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "MenuActions", "ColorActions", "NavigationActions"], {
			"ok": (self.keySend, _("Send the selected crash log")),
			"cancel": (self.close, _("Close the screen")),
			"close": (self.keyCloseRecursive, _("Close the screen and exit all menus")),
			"menu": (self.keySettings, _("Open the Crash Reporter settings")),
			"red": (self.close, _("Close the screen")),
			"green": (self.keyReports, _("Show the sent reports and the answers")),
			"yellow": (self.keySend, _("Send the selected crash log")),
			"blue": (self.keyDeleteLog, _("Delete the selected local crash log")),
			"top": (self["logs"].goTop, _("Move to first line / screen")),
			"pageUp": (self["logs"].goPageUp, _("Move up a screen")),
			"up": (self["logs"].goLineUp, _("Move up a line")),
			"down": (self["logs"].goLineDown, _("Move down a line")),
			"pageDown": (self["logs"].goPageDown, _("Move down a screen")),
			"bottom": (self["logs"].goBottom, _("Move to last line / screen"))
		}, prio=0, description=_("Crash Reporter Actions"))
		self.uiClosed = False  # Background jobs can finish after the screen was closed.
		self.deferRunning = False
		self.crashLogs = []
		self.debugLogs = []
		self.onLayoutFinish.append(self.layoutFinished)
		self.onClose.append(self.screenClosed)

	def layoutFinished(self):
		self["logs"].enableAutoNavigation(False)
		self.scanForLogs()

	def screenClosed(self):
		self.uiClosed = True

	def scanForLogs(self, *args):  # Also the callback of Setup and deleteCrashLog, they pass a result.
		def scanForLogsCallback(result):
			self.deferRunning = False
			if not self.uiClosed:
				self.crashLogs, self.debugLogs = result
				self["logs"].setList([f"{strftime('%d.%m.%Y %H:%M', localtime(x['mtime']))}  ·  {x['size'] // 1024} KiB  ·  {x['name']}" for x in self.crashLogs])
				for action in ("ok", "yellow", "blue"):
					self["actions"].setEnabledAction(action, bool(self.crashLogs))
				if self.crashLogs:
					self["key_yellow"].setText(_("Send Log"))
					self["key_blue"].setText(_("Delete Log"))
					self["description"].setText(_("Select a crash log to be sent for analysis, scan the QR code or enter the tracking number on a phone or PC to complete and confirm your report."))
				else:
					self["key_yellow"].setText("")
					self["key_blue"].setText("")
					self["description"].setText(_("No crash logs found."))

		if not self.uiClosed:
			self.deferRunning = True
			deferToThread(reportClient.scanLogs, reportClient.logDirectories(config.crash.debug_path.value)).addCallbacks(scanForLogsCallback, self.failedCallback)

	def failedCallback(self, failure):
		self.deferRunning = False
		if not self.uiClosed:
			self["description"].setText(reportHelper.errorText(failure.value))

	def keySend(self):
		def keySendCallback(answer):
			if answer and not self.uiClosed:
				self.deferRunning = True
				self["description"].setText(_("Preparing and sending the report in the background. Please wait..."))
				receiverInfo = (
					str(BoxInfo.getItem("model") or BoxInfo.getItem("machinebuild")),  # Model.
					" ".join(getBoxDisplayName()),  # Model name.
					f"{BoxInfo.getItem('imageversion', 'unknown')} {BoxInfo.getItem('imagebuild', '')}",  # Image version.
					getE2Rev()  # Enigma2 version.
				)
				diagnostics = diagnosticsFor(selectedLogs, reportClient.logDirectories(config.crash.debug_path.value), reportOptions)
				deferToThread(reportClient.uploadReport, receiverInfo, selectedLogs, diagnostics, sanitizeText, "plugin").addCallbacks(uploadCallback, self.failedCallback)

		def uploadCallback(result):
			self.deferRunning = False
			if not self.uiClosed:
				text = _("Tracking: %s\n%s\nSign in and complete the report within 48 hours.") % (result["tracking"], result["complete_url"])
				if result.get("save_warning"):
					text = f"{text}\n{_(result['save_warning'])}"
				self["description"].setText(text)
				self.session.open(CrashReporterResult, result)

		if not self.deferRunning and self.crashLogs:
			selectedLogs = reportClient.selectLogs(self.crashLogs[self["logs"].getSelectedIndex()], self.debugLogs, config.plugins.CrashReporter.includeDebug.value)
			reportOptions = {x: getattr(config.plugins.CrashReporter, x).value for x in ("receiverInfo", "configuration", "systemLogs", "extraLogs")}
			optionNames = {
				"receiverInfo": _("receiver, image and installed plugins"),
				"configuration": _("OpenATV configuration files"),
				"systemLogs": _("kernel and system logs"),
				"extraLogs": _("additional logs")
			}
			text = [_("Send these logs to OpenATV?"), "\n".join(f"    {x['name']}" for x in selectedLogs)]
			if any(reportOptions.values()):
				reportContents = ", ".join(optionNames[option] for option, enabled in reportOptions.items() if enabled)
				text.append(f"{_('Report will contain')} {reportContents}.")
			text.append(_("Known usernames, passwords, API keys, tokens and URLs are removed before upload. Key files and known softcam files are excluded. Other personal information may remain. Reports are private and accessible to you and the OpenATV support team."))
			text.append(_("Unconfirmed uploads will expire and be deleted after 48 hours. Your local files are not affected."))
			self.session.openWithCallback(keySendCallback, MessageBox, "\n\n".join(text), type=MessageBox.TYPE_YESNO, default=False, windowTitle=self.getTitle())

	def keyCloseRecursive(self):
		self.close(True)

	def keyReports(self):
		if not self.deferRunning:
			self.session.open(CrashReporterReports)

	def keySettings(self):
		if not self.deferRunning:
			self.session.openWithCallback(self.scanForLogs, CrashReporterSettings)

	def keyDeleteLog(self):
		def keyDeleteLogCallback(answer):
			if answer and not self.deferRunning and not self.uiClosed:
				self.deferRunning = True
				self["description"].setText(_("Deleting the selected local crash log..."))
				deferToThread(reportClient.deleteCrashLog, crashLog, reportClient.logDirectories(config.crash.debug_path.value)).addCallbacks(self.scanForLogs, self.failedCallback)

		if not self.deferRunning and self.crashLogs:
			crashLog = dict(self.crashLogs[self["logs"].getSelectedIndex()])
			text = _("Permanently delete this crash log from the receiver?\n\n%s\n\nThis cannot be undone. Other logs and uploaded reports are not affected.") % crashLog["name"]
			self.session.openWithCallback(keyDeleteLogCallback, MessageBox, text, type=MessageBox.TYPE_YESNO, default=False, windowTitle=self.getTitle())


class CrashReporterSettings(Setup):
	def __init__(self, session):
		Setup.__init__(self, session=session, setup="CrashReporter", plugin="Extensions/CrashReporter", PluginLanguageDomain=PluginLanguageDomain)


class CrashReporterResult(QrCodeScreen):
	skin = """
	<screen name="CrashReporterResult" title="Complete Your Crash Report" position="center,center" size="1100,540" resolution="1280,720">
		<widget name="intro" position="30,25" size="700,60" font="Regular;24" />
		<widget name="tracking" position="30,95" size="655,70" font="Regular;44" />
		<widget name="details" position="30,185" size="645,245" font="Regular;23" />
		<widget name="qr" position="770,25" size="300,300" alphatest="off" />
		<widget name="qrStatus" position="750,350" size="340,100" font="Regular;19" horizontalAlignment="center" />
		<widget source="key_red" render="Label" position="30,e-50" size="180,40" backgroundColor="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-100,e-50" size="90,40" backgroundColor="key_back" font="Regular;20" conditional="key_help" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session, result):
		QrCodeScreen.__init__(self, session, _("Preparing QR code..."))
		self.setTitle(_("Complete Your Crash Report"))
		self.result = result
		self["intro"] = Label(_("Scan the QR code, or enter the tracking number on the website."))
		self["tracking"] = Label(reportHelper.formatTracking(result["tracking"]))
		self["details"] = Label(_("%s\n\nSign in or register and confirm your email. Then describe the problem and submit the report within 48 hours. The box model is supplied automatically.") % result["complete_url"])
		self["key_red"] = StaticText(_("Close"))
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions"], {
			"ok": (self.close, _("Close the screen")),
			"cancel": (self.close, _("Close the screen")),
			"red": (self.close, _("Close the screen"))
		}, prio=0, description=_("Crash Reporter Actions"))
		self.onLayoutFinish.append(self.layoutFinished)

	def layoutFinished(self):
		self.showQrCode(reportHelper.reportUrl(self.result["tracking"]), _("The tracking number is filled in automatically."))


class CrashReporterReports(Screen):
	skin = """
	<screen name="CrashReporterReports" title="My Crash Reports" position="center,center" size="1000,460" resolution="1280,720">
		<widget name="reports" position="10,10" size="e-20,e-180" enableWrapAround="1" font="Regular;25" itemHeight="35" scrollbarMode="showOnDemand" verticalAlignment="center" />
		<widget name="description" position="10,e-160" size="e-20,100" font="Regular;20" padding="10" verticalAlignment="center" widgetBorderColor="#00999999" widgetBorderWidth="1" />
		<widget source="key_red" render="Label" position="10,e-50" size="180,40" backgroundColor="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_green" render="Label" position="200,e-50" size="180,40" backgroundColor="key_green" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_yellow" render="Label" position="390,e-50" size="180,40" backgroundColor="key_yellow" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-100,e-50" size="90,40" backgroundColor="key_back" font="Regular;20" conditional="key_help" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session, enableHelp=True)
		self.setTitle(_("My Crash Reports"))
		self["reports"] = MenuList([])
		self["description"] = Label(_("Asking the report server for the state of your reports..."))
		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText(_("Refresh"))
		self["key_yellow"] = StaticText()
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions", "NavigationActions"], {
			"ok": (self.keyShow, _("Show the selected report and the answers")),
			"cancel": (self.close, _("Close the screen")),
			"red": (self.close, _("Close the screen")),
			"green": (self.keyRefresh, _("Ask the report server again")),
			"yellow": (self.keyDelete, _("Delete the selected report from the receiver")),
			"top": (self["reports"].goTop, _("Move to first line / screen")),
			"pageUp": (self["reports"].goPageUp, _("Move up a screen")),
			"up": (self["reports"].goLineUp, _("Move up a line")),
			"down": (self["reports"].goLineDown, _("Move down a line")),
			"pageDown": (self["reports"].goPageDown, _("Move down a screen")),
			"bottom": (self["reports"].goBottom, _("Move to last line / screen"))
		}, prio=0, description=_("Crash Reporter Actions"))
		self.uiClosed = False
		self.refreshRunning = False
		self.deleteRunning = False
		self.reports = []
		self.notes = {}
		self.onLayoutFinish.append(self.layoutFinished)
		self.onClose.append(self.screenClosed)

	def layoutFinished(self):
		self["reports"].enableAutoNavigation(False)
		self.showReports(reportClient.validReports(reportClient.readState()))
		self.keyRefresh()

	def screenClosed(self):
		self.uiClosed = True

	def showReports(self, reports):
		self.reports = sorted(reports, key=reportHelper.lastChange, reverse=True)
		newAnswer = f"  ·  {_('New answer')}"
		self["reports"].setList([f"{reportHelper.formatTime(reportHelper.lastChange(x))}  ·  {reportHelper.formatTracking(x['tracking'])}  ·  {reportHelper.reportStateText(x)}{newAnswer if reportClient.hasNews(x) else ''}" for x in self.reports])
		self["key_yellow"].setText(_("Delete") if reports else "")
		for action in ("ok", "yellow"):
			self["actions"].setEnabledAction(action, bool(reports))

	def keyRefresh(self, *args):  # Also the callback of the report screen.
		def refreshCallback(result):
			self.refreshRunning = False
			if not self.uiClosed:
				self.notes = result[1]
				self.showReports(result[0])
				self["description"].setText(_("Select a report to read the answers. The QR code opens it on a phone or PC.") if result[0] else _("No reports were sent from this receiver yet."))

		def refreshFailed(failure):
			self.refreshRunning = False
			if not self.uiClosed:
				self.showReports(reportClient.validReports(reportClient.readState()))
				self["description"].setText(reportHelper.errorText(failure.value))

		if not self.refreshRunning and not self.uiClosed:
			self.refreshRunning = True
			deferToThread(reportClient.refreshReports).addCallbacks(refreshCallback, refreshFailed)

	def keyDelete(self):
		def deleteCallback(answer):  # A status for an open ticket, otherwise True or False.
			status = answer if isinstance(answer, str) else ("closed" if answer else None)
			if status and not self.uiClosed:
				self.deleteRunning = True
				self["description"].setText(_("Deleting the report. Please wait..."))
				text = "" if report.get("state") == "pending" else reportHelper.finishText(status)
				deferToThread(reportClient.removeReport, report["upload_id"], status, text).addCallbacks(deleteDone, deleteFailed)

		def deleteDone(result):
			self.deleteRunning = False
			if not self.uiClosed:
				self.showReports(reportClient.validReports(reportClient.readState()))
				self["description"].setText(_("The report was deleted from the receiver."))

		def deleteFailed(failure):
			self.deleteRunning = False
			if not self.uiClosed:
				self["description"].setText(_("The report was not deleted. %s") % reportHelper.errorText(failure.value))

		if self.reports and not self.deleteRunning and not self.refreshRunning:
			report = self.reports[self["reports"].getSelectedIndex()]
			if reportClient.canFinish(report):
				if report.get("state") == "pending":
					self.session.openWithCallback(deleteCallback, MessageBox, _("Should the report be deleted?"), type=MessageBox.TYPE_YESNO, default=False, windowTitle=self.getTitle())
				else:
					choices, index = reportHelper.finishChoices(report)
					self.session.openWithCallback(deleteCallback, MessageBox, _("Should the report be deleted?"), list=choices, default=index, windowTitle=self.getTitle())
			else:
				self.session.openWithCallback(deleteCallback, MessageBox, _("Should the report be deleted?"), type=MessageBox.TYPE_YESNO, default=False, windowTitle=self.getTitle())

	def keyShow(self):
		if self.reports:
			report = self.reports[self["reports"].getSelectedIndex()]
			self.session.openWithCallback(self.keyRefresh, CrashReporterReport, report, self.notes.get(report["upload_id"], []))


class CrashReporterReport(QrCodeScreen):
	skin = """
	<screen name="CrashReporterReport" title="Crash Report" position="center,center" size="1100,540" resolution="1280,720">
		<widget name="text" position="30,25" size="700,e-95" font="Regular;22" scrollbarMode="showOnDemand" />
		<widget name="qr" position="770,25" size="300,300" alphatest="off" />
		<widget name="qrStatus" position="750,350" size="340,100" font="Regular;19" horizontalAlignment="center" />
		<widget source="key_red" render="Label" position="30,e-50" size="180,40" backgroundColor="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_green" render="Label" position="220,e-50" size="180,40" backgroundColor="key_green" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_yellow" render="Label" position="410,e-50" size="180,40" backgroundColor="key_yellow" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_blue" render="Label" position="600,e-50" size="180,40" backgroundColor="key_blue" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-100,e-50" size="90,40" backgroundColor="key_back" font="Regular;20" conditional="key_help" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session, report, notes):
		QrCodeScreen.__init__(self, session)
		self.setTitle(_("Crash Report %s") % reportHelper.formatTracking(report["tracking"]))
		self.report = report
		self["text"] = ScrollLabel(self.reportText(report, notes))
		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText()
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText()
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions", "NavigationActions"], {
			"ok": (self.keyFinish, _("Mark the ticket as resolved or close it")),
			"cancel": (self.close, _("Close the screen")),
			"red": (self.close, _("Close the screen")),
			"green": (self.keyFinish, _("Mark the ticket as resolved or close it")),
			"yellow": (self.keyAnswer, _("Write an answer for the developers")),
			"blue": (self.keyAttach, _("Send another log or the diagnostics")),
			"top": (self["text"].goTop, _("Move to first line / screen")),
			"pageUp": (self["text"].goPageUp, _("Move up a screen")),
			"up": (self["text"].goLineUp, _("Move up a line")),
			"down": (self["text"].goLineDown, _("Move down a line")),
			"pageDown": (self["text"].goPageDown, _("Move down a screen")),
			"bottom": (self["text"].goBottom, _("Move to last line / screen"))
		}, prio=0, description=_("Crash Reporter Actions"))
		self.sendRunning = False
		self.onLayoutFinish.append(self.layoutFinished)

	def updateKeys(self):
		writable = bool(self.report.get("writable")) and self.report.get("state") == "submitted"
		finish = self.report.get("state") == "submitted" and reportClient.canFinish(self.report)
		self["key_green"].setText(_("Finish") if finish else "")
		self["key_yellow"].setText(_("Answer") if writable else "")
		self["key_blue"].setText(_("Attach") if writable else "")
		for action in ("ok", "green"):
			self["actions"].setEnabledAction(action, finish)
		self["actions"].setEnabledAction("yellow", writable)
		self["actions"].setEnabledAction("blue", writable)

	def keyFinish(self):
		def finishCallback(status):
			if status and not self.uiClosed:
				self.sendRunning = True
				self["qrStatus"].setText(_("Sending to ticket #%s in the background. Please wait...") % self.report.get("issue"))
				deferToThread(reportClient.finishReport, self.report["upload_id"], status, reportHelper.finishText(status)).addCallbacks(finishDone, finishFailed)

		def finishDone(result):
			deferToThread(reportClient.refreshReports, self.report["upload_id"]).addCallbacks(refreshDone, refreshDone)

		def refreshDone(result):
			self.sendRunning = False
			if not self.uiClosed:
				report = next((x for x in result[0] if x["upload_id"] == self.report["upload_id"]), None) if isinstance(result, tuple) else None
				if report:
					self.report = report
					self["text"].setText(self.reportText(report, result[1].get(report["upload_id"], [])))
				self.updateKeys()
				self.showMessage(_("Ticket #%s now has the status %s.") % (self.report.get("issue"), reportHelper.statusName(self.report.get("status", ""))))

		def finishFailed(failure):
			self.sendRunning = False
			self.showError(failure.value)

		if not self.sendRunning:
			choices, index = reportHelper.finishChoices(self.report)
			self.session.openWithCallback(finishCallback, MessageBox, _("Should the ticket be finished?"), list=choices, default=index, windowTitle=self.getTitle())

	def keyAnswer(self):
		def answerCallback(text):
			if text and text.strip() and not self.uiClosed:
				question = _("Send this answer to ticket #%s?") % self.report.get("issue")
				self.session.openWithCallback(lambda answer: answer and self.send(text=text), MessageBox, f"{question}\n\n{text.strip()}", type=MessageBox.TYPE_YESNO, default=True, windowTitle=self.getTitle())

		if not self.sendRunning:
			self.session.openWithCallback(answerCallback, VirtualKeyBoard, title=_("Answer for ticket #%s (at most %d characters)") % (self.report.get("issue"), reportClient.MAX_NOTE_CHARS), windowTitle=self.getTitle())

	def keyAttach(self):
		def scanCallback(result):
			crashLogs, debugLogs = result
			choices = [(f"{_('Crash log')}: {x['name']}", ("crash", x)) for x in crashLogs[:5]]
			if debugLogs:
				choices.append((f"{_('Current debug log')}: {debugLogs[0]['name']}", ("debug", debugLogs[0])))
			if diagnosticsFor([], reportClient.logDirectories(config.crash.debug_path.value), self.reportOptions()):
				choices.append((_("New diagnostics with the current settings"), ("diagnostics", None)))
			if not self.uiClosed:
				self.session.openWithCallback(choiceCallback, ChoiceBox, text=_("What should be added to ticket #%s?") % self.report.get("issue"), choiceList=choices, windowTitle=self.getTitle())

		def choiceCallback(choice):
			if choice and not self.uiClosed:
				kind, log = choice[1]
				diagnostics = diagnosticsFor([], reportClient.logDirectories(config.crash.debug_path.value), self.reportOptions()) if kind == "diagnostics" else None
				question = _("Send this to ticket #%s?") % self.report.get("issue")
				privacy = _("Known usernames, passwords, API keys, tokens and URLs are removed before upload. Key files and known softcam files are excluded. Other personal information may remain. Reports are private and accessible to you and the OpenATV support team.")
				text = f"{question}\n\n{choice[0]}\n\n{privacy}"
				if kind == "diagnostics":  # Always English, for the developers.
					note = "Added on the receiver: new diagnostics."
				else:
					note = f"Added on the receiver: {'crash log' if kind == 'crash' else 'current debug log'} {log['name']}"
				self.session.openWithCallback(lambda answer: answer and self.send(text=note, logs=[log] if log else [], diagnostics=diagnostics), MessageBox, text, type=MessageBox.TYPE_YESNO, default=True, windowTitle=self.getTitle())

		if not self.sendRunning:
			deferToThread(reportClient.scanLogs, reportClient.logDirectories(config.crash.debug_path.value)).addCallbacks(scanCallback, lambda failure: self.showError(failure.value))

	def reportOptions(self):
		return {x: getattr(config.plugins.CrashReporter, x).value for x in ("receiverInfo", "configuration", "systemLogs", "extraLogs")}

	def send(self, text="", logs=(), diagnostics=None):
		def sendCallback(result):
			deferToThread(reportClient.refreshReports, self.report["upload_id"]).addCallbacks(refreshCallback, refreshFailed)

		def refreshCallback(result):
			self.sendRunning = False
			report = next((x for x in result[0] if x["upload_id"] == self.report["upload_id"]), None)
			if report and not self.uiClosed:
				self.report = report
				self["text"].setText(self.reportText(report, result[1].get(report["upload_id"], [])))
				self["text"].goBottom()
				self.updateKeys()
			self.showMessage(_("Sent to ticket #%s. Thank you!") % self.report.get("issue"))

		def refreshFailed(failure):
			self.sendRunning = False
			self.showMessage(_("Sent to ticket #%s. Thank you!") % self.report.get("issue"))

		def sendFailed(failure):
			self.sendRunning = False
			self.showError(failure.value)

		if not self.sendRunning and not self.uiClosed:
			self.sendRunning = True
			self["qrStatus"].setText(_("Sending to ticket #%s in the background. Please wait...") % self.report.get("issue"))
			deferToThread(reportClient.sendToTicket, self.report["upload_id"], text, logs, diagnostics, sanitizeText).addCallbacks(sendCallback, sendFailed)

	def showMessage(self, text):
		if not self.uiClosed:
			self["qrStatus"].setText(text)

	def showError(self, error):
		if not self.uiClosed:
			self["qrStatus"].setText("")
			self.session.open(MessageBox, reportHelper.errorText(error), type=MessageBox.TYPE_ERROR, windowTitle=self.getTitle())

	def reportText(self, report, notes):
		text = [
			f"{_('Tracking number')}: {reportHelper.formatTracking(report['tracking'])}",
			f"{_('Sent')}: {reportHelper.formatTime(report.get('sent'))}  ·  {report.get('log', '')}"
		]
		if report.get("state") == "submitted":
			text.append(f"{_('Ticket')}: #{report.get('issue')}  ·  {_('Status')}: {reportHelper.statusName(report.get('status', ''))}")
			text.append("")
			if notes:
				if report.get("notes_total", 0) > len(notes):
					text.append(_("The newest %d of %d answers:") % (len(notes), report["notes_total"]))
				for note in notes:
					sender = _("Developer") if note.get("from") == "developer" else _("You")
					text.append(f"{reportHelper.formatTime(note.get('created_on'))}  {sender}:")
					text.append(f"{note['text']}{' ...' if note.get('truncated') else ''}")
					text.append("")
			else:
				text.append(_("There are no answers yet."))
		elif report.get("state") == "pending":
			text.append("")
			text.append(_("This report was not submitted yet. Scan the QR code and complete it on the website until %s.") % reportHelper.formatTime(report.get("expires_at")))
		else:
			text.append("")
			text.append(_("This report is no longer available on the report server. A report that was not completed on the website is deleted after 48 hours."))
		return "\n".join(text)

	def layoutFinished(self):
		def loadCallback(result):
			report = next((x for x in result[0] if x["upload_id"] == self.report["upload_id"]), None)
			if report and not self.uiClosed:
				self.report = report
				self["text"].setText(self.reportText(report, result[1].get(report["upload_id"], [])))
				self.updateKeys()

		self["qr"].hide()
		self.updateKeys()
		if self.report.get("state") == "submitted":
			self.showQrCode(reportHelper.reportUrl(self.report["tracking"]), _("Scan the QR code to open the ticket on a phone or PC. You may have to confirm your email again."))
			if reportClient.hasNews(self.report):
				deferToThread(reportClient.markSeen, self.report["upload_id"]).addErrback(lambda failure: None)
			deferToThread(reportClient.refreshReports, self.report["upload_id"]).addCallbacks(loadCallback, lambda failure: None)
		elif self.report.get("state") == "pending":
			self.showQrCode(reportHelper.reportUrl(self.report["tracking"]), _("The tracking number is filled in automatically."))


class CrashReporterReminder:
	"""Offer to report a new crash log, after a restart or after a Python exception (BSOD screen)."""

	def __init__(self, session):
		self.session = session
		self.infoBar = None
		self.scanRunning = False
		self.promptIdentity = None  # The crash log the user is currently asked about.
		self.crashPending = False
		self.bsodCount = getBsodCounter()
		self.startTimer = eTimer()
		self.startTimer.callback.append(self.checkForCrash)
		self.startTimer.startLongTimer(10)  # Check once after the start for a crash that restarted Enigma2.
		self.answerTimer = eTimer()
		self.answerTimer.callback.append(self.checkForAnswers)
		self.answerTimer.startLongTimer(60)  # After the crash check.

	def attachInfoBar(self, infoBar):
		if self.infoBar is not infoBar:
			self.detachInfoBar()
			self.infoBar = infoBar
			infoBar.onLayoutFinish.append(self.bindInfoBar)  # The BSOD timer doesn't exist yet.

	def bindInfoBar(self):
		if self.infoBar:
			if self.bindInfoBar in self.infoBar.onLayoutFinish:
				self.infoBar.onLayoutFinish.remove(self.bindInfoBar)
			timer = getattr(self.infoBar, "bsodTimer", None)  # Use the BSOD timer of the InfoBar instead of an own timer.
			if timer and self.crashChanged not in timer.callback:
				timer.callback.append(self.crashChanged)

	def detachInfoBar(self):
		if self.infoBar:
			if self.bindInfoBar in self.infoBar.onLayoutFinish:
				self.infoBar.onLayoutFinish.remove(self.bindInfoBar)
			timer = getattr(self.infoBar, "bsodTimer", None)
			if timer and self.crashChanged in timer.callback:
				timer.callback.remove(self.crashChanged)
			self.infoBar = None

	def crashChanged(self):
		bsodCount = getBsodCounter()
		if bsodCount > self.bsodCount:
			self.crashPending = True
		self.bsodCount = bsodCount  # The user can reset the counter.
		if self.crashPending and not self.scanRunning and self.promptIdentity is None and not getattr(self.infoBar, "bsodIsShown", False):
			self.crashPending = False
			self.checkForCrash()

	def checkForCrash(self):
		def checkForCrashCallback(result):
			self.scanRunning = False
			crashLogs = result[0]
			if getattr(self.infoBar, "bsodIsShown", False):
				self.crashPending = True
			elif config.plugins.CrashReporter.reminder.value and crashLogs and self.promptIdentity is None:
				identity = reportClient.logIdentity(crashLogs[0])
				if reportClient.readState().get("last_prompt") != identity:
					self.promptIdentity = identity
					text = _("Enigma2 has created a new crash log. Would you like to report the problem now? No data will be sent without your confirmation.")
					try:  # A modal notification also shows while the faulty screen is open. No timeout, so the offer isn't lost.
						AddModalNotification(text, timeout=-1, default=False, typeIcon=MessageBox.TYPE_YESNO, windowTitle=_("Crash Reporter"), callback=self.answerCallback)
					except Exception as err:
						self.promptIdentity = None
						print(f"[CrashReporter] Error: Unable to show the crash report offer!  ({err})")

		def checkForCrashFailed(failure):
			self.scanRunning = False
			print(f"[CrashReporter] Error: Unable to scan for crash logs!  ({failure.value})")

		if not self.scanRunning and self.promptIdentity is None and config.plugins.CrashReporter.reminder.value:
			if getattr(self.infoBar, "bsodIsShown", False):
				self.crashPending = True
			else:
				self.scanRunning = True
				deferToThread(reportClient.scanLogs, reportClient.logDirectories(config.crash.debug_path.value)).addCallbacks(checkForCrashCallback, checkForCrashFailed)

	def checkForAnswers(self):
		def checkForAnswersCallback(result):
			if any(reportClient.hasNews(x) for x in result[0]):
				text = _("A developer has answered your crash report. Would you like to read the answer now?")
				try:
					AddModalNotification(text, timeout=-1, default=True, typeIcon=MessageBox.TYPE_YESNO, windowTitle=_("Crash Reporter"), callback=answersCallback)
				except Exception as err:
					print(f"[CrashReporter] Error: Unable to show the answer reminder!  ({err})")

		def checkForAnswersFailed(failure):
			print(f"[CrashReporter] Unable to check the sent reports.  ({failure.value})")

		def answersCallback(answer):
			if answer:
				self.session.open(CrashReporterReports)

		# Only reports that can still change.
		if config.plugins.CrashReporter.answerReminder.value and any(x.get("state") == "pending" or (x.get("state") == "submitted" and not x.get("closed")) for x in reportClient.validReports(reportClient.readState())):
			deferToThread(reportClient.refreshReports).addCallbacks(checkForAnswersCallback, checkForAnswersFailed)

	def answerCallback(self, answer):
		identity = self.promptIdentity
		self.promptIdentity = None
		if identity:  # Only save after the user answered, so a restart doesn't lose an unseen offer.
			state = reportClient.readState()
			state["last_prompt"] = identity
			try:
				reportClient.saveState(state)
			except OSError as err:
				print(f"[CrashReporter] Error {err.errno}: Unable to save the reminder state!  ({err.strerror})")
		if answer:
			self.session.open(CrashReporter)


def main(session, **kwargs):
	session.open(CrashReporter)


def menu(menuid, **kwargs):
	return [(_("Crash Reporter"), main, "crashreporter", 30)] if menuid == "support" else []


def sessionStart(reason, session=None, **kwargs):
	global crashReminder
	if reason == 0 and session:
		crashReminder = CrashReporterReminder(session)


def infoBarLoaded(reason, session=None, instance=None, typeInfoBar=None, **kwargs):
	if crashReminder and typeInfoBar == "InfoBar":
		if reason == 1 and instance:
			crashReminder.attachInfoBar(instance)
		elif reason == 0 and crashReminder.infoBar is instance:
			crashReminder.detachInfoBar()


def Plugins(**kwargs):
	name = _("Crash Reporter")
	description = _("Send crash logs to OpenATV support and get a case tracking number. (Version %s)") % __version__
	icon = "CrashReporter-fhd.png" if getDesktop(0).size().width() >= 1920 else "CrashReporter.png"
	return [
		PluginDescriptor(name=name, description=description, where=PluginDescriptor.WHERE_PLUGINMENU, icon=icon, fnc=main, needsRestart=False),
		PluginDescriptor(name=name, description=description, where=PluginDescriptor.WHERE_MENU, fnc=menu, needsRestart=False),
		PluginDescriptor(where=PluginDescriptor.WHERE_SESSIONSTART, fnc=sessionStart),
		PluginDescriptor(where=PluginDescriptor.WHERE_INFOBARLOADED, fnc=infoBarLoaded)
	]
