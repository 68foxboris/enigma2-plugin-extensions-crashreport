from gettext import bindtextdomain, dgettext, gettext
from Components.International import international
from Tools.Directories import SCOPE_PLUGINS, resolveFilename

__version__ = "0.5"

PluginLanguageDomain = "CrashReporter"
PluginLanguagePath = "Extensions/CrashReporter/locale"


def _(text):
	if (translation := dgettext(PluginLanguageDomain, text)) == text:
		translation = gettext(text)
	return translation


def localeInit():
	bindtextdomain(PluginLanguageDomain, resolveFilename(SCOPE_PLUGINS, PluginLanguagePath))


localeInit()
international.addCallback(localeInit)
