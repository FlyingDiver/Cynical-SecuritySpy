#
# cyin.plug - cyin Plugin class core
#
# Copyright 2011-2016 Perry The Cynic. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import with_statement
from distutils.version import StrictVersion
import sys
import os
import select
import time
import weakref
import plistlib
from collections import defaultdict, deque

import indigo

import cyin
import cyin.core
import cyin.common
import cyin.filter
import cyin.debugging
from cyin import iom
from cyin import stdaction
from cyin.core import debug, error, log
from cyin.configui import ConfigUI
from cyin.debugging import diagnose, diagnostic_log


#
# A decorator to handle Indigo entry points and allow subclasses to modify behavior:
#	@entry(type)
#	def frobolate(whatever):
# This sends the call through the call_entry gate of the plugin class, where it
# can be wrapped, coddled, adulterated, and seasoned to taste.
#
def entry(type):
	def deco(method):
		def call(*args, **kwargs):
			return cyin.plugin.call_entry(type, method, *args, **kwargs)
		return call
	return deco

CONCURRENT = "concurrent"			# other-thread entry, no reply
CONFIGUI = "config_ui"				# other-thread entry, wait for reply


#
# The base class of all cyin plugin objects. Define a subclass Plugin
# in your plugin.py and Indigo will create a singleton for you.
#
# From Indigo's point of view, only this one class instance exists,
# and Indigo will send all calls to it. Plugin picks up all those
# myriad calls, organizes them neatly, and passes them off to the
# various classes that make up a cyin-based plugin.
#
# Thus, in the cyin universe, Plugin isn't very special at all - it
# is duck-type similar to IOMBase, and carries a few global methods
# that might be useful to override for global state control.
# It is perfectly possible for a useful plugin to have a completely
# empty Plugin class. (You still need to declare it.)
#
class Plugin(indigo.PluginBase, iom.PluginCore, iom.Observer, metaclass=cyin.iom.IOMeta):

	_config_type = 'preference'

	UI = ConfigUI

	shutting_down = False		# will become True once shutdown has begin


	#
	# Construction
	#
	def __init__(self, ident, name, version, prefs):
		indigo.PluginBase.__init__(self, ident, name, version, prefs)
		iom.PluginCore.__init__(self, ident, name, version)
		iom.Observer.__init__(self)

		# we're sort of our own iom object, so let's quack like one
		self.io = self
		self._config_level = 1			# ConfigUI running revision level
		self._config = indigo.PluginBase.getPrefsConfigUiXml(self)	# ConfigUI XML
		self.plugin = self				# well, technically...
		self.active = False				# will become True when Indigo tells us to run

		# about ourselves on disk...
		here = sys.modules[__name__].__file__
		self.location = here[0:here.rindex('/Contents/')]
		with open(self.location + "/Contents/Info.plist", "rb") as f:
			self.info_plist = plistlib.load(f)
		try:
			self.support_url = self.info_plist["CFBundleURLTypes"][0]["CFBundleURLName"]
		except:
			self.support_url = None

		# compatibility/version check
		try:
			api = indigo.server.apiVersion
		except:
			api = "1.0"		# pre-1.7; just assume minimum
		debug("API version", api)
		debug("Python version", ".".join(str(s) for s in sys.version_info))
		self.apiVersion = StrictVersion(api)
		problem = self.check_compatibility()
		if problem:
			error(problem)
			raise Exception(problem)

		# set the plugin singleton
		assert cyin.plugin is None
		cyin.plugin = self

		# initialize state
		self._ui = None				# pending IOM-based ConfigUI (modal, so at most one)
		self._observed_kinds = set()
		self._observers = weakref.WeakKeyDictionary()

		# configure debug layer
		cyin.debugging.configure()

		# redirect stdout/stderr to Indigo log
		sys.stdout = cyin.core.LogWriter("[OUT]", debug)
		sys.stderr = cyin.core.LogWriter("[ERR]", error)

		# add canned elements to our plugin
		cyin.common.add_features(self)

		for id, desc in self.devicesTypeDict.items():
			iom.type_for(id).adapt(desc)
		for id, desc in self.eventsTypeDict.items():
			iom.type_for(id).adapt(desc)


	#
	# PluginFeature personality
	#
	enabled = True	# we're running, ergo we're enabled

	def restart(self):
		indigo.server.getPlugin(self.ident).restart(waitUntilDone=False)


	#
	# Early compatibility checks. Override these constants for your plugin.
	#
	MIN_INDIGO_VERSION = '5.0.0' # do not run if Indigo is older than this
	BAD_INDIGO_VERSIONS = []	# explicitly known-bad versions

	#
	# Or for more complicated situations, override this method
	# and return an error message to refuse to run.
	#
	def check_compatibility(self):
		try:
			indigo_version = StrictVersion(indigo.server.version.replace(" ", ""))
		except ValueError:
			log("Indigo version %s not recognized; proceeding" % indigo.server.version)
			return
		if indigo_version < self.MIN_INDIGO_VERSION:
			 return "Indigo version %s or later is required for version %s of the %s plugin. Please upgrade Indigo." % (
				self.MIN_INDIGO_VERSION, self.version, self.name)
		if indigo_version in self.BAD_INDIGO_VERSIONS:
			return "Indigo version %s cannot be used with version %s of the %s plugin. Please upgrade Indigo." % (
				indigo_version, self.version, self.name)


	#
	# Unified feature support check facility
	#
	def supports(self, feature):
		""" Check for availability of a named feature.

			This is a cyin facility. Pass the well known name of a feature,
			and get back None if not supported, or Python true if it is.
			More detailed information may be conveyed through that value.
		"""
		if feature == 'uivalue':	# support ..., uivalue=<str> key of state update calls
			return self.apiVersion >= "1.6"
		if feature == 'devicegroups': # supports getGroupList
			return self.apiVersion >= "1.14"


	#
	# Managing watch notifications
	#
	_OBSERVABLES = {
		"device":	{ "enable": indigo.devices.subscribeToChanges,	"setPrior": True },
		"event":	{ "enable": indigo.triggers.subscribeToChanges, "setPrior": True },
		"variable":	{ "enable": indigo.variables.subscribeToChanges,"setPrior": False },
		"action":	{ "enable": lambda: 0,							"setPrior": False },
		"log":		{ "enable": lambda: cyin.plugin._startLogObservation(), "setPrior": False }
	}

	def _observe(self, observer, kind, qual):
		if qual == []:
			if observer in self._observers:
				self._observers[observer].discard(kind)
			if not self._observers[observer]:
				del self._observers[observer]
		else:
			if observer not in self._observers:
				self._observers[observer] = set()
			self._observers[observer].add(kind)
			if kind not in self._observed_kinds:
				assert kind in self._OBSERVABLES
				debug("enabling", kind, "observations")
				self._OBSERVABLES[kind]["enable"]()
				self._observed_kinds.add(kind)

	# notify Observers that have active notification requests
	def _notify(self, kind, op, new, make, prior=None):
		#debug("_notify", kind, op, new.name, new, make, "prior", prior)
		if kind in self._observed_kinds:
			setPrior = self._OBSERVABLES[kind]["setPrior"]
			for observer in self._observers:
				if kind in observer._observing:
					qual = observer._observing[kind]
					if qual is None or new.id in qual:
						iom = make(new)
						if iom is not None:
							if setPrior: iom._prior = prior
							try:
								observer.notify(kind, op, iom)
							finally:
								if setPrior: iom._prior = None

	def _unobserve(self, observer):
		if observer in self._observers:
			del self._observers[observer]


	#
	# The official "start" and "end" calls made by Indigo.
	# Cyin plugins often don't use them, so we provide empty shells.
	#
	def startup(self):
		""" First call made to the plugin. """
		pass

	def begin_shutdown(self):
		""" Called when the plugin begins shutting down. """
		debug("shutdown sensed")

	def shutdown(self):
		""" Last call made to the plugin. """
		pass


	#
	# Provide a default do-nothing main thread that just goofs off until
	# it's time to die. Override runConcurrentThread to do proactive work.
	#
	@diagnose
	def run_concurrent_thread(self):
		""" Start main thread - threading version. """
		debug("plugin starting threaded operation")
		self.active = True
		try:
			while True:
				self.sleep(3600*24*365)
		except self.StopThread:
			pass
	


	#
	# Device management relays
	#
	@entry(CONCURRENT)
	def deviceStartComm(self, io):
		iom.start_object(io, io.deviceTypeId)

	@entry(CONCURRENT)
	def deviceStopComm(self, io):
		iom.stop_object(io)

	@entry(CONCURRENT)
	def deviceUpdated(self, old, new):
		iom.update_object(old, new, new.deviceTypeId)
		self._notify("device", "update", new, make=lambda x: iom.device(x.id), prior=old)

	@entry(CONCURRENT)
	def deviceCreated(self, io):
		if io.deviceTypeId:
			iom.start_object(io, io.deviceTypeId)

	@entry(CONCURRENT)
	def deviceDeleted(self, io):
		iom.stop_object(io, destroy=True)
		self._notify("device", "delete", io, make=lambda x: iom.device(x.id))


	#
	# Event/trigger management relays
	#
	@entry(CONCURRENT)
	def triggerStartProcessing(self, io):
		iom.start_object(io, io.pluginTypeId)

	@entry(CONCURRENT)
	def triggerStopProcessing(self, io):
		iom.stop_object(io)

#	@entry(CONCURRENT)
#	def triggerUpdated(self, old, new):
#		iom.update_object(old, new, new.pluginTypeId)

#	@entry(CONCURRENT)
#	def triggerCreated(self, io):
#		iom.start_object(io, io.pluginTypeId)

#	@entry(CONCURRENT)
#	def triggerDeleted(self, io):
#		iom.stop_object(io, destroy=True)


	#
	# Drive the plugin's own ConfigUI (annoyingly different from device/event/action)).
	#
	@entry(CONFIGUI)
	def getPrefsConfigUiXml(self):
		if self._ui is None:
			self._ui = self.UI(cyin.plugin)
		return self._ui._xml(indigo.PluginBase.getPrefsConfigUiXml(self), "plugin")

	@entry(CONFIGUI)
	def getPrefsConfigUiValues(self):
		init = indigo.PluginBase.getPrefsConfigUiValues(cyin.plugin)
		if self._ui is None:
			self._ui = self.UI(cyin.plugin)
		return self._ui._start_ui(init, None, None, None)

	@entry(CONFIGUI)
	def validatePrefsConfigUi(self, values):
		return self._ui._check_ui(values)

	@entry(CONFIGUI)
	def closedPrefsConfigUi(self, values, cancelled):
		if not cancelled:
			cyin.debugging.configure() # reconfigure debug options
		self._ui._end_ui(values, cancelled)
		self._ui = None

	#
	# Drive ConfigUI for IOMs (device, events, and actions)
	#
	def _startUi(self, iotype, id):
		cls = iom.type_for(iotype)	# implementing class
		if self._ui is None:
			self._ui = cls.UI(cls)
		obj = dev = None
		if cls._iom_type == 'device':
			obj = dev = iom.device(id, ui=self._ui) # existing object, if any
			if obj:
				obj.refresh()			# update
		elif cls._iom_type == 'event':
			obj = iom.trigger(id, ui=self._ui)
			if obj:
				obj.refresh()			# update
		elif cls._iom_type == 'action':
			if id:
				dev = cyin.device(id)
			obj = cls(None, dev=dev)
		return (cls, obj, dev)

	@entry(CONFIGUI)
	def getIOMConfigUiXml(self, type, id):
		(cls, obj, dev) = self._startUi(type, id)
		iodict = cls._configsDict()[type]
		return self._ui._xml(iodict["ConfigUIRawXml"], iodict["Name"])

	@entry(CONFIGUI)
	def getIOMConfigUiValues(self, props, type, id):
		(cls, obj, dev) = self._startUi(type, id)
		return self._ui._start_ui((props, indigo.Dict()), cls, obj, dev)

	@entry(CONFIGUI)
	def validateIOMConfigUi(self, values, type, id):
		return self._ui._check_ui(values)

	@entry(CONFIGUI)
	def endIOMConfigUi(self, values, cancelled, type, id):
		(cls, obj, dev) = self._startUi(type, id)
		if obj:
			obj.configUI = None
		self._ui._end_ui(values, cancelled)
		self._ui = None

	getDeviceConfigUiXml = getIOMConfigUiXml
	getEventConfigUiXml = getIOMConfigUiXml
	getActionConfigUiXml = getIOMConfigUiXml

	getDeviceConfigUiValues = getIOMConfigUiValues
	validateDeviceConfigUi = validateIOMConfigUi
	closedDeviceConfigUi = endIOMConfigUi

	getEventConfigUiValues = getIOMConfigUiValues
	validateEventConfigUi = validateIOMConfigUi
	closedEventConfigUi = endIOMConfigUi

	getActionConfigUiValues = getIOMConfigUiValues
	validateActionConfigUi = validateIOMConfigUi
	closedActionConfigUi = endIOMConfigUi


	#
	# Stand-alone menu dialogs are a bit... half-baked
	#
	def getMenuActionConfigUiXml(self, name):
		xml = indigo.PluginBase.getMenuActionConfigUiXml(self, name)
		return ConfigUI._xml(xml, name)

#	def getMenuActionConfigUiValues(self, menuId):
#		return indigo.PluginBase.getMenuActionConfigUiValues(self, menuId)

	# currently not implemented
#	def validateMenuActionConfigUi(self, valuesDict, menuId):
#		return (True, valuesDict)

	# currently not implemented
#	def closedMenuActionConfigUi(self, valuesDict, userCancelled, menuId):
#		return


	#
	# Device callbacks for the predefined device types
	#
	def action_control_universal(self, action, dev):
		stdaction.UniversalAction(action).dispatch()

	def action_control_device(self, action, dev):
		stdaction.ControlAction(action).dispatch()

	def action_control_sensor(self, action, dev):
		stdaction.SensorAction(action).dispatch()

	def action_control_thermostat(self, action, dev):
		stdaction.ThermostatAction(action).dispatch()


	#
	# Dynamic state maintenance. Handed to device instances.
	#
	@entry(CONFIGUI)
	def getDeviceStateList(self, iodev):
		# no Indigo5/6 compatible approach yet
		return indigo.PluginBase.getDeviceStateList(self, iodev)

	@entry(CONFIGUI)
	def getDeviceDisplayStateId(self, iodev):
		# no Indigo5/6 compatible approach yet
		return indigo.PluginBase.getDeviceDisplayStateId(self, iodev)


	#
	# Sleep/wake notifications from Indigo
	#
	def prepareToSleep(self):
		debug("going to sleep")
		indigo.PluginBase.prepareToSleep(self)

	def wakeUp(self):
		debug("waking up")
		indigo.PluginBase.wakeUp(self)


	#
	# Variable event hooks. Only called when we subscribeToChanges.
	#
	@entry(CONCURRENT)
	def variableCreated(self, var):
		self._notify("variable", "create", var, make=lambda x: cyin.variable(x))

	@entry(CONCURRENT)
	def variableUpdated(self, old, new):
		self._notify("variable", "update", new, make=lambda x: cyin.variable(x), prior=old)

	@entry(CONCURRENT)
	def variableDeleted(self, var):
		self._notify("variable", "delete", var, make=lambda x: cyin.variable(x))
	
	
	#
	# Log event hook
	#
	@entry(CONCURRENT)
	def eventLogLineReceived(self, entry):
		msg = iom.LogMessage(entry)
		self.logQueue.append(msg)
		self._notify("log", "add", msg, lambda x: x)

	def _startLogObservation(self):
		self.logQueue = deque([iom.LogMessage(m) for m in indigo.server.getEventLogList(returnAsList=True)])
		indigo.server.subscribeToLogBroadcasts()
	

	#
	# Support for adding UI elements directly
	#
	def add_action(self, id, uiPath="DeviceActions", **kwargs):
		base = self.actionsTypeDict
		dic = dict(SortOrder=len(base), UiPath=uiPath, **kwargs)
		if "CallbackMethod" not in dic:
			dic["CallbackMethod"] = ""
		if "DeviceFilter" not in dic:
			dic["DeviceFilter"] = ""
		base[id] = dic


	#
	# Default entry gate: Guard with diagnostics, but otherwise just call
	#
	@staticmethod
	def call_entry(type, method, *args, **kwargs):
		with diagnostic_log(name=method.__name__):
			return method(*args, **kwargs)


	#
	# Dispatch callbacks configured from XML. This currently handles:
	#
	# Action callbacks - dispatched to action class or subject device
	# Button and checkbox callbacks - dispatched to active ConfigUI object
	# Menu filter callbacks - dispatched by creating the matching MenuFilter
	#	class and invoking it.
	#
	# The upshot is that these calls are transferred to the naturally owning
	# class, and thus away from the grab-bag that Indigo thinks the plugin is.
	#
	def __getattr__(self, name):
		# blacklist certain names (hopefully temporary)
		if name in ['launchDebugger']:
			raise AttributeError(name=name, obj=self)

		class Forward(object):
			def __init__(self, name):
				self.name = name
			
			def __call__(self, arg=None, *args, **kwargs):
				if arg is None:
					return error(f'{self.name} invoked on Plugin with no arguments')
				if isinstance(arg, indigo.Dict):	# crude but effective
					return self.button(arg, *args, **kwargs)
				elif isinstance(arg, str):
					return self.menufilter(arg, *args, **kwargs)
				elif isinstance(arg, indigo.BaseAction):
					return self.action(arg, *args, **kwargs)
				else:
					error(f'unexpected argument {arg} calling {name}')

			# button (and menu change, and the like) callback
			def button(self, config, *args):
				ui = cyin.plugin._ui
				ui._ui_values = config	# pick up latest values
				assert ui
				if hasattr(ui, name):
					method = getattr(ui, name)
					if hasattr(method, '_method_type'):
						with diagnostic_log(name):
							method()
							return ui._ui_values	# pick up any changes
					else:
						error("internal error: %s is not a button or checkbox method" % name)
						return config	# don't change anything
				elif ui.iomtype:
					error("no button", name, "in", ui.iomtype._iom_type, ui.iomtype.__name__)
				else:
					error("no button", name)

			# action callback
			def action(self, ioaction, iodev, want_result):
				try:
					if ioaction.pluginTypeId:
						actiontype = cyin.iom.type_for(ioaction.pluginTypeId)
					else:
						actiontype = cyin.iom.type_for(type(ioaction).__name__)
				except AttributeError:
					return error(f'ignoring unrecognized action {actiontype} for {ioaction}')
				action = actiontype(ioaction)
				target = action.bind("perform", "action") # always use an action method
				if target is not None:
					with diagnostic_log(name):
						return target()
				dev = action.device
				if dev:	# send to device instance
					if hasattr(dev, name):
						target = dev.bind(name, "action")
						if not dev.ready():
							error("ignoring", name, "action for unready device", dev.name)
							return
					else:
						return error("no callback", name, "in", dev)
				if target:
					with diagnostic_log(name):
						target(action)
				else:
					error(f'no method "{name}" for action "{action.description}"')

			# a menu filter
			def menufilter(self, filter, *args, **kwargs):
				assert cyin.plugin._ui	# active ui
				with diagnostic_log("filter %s" % name):
					filter = cyin.filter.create(name, filter, cyin.plugin._ui)
					if filter:
						menu = filter._evaluate()
						if menu:
							return menu
					else:
						error("internal error: no menu filter class", name)
				return []

		return Forward(name)
