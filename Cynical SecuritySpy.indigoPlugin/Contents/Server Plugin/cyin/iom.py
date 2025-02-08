#
# cyin.iom - objects that shape the Cynical Indigo Object Model interface
#
# In the cyin world, the plugin maker creates classes to "shadow" the XML.
# The class names must match the id="..." clause of the XML (except for case).
# The Plugin class will forward substantially all behavior to these classes.
# You *must* create a class (subclassed from one declared here) for each
# action, event, and device in your XML. Cyin will take it from there.
#
# Copyright 2011-2019 Perry The Cynic. All rights reserved.
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
import indigo
import cyin
from cyin.core import debug, error, log
from cyin.core import i_equal
from cyin.attr import PluginProperty, DeviceState, is_descriptor
from cyin.configui import ConfigUI

import datetime

DEBUG = None


#
# Mapping and tracking IOM objects.
# Note that this tracks *our* objects; indigo.* tracks Indigo's objects just fine.
#
_iomap = { }				# indigo object id -> IOM object
_clsmap = { }				# indigo type string -> IOM class object
_pluginmap = { }			# indigo plugin id -> PluginCore object

_self = object()			# under-construction marker in _iomap


def type_for(type, report_error=True):
	""" Get the class object for an XML type name. Returns None (and yells) if not found. """
	ltype = type.lower()
	if ltype not in _clsmap:
		if report_error:
			error('XML inconsistent: missing class', ltype)
		return None
	return _clsmap[ltype]


#
# Readiness state adapter
#
def _enabled(io):
	try:
		return io.enabled and io.configured
	except AttributeError:
		return io.enabled


#
# Map indigo IOM ("io") references to ids.
# This works for devices and triggers (but not action groups).
#
def _normalize(id, collection):
	if not id:
		return None						# None -> None
	if isinstance(id, int):
		return id						# numbers are ids
	elif isinstance(id, str):
		try:
			return int(id)				# numeric strings are ids
		except ValueError:
			dev = collection.get(id)	# try it as a device name
			if dev:
				return dev.id
	else:
		error("unexpected _normalize(%s)" % id)


def device(id, ui=None):
	""" Get our object for an Indigo device id or name.

		This will construct our object if it's not already known.
		Thus, your object constructor may fetch another device's id
		from its properties and feed it to device() before its turn
		in deviceStartComm, effectively constructing in topological order.
		Construction will then be skipped later.

		If the argument is a number (even a numeric string), it denotes
		its indigo object id. If it's another kind of string, it is taken
		to be the device's name.
	"""
	id = _normalize(id, indigo.devices)
	if id is None:
		return None
	if id not in _iomap:
		if id not in indigo.devices:	# stale, deleted, just plain wrong, ...
			error("attempt to use missing device id", id) # (we know nothing more about it)
			return None
		iodev = indigo.devices[id]
		try:
			if not iodev.configured:	# Indigo 6 only
				return					# too early to process
		except:
			pass
		try:
			_iomap[id] = _self				# mark id slot "being created"
			start_object(iodev, iodev.deviceTypeId, ui=ui) # canonical create-and-optional-start
		finally:
			if _iomap[id] == _self:			# construction failed
				error("Error constructing %s device %s[%d]" % (iodev.deviceTypeId, iodev.name, id))
				del _iomap[id]				# clear marker; allow retry
				return None
	return _iomap[id]


def trigger(id, ui=None):
	id = _normalize(id, indigo.triggers)
	if id is None:
		return None
	if id not in _iomap:
		if id not in indigo.triggers:	# stale, deleted, just plain wrong, ...
			error("attempt to use missing even trigger id", id) # (we know nothing more about it)
			return None
		iotrig = indigo.triggers[id]
		start_object(iotrig, iotrig.pluginTypeId, ui=ui) # canonical create-and-optional-start
		if id not in _iomap:			# construction failed
			error("Error constructing %s event trigger %s[%d]" % (iotrig.pluginTypeId, iotrig.name, id))
			return None
	return _iomap[id]


#
# Look up (and optionally create) a plugin object
#
def plugin_for(io, make=False):
	""" Given an Indigo iom object, return our Plugin object for it.
	
		Returns cyin.plugin for our own plugin and any of its objects.
		Returns a ForeignPlugin object for other plugins.
		Returns a BuiltinPlugin for built-in iom objects.
	"""
	if hasattr(io, 'pluginId'):
		id = io.pluginId or None
		if id in _pluginmap:
			return _pluginmap[id]
		if make:
			if id:
				return ForeignPlugin(id)
			else:
				return BuiltinPlugin()


#
# General object lifetime harness for IOM subclasses.
# This only works for IOMs (i.e. not for Actions).
#
def start_object(io, type, ui=None):
	""" Create or locate an object, then start it if it should be active. """
	id = io.id
	if id not in _iomap or _iomap[id] == _self:		# new
		if io.pluginId == cyin.plugin.ident:
			cls = type_for(type)
			if cls is None:
				return error("unrecognized type", type)
			iom = cls(io)
		else:
			from cyin.stddevice import builtinObject
			iom = builtinObject(io)
	else:
		iom = _iomap[id]
	if _enabled(io) and not iom.active:
		debug(iom.name, "starting")
		iom.io = io
		iom.active = True
		iom.start()

def stop_object(io, change=False, destroy=False):
	""" Universal stop funnel. Called whenever someone wants to deactivate a device. """
	id = io.id
	if id in _iomap:
		iom = _iomap[id]
		if not change and not destroy and not cyin.plugin.shutting_down:
			# unmotivated stop - assume shutdown has begun
			cyin.plugin.shutting_down = True
			cyin.plugin.begin_shutdown()
		if destroy:
			iom.deleted = True	# prevent further IOM updates (Indigo won't allow them)
		if iom.active:
			debug(iom.name, "stopping")
			iom.active = False
			iom.stop()
		if destroy:
			debug(iom.name, "destroyed")
			del _iomap[id]

def update_object(old, new, typeid):
	""" Unconditional update funnel. Called whenever Indigo signals a config change. """
	assert old.id == new.id
	old_e = _enabled(old)
	new_e = _enabled(new)
	if not old_e and new_e:
		return start_object(new, typeid)
	elif old_e and not new_e:
		return stop_object(new, change=True)
	elif new_e and new.id in _iomap:			# we know about it
		iom = _iomap[new.id]
		assert iom.id == new.id
		iom.name = new.name			# keep newest
		iom.io = new				# keep newest
		descriptors = type(iom)._descmap.values()
		# apply defaults for (newly) missing attributes
		for desc in [desc for desc in descriptors if desc.name not in old.pluginProps and desc.default is not None]:
			desc._apply_default(iom)
		# (but still count defaulted values as changes, this time)
		changes = [desc for desc in descriptors
			if desc.name not in old.pluginProps or old.pluginProps[desc.name] != new.pluginProps[desc.name]]
		essentials = [desc.name for desc in changes if desc.reconfigure == 'essential']
		if essentials:
			debug(iom.name, "reconfiguring because", ', '.join(essentials), "changed")
			iom.reconfigure()
		else:
			notifies = [desc.name for desc in changes if desc.reconfigure == 'notify']
			if notifies:
				iom.config_changed(notifies)


#
# A mix-in class for objects that can receive observations
#
class Observer(object):
	""" A recipient of Indigo state notifications. """
	def __init__(self):
		self._observing = { }

	def __del__(self):
		cyin.plugin._unobserve(self)

	def observe(self, kind, qual):
		""" Set the set of observables of a given kind.
		
			Qual can be a list of IOMs, or None to observe all objects of that kind.
			For each kind, the last value supersedes all previous settings.
			Pass an empty list [] to discontinue notifications of that kind.
		"""
		if qual is not None:
			qual = [q if isinstance(q, int) else q.id for q in qual if q]
		self._observing[kind] = qual
		cyin.plugin._observe(self, kind, qual)

	def notify(self, kind, op, *args):
		pass


#
# Meta-classes for fun and profit.
#
class IOMeta(type):
	""" A metaclass to collect (some) attribute Descriptors from class definitions.

		Specifically, collect any descriptors from this or any base class,
		except ones whose name starts with _, and put them into cls.attributes.
	"""
	@staticmethod
	def _collect_descriptors(cls):
		descmap = { }
		# pick up descriptors from base classes
		for parent in cls.__bases__:		# inherit descriptors, if any
			if 'attributes' in parent.__dict__:
				descmap.update(parent.attributes)
		# update our own descriptors and collect properties (only)
		for name, attr in [(k, v) for (k, v) in cls.__dict__.items()
				if k[0] != '_' and is_descriptor(v)]:
			if attr.name is None:
				attr.default_name(name)
			if is_descriptor(attr):
				descmap[name] = attr
		return descmap
	
	def __new__(mcls, name, bases, content):
		cls = type.__new__(mcls, name, bases, content)
		config_type = cls._config_type if hasattr(cls, '_config_type') else 'property'
		if '_iom_type' not in cls.__dict__:	# (and not IOM or excluded)
			cls.attributes = IOMeta._collect_descriptors(cls)
			cls._descmap = dict([(k, v) for (k, v) in cls.attributes.items()
				if v._desc_type == config_type])
		return cls


class IOMetaMap(IOMeta):
	""" A metaclass to record each created class into _clsmap.

		In addition to IOMeta, we also record the new class in _clsmap
		unless it's an abstract base class or its name starts with _.
	"""
	def __new__(mcls, name, bases, content, register=True):
		cls = IOMeta.__new__(mcls, name, bases, content)
		# record in class map unless private
		if isinstance(register, str):
			name = register
		elif not register or name.startswith('_'):
			name = None
		if name:
			name = name.lower()
			assert name not in _clsmap
			_clsmap[name] = cls
		return cls


#
# Base class of IOM shadow objects, whether they have IOM ids or not.
# This currently applies to devices, events, and actions.
#
class IOMBase(object):
	""" Basic shadow class for an Indigo Object Model entity.

		IOMBase is cyin's way of talking about objects in the Indigo Object Model.
		Its self.io is Indigo's object.

		Not all IOMBase objects have official 'id' values. Notably,	Actions
		do not (currently). Plugin objects quack like IOMBase but are not
		technically a subclass.

		You can create IOMBase for objects of other plugins. Each IOMBase
		has a self.plugin referring to cyin's plugin object for it.
		An object for our own plugin is called local; any other is called foreign.
		The internal details of a foreign object are not currently visible to cyin, even if
		that other plugin is built on cyin.
	"""
	_config_type = 'property'

	UI = ConfigUI
	deleted = False
	configUI = None

	def __init__(self, io):
		self.io = io
		self.description = io.description if io else None
		self._config_level = 1	# ConfigUI running revision level for deferred updates
		self.plugin = plugin_for(io, True)
		if self.local:
			self._typeid = type(self).__name__.lower()
			# pull the ConfigUI XML and save it in a common place. This is also a sanity check
			config = self._configsDict()
			if self._typeid in config:
				self._config = config[self._typeid]
			else:
				error("configuration error: no", self._typeid, "in", self._iom_type, "XML")
				self._config = None

	@property
	def local(self):
		return self.plugin == cyin.plugin
	
	@classmethod
	def canonicalName(cls):
		return cls.__name__.lower()

	def bind(self, name, type):
		""" Return a bound method by name, only if it is tagged with type. """
		if hasattr(self, name):
			method = getattr(self, name)
			if hasattr(method, "_method_type") and getattr(method, "_method_type") == type:
				return method

	def eval_context(self):
		""" Return initial local names in dynamic evaluations for this object. """
		return dict(self=self)

	@classmethod
	def all(cls, filter = lambda _: True):
		""" Iterate over all active instances of this class (including subclasses).

			During startup, this iteration may be incomplete; it only shows
			objects already registered with cyin.
		"""
		for iom in list(_iomap.values()):		# snapshot _iomap - it may change
			if isinstance(iom, cls) and iom.active:
				if filter(iom):
					yield iom

	@classmethod
	def all_attr(cls, form, value=True):
		""" Iterate over all objects of this class whose form(object) == value.
		
			If form is a string, fetch that named attribute (hence the name).
		"""
		if isinstance(form, str):
			filter = lambda dev: getattr(dev, form)
		else:
			filter = form
		return cls.all(lambda i: filter(i) == value)

	@classmethod
	def find_attr(cls, attr, value=True):
		""" Find the one object of this class whose attr(object) == value. Warn for duplicates. """
		try:
			result = None
			gen = cls.all_attr(attr, value)
			result = next(gen)
			next(gen)
			debug("ambiguous find_attr", cls, attr, value)
		except StopIteration:
			pass
		finally:
			return result


#
# Base class of IOM shadow objects that have official Indigo "id" values.
#
class IOM(IOMBase, Observer):
	""" A shadow class for IOM objects that have official handles.

		This specializes IOMBase for objects that have official 'id' values.
		This includes devices and events but not actions. IOM is abstract.
	"""
	config_version = 0

	def __init__(self, io):
		IOMBase.__init__(self, io)
		Observer.__init__(self)
		self.id = io.id
		_iomap[self.id] = self
		self.name = io.name
		self.active = False
		if self.local:
			debug('mapping %s "%s" %d(%s)' % (self._iom_type, self.name, self.id, self._typeid))
		elif self.plugin.ident:
			debug('mapping "%s" %d [%s]' % (self.name, self.id, self.plugin.ident))
		else:
			debug('mapping "%s" %d [built-in %s]' % (self.name, self.id, type(self).__name__))
		self._upgrade_check()

	def filter_clause(self):
		return (self.id, self.name)
	
	@property
	def group_list(self):
		if cyin.plugin.supports("devicegroups"):
			return indigo.device.getGroupList(self.id)
		else:
			return [self.id]

	@property
	def main_device(self):
		groupList = indigo.device.getGroupList(self.id)
		if groupList[0] == self.id:
			return self
		else:
			return device(groupList[0])
	
	@property
	def batteryLevel(self):
		return self.main_device.io.batteryLevel
	
	#
	# Upgrade processing
	#
	def _upgrade_check(self):
		old_version = self.current_config_version()
		new_version = self.config_version
		if new_version > old_version or DEBUG:
			debug(self.name, 'upgrading config from version', old_version, 'to', new_version)
			self._do_upgrade(old_version)

	def _do_upgrade(self, old_version):
		self.upgrade_config(old_version)
		props = self.io.pluginProps
		props['version_'] = self.config_version
		self.io.replacePluginPropsOnServer(props)
	
	def current_config_version(self):
		return self.io.pluginProps.get('version_', 0)

	def __repr__(self):
		return "<IOM%s %d=%s>" % (
			"+" if self.active else "-",
			self.id, self.name
		)


	#
	# Override the following methods for more interesting behavior.
	#
	def start(self):
		pass

	def stop(self):
		pass

	def ready(self):
		""" Is this device ready to be used? Override to make sense for your device. """
		return self.active

	def wants_reset(self):
		""" Might we benefit from an attempt at peremptory restart? """
		return False

	def reconfigure(self):
		""" Default behavior for essential attribute change(s). """
		if self.active:
			self.stop()
		self.start()

	def config_changed(self, changed_attrs):
		pass

	def upgrade_config(self, old_version):
		""" Custom adjustments when upgrading config properties. """
		pass

	def refresh(self):
		self.io.refreshFromServer()

	@classmethod
	def adapt(self, iodict):
		pass

	#
	# Generic property access.
	# Use declared properties whenever possible. This is your fallback.
	#
	@property
	def props(self):
		return self.io.pluginProps
		
	@property
	def globalProps(self):
		return self.io.globalProps
		
	@property
	def ownerProps(self):
		return self.io.ownerProps
	
	def setProperties(self, props):
		propDict = self.props
		propDict.update(props)
		self.io.replacePluginPropsOnServer(propDict)
	
	def setProperty(self, name, value):
		props = self.props
		props[name] = value
		self.setProperties(props)


#
# Features of Device shared with ForeignDevice (which inherits from IOM, not Device).
#
class DeviceFeatures(object):
	
	_prior = None		# temporary store for old value during update notices

	#
	# pass protocol, model, and address through to our io object.
	#
	@property
	def address(self):
		return self.io.address
	
	@property
	def protocol(self):
		return self.io.protocol
		
	@property
	def model(self):
		return self.io.model


	#
	# Many devices have on/off capability, so let's throw this in.
	# This is an active state; assign to switch.
	#
	onOff = DeviceState(type=bool, name="onOffState")

	def turn(self, on, delay=0, duration=0, suppressLogging=False, updateStatesOnly=False):
		if on:
			indigo.device.turnOn(self.id, delay=delay, duration=duration, suppressLogging=suppressLogging, updateStatesOnly=updateStatesOnly)
		else:
			indigo.device.turnOff(self.id, delay=delay, duration=duration, suppressLogging=suppressLogging, updateStatesOnly=updateStatesOnly)
	

	#
	# Access to prior value during update notifications (only)
	#
	@property
	def priorStates(self):
		if self._prior:
			return self._prior.states

	def stateChanged(self, name):
		if self._prior:
			return self.io.states[name] != self._prior.states[name]
		else:
			return True		# by convention, creation or deletion

	
	#
	# pass lastChanged and some variations thereon
	#
	NEVERCHANGED = datetime.datetime(2000, 1, 1, 0, 0)	# what Indigo uses when that was never set
	
	@property
	def lastChanged(self):
		return self.io.lastChanged if self.io.lastChanged != self.NEVERCHANGED else None
	
	@property
	def lastComm(self):
		return self.io.lastSuccessfulComm if self.io.lastSuccessfulComm != self.NEVERCHANGED else None
	
	def secondsSinceLastChanged(self, base=datetime.datetime.now()):
		last = self.lastChanged
		if last:
			dt = base - last
			return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600.0) * 10**6) / 10**6


#
# Base class of all device objects
#
class Device(IOM, DeviceFeatures, metaclass=IOMetaMap, register=False):
	""" IOM shadow class for a plugin-defined device.

		For each custom device in your plugin, define a subclass of Device
		that is named the same as the device's type-id string (capitalization may differ).
	"""
	_iom_type = 'device'

	def _do_upgrade(self, old_version):
		self.reconfigure_state()
		IOM._do_upgrade(self, old_version)

	def eval_context(self):
		return dict(self=self, device=self)

	#
	# State configuration magic.
	# When a device is created, Indigo is fed the static state configuration
	# as written in the device's XML. (Dynamic state generation during creation ConfigUI
	# is essentially broken.) Once the device is live, perhaps in its start() method,
	# you may call reconfigure_state() which will trigger callbacks to your stateList()
	# and stateDisplayField() methods to reconfigure the state data as needed.
	#
	def reconfigure_state(self):
		""" Ask Indigo to re-fetch state information for this device. """
		self.io.stateListOrDisplayStateIdChanged()

	def stateList(self):
		""" Generate dynamic state configuration for this device. """
		return indigo.PluginBase.getDeviceStateList(cyin.plugin, self.io)

	def stateDisplayField(self):
		""" Identify the state field that should be displayed in Indigo's "state" column. """
		return indigo.PluginBase.getDeviceDisplayStateId(cyin.plugin, self.io)


	#
	# Activate (only) all devices of this type
	#
	@classmethod
	def preload(cls):
		me = cls.canonicalName()
		filter = "self" if me == "device" else "self.%s" % me
		for io in indigo.devices.iter(filter):
			cyin.device(io.id)
	
	@staticmethod
	def preloadAll():
		for io in indigo.devices:
			cyin.device(io.id)
	

	#
	# Manage Indigo display features
	#
	def set_display_address(self, value):
		""" Set the address property of this device.

			The device configuration property named 'address' is magic in that
			Indigo has a display column for its value. This method sets the 'address'
			property directly (in the vain hope that perhaps later there'll be a better
			way to do this).
			By convention, any real 'address' property is currently called 'xaddress'.
		"""
		props = self.io.pluginProps
		props['address'] = value
		self.io.replacePluginPropsOnServer(props)

	@staticmethod
	def _configsDict():
		return cyin.plugin.getDevicesDict()


#
# Base class of all trigger objects
#
class Event(IOM, metaclass=IOMetaMap, register=False):
	""" IOM shadow class for a plugin-defined event.

		For each custom event in your plugin, define a subclass of Event.
		For each active custom trigger in the system, an instance of your class will be
		created and started automatically; start/stop will be called as the trigger
		becomes active/inactive.

		Each event subclass defines a matching method that can be used to restrict
		what event triggers qualify. Arbitrary arguments can be passed to this method.
	"""
	_iom_type = 'event'

	@classmethod
	def all_matching(cls, *args, **kwargs):
		""" Iterate over all active events of this type that match the arguments provided. """
		for event in cls.all():
			if event.matches(*args, **kwargs):
				yield event

	@classmethod
	def trigger(cls, *args, **kwargs):
		""" Set off all triggers for this event class that match the arguments provided. """
		for event in cls.all_matching(*args, **kwargs):
			event.trigger_me()

	def trigger_me(self):
		""" Explicitly trigger this one trigger instance (only). """
		indigo.trigger.execute(self.io)

	def matches(self, *args, **kwargs):
		""" By default, match everything. Override this to implement restrictions. """
		return True

	@staticmethod
	def _configsDict():
		return cyin.plugin.getEventsDict()


#
# Base class of all Action objects.
# Actions do not have iom ids, so they're the odd duck out in this game.
# In essence, they're made when needed and tend to be very short-lived.
#
class Action(IOMBase, metaclass=IOMetaMap, register=False):

	_iom_type = 'action'

	def __init__(self, io, dev=None):
		IOMBase.__init__(self, io)
		if not hasattr(self, 'device'):		# has no device attribute
			if not dev:
				if self.io:
					if self.io.deviceId:
						dev = cyin.device(self.io.deviceId)
					elif 'device' in self.io.props:
						dev = cyin.device(self.io.props['device'])
			self.__dict__['device'] = dev	# bypass any descriptor

	def eval_context(self):
		""" Default evaluation context for actions includes self and device. """
		return dict(self=self, device=self.device)

	@staticmethod
	def _configsDict():
		return cyin.plugin.getActionsDict()


#
# Actions with a 'device' property (a common case).
#
class DeviceAction(Action, register=False):
	device = PluginProperty(type=device)


#
# Base class of all plugin objects.
# Note that these are NOT subclasses of indigo.PluginBase.
#
class PluginCore(object):
	""" Either our own plugin or some other one (that may not exist). """
	def __init__(self, ident, name, version):
		self.ident = ident
		self.name = self.description = name
		self.version = version
		_pluginmap[self.ident] = self


#
# A plugin that isn't ours.
#
class ForeignPlugin(PluginCore):
	""" The representation of a plugin other than our own. """
	def __init__(self, id):
		self._plugin = indigo.server.getPlugin(id)
		PluginCore.__init__(self, id,
			self._plugin.pluginDisplayName, self._plugin.pluginVersion)

	@property
	def enabled(self):
		return self._plugin.isEnabled()

	def action(self, id, args={}, device=None):
		dev = device.id if device else 0
		return self._plugin.executeAction(id, dev, args)

	def restart(self, wait=False):
		return self._plugin.restart(not wait)


#
# A "plugin" that represents built-in Indigo facilities
#
class BuiltinPlugin(PluginCore):
	""" A pseudo-plugin for objects managed by Indigo's core. """
	def __init__(self):
		PluginCore.__init__(self, None, "Indigo", indigo.server.version)


#
# A completely fake "iom-alike" class representing a log message.
# The id values are made up to be unique, no more.
#
_logId = 1
_epoch = datetime.datetime(year=1970,month=1,day=1,hour=0,minute=0,second=0)	# unix epoch

class LogMessage(object):
	def __init__(self, args):
		global _logId
		_logId += 1
		self.id = _logId
		self.time = args["TimeStamp"]
		self.type = args["TypeVal"]
		self.typeString = args["TypeStr"]
		self.message = args["Message"]

	@property
	def error(self):
		return self.type == 1
