#
# cyin.devstate - Device objects with state tracking
#
# Devstate offers a series of increasingly detailed canned state models
# that simplify the writing of standard plugin patterns based on cyin.
# They build on each other; the deeper you dive, the less work you have to
# do but the less flexibility remains in your implementation.
#
# Devstate requires asynplugin (for timers, retries, etc. etc.)
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
import socket
import os
import random
import serial

import asyn

import cyin
import cyin.check
from cyin.core import debug, error, log

DEBUG = None


#
# devstate.Device microstate (in self.mstate)
#
OPERATING = ''			# no error
FAILSOFT = 'soft'		# retry setup()
FAILHARD = 'hard'		# hard error (stay down)
STOPPED = 'stopped'		# intentional non-operating


#
# A Device with some useful canned state machinery added.
#
class Device(cyin.Device, asyn.Callable, register=False):
	""" A Device subclass that adds some standardized device state management.

		This Device has a visible "state" state that is an enumerated list of
		strings. Your device XML must say so, and the list must include at least
		the values "preparing" and "unavailable". We also have an invisible
		(to the user) micro-state (mstate) that records soft or hard failure,
		as well as the (default) normal operating state.

		Each Device must successfully transition through start() and then setup()
		to leave the "preparing" state and become operational. If start() fails,
		we (must) fail hard and remain unavailable. If setup() fails, we may fail
		hard (ditto) or soft.

		Soft failure is retried automatically in lengthening intervals by calling
		setup() again. The first retry is immediate, followed by exponentially
		backed off retries, randomized to avoid training. The SOFT_RETRY member
		of your class can be set to (min, max), where retries begin at min seconds
		apart and will not get longer than max.

		Device can track at most one "host device" on which we rely for
		our operation. State changes in the base device are automatically
		tracked and echoed into our state. If the host device resets, so do we
		(even from a hard failure).

		Device is an asyn.Callable. It will callout when it changes state.
		This is how host device state tracking works, and you can hook state
		changes for any other purpose by adding your own callback.
	"""
	state = cyin.DeviceState(type=str)	# required

	SOFT_RETRY = (5, 60)	# seconds to delay (min, max) between soft retries

	_soft_retry = None					# active retry timer

	def __init__(self, io):
		cyin.Device.__init__(self, io)
		asyn.Callable.__init__(self)
		self.mstate = OPERATING			# microstate
		self.hostdev = None				# no host device

	def start(self):
		super(Device, self).start()
		self.reset()

	def stop(self):
		self.state = "unavailable"
		self.mstate = STOPPED			# make unready
		self._cancel_retry()
		self.callout('change', self)	# tell any dependents
		super(Device, self).stop()

	def set_hostdev(self, dev):
		""" Establish our host device. None disable hosting. """
		assert dev != self				# can't host yourself
		if dev != self.hostdev:
			if self.hostdev:
				self.hostdev.remove_callout(self._base_change)
			self.hostdev = dev
			if dev:
				dev.add_callout(self._base_change)
				if dev.state == "unavailable":
					self.fail_hard("host device %s is unavailable" % dev.name)
				return dev.ready()
		return True

	def ready(self):
		""" Have we made it out of "preparing" without failing? """
		return cyin.Device.ready(self) and self.mstate == OPERATING and self.state != "preparing"

	def wants_reset(self):
		return (cyin.Device.ready(self)
			and self.mstate != OPERATING
			and (self.hostdev == None or not self.hostdev.wants_reset()))

	# notifications from our host device (if any) come here
	def _base_change(self, ctx, dev=None):
		if ctx.state == 'change':	# state change notification
			assert dev == self.hostdev
			if dev.ready() and not self.ready():	# base became ready
				debug(self.name, "host device", dev.name, "now available")
				self.start()
			elif dev.mstate in [FAILSOFT, FAILHARD] or dev.state == "unavailable":
				if cyin.plugin.shutting_down:
					self.stop()
				else:
					self.fail_hard("host device %s is unavailable" % dev.name)
		elif ctx.state == 'reset':	# hard reset
			if self.state == "unavailable":
				self.reset()		# ripple the reset

	def reset(self):
		""" (Re)Start state evolution from the beginning. Discards all prior error state. """
		if self.mstate != OPERATING:
			debug(self.name, "reset")
		self.mstate = OPERATING
		self.state = "preparing"
		self._cancel_retry()
		self.callout('reset', self)

	def proceed(self, state, log=None, recovered=False):
		""" Make a visible change to the device's state.

			Does nothing if the new state equals the old one.
			Pass recovered=True if this state change signals successful
			recovery from earlier failure.

			By default, issues a debug-log message indicating the change.
			Pass log= to override the default message; pass log=False to defeat it.
		"""
		if recovered:
			self.mstate = OPERATING
		if state != self.state:
			self.state = state
			if log is None:
				debug(self.name, "is now", self.state)
			elif log != False:
				debug(self.name, log)
			self.callout('change', self)
		self._cancel_retry()

	def fail_soft(self, reason):
		""" Indicate that we can't complete setup().

			Start() has succeeded, and the device is known, but we can't use it
			right now for some reason. The device will be flagged "unavailable".
			The system will periodically retry the setup() call in case things
			have improved.
		"""
		if self.mstate == FAILHARD:		# already hard failed, can't improve
			return
		if self.mstate == FAILSOFT:
			if DEBUG: DEBUG(self.name, "retry still unavailable:", self._reason(reason))
			delay = self._soft_delay
			self._soft_delay = min(1.3 * self._soft_delay, self.SOFT_RETRY[1])
		else:
			self.mstate = FAILSOFT
			self.state = "unavailable"
			error(self.name, "unavailable:", self._reason(reason))
			delay = 0
			self._soft_delay = self.SOFT_RETRY[0]
		if DEBUG: DEBUG(self.name, "retry delay", delay, "next", self._soft_delay)
		self._soft_retry = cyin.plugin.schedule(self._retry_soft, after=delay+random.uniform(0, 0.2))
		self.callout('change', self)

	def _retry_soft(self, ctx):
		if self.deleted:
			return
		self.setup(ctx)

	def fail_hard(self, reason=None):
		""" Indicate that a persistent error condition keeps us from operating.

			This means that something is permanently wrong. The device will be
			flagged "unavailable", and we won't try to do anything with it until
			it's explicitly told to reset for some reason.

			If we have a host device and it resets, we reset with it.
			Note that this happens whether we failed because of it, or for any other reason.
		"""
		if DEBUG: DEBUG(self.name, "fail hard", reason)
		if self.mstate != FAILHARD:
			self.mstate = FAILHARD
			if reason:
				error(self.name, "unavailable:", self._reason(reason))
			self.state = "unavailable"
			self._cancel_retry()
			self.callout('change', self)

	def _reason(self, value):
		""" Distill an explanatory string from a highly polymorphic value. """
		if isinstance(value, asyn.Error):
			value = value.error
		if isinstance(value, Exception):
			value = str(value)
		return value

	def _cancel_retry(self):
		""" Cancel any pending retry timer. """
		if self._soft_retry:
			self._soft_retry.cancel()
			self._soft_retry = None


#
# A devstate.Device with support for IP lookups and connections.
#
class IPDevice(Device):
	""" A devstate.Device with an asynchronous stream to some IP-like source.

		IPDevice is a devstate.Device focused on a (single) stream connection
		to some byte source. That is usually a TCP/IP connection, but optionally
		accommodates a local serial port stream as a backup case.

		Your subclass of IPDevice must have a resolve() method that delivers
		a getaddrinfo resolution vector based on its own configuration (typically
		produced with a call to self.resolve_ip). If a connection to this address
		can be made, your self.connected() method is called with a live socket to it.
		Self.connected must assign some closeable object to self.target. By convention,
		this is the underlying implementation object (typically @property-equivalenced
		to some topical name).

		IPDevice objects must have a "connecting" state enumeration, and often
		have an "exploring" state as well.
	"""
	address = cyin.PluginProperty(name="address", eval=True, check=[cyin.check.check_host(serial=True)])

	target = None
	_connector = None


	#
	# A conventional start/resolve/setup/connect/ready state sequence.
	# You need to provide at least self.resolve() and self.connected(),
	# and remember to pass through start/setup if overridden.
	#
	def start(self):
		super(IPDevice, self).start()
		self.res = self.resolve()
		if self.res:
			self.setup()

	def stop(self):
		if self.target:
			self.target.close()
			self.target = None
		if self._connector:
			self._connector.close()
			self._connector = None
		super(IPDevice, self).stop()

	def setup(self, ctx=None):
		self.connect_ip(self.res)

	def reconnect(self):
		error(self.name, "connection lost - resetting")
		if self.target:
			   self.target.close()
		self.setup()


	#
	# Default name resolution is based on manifest class constants.
	# Override for more detailed control.
	#
	DEFAULT_PORT = None			# no default default port
	SERIAL_CONFIG = None		# no serial option

	def resolve(self):
		def value(s): return s() if callable(s) else s
		return self.resolve_ip(self.address, port=value(self.DEFAULT_PORT), serial_port=value(self.SERIAL_CONFIG))


	#
	# Resolve a hostname/port combo
	#
	def resolve_ip(self, address, port, type=socket.SOCK_STREAM, flags=0, serial_port=None):
		""" Synchronously resolve a name/port and return its resolution list.

			On error, fails and returns None.
		"""
		if address.startswith('/'):		# serial device
			if not serial_port:
				raise TypeError("Serial port address not supported")
			try:
				serial.Serial(address, timeout=0, **serial_port).close()
				return (address, serial_port)
			except Exception as e:
				self.fail_hard(str(e))
		else:
			try:
				address, _, cport = address.partition(':')
				return socket.getaddrinfo(address, cport or port, 0, type, 0, socket.AI_CANONNAME | flags)
			except socket.gaierror as e:
				if e[0] == socket.EAI_NONAME:
					self.fail_hard("cannot find %s" % address)
				else:
					self.fail_hard(e[1])

	#
	# Connect to a (tcp) target based on a resolution list
	#
	def connect_ip(self, res):
		""" Connect to a TCP target. Either calls self.connected, or fails the object. """

		if isinstance(res, tuple):
			address, serial_port = res
			self.proceed("connecting", log="connecting to serial port %s" % address)
			try:
				fd = serial.Serial(address, timeout=0, **serial_port)
				return self.connected(fd)
			except Exception as e:
				return self.fail_soft(str(e))

		def complete(ctx, socket=None):
			""" Connection attempt complete (one way or another). """
			if ctx.error:
				if asyn.resolve.transient_error(ctx.error):
					self.fail_soft(ctx.error)
				else:
					self.fail_hard(ctx.error)
				return
			if ctx.state == 'CANCELLED':	# we're going to die
				return
			self._connector = None	# done with it
			self.connected(socket)

		self.proceed("connecting", log="connecting to %s" % (res[0][3] or "host"))
		self._connector = cyin.plugin.connector(self.res, callout=complete)

	#
	# Exclude "connecting" and "exploring" from ready state
	#
	def ready(self):
		return super(IPDevice, self).ready() and self.state != "connecting" and self.state != "exploring"


#
# A Mix-in that automates conventional Idler logic.
#
class Idler(object, metaclass=cyin.iom.Device.__class__, register=False):

	_config_type = cyin.iom.Device._config_type

	keepalive = cyin.PluginProperty(type=bool, required=False, reconfigure='notify')

	# be sure to chain to this if you override
	def config_changed(self, fields):
		if 'keepalive' in fields:
			self.idle_update()

	def idle_update(self):
		if self.keepalive:
			debug(self.name, "enabling idle probes")
			self.target.idle_set()
		else:
			self.target.idle_cancel()

	def idle_cancel(self):
		if self.target:
			self.target.idle_cancel()


#
# A devstate sub-Device.
#
class SubDevice(Device):
	""" A devstate.Device that acts as a subsidiary to another devstate.Device.

		A SubDevice has a property "xaddress" of the form hostid@subaddress.
		The connection to the host device is automatically maintained, and the
		subaddress deposited in the self.subaddress property.
	"""
	address = cyin.PluginProperty(name='xaddress')

	PARTNAME = 'device'		# name of sub-device used by default implementations

	def start(self):
		super(SubDevice, self).start()
		if '@' not in self.address:		# not subaddress format - pass to subclass
			return self.setup()
		hostid, subaddr = self.address.split('@', 2)
		self.set_hostdev(cyin.device(int(hostid)))
		assert self.hostdev
		self.subaddress = subaddr
		self.set_subaddress(subaddr)	# may override type etc.
		self.set_display_address("%s %s %s" % (self.hostdev.name, self.PARTNAME, self.subaddress))
		self.setProperties({
			"hostdev": self.hostdev.id,
			"subaddress": self.subaddress,
		})
		if self.hostdev.ready():
			self.setup()

	#
	# Override this to control how the subaddress is set.
	# May also call set_display_address to override the display address string.
	#
	def set_subaddress(self, subaddr):
		pass

	@classmethod
	def subfilter_clause(cls, hostdev, subaddr):
		return (
			"%d@%s" % (hostdev.id, subaddr),
			"%s %s %s" % (hostdev.name, cls.PARTNAME, subaddr)
		)
