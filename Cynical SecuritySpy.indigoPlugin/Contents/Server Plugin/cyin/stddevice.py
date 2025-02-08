#
# cyin.stddevice - cyin device objects for foreign objects.
#
# The builtinObject function creates cyin wrappers for Indigo iom objects
# that do not belong to our plugin - they belong either to another plugin
# or are built-in. This is currently quite adhoc and unsystematic.
# Everything produced here is a subclass of ForeignIOM.
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
import indigo
import cyin
import cyin.iom
from cyin.core import debug, error, log


#
# A foreign IOM object - an IOM managed by another plugin or built-in.
#
class ForeignDevice(cyin.iom.IOM, cyin.iom.DeviceFeatures):
	""" A device object that isn't one of ours.
	
		Note that this isn't an iom.Device; it's an iom.IOM.
	"""
	_descmap = {}	# placebo


	#
	# Mostly for the sake of plug-in expressions, interprete anything undefined as a state
	#
	def __getitem__(self, name):
		self.refresh()
		if name in self.io.states:
			return self.io.states[name]
		error(f'ForeignDevice {self} of type {type(self).__name__} has no property "{name}"')
		raise KeyError
	__getattr__ = __getitem__


#
# A dummy placeholder for foreign triggers
#
class ForeignTrigger(cyin.iom.IOM):
	""" A trigger object that isn't one of ours. Stubbed out for now. """
	_descmap = {}	# placebo


#
# A foreign device with an INSTEON address
#
class InsteonDevice(ForeignDevice):

	def sendRaw(self, cmd, waitUntilAck=False, waitForStandardReply=False, waitForExtendedReply=False, suppressLogging=True):
		return indigo.insteon.sendRaw(self.address, cmd,
			waitUntilAck=waitUntilAck, waitForStandardReply=waitForStandardReply, waitForExtendedReply=waitForExtendedReply,
			suppressLogging=suppressLogging and not cyin.DEBUG)
	
	#
	# Lookup by INSTEON address
	#
	@classmethod
	def findAddress(self, address):
		for io in indigo.devices.itervalues(filter="indigo.insteon"):
			if io.address == address:
				return cyin.device(io.id)


#
# A KeypadLinc device.
# Technically, this could serve any INSTEON device with multiple lit buttons,
# but in practice this is pretty unique functionality.
#
class KPLDevice(InsteonDevice):

	_ledConfig = None

	def __init__(self, io):
		super(KPLDevice, self).__init__(io)
		model = io.model.lower()
		if 'dimmer' in model:
			self.commands = indigo.dimmer
		elif 'relay' in model:
			self.commands = indigo.relay
		else:
			error(self.name, "unrecognized type of KeypadLinc -", io.model)
			self.commands = indigo.relay	# hope & pray

	_buttonConfig = None
	def buttonConfiguration(self):
		if self._buttonConfig is None:
			reply = self.sendRaw([0x1F, 0x00], waitUntilAck=True)
			if reply.cmdSuccess:
				if (reply.ackValue & 0x08):
					self._buttonConfig = 8
				else:
					self._buttonConfig = 6
		return self._buttonConfig
	
	#
	# LED management
	#
	def canSetLed(self, ledno):
		""" True if LED #ledno can be changed. LEDs are numbered starting with 1. """
		return ledno <= len(self.ledConfig) and self.ledConfig[ledno-1]

	def getLed(self, button):
		self.io.refreshFromServer()
		return self.io.ledStates[button-1]

	def setLed(self, button, value, **kwargs):
		self.commands.setLedState(self.io.id, button-1, value, **kwargs)

	@property
	def ledConfig(self):
		config = self.buttonConfiguration()
		if config == 8:		# all but #1
			return [False, True, True, True, True, True, True, True]
		elif config == 6:	# only the middle quad
			return [False, False, True, True, True, True, False, False]
		else:				# failed; offer them all (we'll try again next time)
			return [True, True, True, True, True, True, True, True]


#
# An IOLinc device.
# We make this look as much like a relay/sensor combo as we can.
#
class IOLincDevice(InsteonDevice):
	
	binaryInput1 = cyin.DeviceState(type=bool, name="binaryInput1")
	binaryOutput1 = cyin.DeviceState(type=bool, name="binaryOutput1")
	onOff = binaryInput1

	# simulated turn(on) command commanding digital output 0
	def turn(self, on, suppressLogging=False, updateStatesOnly=False):
		indigo.iodevice.setBinaryOutput(self.io, index=0, value=on, suppressLogging=suppressLogging, updateStatesOnly=updateStatesOnly)


#
# Take a good look at an iom (not one of ours) and see what
# useful representation we can make.
#
def builtinObject(io):
	if isinstance(io, indigo.Trigger):
		return ForeignTrigger(io)
	assert isinstance(io, indigo.Device)
	if io.model == "I/O-Linc Controller":
		return IOLincDevice(io)
	elif io.protocol == indigo.kProtocol.Insteon and io.model.startswith("KeypadLinc "):		# cheesy
		return KPLDevice(io)
	elif io.protocol == indigo.kProtocol.Insteon:
		return InsteonDevice(io)
	else:
		return ForeignDevice(io)
