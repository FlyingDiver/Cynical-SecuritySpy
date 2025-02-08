#
# cyin.stdaction - action classes representing Indigo-defined standard actions
#
# These are actions defined by Indigo and delivered to manipulate standard-pattern
# devices such as relays and thermostats. Indigo delivers those by calling yet more
# predefined methods on the plugin object, delivering action classes with ad-hoc
# named content. The classes in this file wrap Action and dispatch requests to
# well-named methods on device objects.
#
# At present, these Action subclasses are only instantiated by the plugin wrapper,
# and are thus an implementation detail of cyin.
#
# Copyright 2013-2016 Perry The Cynic. All rights reserved.
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

from cyin import iom
from cyin.core import debug, error, log


#
# The base class of standard Indigo-defined actions
#
class _StandardAction(iom.Action):

	def __init__(self, io, action):
		iom.Action.__init__(self, io)
		self.action = action

	def do(self, name, complaint, *args):
		if not self.device.ready():
			return error(self.device.name, "ignoring", complaint, "request because the device is not ready")
		method = self.device.bind(name, "action")
		if method:
			method(*args)
		else:
			error(self.device.name, "cannot", complaint)


#
# Standard Action subclasses for predefined actions
#
class UniversalAction(_StandardAction):

	def __init__(self, io):
		_StandardAction.__init__(self, io, io.deviceAction)

	def dispatch(self):
		do = self.do
		if self.action == indigo.kDeviceAction.RequestStatus:
			do("standard_status", "get status")
		# there's more here - power status, beep, etc.
		else:
			error(self.device.name, "has no support to", self.action)


# ControlAction should really be called DeviceAction, but we're pervasively using that name elsewhere
class ControlAction(_StandardAction, register="deviceAction"):

	def __init__(self, io):
		_StandardAction.__init__(self, io, io.deviceAction)

	def dispatch(self):
		do = self.do
		if self.action == indigo.kDeviceAction.TurnOn:
			do("standard_switch", "switch on", True)
		elif self.action == indigo.kDeviceAction.TurnOff:
			do("standard_switch", "switch on", False)
		elif self.action == indigo.kDeviceAction.Toggle:
			do("standard_toggle", "toggle")
		elif self.action == indigo.kDeviceAction.SetBrightness:
			do("standard_brightness", "set brightness", self.io.actionValue)
		elif self.action == indigo.kDeviceAction.BrightenBy:
			do("standard_brighten", "brighten", self.io.actionValue)
		elif self.action == indigo.kDeviceAction.SetBrightness:
			do("standard_brighten", "dim", -self.io.actionValue)
		elif self.action == indigo.kDeviceAction.RequestStatus:
			do("standard_status", "get status")
		else:
			error(self.device.name, "has no support to", self.action)


class SensorAction(_StandardAction):

	def __init__(self, io):
		_StandardAction.__init__(self, io, io.sensorAction)

	def dispatch(self):
		if self.action == indigo.kSensorAction.RequestStatus:
			self.do("standard_status", "get status")
		# add energy-management actions here
		else:
			error(self.device.name, "has no support for", self.action)


class ThermostatAction(_StandardAction):

	def __init__(self, io):
		_StandardAction.__init__(self, io, io.thermostatAction)

	def dispatch(self):
		debug("dispatch thermostat", self.action, self.io, self.io.actionValue)
		if self.action == indigo.kThermostatAction.SetHvacMode:
			self.do("standard_hvac_mode", "set the HVAC mode", self.io.actionMode)
		elif self.action == indigo.kThermostatAction.SetFanMode:
			self.do("standard_hvac_fanmode", "set the fan mode", self.io.actionMode)
		elif self.action == indigo.kThermostatAction.SetCoolSetpoint:
			self.do("standard_set_coolpoint", "change the cool setpoint", self.io.actionValue)
		elif self.action == indigo.kThermostatAction.SetHeatSetpoint:
			self.do("standard_set_heatpoint", "change the heat setpoint", self.io.actionValue)
		elif self.action == indigo.kThermostatAction.IncreaseCoolSetpoint:
			self.do("standard_move_coolpoint", "change the cool setpoint", self.io.actionValue)
		elif self.action == indigo.kThermostatAction.DecreaseCoolSetpoint:
			self.do("standard_move_coolpoint", "change the cool setpoint", -self.io.actionValue)
		elif self.action == indigo.kThermostatAction.IncreaseHeatSetpoint:
			self.do("standard_move_heatpoint", "change the heat setpoint", self.io.actionValue)
		elif self.action == indigo.kThermostatAction.DecreaseHeatSetpoint:
			self.do("standard_move_heatpoint", "change the heat setpoint", -self.io.actionValue)
		elif self.action in [indigo.kThermostatAction.RequestStatusAll,
				indigo.kThermostatAction.RequestMode,
				indigo.kThermostatAction.RequestEquipmentState,
				indigo.kThermostatAction.RequestTemperatures,
				indigo.kThermostatAction.RequestHumidities,
				indigo.kThermostatAction.RequestDeadbands,
				indigo.kThermostatAction.RequestSetpoints]:
			self.do("standard_hvac_status", "make HVAC status requests")
		else:
			error(self.device.name, "has no support for", self.action)


class SprinklerAction(_StandardAction):
	pass
