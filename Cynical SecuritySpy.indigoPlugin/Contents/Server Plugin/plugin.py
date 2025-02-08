#
# SecuritySpy plugin interface to Indigo 5
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
from distutils.version import StrictVersion
import time

import asyn
import asyn.scan
import cyin
import cyin.asynplugin
import cyin.devstate
import spy
from spy import ARM_MOTION, ARM_CONTINUOUS, ARM_ACTIONS
from cyin import log, debug, error
from cyin.asynplugin import action
from cyin.check import *


#
# We need SecuritySpy's event tap, which was added in 2.1.1
#
REQUIRED_VERSION = StrictVersion('2.1.1')


#
# Trigger reason codes delivered by 'trigger' events and how to present them to the user.
#
DETECTION_REASONS = [
	("any",			"Anything"),
	("human",		"Human detected in camera picture"),
	("vehicle",		"Vehicle detected in camera picture"),
	("motion",		"Other motion in camera picture"),
	("manual",		"Triggered manually"),
	("audio",		"Sound detected"),
	("applescript",	"Triggered by Applescript"),
	("camera",		"Reported by camera"),
	("crosscamera",	"Triggered by another camera"),
	("web",			"Triggered via web interface"),
]


#
# A SecuritySpy server installation
#
class Server(cyin.devstate.Device):
	""" A SecuritySpy server somewhere.

		We talk to SecuritySpy through its http interface ONLY. This means we can cross
		IP networks without extra effort.
	"""
	address = cyin.PluginProperty(required=False, check=[check_host])
	port = cyin.PluginProperty(check=[check_port])
	username = cyin.PluginProperty(required=False, eval=True)
	password = cyin.PluginProperty(required=False, eval=True)
	errors = cyin.PluginProperty(type=bool, reconfigure=False)

	version = cyin.DeviceState()

	def start(self):
		self.spy = None
		self.reset()
		self.setup()

	def setup(self, ctx=None):
		self.spy = spy.SecuritySpy(cyin.plugin,
			self.address or "localhost", self.port,
			user=self.username or None, password=self.password or None,
			callout=self._event)
		self.spy.debugtag = self.name	# for better DEBUG output

	def stop(self):
		cyin.devstate.Device.stop(self)
		if self.spy:
			self.spy.close()
			self.spy = None

	def update(self):
		self.spy.update()

	def _event(self, ctx, data=None):
		if ctx.error:
			if isinstance(ctx.error, asyn.http.StatusError):
				if ctx.error.n_status == 404:
					# unrecognized request - assume missing ++systemInfo (pre-2.1)
					return self.fail_hard("SecuritySpy version %s or later is required" % REQUIRED_VERSION)
			if asyn.resolve.transient_error(ctx.error):
				return self.fail_soft(ctx.error)
			return self.fail_hard(ctx.error)
		if self.active and ctx.state == 'ready':	# full status report from SecuritySpy
			self.version = self.spy.version
			if REQUIRED_VERSION > self.version:
				self.fail_hard("version %s not supported - you need %s or later"
					% (self.version, REQUIRED_VERSION))
			else:
				self.proceed("ready", recovered=True)
		if ctx.state == 'event tap':
			if data == '200':
				debug(self.name, "event tap active")
			elif data == '401' and self.username:
				error("event tap refused - make sure user \"%s\" has access to general settings" % self.username)
			else:
				self.fail_hard("event tap failed (http %s)" % data)

	def display_address(self):
		return "%s:%s" % (self.address or "localhost", self.port)

	@action
	def restart_server(self, action):
		self.spy.restart_server()

	@action
	def run_script(self, action):
		self.spy.run_script(action.name)

	@action
	def play_sound(self, action):
		self.spy.play_sound(action.name)

	@classmethod
	def all_spy_cameras(cls):
		""" iterate all (our server device, spy's camera object on it). """
		for server in sorted(Server.all(), key=lambda s: s.name):
			if server.ready():
				for camera in sorted(server.spy.cameras.values(), key=lambda c: c.name):
					yield (server, camera)

	@classmethod
	def find_camera(cls, ident):
		for spy in cls.all():
			if spy.ready():
				camera = spy.spy.find_camera(m.group(1))
				if not camera:
					continue
				return Camera.find_attr(lambda c: c.camera, camera)


#
# A single Camera (not device) on a SecuritySpy server
#
class Camera(cyin.devstate.SubDevice):
	""" A camera device managed by SecuritySpy.
	"""
	type = cyin.DeviceState()
	sensitivity = cyin.DeviceState(type=int)
	width = cyin.DeviceState(type=int)
	height = cyin.DeviceState(type=int)
	recording = cyin.DeviceState(type=bool)
	motion = cyin.DeviceState(type=bool)
	actions = cyin.DeviceState(type=bool)
	
	config_version = 3		# SecuritySpy 4; add width/height

	spy_camera = None

	PARTNAME = "camera"

	def setup(self, ctx=None, update=False):
		number = int(self.subaddress)
		if number not in self.hostdev.spy.cameras:
			return self.fail_hard("no camera #%d in %s" % (number, self.hostdev.name))
		self.spy_camera = self.hostdev.spy.cameras[number]
		if not update:
			self.spy_camera.add_callout(self._event)
		self.proceed(self._state(), recovered=True)
		self.type = "%s %s" % (self.spy_camera.type, self.spy_camera.device)
		self.sensitivity = self.spy_camera.sensitivity
		self.width = self.spy_camera.size[0]
		self.height = self.spy_camera.size[1]
		self.recording = self.spy_camera.armed[ARM_CONTINUOUS]
		self.motion = self.spy_camera.armed[ARM_MOTION]
		self.actions = self.spy_camera.armed[ARM_ACTIONS]
		self.set_display_address("%s (%d)" % (self.spy_camera.name, number))

	def stop(self):
		if self.spy_camera:
			self.spy_camera.remove_callout(self._event)
			self.spy_camera = None
		super(Camera, self).stop()

	def _event(self, ctx, *args):
		if ctx.error:
			self.fail_hard(ctx.error)
		elif ctx.state == 'motion':		# SecuritySpy 4- ("classic"), only motion detect
			CameraMotion.trigger(self, 'raw', {})
			CameraMotion.trigger(self, 'recording', ['motion'])
		elif ctx.state == 'trigger':	# SecuritySpy 5+ ("AI") trigger report
			CameraMotion.trigger(self, args[0], args[1])
		elif ctx.state == 'classify':	# SecuritySpy 5+ ("AI") classifier output
			CameraMotion.trigger(self, 'raw', args[0])
		elif ctx.state == 'error':
			if self.hostdev.errors:
				error(self.name, *args)
		elif ctx.state == 'removed':
			self.fail_hard("SecuritySpy camera has been deleted")
		else:
			self.setup(update=True)	# pick up any changes

	def _state(self):
		if self.spy_camera is None:
			return "error"
		if self.spy_camera.connected:
			if self.spy_camera.armed[ARM_MOTION]:
				return "active"
			else:
				return "passive"
		else:
			return "disconnected"

	def update(self):
		self.spy_camera.update()

	#
	# Old suite of active/passive/toggle commands now manipulate (only) the motion arm state
	#
	@action
	def set_active(self, action):
		self.spy_camera.set_active(True)

	@action
	def set_passive(self, action):
		self.spy_camera.set_active(False)

	@action
	def toggle_active(self, action):
		self.spy_camera.set_active(not self.spy_camera.armed[ARM_MOTION])

	#
	# New, unified arming control action
	#
	@action
	def set_arm(self, action):
		value = not self.spy_camera.armed[action.type] if action.value == 'toggle' else (action.value == 'arm')
		self.spy_camera.set_arm(action.type, value)


	#
	# More direct commands
	#
	@action
	def trigger_recording(self, action):
		self.spy_camera.trigger_motion()

	@action
	def set_overlay(self, action):
		self.spy_camera.set_overlay(action.text, action.pointsize, action.position)

	@action
	def set_sensitivity(self, action):
		self.spy_camera.set_sensitivity(action.sensitivity)

	@action
	def ptz_motion(self, action):
		self.spy_camera.ptz_action(action.motion)

	@action
	def ptz_preset(self, action):
		command = action.preset
		if action.save:
			command += str(int(command) + 100)
		self.spy_camera.ptz_action(command)


#
# Actions
#
class RestartServer(cyin.Action):
	pass

class RunScript(cyin.Action):
	name = cyin.PluginProperty(eval=True)

class PlaySound(cyin.Action):
	name = cyin.PluginProperty(eval=True)

class SetActive(cyin.Action):
	pass

class SetPassive(cyin.Action):
	pass

class ToggleActive(cyin.Action):
	pass

class Arm(cyin.Action):
	type = cyin.PluginProperty(type=str, eval=True)
	value = cyin.PluginProperty(type=str)

class Record(cyin.Action):
	pass

class SetOverlay(cyin.Action):
	text = cyin.PluginProperty(required=False, eval=True)
	pointsize = cyin.PluginProperty(type=int, eval=True, check=[check_int(min=6)])
	position = cyin.PluginProperty()

class SetSensitivity(cyin.Action):
	sensitivity = cyin.PluginProperty(type=int, eval=True, check=[check_int(min=0, max=100)])

class PTZMotion(cyin.Action):
	motion = cyin.PluginProperty(eval=True)

class PTZPreset(cyin.Action):
	preset = cyin.PluginProperty(eval=True)
	save = cyin.PluginProperty(type=bool)


#
# Events
#
class CameraMotion(cyin.Event):
	""" Event: SecuritySpy is signaling motion on a camera.

		All triggers for a given camera fire when SecuritySpy tells us about motion
		on that camera. However, each trigger can set a separate rate throttle to
		reduce the trigger frequency on continuous bursts of motion. We implement that
		(cheesily) by simply keeping the last-time-matched as an attribute.
		As of SecuritySpy 5, you can choose between motion-detect triggers, action triggers,
		or "raw" triggers specifying image recognition. Earlier versions are mapped to
		motion-detect triggers (with "any" reason).
	"""
	camera = cyin.PluginProperty(type=cyin.device)
	throttle = cyin.PluginProperty(type=int, check=[check_int(min=1)])
	type = cyin.PluginProperty(type=str)
	# conditional for cooked detection types
	trigger_reason = cyin.PluginProperty(type=str, name='reason', required=False)
	# conditional for raw detection types
	recognition_type = cyin.PluginProperty(type=str, name='recogtype')
	recognition_threshold = cyin.PluginProperty(type=int, name='threshold', check=[check_int(min=0,max=100)])
	recognition_negate = cyin.PluginProperty(type=bool, name='negate')

	config_version = 3		# SecuritySpy 5+ image recognition settings

	last_motion = None
	
	def upgrade_config(self, old_version):
		if old_version < 3:
			self.type = 'recording'
			self.trigger_reason = 'any'

	def matches(self, camera, type, *args):
		if self.camera:
			if self.camera != camera:
				return False
		if self.type != type:
			return False
		if type in ['recording', 'action']:
			reasons = args[0]
			# optionally filter by trigger reason
			if self.trigger_reason and self.trigger_reason != 'any' and self.trigger_reason not in reasons:
				return False
		elif type == 'raw':
			# optionally filter by recognition type and threshold. Default is SecuritySpy settings
			recognized, = args	# dict(type: strength)
			if self.recognition_type != 'raw':
				strength = recognized.get(self.recognition_type) or 0
				accept = strength >= self.recognition_threshold
				if accept == self.recognition_negate:
					return False
			
		# defer to throttle interval only for otherwise deliverable events
		now = time.time()
		if self.last_motion and self.last_motion + self.throttle > now:
			return False				# too close since last motion
		self.last_motion = now			# set mark
		return True


#
# Menu generators
#
class CameraFilter(cyin.MenuFilter):
	def evaluate(self):
		""" UI Filter: (server-object, spy-camera) pairs. """
		return [("%d@%s" % (server.id, camera.number), "%s @ %s" % (server.name, camera.name))
			for (server, camera) in Server.all_spy_cameras()]

class PTZFilter(cyin.MenuFilter):
	def evaluate(self):
		""" UI Filter: cameras whose PTZ capabilities include (filter) bits. """
		ptz_bits = int(self.filter)
		return [(camera.id, "%s @ %s" % (camera.hostdev.name, camera.name))
			for camera in sorted(Camera.all(), key=lambda c: (c.hostdev.name, c.name))
			if camera.spy_camera and (camera.spy_camera.ptz_capabilities & ptz_bits)]

class ServerObjectFilter(cyin.MenuFilter):
	def evaluate(self):
		""" UI Filter: List of spy server objects (scripts, sounds, ...). Servers and their actions only. """
		server = self.ui.iom.device
		if server:
			getter = getattr(server.spy, self.filter)
			return [(it, it.partition('.')[0]) for it in getter()]
			
class TriggerReasonFilter(cyin.MenuFilter):
	def evaluate(self):
		""" UI Filter: (detection code, human description) pairs. """
		return DETECTION_REASONS


#
# The plugin
#
class Plugin(cyin.asynplugin.Plugin):
	pass
