from __future__ import print_function
#
# spy.core - Core interface to SecuritySpy
#
# Copyright 2011-2016,2019 Perry The Cynic. All rights reserved.
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
import urllib.parse
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
from distutils.version import StrictVersion
import re

import asyn
import asyn.http

import spy

DEBUG = None


V3_VERSION = StrictVersion("3.0")
BBVS_PARSE = re.compile('BBVS/([0-9.]+)')


# arm states
ARM_MOTION =		'MotionCapture'		# enable motion recording
ARM_CONTINUOUS =	'ContinuousCapture'	# enable continuous recording
ARM_ACTIONS =		'Actions'			# enable action execution

# map change report codes to states
ARM_REPORTS = {
	'M': ARM_MOTION,
	'C': ARM_CONTINUOUS,
	'A': ARM_ACTIONS
}

# trigger types
TRIGGER_TYPES = {
	'M': 'recording',
	'A': 'action'
}

# motion report codes (translated to string sets)
MOTION_CODES = {
	1: "motion",
	2: "audio",
	4: "applescript",
	8: "camera",
	16: "web",
	32: "crosscamera",
	64: "manual",
	128: "human",
	256: "vehicle",
}

def motions(codes):
	return set([MOTION_CODES[code] for code in MOTION_CODES.keys() if code & codes] or ["motion"])

# CLASSIFY arguments turned into a dictionary
def classify(form):
	s = form.split()
	return {key.lower(): int(value) for (key, value) in zip(s[0::2], s[1::2])}


#
# Little helpers for processing SecuritySpy's ++systemInfo XML output
#
def get(elem, name):
	e = elem.find(name)
	return None if e is None else e.text
def iget(elem, name):
	s = get(elem, name)
	return None if s is None else int(s)
def bget(elem, name, true='yes'):
	return get(elem, name) == true


#
# An Exception subclass for sending problems through callouts
#
class Error(Exception):
	pass


#
# Context for one SecuritySpy server installation.
#
class SecuritySpy(asyn.Callable):
	""" Interface to one SecuritySpy server.

		Given a hostname and (web service) port number, this class contacts
		the SecuritySpy server there, collects information on all cameras on
		that server, and lets you manipulate them in interesting ways.
	"""
	def __init__(self, control, host=None, webport=8000, callout=None, user=None, password=None):
		asyn.Callable.__init__(self, callout=callout)
		self.control = control
		self.cameras = None
		self._events = None
		self._lists = { }
		self._auth = None
		if user and password:
			self._auth = asyn.http.BasicAuth(user, password)
		self.debugtag = hex(id(self))	# to distinguish log messages
		if host:
			self.open(host, webport)

	def open(self, host, webport=8000):
		""" Contact the server at the host/port given and start discovery. """
		self.close()
		self.host = host
		self.webport = webport
		self.cameras = { }
		self.update()

	def close(self):
		if self._events:
			self._events.close()
			self._events = None

	def update(self):
		""" Fetch SecuritySpy's configuration and update state accordingly. """
		def reply(ctx, arg=None):
			if ctx.error:
				return self.callout(ctx)
			if ctx.state == 'headers':
				# certain V4 features are gated on the Server: version
				server = arg["Server"]
				m = BBVS_PARSE.match(server)
				if not m:
					return self.callout_error(Error("unrecognized server version - %s") % server)
				self.webversion = float(m.group(1))
			if ctx.state == 'body':
				if req.n_status == '200':
					self._configure(arg)
				else:
					self.callout_error(asyn.http.StatusError(req.n_status, req.v_status))
		req = self._request("/++systemInfo", callout=reply)

	def restart_server(self):
		""" Request that the web server be restarted. """
		self._request("/++ssControlRestartWebServer")

	def run_script(self, scriptname):
		""" Request SecuritySpy run a script from its scripts folder. """
		self._request("/++doScript", query={'name': scriptname}) # no reply

	def play_sound(self, soundname):
		""" Request SecuritySpy play a sound from its sound list. """
		self._request("/++doSound", query={'name': soundname}) # no reply

	def scripts(self):
		return self._lists['scripts']

	def sounds(self):
		return self._lists['sounds']


	def find_camera(self, ident):
		""" Retrieve a Camera by number (int) or name (basestring). """
		if isinstance(ident, int):
			return self.cameras.get(ident)
		elif isinstance(ident, basestring):
			for camera in self.cameras.values():
				if camera.name == ident:
					return camera

	def _configure(self, system_info):
		try:
			system = ET.fromstring(system_info)
		except ExpatError as e:
			self.callout_error(e)
			return
		server = system.find('server')
		self.server = get(server, 'name')
		self.version = get(server, 'version')
		sync_seq = iget(server, 'eventstreamcount')
		# install event tap if possible
		if not self._events:		# not live connected
			self._event_stream()
			self._fetch_list('scripts')
			self._fetch_list('sounds')
		# update camera set
		old_cameras = dict(self.cameras)	# check-off copy
		for elem in system.find('cameralist'):
			camera = Camera(elem, self)
			if camera.number in self.cameras:
				self.cameras[camera.number]._refresh(camera)
				del old_cameras[camera.number]
			else:
				self.cameras[camera.number] = camera
				self.callout('added', camera)
		for cnum in old_cameras:			# deal with cameras that disappeared
			old_cameras[cnum].callout('removed')
			del self.cameras[cnum]
		self.callout('ready', self.cameras)

	_RE_FILELIST = re.compile(r'<a href=.*?>([^<]+)</a>')
	def _fetch_list(self, name):
		def reply(ctx, arg=None):
			if ctx.state == 'body':
				self._lists[name] = self._RE_FILELIST.findall(str(arg, 'utf-8'))
				self.callout('list available', name)
		req = self._request("/++%s" % name, callout=reply)

	_SCAN_EVENT_TAP = asyn.scan.Regex([
		# common messages
		(r'(\d+) (\d+) (?:CAM)?(\d+) MOTION\r', 'motion'),					# v4-
		(r'(\d+) (\d+) (?:CAM)?(\d+) TRIGGER_([MA]) ([0-9]+)\r', 'trigger'),	# v5+
		(r'(\d+) (\d+) (?:CAM)?(\d+) CLASSIFY ([^\r]*)\r', 'classify'),
		(r'(\d+) (\d+) (?:CAM)?(\d+) ONLINE\r', 'online'),
		(r'(\d+) (\d+) (?:CAM)?(\d+) OFFLINE\r', 'offline'),
		(r'(\d+) (\d+) ([^ ]+ )?CONFIGCHANGE\r', 'change'),
		(r'(\d+) (\d+) (?:CAM)?(\d+) ERROR ([^\r]*)\r', 'error'),
		
		# version 3 reports "active" and "passive"; we'll map that to ARM_M (motion)
		(r'(\d+) (\d+) (?:CAM)?(\d+) ACTIVE\r', 'active'),
		(r'(\d+) (\d+) (?:CAM)?(\d+) PASSIVE\r', 'passive'),

		# version 4 has three arming types for each camera
		(r'(\d+) (\d+) (?:CAM)?(\d+) ARM_(\w+)\r', 'arm'),
		(r'(\d+) (\d+) (?:CAM)?(\d+) DISARM_(\w+)\r', 'disarm'),
		
		# new event or bug
		(r'([^\r]*)\r', 'unknown')
	])

	def _event_stream(self):
		""" Open an HTTP channel to SecuritySpy, read event records, and dispatch them.

			This is a "keep open" request; if the server closes, we re-execute the request.
			++eventStream requires version 2.1.1 of SecuritySpy.
		"""
		def reply(ctx, *args):
			if ctx.error:
				self._close_events()
				return self.callout(ctx)
			if ctx.state == 'headers':
				self.callout('event tap', req.n_status)
				if req.n_status == '200':
					req.scan = self._SCAN_EVENT_TAP
				else:
					self._close_events()
					self.callout(asyn.http.StatusError(req.n_status, req.v_status))
			elif ctx.state == 'body':
				# http signals end of body - restart the tap
				self._close_events()
				self._event_stream()
			elif ctx.scan == self._SCAN_EVENT_TAP:
				if DEBUG: DEBUG('TAP:', self.debugtag, ctx.state, *args)
				if ctx.state == 'unknown':
					self.callout_error(Error("unknown event tap (%s)" % args))
				elif ctx.state == 'change':
					if DEBUG: DEBUG("CONFIGCHANGE", args)
					self.update()
				else:
					ctx.spy_ts = args[0]
					ctx.spy_seq = int(args[1])
					cnum = int(args[2])
					if cnum not in self.cameras:
						# can't handle now; trigger config update
						self.update()
					else:
						camera = self.cameras[cnum]
						self.cameras[cnum]._event_tap(ctx, *args[3:])
		self._events = req = self._request("/++eventStream?version=2", callout=reply)

	def _close_events(self):
		if self._events:
			self._events.close()
			self._events = None


	#
	# Web interface primitives
	#
	def _request(self, req, callout=None, action='GET', query=None):
		""" Send a web request to SecuritySpy. """
		return asyn.http.request(self.control, self._weburl(req),
			callout=callout, action=action, query=query, auth=self._auth)

	def _weburl(self, path):
		return urllib.parse.urlunsplit(('http', f'{self.host}:{self.webport}', path, None, None))


#
# One Camera as presented by a SecuritySpy installation somewhere.
#
class Camera(asyn.Callable):
	""" One camera on a SecuritySpy server. """

	def __init__(self, elem, spy):
		""" Construct a Camera object from a fragment of ++systemInfo XML describing it. """
		asyn.Callable.__init__(self)
		self.spy = spy
		self.number = iget(elem, 'number')
		self.name = get(elem, 'name')
		self.connected = bget(elem, 'connected')
		self.size = (iget(elem, 'width'), iget(elem, 'height'))
		self.armed = { }
		self.classifications = { }
		if self.spy.webversion >= 4:
			self.armed[ARM_MOTION] = bget(elem, 'mode-m', 'armed')
			self.armed[ARM_CONTINUOUS] = bget(elem, 'mode-c', 'armed')
			self.armed[ARM_ACTIONS] = bget(elem, 'mode-a', 'armed')
		else:
			self.armed[ARM_MOTION] = bget(elem, 'mode', 'active')	# pre-V4 this was just "armed"
			self.armed[ARM_CONTINUOUS] = False						# no control over this
			self.armed[ARM_ACTIONS] = False							# no control over this
		self.audio = bget(elem, 'hasaudio')
		self.device = get(elem, 'devicename')
		self.ptz_capabilities = iget(elem, 'ptzcapabilities')
		self.sensitivity = iget(elem, 'mdsensitivity')
		self.type = get(elem, 'devicetype')
		if elem.find('address') is not None:
			self.location = (get(elem, 'address'), iget(elem, 'port'))
		else:
			self.location = None

	@property
	def control(self):
		return self.spy.control

	def set_active(self, active):
		""" Switch camera to active or passive mode. """
		if self.spy.webversion >= 4:
			self._request("/++ssControlMotionCapture", query={"arm": 1 if active else 0})
		else:
			self._request("/++ssControl%sMode" % ("Active" if active else "Passive"))
	
	def set_arm(self, type, armed):
		if self.spy.webversion >= 4:
			self._request("/++ssControl%s" % type, query={"arm": 1 if armed else 0})
		else:
			error("arm request not supported on version %d of SecuritySpy", self.spy.version)
	

	def trigger_motion(self):
		""" Artificially trigger motion processing for this camera. """
		self._request("/++triggermd")	# no reply

	def set_overlay(self, text, pointsize=12, position="0"):
		""" Change the overlay text, font, or position for the camera. """
		if self.spy.version >= V3_VERSION:
			self._request("/camerasettings", action='POST', query={
				'overlayText': text,
				'overlayFontSize': pointsize,
				'overlayPosition': position,
				'action': 'save',
				'Save': 'Save'
			})
		else:
			self._request("/++overlaysettings", action='POST', query={
				'overlayText': text,
				'fontSizeText': pointsize,
				'positionMenu': position,
				'Save': 'Save'
			})

	def set_sensitivity(self, level):
		self._request("/++camerasetup", action='POST', query={
			'mdSensitivityText': level,
			'action': 'save',
			'Submit': 'Submit'
		})

	def ptz_action(self, action):
		""" Request the camera to move or zoom.

			Check self.ptz_capabilities to see if this is meaningful.
		"""
		self._request('/++ptz/command', query={'command': action})

	def _refresh(self, update):
		""" Take a new Camera object and merge its state into self. Callout updates on change. """
		change = (self.armed != update.armed
			or self.connected != update.connected
			or self.sensitivity != update.sensitivity)
		self.name = update.name
		self.size = update.size
		self.connected = update.connected
		self.armed = dict(update.armed)
		self.sensitivity = update.sensitivity
		if change:
			self.callout('status')

	def _event_tap(self, ctx, *args):
		""" Process camera-specific event tap messages. """
		if ctx.state == 'active':	# v3, map to M active
			self.armed[ARM_MOTION] = True
		elif ctx.state == 'passive': # ditto
			self.armed[ARM_MOTION] = False
		elif ctx.state == 'arm':
			self.armed[ARM_REPORTS[args[0]]] = True
		elif ctx.state == 'disarm':
			self.armed[ARM_REPORTS[args[0]]] = False
		elif ctx.state == 'classify':	# SecuritySpy 5+ only
			self.classifications = classify(args[0])
			return self.callout('classify', self.classifications)
		elif ctx.state == 'trigger':	# SecuritySpy 5+ only
			type, reasons = args
			return self.callout('trigger', TRIGGER_TYPES[type], motions(int(reasons)))
		elif ctx.state == 'online':
			self.connected = True
		elif ctx.state == 'offline':
			self.spy.update()	# see if the camera was deleted
			self.connected = False
		self.callout(ctx, *args)

	def _request(self, req, callout=None, action='GET', query=None):
		""" Send a camera-specific web request. """
		rquery = {'cameraNum': self.number}
		if query:
			rquery.update(query)
		return self.spy._request(req, callout=callout, action=action, query=rquery)
	
	def __str__(self):
		return '<camera#%d "%s" %s %s @%s>' % (self.number, self.name, self.type, self.size, hex(id(self)))

	def __repr__(self): return str(self)


#
# Regression test. Specify host and web port number.
#
if __name__ == "__main__":

	import sys
	import getopt

	def dlog(*it):
		print(' '.join(map(str, it)))

	opts, args = getopt.getopt(sys.argv[1:], "a:CHp:t:")
	port = 8000
	user = password = None
	test_xml = None
	for opt, value in opts:
		if opt == '-a':
			user, password = value.split(':', 2)
		if opt == '-C':
			asyn.controller.DEBUG = dlog
		if opt == '-H':
			asyn.http.DEBUG = dlog
		if opt == '-p':
			port = int(value)
		if opt == '-t':
			f = open(value, "r")
			text_xml = f.read()
			f.close()
	if len(args) != 1:
		print("Usage: spy/core.py [-p port] [-t test_xml] [-a user:pass] host")
		exit(2)
	host = args[0]

	class CameraTest(object):
		def __init__(self, camera):
			self.camera = camera
			camera.add_callout(self._callout)
			print("Add camera", self.camera)
		def _callout(self, ctx, *args):
			print(self.camera, 'EVENT', ctx, args)

	def cb(ctx, *args):
		if ctx.error:
			print('ERROR', ctx.error)
			control.close()
			return
		print(ctx, args)
		if ctx.state == 'ready':
			global test_xml
			if test_xml:
				print("Reading supplemental config from %s" % test_xml)
				xml = test_xml
				test_xml = None
				spy._configure(xml)
		elif ctx.state == 'added':
			CameraTest(args[0])

	control = asyn.Controller()
	spy = SecuritySpy(control, host, port, callout=cb, user=user, password=password)
	control.run()
