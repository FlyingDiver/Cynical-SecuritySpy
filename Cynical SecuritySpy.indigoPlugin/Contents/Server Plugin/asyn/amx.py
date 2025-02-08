from __future__ import print_function
#
# asyn-based monitor for AMX device beacons
#
# Some consumer devices announce their presence by periodically
# multicasting discovery "beacon" packets. This is the AMX protocol.
# This file allows you to place a Lookout instance into an asyn.Controller
# that collects and parses AMX beacons and produces upcalls whenever
# anything changes. It also allows for saving and restoring discovery
# state, and for (simplistically) sharing discovery state between processes.
#
# Copyright 2010-2016 Perry The Cynic. All rights reserved.
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
import asyn
import socket
import struct
import sys
import time
import re

ADDRESS = '239.255.250.250' # multicast address
PORT = 9131					# canonical beacon port
TIMEOUT = 75				# device is considered "gone" after this may seconds of silence
HOLDDOWN = 80				# settle time for initial full sweep


_RE_SCAN = re.compile(b'<(.*?)>')

def parse_amx(data):
	""" Parse an AMX packet into its dictionary contents (or raise). """
	if data[0:4] != b'AMXB' or data[-1:] != b'\r':
		raise ValueError('invalid frame')
	return dict(map(lambda s: str(s, 'UTF8').split('=', 1), _RE_SCAN.findall(data)))


#
# Representation of one AMX-announcing device on the network
#
class Device(object):
	""" Representation of one AMX beacon on the network. """

	def __init__(self, desc, source):
		self.source = source		# ip source address of beacon
		self.last = None			# time last received
		self.raw = desc				# full descriptor dict as sent
		self.uuid = desc.get('-UUID')
		self.type = desc.get('-SDKClass')
		self.make = desc.get('-Make')
		self.revision = desc.get('-Revision')
		self.model = desc.get('-Model')

	def save_state(self):
		return dict(source=self.source, last=self.last, raw=self.raw)

	def __repr__(self):
		return '<AMX:%s %s/%s/%s %s@%s>' % (self.type, self.make, self.model, self.revision, self.uuid, self.source)


#
# A watcher of AMX beacons
#
class Lookout(asyn.Callable):
	""" An asyn collector of AMX beacon messages on the network. """

	def __init__(self, control, callout=None):
		asyn.Callable.__init__(self, callout=callout)
		self.control = control
		self.devices = { }
		self.ready = False

		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		s.bind(('', PORT))

		# join multicast group
		mreq = struct.pack('4sl', socket.inet_aton(ADDRESS), socket.INADDR_ANY)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		self._dev = control.datagram(s, callout=self._calldown)

		self._holddown_timer = None
		self._timer = None
		self._holddown()
		self._reschedule()

	def close(self):
		if self._dev:
			self._dev.close()
			assert self._dev is None	# from close calldown
			if self._timer:
				self._timer.cancel()
			if self._holddown_timer:
				self._holddown_timer.cancel()


	def save_state(self):
		""" Produce a dict suitable for re-loading later.

			The result is a "pure" Python dict suitable for encoding through
			json, xml, plists, or such.
		"""
		return dict(
			when=time.time(),
			devices=[dev.save_state() for dev in self.devices.values()]
		)


	def load_state(self, save_data):
		""" Add data earlier saved with save_state.

			The last-seen timestamps of such old device records are probably
			out of date, so we (re)engage hold-down mode to keep them around
			until they've had a chance to refresh.
		"""
		added = 0
		for state in save_data['devices']:
			raw = state['raw']
			uuid = raw['-UUID']
			if uuid not in self.devices:
				dev = Device(raw, state['source'])
				self.devices[uuid] = dev
				self.callout('loaded', dev)
				dev.last = state['last']
				added += 1
		if added:
			self._holddown()


	#
	# Incoming data callback.
	#
	def _calldown(self, ctx, data=None):
		""" Process incoming AMX beacon messages. """
		if ctx.error:
			return self.callout(ctx)
		if ctx.state == 'DGRAM':
			try:
				desc = parse_amx(data)
			except:
				return
			uuid = desc['-UUID']
			if uuid in self.devices:
				dev = self.devices[uuid]
				self.callout('update', dev)
			else:
				dev = Device(desc, ctx.source)
				self.devices[uuid] = dev
				self.callout('new', dev)
			dev.last = time.time()
			self._reschedule()
		elif ctx.state == 'CLOSE':
			self._dev = None


	#
	# Initial timer - we waited long enough to have caught all periodic announcements
	#
	def _holddown(self):
		if self._holddown_timer:
			self._holddown_timer.cancel()
		self._holddown_timer = control.schedule(self._do_holddown, after=HOLDDOWN)
		self.ready = False	# hold timeouts
		self._reschedule()

	def _do_holddown(self, ctx):
		self._holddown_timer = None
		self.ready = True
		self.callout('ready', self.devices)


	#
	# Periodic timer for removing "disappeared" devices
	#
	def _reschedule(self):
		""" Reschedule the timeout timer according to known beacons. """
		if self._timer:
			self._timer.cancel()
		self._timer = None
		if self.ready:
			devlast = [dev.last for dev in self.devices.values()]
			if devlast:
				self._timer = self.control.schedule(self._process_timer, at=TIMEOUT + min(devlast))

	def _process_timer(self, ctx):
		""" Handle timeouts of AMX beacons. """
		if self.devices:
			for dev in self.devices.values():
				if dev.last + TIMEOUT < ctx.now:
					self.callout('gone', dev)
					del self.devices[dev.uuid]
		else:
			self.callout('empty', None)
		self._reschedule()


#
# Basic test operation
#
if __name__ == "__main__":
	from getopt import getopt
	show_updates = False
	(options, args) = getopt(sys.argv[1:], "u")
	for opt, value in options:
		if opt == '-u': show_updates = True

	def cb(ctx, arg=None):
		if ctx.error:
			print('ERROR', ctx)
		if ctx.state in ['ready', 'new', 'loaded', 'update', 'gone']:
			if ctx.state != 'update' or show_updates:
				print('AMX[+%g]:' % (time.time()-start), ctx.state, arg)
		elif ctx.state == 'nothing':
			print('<<EMPTY>>')
		else:
			print('UNEXPECTED', ctx, arg)

	def commands(ctx, cmd=None):
		global lookout
		if ctx.state == 'END':
			return control.close()
		if ctx.scan:
			if cmd == 'list':
				for dev in lookout.devices.values():
					print('\t%s' % dev, dev.raw)
			elif cmd == 'save':
				print(lookout.save_state())
			elif cmd == 'reload':
				save = lookout.save_state()
				lookout.close()
				print('RELOADING')
				lookout = Lookout(control, cb)
				lookout.load_state(save)
				print('RELOAD COMPLETE')
			else:
				print("? %s" % cmd)

	control = asyn.Controller()
	lookout = Lookout(control, cb)
	control.commands(commands)
	print("Starting AMX beacon scan...")
	start = time.time()
	control.run()
