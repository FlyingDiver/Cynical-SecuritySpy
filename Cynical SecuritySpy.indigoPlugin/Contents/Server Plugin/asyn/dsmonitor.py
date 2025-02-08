from __future__ import print_function
#
# dsmonitor - Apple Distributed Notifications monitor.
#
# This module encapsulates Mac OS Distributed Notification events and delivers
# notifications as asyn callouts using plain Python data structures.
#
# Mac OS delivers change notifications using Distributed Notifications.
# They are a royal pain unless you've already sold your soul to the CFRunloop Gods.
# In particular, this won't work unless you run a CFRunloop on the *main thread*. Sheesh.
#
# The idea is that this file can run as a (main program) daemon doing all those
# Apple-y things, collecting DNs and packaging them up for delivery on stdout.
# The DSMonitor class launches that daemon, receives incoming notifications,
# unpacks them into Python data, and delivers them as asyn callouts. That way,
# the client side need not tangle with CFRunloop and its over-possessive personality.
#
# Copyright 2012-2016 Perry The Cynic. All rights reserved.
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
import sys
import os
import plistlib
import base64
import cPickle as pickle

import asyn.selectable


#
# A DSMonitor delivers distributed notifications as asyn callouts.
#
class DSMonitor(asyn.Callable):
	""" A watcher for Mac OS distributed notifications.

		The callout form is (ctx, name, info), where info is the information dictionary
		delivered or None if there was none.

		This class knows nothing about the semantics of the DNs delivered.
		That's up to the calling layer to figure out.
	"""
	_scan_events = asyn.scan.Regex([
		(r'NOTIFY@([^@]+)@([^@]+)@-\n', 'notify'),			# notification event
		(r'NOTIFY@([^@]+)@([^@]+)@(.*)\n', 'notify-info')	# notification event with dictionary info
	])

	def __init__(self, control, event_list, callout=None):
		asyn.Callable.__init__(self, callout=callout)
		self.control = control

		# make sure our python-child has the same configuration as we do
		pathenv = os.getenv("PYTHONPATH")
		ppath = pathenv.split(':') if pathenv else []
		for path in [path for path in sys.path if not path.startswith('/System/Library/Frameworks/')]:
			if not path in ppath:
				ppath = [path] + ppath
		if ppath:
			os.environ["PYTHONPATH"] = ':'.join(ppath)

		pythonbin = '/usr/bin/python%d.%d' % (sys.version_info[0], sys.version_info[1])

		self._listener = asyn.selectable.ProcessPipe(control,
			path=pythonbin,
			args=[__file__, "-M"] + (event_list or []),
			callout=self._event)
		self._listener.scan = self._scan_events
		self.pid = self._listener.pid

	def close(self):
		if self._listener:
			self._listener.close()

	def _event(self, ctx, *args):
		if ctx.error:
			return self.callout(ctx)
		if ctx.state == 'notify':
			(when, name) = args
			self.callout(asyn.Context('notify', time=when), name, None)
		elif ctx.state == 'notify-info':
			(when, name, data) = args
			data = pickle.loads(base64.b64decode(data))
			self.callout(asyn.Context('notify', time=when), name, data)
		elif ctx.state == 'END':
			self.callout(ctx)


#
# Daemon form: run as a daemon, report distributed notifications to stdout.
#
if __name__ == "__main__":
	from Cocoa import NSObject
	from Cocoa import NSString, NSUTF8StringEncoding
	from Cocoa import NSPropertyListSerialization, NSPropertyListXMLFormat_v1_0
	from Cocoa import NSDistributedNotificationCenter
	from PyObjCTools import AppHelper
	import sys
	import time

	def encode(it):
		""" Default wire encoder: base64-wrapped binary pickle. """
		return base64.b64encode(pickle.dumps(it, -1))

	def plistify(nsdict):
		""" Turn an NS-style plist into encoded string form. """
		if nsdict is None:
			return "-"
		(data, err) = NSPropertyListSerialization.dataWithPropertyList_format_options_error_(nsdict,
			NSPropertyListXMLFormat_v1_0, 0, None)
		string = NSString.alloc().initWithData_encoding_(data, NSUTF8StringEncoding)
		plist = plistlib.readPlistFromString(str(string))
		return encode(plist)


	class Listener(NSObject):
		""" An NSObject to register for and receive Distributed Notification events. """

		def initWithEventList_(self, event_list):
			""" Create a Listener.

				If event_list is true, listen for those event names only.
				If it's false, listen for everything.
			"""
			self = super(Listener, self).init()
			assert self is not None
			nc = NSDistributedNotificationCenter.defaultCenter()
			for event_name in event_list or [None]:
				nc.addObserver_selector_name_object_(self, 'observe:', event_name, None)
			return self

		def observe_(self, notification):
			""" Generic observer relay. """
			name = notification.name()
			obj = notification.object()
			info = notification.userInfo()
			try:
				print("NOTIFY@%s@%s@%s" % (
					time.time(),
					name,
					plistify(info)
				))
				sys.stdout.flush()
			except IOError:
				sys.exit(0)

	#
	# Be a daemon: invoked as __file__ -M [event_list]
	#
	args = sys.argv[1:]
	if args and args[0] == '-M':
		listener = Listener.alloc().initWithEventList_(args[1:])
		try:
			AppHelper.runConsoleEventLoop()
			sys.exit(0)
		except KeyboardInterrupt:
			sys.exit(0)
		sys.exit(1)

	#
	# Regression test
	#
	import asyn
	def report(ctx, *it):
		if ctx.state == 'notify':
			(name, info) = it
			print(name)
			if info:
				for (key, value) in info.items():
					print("\t%s = %s" % (key, value))
		else:
			print(ctx, it)

	control = asyn.Controller()
	monitor = DSMonitor(control, args, callout=report)
	control.run()
