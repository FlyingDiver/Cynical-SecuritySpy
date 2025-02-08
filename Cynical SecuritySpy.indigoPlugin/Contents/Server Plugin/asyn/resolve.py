from __future__ import print_function
#
# asyn.resolve - asynchronous network connector
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
import errno

import asyn
import asyn.selectable


#
# Evaluate an Exception to see if it might indicate a transient condition
#
def transient_error(ex):
	if isinstance(ex, OSError):
		if ex.errno in [
			errno.ECONNREFUSED,		# host up, nobody home
			errno.EHOSTDOWN,		# host down - perhaps someone will reboot it?
			errno.EHOSTUNREACH,		# host unreachable - perhaps someone will fix the router?
			errno.ETIMEDOUT,		# TCP SYN timeout - might get better
			errno.ENOBUFS			# temporary resource shortage
			]:
			return True


#
# A Selectable that asynchronously attempts a TCP connect.
#
class Connector(asyn.selectable.IO):
	""" A Selectable that makes an asynchronous outbound stream connection.

		If connected, calls out the socket object. If failed, calls out an asyn.Error.
		Either way, it cleans itself up and can be cleanly discarded.
	"""
	def __init__(self, control, res, callout=None):
		asyn.selectable.IO.__init__(self, control,
			socket.socket(res[0], res[1], res[2]), callout=callout)
		self._res = res
		try:
			self.io.setblocking(0)
			self.io.connect(res[4])
		except OSError as e:
			if e.errno != errno.EINPROGRESS:
				self.callout_error(e)
				self.close()
				return

	def _wants_write(self):
		return self.has_callouts()

	def _can_write(self):
		error = self.io.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
		if error:
			self.close()
			self.callout_error(OSError(error, os.strerror(error)))
		else:
			self.keep_file()
			self.close()
			ctx = asyn.Context('connected', resolved=self._res)
			self.callout(ctx, self.io)


#
# An asyn driver that tries all addresses of a target to obtain a TCP connection.
#
class TCPConnector(asyn.Callable):
	""" Asyn driver for asynchronous stream connecting.

		TCPConnector takes the output of socket.getaddrinfo() and attempts
		to connect to all listed addresses in some unspecified but efficient
		order.
		Upon success, it upcalls the ready-to-use socket.
		Upon failure, it upcalls an Error indicating one of the failures
		encountered trying to connect. (No attempt is made to record all
		failures.)

		This is a one-shot self-cleaning object: once it succeeds or fails,
		it removes its network and controller resources and can be safely discarded.

		In the current implementation, we sequentially try all listed addresses.
		Don't rely on that; we may cut/branch/overlap/preempt later.
	"""
	CANCELLED = asyn.Context('CANCELLED')	# sent if we close() while busy

	def __init__(self, control, res, callout=None):
		asyn.Callable.__init__(self, callout=callout)
		self.control = control
		self.candidates = list(res)	# copy (will mutate)
		self._lasterror = "No address(es) for host"
		self._schedule()

	def close(self):
		""" Stop what you're doing, making sure to release resources. """
		if self.connector:
			self.connector.close()
			self.connector = None
			self.callout(self.CANCELLED)

	def _schedule(self):
		if not self.candidates:	# we've run out of addresses to try
			self.control = None
			self.callout_error(self._lasterror)
		else:
			res = self.candidates.pop(0)
			self.connector = Connector(self.control, res, callout=self._connected)

	def _connected(self, ctx, result=None):
		if ctx.error:
			self._lasterror = ctx.error
			self._schedule() # try next one
		elif ctx.state == 'connected':
			self.connector = None
			self.callout(ctx, result)


#
# A Selectable that listens for incoming (stream) connection requests.
#
class Listener(asyn.selectable.IO):
	""" A Selectable that listens for incoming connection requests.

		The file or fileno we're given must already have been socket.listen()ed to.
	"""
	def _wants_read(self):
		return self.has_callouts()

	def _can_read(self):
		socket, address = self.io.accept()
		ctx = asyn.Context('accept', source=address)
		self.callout(ctx, socket)


#
# An asyn driver that listens on all addresses of a set to accept incoming TCP connections.
#
class TCPListener(asyn.Callable):
	""" Asyn driver for asynchronous stream accepting.

		TCPListener takes the output of socket.getaddrinfo() and sets up
		TCP listeners for all the address records in it. These listeners will
		accept incoming TCP connections in parallel and deliver them as 'accept'
		callouts from the TCPListener.

		This is a persistent object: It will continue to generate sockets and
		call them out until it is reconfigured or closed. Call accepting() to
		temporarily stem the tide (and have incoming requests queue up in the
		kernel, there to be bounced eventually).

		TCPListener currently passes all OS errors through as callouts, and does
		not attempt to reset or reconfigure anything on error.
	"""
	def __init__(self, control, res, callout=None):
		asyn.Callable.__init__(self, callout=callout)
		self.control = control
		self.listeners = { }
		self.active = False
		self.listen(res)

	def close(self):
		for res in self.listeners:
			self.listeners[res].close()
		self.listeners = { }
		self.active = False

	def listen(self, reslist, allow=True):
		self.close()
		error = None
		for res in list(reslist):
			try:
				s = socket.socket(res[0], res[1], res[2])
				s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				s.bind(res[4])
				s.listen(5)
				self.listeners[res] = Listener(self.control, s)
			except OSError as e:
				error = e
		if self.listeners:			# at least one worked
			self.accepting(allow)
		else:						# they all failed...
			self.callout(error)		# ... so report one error

	def accepting(self, allow):
		if allow != self.active:
			for listener in self.listeners.values():
				if allow:
					listener.add_callout(self._accept)
				else:
					listener.remove_callout(self._accept)
			self.active = allow

	def _accept(self, ctx, sock=None):
		if ctx.error:
			return self.callout(ctx)
		if ctx.state == 'accept':
			return self.callout(ctx, sock)


#
# Basic test operation.
# Give a list of hosts for outbound test. Give just a port for inbound test.
#
if __name__ == "__main__":
	import sys
	import time
	if len(sys.argv) == 1:
		print("Usage: resolve.py port [outgoing-host ...]")
		exit(2)
	port = sys.argv[1]
	control = asyn.Controller()
	now = time.time()
	pending = 0

	class Tester(object):
		def __init__(self, host):
			self.host = host
			try:
				res = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
			except socket.gaierror as e:
				print(host, "lookup failed:", e)
				return
			self.connector = control.connector(res, self.cb)
			global pending
			pending += 1

		def cb(self, ctx, sock=None):
			if ctx.error:
				print(self.host, "failed:", ctx)
			else:
				print(self.host, "connected:", sock)
				sock.close()
			global pending
			pending -= 1
			if pending == 0:
				exit(0)

	def tick(ctx):
		print("tick +%ds (%d pending)" % (time.time() - now, pending))
		ctx.reschedule(ctx.when + 5)

	if len(sys.argv) == 2:		# listen operation
		def acceptor(ctx, sock=None):
			if ctx.error:
				print("listen failed:", ctx)
			elif ctx.state == 'accept':
				print('incoming connection from', ctx.source)
				sock.send('Hello, there!\n')
				sock.close()
			else:
				print('UNEXPECTED', ctx, sock)
		listener = control.listener(socket.getaddrinfo(None, port, 0, socket.SOCK_STREAM, 0, socket.AI_PASSIVE),
			callout=acceptor)
	else:
		for host in sys.argv[2:]:
			Tester(host)

	print("Connecting...")
	control.schedule(tick)
	control.run()
