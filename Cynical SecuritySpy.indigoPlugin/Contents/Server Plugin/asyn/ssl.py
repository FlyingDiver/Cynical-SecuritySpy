#
# asyn.ssl - SSL interface
#
# This uses the Python openssl module to implement
# an SSL pipe on top of an Raw Callable.
#
# This is using the very basic Python OpenSSL module, which basically
# wraps the host system's OpenSSL library.
#
# Copyright 2013-2019 Perry The Cynic. All rights reserved.
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
from contextlib import contextmanager

import OpenSSL.SSL
import OpenSSL.crypto

import asyn

DEBUG = None


#
# OpenSSL tends to use 16K buffering
#
BUFSIZE = 64 * 1024		# default read buffer size


#
# An asyn SSL adapter for OpenSSL.
#
class SSL(asyn.FilterCallable):
	""" An asyn adaptation of SSL.

		SSL presents the standard asyn Callable interface, forwarding data
		to the provided Selectable and imposing OpenSSL on the connection.
		This should work as a rough functional adapter to add SSL to any
		standard asyn.Stream-like data flow.
	"""
	def __init__(self, source=None, type=OpenSSL.SSL.TLSv1_2_METHOD, key=None, certs=None, *args, **kwargs):
		asyn.FilterCallable.__init__(self)
		self.connection = None
		self.ctx = OpenSSL.SSL.Context(type)
		if key:
			if isinstance(key, str):
				self.ctx.use_privatekey_file(key)
			else:
				self.ctx.use_privatekey(key)
		if certs:
			if isinstance(certs, str):
				self.ctx.use_certificate_chain_file(certs)
			else:
				self.ctx.use_certificate(certs)
		if source:
			self.open(source, *args, **kwargs)

	def open(self, source, accept=False, hostname=None, callout=None):
		super(SSL, self).open(source, callout=callout)
		self.connection = OpenSSL.SSL.Connection(self.ctx, None)	# no direct I/O object
		self._wbuf = b''
		if accept:
			self.connection.set_accept_state()
		else:
			self.connection.set_connect_state()
			if hostname:
				self.connection.set_tlsext_host_name(hostname.encode('ascii'))
		self._startup = True
		self.handshake()		# start it off

	def close(self):
		if self.connection:
			self.connection = None
			super(SSL, self).close()

	def write(self, data):
		if self.connection:
			self._wbuf += data
			self._service()

	def handshake(self):
		with self.frame():
			self.connection.do_handshake()

	def shutdown(self):
		with self.frame():
			self.connection.shutdown()

	@contextmanager
	def frame(self):
		""" Perform an SSL operation and ignore non-error exceptions. """
		try:
			yield
		except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantWriteError, OpenSSL.SSL.WantX509LookupError):
			pass
		except OpenSSL.SSL.Error as e:
			if DEBUG: DEBUG(self, "TLS ERROR", e)
			self.callout('SSLERR', e)

	def _service(self):
		""" Make what progress we can by servicing the memory BIO and SSL. """
		while self.connection:	# (could be close()d in this loop)
			# send any buffered clear output to SSL
			if self._wbuf:
				with self.frame():
					written = self.connection.write(self._wbuf)
					if DEBUG: DEBUG("SSL -> [%d of %d]" % (written, len(self._wbuf)), repr(self._wbuf[:written]))
					self._wbuf = self._wbuf[written:]
					continue
			# pull data from SSL and deliver it downstream
			with self.frame():
				try:
					rdata = self.connection.read(BUFSIZE)
					if DEBUG: DEBUG("SSL <-", repr(rdata))
					if self._startup:
						self.callout('start')
						self._startup = False
					self._scan(rdata)
					continue
				except OpenSSL.SSL.ZeroReturnError:		# EOF (it's a long story)
					if DEBUG: DEBUG(self, "ZERO RETURN")
					self.callout('END')
					return
			# Note that the downstream leg of the memory BIO is managed by self._incoming
			# pull pending data from the memory BIO and deliver it upstream
			if self.connection and self.connection.want_read():
				with self.frame():
					wdata = self.connection.bio_read(BUFSIZE)
					if DEBUG: DEBUG("SSL -->", len(wdata))
					self.upstream.write(wdata)
					continue
			# no progress, done servicing
			return

	def incoming(self, ctx, *args):
		""" Upstream tap. """
		if self.connection:
			if ctx.state == 'RAW':
				data = args[0]
				with self.frame():
					written = self.connection.bio_write(data)
					if DEBUG: DEBUG("SSL <--", written)
					assert written == len(data)		# memory BIOs have no size limit
					self._service()
			else:
				super(SSL, self).incoming(ctx, *args)


#
# Regression test
#
# Broken and obsolete - removed. Use the http.py regression test with an https: scheme.
#
