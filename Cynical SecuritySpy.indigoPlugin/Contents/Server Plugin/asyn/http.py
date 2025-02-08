from __future__ import print_function
#
# asyn.http - asynchronous http requests, simplified with extreme prejudice.
#
# This is not general purpose. It is just (barely) enough http to get by
# in a stand-alone world where some services use http as a transport.
# No web browser will ever find this useful. In particular, we actively
# eschew all persistence features; each Request is self-contained.
#
# Actually supported features: HTTP/1.0 and 1.1. TLS via OpenSSL.
# Gzip and chunked transfer encoding.
# Not implemented features: Everything else; notably no redirects, cookies,
# or server side operation.
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
import os
import socket
import errno
import re
import string
import urllib
import base64

import asyn

try:
	from asyn.ssl import SSL
except ImportError:
	SSL = None
try:
	from asyn.zfilter import GZipCoder
except ImportError:
	GZipCoder = None
try:
	from asyn.http_chunk import ChunkedCoder
except ImportError:
	ChunkedCoder = None

DEFAULT_AGENT = 'cy-asyn/1.1'		# generic cynical asyn (v1)

DEBUG = None


#
# An Exception for HTTP status errors
#
class StatusError(Exception):
	def __init__(self, n, v):
		Exception.__init__(self, n, v)		# fill in args tuple
		self.n_status = n
		self.v_status = v


#
# Assisted dictionaries for both requests and replies
#
class HeaderDict(dict):
	""" A dict that normalizes its key strings, and collects multiples in list values. """
	def __init__(self, source=None):
		dict.__init__(self)
		if source:
			self.update(source)

	def add(self, key, value):
		key = self._key(key)
		if key in self:
			prior = self[key]
			if isinstance(prior, list):
				prior.append(value)
			else:
				self[key] = [prior, value]
		else:
			self[key] = value

	def update(self, source):
		for key in source.iter():
			self.add(key, source[key])

	@staticmethod
	def _matches(pattern, value):
		pattern = pattern.lower()
		value = value.lower()
		return value is None or pattern == value or pattern.startswith(value + ';')

	def match(self, key, spec=None):
		""" Return a full or semic-prefix match for a given key. """
		key = self._key(key)
		if key in self:
			value = self[key]
			if isinstance(value, list):	# multiples
				for v in value:
					if self._matches(v, spec):
						return v
			elif self._matches(value, spec):
				return value

	@staticmethod
	def _key(value):
		return '-'.join([s.capitalize() for s in value.split('-')])	# "Transfer-Coding"



#
# HTTP authentication basics
#
class BasicAuth(object):

	def __init__(self, user, password):
		self.user = user
		self.password = password

	def write_headers(self, req):
		code = base64.b64encode(f'{self.user}:{self.password}'.encode())
		req.write('Authorization: Basic ' + str(code, 'ascii'))


#
# HTTP schemes. Quite rudimentary.
#
class Scheme(object):
	@classmethod
	def create(cls, request):
		pass

class HTTP(Scheme):
	scheme = 'http'
	defaultPort = 80

class HTTPS(Scheme):
	scheme = 'https'
	defaultPort = 443

	@classmethod
	def create(cls, request):
		request.insert_filter(SSL, hostname=request.host, uplink=request.incoming)


#
# Supported schemes.
#
SCHEMES = {
	'http':		HTTP,
	'https':	HTTPS,
}


#
# An HTTP request in the asyn frame
#
class Request(asyn.FilterCallable):
	""" Prepare and send an HTTP request, and parse and deliver the reply.

		Requests broker their own network connections; they are not under
		the control of the caller.
	"""
	_scan_headers = asyn.scan.Regex([
		(r'HTTP/(1.[01]) (\d+) ([^\r]*)\r\n', 'status'), # status reply line
		(r'([^:]+):\s+([^\r]*)\r\n', 'header'),	# reply header line
		(r'\r\n', 'end-headers')				# end of headers
	])

	p_version = None
	n_status = None
	v_status = None

	def __init__(self, control, url=None, callout=None, res=None,
			action='GET', query=None, body=None, auth=None, compression=None):
		asyn.FilterCallable.__init__(self)
		self.add_callout(callout)
		self.control = control
		self.auth = auth
		self.user_agent = DEFAULT_AGENT
		self.h_request = HeaderDict()
		self.query = query or { }
		self.h_reply = HeaderDict()
		self.action = action
		self.body_request = body
		self.body_reply = None
		self.res = res
		self.http_version = "1.1" if ChunkedCoder else "1.0"	# mandatory in 1.1

		if GZipCoder and compression != False:
			self.add_header("Accept-Encoding", "gzip")

		if url:
			self.open(url)

	def add_header(self, name, value):
		self.h_request.add(name, value)

	def open(self, url, query=None):
		""" Specify an entire URL and start sending a request for it. """
		if "User-Agent" not in self.h_request:
			self.add_header("User-Agent", self.user_agent)
		self.url = url
		self.urlparts = urllib.parse.urlsplit(self.url, 'http')
		if query:
			self.query.update(query)
		self.scheme = SCHEMES[self.urlparts[0]]
		assert self.scheme
		self.host = self.urlparts.hostname
		self.port = self.urlparts.port or self.scheme.defaultPort
		if self.res is None:
			try:
				self.res = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM, 0, 0)
			except OSError as e:
				self.callout_error(e)
				return
		self._con = self.control.connector(self.res, self._connected)
	send = open		# history

	def _connected(self, ctx, sock=None):
		self._con = None
		if ctx.error:
			return self.callout(ctx)
		assert isinstance(sock, socket.socket)
		asyn.FilterCallable.open(self, asyn.selectable.Stream(self.control, sock), callout=self.incoming)
		self.scheme.create(self)
		self._sendRequest()

	def _sendRequest(self):
		self.upstream.scan = self._scan_headers
		p = self.urlparts
		if self.action != 'POST' and self.query:
			uri = urllib.parse.urlunsplit(('', '', p.path, self._querystring(), p.fragment))
		else:
			uri = urllib.parse.urlunsplit(('', '', p.path, p.query, p.fragment))
		self.write(f'{self.action} {uri or "/"} HTTP/{self.http_version}')
		self.write(f'Host: {self.host}')
		self.write("Connection: close")
		for h in self.h_request:
			self.write(f'{h}: {self.h_request[h]}')
		if self.auth:
			self.auth.write_headers(self)
		if self.action == 'POST':
			if self.query:
				query = self._querystring()
				self.write(f'Content-Length: {len(query)}')
				self.write('Content-Type: application/x-www-form-urlencoded')
				self.write('')
				self.write(query)
				self.end_request()
			elif self.body_request:
				self.write(f'Content-Length: {len(self.body_request)}')
				self.write('')
				self.write(self.body_request)
				self.end_request()
			else:
				pass	# streaming output; writer needs to chunk-encode, .write, and .end_request when done
		else:
			self.write('')

	def write(self, it):
		if DEBUG: DEBUG('->', it)
		super(Request, self).write(f'{it}\r\n'.encode())

	def end_request(self):
		pass

	def incoming(self, ctx, *args):
		if ctx.error:
			return self.callout(ctx)
		if ctx.state == 'END':
			self.close()
			if self.body_reply is None:
				self.callout(ctx)	# unexpected END in headers
			else:
				self.callout('body', self.body_reply)
		elif ctx.state == 'status':
			if DEBUG: DEBUG('<- HTTP/%s %s %s' % args)
			self.p_version, self.n_status, self.v_status = args
			self.callout(ctx, self.n_status)
		elif ctx.state == 'header':
			if DEBUG: DEBUG('<- %s: %s' % args)
			key, value = args
			self.h_reply[key] = value
		elif ctx.state == 'end-headers':
			self._prepare_body()
			self.callout('headers', self.h_reply)
		elif ctx.state == 'RAW' and self.scan is None:
			self.body_reply += args[0]
		else:
			super(Request, self).incoming(ctx, *args)

	def _prepare_body(self):
		self.upstream.scan = None
		
		self.body_reply = b''

		if self.h_reply.match("Transfer-Encoding", "chunked"):
			self.insert_filter(ChunkedCoder, uplink=self.incoming, push_back=b'')
		if self.h_reply.match("Content-Encoding", "gzip"):
			self.insert_filter(GZipCoder, uplink=self.incoming, push_back=b'')

	def _querystring(self):
		return urllib.parse.urlencode(self.query)


	#
	# Display formats
	#
	def __repr__(self):
		s = "<Request %s" % self.action
		if self.http_version != "1.1":
			s += "[%s]" % self.http_version
		if self.p_version:
			s += " - %s %s %s" % (self.p_version, self.n_status, self.v_status)
		return s + ">"


#
# Request-making convenience function
#
def request(control, url=None, res=None, callout=None, action='GET', query=None, body=None, auth=None, compression=None):
	""" Create a Request and kick it off. """
	return Request(control, url, res=res, callout=callout, action=action, query=query, body=body, auth=auth, compression=compression)


#
# Regression test
#
if __name__ == "__main__":
	import sys
	import getopt
	if len(sys.argv) == 1:
		print("Usage: asyn/http.py [-P] [-FHTS] [-a user:pass] url [query-fields]")
		exit(1)

	def dlog(*it):
		print(' '.join(map(str, it)))

	def cb(ctx, *args):
		if ctx.error:
			print('ERROR', ctx.error)
			exit(0)
		elif ctx.state == 'status':
			print('REPLY', args[0], req.v_status)
		elif ctx.state == 'headers':
			print('HEADERS', args[0])
		elif ctx.state == 'body':
			control.close()
		else:
			print('UNEXPECTED', ctx, args)

	control = asyn.Controller()
	req = request(control, callout=cb)
	opts, args = getopt.getopt(sys.argv[1:], "a:FHPST")
	for opt, value in opts:
		if opt == '-a':
			user, password = value.split(':', 2)
			req.auth = BasicAuth(user, password)
		if opt == '-F':
			asyn.selectable.DEBUG = dlog
		if opt == '-H':
			DEBUG = dlog
		if opt == '-T':
			asyn.ssl.DEBUG = dlog
		if opt == '-S':
			asyn.scan.DEBUG = dlog
		if opt == '-P':
			req.action = 'POST'
	for arg in args[1:]:
		key, _, value = arg.partition('=')
		req.query[key] = value
	req.send(args[0])
	print("Running...")
	control.run()
	print(req.body_reply)
