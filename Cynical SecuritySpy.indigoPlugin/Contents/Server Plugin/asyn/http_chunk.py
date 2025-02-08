#
# asyn.http_chunk - chunked coding FilterCallable
#
# Standard HTTP/1.1 chunked coder, read and write.
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
import asyn


#
# Chunked-Transfer encoding (both sides)
#
# Every output block is written as a distinct chunk.
# (Note that an empty chunk will effectively signal an END to the receiver.)
#
# Input is de-chunked and fed to our _scan.
# End-of-frame is upcalled as END with values ('CHUNKS', remaining-data).
# If caller wants to reuse the upstream, it needs to pop the coder.
#
class ChunkedCoder(asyn.FilterCallable):

	def __init__(self, source, callout=None):
		asyn.FilterCallable.__init__(self)
		if source:
			self.open(source, callout=callout)

	def open(self, source, callout=None):
		super(ChunkedCoder, self).open(source, callout=callout)
		self._pending = None
		self._remain = 0

	def incoming(self, ctx, *data):
		if self.read_enable and ctx.state == 'RAW':	# data
			self._pass_downstream(data[0])
		else:
			return super(ChunkedCoder, self).incoming(ctx, *data)

	def _pass_downstream(self, data):
		if self._pending:
			data = self._pending + data
			self._pending = None
		while data:
			if self._remain:
				rlen = min(len(data), self._remain)	# remaining in pending chunk
				self._remain -= rlen
				sendlen = rlen - max(2-self._remain, 0) # don't send trailing \r\n
				self._scan(data[:sendlen])
				data = data[rlen:]
			assert self._remain == 0 or not data	# out of data or at chunk boundary
			if self._remain == 0 and data:			# start a new chunk
				hlen = data.find(b'\r\n')
				if hlen == -1:						# incomplete chunk header; defer
					self._pending = data
					return
				header = data[:hlen].partition(b';')[0]	# discard any chunk extensions
				self._remain = int(header, 16) + 2	# count trailing \r\n
				data = data[hlen+2:]				# drop header \r\n
				if self._remain == 2:				# last-chunk
					self._pending = data
					# trailer processing is up to caller
					self.callout('END', 'CHUNKS', data)
					return

	def write(self, data):
		if self.write_enable:
			# Each chunk of data is sent as a separate chunk
			lengthCode = b'%X\r\n' % len(data)
			self.upstream.write(lengthCode + data + b'\r\n')
		else:
			self.upstream.write(data)

	def write_flush(self):
		""" Finish an outbound stream. """
		# last-chunk marker + no trailers + \r\n
		if self.upstream:
			self.upstream.write(b'0\r\n\r\n')
		super(ChunkedCoder, self).write_flush()
