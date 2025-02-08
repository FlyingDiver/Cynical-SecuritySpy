#
# asyn.zfilter - zlib FilterCallable
#
# Copyright 2013-2018 Perry The Cynic. All rights reserved.
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
import zlib

import asyn


#
# Gzip coder
#
class GZipCoder(asyn.FilterCallable):

	def __init__(self, source, compresslevel=6, callout=None):
		asyn.FilterCallable.__init__(self)
		self._zr = self._zw = None
		self.compresslevel = compresslevel
		if source:
			self.open(source, callout=callout)

	def incoming(self, ctx, *args):
		if ctx.state == 'RAW':	# data
			if not self.read_enable:
				return self.callout(ctx, *args)
			if not self._zr:
				self._zr = zlib.decompressobj(32 + zlib.MAX_WBITS)	# (stupid convention)
			self.callout(ctx, self._zr.decompress(args[0]))
		elif ctx.state == 'END':
			if self._zr:
				rest = self._zr.flush()
				if rest:
					self.callout('RAW', rest)
			self.callout(ctx)
		else:
			return super(GZipCoder, self).incoming(ctx, *args)

	def write(self, data):
		if not self.write_enable:
			return self.upstream.write(data)
		if not self._zw:
			self._zw = zlib.compressobj(self.compresslevel)
		self.upstream.write(self._zw.compress(data))

	def write_flush(self):
		if self._zw:
			rest = self._zw.flush(zlib.Z_FINISH)
			if rest:
				self.upstream.write(rest)
		super(GZipCoder, self).write_flush()
