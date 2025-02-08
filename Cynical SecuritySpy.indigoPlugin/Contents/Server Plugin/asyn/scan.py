#
# asyn.scan - asyn pluggable scanners.
#
# A Scanner is an object implementing the informal scanner protocol:
#	scan(self, target)
# This should examine the (bytes) data bytes in target._rbuf and decide
# whether a leading substring thereof warrants processing. If it does,
# remove that prefix from target._rbuf and call the standard-form callout method
#	target.callout(ctx, <whatever>)
# where <whatever> is any number of positional arguments representing the match.
# If the remaining buffer warrants repeated processing, do so. When no more match
# can be made, leave the remaining data (if any) in target._rbuf and return.
#
# Copyright 2010-2016,2019 Perry The Cynic. All rights reserved.
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
DEBUG = None

import re

from asyn.core import Context


#
# Base (mix-in) class for objects that feed a Scanner.
#
RAW = Context('RAW')		# canonical raw data delivery context

class Scannable(object):
	""" A mix-in class that parses and delivers data based on scanning classes.

		Scannable must be mixed-in to a subclass of Callable. Scannable maintains
		a read buffer ._rbuf fed through self._scan(data). Each _scan call attempts to deliver
		data downstream through the current self.scan object (or as a 'RAW' callout
		if scan is None). If the scan stalls, the remaining ._rbuf data is retained
		for the next _scan call. It is up to the scanner to discard invalid or unexpected data
		from the buffer by consuming it.

		The read buffer is a bytes array. If a scanner wants to consider it as text, it will
		interpret it as the target's .scan_encoding (usually utf-8).
	"""
	def __init__(self):
		self.scan = None
		self.scan_encoding = 'utf-8'
		self._rbuf = b''
		self._scan_active = True

	def _scan(self, data):
		""" Repeatedly generate scan events until we can't make any more progress.

			If self.scan is ever None, deliver (the rest of) the data as a RAW callout.
		"""
		self._rbuf += data
		while self._scan_active and self._rbuf:
			if self.scan is not None:
				if not self.scan.scan(self):
					break
			else:
				self.callout(RAW, self.flush_scan())
	
	@property
	def scan_active(self):
		return self._scan_active
		
	@scan_active.setter
	def scan_active(self, activate):
		if activate != self._scan_active:
			self._scan_active = activate
			if activate:
				self._scan(b'')		# process accumulated buffer

	def flush_scan(self):
		""" Flush the scan buffer and return its contents. """
		buf = self._rbuf
		self._rbuf = b''
		return buf


#
# A Scanner based on a vector of regex rules.
#
class Regex(object):
	""" A Scanner object based on a vector of regular expression matching rules.

		Regex implements a Scanner based on a list of (regex, state) pairs.
		The buffer is scanned by trying each regex in order; the first match wins.
		If no regex matches, the scan fails.

		There is no implicit mechanism for skipping bytes that won't or can't match
		any of our regex rules. If you want to recover from unexpected input, you
		must have a rule that does so.
	"""

	def __init__(self, ruleset, options=0):
		""" Initialize with optional rules. """
		self._rules = [(re.compile(rule[0], options),) + rule[1:] for rule in ruleset]

	def scan(self, target):
		""" Try to match the buffer against our ruleset and callout a match.

			The first matching regex wins. We construct a Context from the rule's
			state value and attach the regex match object as ctx.match.
			All match groups in the winning regex become additional arguments
			passed to the callout.

			A rule with a false state suppresses the callout but still consumes its match
			in the buffer. Use this for whitespace consumption and recovery rules without
			bothering the callout recipients.

			Any values in a matching tuple beyond the second are assigned to the 'aux'
			field of the context. Aux is not set if there are only the regex and state.
			
			Return Python true to indicate that a valid match has consumed (some or all of)
			the data. Return false to indicate that no progress was possible.
		"""
		if DEBUG: DEBUG("scanning", repr(target._rbuf))
		if target._rbuf:
			rbuf = str(target._rbuf, target.scan_encoding, errors='surrogateescape')
			for rule in self._rules:
				if DEBUG: DEBUG(" trying", *rule)
				pattern = rule[0]
				state = rule[1]
				m = pattern.match(rbuf)
				if m:
					pos = m.end(0)				# consumption count
					remains = rbuf[pos:]		# rest of subject buffer
					if DEBUG: DEBUG(" matched", repr(rbuf[:pos]), "|", repr(remains))
					target._rbuf = remains.encode(target.scan_encoding, errors='surrogateescape') # remove match
					if state:					# if no state, drop it
						ctx = Context(state, scan=self, rule=rule, match=m)
						if len(rule) > 2:
							ctx.aux = rule[2:]
						target.callout(ctx, *m.groups())
					return True
			if DEBUG: DEBUG(" no match")


#
# An efficient record separator based on fixed separation (byte) strings.
#
class TokenScan(object):
	""" A Scanner object that separates records based on fixed separator strings.
	
	"""
	def __init__(self, separator, state='record'):
		self.separator = separator
		self.state = state
	
	def scan(self, target):
		""" Call out full records (without separators) """
		if DEBUG: DEBUG("scanning", repr(target._rbuf))
		
		records = target._rbuf.split(self.separator)
		target._rbuf = records.pop()
		for record in records:
			target.callout(self.state, record)
		return len(records)			# will be 0 ~ false if no full records found
			

#
# A Scanner that passes input subject to byte count constraints.
#
class ByteLimit(object):

	def __init__(self, limit, threshold=None):
		self._limit = limit
		self._threshold = threshold
		self._delivered = 0

	def scan(self, target):
		available = self._delivered + len(target._rbuf)
		if self._threshold and available < self._threshold:
			return False		# not yet
		if available > self._limit:		# too much
			count = self._limit - self._delivered
			send = target._rbuf[0:count]
			target._rbuf = target._rbuf[count:]
		else:
			count = len(target._rbuf)
			send = target._rbuf
			target._rbuf = b''
		target.callout('limit-data', send, scan=self)
		self._delivered = self._delivered + count
		if self._delivered == self._limit:
			target.callout('limit-reached', scan=self)
		return True
