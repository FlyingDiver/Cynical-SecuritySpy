#
# asyn.core - asyn core implementation.
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
from functools import reduce


#
# Add ./vendor to the module search path
#
import os
import sys
parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, 'vendor')
sys.path.append(vendor_dir)


#
# Context passed to a Callable's callout as first argument
#
class Context(object):
	""" A Context is passed to every callout as the first argument. """

	scan = None				# producing scanner
	error = None			# carried exception (None for non-error Contexts)

	def __init__(self, state, scan=None, **kwargs):
		""" Construct a Context. All keyword arguments become attributes of the Context. """
		self.state = state
		if scan:
			self.scan = scan
		for key in kwargs:
			if not hasattr(self, key):
				setattr(self, key, kwargs[key])

	def __str__(self):
		return '<Ctx:%s>' % (self.state,)

	def __repr__(self):
		return '<Ctx:%s>' % (self.state,)


#
# A Context indicating an error condition.
#
class Error(Context):
	""" A Context that indicates an error condition. """

	def __init__(self, error, **kwargs):
		""" Construct an Error Context

			Positional arguments become part of the Exception "args" tuple.
			Keyword arguments become part of the Context.
		"""
		Context.__init__(self, 'ERROR', **kwargs)
		assert isinstance(error, Exception)
		self.error = error

	def __str__(self):
		if len(self.error.args) > 1 and isinstance(self.error[0], int) and isinstance(self.error[1], str):
			return self.error[1]
		return str(self.error)

	def __repr__(self):
		return '<Ctx!Error %r>' % (self.error,)


#
# An object with a standardized callback.
#
class Callable(object):
	""" Mix-in class managing callback funnels.

		A Callable bears zero or more Python callables as its "callout set".
		When callout() is called, all those registered callables are called,
		in undefined order.

		The first argument of all callouts must be a Context value. Any additional
		number of Python values may be sent along.

		Existing Callables may invent new Context types at times. Match incoming contexts
		positively. Do not assume you know all context types you may receive. Ignore
		or merely log unknown contexts, rather than failing.

		Any callout may be handed an error context, and error callouts carry no arguments.
		Make all callout arguments (beyond context) optional.
	"""
	def __init__(self, callout=None):
		""" Construct a Callable with an optional (single) callout pre-registered. """
		self.set_callout(callout)
		self._callback_reducer = lambda a, b: a or b

	def set_callout(self, callee):
		""" Replace all callouts with a single new one. """
		self._callbacks = [callee] if callee else []

	def add_callout(self, callee):
		""" Add a new callout to the existing set. """
		if callee:
			self._callbacks.append(callee)

	def remove_callout(self, callee, required=True):
		""" Remove a single callout from the current set (in which it must be). """
		try:
			self._callbacks.remove(callee)
		except ValueError:
			if required:
				raise

	def clear_callouts(self):
		""" Unconditionally remove all callouts. """
		self._callbacks = []

	def has_callouts(self):
		""" Test whether any callouts are currently registered. """
		return bool(self._callbacks)

	def has_callout(self, callee):
		""" Test whether a particular callable is currently registered as a callout. """
		return callee in self._callbacks


	def set_callout_reduce(self, reducer):
		self._callback_reducer = reducer


	def callout(self, ctx, *args):
		""" Perform a callout.

			The first argument must be a Context. If it's a simple string, it is
			automatically turned into a minimal Context with that state value.
			If it's an Exception, you get an Error context.

			Any other positional arguments are passed along unchanged. Keyword arguments
			are reserved.

			All registered callables are called in some undefined order.
			If any raises an exception, we're going straight to hell.
			The results from all these calls are coalesced (with reduce)
			to a single value which is returned from callout. The default
			reducer returns the first true value encountered.
			If the reducer is None, a list of all results (even if None or False) is returned.
		"""
		if not isinstance(ctx, Context):
			if isinstance(ctx, str):
				ctx = Context(ctx)
			elif isinstance(ctx, Exception):
				ctx = Error(ctx)
		assert isinstance(ctx, Context)
		results = [cb(ctx, *args) for cb in list(self._callbacks)]	# latch callback list
		if self._callback_reducer:
			return reduce(self._callback_reducer, results, None)
		else:
			return results

	def callout_error(self, error, **kwargs):
		""" Perform a callout, sending an Error Context (only).

			Positional arguments become part of the Exception args tuple.
			Keywords arguments become Context attributes.
		"""
		if isinstance(error, Error):
			return self.callout(error)
		assert isinstance(error, Exception)
		self.callout(Error(error, **kwargs))
