#
# asyn.inject - out-of-thread injection of work
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
from __future__ import with_statement

import os
import threading
from collections import deque

import asyn
from asyn import selectable


#
# An Injector is a Controller subclass that works well with other threads.
# It adds the ability to "inject" code for execution from another thread
# without disturbing its serene single-threaded happiness.
#
class Controller(asyn.Controller):
	""" A Controller that allows other threads to inject work into it.

		This is a standard Controller that can interact with other threads.
		It allows any thread to inject calls into its schedule queue, either
		asynchronous or with the calling thread waiting for the outcome.

		Note that even for the waiting versions, the actual call is still
		made on the controller thread (with the result being transferred to
		the waiting caller).

		The queue_idle construction argument determines what injection does
		when the Controller is not running. If queue_idle is False (the default),
		other threads will directly execute their injection. The caller is responsible
		for avoiding thread contention on the data used. If queue_idle is True,
		injections will be queued, but will not execute until the Controller is
		resumed. The waiting versions of injection will wait until that happens.
	"""
	def __init__(self, queue_idle=False, **kwargs):
		asyn.Controller.__init__(self, **kwargs)
		self._injector = _Inject(self)
		self._run_thread = None
		self._queue_idle = queue_idle

	def run(self):
		try:
			self._run_thread = threading.get_ident()
			asyn.Controller.run(self)
		finally:
			self._run_thread = None

	def stop(self):
		asyn.Controller.stop(self)
		# ought to release any blocked threads here


	def run_locally(self):
		""" Should we run on the local thread (bypassing injection)? """
		return (threading.get_ident() == self._run_thread
			or self._run_thread is None and not self._queue_idle)


	#
	# Inject-and-go: drop a call into the controller schedule and move on.
	#
	def inject(self, call, *args, **kwargs):
		""" Inject call(*args, **kwargs) into the controller and move on.

			This performs a call in the Controller thread (as a scheduled action).
			The calling thread does not wait for this and won't know when it's done.
		"""
		if self.run_locally():
			return call(*args, **kwargs)
		self._injector.post(call, args, kwargs)


	#
	# Inject-and-wait: inject, wait for completion, and return result (or raise).
	#
	def inject_wait(self, call, *args, **kwargs):
		""" Inject call(*args, **kwargs) into the controller and return or raise the result.

			This performs a call in the Controller thread (as a scheduled action),
			waits until the call is done, and returns the evaluated value.
			If the callable raises an exception, that is raised in the caller instead.
			Use this to inject a simple function call.
		"""
		if self.run_locally():
			return call(*args, **kwargs)
		cond = threading.Condition()
		reply = { 'error': None, 'value': None }

		def runner():
			with cond:
				try:
					reply['value'] = call(*args, **kwargs)
				except Exception as e:
					reply['error'] = e
				cond.notify()

		with cond:
			self.inject(runner)
			while reply['error'] is None and reply['value'] is None:
				cond.wait()
		if reply['error']:
			raise reply['error']
		return reply['value']


	#
	# Inject-and-wait-for-callout
	#
	def inject_callout(self, call, timeout=None, timeout_notify=None, *args, **kwargs):
		""" Inject call(*args, **kwargs), wait for a callout, and return its value or error.

			Call will receive a reply=callable keyword argument in addition to those given.
			It must arrange for a callout to that callable. The value passed to that
			is returned. If the reply callable receives an error context, that is raised instead.
			Use this to inject a sequence of callouts.
		"""
		assert threading.get_ident() != self._run_thread
		cond = threading.Condition()
		reply = { 'ctx': None }

		if timeout is not None:
			def catch_timeout(ctx=None):
				if timeout_notify is not None:
					timeout_notify()
				with cond:
					reply['ctx'] = ctx
					cond.notify()
			timer = self.schedule(catch_timeout, after=timeout)

		def catch_reply(ctx=None, value=None, *args):
			with cond:
				reply['ctx'] = ctx
				reply['value'] = value
				if timeout is not None:
					timer.cancel()
				cond.notify()

		with cond:
			kwargs['reply'] = asyn.Callable(callout=catch_reply)
			self.inject(call, *args, **kwargs)
			while reply['ctx'] is None:
				cond.wait()
		ctx = reply['ctx']
		if ctx.error:
			raise ctx.error
		elif ctx.state == 'TIMER':
			return None
		else:
			return reply['value']


#
# A Selectable that simply pulls objects off a deque and feeds them to a callback function.
#
class _Inject(asyn.Selectable):
	""" A Selectable that allows another thread to inject work into a Controller thread.

		Any call to self.post(whatever) is transformed into a call
		within the Controller's thread soon thereafter. This is a way
		to inject work into a Controller environment from another thread,
		and to interrupt any timer in that Controller.
	"""
	is_plumbing = True			# internal plumbing; skip in external views and lists

	def __init__(self, control):
		(self._r, self._w) = os.pipe()
		asyn.Selectable.__init__(self, control)
		self._q = deque()

	def fileno(self):
		return self._r

	def close(self):
		os.close(self._r)
		os.close(self._w)
		asyn.Selectable.close(self)

	def _wants_read(self):
		return True

	def _can_read(self):
		os.read(self._r, asyn.selectable.BUFSIZE)	# discard; it was just a wakeup call
		while True:		# atomically process queue elements
			try:
				sel, args, kwargs = self._q.popleft()
			except IndexError:
				return
			try:
				sel(*args, **kwargs)
			except Exception:
				pass

	def post(self, sel, args, kwargs):
		""" Forward sel(*args, *kwargs) to the Controller's thread.

			Any resulting result or exception will be ignored.
		"""
		self._q.append((sel, args, kwargs))
		os.write(self._w, b'x')
