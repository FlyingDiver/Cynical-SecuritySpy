#
# asyn.controller - asyn Controller objects.
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
import os
import socket
import select
import fcntl
import sys
import time
import heapq

import asyn
from asyn import core
from asyn import selectable
from asyn import resolve

DEBUG = None


ctx_periodic = asyn.Context('PERIODIC')


#
# A dispatch controller. There should be one per thread.
#
class Controller(object):
	""" A dispatch controller. Every thread should have at most one.

		A Controller owns a set of Selectables and shepherds them along,
		dispatching I/O notifications and eventually causing calls to their
		various callouts.

		Controller manages a set of time-triggered Controller.Scheduled objects
		that effectively act as timers. Timers can be set, rescheduled, and cancelled.
		They fire through callouts.

		Controller also manages a single Controller.periodic callout that fires
		whenever Controller gets around to it. Use this to perform cleanup work
		or logging that has no time dependencies but needs to be done eventually.
		There is no high or low bound on the time between period callouts.

		While Controller provides convenience methods for creating suitable
		Selectable subclasses and servicing them, Selectables can also be
		created explicitly and submitted for servicing.

		There is no global state. Make a Controller and then ask it nicely.

		Controller lives in a single thread (the one that called its run() method).
		If your program is multi-threaded, you want the asyn.inject.Controller
		subclass that adds methods for shunting work onto that thread as needed.
	"""
	
	TIMERLIMIT = 1000		# max # of back-to-back timer dispatches before taking a break

	def __init__(self, **kwargs):
		""" Make an empty, ready-to-use Controller. """
		self._map = { }							# map of inserted Selectables
		self._schedq = []						# scheduled timer tasks
		self.periodic = asyn.Callable()			# irregular periodic callout
		self.running = False					# main run gate

	def close(self):
		""" Shut down the entire Controller.

			This closes all Selectables and removes all timers, leaving the Controller empty.
			This is usually only done when it's time to quit the program.
		"""
		self.stop()
		for item in list(self._map.values()):	# close all I/O dispatchers
			item.close()
		self._schedq = []						# clear timers
		self.periodic.clear_callouts()			# clear periodic callouts


	def run(self):
		""" Run the Controller loop until .stop() is called on it. """
		self.running = True
		while self.running:
			self.periodic.callout(ctx_periodic)
			self._dispatch()
			fds = self._map
			reads = [item for item in fds.values() if item._wants_read()]
			writes = [item for item in fds.values() if item._wants_write()]
			timeout = max(0, self._schedq[0].when - time.time()) if self._schedq else None
			assert timeout or reads or writes	# or else we're permanently stalled
			if DEBUG: DEBUG("select", timeout, reads, writes)
			(reads, writes, others) = select.select(reads, writes, [], timeout)
			if DEBUG: DEBUG("selected", reads, writes)
			for item in reads:
				if item.control:
					item._can_read()
			for item in writes:
				if item.control:
					item._can_write()
			self._dispatch()

	def stop(self):
		""" Stop running the Controller. Resume by calling run() again.

			Note that stop() must be called from the Controller's thread.
			If you need to stop from another thread, use asyn.inject.Controller
			and inject it.
		"""
		self.running = False


	#
	# Direct construction and insertion of some useful Selectables
	#
	def commands(self, callout=None, io=sys.stdin):
		""" Create a command-line channel (CommandSelectable) and return it. """
		sel = selectable.Command(self, io, callout=callout)
		if sel.fileno() <= 2:
			sel.keep_file()
		return sel

	def stream(self, file, callout=None):
		""" Take a file-like object and return its Selectable. This will dup(2) the fd. """
		return selectable.Stream(self, file, callout=callout)
	file = stream

	def datagram(self, socket, callout=None):
		return selectable.Datagram(self, socket, callout=callout)

	def connector(self, res, callout=None):
		return resolve.TCPConnector(self, res, callout=callout)

	def listener(self, res, callout=None):
		return resolve.TCPListener(self, res, callout=callout)


	#
	# insert/remove are currently driven from Selectable constructor and .close, so you
	# should never have to call them explicitly.
	#
	def insert(self, selectable):
		""" Insert a Selectable so it becomes eligible for I/O callbacks. """
		fd = selectable.fileno()
		fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
		if DEBUG: DEBUG("insert", selectable.fileno(), selectable)
		assert fd not in self._map
		self._map[fd] = selectable

	def remove(self, selectable):
		if DEBUG: DEBUG("remove", selectable.fileno(), selectable)
		del self._map[selectable.fileno()]


	#
	# Simple timed scheduling
	#
	class Scheduled(core.Callable):
		""" A time-scheduled callout.

			This is a Callable that gets called based on time passing.
			Scheduling is based on real time (UNIX epoch seconds).
			Scheduled objects are created automatically by Controller.schedule(),
			but can also be created explicitly (perhaps as subclasses) and submitted
			to Controller.schedule() explicitly. They can also be rescheduled by
			calling methods on their callout context during the callout, which provides
			for drift-less periodic timers.
		"""
		def __init__(self, when, callback):
			core.Callable.__init__(self, callback)
			self.when = when
			self.active = True
		def cancel(self):
			""" Cancel the timer. Callout will not be made. """
			self.active = False
		def __lt__(self, other):
			return self.when < other.when
		def __repr__(self):
			if self.active:
				return f'<Scheduled:{self.when}:{self._callbacks}>'
			else:
				return f'<Scheduled:DELETED:{self._callbacks}>'

	def schedule(self, entity, at=None, after=None):
		""" Schedule a one-shot callback at a future time.

			Entity may be an existing Scheduled object, or any callable to be wrapped
			into a new Scheduled object as its callout.
			Use at= for an absolute time, or after= for a relative (future) time.
			Either way, this returns a Scheduled object that you can use to cancel the timer.
		"""
		now = time.time()
		if at is not None:
			when = at
		elif after is not None:
			assert after >= 0
			when = now + after
		else:
			when = now
		if isinstance(entity, self.Scheduled):
			entity.when = when
			entity.active = True
		else:
			entity = self.Scheduled(when, entity)
		if DEBUG: DEBUG("schedule", entity)
		heapq.heappush(self._schedq, entity)
		return entity

	#
	# Dispatch all due scheduled tasks.
	# Cancelled events are still in the queue (but with active==False); discard those
	# as they pop to the front.
	# Non-cancelled events are called out to their Scheduled with a context that is
	# enriched with useful state fields. The context also holds a .reschedule() method
	# that can be used to turn a one-shot timer into repeating form without drift.
	# Note that a *very* tight reschedule may slow the main event loop to a crawl
	# though it won't entirely starve it.
	#
	def _dispatch(self):
		backstop = self.TIMERLIMIT
		while self.running and self._schedq:
			backstop -= 1
			if backstop < 0:
				if DEBUG: DEBUG("timers backSTOP after", TIMERLIMIT, "consecutive issued")
				return
			top = self._schedq[0]
			if not top.active:		# has been cancelled
				heapq.heappop(self._schedq)	# get rid of it
				if DEBUG: DEBUG("schedule drop", top)
				continue
			now = time.time()
			if top.when > now:
				if DEBUG: DEBUG("queue top", top, "not ready at", now)
				break
			heapq.heappop(self._schedq)
			class Ctx(asyn.Context):
				def reschedule(self, at=None, after=None):
					if at:
						self.control.schedule(self.sched, at)
					elif after:
						self.control.schedule(self.sched, at=self.when + after)	# no-drift
				def __repr__(self): return "<TIMER CTX:%r>" % self.sched
			if DEBUG: DEBUG("schedule dispatch", top)
			top.callout(Ctx('TIMER', sched=top, control=self, when=top.when, now=now))
