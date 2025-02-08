#
# asyn.selectable - asyn Selectables
#
# Copyright 2010-2018 Perry The Cynic. All rights reserved.
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
from collections import deque
import os
import socket
import errno

from asyn import Callable, Context
from asyn import scan

DEBUG = None


BUFSIZE = 4096	# default read buffer size

END = Context('END')		# canonical end-of-input context
CLOSE = Context('CLOSE')	# sent by self.close()


#
# Base class of all members in the select maps.
# Abstract.
#
class Selectable(Callable):
	""" Base class representing a file descriptor-based I/O activity.

		Selectable represents a file descriptor of some sort. Once inserted
		into a Controller, it becomes eligible for event calls as I/O activity
		becomes available for it.

		Selectable itself does not have an attribute that holds the file descriptor.
		The subclass must provide a fileno() method that returns it.

		Selectable itself has no read or write behavior. Subclasses define this.

		Subclasses of Selectable use their Callable personality to deliver input.

		Selectable sends out a 'CLOSE' context (with no arguments) when it is closed.

		The empty input condition is delivered separately through the _null_read
		method. In most situations, that's an end or error condition; but a few
		devices can continue to read after that. The default _null_read will close
		the Selectable; override it for odder handling.	All of this is quite UNIX-specific,
		of course.
	"""
	is_plumbing = False			# do not hide in external lists and views

	def __init__(self, control, callout=None):
		""" Construct a Selectable for a given Control. """
		Callable.__init__(self, callout=callout)
		self.control = control
		control.insert(self)

	def close(self):
		""" Shut down this Selectable, removing it from its Control.

			This is an unconditional close with prejudice. Any buffered
			data is discarded (not delivered). Since we're asynchronous,
			this means you won't generally know what made it and what was ditched.
			See self.shutdown for possibly better handling.
		"""
		if self.control:			# we're active
			self.callout(CLOSE)		# tell everyone we're dying
			self.control.remove(self) # remove from Controller
			self.control = None		# don't do this again

	def shutdown(self):
		""" Schedule this selectable for closing once all queued work is done.

			The default implementation knows of no state and thus closes immediately.
		"""
		return self.close()

	def _wants_read(self):
		""" Tell control that we want to read. """
		return False

	def _wants_write(self):
		""" Tell control that we want to write. """
		return False

	def _null_read(self):
		""" Default action for null reads is to close. May be overridden. """
		self.callout(END)
		self.close()

	# extensible representation for Selectables. Chain _repr() to add data
	def __repr__(self):
		try:
			return "<%s(%d):%s>" % (type(self).__name__, self.fileno(), self._repr())
		except:
			return "<%s(--):%s>" % (type(self).__name__, self._repr())

	def _repr(self):
		return hex(id(self))


	#
	# Shorthands to set up frequent activities.
	# These all add callouts to self and return the callable used,
	# so they can be cancelled by removing that from self.
	#
	def copy_to(self, dest, errors=None, pass_end=True):
		""" Take any data called-out by this and write it to dest.

			If errors= is set, pass any source errors to that callable.
			If pass_end is True (default), shut down dest when source
			reports the end.

			Returns the callout function used. Cancel the copy by removing
			that from source's callout.
		"""
		def copying(ctx, data=None, *args):
			if ctx.error:
				if errors:
					errors.callout(ctx)
			elif ctx.state == 'END':	# eox
				if pass_end:
					dest.shutdown()
			elif data:
				dest.write(data)
		self.add_callout(copying)
		dest.if_close(lambda: self.remove_callout(copying))
		return copying

	def if_state(self, state, action):
		""" Do something if a called-out Context has the given state. """
		def sensor(ctx, *args):
			if ctx.state == state:
				action(*args)
		self.add_callout(sensor)
		return sensor

	def if_end(self, action):
		""" Do something if END (of data) is called out. """
		return self.if_state('END', action)

	def if_close(self, action):
		""" Do something if CLOSE (of the Selector) is called out. """
		return self.if_state('CLOSE', action)


#
# A Selectable that owns a file object.
#
class IO(Selectable):
	""" A Selectable that directly owns a Python I/O object.

		Construct an IO with a file-like object (that has a fileno() method).
		As a special case, a bare int is accepted as an OS-level file descriptor.

		Closing the IO will close the I/O channel unless .keep_file() was called to preserve
		it, which leaves it alone (and owned by the caller).
		
		Note that there are many users of IO - not just Stream and Datagram.
	"""
	def __init__(self, control, io, callout=None):
		self.io = self._IOW(io) if isinstance(io, int) else io
		self._keep_file = False
		Selectable.__init__(self, control, callout=callout)

	def fileno(self):
		return self.io.fileno()

	def keep_file(self):
		""" Tell IO that closing it should not close the underlying file object. """
		self._keep_file = True

	def close(self):
		""" Close the Selectable and release the IO resource unless keep_file was called. """
		Selectable.close(self)
		if not self._keep_file:
			self.io.close()
	
	def write_flush(self):
		""" Default IO.flush_write does nothing; override where needed """
		pass

	class _IOW(object):
		def __init__(self, fd):
			self.fd = fd
		def fileno(self):
			return self.fd
		def close(self):
			os.close(self.fd)


#
# A Selectable that owns a stream I/O object.
#
class Stream(IO, scan.Scannable):
	""" A Selectable for stream-oriented posix file descriptors or File-like objects.
		
		Incoming data is fed to the scanner objects maintained by the Scannable
		personality.

		Outgoing data is buffered and sent to the I/O object as fast as it will go.
		There are currently no notifications of writability or queue-empty events,
		but you can call .shutdown() and the Stream will close after all pending
		data has been sent.
	"""
	def __init__(self, control, io, callout=None):
		IO.__init__(self, control, io, callout=callout)
		scan.Scannable.__init__(self)
		self._wbuf = b''
		self._shutdown = False

	def close(self):
		if self._wbuf:						# still have bytes to write
			if DEBUG: DEBUG(self, "deferring close for", len(self._wbuf), "bytes remaining")
			return self.shutdown()			# set shutdown flag; will self-close
		if DEBUG: DEBUG(self, "closing")
		super(Stream, self).close()
		self.read_flush()

	def _wants_read(self):
		return self.has_callouts()

	def _can_read(self):
		""" Notification that we may try to read from our file descriptor. """
		try:
			input = os.read(self.fileno(), BUFSIZE)
		except OSError as e:
			self.callout_error(e)
			return
		if not input:						# conditional EOF indicator
			self._null_read()
			return
		self._scan(input)

	def read_flush(self, discard=None):
		""" Throw out the read buffer. """
		self.flush_scan()

	def _wants_write(self):
		return self._wbuf

	def _can_write(self):
		""" Notification that we may try to write to our file descriptor. """
		try:
			if self._wbuf:
				written = os.write(self.fileno(), self._wbuf)
				self._wbuf = self._wbuf[written:]
			if not self._wbuf and self._shutdown:
				self.close()
		except OSError as e:
			if e.errno == errno.EAGAIN:	# called explicitly & unready to send
				return
			self.callout_error(e)

	def write(self, whatever):
		""" Add some bytes to the write queue and push them out. """
		self._wbuf += whatever
		self._can_write()

	def write_a(self, whatever):
		self.write(whatever.encode('ascii'))

	def shutdown(self):
		self._shutdown = True
		self._can_write()


#
# A Selectable for packet-oriented socket operations.
#
class Datagram(IO, scan.Scannable):
	""" A Selectable for packet-oriented sockets.

		Incoming packets are passed through the scanner machine ONCE. Packets are not
		queued, merged, or assembled. Datagram uses recvfrom and delivers the source address
		as part of the callout context. Any data not consumed by the scanners is delivered
		immediately as a DGRAM callout.

		Output buffering is packet-oriented, too - every call to write() produces
		a distinct packet write request as soon as the socket accepts writes.
		Datagram's shutdown() will throw out any queued packets. It's best-effort
		delivery we're promising, after all.
	"""

	def __init__(self, control, io, callout=None):
		IO.__init__(self, control, io, callout=callout)
		scan.Scannable.__init__(self)
		self._wqueue = deque()

	def _wants_read(self):
		return self.has_callouts()

	def _can_read(self):
		""" Receive a datagram and deliver it. """
		data, addr = self.io.recvfrom(BUFSIZE)
		if not self.scan or self.scan.scan(data, self.callout):	# not consumed
			ctx = Context('DGRAM', source=addr)
			self.callout(ctx, data)

	def _wants_write(self):
		return self._wqueue

	def _can_write(self):
		data, addr, flags = self._wqueue.popleft()
		try:
			sent = self.io.sendto(data, flags, addr)
			if sent != len(data):	# all or nothing - I guess nothing
				self.callout_error("incomplete datagram write: sent %d got %d" % (len(data), sent))
		except OSError as e:
			self.callout_error(e)

	def write(self, data, addr, flags=0):
		self._wqueue.append((data, addr, flags))


#
# A Selectable that implements a line-by-line command processor.
#
class Command(Stream):
	""" A Selectable for reading lines from somewhere (usually a tty device).

		As configured, this simply delivers text lines (newline delimited)
		to the callout without interpretation. Null reads are passed through
		if the input is a terminal device, but otherwise trigger closing.

		This is usually used on stdin for local command handling; but it
		works just fine with anything else, including a network connection.
		Just remember to send your output back to the underlying fd.
	"""

	_line = scan.Regex([(r'([^\n]*)\n', 'command')])

	def __init__(self, control, io, callout=None):
		Stream.__init__(self, control, io, callout=callout)
		self.scan = self._line


#
# A Raw Filter Callable.
#
class FilterCallable(Callable, scan.Scannable):
	""" A Callable that filters data bubbling up "raw" from an underlying Callable.

		This allows construction of a filter pipeline, allowing re-use of protocol
		drivers on top of data management filters for things such as compression or encryption.
		"Upstream" is towards the source; "downstream" is towards the consumer.
		
		FilterCallable is not a Selectable. It's designed to be pushed downstream of one
		and is duck-compatible with it.

		To work as the "source" object of a FilterCallable, a source must be Callable;
		it must have a control member that is an asyn.Controller; it must deliver
		data downstream using 'RAW' callouts; and it must send 'END' and 'CLOSE' callouts
		in the standard fashion. This is the informal "extended Selectable" protocol, though
		it could be implemented by anything that is driven by asyn.Controller and spontaneously
		calls out data.
		
		FilterCallable has a write_enable and read_enable flag. The default behavior is
		to pass data through, and thus ignores these flags. They exist to be used by
		subclasses that may use them to selectively enable one both directions.
	"""
	def __init__(self):
		Callable.__init__(self)
		scan.Scannable.__init__(self)
		self.upstream = None					# upstream data source (Callable)
		self.write_enable = False
		self.read_enable = False

	def open(self, source, callout=None):
		if DEBUG: DEBUG(self, "opens", source)
		self.control = source.control
		self.upstream = source
		source.add_callout(callout)

	def close(self):
		self.flush_scan()
		upstream = self.upstream
		if upstream:
			upstream.remove_callout(self.incoming, required=True)
			self.upstream = None
			if DEBUG: DEBUG(self, "filter close")
			upstream.close()

	def write(self, data):
		""" Default write operation: Just pass it up unchanged. """
		if self.upstream:
			self.upstream.write(data)

	def write_flush(self):
		if self.upstream:
			self.upstream.write_flush()

	def shutdown(self):
		self.write_flush()
		self.upstream.shutdown()

	def incoming(self, ctx, *args):
		""" Upstream tap. The default just passes the data through. """
		if ctx.error:
			return self.callout(ctx)
		if ctx.state == 'END':		# downstream disconnect
			self.close()
			self.callout(ctx)
		elif ctx.state == 'RAW':
			self._scan(args[0])
		else:
			self.callout(ctx, *args)

	def insert_filter(self, filter_class, uplink=None, push_back=None,
		write_enable=True, read_enable=True, *args, **kwargs):
		""" Create and insert a filter object into a FilterCallable.
		
			Specify uplink=(existing callout) to automagically replumb it
			and the scan filter onto the new filter. If uplink= is omitted or None,
			replumbing must be done manually.
			
			If push_back is passed, it prepends that data to the old upstream scan buffer
			and feeds the result back to the newly installed filter object (only).
			This gives a very limited form of do-over when a scan outcome indicates
			the need for an additional filter (e.g. TLS, compression etc.)
		"""
		filter = filter_class(self.upstream, *args, **kwargs)
		self.upstream.add_callout(filter.incoming)
		if uplink:
			self.upstream.remove_callout(uplink)
			old_scan = self.upstream.scan
		self.upstream = filter
		filter.write_enable = write_enable
		filter.read_enable = read_enable
		if uplink:
			self.upstream.add_callout(uplink)
			self.upstream.scan = old_scan
		if push_back is not None:
			buffer = self.flush_scan()
			if DEBUG: DEBUG("filter pushed back %d+%d bytes" % (len(push_back), len(buffer)))
			filter.incoming(scan.RAW, push_back + buffer)
		return filter

	@property
	def stack(self):
		""" Return the whole filter stack (downstream first). For debugging only """
		if self.upstream is None:
			return [self]
		try:
			return [self] + self.upstream.stack
		except AttributeError:	# no upstream.stack
			return [self] + [self.upstream]


#
# A forker with asyn bidirectional connection
#
class ForkPipe(Command):
	""" ForkPipe is a Selectable that launches and connects to a fork-child.

		The connection is bidirectional (a socketpair). You can read and write
		without fear; we're all asyn here, after all.
		The input is line-scanned by default. Change .scan for other processing.
	"""
	def __init__(self, control, child_action, callout=None):
		self.pid = 0
		(parent_fd, child_fd) = socket.socketpair()
		pid = os.fork()
		if pid == 0:	# child
			parent_fd.close()
			rc = child_action(child_fd)
			os._exit(rc or 0)
		self.pid = pid
		child_fd.close()
		Command.__init__(self, control, io=parent_fd, callout=callout)


class ProcessPipe(ForkPipe):
	""" A ForkPipe that executes a file.

		No shell is involved in the execution of the process (unless you put one
		in yourself). Environment is inherited.
	"""
	def __init__(self, control, path, args=[], callout=None):

		def execute(fd):
			os.dup2(fd.fileno(), 0)
			os.dup2(fd.fileno(), 1)
			fd.close()
			return os.execv(path, [path] + args)

		ForkPipe.__init__(self, control, execute, callout=callout)
