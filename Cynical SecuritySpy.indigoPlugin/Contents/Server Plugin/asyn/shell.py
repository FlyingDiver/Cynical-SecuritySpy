from __future__ import print_function
#
# shell - generic command shell driver
#
# Copyright 2010-2012,2015-2016 Perry The Cynic. All rights reserved.
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
import re
import sys
import os
import time
import code
import inspect


#
# An exception to escape back to the command loop
#
class Error(Exception):
	pass


def onoff(s):
	return s in ['on', 'ON', 'yes', 'YES']


def internal(f):
	f._internal = True
	return f


#
# A command shell
#
class Shell(object):
	""" A command shell. """
	COMMENT = '#'	# comment leader string. Override in subclass to change

	def __init__(self, control, path=None, quiet=False, context=globals()):
		self.control = control
		self.path = path
		if path:
			try:
				io = open(os.path.expanduser(path), "r")
			except IOError as e:
				if not quiet:
					print(e)
				return
		else:
			io=sys.stdin
		self.commands = control.commands(io=io, callout=self._cmd)
		self._context = context
		self._console = code.InteractiveConsole(self._context)

	@internal
	def fail(self, *args):
		raise Error(' '.join(map(str, args)))

	@internal
	def write(self, stuff):
		self.commands.write_a(stuff)

	def _end(self):
		self.control.close()

	def _prescreen(self, line):
		return False

	def _prefix(self, args):
		pass

	def _cmd(self, ctx, line=None):
		if ctx.error:
			print(ctx.error)
		elif ctx.state == 'END':
			if not self.path:
				self._end()
		if not line or not line.strip():
			return
		try:
			if self.path:
				print(".. %s" % line)
			if self.COMMENT and line.startswith(self.COMMENT):
				return
			if line[0] == '!':
				self._console.push(line[1:])
			elif line[0] == '<' or line[0] == '.':
				self.do(line[1:].strip())
			elif self._prescreen(line.rstrip()):
				pass
			elif not self._invoke(self._parse(line)):
				print("? %s" % line)
		except Error as e:
			print(e)
		sys.stdout.flush()

	def _parse(self, line):
		head, _, tail = line.partition('=')
		args = head.split(None)
		if tail:
			args.append(tail)
		return args

	def _invoke(self, args):
		self._prefix(args)
		cmd = []
		func = None
		while args:
			cmd.append(args.pop(0))
			name = "_".join(cmd)
			if hasattr(self, name):
				func = getattr(self, name)
			elif hasattr(self, name + "_"):
				func = getattr(self, name + "_")
			if func:
				try:
					func(*args)
					return True
				except TypeError as e:
					raise Error(e)


	#
	# Administrative commands
	#
	def do(self, source):
		""" Read commands from a file, recursively. """
		type(self)(self.control, path=source, context=self._context)

	def help(self):
		""" List available commands. """
		commands = { }		# method: [list of names]
		for name, method in inspect.getmembers(self, inspect.ismethod):
			if name[0] == '_':		# ignore _foo (internal)
				continue
			if hasattr(method, '_internal'):	# ignore @internal methods
				continue
			if method not in commands:
				commands[method] = []
			commands[method].append(name.replace("_", " ").strip())
		for method in commands:
			commands[method].sort(reverse=True)

		def row(label, description):
			print(label.ljust(20), description if description else "(unknown)")

		for method, names in sorted(commands.items(), key=lambda p: p[1][0]):
			row(", ".join(names).ljust(20), inspect.getdoc(method))

		if self.COMMENT:
			row(self.COMMENT, "Comment line (ignored).")
		row(".", inspect.getdoc(self.do))
		row("!", "Evaluate some Python code.")
