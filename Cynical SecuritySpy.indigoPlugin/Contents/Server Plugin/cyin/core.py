#
# cyin.core - Cynical core interface to Indigo 5+
#
# Copyright 2011-2016 Perry The Cynic. All rights reserved.
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
import traceback
import re

import indigo

import cyin


#
# A chance to reformat various types to look better when printed
#
_re_type = type(re.compile(''))

def irepr(whatever):
	if isinstance(whatever, indigo.Dict):
		return repr(dict(whatever))
	if isinstance(whatever, indigo.List):
		return repr(list(whatever))
	if isinstance(whatever, str):
		return whatever
	if isinstance(whatever, _re_type):
		return "<RE(%s)%d>" % (repr(whatever.pattern), whatever.flags)
	return repr(whatever)

def logformat(whatever):
	s = ' '.join(map(irepr, whatever))
	if s[0] == '^':
		import cyin.debugging
		s = s[1:] + '\n' + cyin.debugging.stack(drop=3)
	return s


#
# Careful comparison of indigo values.
# Note that indigo.List and .Dict do NOT obey standard Python rules!
#
def i_equal(s1, s2):
	if isinstance(s1, indigo.List):
		return list(s1) == list(s2)
	if isinstance(s1, indigo.Dict):
		return dict(s1) == dict(s2)
	return s1 == s2


#
# Unconditional logging
#
def log(*whatever, **whatkey):
	indigo.server.log(logformat(whatever), **whatkey)

def error(*whatever):
	indigo.server.log(logformat(whatever), isError=True)


#
# Debug logging
#
def debug(*whatever, **whatkey):
	if cyin.DEBUG:
		indigo.server.log(logformat(whatever), **whatkey)


#
# A file object that writes to Indigo's log
#
class LogWriter(object):

	def __init__(self, tag, logfunc):
		self._log = logfunc
		self._tag = tag
		self._buffer = ''

	def write(self, it):
		lines = (self._buffer + str(it)).split('\n')
		for full_line in lines[:-1]:
			self._log(self._tag, full_line)
		self._buffer = lines[-1]


#
# Create or return a folder by name.
# (type) is the canonical container (indigo.variables, indigo.devices, etc.)
# Returns None and makes nothing if name is false.
#
def make_folder(type, name):
	if not name:
		return None
	if name in type.folders:
		return type.folders[name]
	return type.folder.create(name)


#
# Turn a variable name into a variable by any means necessary.
# Specify "folder.variable" to create a variable in a named folder;
# the folder will be created if needed.
# The default value is applied (only) if we create the variable.
# Note that this goes purely by name; if the user renames our variable,
# we'll make a new one.
# If name is a number, it is directly taken as a variable ID.
# Returns None if name is false.
#
def variable(name, default="", folder=None):
	if name:
		if folder is None and isinstance(name, str):
			f, s, n = name.partition('.')		# folder.name
			if s:
				folder = f
				name = n
		if name in indigo.variables:			# return existing (in whichever folder it's in)
			return indigo.variables[name]
		else:									# create in specified folder and return
			if isinstance(name, str):
				return indigo.variable.create(name,
					value=default, folder=make_folder(indigo.variables, folder))
			else:
				error("no variable with ID", name)


#
# Method decorator to mark various callback methods.
# No callback forwarding will happen unless your method
# is decorated appropriately.
#
def action(operation):
	operation._method_type = 'action'
	return operation

def button(operation):
	operation._method_type = 'button'
	return operation

def checkbox(operation):
	operation._method_type = 'checkbox'
	return operation

def menu(operation):
	operation._method_type = 'menu'
	return operation
