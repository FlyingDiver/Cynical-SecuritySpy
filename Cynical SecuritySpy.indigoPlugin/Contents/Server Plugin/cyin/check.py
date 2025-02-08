#
# cyin.check - check functions for attribute descriptors.
#
# A checkrule can be added to the check= keyword argument of PluginProperty descriptors.
# It causes the checkrule to be applied to the attribute whenever UI is being validated.
#
# A checkrule is passed the property value as its (single) argument, as either converted
# to the property's static type or as returned by its dynamic evaluation formula.
# This may well not be a string.
# To approve the value, return None. To change the value but approve that substitute,
# return the new value. To disapprove, return a tuple (error message, new value),
# where the new value is optional. Note that this value is simply assigned to the
# attribute in the context of ConfigUI validation.
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
import indigo
import cyin
from cyin.core import log, debug, error
import socket
import re
import os


#
# Decorators for checkrules.
#
def checkrule(it):
	""" Decorator to tag all checkrule functions. """
	it._is_ui_check = True
	return it

def advisory(it):
	it._is_advisory = True
	return it


#
# Apply a clamping range.
# The min/max values must be compatible with the attribute type.
#
@checkrule
def check_range(min=None, max=None):
	""" Checkrule: value within range. """
	def checker(value):
		if min is not None and value < min:
			return ("%%s must not be smaller than %s" % min, min)	# clamp it
		if max is not None and value > max:
			return ("%%s must not be greater than %s" % max, max)	# clamp it
	return checker

check_int = check_range	# legacy


#
# Check for a UNIX path to an existing file
#
@checkrule
def check_path():
	""" Checkrule: a file exists at that path. """
	@advisory
	def checker(value):
		if not os.path.exists(value):
			return ("this file does not exist",)
	return checker


#
# Check for a valid Internet host name or number.
# The host doesn't need to be reachable.
#
@checkrule
def check_host(flags=0, type=0, serial=False):
	""" Checkrule: the value resolves as a host name. """
	@advisory
	def checker(value):
		if serial and value.startswith('/'):
			if not os.path.exists(value):
				return ("no such serial port",)
			return
		try:
			(host, _, port) = value.partition(':')
			socket.getaddrinfo(host, port, 0, type, 0, flags);
		except socket.error as e:
			if e.args[0] == socket.EAI_NONAME:
				return ("invalid network address: cannot find %s" % value,)
			else:
				return ("invalid network address: %s" % e.args[1],)
	return checker


#
# Check for a valid IP port number or name.
#
@checkrule
def check_port(flags=0, type=0):
	""" Checkrule: the value resolves as an IP port number. """
	def checker(value):
		try:
			socket.getaddrinfo('', str(value), 0, type, 0, flags);
		except socket.error as e:
			return ("invalid network port: %s" % e.args[1],)
	return checker


#
# Check that the (string) value matches an arbitrary regular expression.
#
@checkrule
def check_format(regex, error='invalid format', options=0):
	""" Checkrule: the value patches a regex pattern. """
	if isinstance(regex, str):
		if regex[-1] != '$':
			regex += '$'	# force full match
		regex = re.compile(regex, options)
	def checker(value):
		if not regex.match(value):
			return (error,)
	return checker


#
# Check that an arbitrary callable produces a non-None result.
# Raising an exception is considered a failure.
#
@checkrule
def check_makes(maker, error, *args, **kwargs):
	""" Checkrule: maker(*args, **kwargs) succeeds and returns non-None. """
	def checker(value):
		try:
			r = maker(value, *args, **kwargs)
			if not r:
				return (error,)
		except Exception as e:
			return (str(e),)
	return checker
