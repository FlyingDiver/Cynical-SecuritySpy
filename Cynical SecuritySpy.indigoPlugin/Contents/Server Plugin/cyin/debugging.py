#
# cyin.debugging - debug support for cyin
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
from __future__ import with_statement
import sys
import re
from contextlib import contextmanager
import traceback

import indigo

import cyin
from cyin.core import log, error, debug
from functools import reduce


#
# Make tracebacks a bit prettier (and a lot less voluminous)
#
_re_trunc = re.compile(r'^.*cyin/.*plug.*\.py", line \d+, in call_entry\n[^\n]+\n', flags=re.S)
_re_shorten = re.compile(r'"/.*/Contents/', flags=0)

def _edit_trace(s):
	s = _re_trunc.sub('\n', s)			# remove anything upstream of call gate
	s = _re_shorten.sub( '".../', s)	# shorten source paths
	return s

def stack(limit=None, drop=0):
	""" Extract a stack trace from the calling location, dropping the top (drop) frames. """
	frames = traceback.extract_stack()
	if drop:
		frames = frames[:-drop]
	lines = traceback.format_list(frames)
	return _edit_trace(''.join(lines))


#
# Context manager and method decorator to force exception diagnosis to the log channel
#
class QuietError(Exception):
	""" An exception class to suppress diagnostic dumps.

		Raise QuietError(some-exception) to abort operation back to
		the call gate without triggering diagnostic dumps there.
		The idea is that the problem has already been handled at the
		raising site; we just want to quietly get back to Indigo now.
	"""
	pass

@contextmanager
def diagnostic_log(name=None):
	try:
		yield
	except QuietError:
		error("execution of %s abandoned" % (name or "operation"))
	except Exception as e:
		error("in %s:" % name if name else "error:",
			_edit_trace(traceback.format_exc()))

def diagnose(method):
	def diagnose_call(*args, **kwargs):
		with diagnostic_log(name=method.__name__):
			return method(*args, **kwargs)
	return diagnose_call


#
# A straight-forward point tracer to insert in trouble spots
#
def trace(always=False):
	if cyin.DEBUG or always:
		frames = traceback.format_stack()[:-2]
		frames = [frame for frame in frames if '/PlugIns/' not in frame]
		log("TRACEBACK\n" + _edit_trace(reduce(lambda s, t: s+t, frames)))


#
# Configure debug features from plugin config options.
# This behavior is consistent for all plugins using cyin.
#
_modules = []

def configure():
	# fetch debug-log settings from prefs and set for both us and Indigo's debugging
	previous = cyin.DEBUG
	cyin.plugin.debug = cyin.DEBUG = cyin.plugin.pluginPrefs.get("showDebugInfo", False)

	# announce changes in debug setting, but not changes from pre-setup default
	if previous != "initial":
		if previous and not cyin.DEBUG:
			log("debugging disabled")
		elif not previous and cyin.DEBUG:
			log("debugging enabled")
		cyin.debugging._reconfig = True

	# cancel any previously set module debug options
	for module in cyin.debugging._modules:
		module.DEBUG = None
	cyin.debugging._modules = []

	# (re)configure DEBUG values in select modules as per showInternalDebug pref
	if cyin.DEBUG:
		# implement new options
		internal_debug = cyin.plugin.pluginPrefs.get("showInternalDebug", '')
		if internal_debug:
			for module_name in internal_debug.split(','):
				module = sys.modules.get(module_name.strip())
				if module:
					if hasattr(module, "DEBUG"):	# if it has a "DEBUG" variable
						if not module.DEBUG:		# and it's off
							module.DEBUG = debug	# then set it to our debug function
							cyin.debugging._modules.append(module)
					else:
						error("module", module_name, "has no internal debug hook")
				else:
					error("module", module_name, "not found")
			if _modules:
				debug("debugging module%s:" % ('s' if len(_modules) > 1 else ''),
					', '.join([module.__name__ for module in _modules]))
