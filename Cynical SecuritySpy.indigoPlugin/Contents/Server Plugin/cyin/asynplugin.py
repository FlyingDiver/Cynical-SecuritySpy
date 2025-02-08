#
# cyin.asynplugin - Indigo 5 plugin with asyn integration
#
# This brings the asyn runloop framework into an Indigo plugin,
# so we can use asyn-based modules with ease, and generally indulge
# in asynchronous and state-machine programming.
# Note that ConfigUI and button callbacks must be processed in their
# (separate) thread since they require synchronous replies. The injection
# feature of asyn takes care of this quite nicely.
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
import indigo

import cyin
import cyin.core
import cyin.debugging
import asyn
import asyn.inject
from cyin.core import debug
from cyin.debugging import diagnose, diagnostic_log


#
# A cyin.Plugin that is also an asyn.Controller.
# The indigo-fired thread runs the Controller loop.
#
class Plugin(cyin.Plugin, asyn.inject.Controller):
	""" A cyin.Plugin that is an asyn.Controller that automatically
		operates as the plugin's "concurrent thread".
		This allows the plugin to perform asynchronous I/O and timed
		scheduling without throwing Python threads around, and allows
		integration of asyn-based modules into Indigo plugins.
	"""
	#
	# Construction
	#
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		cyin.Plugin.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		asyn.inject.Controller.__init__(self)


	#
	# State management.
	#
	@diagnose
	def run_concurrent_thread(self):
		""" Indigo says, "Go!" We start the Controller runloop. """
		debug("plugin starting asyn operation")
		self.active = True
		self.run()

	@diagnose
	def stop_concurrent_thread(self):
		""" Indigo says, "Stop!" We stop the Controller and thus the main thread.

			Note that this automatically closes all Selectables in the plugin.
			But Selectable.close() is idempotent, so it's okay to also close them
			in your IOM.stop methods.
		"""
		self.inject(self.close)


	#
	# Dispatch CONCURRENT type Indigo calls to the Controller thread
	#
	@staticmethod
	def call_entry(type, method, *args, **kwargs):
		if type == "concurrent":
			def call_entry():
				with diagnostic_log():
					method(*args, **kwargs)
			cyin.plugin.inject(call_entry)
		else:
			return cyin.Plugin.call_entry(type, method, *args, **kwargs)


#
# A decorator to put the method call on the controller thread.
# If invoked on the controller thread, performs a zero-time reschedule.
#
def asyncmethod(method):
	return lambda *args, **kwargs: cyin.plugin.inject(diagnose(method), *args, **kwargs)

_cyin_action = cyin.action
def action(method):
	return _cyin_action(asyncmethod(method))
cyin.action = action	# override
