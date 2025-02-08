#
# asyn.utility - various minor utility enhancements
#
# These are mix-in classes that add canned functionality
# to uses of the asyn harness, all strictly optional.
#
# Copyright 2013-2016 Perry The Cynic. All rights reserved.
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
import asyn


#
# A mix-in class that implements an idle timer with arbitrary
# idle behavior.
#
DEFAULT_DELAY = 10 * 60			# 10 minutes idle
FOLLOWUP_DELAY = 20				# 20 seconds after active ping

class Idler(object):
	""" Inherit for automated idle time-out behavior.

		Call idle_activity() whenever you see evidence of activity.
		If idle_activity was not called for too long, self.idle() will be called.
		That method may do whatever is desired, but it should actively elicit some
		response from the peer. If another period elapses without any incoming traffic
		causing an idle_activity call, the idle_timeout method is called, at which
		point you should probably tear down the connection and start over.
	"""

	def __init__(self, control, delay=DEFAULT_DELAY, follow=FOLLOWUP_DELAY):
		self._idle_control = control
		self._idle_timer = None
		self.idle_set(delay=delay, follow=follow)

	def idle_set(self, delay=DEFAULT_DELAY, follow=FOLLOWUP_DELAY):
		""" Enable idle messages every delay seconds to probe connectivity. """
		self._idle_delay = delay
		self._idle_follow = follow
		self.idle_activity()

	def idle_cancel(self):
		if self._idle_timer:
			self._idle_timer.cancel()
			self._idle_timer = None

	def idle_control(self, enable, delay=DEFAULT_DELAY):
		if enable:
			self.idle_set(delay=delay)
		else:
			self.idle_cancel()

	def idle_activity(self):
		if self._idle_timer:
			self._idle_timer.cancel()
		self._idle_armed = False
		def trigger_idle(ctx):
			if self._idle_armed:
				self._idle_timer = None
				self.idle_timeout()
			else:
				self._idle_armed = True
				self._idle_timer = self._idle_control.schedule(trigger_idle, after=self._idle_follow)
				self.idle()
		self._idle_timer = self._idle_control.schedule(trigger_idle, after=self._idle_delay)

	def idle_timeout(self):
		pass
