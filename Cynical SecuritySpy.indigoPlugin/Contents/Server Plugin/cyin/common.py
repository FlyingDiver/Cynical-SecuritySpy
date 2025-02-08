from __future__ import absolute_import
#
# cyin.common - common features of cyin-based plugins
#
# Copyright 2012-2016 Perry The Cynic. All rights reserved.
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
import cyin
import cyin.eval
from cyin.attr import PluginProperty
from cyin.core import log, debug, error


#
# Feature edit driver
#
def add_features(plugin):
	add_scripting(plugin)


#
# Add common scripting actions and behaviors
#
def add_scripting(plugin):
	plugin.add_action("COMMON_s1", Name=" - ")
	plugin.add_action("scripting",
		Name="Python Script",
		CallbackMethod="do_script",
		ConfigUIRawXml="""
			<ConfigUI>
				<SupportURL>http://www.cynic.org/indigo/plugins/info/common_features.html#doscript</SupportURL>
				<Field id="script" type="textfield">
					<Label>Script:</Label>
				</Field>
				<Field id="device" type="menu">
					<List class="self" method="DeviceFilter" filter="self;none"/>
					<Label>Device:</Label>
				</Field>
			</ConfigUI>
		"""
	)

	class Scripting(cyin.Action):
		script = PluginProperty()
		device = PluginProperty(type=cyin.device, required=False)

		@cyin.action
		def perform(self):
			cyin.eval.evaluate(self.script, values={
				"self": self,
				"device": self.device
			})
