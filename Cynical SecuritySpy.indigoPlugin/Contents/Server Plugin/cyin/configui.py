#
# cyin.configui - manage configuration UI for Indigo 5 plugins
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
from xml.etree import ElementTree
import sys

import indigo
import cyin
import cyin.eval
import cyin.core
import cyin.confedit
from cyin.attr import is_descriptor
from cyin.core import log, debug, error

DEBUG = None


#
# A class to track Indigo's odd configuration-UI facility.
#
class ConfigUI(object):
	""" ConfigUI manages Indigo's odd configuration-UI facility.

		Cyin will create an instance of ConfigUI whenever Indigo presents
		configuration UI. It lives until the user dismisses the dialog. The subclass
		created is the UI attribute of the IOM class (not instance) being edited.
		The default is ConfigUI itself, which manages a set of default behaviors
		suitable for many cases.

		Start_ui is called when the dialog initializes. Check_ui is called whenever
		the user clicks the OK button. End_ui is called when the dialog is dismissed,
		whether successfully or not.

		Within a ConfigUI, each PluginProperty attribute descriptor declared in the
		underlying IOM class is available as an attribute. From ConfigUI, its value
		is the current config value rather than the pluginProps. Assign a value
		to change it. Assign a tuple (message, new-value) to set an error message
		and optionally change the value; this triggers rejection.

		You may refer to the underlying IOM class as self.iomtype, and to the
		particular object instance as self.iom. The latter is sadly None if this is
		an object creation dialog.

		Before check_ui is called, each config value is matched against its attribute
		Descriptor's checkrules. If any of these checks fail, the errors are reported
		to the user and check_ui is not called. This means that check_ui may assume that
		all declared properties are met.

		If your UI has a button, declare a method named after its callback and
		decorate it with @button. It will be passed nothing (other than self);
		use the attribute descriptors to read and write config values.
		You cannot flag errors from button methods, but you can change values.
		The same applies for checkboxes (using @checkbox).
	"""

	def __init__(self, cls):
		self.__dict__['_attributes'] = cls.attributes	# evade setattr trap
		self._descmap = cls._descmap
		self._ui_values = None
		self._type = cls


	#
	# Default behaviors. Override this if needed.
	#
	def start_ui(self):
		pass
	def end_ui(self, succeeds):
		pass

	def check_ui(self):
		pass

	@cyin.core.menu
	def updateUI(self):
		pass

	def docname(self):
		return self._type.__name__.lower()


	#
	# Private parts. Do not fondle.
	# These are called from the plugin callback jungle in plug.Plugin.
	#


	#
	# XML editor. Given the parsed XML from file, produce the XML Indigo sees.
	#
	@classmethod
	def _xml(cls, xml, name):
		# something changed in ElementTree between 2.6 and 2.7 here...
		if sys.version_info[0] == 2 and sys.version_info[1] < 7:
			uixml = ElementTree.XML(xml.encode('utf-8'))
		else:
			uixml = ElementTree.XML(xml)
		if uixml.find('SupportURL') is None and cyin.plugin.support_url:
			ElementTree.SubElement(uixml, 'SupportURL').text = "%s#%s" % (
				cyin.plugin.support_url, name.lower().replace(' ', ''))
		if uixml.tag == 'PluginConfig':
			cyin.confedit.add_debug(uixml)
		else:
			cyin.confedit.add_standard(uixml)
		result = ElementTree.tostring(cls.xml(uixml), encoding="utf-8")
		if DEBUG:
			DEBUG(result)
		return result


	#
	# Implicit UI state drivers. Private to ConfigUI; called from Plugin.
	#
	def _start_ui(self, init, cls, iom, dev):
		assert self._ui_values is None
		self._ui_values, self._ui_errors = init
		self.iomtype = cls
		self.iom = iom
		self.dev = dev
		self.start_ui()
		return (self._ui_values, self._ui_errors)

	def _check_ui(self, values):
		assert self._ui_values is not None
		(self._ui_values, self._ui_errors) = (values, indigo.Dict())
		self._check_fields()
		if not self._ui_errors:
			self.check_ui()
		if self._ui_errors:
			return (False, self._ui_values, self._ui_errors)
		else:
			if hasattr(self, 'description'):
				self._ui_values["description"] = self.description()
			return (True, self._ui_values)

	def _end_ui(self, values, cancelled):
		assert self._ui_values is not None
		self._ui_values = values
		self.end_ui(not cancelled)
		if self.iom and not cancelled:
			self.iom._config_level += 1
		self._ui_values = None

	# perform canned field checks
	def _check_fields(self):
		for fname, field in self._descmap.items():
			name = field.name
			if name == 'device' and 'device' not in self._ui_values:
				continue		# special exception (maps to deviceId field)
			value = self._ui_values[name]
			if field._absent(value):
				if field.required:
					setattr(self, fname, (name + ' is required',))
				continue
			# apply all checkrules
			expr = field.dynamic_value(value)
			if expr:
				try:
					cyin.eval.expression(expr, check=True)
				except Exception as e:
					setattr(self, fname, (str(e),))
			else:
				try:
					value = field.type(value)
				except Exception as e:
					setattr(self, fname, (str(e),))
					continue
				failure = field.check_rules(value, ui=True)
				if failure:
					setattr(self, fname, failure)
		# recalculate the magic 'address' field (if any)
		if hasattr(self.iomtype, 'display_address'):
			self._ui_values['address'] = getattr(self.iomtype, 'display_address')(self)


	#
	# Allow reads and writes from ConfigUI attributes that shadow the underlying
	# IOM's declared descriptor attributes.
	#
	def __getattr__(self, name):
		if name in self._attributes:
			desc = self._attributes[name]
			if name == 'device' and not 'device' in self._ui_values:
				return self.dev
			return desc._eval(self._ui_values.get(desc.name))
		raise AttributeError(name)

	def __setattr__(self, name, value):
		if name in self.__dict__:	# prefer existing local attribute
			object.__setattr__(self, name, value)
		elif name in self._attributes:	# underlying IOM has a descriptor
			desc = self._attributes[name]
			if isinstance(value, tuple):	# error indication: (msg, [new value])
				errmsg = value[0]
				if errmsg and errmsg[0] == '!':
					errmsg = errmsg[1:]
					self._ui_errors["showAlertText"] = errmsg
				self._ui_errors[desc.name] = errmsg
				if len(value) > 1:
					self._ui_values[desc.name] = value[1]
			else:
				self._ui_values[desc.name] = value
		else:	# not a descriptor, not present - create locally
			object.__setattr__(self, name, value)


	#
	# The default xml edit behavior.
	# Subclasses may interpose and inherit or replace it.
	# Do keep in mind that in Indigo 5, this happens before we get config values
	# to play with. (Indigo 6 gets the values first.)
	#
	@classmethod
	def xml(cls, uixml):
		""" Default ConfigUI XML processor.

			This takes an ElementTree.Element representing the <ConfigUI> or
			<PluginConfig> element. It performs any edits it likes and returns
			a new (or edited old) Element representing the XML to be sent to
			Indigo for display.

			This implementation scans through all <Field> elements and tries
			to locate a subclass of FieldEditor named after the Field type.
			If so, we instantiate it and ask it to edit the field. Field editors
			may add additional fields, but cannot "reach across" and change
			other fields. This is meant to be a localized editing facility.
		"""
		new = ElementTree.Element(uixml.tag, attrib=uixml.attrib)
		rseq = 1
		for field in uixml:
			new.insert(len(new), field)
			if field.tag == 'Field':
				id = field.get('id')
				if id is None:
					field.set('id', 'AUTO_%d' % rseq)
					rseq += 1
				editor = cyin.confedit.editor(field.get('type'))
				if editor:
					editor(new, field).edit()
		return new
