#
# cyin.confedit - edit and manipulate Indigo's ConfigUI XML
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
from xml.etree import ElementTree

import indigo
import cyin
import cyin.core
from cyin.attr import is_descriptor
from cyin.core import log, debug, error


#
# A framework for editing a single field definition in a ConfigUI XML.
#
_editors = { }

def editor(type_name):
	return _editors.get('FieldType_' + type_name)

class _meta_FieldEditor(type):
	def __init__(cls, name, bases, content):
		type.__init__(cls, name, bases, content)
		if '_abstract' not in cls.__dict__:	# proper subclass of FieldEditor
			_editors[name] = cls

class FieldEditor(object, metaclass=_meta_FieldEditor):
	_abstract = True

	def __init__(self, top, field):
		self.top = top
		self.field = field
		self.id = field.get('id')
		label = field.find('Label')
		self.label = None if label is None else label.text

	def get(self, name):
		return self.field.get(name)

	def find(self, tag):
		return self.field.find(tag)

	def add_field(self, suffix="__", type=None, **kwargs):
		return ElementTree.SubElement(self.top, 'Field',
			id=self.id + suffix, type=type, **kwargs)


#
# The standard XML edit for menu fields (type="menu")
#
class FieldType_menu(FieldEditor):

	def edit(self):
		if self.get('menu_other') == "true":
			# append an "Other foobar" text field
			other = self.add_field(suffix="_other", type='textfield',
				visibleBindingId=self.id, visibleBindingValue="_other")
			ElementTree.SubElement(other, 'Label').text = ''
			# arrange for an "Other..." option
			listsub=self.find('List')
			if list:
				if listsub.find('Option') is not None:	# contains list of options
					ElementTree.SubElement(listsub, 'Option', value='_other').text = "Other..."
				elif listsub.get('method'): # dynamic list
					listsub.set('filter', listsub.get('filter', '') + ';other')
				else:
					error("internal error: list edit failed for", self.id)


#
# The label type simply provides the blindingly obvious <Label> content,
# copying attributes into that.
#
class FieldType_label(FieldEditor):

	def edit(self):
		if self.field.text:
			label = ElementTree.SubElement(self.field, 'Label')
			label.text = self.field.text
			self.field.text = None
			for name, value in self.field.attrib.items():
				label.set(name, value)


#
# Add the canonical debug ConfigUI.
# This should be matched with equivalen attribute definitions in Plugin et al
#
def add_debug(uixml):
	debug_additions = ElementTree.XML("""
		<additions>
			<Field type="separator"/>
			<Field id="showDebugInfo" type="checkbox" defaultValue="false"
				tooltip="Check to get many more log messages.">
				<Label>Debug:</Label>
				<Description>Enable debug messages.</Description>
			</Field>
			<Field id="showInternalDebug" type="textfield" defaultValue=""
				visibleBindingId="showDebugInfo" visibleBindingValue="true"
				alwaysUseInDialogHeightCalc="true"
				tooltip="If you don't know what to put here, leave it alone.">
				<Label>Debug Modules:</Label>
			</Field>
		</additions>
	""")
	for n in range(0, len(debug_additions)):
		uixml.insert(len(uixml), debug_additions[n])


#
# Arrange for common additions to ConfigUI sections
#
def add_standard(uixml):
	# add a hidden "description" field
	ElementTree.SubElement(uixml, 'Field', id='description', type='textfield', hidden='true')
