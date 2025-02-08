#
# cyin.filter - menu generators/filters for Cynical Indigo 5 plugins
#
# Indigo calls a method in the plugin object to populate custom popup fields.
# We implement by instantiating a subclass of MenuFilter and asking it to
# deliver the goods. We implement a few common ones here, too.
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
import re

import indigo
import cyin
from cyin.core import log, debug, error


#
# Create an instance of the appropriate filter class for a given method
# and (optional) filter name. Also provides the active ConfigUI object.
# Returns None of the filter cannot be found.
#
def create(name, filter, ui):
	if name in _filters:
		return _filters[name](filter, ui)


#
# Base class of all Indigo filters.
# Subclasses are automatically registered for invocation (by class name) through
# the plugin attribute dispatcher. To excempt a base class, give it an _abstract
# attribute.
#
# The filter string, if present, can be of the form
#	filter;option1;option2=value2;...
# where the options are parsed and inserted into self.options for use by subclasses.
# Options are:
#	none		Add a "- no selection -" menu item, representing no choice.
#	other		Add a "Other..." menu item.
# Other options are available for subclasses to interpret as they wish.
#
_filters = { }

class _meta_MenuFilter(type):
	def __init__(cls, name, bases, content):
		type.__init__(cls, name, bases, content)
		if '_abstract' not in cls.__dict__:	# proper subclass of MenuFilter
			_filters[name] = cls

class MenuFilter(object, metaclass=_meta_MenuFilter):
	_abstract = True

	def __init__(self, filter, ui):
		self.ui = ui
		self._options = { }
		if filter:
			filters = filter.strip().split(';')
			self.filter = filters.pop(0)
			for option in filters:
				(key, s, value) = option.partition('=')
				self._options[key] = value if s else False
		else:
			self.filter = None

	def _evaluate(self):
		menu = self.evaluate()
		if menu:
			if self.option('none'):
				menu = [(0, self.option('none', "- no selection -"))] + menu
			if self.option('other'):
				menu.append(('_other', 'Other...'))
		return menu

	def option(self, name, default=True):
		if name in self._options:
			return self._options[name] or default

	def evaluate(self):
		return [(None, "-- ERROR --")]


#
# A version of MenuFilter that uses a subclass-provided generator to yield up
# the menu items.
#
tokenize = re.compile(r'(\d+)|(\D+)').findall
def natural_sort(s):
    return tuple(int(num) if num else alpha for num, alpha in tokenize(s))

class MenuGenerator(MenuFilter):
	_abstract = True

	def evaluate(self):
		return self.sort([item for item in self.generate()])

	def sort(self, values):
		""" Sort generated menu items as desired. Defaults to numeric-preference string sort. """
		return sorted(values, key=lambda s: natural_sort(s[1]))


#
# A simple "expression" parser that can form conjunction and disjunction
# of IOM-provided object lists. Accepts something like
#	self.myclass&indigo.sensor|self.anotherclass
# where & binds stronger than |. The string literals are handed to indigo.whatever.iter().
# A dash means "no object" and can be used to add a null value:
#	-|indigo.device
# keeps the "- no selection -" choice available. No, we don't do parentheses or negation.
#
# This is abstract. Subclass must provide 'collection' attribute to indicate
# source of data (indigo.devices, etc.) They may also override term() etc. to alter
# the way the filter string is parsed.
#
class IOMFilter(MenuFilter):
	_abstract = True

	def evaluate(self):
		return sorted(map(self.form, self.disj(self.filter)), key=lambda s: s[1])

	def form(self, id):
		if id == 0:
			return (0, '- no selection -')
		iom = self.collection[id]
		return (iom.id, iom.name)

	def disj(self, filter):
		(left, op, right) = filter.strip().partition('|')
		return (self.conj(left) | self.disj(right)) if op else self.conj(left)

	def conj(self, filter):
		(left, op, right) = filter.strip().partition('&')
		return (self.term(left) & self.conj(right)) if op else self.term(left)

	def term(self, filter):
		filter = filter.strip()
		# special case: "-" is the none/no selection item
		if filter == '-':
			return set([0])
			
		# check for name:value according to match_property
		(name, s, prefix) = filter.partition(':')
		if s:
			return set([iom.id for iom in self.collection.iter() if match_property(iom, name, prefix)])
		
		# default to Indigo collection filter
		return set([iom.id for iom in self.collection.iter(filter)])

def match_property(io, name, value):
	# state:statename -> presence of this named state
	if name == 'state':
		return value in io.states
	# otherwise name:prefix -> io has a property named name whose string value begins with value
	if hasattr(io, name):
		attr = getattr(io, name)
		return isinstance(attr, str) and attr.startswith(value)
	

#
# An IOMFilter for Indigo devices
#
class DeviceFilter(IOMFilter):
	collection = indigo.devices
	
class VariableFilter(IOMFilter):
	collection = indigo.variables
