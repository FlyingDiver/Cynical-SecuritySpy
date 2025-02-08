#
# cyin.attr - attribute descriptors for Cynical Indigo plugins
#
# Devices, actions, events, and plugins themselves have access
# to dictionaries of simple values that Indigo keeps for them.
# Instead of reading and writing those the normal way, they should
# be defined as attribute descriptors. Not only is this easier
# on the eyes, but configuration parameters can also be annotated
# with keywords that trigger a variety of automatic enhancements.
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
import cyin.eval
from cyin.core import log, debug, error
from cyin.debugging import QuietError


#
# A smart(er) version of a boolean converter
#
def smart_bool(value):
	if isinstance(value, str):
		return value.lower() in ["on", "yes", "true"]
	else:
		return bool(value)


#
# A tristate bool with a toggle option.
# It uses a canonical object value for its toggle state.
#
class _Toggle(object):
	def __str__(self):
		return "<toggle>"
Toggle = _Toggle()

def toggle_bool(value):
	""" A smart_bool that recognizes a toggle state. """
	if isinstance(value, str):
		v = value.lower()
		if v in ["on", "yes", "true"]:
			return True
		elif v in ["toggle", "switch", "invert"]:
			return Toggle
		else:
			return False
	elif value == Toggle:
		return Toggle
	else:
		return bool(value)


#
# Common features of attribute descriptors
#
class _DescField(object):
	""" The common behavior of all attribute descriptors.

		Type converts from source form to internal form. 'int' works well,
		but more esoteric callables like cyin.device work fine, too.
		Untype reverses the operation for writes, though most stores use strings
		internally and thus the default is sufficient. Type is not used for computed
		attribute values.

		Required indicates whether a value may be absent. It defaults to True,
		meaning a value is required. Set to False to make it optional. In this
		context, "present" means any value except None, the empty string, or the
		empty list.	(int(0) and False are considered present.) See _absent() below.

		If reconfigure is 'essential' (the default), a successful change to the
		attribute triggers object reconfiguration. If it is 'notify', the object's
		config_changed() method is called. Set this to False to indicate that the
		attribute does not affect the way the object is configured. If a default is
		given, it is automatically assigned to the attribute if it is missing, but
		this still counts as a change for reconfiguration purposes.
		
		Eval, if true, enables computed values. If the field content starts with
		an equal sign "=", the rest is interpreted as a Python expression whose
		value is computed whenever the field's value is fetched. For computed field
		values, checks are performed at runtime (every time) when the value is used.
		If dynamic_type is given, it is applied to computed values (instead of type).
		The value of eval determines the richness of the evaluation context - see eval.py.

		Check= specifies a list of checkrules that are applied, in order,
		to the value during ui validation. Checkrules are never applied to absent values.
		You may use canned checkrules from the cyin.check module, or write your own (see there).
		The value passed to checkrules is the final value of the attribute, whether
		dynamically computed or type-converted. Any substitution value returned must
		be of that final type.

		Any keyword construction arguments not understood by _DescField itself are
		preserved in a dict and can be retrieved as self.more(name). Keys can also
		be retrieved as field attributes unless they conflict with existing fields.
	"""
	def __init__(self, name=None, type=str, untype=str, dynamic_type=None,
			reconfigure='essential', required=True, default=None, eval=False, redirect={},
			format=None, check=(), **kwargs):
		self.name = name
		self.type = smart_bool if type == bool else type
		self.untype = untype
		self.dynamic_type = dynamic_type or type
		self.reconfigure = reconfigure
		self.required = required
		self.default = default
		self.eval = eval
		self.redirect = {redirect: redirect} if isinstance(redirect, str) else redirect
		self.format = format
		self.check = [it() if hasattr(it, '_is_ui_check') else it for it in check]
		# record any other keyword arguments
		self._more = kwargs
		for kw in kwargs:
			if not hasattr(self, kw):
				setattr(self, kw, kwargs[kw])

	def default_name(self, name):
		self.name = name

	def more(self, name, default=None):
		""" Return a named "extra" construction argument, if given, or a default. """
		return self._more.get(name, default)

	def check_rules(self, value, ui):
		""" Apply all checkrules and return the first failure. Return None on success. """
		for check in self.check:
			if not ui:
				if hasattr(check, '_is_advisory'):
					continue
			result = check(value)
			if result:
				if isinstance(result, tuple) and '%' in result[0]:	# flags an error
					result = (result[0] % self.name,) + result[1:]	# substitute field name
				return result

	def dynamic_value(self, value):
		""" Returns the dynamic formula in value, or None if it's a static value. """
		if self.eval and value and isinstance(value, str) and value[0] == '=':
			return value[1:]

	@staticmethod
	def _absent(value):
		from cyin.core import i_equal
		return value is None or value == '' or i_equal(value, [])

	def _apply_default(self, obj):
		""" Apply any attribute default to obj. Callable defaults are called on the object. """
		if self.default is not None:
			value = self.default(obj) if callable(self.default) else self.default
			setattr(obj, self.name, value)

	def _eval(self, value, obj=None):
		""" Compute the value of a field, check it, and return it or raise. """
		expr = self.dynamic_value(value)

		def fail(problem):
			""" Diagnose a dynamic evaluation error - nicely. """
			error('field "%s": %s' % (self.name, problem))
			if expr:
				error('while evaluating: %s' % (expr,))
			raise QuietError(problem)

		try:
			if expr:
				if obj is None:		# no target object; return raw string
					return value
				values = obj.eval_context()
				if hasattr(self, 'eval_context'):
					values.update(self.eval_context(obj))
				value = cyin.eval.expression(expr,
					values=values,
					context=self.eval,
					auto_import=True)
				if self._absent(value):
					if self.required:
						fail('missing value')
				elif self.dynamic_type:
					value = self.dynamic_type(value)
			else:
				if self._absent(value):
					if self.required:
						fail('missing value')
					else:
						return None
				else:
					value = self.type(value)
		except QuietError:
			raise
		except Exception as e:
			fail(str(e))
		failure = self.check_rules(value, ui=False)
		if isinstance(failure, tuple):	# (error [,replacement])
			fail(failure[0])
		elif failure is not None:	# replacement value (recoverable error)
			if failure != value:
				log('while evaluating field "%s": %s replaced with %s' % (
					self.name, value, failure))
				value = failure
		return value


def is_descriptor(it, type=None):
	""" Check whether an object is (a particular type of) a descriptor. """
	return isinstance(it, _DescField) and (type is None or it._desc_type == type)


#
# A plugin property ("pluginProps") of an IOM object.
# This applies to devices, actions, and events.
# (For actions, it uses its props instead. Action props cannot be written.)
#
class PluginProperty(_DescField):
	""" A descriptor to hook into an object's pluginProps dictionary. """
	_desc_type = "property"

	def __get__(self, obj, type):
		if hasattr(obj.io, 'pluginProps'):
			value = obj.io.pluginProps.get(self.name)
		else:	# action, use .props
			value = obj.io.props.get(self.name)
			if value is None and self.name == 'device':
				value = obj.io.deviceId
		if value in self.redirect:
			target = self.redirect[value]
			value = dict.get(self.name + target if target.startswith("_") else target)
		return self._eval(value, obj)

	def __set__(self, obj, value):
		if hasattr(obj.io, 'pluginProps'):
			props = obj.io.pluginProps
			props[self.name] = value
			obj.io.replacePluginPropsOnServer(props)
		else:
			raise AttributeError(self.name)

	def default_name(self, name):
		self.name = "xaddress" if name == "address" else name


#
# An auto-cached calculated (read-only) attribute, based on (only) PluginProperties
# and immutable values.
#
def cached(calc):
	""" A lazy-computed, auto-cached property of an IOM object.

		The calculation must only depend on PluginProperties and otherwise
		immutable values (constants or values that don't ever change).
		The value is computed when first needed, and is automatically
		recomputed (only) after ConfigUI has made changes to PluginProperties
		of the bearer object.
	"""
	class CachedProperty(object):
		def __get__(self, obj, type):
			# cache entries are (value, _config_level when made)
			if not hasattr(obj, '_cached'):
				obj._cached = { }
			if self not in obj._cached or obj._cached[self][1] < obj._config_level:
				obj._cached[self] = (calc(obj), obj._config_level)
			return obj._cached[self][0]
	return CachedProperty()


#
# A cached field derived from applying a callable to the field value:
#	foo = Cached('bar', func)
# is short for
#	@cyin.cached
#	def foo(self):
#		return func(self.bar)
# except that if the value is false, it is not evaluated.
#
def Cached(name, func):
	def fetch(obj):
		value = getattr(obj, name)
		return func(value) if value else value
	return cached(fetch)


#
# A device state.
# This must be an attribute of a Device object (cyin.iom).
# Note that Indigo restricts values assigned to device properties.
#
class DeviceState(_DescField):
	""" A descriptor to hook into a device's state dictionary. """
	_desc_type = "state"

	def __init__(self, type=str, untype=None, setter=None, **kwargs):
		super(DeviceState, self).__init__(type=type, untype=untype or type, **kwargs)
		self.setter = setter

	def __get__(self, obj, type):
		obj.refresh()
		return self.type(obj.io.states[self.name])

	def __set__(self, obj, value):
		if not obj.deleted:
			value = self.untype(value)
			if self.setter:		# custom
				return self.setter(obj, value)
			if self.format is not None and cyin.plugin.supports("uivalue"):
				if isinstance(self.format, str):
					uiValue = str(value) + self.format	# simple suffix
				else:
					uiValue = self.format(value, obj) # computation
				obj.io.updateStateOnServer(self.name, value, uiValue=uiValue)
			else:
				obj.io.updateStateOnServer(self.name, value)


#
# A descriptor for a plugin preference.
#
# This is commonly attached to the Plugin object itself, but will work
# virtually anywhere (e.g. a Device class). Multiple instances of the
# same attribute will access the same preference store, but that's confusing
# and should be avoided.
#
class PluginPreference(_DescField):
	""" A descriptor that hooks into the plugin's preference dictionary. """
	_desc_type = "preference"

	def __get__(self, obj, type):
		value = cyin.plugin.pluginPrefs.get(self.name)
		if value in self.redirect:
			target = self.redirect[value]
			value = cyin.plugin.pluginPrefs.get(self.name + target if target.startswith("_") else target)
		return self._eval(value, obj)

	def __set__(self, obj, value):
		cv = None if value is None else self.untype(value)
		cyin.plugin.pluginPrefs[self.name] = cv


#
# A descriptor for an Indigo variable.
# The name can either be fixed or in another descriptor.
# Note that you *can* make dynamic variable objects, which allows the user
# to put Python expressions into Indigo variables for evaluation. Obscure but useful...
#
class Variable(_DescField):
	""" A descriptor that addresses an fixed-name Indigo variable. """
	_desc_type = "variable"

	def _vname(self, obj):
		return self.name

	def _variable(self, obj):
		return cyin.variable(self._vname(obj), default=self.more("default", ""), folder=self.more("folder"))

	def __get__(self, obj, type):
		return self._eval(self._variable(obj).value)

	def __set__(self, obj, value):
		indigo.variable.updateValue(self._variable(obj), str(value))


class NamedVariable(Variable):
	""" A descriptor that addresses an Indigo variable identified indirectly by another attribute. """
	_desc_type = "variable"

	def _vname(self, obj):
		target = getattr(obj, self.name)
		if isinstance(target, indigo.Variable):
			target = target.name
		return target
