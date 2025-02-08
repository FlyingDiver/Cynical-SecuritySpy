#
# cyin.eval - mixed mode expression evaluator for cyin
#
# This provides an eval/exec wrapper providing expression evaluation
# end name access to various cyin data sets. This notably includes
# Indigo variables, cyin devices, and the plugin object itself.
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
from __future__ import with_statement
from __future__ import absolute_import
from contextlib import contextmanager

import indigo

import cyin
from cyin import iom
from cyin.core import log, debug, error


#
# A read-only container for Indigo variables
#
class Variables(object):

	def __getitem__(self, name):
		return indigo.variables[name].value
	__getattr__ = __getitem__

	def __setitem__(self, name, value):
		var = indigo.variables[name]
		indigo.variable.updateValue(var, value=value)
	__setattr__ = __setitem__

	def __contains__(self, name):
		return name in indigo.variables


#
# A read-only container for cyin device objects
#
class Devices(object):

	def __getitem__(self, name):
		dev = cyin.device(name)
		if dev is None:
			raise AttributeError('no device named "%s"' % name)
		return dev
	__getattr__ = __getitem__

	def __contains__(self, name):
		return name in indigo.devices


#
# A read-only container for cyin plugin objects
#
class Plugins(object):

	def __getitem__(self, id):
		return iom.plugin_for(id, True)

	def __contains__(self, id):
		return id in iom._pluginmap


#
# A local name scope for in-plugin evaluation of expressions
#
class LocalScope(object):

	def __init__(self, values={}, auto_import=False):
		self._variables = Variables()
		self._devices = Devices()
		self._plugins = Plugins()
		self._locals = values
		self._auto_import = auto_import

	@property
	def plugin(self):
		return cyin.plugin

	@property
	def variables(self):
		return self._variables

	@property
	def devices(self):
		return self._devices

	@property
	def plugins(self):
		return self._plugins

	@property
	def modules(self):
		class Modules(object):
			def __getattr__(iself, name):
				return self._import(name)
		return Modules()

	def __getitem__(self, name):
		self._check_name(name)

		# previously set local variables always win
		if name in self._locals:
			return self._locals[name]

		# anything defined as an attribute here comes next
		if hasattr(self, name):
			return getattr(self, name)

		# if we have an Indigo variable by this name, use its value
		if name in self.variables:
			return self.variables[name]

		# try to import a module by that name and return it
		if self._auto_import:
			try:
				return self._import(name)
			except Exception:
				pass

		# no joy
		raise KeyError

	def __setitem__(self, name, value):
		self._check_name(name)
		self._locals[name] = value

	def __contains__(self, name):
		return name in self._locals

	def __len__(self):
		return len(self._locals)

	def _import(self, name):
		module = __import__(name, self, self, [], 0)	# or raise exception
		self._locals[name] = module
		return module

	def _check_name(self, name):
		if name[0] == '_':					# don't allow private names
			raise NameError("access to %s not allowed" % name)


#
# Default globals scope. Very limited, for safety's sake.
#
class GlobalScope(dict):

	def __init__(self):
		dict.__init__(self,
			log=log,
			debug=debug,
			error=error,
			indigo=indigo
		)


#
# Our canonical execution context management.
#
# The values argument directly initializes the locals map.
# Note that additional local names are programmed into LocalScope.
#
# The context argument determines the globals as follows:
#	True -> basic minimal context (indigo, logging)
#	A callable -> the result of calling it with no arguments
#	Anything else -> use as is
#
@contextmanager
def eval_context(values={}, context=True, auto_import=False):
	if context == True:
		context = GlobalScope()
	elif callable(context):
		context = context()
	yield (context, LocalScope(values, auto_import=auto_import))


#
# A single-expression evaluator.
#
def expression(form, check=False, **kwargs):
	if form:
		if check:
			return compile(form, "<string>", "eval")
		else:
			with eval_context(**kwargs) as (globals, locals):
				return eval(form, globals, locals)


#
# A general command execution engine.
# This supports locally defined variables (disappearing at the end).
#
def evaluate(form, check=False, **kwargs):
	if form:
		if check:
			return compile(form, "<string>", "exec")
		else:
			with eval_context(**kwargs) as (globals, locals):
				exec(form, globals, locals)
