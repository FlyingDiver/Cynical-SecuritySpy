from __future__ import absolute_import
#
# asyn - A simple asynchronous event manager
#
# Asyn doesn't solve the world.
# It's meant to effectively (and stylishly) deal with common cases.
#
# Asyn provides runloop-style asynchronous processing through callback
# hierarchies. If you understand how select(2)/poll(2) work, you won't
# find this hard to work with.
# Controller is the run loop. Selectables manage file descriptors for
# the Controller. There's a simple timer facility. Everything's ultimately
# based on delivering callbacks to arbitrary Python callables.
#
# The one surprising feature is that Selectables have Scanners, which
# provide a processing facility for incoming input. Scannable.scan can be
# set to a Scanner object at any time, which lets you switch between parsing
# rule sets by switching Scanners. If no Scanner is set for a Selectable,
# an internal default is used, which usually delivers data as it arrives.
#
# Copyright 2010-2016 Perry The Cynic. All rights reserved.
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
from asyn.core import Context, Error, Callable
from asyn.selectable import Selectable, FilterCallable
from asyn.scan import Scannable
from asyn.controller import Controller
