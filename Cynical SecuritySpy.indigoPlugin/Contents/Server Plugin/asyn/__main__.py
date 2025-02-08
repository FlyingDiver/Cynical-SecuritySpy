from __future__ import print_function
#
# Regression test for asyn
#
from collections import deque
import socket
import threading
import time

import asyn
import asyn.controller
import asyn.inject
import asyn.resolve


print('asyn.controller regression starting (this will take several seconds)...')


#
# Core infrastructure test
#
print('(asyn.core)')
class Test(object):

	def cb(self, result=None):
		def _cb(ctx, *args):
			assert ctx == self._ctx
			assert args == self._args
			self._set.append(_cb)
			return result
		return _cb

	def __call__(self, callable, ctx, args=(), result=None, called=[]):
		self._ctx = ctx
		self._args = args
		self._set = []
		res = callable.callout(ctx, *args)
		assert res == result
		assert self._set == called

test = Test()
cal = asyn.Callable()
ctx1 = asyn.Context('blah')
c0 = test.cb(result=None)
c1 = test.cb(result=1)
c2 = test.cb(result=2)
test(cal, ctx1)
test(cal, ctx1, args=(666, 'wallaby', [1,2,3]))	# nobody gets those arguments anyway
cal.set_callout(c1)
test(cal, ctx1, args=(6, 'foo'), result=1, called=[c1])
cal.set_callout(c0)
cal.add_callout(c2)
cal.add_callout(c1)
test(cal, ctx1, result=2, called=[c0,c2,c1])
cal.remove_callout(c2)
test(cal, ctx1, result=1, called=[c0,c1])
cal.set_callout_reduce(None)
test(cal, ctx1, result=[None, 1], called=[c0,c1])
cal.set_callout_reduce(lambda a, b: None)
test(cal, ctx1, result=None, called=[c0,c1])


#
# test injection wake-up
#
print('(injection)')
control = asyn.inject.Controller()

def backstop(ctx):
	print('INJECTION HEDGE FAILED')
control.schedule(backstop, after=5)	# in case it all fails
started = time.time()

def injected():
	assert abs(time.time() - started - 1) < 0.1
	return "wallaby!"
def injector():
	now = time.time()
	assert control.inject_wait(injected) == "wallaby!"
	assert time.time() - now < 0.1
threading.Timer(1, injector).start()
threading.Timer(2, lambda: control.inject(control.close)).start()
control.run()
assert time.time() - started < 2.1	# broke the select loop properly


#
# Test a mix of TCP connects, UDP messaging, and timers
#
print('(TCP/UDP messaging)')
control = asyn.Controller()

# test a mix of TCP connects, UDP messaging, and timers
tcp_schedule = [0.1, 0.9, 1, 1, 1.1, 1.11]
LIMIT=2 # seconds
PORT=55072
check = { 'tcp': 0 }

res_clnt = socket.getaddrinfo('localhost', PORT, 0, socket.SOCK_STREAM)
class Client(object):
	def __init__(self, ctx, socket=None):
		if ctx.state == 'connected':
			self.stream = control.stream(socket, callout=self.cb)
			self.stream.write(b'Hello, server!\n')
		elif ctx.state == 'CLOSE':
			pass
		else:
			print('CLIENT CONNECT UNEXPECTED', ctx)
	def cb(self, ctx, data=None):
		if ctx.state == 'RAW':
			if data == b'Hello, server!\n':
				self.stream.write(b'Good bye!\n')
			elif data == b'Good bye!\n':
				check['tcp'] += 1
				self.stream.close()
			else:
				print(f'UNEXPECTED RAW DATA {data=}')
		elif ctx.state == 'CLOSE':
			pass
		else:
			print('CLIENT UNEXPECTED', ctx)
for delay in tcp_schedule:
	control.schedule(lambda ctx: control.connector(res_clnt, callout=Client), after=delay)

def connect_server(ctx, socket=None):
	def do_server(ctx, data=None):
		if ctx.state == 'END':
			con.shutdown()
		elif ctx.state == 'RAW':
			con.write(data)	# echo back to client
		elif ctx.state == 'CLOSE':
			pass
		else:
			print('SERVER UNEXPECTED', ctx)
	if ctx.state == 'accept':
		con = control.stream(socket, callout=do_server)
	elif ctx.state == 'CLOSE':
		pass
	else:
		print('SERVER ACCEPT UNEXPECTED', ctx)

res_svr = socket.getaddrinfo('localhost', PORT, 0, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
server = control.listener(res_svr, callout=connect_server)
control.schedule(lambda ctx: server.close(), after=LIMIT)

def cb_dgram(ctx, data=None):
	if ctx.state == 'DGRAM':
		assert data == b'Walla Walhalla!'
	elif ctx.state == 'CLOSE':
		pass
	else:
		print('DGRAM UNEXPECTED', ctx)

res_dgram = socket.getaddrinfo('localhost', PORT, 0, socket.SOCK_DGRAM)[0]
sd = socket.socket(res_dgram[0], res_dgram[1], res_dgram[2])
sd.bind(res_dgram[4])
dgram = control.datagram(sd, callout=cb_dgram)
for delay in [0, 0, 0, 0.7, 1.1, 1.1]:
	control.schedule(lambda ctx: dgram.write(b'Walla Walhalla!', res_dgram[4]), after=delay)
control.schedule(lambda ctx: control.close(), after=LIMIT)

control.run()
assert check['tcp'] == len(tcp_schedule)


print('asyn.controller regression passed')
