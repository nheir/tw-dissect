import network

lines = ['local case_net_msg_type = {']
for m in network.Messages:
	lines += ['\t'+l for l in m.emit_unpack()]
lines += ['}']
lines += ['']
lines += ['local case_net_msg_system = {']
for m in network.System:
	lines += ['\t'+l for l in m.emit_unpack()]
lines += ['}']

print('\n'.join(lines))