import network

lines = ['local case_net_msg = {']
for m in network.Messages:
	lines += ['\t'+l for l in m.emit_unpack()]
lines += ['}']

print('\n'.join(lines))