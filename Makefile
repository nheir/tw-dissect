all: dissector.lua

dissector.lua: constants.lua tools.lua huffman.lua netmsg_generated.lua core.lua
	cat $^ > $@

netmsg_generated.lua:
	python generate.py > $@