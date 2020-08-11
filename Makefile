.PHONY: all

all: dissector.lua

dissector.lua: constants.lua tools.lua huffman.lua netmsg_generated.lua post_parsing.lua core.lua
	cat $^ > $@

netmsg_generated.lua: generate.py datatypes.py network.py
	python generate.py > $@

.PHONY: install

DIR:=$(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))

install: dissector.lua
	ln -s $(DIR)/dissector.lua ~/.config/wireshark/plugins/dissector.lua

.PHONY: clean

clean:
	rm ~/.config/wireshark/plugins/dissector.lua
	rm *.pyc
	rm *_generated.lua
	rm dissector.lua

