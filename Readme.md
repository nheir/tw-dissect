# Wireshark plug-in to dissect teeworlds traffic

This a WIP dissector for the teeworlds protocol.
It is written in Lua but could be ported to C for better performance.

## Installation

You have to build the file `dissector.lua` first, using the command `make`.

Then add it to the plugins directory of wireshark. (see (https://wiki.wireshark.org/Lua/Examples)).

On linux, you have to add it to `~/.config/wireshark/plugins`.

Then to (re)load it, Menu -> Analyse -> Reload Lua Plugins.

## Similar projects

There is a [dissector from 2015](https://github.com/fstd/wireshark/blob/twdis/epan/dissectors/packet-tw.c) written by [fstd](https://github.com/fstd) for the 0.6 protocol.
It is written in C and based on an outdated wireshark base.
There is a port to the new wireshark version with even less functionallity and a [binary release](https://github.com/ChillerDragon/wireshark/releases).


[libtw2](https://github.com/heinrich5991/libtw2) by [heinrich5991](https://github.com/heinrich5991) also has a [dissector written in rust](https://github.com/heinrich5991/libtw2/tree/master/wireshark-dissector).
