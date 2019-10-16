# Wireshark plug-in to dissect teeworlds traffic

This a WIP dissector for the teeworlds protocol.
It is written in Lua but could be ported to C for better performance.

## Installation

You have to add it to the plugins directory of wireshark. (see (https://wiki.wireshark.org/Lua/Examples)).

On linux, you have to add it to `~/.config/wireshark/plugins`.

Then to (re)load it, Menu -> Analyse -> Reload Lua Plugins.
