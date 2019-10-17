-- dissector.lua
-- A wireshark plug-in to dissect teeworlds traffic

tw_proto=Proto("Teeworlds", "Teeworlds")

PACKET_GETLIST = "\xff\xff\xff\xffreq2"
PACKET_LIST =    "\xff\xff\xff\xfflis2"

PACKET_GETINFO = "\xff\xff\xff\xffgie3"
PACKET_INFO =    "\xff\xff\xff\xffinf3"

NET_CTRLMSG_TOKEN = 5

local Const = {
  NETMSG_NULL=0
}
for i,k in ipairs{
    -- NETMSG_NULL=0,

    -- the first thing sent by the client
    -- contains the version info for the client
    'NETMSG_INFO',

    -- sent by server
    'NETMSG_MAP_CHANGE',      -- sent when client should switch map
    'NETMSG_MAP_DATA',        -- map transfer, contains a chunk of the map file
    'NETMSG_SERVERINFO',
    'NETMSG_CON_READY',       -- connection is ready, client should send start info
    'NETMSG_SNAP',            -- normal snapshot, multiple parts
    'NETMSG_SNAPEMPTY',       -- empty snapshot
    'NETMSG_SNAPSINGLE',      -- ?
    'NETMSG_SNAPSMALL',       --
    'NETMSG_INPUTTIMING',     -- reports how off the input was
    'NETMSG_RCON_AUTH_ON',    -- rcon authentication enabled
    'NETMSG_RCON_AUTH_OFF',   -- rcon authentication disabled
    'NETMSG_RCON_LINE',       -- line that should be printed to the remote console
    'NETMSG_RCON_CMD_ADD',
    'NETMSG_RCON_CMD_REM',

    'NETMSG_AUTH_CHALLANGE',  --
    'NETMSG_AUTH_RESULT',     --

    -- sent by client
    'NETMSG_READY',           --
    'NETMSG_ENTERGAME',
    'NETMSG_INPUT',           -- contains the inputdata from the client
    'NETMSG_RCON_CMD',        --
    'NETMSG_RCON_AUTH',       --
    'NETMSG_REQUEST_MAP_DATA',--

    'NETMSG_AUTH_START',      --
    'NETMSG_AUTH_RESPONSE',   --

    -- sent by both
    'NETMSG_PING',
    'NETMSG_PING_REPLY',
    'NETMSG_ERROR',

    'NETMSG_MAPLIST_ENTRY_ADD',-- todo 0.8: move up
    'NETMSG_MAPLIST_ENTRY_REM',
  } do
  Const[k] = i
end

for k,v in pairs{
  NETSENDFLAG_VITAL=1,
  NETSENDFLAG_CONNLESS=2,
  NETSENDFLAG_FLUSH=4,
} do
  Const[k] = v
end

for k,v in pairs{
  NET_MAX_CHUNKHEADERSIZE = 3,

  -- packets
  NET_PACKETHEADERSIZE = 7,
  NET_PACKETHEADERSIZE_CONNLESS = 9, -- NET_PACKETHEADERSIZE + 2,
  NET_MAX_PACKETHEADERSIZE = 9, -- NET_PACKETHEADERSIZE_CONNLESS,

  NET_MAX_PACKETSIZE = 1400,
  NET_MAX_PAYLOAD = 1409, -- NET_MAX_PACKETSIZE-NET_MAX_PACKETHEADERSIZE,

  NET_PACKETVERSION=1,

  NET_PACKETFLAG_CONTROL=1,
  NET_PACKETFLAG_RESEND=2,
  NET_PACKETFLAG_COMPRESSION=4,
  NET_PACKETFLAG_CONNLESS=8,

  NET_MAX_PACKET_CHUNKS=256,

  -- token
  NET_SEEDTIME = 16,

  NET_TOKENCACHE_SIZE = 64,
  NET_TOKENCACHE_ADDRESSEXPIRY = 16, -- NET_SEEDTIME,
  NET_TOKENCACHE_PACKETEXPIRY = 5,
} do
  Const[k] = v
end

for k,v in pairs{
  NET_TOKENFLAG_ALLOWBROADCAST = 1,
  NET_TOKENFLAG_RESPONSEONLY = 2,

  NET_TOKENREQUEST_DATASIZE = 512,

  NET_CTRLMSG_KEEPALIVE=0,
  NET_CTRLMSG_CONNECT=1,
  NET_CTRLMSG_CONNECTACCEPT=2,
  NET_CTRLMSG_ACCEPT=3,
  NET_CTRLMSG_CLOSE=4,
  NET_CTRLMSG_TOKEN=5,
} do
  Const[k] = v
end


function unpack_int(tvb, pos)
  local buf = tvb:raw(pos,math.min(5,tvb:len()-pos))
  buf = {buf:byte(1, -1)}
  local i = 1
  local Sign = bit.band(bit.rshift(buf[i], 6), 1)
  local res = bit.band(buf[i], 0x3F)

  local shift = 6
  for _=1,4 do
    if bit.band(buf[i], 0x80) == 0 then
      break
    end
    i = i+1

    res = bit.bor(res, bit.lshift(bit.band(buf[i], 0x7F), shift))

    shift = shift + 7
  end

  res = bit.bxor(res, -Sign)
  return res, i
end

function tw_proto.dissector(tvb,pinfo,tree)
  local code
  local pos
  local subtree
  local branch
  local stub
  local length
  local unknown
  local i

  unknown=0
  pos=0
  stub=tree:add(tw_proto, tvb(), "Teeworlds")

  local flags = bit.rshift(tvb(0,1):uint(),2)
  if bit.band(flags, Const.NET_PACKETFLAG_CONNLESS) ~= 0 then
    stub:append_text(" Connless packet")
    stub:add(tvb(0,1), "Packet Version: " .. bit.band(tvb(0,1):uint(), 0x03))
    stub:add(tvb(1,4), "Recv token: " .. tvb(1,4):uint())
    stub:add(tvb(5,4), "Send token: " .. tvb(5,4):uint())

    local packet_header = tvb:raw(9,8)
    if packet_header == PACKET_GETINFO then
      local stub = stub:add(tvb(9), "Get Info packet")
      local pos = 17
      local token, length = unpack_int(tvb, pos)
      stub:add(tvb(pos, length), "Browser token: " .. token)
      pos = pos + length
    elseif packet_header == PACKET_INFO then
      local stub = stub:add(tvb(9), "Info packet")
      local pos = 17

      local token, length = unpack_int(tvb, pos)
      stub:add(tvb(pos, length), "Browser token: " .. token)
      pos = pos + length

      local version = tvb(pos):stringz()
      stub:add(tvb(pos, tvb(pos):strsize()), "Version: " .. version)
      pos = pos + tvb(pos):strsize()

      local name = tvb(pos):stringz()
      stub:add(tvb(pos, tvb(pos):strsize()), "Name: " .. name)
      pos = pos + tvb(pos):strsize()

      local hostname = tvb(pos):stringz()
      stub:add(tvb(pos, tvb(pos):strsize()), "Hostname: " .. hostname)
      pos = pos + tvb(pos):strsize()

      local map = tvb(pos):stringz()
      stub:add(tvb(pos, tvb(pos):strsize()), "Map: " .. map)
      pos = pos + tvb(pos):strsize()

      local gametype = tvb(pos):stringz()
      stub:add(tvb(pos, tvb(pos):strsize()), "Gametype: " .. gametype)
      pos = pos + tvb(pos):strsize()
    elseif packet_header == PACKET_GETLIST then
      local stub = stub:add(tvb(9), "Get list packet")
    elseif packet_header == PACKET_LIST then
      local stub = stub:add(tvb(9), "List packet")
      local pos = 17
      local num_servers = (tvb:len() - pos) / 18
      for i=1,num_servers do
        local ip
        local port
        if tvb:raw(pos,12) == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" then
          ip = tvb(pos+12,4):ipv4()
        else
          ip = tvb(pos,16):ipv6()
        end
        port = tvb(pos+16,2):uint()
        stub:add(tvb(pos,18), string.format('%s:%d', ip, port))
        pos = pos + 18
      end
    end
  else
    stub:add(tvb(0,2), "Ack Version: " .. bit.band(tvb(0,2):uint(), 0x03ff))
    stub:add(tvb(2,1), "Number of chunk: " .. tvb(2,1):uint())
    local token = tvb(3,4):int()
    if token ~= -1 then
      token = tvb(3,4):uint()
    end
    stub:add(tvb(3,4), "Token: " .. token)

    if bit.band(flags, Const.NET_PACKETFLAG_CONTROL) ~= 0 then
      stub:append_text(" Control Message")
      local control_msg = tvb(7,1):uint()
      if control_msg == Const.NET_CTRLMSG_TOKEN then
        stub:set_text("Teeworlds Control Message Token")
        stub:add(tvb(8,4), "with token: " .. tvb(8,4):uint())
      elseif control_msg == Const.NET_CTRLMSG_CONNECT then
        stub:set_text("Teeworlds Control Message Connect")
        stub:add(tvb(8,4), "with token: " .. tvb(8,4):uint())
      elseif control_msg == Const.NET_CTRLMSG_CLOSE then
        stub:set_text("Teeworlds Control Message Close")
        if tbv:len() > 8 then
          local string_end = tvb(8):strsize()
          stub:add(tvb(8, string_end), "Reason: " .. tvb:raw(8, string_end))
        end
      elseif control_msg == Const.NET_CTRLMSG_ACCEPT then
        stub:set_text("Teeworlds Control Message Accept")
      elseif control_msg == Const.NET_CTRLMSG_CONNECTACCEPT then
        stub:set_text("Teeworlds Control Message Connect Accept")
      elseif control_msg == Const.NET_CTRLMSG_KEEPALIVE then
        stub:set_text("Teeworlds Control Message Keepalive")
      end
    else
      pos = Const.NET_PACKETHEADERSIZE
      local stub = stub:add(tvb(pos), "Message")
      local data = tvb:raw(pos)
      local compressed = bit.band(flags, Const.NET_PACKETFLAG_COMPRESSION) ~= 0
      if compressed then
        stub:append_text(" [Compressed]")
        --data = decompress(data)
      else
        local msg_sys, length = unpack_int(tvb, pos)
        local msg = bit.rshift(msg_sys, 1)
        local sys = bit.band(msg_sys, 1)
        stub:append_text((" [Type: %d] [System: %d]"):format(msg,sys))
        pos = pos + length

      end
    end
  end
end

prot_table = DissectorTable.get("udp.port")
prot_table:add(8303,tw_proto)
prot_table:add(8283,tw_proto)