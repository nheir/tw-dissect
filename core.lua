-- Dissector hardcoded part
tw_proto=Proto("Teeworlds", "Teeworlds")

function tw_proto.dissector(tvb,pinfo,tree)
  local code
  local pos
  local subtree
  local branch
  local stub
  local length
  local unknown
  local i

  pinfo.cols.protocol = "TW"
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
    if packet_header == Const.PACKET_GETINFO then
      local stub = stub:add(tvb(9), "Get Info packet")
      local pos = 17
      local token, length = unpack_int_from_tvb(tvb, pos)
      stub:add(tvb(pos, length), "Browser token: " .. token)
      pos = pos + length
    elseif packet_header == Const.PACKET_INFO then
      local stub = stub:add(tvb(9), "Info packet")
      local pos = 17

      local token, length = unpack_int_from_tvb(tvb, pos)
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
    elseif packet_header == Const.PACKET_GETLIST then
      local stub = stub:add(tvb(9), "Get list packet")
    elseif packet_header == Const.PACKET_LIST then
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
    local ack = bit.band(tvb(0,2):uint(), 0x03ff)
    stub:add(tvb(0,2), "Ack Version: " .. ack)
    local num_chunks = tvb(2,1):uint()
    stub:add(tvb(2,1), "Number of chunk: " .. num_chunks)
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
        if tvb:len() > 8 then
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
      local tvb = tvb
      local pos = pos
      if compressed then
        stub:append_text(" [Compressed]")
        data = TwHuffman:Decompress(data)
        if not data then
          stub:append_text(" [unable to decompress]")
        else
          -- create a uncompressed frame for data
          tvb = ByteArray.new(data, true):tvb('[decompressed]')
          pos = 0
        end
      end
      if data then
        for i=1,num_chunks do
          -- chunk header
          local b1,b2,b3 = data:byte(1,3)
          local flags = bit.band(bit.rshift(b1, 6), 0x03)
          local size = bit.bor(bit.lshift(bit.band(b1, 0x3f),6), bit.band(b2,0x3f))
          local header_size = 2
          local sequence = -1
          if bit.band(flags, Const.NET_CHUNKFLAG_VITAL) ~= 0 then
            sequence = bit.bor(bit.lshift(bit.band(b2, 0xc0),2),b3)
            header_size  = 3
          end
          msg_pos = header_size

          local stub = stub:add(tvb(pos, size+header_size), "Chunk")
          stub:append_text((", Flag: %d, Size: %d"):format(flags, size))

          local msg_sys, length = unpack_int(data, msg_pos+1)
          local msg = bit.rshift(msg_sys, 1)
          local sys = bit.band(msg_sys, 1)
          stub:add(tvb(pos + msg_pos, length), ("Type: %d, System: %d"):format(msg,sys))
          msg_pos = msg_pos + length

          if sys == 1 then
            if msg == Const.NETMSG_INFO then
              local stub = stub:add(tvb(pos + msg_pos, size - length), ("Client Info"):format(size-length))

              local net_version, next_pos = Struct.unpack("s", data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, next_pos - msg_pos - 1), "NetVersion: " .. net_version)
              msg_pos = next_pos-1

              local password, next_pos = Struct.unpack("s", data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, next_pos - msg_pos - 1), "Password: " .. password)
              msg_pos = next_pos-1

              local client_version, length = unpack_int(data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, length), ("Client: 0x%x"):format(client_version))
            elseif false and msg == Const.NETMSG_MAP_CHANGE then
              local stub = stub:add(tvb(pos + msg_pos, size - length), ("Map change"):format(size-length))

              local map_name, next_pos = Struct.unpack("s", data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, next_pos - msg_pos - 1), "Map name: " .. map_name)
              msg_pos = next_pos-1

              local map_crc, length = unpack_int(data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, length), ("Map crc: 0x%08x"):format(map_crc))
              msg_pos = msg_pos+length

              local map_size, length = unpack_int(data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, length), ("Map size: %d"):format(map_size))
              msg_pos = msg_pos+length

              local map_chunk_per_request, length = unpack_int(data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, length), ("Map chunk per request: %d"):format(map_chunk_per_request))
              msg_pos = msg_pos+length

              local map_chunk_size, length = unpack_int(data, msg_pos+1)
              stub:add(tvb(pos + msg_pos, length), ("Map chunk size: %d"):format(map_chunk_size))
              msg_pos = msg_pos+length

              local map_sha256 = string.rep("%02x", 32):format(data:byte(msg_pos+1, msg_pos+1+32))
              stub:add(tvb(pos + msg_pos, 32), ("Map sha256: %s"):format(map_sha256))
              msg_pos = msg_pos + 32
            elseif msg == Const.NETMSG_READY then
              local stub = stub:add(tvb(pos + msg_pos, size - length), ("Client Ready"):format(size-length))
            elseif case_net_msg_system[msg] then
              local tree = case_net_msg_system[msg](data, header_size + length)
              local stub = stub:add(tvb(pos + header_size + length, size - length), tree.name)
              for _, field in ipairs(tree) do
                stub:add(tvb(pos + field.start, field.size), field.name .. ': ' .. field.value)
              end
            else
              stub:add(tvb(pos + msg_pos, size - length), ("Data [%d bytes]"):format(size-length))
            end
          else
            if case_net_msg_type[msg] then
              local tree = case_net_msg_type[msg](data, header_size + length)
              local stub = stub:add(tvb(pos + header_size + length, size - length), tree.name)
              for _, field in ipairs(tree) do
                stub:add(tvb(pos + field.start, field.size), field.name .. ': ' .. field.value)
              end
            else
              stub:add(tvb(pos + msg_pos, size - length), ("Data [%d bytes]"):format(size-length))
            end
          end

          data = data:sub(size + header_size + 1)
          pos = pos + size + header_size
        end
      end
    end
  end
end

prot_table = DissectorTable.get("udp.port")
prot_table:add(8303,tw_proto)
prot_table:add(8305,tw_proto)
prot_table:add(8283,tw_proto)
-- Dissector End
