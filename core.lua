-- Dissector hardcoded part
tw_proto=Proto("Teeworlds", "Teeworlds")

function tw_proto.dissector(tvb,pinfo,tree)
  local pos
  local stub

  pinfo.cols.protocol = "TW"
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
      local pos = 9
      local data = tvb:raw(pos)
      local token, length = unpack_int_from_tvb(tvb, pos+8)
      local field_token = {name = "Browser token: ", start = 8, size = length, value = token}

      local data = tvb:raw(pos)
      local tree = case_net_msg_system[Const.NETMSG_SERVERINFO](data, field_token.start + field_token.size, #data - field_token.start - field_token.size)
      tree.size = #data - field_token.start
      tree.start = field_token.start
      table.insert(tree, 1, field_token)

      local num_players = tree[9].value
      local offset = tree[#tree].start + tree[#tree].size
      local msg_pos = offset
      if num_players > 0 then
        for i=1,num_players do
          local player = {name = string.format("Player[%d]", i-1), start = msg_pos}
          local value, next_pos = Struct.unpack("s", data, msg_pos+1)
          table.insert(player, { name = "Name", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
          msg_pos = next_pos-1
          local value, next_pos = Struct.unpack("s", data, msg_pos+1)
          table.insert(player, { name = "Clan", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
          msg_pos = next_pos-1
          local value, length = unpack_int(data, msg_pos+1)
          table.insert(player, { name = "Country", start = msg_pos, size = length, value = value })
          msg_pos = msg_pos + length
          local value, length = unpack_int(data, msg_pos+1)
          table.insert(player, { name = "Score", start = msg_pos, size = length, value = value })
          msg_pos = msg_pos + length
          local value, length = unpack_int(data, msg_pos+1)
          table.insert(player, { name = "Spec/Player/Bot", start = msg_pos, size = length, value = value })
          msg_pos = msg_pos + length
          player.size = msg_pos - player.start
          table.insert(tree, player)
        end
      end

      tree_to_treeitem(tree, stub, tvb, 9, true)
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
    elseif packet_header == Const.PACKET_HEARTBEAT then
      local stub = stub:add(tvb(9), "Heartbeat packet")
      local port = tvb(17,2):uint()
      stub:add(tvb(17,2), string.format('Port: %d', port))
    elseif packet_header == Const.PACKET_GETCOUNT then
      local stub = stub:add(tvb(9), "Get Count packet")
    elseif packet_header == Const.PACKET_COUNT then
      local stub = stub:add(tvb(9), "Count packet")
      local count = tvb(17,2):uint()
      stub:add(tvb(17,2), string.format('Count: %d', count))
    elseif packet_header == Const.PACKET_FWCHECK then
      local stub = stub:add(tvb(9), "FwCheck packet")
    elseif packet_header == Const.PACKET_FWRESPONSE then
      local stub = stub:add(tvb(9), "FwResponse packet")
    elseif packet_header == Const.PACKET_FWOK then
      local stub = stub:add(tvb(9), "FwOk packet")
    elseif packet_header == Const.PACKET_FWERROR then
      local stub = stub:add(tvb(9), "FwError packet")
    else
      local stub = stub:add(tvb(9), "Unrecognized packet")
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

          local stub = stub:add(tvb(pos, size+header_size), "Chunk")
          stub:append_text((", Flag: %d, Size: %d"):format(flags, size))

          local msg_sys, length = unpack_int(data, header_size+1)
          local msg = bit.rshift(msg_sys, 1)
          local sys = bit.band(msg_sys, 1)
          stub:add(tvb(pos + header_size, length), ("Type: %d, System: %d"):format(msg,sys))

          local tree = {start = header_size + length, size = size - length}
          if sys == 1 and case_net_msg_system[msg] then
            tree = case_net_msg_system[msg](data, tree.start, tree.size)
            if post_netmsg_system[msg] then
              post_netmsg_system[msg](tree, data)
            end
          elseif sys == 0 and case_net_msg_type[msg] then
            tree = case_net_msg_type[msg](data, tree.start, tree.size)
            if post_netmsg_type[msg] then
              post_netmsg_type[msg](tree, data)
            end
          end

          if tree.name then
            tree_to_treeitem(tree, stub, tvb, pos, true)
          else
            stub:add(tvb(pos + tree.start, tree.size), ("Data [%d bytes]"):format(size-length))
          end

          data = data:sub(size + header_size + 1)
          pos = pos + size + header_size
        end
      end
    end
  end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(8303,tw_proto)
udp_table:add(8283,tw_proto)
udp_table:add(8284,tw_proto)
-- Dissector End
