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

for i,k in ipairs{
  -- NETMSG_INVALID=0,
  'NETMSGTYPE_SV_MOTD',
  'NETMSGTYPE_SV_BROADCAST',
  'NETMSGTYPE_SV_CHAT',
  'NETMSGTYPE_SV_TEAM',
  'NETMSGTYPE_SV_KILLMSG',
  'NETMSGTYPE_SV_TUNEPARAMS',
  'NETMSGTYPE_SV_EXTRAPROJECTILE',
  'NETMSGTYPE_SV_READYTOENTER',
  'NETMSGTYPE_SV_WEAPONPICKUP',
  'NETMSGTYPE_SV_EMOTICON',
  'NETMSGTYPE_SV_VOTECLEAROPTIONS',
  'NETMSGTYPE_SV_VOTEOPTIONLISTADD',
  'NETMSGTYPE_SV_VOTEOPTIONADD',
  'NETMSGTYPE_SV_VOTEOPTIONREMOVE',
  'NETMSGTYPE_SV_VOTESET',
  'NETMSGTYPE_SV_VOTESTATUS',
  'NETMSGTYPE_SV_SERVERSETTINGS',
  'NETMSGTYPE_SV_CLIENTINFO',
  'NETMSGTYPE_SV_GAMEINFO',
  'NETMSGTYPE_SV_CLIENTDROP',
  'NETMSGTYPE_SV_GAMEMSG',
  'NETMSGTYPE_DE_CLIENTENTER',
  'NETMSGTYPE_DE_CLIENTLEAVE',
  'NETMSGTYPE_CL_SAY',
  'NETMSGTYPE_CL_SETTEAM',
  'NETMSGTYPE_CL_SETSPECTATORMODE',
  'NETMSGTYPE_CL_STARTINFO',
  'NETMSGTYPE_CL_KILL',
  'NETMSGTYPE_CL_READYCHANGE',
  'NETMSGTYPE_CL_EMOTICON',
  'NETMSGTYPE_CL_VOTE',
  'NETMSGTYPE_CL_CALLVOTE',
  'NETMSGTYPE_SV_SKINCHANGE',
  'NETMSGTYPE_CL_SKINCHANGE',
  'NUM_NETMSGTYPES'
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

  NET_CHUNKFLAG_VITAL=1,
  NET_CHUNKFLAG_RESEND=2,

  NET_CTRLMSG_KEEPALIVE=0,
  NET_CTRLMSG_CONNECT=1,
  NET_CTRLMSG_CONNECTACCEPT=2,
  NET_CTRLMSG_ACCEPT=3,
  NET_CTRLMSG_CLOSE=4,
  NET_CTRLMSG_TOKEN=5,
} do
  Const[k] = v
end

function unpack_int(buf, pos)
  pos = pos or 1
  buf = {buf:byte(pos, pos+4)}
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

function unpack_int_from_tvb(tvb, pos)
  return unpack_int(tvb:raw(pos,math.min(5,tvb:len()-pos)))
end

local case_net_msg_type = {
  [Const.NETMSGTYPE_SV_MOTD] = function (data, offset)
    local tree = { name = 'Sv_Motd' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pMessage", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_BROADCAST] = function (data, offset)
    local tree = { name = 'Sv_Broadcast' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pMessage", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_CHAT] = function (data, offset)
    local tree = { name = 'Sv_Chat' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Mode", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_TargetID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pMessage", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_TEAM] = function (data, offset)
    local tree = { name = 'Sv_Team' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Team", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Silent", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_CooldownTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_KILLMSG] = function (data, offset)
    local tree = { name = 'Sv_KillMsg' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Killer", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Victim", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Weapon", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ModeSpecial", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_TUNEPARAMS] = function (data, offset)
    local tree = { name = 'Sv_TuneParams' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_SV_EXTRAPROJECTILE] = function (data, offset)
    local tree = { name = 'Sv_ExtraProjectile' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_SV_READYTOENTER] = function (data, offset)
    local tree = { name = 'Sv_ReadyToEnter' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_SV_WEAPONPICKUP] = function (data, offset)
    local tree = { name = 'Sv_WeaponPickup' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Weapon", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_EMOTICON] = function (data, offset)
    local tree = { name = 'Sv_Emoticon' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Emoticon", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTECLEAROPTIONS] = function (data, offset)
    local tree = { name = 'Sv_VoteClearOptions' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTEOPTIONLISTADD] = function (data, offset)
    local tree = { name = 'Sv_VoteOptionListAdd' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTEOPTIONADD] = function (data, offset)
    local tree = { name = 'Sv_VoteOptionAdd' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pDescription", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTEOPTIONREMOVE] = function (data, offset)
    local tree = { name = 'Sv_VoteOptionRemove' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pDescription", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTESET] = function (data, offset)
    local tree = { name = 'Sv_VoteSet' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Type", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Timeout", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pDescription", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pReason", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_SV_VOTESTATUS] = function (data, offset)
    local tree = { name = 'Sv_VoteStatus' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Yes", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_No", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Pass", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Total", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_SERVERSETTINGS] = function (data, offset)
    local tree = { name = 'Sv_ServerSettings' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_KickVote", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_KickMin", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_SpecVote", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_TeamLock", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_TeamBalance", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_PlayerSlots", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_CLIENTINFO] = function (data, offset)
    local tree = { name = 'Sv_ClientInfo' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Local", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Team", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pName", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pClan", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Country", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[0]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[1]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[2]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[3]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[4]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[5]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Silent", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_GAMEINFO] = function (data, offset)
    local tree = { name = 'Sv_GameInfo' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_GameFlags", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ScoreLimit", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_TimeLimit", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_MatchNum", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_MatchCurrent", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_CLIENTDROP] = function (data, offset)
    local tree = { name = 'Sv_ClientDrop' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pReason", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Silent", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_GAMEMSG] = function (data, offset)
    local tree = { name = 'Sv_GameMsg' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_DE_CLIENTENTER] = function (data, offset)
    local tree = { name = 'De_ClientEnter' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pName", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Team", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_DE_CLIENTLEAVE] = function (data, offset)
    local tree = { name = 'De_ClientLeave' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pName", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pReason", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_CL_SAY] = function (data, offset)
    local tree = { name = 'Cl_Say' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Mode", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Target", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pMessage", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSGTYPE_CL_SETTEAM] = function (data, offset)
    local tree = { name = 'Cl_SetTeam' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Team", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_SETSPECTATORMODE] = function (data, offset)
    local tree = { name = 'Cl_SetSpectatorMode' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_SpecMode", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_SpectatorID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_STARTINFO] = function (data, offset)
    local tree = { name = 'Cl_StartInfo' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pName", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_pClan", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Country", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[0]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[1]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[2]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[3]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[4]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[5]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_KILL] = function (data, offset)
    local tree = { name = 'Cl_Kill' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_CL_READYCHANGE] = function (data, offset)
    local tree = { name = 'Cl_ReadyChange' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSGTYPE_CL_EMOTICON] = function (data, offset)
    local tree = { name = 'Cl_Emoticon' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Emoticon", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_VOTE] = function (data, offset)
    local tree = { name = 'Cl_Vote' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Vote", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_CALLVOTE] = function (data, offset)
    local tree = { name = 'Cl_CallVote' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_Type", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_Value", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_Reason", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_Force", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_SV_SKINCHANGE] = function (data, offset)
    local tree = { name = 'Sv_SkinChange' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_ClientID", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[0]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[1]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[2]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[3]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[4]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[5]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSGTYPE_CL_SKINCHANGE] = function (data, offset)
    local tree = { name = 'Cl_SkinChange' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[0]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[1]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[2]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[3]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[4]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "m_apSkinPartNames[5]", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aUseCustomColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[0]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[1]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[2]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[3]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[4]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_aSkinPartColors[5]", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
}

local case_net_msg_system = {
  [Const.NETMSG_INPUT] = function (data, offset)
    local tree = { name = 'Input' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_AckGameTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "m_PredTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Size", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_INPUTTIMING] = function (data, offset)
    local tree = { name = 'InputTiming' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "IntendedTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "TimeLeft", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_INFO] = function (data, offset)
    local tree = { name = 'Info' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "NetVersion", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Password", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "ClientVersion", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_ENTERGAME] = function (data, offset)
    local tree = { name = 'EnterGame' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_READY] = function (data, offset)
    local tree = { name = 'Ready' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_CON_READY] = function (data, offset)
    local tree = { name = 'Con_Ready' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_MAP_CHANGE] = function (data, offset)
    local tree = { name = 'Map_Change' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Map name", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Map CRC", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Map size", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Map chunk per request", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Map chunk size", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value = data:sub(msg_pos+1, msg_pos+32)
    table.insert(tree, { name = "Map Sha256", start = msg_pos, size = 32, value = value })
    msg_pos = msg_pos + 32
    return tree
  end,
  [Const.NETMSG_REQUEST_MAP_DATA] = function (data, offset)
    local tree = { name = 'Request_Map_Data' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_MAP_DATA] = function (data, offset)
    local tree = { name = 'Map_Data' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_RCON_AUTH] = function (data, offset)
    local tree = { name = 'Rcon_Auth' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Password", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_RCON_AUTH_ON] = function (data, offset)
    local tree = { name = 'Rcon_Auth_On' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_RCON_AUTH_OFF] = function (data, offset)
    local tree = { name = 'Rcon_Auth_Off' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_RCON_LINE] = function (data, offset)
    local tree = { name = 'Rcon_Line' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Line", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_RCON_CMD] = function (data, offset)
    local tree = { name = 'Rcon_Cmd' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Command", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_RCON_CMD_ADD] = function (data, offset)
    local tree = { name = 'Rcon_Cmd_Add' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Name", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Help", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Params", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_MAPLIST_ENTRY_ADD] = function (data, offset)
    local tree = { name = 'Maplist_Entry_Add' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Name", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_MAPLIST_ENTRY_REM] = function (data, offset)
    local tree = { name = 'Maplist_Entry_Rem' }
    local msg_pos = offset
    local value, next_pos = Struct.unpack("s", data, msg_pos+1)
    table.insert(tree, { name = "Name", start = msg_pos, size = next_pos - msg_pos - 1, value = value })
    msg_pos = next_pos-1
    return tree
  end,
  [Const.NETMSG_PING] = function (data, offset)
    local tree = { name = 'Ping' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_PING_REPLY] = function (data, offset)
    local tree = { name = 'Ping_Reply' }
    local msg_pos = offset
    return tree
  end,
  [Const.NETMSG_SNAP] = function (data, offset)
    local tree = { name = 'Snap' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "GameTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Relative DeltaTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "NumParts", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Part", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Crc", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "PartSize", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_SNAPSINGLE] = function (data, offset)
    local tree = { name = 'SnapSingle' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "GameTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Relative DeltaTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Crc", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Size", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_SNAPEMPTY] = function (data, offset)
    local tree = { name = 'SnapEmpty' }
    local msg_pos = offset
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "GameTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    local value, length = unpack_int(data, msg_pos+1)
    table.insert(tree, { name = "Relative DeltaTick", start = msg_pos, size = length, value = value })
    msg_pos = msg_pos + length
    return tree
  end,
  [Const.NETMSG_SERVERINFO] = function (data, offset)
    local tree = { name = 'ServerInfo' }
    local msg_pos = offset
    return tree
  end,
}

-- Huffman
local TwHuffman
do
  local tw_freqtable = {
    [0]=0x40000000,
    4545,2657,431,1950,919,444,482,2244,617,838,542,715,1814,304,240,754,212,647,186,
    283,131,146,166,543,164,167,136,179,859,363,113,157,154,204,108,137,180,202,176,
    872,404,168,134,151,111,113,109,120,126,129,100,41,20,16,22,18,18,17,19,
    16,37,13,21,362,166,99,78,95,88,81,70,83,284,91,187,77,68,52,68,
    59,66,61,638,71,157,50,46,69,43,11,24,13,19,10,12,12,20,14,9,
    20,20,10,10,15,15,12,12,7,19,15,14,13,18,35,19,17,14,8,5,
    15,17,9,15,14,18,8,10,2173,134,157,68,188,60,170,60,194,62,175,71,
    148,67,167,78,211,67,156,69,1674,90,174,53,147,89,181,51,174,63,163,80,
    167,94,128,122,223,153,218,77,200,110,190,73,174,69,145,66,277,143,141,60,
    136,53,180,57,142,57,158,61,166,112,152,92,26,22,21,28,20,26,30,21,
    32,27,20,17,23,21,30,22,22,21,27,25,17,27,23,18,39,26,15,21,
    12,18,18,27,20,18,15,19,11,17,33,12,18,15,19,18,16,26,17,18,
    9,10,25,22,22,17,20,16,6,16,15,20,14,18,24,335,1517
  }

  local Huffman = {}
  Huffman.__index = Huffman
  Huffman.HUFFMAN_EOF_SYMBOL = 256
  Huffman.HUFFMAN_MAX_SYMBOLS = Huffman.HUFFMAN_EOF_SYMBOL+1
  Huffman.HUFFMAN_MAX_NODES = Huffman.HUFFMAN_MAX_SYMBOLS*2-1
  Huffman.HUFFMAN_LUTBITS = 10
  Huffman.HUFFMAN_LUTSIZE = bit.lshift(1, Huffman.HUFFMAN_LUTBITS)
  Huffman.HUFFMAN_LUTMASK = Huffman.HUFFMAN_LUTSIZE-1

  function Huffman.new()
    local t = {
      decode_lut = {}
    }
    return setmetatable(t, Huffman)
  end

  local function bubble_sort(list)
    local changed = true
    local size = #list

    while changed do
      changed = false
      for i=1,size-1 do
        if list[i].freq < list[i+1].freq then
          list[i], list[i+1] = list[i+1], list[i]
          changed = true
        end
      end
      size = size-1
    end
  end

  function Huffman:SetDepth_r(node, depth)
    if node.left then
      self:SetDepth_r(node.left, depth+1)
      self:SetDepth_r(node.right, depth+1)
    end

    if node.symbol then
      node.num_bits = depth
    end
  end

  function Huffman:ConstructTree(frequencies)
    local nodes = {}
    -- add the symbols
    for i,f in pairs(frequencies) do
      local node = {symbol = i, freq = f}
      table.insert(nodes, node)
      if node.symbol == Huffman.HUFFMAN_EOF_SYMBOL then
        self.eof_node = node
        self.eof_node.freq = 1
      end
    end

    bubble_sort(nodes)

    while #nodes > 1 do
      local n = #nodes
      local left = nodes[n]
      nodes[n] = nil

      local right = nodes[n - 1]
      nodes[n - 1] = nil

      local new = { freq = left.freq + right.freq, left = left, right = right }

      --- insert new node at correct priority
      local prio = 1
      while prio <= #nodes and nodes[prio].freq >= new.freq do
        prio = prio + 1
      end
      table.insert(nodes, prio, new)
    end
    self.start_node = nodes[1]

    self:SetDepth_r(self.start_node, 0)
  end

  --void CHuffman::Init(const unsigned *pFrequencies)
  function Huffman:Init(frequencies)
    -- construct the tree
    self:ConstructTree(frequencies)

    -- build decode LUT
    for i=0,Huffman.HUFFMAN_LUTSIZE-1 do
      local bits = i
      local node = self.start_node
      for k=1,Huffman.HUFFMAN_LUTBITS do
        if bits % 2 == 0 then
          node = node.left
        else
          node = node.right
        end
        bits = bit.rshift(bits, 1)

        if not node then
          break
        end

        if node.symbol then
          self.decode_lut[i] = node
          break
        end

        if k == Huffman.HUFFMAN_LUTBITS then
          self.decode_lut[i] = node
        end
      end
    end
  end


  --***************************************************************
  -- int CHuffman::Decompress(const void *pInput, int InputSize, void *pOutput, int OutputSize)
  function Huffman:Decompress(input, input_size, output_size)
    input_size = input_size or #input
    input = {input:byte(1, input_size)}

    local output = {}

    local src_i = 1

    local bits = 0
    local bitcount = 0

    while true do
      -- {A} try to load a node now, this will reduce dependency at location {D}
      node = nil
      if bitcount >= Huffman.HUFFMAN_LUTBITS then
        node = self.decode_lut[bit.band(bits, Huffman.HUFFMAN_LUTMASK)]
      end

      -- {B} fill with new bits
      while bitcount < 24 and src_i <= input_size do
        bits = bit.bor(bits, bit.lshift(input[src_i], bitcount))
        bitcount = bitcount + 8
        src_i = src_i+1
      end

      -- {C} load symbol now if we didn't that earlier at location {A}
      if not node then
        node = self.decode_lut[bit.band(bits, Huffman.HUFFMAN_LUTMASK)]
      end

      if not node then
        return
      end

      -- {D} check if we hit a symbol already
      if node.symbol then
        -- remove the bits for that symbol
        bits = bit.rshift(bits, node.num_bits)
        bitcount = bitcount - node.num_bits
      else
        -- remove the bits that the lut checked up for us
        bits = bit.rshift(bits, Huffman.HUFFMAN_LUTBITS)
        bitcount = bitcount - Huffman.HUFFMAN_LUTBITS

        -- walk the tree bit by bit
        while true do
          -- traverse tree
          if bits % 2 == 0 then
            node = node.left
          else
            node = node.right
          end

          -- remove bit
          bitcount = bitcount-1
          bits = bit.rshift(bits, 1)

          -- check if we hit a symbol
          if node.symbol then
            break
          end

          -- no more bits, decoding error
          if bitcount == 0 then
            return
          end
        end
      end

      -- check for eof
      if node == self.eof_node then
        break
      end

      if #output == output_size then
        return
      end

      output[#output+1] = string.char(node.symbol)
    end

    -- return the size of the decompressed buffer
    return table.concat(output)
  end

  TwHuffman = Huffman.new()
  TwHuffman:Init(tw_freqtable)
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
    if packet_header == PACKET_GETINFO then
      local stub = stub:add(tvb(9), "Get Info packet")
      local pos = 17
      local token, length = unpack_int_from_tvb(tvb, pos)
      stub:add(tvb(pos, length), "Browser token: " .. token)
      pos = pos + length
    elseif packet_header == PACKET_INFO then
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
            elseif msg == Const.NETMSG_MAP_CHANGE then
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
prot_table:add(8283,tw_proto)