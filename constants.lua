-- Constants
local Const = {
  NETMSG_NULL=0,

  PACKET_HEARTBEAT  = "\xff\xff\xff\xffbea2",

  PACKET_GETLIST    = "\xff\xff\xff\xffreq2",
  PACKET_LIST       = "\xff\xff\xff\xfflis2",

  PACKET_GETCOUNT   = "\xff\xff\xff\xffcou2",
  PACKET_COUNT      = "\xff\xff\xff\xffsiz2",

  PACKET_GETINFO    = "\xff\xff\xff\xffgie3",
  PACKET_INFO       = "\xff\xff\xff\xffinf3",

  PACKET_FWCHECK    = "\xff\xff\xff\xfffw??",
  PACKET_FWRESPONSE = "\xff\xff\xff\xfffw!!",
  PACKET_FWOK       = "\xff\xff\xff\xfffwok",
  PACKET_FWERROR    = "\xff\xff\xff\xfffwer",
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
-- Constants End
