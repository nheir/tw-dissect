-- post parsing
local post_netmsg_system = {
	[Const.NETMSG_INPUT] = function(tree, data)
		local size_field = tree[#tree]
		assert(size_field.name == 'Size')
		local size = size_field.value / 4
		local msg_pos = size_field.start + size_field.size
		for i=1,size do
			local value, length = unpack_int(data, msg_pos+1)
			table.insert(tree, {name = string.format('m_aData[%d]', i-1), start = msg_pos, size = length, value = value})
			msg_pos = msg_pos + length
		end
		local value, length = unpack_int(data, msg_pos+1)
		table.insert(tree, {name = 'PingCorrection', start = msg_pos, size = length, value = value})
	end,
}

local post_netmsg_type = {
	[Const.NETMSGTYPE_SV_TUNEPARAMS] = function(tree, data)
		local msg_pos = tree.start
		for _,k in ipairs{
			'GroundControlSpeed',
			'GroundControlAccel',
			'GroundFriction',
			'GroundJumpImpulse',
			'AirJumpImpulse',
			'AirControlSpeed',
			'AirControlAccel',
			'AirFriction',
			'HookLength',
			'HookFireSpeed',
			'HookDragAccel',
			'HookDragSpeed',
			'Gravity',
			'VelrampStart',
			'VelrampRange',
			'VelrampCurvature',
			'GunCurvature',
			'GunSpeed',
			'GunLifetime',
			'ShotgunCurvature',
			'ShotgunSpeed',
			'ShotgunSpeeddiff',
			'ShotgunLifetime',
			'GrenadeCurvature',
			'GrenadeSpeed',
			'GrenadeLifetime',
			'LaserReach',
			'LaserBounceDelay',
			'LaserBounceNum',
			'LaserBounceCost',
			'PlayerCollision',
			'PlayerHooking',
		} do
			local value, length = unpack_int(data, msg_pos+1)
			table.insert(tree, {name = k, start = msg_pos, size = length, value = value / 100})
			msg_pos = msg_pos + length
		end
	end,
}

-- post parsing end
