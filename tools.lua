-- Tools
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
-- Tools end
