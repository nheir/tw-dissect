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

function tree_to_treeitem(tree, stub, tvb, offset, default)
  local stub = stub:add(tvb(offset + tree.start, tree.size), tree.name)
  local last_pos = 0
  for _, field in ipairs(tree) do
    if type(field.value) == 'table' then
      tree_tp_treeitem(field, stub, tvb, offset, default)
    else
      stub:add(tvb(offset + field.start, field.size), field.name .. ': ' .. field.value)
    end
    last_pos = field.start + field.size
  end
  if default and last_pos < tree.start + tree.size then
    stub:add(tvb(offset + last_pos, tree.start + tree.size - last_pos), ("Data [%d bytes]"):format(tree.start + tree.size - last_pos))
  end
end
-- Tools end
