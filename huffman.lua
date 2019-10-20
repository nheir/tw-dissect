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
-- Huffman End
