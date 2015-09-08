-- nsdp protocol
-- declare our protocol
nsdp_proto = Proto("nsdp","NSDP")
-- protocol fields
local nsdp_proto_field_version = ProtoField.uint16("nsdp.version", "Version")
local nsdp_proto_field_direction = ProtoField.uint16("nsdp.direction", "Direction")
local nsdp_proto_field_operation = ProtoField.uint16("nsdp.operation", "Operation")
local nsdp_proto_field_header_netgear_ip = ProtoField.ipv4("nsdp.netgearip", "netgear.com IP", "(old)netgear.com IP adress")
local nsdp_proto_field_hwaddr = ProtoField.ether("nsdp.hwaddr", "Device eth-addr", "Device ethernet adress repeated in packet")
local nsdp_proto_field_header_dst_hwaddr = ProtoField.ether("nsdp.dsthwaddr", "Header Destination eth-addr", "Header destination ethernet adress")
nsdp_proto.fields = {
 nsdp_proto_field_version,
 nsdp_proto_field_direction,
 nsdp_proto_field_operation,
 nsdp_proto_field_hwaddr,
 nsdp_proto_field_header_netgear_ip,
 nsdp_proto_field_header_dst_hwaddr
}

-- field we need to read
local srcport = Field.new("udp.srcport")
local dstport = Field.new("udp.dstport")

-- protocol static offsets
local versionOffset = 0
local operationOffset = 2
-- hardcoded / magic fields
local netgear_ip = "12.7.210.242"
local nsdp_proto_v1_srcport = 63321 -- @link https://github.com/kvishnivetsky/NetgearProSafeUtils/blob/master/nsdp-config#L49
local nsdp_proto_v1_dstport = 63322 -- @link https://github.com/kvishnivetsky/NetgearProSafeUtils/blob/master/nsdp-config#L265
local nsdp_proto_v1FS726TP_srcport = 63323 -- @link https://www.toolswatch.org/2014/03/nsdtool-netgear-switch-discovery-tool-released/#more-43234
local nsdp_proto_v1FS726TP_dstport = 63324 -- @see nsdp_proto_v1FS726TP_srcport
local nsdp_proto_v2_srcport = 64513
local nsdp_proto_v2_dstport = 64515
local nsdp_proto_dgramports = {
nsdp_proto_v2_srcport,
nsdp_proto_v2_dstport,
nsdp_proto_v1_srcport,
nsdp_proto_v1_dstport,
nsdp_proto_v1FS726TP_srcport,
nsdp_proto_v1FS726TP_dstport
}
local nsdp_proto_v2_dstHwaddrBroadcast = "00:00:00_00:00:00"
local nsdp_proto_v2_headerlen = 0x52 - 0x2a -- current offset in datagram
local nsdp_proto_v2_tlv_types = {
 {name = "Device type"},
 {name = "Hostname"},
 {name = "Location(custom value)"},
 {name = "Device IP"},
 {name = "Subnetmask"},
 {name = "Gateway"},
 {name = ""},
 {name = "Password(new)"},
 {name = "Password(auth)"},
 {name = "DHCP on/off"},
 {name = "Version"},
 {name = "ever 0001"},
}
local nsdp_proto_v2_operations = {
 {},
 {{name = "Firmware"},{name = "Networksetting"}}
}
nsdp_proto_v2_operations[0] = {{name = "Discover"},{name = "Pwchange"}}

-- function to dissect it
function nsdp_proto.dissector(buffer,pinfo,tree)
    function parseTlvField(tlv4buf, pinfo, tlvFieldTree, tlvOffset)
      if tlv4buf:len() > tlvOffset + 2 + 2 then
        local tlvFieldType = tlv4buf:range(tlvOffset, 2):uint()
        if nsdp_proto_v2_tlv_types[tlvFieldType] then
          tlvFieldTypeName = nsdp_proto_v2_tlv_types[tlvFieldType].name
        end
        local tlvFieldLen = tlv4buf:range(tlvOffset + 2, 2):uint() - 2 - 2
        if tlv4buf:len() >= tlvOffset + 2 + 2 + tlvFieldLen then
            tlvFieldBuf = tlv4buf:range(tlvOffset, 2 + 2 + tlvFieldLen)
            tlvFieldTree = tlvtree:add(tlvFieldBuf, "TLV4 Field Type: " .. tlvFieldType .. " Len: " .. tlvFieldLen)
            if tlvFieldTypeName then
              tlvFieldTree:set_text(tlvFieldTypeName .. " " .. "(Len: " .. tlvFieldLen .. ")")
            end
            tlvFieldTree:add(tlvFieldBuf:range(0, 2), "Field Type: " .. tlvFieldBuf:range(0, 2):uint())
            tlvFieldTree:add(tlvFieldBuf:range(2, 2), "Field Len: " .. tlvFieldBuf:range(2, 2):uint())
            if tlvFieldLen > 0 then
                tlvFieldTree:add(tlvFieldBuf:range(2 + 2, tlvFieldLen), "Field Value: " .. tostring(tlvFieldBuf:range(2 + 2)))
            else
                tlvFieldValueEmptyGeneratedTree = tlvFieldTree:add(tlvFieldBuf, "Empty Field Value")
                tlvFieldValueEmptyGeneratedTree:set_generated()
            end
        end
      end
    end
    function parseV2DstHwaddr(buffer, pinfo, subtree)
      local hwaddrRange = buffer:range(0x14,6)
      local subtree_hwaddr = subtree:add(nsdp_proto_field_header_dst_hwaddr, hwaddrRange)
      if tostring(hwaddrRange:ether()) == nsdp_proto_v2_dstHwaddrBroadcast then
        local subtreeBroadcastHint = subtree_hwaddr:add(hwaddrRange, "Broadcast")
        subtreeBroadcastHint:set_generated()
      end
    end
    function parseV2Operation(headv2buf, pinfo, subtree)
      local headv2_operationRange = headv2buf:range(0x1a, 2)
      local operation = headv2_operationRange:uint()
      local headv2_operationTreeItem = subtree:add(nsdp_proto_field_operation, headv2_operationRange)
      if nsdp_proto_v2_operations[operation] then
        local operations = nsdp_proto_v2_operations[operation]
        local len = #(operations)
        if len > 0 then
          for i = 1,len,1 do
            if operations[i].name then
              operationCandidateItem = headv2_operationTreeItem:add("Candidate: " .. operations[i].name)
              operationCandidateItem:set_generated()
            end
          end
        end
      else
        local operationHintItem = headv2_operationTreeItem:add("Unknown Operation Code")
        operationHintItem:set_generated()
      end
    end
    -- three strange header fields
    function parseV2Headers(headv2buf, pinfo, subtree)
      -- buffers
      local field1range = headv2buf:range(0x0a + 2 * 0, 2)
      local field2range = headv2buf:range(0x0a + 2 * 1, 2)
      local field3range = headv2buf:range(0x0a + 2 * 2, 2)
      -- values
      local field1 = field1range:uint()
      local field2 = field2range:uint()
      local field3 = field3range:uint()
      -- tree
      local header = "Header: "
      local invalid = 0
      if field1 == 0 then
        if field2 == 1 then
          header = header .. "Discover Query"
        elseif field2 == 3 then
          header = header .. "Pwchange or Networksetting Query"
        else
          header = header .. "Unknown Query"
          invalid = 1
        end
      elseif field1 == 2 then
        if field2 == 0x02 then
          header = header .. "Discover Response"
        elseif field2 == 0x04 then
          header = header .. "Pwchange or Networksetting Response"
        elseif field2 == 0x0b then
          header = header .. "Firmware Response"
        else
          header = header .. "Unknown Response"
          invalid = 1
        end
      elseif field1 == 3 then
        if field2 == 0x0a then
          header = header .. "Firmware Query"
        else
          header = header .. "Unknown Firmware Query"
          invalid = 1
        end
      else
       invalid = 1
      end
      if field3 > 0 then
        invalid = 1
      end
      local headerTree = subtree:add(header)
      if invalid > 0 then
        invalidHint = headerTree:add(field1range, "Invalid")
        invalidHint:set_generated()
      end
      local field1tree = headerTree:add(field1range, "Field1: " .. field1)
      local field2tree = headerTree:add(field2range, "Field2: " .. field2)
      local field3tree = headerTree:add(field3range, "Field3: " .. field3)
    end
    -- udp environment
    local srcport = pinfo.src_port
    local dstport = pinfo.dst_port
    -- preperation
    local portversionhint = 0
    local direction = 0
    -- protocol static fields
    local versionBuffer = buffer(versionOffset,2)
    local version = versionBuffer:uint()
    -- protocol known version static fields
    -- if version <= 2 then
        local operationBuffer = buffer(operationOffset,2)
        local operation = operationBuffer:uint()
    -- end
    -- port heuristics
    if srcport == 64513 and dstport == 64515 then
        portversionhint = 2
        direction = 1
    elseif dstport == 64513 then
        direction = 2
        portversionhint = 2
    else
        debug("unknown port usage")
    end
    -- output
    if direction == 1 then
         pinfo.cols.info:prepend("-> ")
    elseif direction == 2 then
         pinfo.cols.info:prepend("<- ")
    end
    if version <= 2 then
        pinfo.cols.protocol = "NSDPv" .. version
        local subtree = tree:add(nsdp_proto,buffer(),"Netgear NSDPv" .. version .. " Data")
        subtree:add(nsdp_proto_field_version,versionBuffer)
        subtree:add(nsdp_proto_field_direction, operationBuffer)
        if version == 2 then
            local headv2buf = buffer:range(0, nsdp_proto_v2_headerlen)
            subtree = subtree:add(buffer(4,6),"Version 2 fields")
            subtree:add(nsdp_proto_field_hwaddr,buffer(4,6))
            parseV2Headers(headv2buf, pinfo, subtree)
            subtree_netgear_ip = subtree:add(nsdp_proto_field_header_netgear_ip, buffer(0x10,4))
            if not tostring(buffer(0x10,4):ipv4()) == netgear_ip then
                subtree_netgear_ip:add_expert_info(PI_CHECKSUM, PI_NOTE, "Does not match " .. netgear_ip)
            end
            parseV2DstHwaddr(buffer, pinfo, subtree)
            parseV2Operation(headv2buf, pinfo, subtree)
            local headv2_zeropadbuf = headv2buf:range(nsdp_proto_v2_headerlen - 0x0c)
            local headv2_zeropadtree = subtree:add(headv2_zeropadbuf, "Zero padding")
            headv2_zeropadtree:set_generated()
            local tlv4buf = buffer:range(nsdp_proto_v2_headerlen)
            tlvtree = subtree:add(tlv4buf, "TLV4")
            if buffer:len() > nsdp_proto_v2_headerlen then
                local tlvLen = tlv4buf:len()
                local tlvOffset = 0
                while tlvOffset + 2 + 2 <= tlvLen do
                    tlvFieldType = tlv4buf:range(tlvOffset, 2):uint()
                    tlvFieldLen = tlv4buf:range(tlvOffset + 2, 2):uint() - 2 - 2
                    if tlvFieldLen >= 0 then -- could be up to minus 4
                        if tlv4buf:len() >= tlvOffset + 2 + 2 + tlvFieldLen then
                            parseTlvField(tlv4buf, pinfo, tlvFieldTree, tlvOffset)
                        end
                        -- increment
                        tlvOffset = tlvOffset + tlvFieldLen
                    else
                        tlvFieldBuf = tlv4buf:range(tlvOffset, 2 + 2)
                        tlvFieldTree = tlvtree:add(tlvFieldBuf, "TLV4 Field Type: " .. tlvFieldType .. " Len: " .. tlvFieldLen)
                        tlvFieldTree:add(tlvFieldBuf:range(0, 2), "Field Type: " .. tlvFieldBuf:range(0, 2):uint())
                        tlvFieldTree:add(tlvFieldBuf:range(2, 2), "Field Len(faulty): " .. tlvFieldBuf:range(2, 2):uint())
                    end
                    -- increment
                    tlvOffset = tlvOffset + 2 + 2
                end
            else
                tlvtree:append_text(" " .. "Empty Body")
                tlvtree:set_generated()
            end
        end
    end
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 64513,64512
for i,port in ipairs(nsdp_proto_dgramports) do
    udp_table:add(port,nsdp_proto)
end
