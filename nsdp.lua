-- nsdp protocol
-- declare our protocol
nsdp_proto = Proto("nsdp","NSDP")
-- protocol fields
local nsdp_proto_field_version = ProtoField.uint16("nsdp.version", "Version")
local nsdp_proto_field_operation = ProtoField.uint16("nsdp.operation", "Operation")
local nsdp_proto_field_header_netgear_ip = ProtoField.ipv4("nsdp.netgearip", "netgear.com IP", "(old)netgear.com IP adress")
local nsdp_proto_field_hwaddr = ProtoField.ether("nsdp.hwaddr", "Device eth-addr", "Device ethernet adress repeated in packet")
local nsdp_proto_field_header_dst_hwaddr = ProtoField.ether("nsdp.dsthwaddr", "Header Destination eth-addr", "Header destination ethernet adress")
nsdp_proto.fields = {
 nsdp_proto_field_version,
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

-- function to dissect it
function nsdp_proto.dissector(buffer,pinfo,tree)
    function parseTlvField(tlv4buf,pinfo,tlvFieldTree, tlvOffset)
        if tlv4buf:len() >= tlvOffset + 2 + 2 + tlvFieldLen then
            tlvFieldBuf = tlv4buf:range(tlvOffset, 2 + 2 + tlvFieldLen)
            tlvFieldTree = tlvtree:add(tlvFieldBuf, "TLV4 Field Type: " .. tlvFieldType .. " Len: " .. tlvFieldLen)
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
        subtree:add(nsdp_proto_field_operation,operationBuffer)
        if version == 2 then
            subtree = subtree:add(buffer(4,6),"Version 2 fields")
            subtree:add(nsdp_proto_field_hwaddr,buffer(4,6))
            subtree_netgear_ip = subtree:add(nsdp_proto_field_header_netgear_ip, buffer(0x10,4))
            if not tostring(buffer(0x10,4):ipv4()) == netgear_ip then
                subtree_netgear_ip_comp = subtree_netgear_ip:add("Does not match " .. netgear_ip)
                subtree_netgear_ip_comp:set_generated()
            end
            subtree:add(nsdp_proto_field_header_dst_hwaddr, buffer(0x14,6))
            if buffer:len() > 0x28 then
                local tlv4buf = buffer:range(0x28)
                local tlvLen = tlv4buf:len()
                tlvtree = subtree:add(tlv4buf, "TLV4")
                tlvOffset = 0
                while tlvOffset + 2 + 2 <= tlvLen do
                    tlvFieldType = tlv4buf:range(tlvOffset, 2):uint()
                    tlvFieldLen = tlv4buf:range(tlvOffset + 2, 2):uint() - 2 - 2
                    if tlvFieldLen >= 0 then
                        if tlv4buf:len() >= tlvOffset + 2 + 2 + tlvFieldLen then
                            parseTlvField(tlv4buf, pinfo, tlvFieldTree, tlvOffset)
                        end
                        -- increment
                        tlvOffset = tlvOffset + 2 + 2 + tlvFieldLen
                    else
                        tlvFieldBuf = tlv4buf:range(tlvOffset, 2 + 2)
                        tlvFieldTree = tlvtree:add(tlvFieldBuf, "TLV4 Field Type: " .. tlvFieldType .. " Len: " .. tlvFieldLen)
                        tlvFieldTree:add(tlvFieldBuf:range(0, 2), "Field Type: " .. tlvFieldBuf:range(0, 2):uint())
                        tlvFieldTree:add(tlvFieldBuf:range(2, 2), "Field Len(faulty): " .. tlvFieldBuf:range(2, 2):uint())
                        -- increment
                        tlvOffset = tlvOffset + 2 + 2
                    end
                end
            end
        end
    end
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 64513,64512
for i,port in ipairs{64513,64515,63321,63322,63323,63324} do
    udp_table:add(port,nsdp_proto)
end
