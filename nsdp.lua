-- nsdp protocol
-- declare our protocol
nsdp_proto = Proto("nsdp","NSDP")
-- protocol fields
local nsdp_proto_field_version = ProtoField.uint16("nsdp.version", "Version")
local nsdp_proto_field_operation = ProtoField.uint16("nsdp.operation", "Operation")
local nsdp_proto_field_hwaddr = ProtoField.ether("nsdp.hwaddr", "Device eth-addr", "Device ethernet adress repeated in packet")
nsdp_proto.fields = {nsdp_proto_field_version, nsdp_proto_field_operation, nsdp_proto_field_hwaddr}
-- function to dissect it
function nsdp_proto.dissector(buffer,pinfo,tree)
    local version = buffer(0,2):uint()
    local operation = buffer(2,2):uint()
    pinfo.cols.protocol = "NSDPv" .. version
    local subtree = tree:add(nsdp_proto,buffer(),"Netgear NSDPv" .. version .. " Data")
    subtree:add(nsdp_proto_field_version,buffer(0,2),version)
    subtree:add(nsdp_proto_field_operation,buffer(2,2))
    subtree = subtree:add(buffer(4,6),"Version 2 fields")
    subtree:add(nsdp_proto_field_hwaddr,buffer(4,6))
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 64513,64512
for i,port in ipairs{64513,64515,63321,63322,63323,63324} do
    udp_table:add(port,nsdp_proto)
end
