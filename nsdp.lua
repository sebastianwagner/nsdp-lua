-- nsdp protocol
-- declare our protocol
nsdp_proto = Proto("nsdp","NSDP")
-- create a function to dissect it
function nsdp_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "NSDP"
    local subtree = tree:add(nsdp_proto,buffer(),"Netgrear NSDP Data")
    subtree:add(buffer(0,2),"Version: " .. buffer(0,2):uint())
    subtree = subtree:add(buffer(2,2),"Operation")
    subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 64513,64512
udp_table:add(64513,nsdp_proto)
