-- Lua uses '--' as comment to end of line read the
-- manual for more comment options.
local seq_table = {			-- entries can be in any order
  ["eth_dst_addr"] = "f04d:a273:202b",
  ["eth_src_addr"] = "f04d:a272:e15a",
  -- ["eth_src_addr"] = "f04d:a272:e15f",
  ["ip_dst_addr"] = "10.12.0.1",
  ["ip_src_addr"] = "10.12.0.1/16",	-- the 16 is the size of the mask value
  ["sport"] = 9,			-- Standard port numbers
  ["dport"] = 19899,			-- Standard port numbers
  ["ethType"] = "ipv4",	-- ipv4|ipv6|vlan
  ["ipProto"] = "udp",	-- udp|tcp|icmp
  ["vlanid"] = 1,			-- 1 - 4095
  ["pktSize"] = 128,		-- 64 - 1518
  ["dnsName"] = "www1.example.com",
  ["dnsType"] = "A"
};
-- seqTable( seq#, portlist, table );
pktgen.seqTable(0, "all", seq_table );
pktgen.set("all", "seq_cnt", 1);
pktgen.set("all", "count", 10000000);
