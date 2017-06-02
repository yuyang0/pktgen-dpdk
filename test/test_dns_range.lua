package.path = package.path ..";?.lua;test/?.lua;app/?.lua;"

--pktgen.page("range");

-- Port 0 3c:fd:fe:9c:5c:d8,  Port 1 3c:fd:fe:9c:5c:b8
pktgen.range.dst_mac("0", "start", "f0:4d:a2:73:20:2b");
pktgen.range.src_mac("0", "start", "f0:4d:a2:72:e1:5a");

pktgen.range.dst_ip("0", "start", "192.168.1.1");
pktgen.range.dst_ip("0", "inc", "0.0.0.1");
pktgen.range.dst_ip("0", "min", "192.168.1.1");
pktgen.range.dst_ip("0", "max", "192.168.1.128");

pktgen.range.src_ip("0", "start", "192.168.0.1");
pktgen.range.src_ip("0", "inc", "0.0.0.1");
pktgen.range.src_ip("0", "min", "192.168.0.1");
pktgen.range.src_ip("0", "max", "192.168.0.128");

pktgen.range.ip_proto("0", "udp");

pktgen.range.dst_port("0", "start", 19899);
pktgen.range.dst_port("0", "inc", 0);
-- pktgen.range.dst_port("0", "min", 2000);
-- pktgen.range.dst_port("0", "max", 4000);

pktgen.range.src_port("0", "start", 5000);
pktgen.range.src_port("0", "inc", 1);
pktgen.range.src_port("0", "min", 5000);
pktgen.range.src_port("0", "max", 7000);

pktgen.range.pkt_size("0", "start", 64);
pktgen.range.pkt_size("0", "inc", 0);
pktgen.range.pkt_size("0", "min", 64);
pktgen.range.pkt_size("0", "max", 256);

pktgen.range.dns("0", "www1.example.com", "A");

-- Set up second port
-- pktgen.range.dst_mac("1", "start", "3c:fd:fe:9c:5c:d8");
-- pktgen.range.src_mac("1", "start", "3c:fd:fe:9c:5c:b8");

-- pktgen.range.dst_ip("1", "start", "192.168.0.1");
-- pktgen.range.dst_ip("1", "inc", "0.0.0.1");
-- pktgen.range.dst_ip("1", "min", "192.168.0.1");
-- pktgen.range.dst_ip("1", "max", "192.168.0.128");

-- pktgen.range.src_ip("1", "start", "192.168.1.1");
-- pktgen.range.src_ip("1", "inc", "0.0.0.1");
-- pktgen.range.src_ip("1", "min", "192.168.1.1");
-- pktgen.range.src_ip("1", "max", "192.168.1.128");

-- pktgen.set_proto("all", "udp");

-- pktgen.range.dst_port("1", "start", 5000);
-- pktgen.range.dst_port("1", "inc", 1);
-- pktgen.range.dst_port("1", "min", 5000);
-- pktgen.range.dst_port("1", "max", 7000);

-- pktgen.range.src_port("1", "start", 2000);
-- pktgen.range.src_port("1", "inc", 1);
-- pktgen.range.src_port("1", "min", 2000);
-- pktgen.range.src_port("1", "max", 4000);

-- pktgen.range.pkt_size("1", "start", 64);
-- pktgen.range.pkt_size("1", "inc", 0);
-- pktgen.range.pkt_size("1", "min", 64);
-- pktgen.range.pkt_size("1", "max", 256);

-- pktgen.range.dns("1", "www1.example.com", "A");

pktgen.set_range("all", "on");
