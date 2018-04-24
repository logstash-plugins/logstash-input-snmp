# encoding: utf-8
$LOAD_PATH.unshift(File.expand_path(File.join(__FILE__, "..", "..", "lib")))

require "pp"
require "logstash/inputs/snmp/client"
require "logstash/inputs/snmp/mib"

mib = LogStash::SnmpMib.new
mib.add_mib_path(File.expand_path(File.join("..", "..", "spec", "fixtures", "RFC1213-MIB.dic"), __FILE__))
client = LogStash::SnmpClient.new("udp:127.0.0.1/161", "public", "2c", 2, 1000, mib)

pp client.get("1.3.6.1.2.1.1.1.0")

pp client.walk("1.3.6.1.2.1.1")
