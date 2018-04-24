# encoding: utf-8
$LOAD_PATH.unshift(File.expand_path(File.join(__FILE__, "..", "..", "lib")))

require "pp"
require "logstash/inputs/snmp/mib"

mib = LogStash::SnmpMib.new
# module_name, names, oids = mib.read_mib_dic("tmp/RFC1213-MIB.dic")
# puts(module_name)
# pp(names)
# pp(oids)

mib.add_mib_path(File.expand_path(File.join("..", "..", "spec", "fixtures", "RFC1213-MIB.dic"), __FILE__))

pp mib.find_oid("1.3.6.1.2.1.1")
pp mib.find_oid("1.3.6.1.2.1.1.1.0")