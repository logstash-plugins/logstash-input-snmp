require "java"
require "logstash-input-snmp_jars"

java_import "org.snmp4j.CommunityTarget"
java_import "org.snmp4j.PDU"
java_import "org.snmp4j.Snmp"
java_import "org.snmp4j.Target"
java_import "org.snmp4j.TransportMapping"
java_import "org.snmp4j.event.ResponseEvent"
java_import "org.snmp4j.mp.SnmpConstants"
java_import "org.snmp4j.smi.Address"
java_import "org.snmp4j.smi.GenericAddress"
java_import "org.snmp4j.smi.OID"
java_import "org.snmp4j.smi.OctetString"
java_import "org.snmp4j.smi.VariableBinding"
java_import "org.snmp4j.transport.DefaultUdpTransportMapping"
java_import "org.snmp4j.util.TreeUtils"
java_import "org.snmp4j.util.DefaultPDUFactory"

def get(address, community, oids)
  pdu = PDU.new
  oids.each do |oid|
    pdu.add(VariableBinding.new(OID.new(oid)))
  end
  pdu.setType(PDU::GET)
  @snmp.send(pdu, build_target(address, community), nil)
  # if nil it is probably a timeout
end

def bulk(address, community, oid)
  # bulk request result must fit in a UDP packet
  pdu = PDU.new
  pdu.add(VariableBinding.new(OID.new(oid)))
  pdu.setType(PDU::GETBULK)
  event = @snmp.send(pdu, build_target(address, community), nil)
  # if nil it is probably a timeout
  response = event.getResponse
  bindings = response.getVariableBindings

  result = {}
  bindings.each do |binding|
    next if binding.nil?
    result[binding.getOid.toString] = binding.getVariable.toString
  end
  result
end

def build_target(address, community)
  targetAddress = GenericAddress.parse(address)
  target = CommunityTarget.new()
  target.setCommunity(OctetString.new(community))
  target.setAddress(targetAddress)
  target.setRetries(2)
  target.setTimeout(1500)
  target.setVersion(SnmpConstants.version2c)
  target
end

def walk(address, community, oid)
  result = {}
  treeUtils = TreeUtils.new(@snmp, DefaultPDUFactory.new)
  events = treeUtils.getSubtree(build_target(address, community), OID.new(oid))
  if events.nil? || events.size == 0
    puts("unable to read table")
    return
  end

  events.each do |event|
    next if event.nil?
    if event.isError
      puts("error: #{event.getErrorMessage}")
      next
    end

    var_bindings = event.getVariableBindings
    next if var_bindings.nil? || var_bindings.size == 0

    var_bindings.each do |var_binding|
      next if var_binding.nil?
      result[var_binding.getOid.toString] = var_binding.getVariable.toString
    end
  end

  result
end

transport = DefaultUdpTransportMapping.new
@snmp = Snmp.new(transport)
transport.listen()

puts("GET")
event = get("udp:127.0.0.1/161","public", [".1.3.6.1.2.1.1.1.0"])
puts(event.getResponse.size)
puts(PDU.getTypeString(event.getResponse.getType))
puts(event.getResponse.get(0).getVariable.getSyntaxString)
puts(event.getResponse.get(0).getVariable.toString)

puts("WALK")
result = walk("udp:127.0.0.1/161","public", ".1.3.6.1.2.1.2.2")
puts(result.inspect)


puts("BULK")
result = bulk("udp:127.0.0.1/161","public", ".1.3.6.1.2.1.2.2")
puts(result.inspect)



@snmp.close

