require "java"
require "logstash-input-snmp_jars.rb"

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
java_import "org.snmp4j.asn1.BER"

module LogStash
  class SnmpClientError < StandardError
  end

  class SnmpClient

    def initialize(address, community, version, retries, timeout, mib)
      @target = build_target(address, community, version, retries, timeout)
      @mib = mib

      # for now hardwired udp transport
      transport = DefaultUdpTransportMapping.new
      @snmp = Snmp.new(transport)
      transport.listen()
    end

    def get(oids, strip_root = 0)
      pdu = PDU.new
      Array(oids).each { |oid| pdu.add(VariableBinding.new(OID.new(oid))) }
      pdu.setType(PDU::GET)

      response_event = @snmp.send(pdu, @target, nil)
      return nil if response_event.nil?

      e = response_event.getError
      raise(SnmpClientError, "error sending snmp get request: #{e.inspect}, #{e.getMessage}") if e

      result = {}
      response_pdu = response_event.getResponse
      raise(SnmpClientError, "timeout sending snmp get request") if response_pdu.nil?

      size = response_pdu.size
      (0..size - 1).each do |i|
        variable_binding = response_pdu.get(i)
        oid = variable_binding.getOid.toString
        variable = variable_binding.getVariable
        value = coerce(variable)

        result[@mib.map_oid(oid, strip_root)] = value
      end

      result
    end


    def walk(oid, strip_root = 0)
      result = {}
      treeUtils = TreeUtils.new(@snmp, DefaultPDUFactory.new)
      events = treeUtils.getSubtree(@target, OID.new(oid))
      return nil if events.nil? || events.size == 0

      events.each do |event|
        next if event.nil?

        if event.isError
          # TODO: see if we can salvage non errored event here
          raise(SnmpClientError, "error sending snmp walk request: #{event.getErrorMessage}")
        end

        var_bindings = event.getVariableBindings
        next if var_bindings.nil? || var_bindings.size == 0

        var_bindings.each do |var_binding|
          next if var_binding.nil?

          oid = var_binding.getOid.toString
          variable = var_binding.getVariable
          value = coerce(variable)

          result[@mib.map_oid(oid, strip_root)] = value
         end
      end

      result
    end

    private

    def coerce(variable)
      variable_syntax = variable.getSyntax
      # puts("variable.getSyntaxString=#{variable.getSyntaxString}")
      case variable_syntax
      when BER::OCTETSTRING
        variable.toString
      when BER::TIMETICKS, BER::COUNTER, BER::COUNTER32
        variable.toLong
      when BER::INTEGER, BER::INTEGER32, BER::GAUGE, BER::GAUGE32
        variable.toInt
      when BER::IPADDRESS
        variable.toString
      when BER::OID
        variable.toString
      when BER::NOSUCHOBJECT
        "Error: No Such Instance currently exists at this OID"
      else
        raise(SnmpClientError, "unknown variable syntax #{variable_syntax}, #{variable.getSyntaxString}")
      end
    end

    def build_target(address, community, version, retries, timeout)
      target = CommunityTarget.new
      target.setCommunity(OctetString.new(community))
      target.setAddress(GenericAddress.parse(address))
      target.setRetries(retries)
      target.setTimeout(timeout)
      target.setVersion(parse_version(version))
      target
    end

    def parse_version(version)
      # TODO implement
      SnmpConstants.version2c
    end
  end
end
