require "java"
require "logstash-input-snmp_jars.rb"
require_relative "base_client"

module LogStash
  class SnmpClient < BaseSnmpClient

    java_import "org.snmp4j.CommunityTarget"
    java_import "org.snmp4j.PDU"
    java_import "org.snmp4j.ScopedPDU"
    java_import "org.snmp4j.Snmp"
    java_import "org.snmp4j.Target"
    java_import "org.snmp4j.smi.Address"
    java_import "org.snmp4j.smi.GenericAddress"
    java_import "org.snmp4j.smi.OctetString"
    java_import "org.snmp4j.util.DefaultPDUFactory"

    def initialize(protocol, address, port, community, version, retries, timeout, mib)
      super(protocol, address, port, retries, timeout, mib)
      raise(SnmpClientError, "SnmpClient is expecting version '1' or '2c'") unless ["1", "2c"].include?(version.to_s)

      @snmp = Snmp.new(create_transport(protocol))
      @snmp.listen

      @target = build_target("#{protocol}:#{address}/#{port}", community, version, retries, timeout)
    end

    def close
      @snmp.close
    end

    private

    def get_pdu
      pdu = PDU.new
      pdu.setType(PDU::GET)
      pdu
    end

    def get_pdu_factory
      DefaultPDUFactory.new
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
  end
end
