require 'java'
require 'logstash-input-snmp_jars.rb'


java_import 'org.snmp4j.PDU'
java_import 'org.snmp4j.ScopedPDU'
java_import 'org.snmp4j.Snmp'
java_import 'org.snmp4j.Target'
java_import 'org.snmp4j.TransportMapping'
java_import 'org.snmp4j.event.ResponseEvent'
java_import 'org.snmp4j.mp.MPv3'
java_import 'org.snmp4j.mp.SnmpConstants'
java_import 'org.snmp4j.security.AuthMD5'
java_import 'org.snmp4j.security.AuthSHA'
java_import 'org.snmp4j.security.AuthSHA2'
java_import 'org.snmp4j.security.AuthHMAC128SHA224'
java_import 'org.snmp4j.security.AuthHMAC192SHA256'
java_import 'org.snmp4j.security.AuthHMAC256SHA384'
java_import 'org.snmp4j.security.AuthHMAC384SHA512'
java_import 'org.snmp4j.security.Priv3DES'
java_import 'org.snmp4j.security.PrivDES'
java_import 'org.snmp4j.security.PrivAES128'
java_import 'org.snmp4j.security.PrivAES192'
java_import 'org.snmp4j.security.PrivAES256'
java_import 'org.snmp4j.security.SecurityModels'
java_import 'org.snmp4j.security.SecurityProtocols'
java_import 'org.snmp4j.security.USM'
java_import 'org.snmp4j.security.UsmUser'
java_import 'org.snmp4j.smi.Address'
java_import 'org.snmp4j.smi.GenericAddress'
java_import 'org.snmp4j.smi.OID'
java_import 'org.snmp4j.smi.OctetString'
java_import 'org.snmp4j.transport.DefaultUdpTransportMapping'
java_import 'org.snmp4j.transport.DefaultTcpTransportMapping'
java_import 'org.snmp4j.UserTarget'
java_import 'org.snmp4j.util.DefaultPDUFactory'

module LogStash
  class SnmpClientV3Error < SnmpClientError
  end

  class SnmpClientV3 < SnmpClient

    def initialize(protocol, address, port, v3_details, retries, timeout, mib)
      transport = case protocol.to_s
        when 'udp'
          DefaultUdpTransportMapping.new
        when 'tcp'
          DefaultTcpTransportMapping.new
        else
          raise(SnmpClientV3Error, "invalid transport protocol specified '#{protocol.to_s}', expecting 'udp' or 'tcp'")
      end

      sec_level = parse_auth_level(v3_details["auth_level"])
      sec_name = OctetString.new(v3_details["name"])
      sec_auth_proto = parse_auth_proto(v3_details["auth_protocol"])
      sec_priv_proto = parse_priv_proto(v3_details["priv_protocol"])
      if !v3_details["auth_pass"].nil?
        sec_auth_pass = OctetString.new(v3_details["auth_pass"])
      end
      if !v3_details["priv_pass"].nil?
        sec_priv_pass = OctetString.new(v3_details["priv_pass"])
      end
      @snmp = Snmp.new(transport)
      usm = USM.new(SecurityProtocols.getInstance, OctetString.new(MPv3.createLocalEngineID), 0)
      SecurityModels.getInstance.addSecurityModel(usm)
      transport.listen
      @snmp.getUSM.addUser UsmUser.new(sec_name, sec_auth_proto, sec_auth_pass, sec_priv_proto, sec_priv_pass)
      @target = build_v3_target("#{protocol}:#{address}/#{port}", sec_name, sec_level, retries, timeout)
      @mib = mib

    end

    def build_v3_target(address, name, seclevel, retries, timeout)
      target = UserTarget.new
      target.setSecurityLevel(seclevel)
      target.setSecurityName(name)
      target.setAddress(GenericAddress.parse(address))
      target.setRetries(retries)
      target.setTimeout(timeout)
      target.setVersion(SnmpConstants.version3)
      target
    end

    def parse_priv_proto(privp)
      return nil if privp.nil?
      oidPrivP = case privp.to_s.downcase
      when "des"
        OID.new("1.3.6.1.6.3.10.1.2.2")
      when "3des"
        OID.new("1.3.6.1.6.3.10.1.2.3")
      when "aes"
        OID.new("1.3.6.1.6.3.10.1.2.4")
      when "aes128"
        OID.new("1.3.6.1.6.3.10.1.2.4")
      when "aes192"
        OID.new("1.3.6.1.6.3.10.1.2.5")
      when "aes256"
        OID.new("1.3.6.1.6.3.10.1.2.6")
      else
        raise(SnmpClientError, "privacy protocol '#{privp}' is not supported, expected protocols are 'des', '3des', 'aes', 'aes128', 'aes192', and 'aes256'")
      end
      return oidPrivP
    end

    def get(oids, strip_root = 0)
      @pdu = ScopedPDU.new
      @pdu.context_name = OctetString.new('')
      super
    end
    
    def walk(oids, strip_root = 0)
      @pdufactory = DefaultPDUFactory.new(PDU::GETBULK)
      super
    end

    def parse_auth_proto(authp)
      return nil if authp.nil?
      case authp.to_s.downcase
        when 'md5'
          AuthMD5::ID
        when 'sha'
          AuthSHA::ID
        when 'sha2'
          AuthSHA2::ID
        when 'hmac128sha224'
          AuthHMAC128SHA224::ID
        when 'hmac192sha256'
          AuthHMAC192SHA256::ID
        when 'hmac256sha384'
          AuthHMAC256SHA384::ID
        when 'hmac384sha512'
          AuthHMAC384SHA512::ID
        else
          raise(SnmpClientV3Error, "authentication protocol '#{authp}' is not supported, expected protocols are 'md5', 'sha', and 'sha2'")
      end
    end

    def parse_auth_level(authl)
      return 1 if authl.nil?
      case authl.to_s.downcase
        when 'noauthnopriv'
	  1
        when 'authnopriv'
	  2
        when 'authpriv'
          3
        else
          1
      end
    end      
  end
end
