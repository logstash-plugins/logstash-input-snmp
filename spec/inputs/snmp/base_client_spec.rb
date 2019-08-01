# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp/base_client"

java_import "org.snmp4j.smi.AbstractVariable"
java_import "org.snmp4j.smi.SMIConstants"
java_import "org.snmp4j.smi.Gauge32"
java_import "org.snmp4j.smi.Integer32"

module LogStash

  class TestableBaseSnmpClient < BaseSnmpClient
    def coerce(*args)
      super(*args)
    end
  end

  describe BaseSnmpClient do

    subject { TestableBaseSnmpClient.new(*client_options) }

    context "coercion" do
      let(:mib) { SnmpMib.new }
      let(:client_options) {["udp", "127.0.0.1", "161", 2, 1000, mib]}

      it "should handle BER::NOSUCHINSTANCE" do
        v = AbstractVariable.create_from_syntax(SMIConstants::EXCEPTION_NO_SUCH_INSTANCE)
        expect(v.get_syntax).to eq(BER::NOSUCHINSTANCE)
        expect(subject).to receive(:logger).never
        expect(subject.coerce(v)).to eq("error: no such instance currently exists at this OID")
      end

      it "should log on unsupported coercion" do
        v = AbstractVariable.create_from_syntax(SMIConstants::EXCEPTION_END_OF_MIB_VIEW )
        expect(subject).to receive(:logger).exactly(1).times.and_call_original
        expect(subject.coerce(v)).to eq("error: unknown variable syntax 130, EndOfMibView")
      end
	  
      it "should handle max unsigned 32 bits integer GAUGE32" do
        MAX_UNSIGNED_INT_32 = 4294967295
        v = Gauge32.new(MAX_UNSIGNED_INT_32)
        expect(subject.coerce(v)).to eq(MAX_UNSIGNED_INT_32)
      end

      it "should handle max signed 32 bits integer INTEGER32" do
        MAX_SIGNED_INT_32 = 2147483647
        v = Integer32.new(MAX_SIGNED_INT_32)
        expect(subject.coerce(v)).to eq(MAX_SIGNED_INT_32)
      end
    end
  end
end
