# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp/base_client"

java_import "org.snmp4j.smi.AbstractVariable"
java_import "org.snmp4j.smi.SMIConstants"

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
    end
  end
end