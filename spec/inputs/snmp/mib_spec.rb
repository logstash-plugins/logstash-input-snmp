# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp/mib"

module LogStash
  describe SnmpMib do

    subject { SnmpMib.new }
    let (:fixtures_dir) { ::File.expand_path(::File.join("..", "..", "..", "fixtures/"), __FILE__) }
    let (:rfc1213_mib) { ::File.join(fixtures_dir, "RFC1213-MIB.dic") }
    let (:collision_mib) { ::File.join(fixtures_dir, "collision.dic") }

    it "should read valid mib dic file" do
      module_name,  nodes = subject.read_mib_dic(rfc1213_mib)
      expect(module_name).to eq("RFC1213-MIB")
      expect(nodes.keys.size).to eq(201)
    end

    it "should produce 0 warning when first adding a mib path" do
      expect_any_instance_of(SnmpMib::Tree).to receive(:logger).never.and_call_original
      subject.add_mib_path(rfc1213_mib)
    end

    it "should produce 0 warning when adding same keys and values" do
      expect_any_instance_of(SnmpMib::Tree).to receive(:logger).never.and_call_original

      subject.add_mib_path(rfc1213_mib)
      subject.add_mib_path(rfc1213_mib)
    end

    it "should produce warning when adding mib with collisions" do
      expect_any_instance_of(SnmpMib::Tree).to receive(:logger).exactly(1).times.and_call_original
      subject.add_mib_path(rfc1213_mib)
      subject.add_mib_path(collision_mib)
    end
    
    it "should find existing oid" do
      subject.add_mib_path(rfc1213_mib)
      expect(subject.map_oid("1.3.6.1.2.1.1")).to eq("1.3.6.1.2.mib-2.system")
    end

    it "should not find inexisting oid " do
      subject.add_mib_path(rfc1213_mib)
      expect(subject.map_oid("0.0.0.0")).to eq("0.0.0.0")
    end
  end
end