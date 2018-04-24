# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp"

describe LogStash::Inputs::Snmp do
  let(:mock_client) { double("LogStash::SnmpClient") }

  it_behaves_like "an interruptible input plugin" do
    let(:config) {{
        "get" => ["1.3.6.1.2.1.1.1.0"],
        "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}]
    }}

    before do
      expect(LogStash::SnmpClient).to receive(:new).and_return(mock_client)
      expect(mock_client).to receive(:get).and_return({})
    end
  end

  context "OIDs options validation" do
    let(:valid_configs) {
        [
            {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => ["1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
        ]
    }

    let(:invalid_configs) {
      [
          {"get" => ["1.3.6.1.2.1.1.1.a"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["test"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => [], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => "foo", "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
      ]
    }

    it "validates get oids" do
      valid_configs.each do |config|
        expect{ described_class.new(config).register }.not_to raise_error
      end
      invalid_configs.each do |config|
        expect{ described_class.new(config).register }.to raise_error(LogStash::ConfigurationError)
      end
    end
  end

  context "hosts options validation" do
    let(:valid_configs) {
      [
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:localhost/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/112345"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}]},
      ]
    }

    let(:invalid_configs) {
      [
          {"get" => ["1.0"], "hosts" => [{"host" => "aaa:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}, {"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => ""},
          {"get" => ["1.0"], "hosts" => []},
          {"get" => ["1.0"] },
      ]
    }

    it "validates hosts" do
      valid_configs.each do |config|
        expect{ described_class.new(config).register }.not_to raise_error
      end
      invalid_configs.each do |config|
        expect{ described_class.new(config).register }.to raise_error(LogStash::ConfigurationError)
      end
    end
  end
end
