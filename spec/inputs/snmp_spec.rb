# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
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
      # devutils in v6 calls close on the test pipelines while it does not in v7+
      expect(mock_client).to receive(:close).at_most(:once)
    end
  end

  context "OIDs options validation" do
    let(:valid_configs) {
        [
            {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_root_skip" => 2},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => 2},
            {"get" => ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => ["1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"walk" => ["1.3.6.1.2.1.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"tables" => [{"name" => "ltmPoolStatTable", "columns" => ["1.3.6.1.4.1.3375.2.2.5.2.3.1.1", "1.3.6.1.4.1.3375.2.2.5.2.3.1.6"]}], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
        ]
    }

    let(:invalid_configs) {
      [
          {"get" => ["1.3.6.1.2.1.1.1.a"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["test"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => [], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => "foo", "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => "a" },
          {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => 2, "oid_root_skip" => 2 },
          {"walk" => "foo", "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"tables" => [{"columns" => ["1.2.3.4", "4.3.2.1"]}], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
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
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp:127.0.0.1/112345"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp:127.0.0.1/161", "community" => "public"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "1"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "2c"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "v3user"},

          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[::1]/16100"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8:0:1:1:1:1:1]/16100"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8::2:1]/161"}]},
      ]
    }

    let(:invalid_configs) {
      [
          {"get" => ["1.0"], "hosts" => [{"host" => "aaa:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp.127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}, {"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "2"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3a"}]},
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

  context "v3_users options validation" do
    let(:valid_configs) {
      [
	  {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "sha", "auth_pass" => "myshapass", "priv_protocol" => "aes", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"},
	  {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8:0:1:1:1:1:1]/1610", "version" => "3"}], "security_name" => "dellv3", "auth_protocol" => "md5", "auth_pass" => "myshapass", "priv_protocol" => "3des", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"}
      ]
    }

    let(:invalid_configs) {
      [
	  {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "badauth", "auth_pass" => "myshapass", "priv_protocol" => "aes", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"},
	  {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "sha"}
      ]
    }

    it "validates v3_users" do
      valid_configs.each do |config|
        expect{ described_class.new(config).register }.not_to raise_error
      end
      invalid_configs.each do |config|
        expect{ described_class.new(config).register }.to raise_error(LogStash::ConfigurationError)
      end
    end
  end

  context "@metadata" do
    before do
      expect(LogStash::SnmpClient).to receive(:new).and_return(mock_client)
      expect(mock_client).to receive(:get).and_return({"foo" => "bar"})
      # devutils in v6 calls close on the test pipelines while it does not in v7+
      expect(mock_client).to receive(:close).at_most(:once)
    end

    it "shoud add @metadata fields and add default host field" do
      config = <<-CONFIG
          input {
            snmp {
              get => ["1.3.6.1.2.1.1.1.0"]
              hosts => [{host => "udp:127.0.0.1/161" community => "public"}]
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      expect(event.get("[@metadata][host_protocol]")).to eq("udp")
      expect(event.get("[@metadata][host_address]")).to eq("127.0.0.1")
      expect(event.get("[@metadata][host_port]")).to eq("161")
      expect(event.get("[@metadata][host_community]")).to eq("public")
      expect(event.get("host")).to eq("127.0.0.1")
    end

    it "shoud add custom host field" do
      config = <<-CONFIG
          input {
            snmp {
              get => ["1.3.6.1.2.1.1.1.0"]
              hosts => [{host => "udp:127.0.0.1/161" community => "public"}]
              add_field => { host => "%{[@metadata][host_protocol]}:%{[@metadata][host_address]}/%{[@metadata][host_port]},%{[@metadata][host_community]}" }
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      expect(event.get("host")).to eq("udp:127.0.0.1/161,public")
    end
  end
end

