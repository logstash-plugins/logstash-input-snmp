# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require "logstash/inputs/snmp"

describe LogStash::Inputs::Snmp, :ecs_compatibility_support do

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

  ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

    before(:each) do
      allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
    end

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
              hosts => [{ host => "udp:127.0.0.1/161" community => "public" }]
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      if ecs_select.active_mode == :disabled
        expect(event.get("[@metadata][host_protocol]")).to eq("udp")
        expect(event.get("[@metadata][host_address]")).to eq("127.0.0.1")
        expect(event.get("[@metadata][host_port]")).to eq("161")
        expect(event.get("[@metadata][host_community]")).to eq("public")
        expect(event.get("host")).to eql("127.0.0.1")
      else
        expect(event.get("[@metadata][input][snmp][host][protocol]")).to eq("udp")
        expect(event.get("[@metadata][input][snmp][host][address]")).to eq("127.0.0.1")
        expect(event.get("[@metadata][input][snmp][host][port]")).to eq('161')
        expect(event.get("[@metadata][input][snmp][host][community]")).to eq("public")
        expect(event.get("host")).to eql('ip' => "127.0.0.1")
      end
    end

    it "should add custom host field (legacy metadata)" do
      config = <<-CONFIG
          input {
            snmp {
              get => ["1.3.6.1.2.1.1.1.0"]
              hosts => [{ host => "udp:127.0.0.1/161" community => "public" }]
              add_field => { host => "%{[@metadata][host_protocol]}:%{[@metadata][host_address]}/%{[@metadata][host_port]},%{[@metadata][host_community]}" }
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      expect(event.get("host")).to eq("udp:127.0.0.1/161,public")
    end if ecs_select.active_mode == :disabled

    it "should add custom host field (ECS mode)" do
      config = <<-CONFIG
          input {
            snmp {
              get => ["1.3.6.1.2.1.1.1.0"]
              hosts => [{ host => "tcp:192.168.1.11/1161" }]
              add_field => { "[host][formatted]" => "%{[@metadata][input][snmp][host][protocol]}://%{[@metadata][input][snmp][host][address]}:%{[@metadata][input][snmp][host][port]}" }
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      expect(event.get("host")).to eq('formatted' => "tcp://192.168.1.11:1161")
    end if ecs_select.active_mode != :disabled

    it "should target event data" do
      config = <<-CONFIG
          input {
            snmp {
              get => ["1.3.6.1.2.1.1.1.0"]
              hosts => [{ host => "udp:127.0.0.1/161" community => "public" }]
              target => "snmp_data"
            }
          }
      CONFIG
      event = input(config) { |_, queue| queue.pop }

      expect( event.include?('foo') ).to be false
      expect( event.get('[snmp_data]') ).to eql 'foo' => 'bar'
    end
  end

  context "StoppableIntervalRunner" do
    let(:stop_holder) { Struct.new(:value).new(false) }

    before(:each) do
      allow(plugin).to receive(:stop?) { stop_holder.value }
    end

    let(:plugin) do
      double("Plugin").tap do |dbl|
        allow(dbl).to receive(:logger).and_return(double("Logger").as_null_object)
        allow(dbl).to receive(:stop?) { stop_holder.value }
      end
    end

    subject(:interval_runner) { LogStash::Inputs::Snmp::StoppableIntervalRunner.new(plugin) }

    context "#every" do
      context "when the plugin is stopped" do
        let(:interval_seconds) { 2 }
        it 'does not yield the block' do
          stop_holder.value = true
          expect { |yielder| interval_runner.every(interval_seconds, &yielder) }.to_not yield_control
        end
      end

      context "when the yield takes shorter than the interval" do
        let(:duration_seconds) { 1 }
        let(:interval_seconds) { 2 }

        it 'sleeps off the remainder' do
          allow(interval_runner).to receive(:sleep).and_call_original

          interval_runner.every(interval_seconds) do
            Kernel::sleep(duration_seconds) # non-stoppable
            stop_holder.value = true # prevent re-runs
          end

          expect(interval_runner).to have_received(:sleep).with(a_value_within(0.1).of(1))
        end
      end

      context "when the yield takes longer than the interval" do
        let(:duration_seconds) { 2 }
        let(:interval_seconds) { 1 }

        it 'logs a warning to the plugin' do
          allow(interval_runner).to receive(:sleep).and_call_original

          interval_runner.every(interval_seconds) do
            Kernel::sleep(duration_seconds) # non-stoppable
            stop_holder.value = true # prevent re-runs
          end

          expect(interval_runner).to_not have_received(:sleep)

          expect(plugin.logger).to have_received(:warn).with(a_string_including("took longer"), a_hash_including(:interval_seconds => interval_seconds, :duration_seconds => a_value_within(0.1).of(duration_seconds)))
        end
      end

      it 'runs regularly until the plugin is stopped' do
        timestamps = []

        thread = Thread.new do
          interval_runner.every(1) do
            timestamps << Time.now
            Kernel::sleep(Random::rand(0.8))
          end
        end

        Kernel::sleep(5)
        expect(thread).to be_alive

        stop_holder.value = true
        Kernel::sleep(1)

        aggregate_failures do
          expect(thread).to_not be_alive
          expect(timestamps.count).to be_within(1).of(5)

          timestamps.each_cons(2) do |previous, current|
            # ensure each start time is very close to 1s after the previous.
            expect(current - previous).to be_within(0.05).of(1)
          end

          thread.kill if thread.alive?
        end
      end
    end
  end
end

