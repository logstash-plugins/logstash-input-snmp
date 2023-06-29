require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp"

describe LogStash::Inputs::Snmp do
  let(:config) { {"get" => %w[1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.5.0], "ecs_compatibility" => "disabled" } }
  let(:plugin) { LogStash::Inputs::Snmp.new(config)}

  shared_examples "snmp plugin return single event" do
    it "should have OID value" do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
      plugin.close
      event = queue.pop

      expect(event).to be_a(LogStash::Event)
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance")).to be_a Integer
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysName.0")).to be_a String
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0")).to be_a String
    end
  end

  shared_examples "snmp plugin return one udp event and one tcp event" do |config|
    it "should have one udp from snmp1 and one tcp from snmp2" do
      events = input(config) { |_, queue| 2.times.collect { queue.pop } }
      udp = 0; tcp = 0
      events.each { |event|
        if event.get("[@metadata][host_protocol]") == "udp"
          udp += 1
          expect(event.get("[@metadata][host_protocol]")).to eq("udp")
          expect(event.get("[@metadata][host_address]")).to eq("snmp1")
          expect(event.get("[@metadata][host_port]")).to eq("161")
        else
          tcp += 1
          expect(event.get("[@metadata][host_protocol]")).to eq("tcp")
          expect(event.get("[@metadata][host_address]")).to eq("snmp2")
          expect(event.get("[@metadata][host_port]")).to eq("162")
        end
      }
      expect(udp).to eq(1)
      expect(tcp).to eq(1)
    end
  end

  describe "against single snmp server with snmpv2 and udp", :integration => true do
    let(:config) { super().merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}]})}
    it_behaves_like "snmp plugin return single event"
  end

  describe "against single server with snmpv3 and tcp", :integration => true do
    let(:config) { super().merge({
       "hosts" => [{"host" => "tcp:snmp1/161", "version" => "3"}],
       "security_name" => "user_1",
       "auth_protocol" => "sha",
       "auth_pass" => "STrP@SSPhr@sE",
       "priv_protocol" => "aes",
       "priv_pass" => "STr0ngP@SSWRD161",
       "security_level" => "authPriv"
                               })}

    it_behaves_like "snmp plugin return single event"
  end

  describe "invalid user against snmpv3 server", :integration => true do
    let(:config) { super().merge({
                                   "hosts" => [{"host" => "tcp:snmp1/161", "version" => "3"}],
                                   "security_name" => "user_2",
                                   "auth_protocol" => "sha",
                                   "auth_pass" => "STrP@SSPhr@sE",
                                   "priv_protocol" => "aes",
                                   "priv_pass" => "STr0ngP@SSWRD161",
                                   "security_level" => "authPriv"
                               })}

    it "should have error log" do
      expect(plugin.logger).to receive(:error).once
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
      plugin.close
    end
  end

  describe "single input plugin on single server with snmpv2 and mix of udp and tcp", :integration => true do
    let(:config) { super().merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "tcp:snmp1/161", "community" => "public"}]})}
    it "should return two events " do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
      plugin.close

      host_cnt_snmp1 = queue.select {|event| event.get("host") == "snmp1"}.size
      expect(queue.size).to eq(2)
      expect(host_cnt_snmp1).to eq(2)
    end
  end

  describe "single input plugin on multiple udp hosts", :integration => true do
    let(:config) { super().merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "udp:snmp2/162", "community" => "public"}]})}
    it "should return two events, one per host" do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
      plugin.close

      hosts = queue.map { |event| event.get("host") }.sort
      expect(queue.size).to eq(2)
      expect(hosts).to eq(["snmp1", "snmp2"])
    end
  end

  describe "multiple pipelines and mix of udp tcp hosts", :integration => true do
    let(:config) { {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}], "ecs_compatibility" => "disabled" } }
    let(:config2) { {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "tcp:snmp2/162", "community" => "public"}], "ecs_compatibility" => "disabled"} }
    let(:plugin) { LogStash::Inputs::Snmp.new(config)}
    let(:plugin2) { LogStash::Inputs::Snmp.new(config2)}

    it "should return two events, one per host" do
      plugin.register
      plugin2.register
      queue = []
      queue2 = []
      t = Thread.new {
        stop_plugin_after_seconds(plugin)
        plugin.run(queue)
      }
      t2 = Thread.new {
        stop_plugin_after_seconds(plugin2)
        plugin2.run(queue2)
      }
      t.join(2100)
      t2.join(2100)
      plugin.close
      plugin2.close

      hosts = [queue.pop, queue2.pop].map { |event| event.get("host") }.sort
      expect(hosts).to eq(["snmp1", "snmp2"])
    end
  end

  describe "multiple plugin inputs and mix of udp tcp hosts", :integration => true do
    config = <<-CONFIG
        input {
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "udp:snmp1/161" community => "public"}]
            ecs_compatibility => "disabled"
          }
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "tcp:snmp2/162" community => "public"}]
            ecs_compatibility => "disabled"
          }
        }
    CONFIG

    it_behaves_like "snmp plugin return one udp event and one tcp event", config
  end

  describe "two plugins on different hosts with snmpv3 with same security name with different credentials and mix of udp and tcp", :integration => true do
    config = <<-CONFIG
        input {
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "udp:snmp1/161" version => "3"}]
            security_name => "user_1"
            auth_protocol => "sha"
            auth_pass => "STrP@SSPhr@sE"
            priv_protocol => "aes"
            priv_pass => "STr0ngP@SSWRD161"
            security_level => "authPriv"
            ecs_compatibility => "disabled"
          }
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "tcp:snmp2/162" version => "3"}]
            security_name => "user_1"
            auth_protocol => "sha"
            auth_pass => "STrP@SSPhr@sE"
            priv_protocol => "aes"
            priv_pass => "STr0ngP@SSWRD162"
            security_level => "authPriv"
            ecs_compatibility => "disabled"
          }
        }
    CONFIG

    it_behaves_like "snmp plugin return one udp event and one tcp event", config
  end

  describe "single host with tcp over ipv6", :integration => true do
    let(:config) { super().merge({"hosts" => [{"host" => "tcp:[2001:3984:3989::161]/161"}]})}
    it_behaves_like "snmp plugin return single event"
  end

  def stop_plugin_after_seconds(plugin)
      Thread.new{
        sleep(2)
        plugin.do_stop
      }
  end

end