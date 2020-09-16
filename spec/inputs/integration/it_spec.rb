require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp"

describe LogStash::Inputs::Snmp do
  let(:config) { {"get" => ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]} }
  let(:plugin) { LogStash::Inputs::Snmp.new(config)}

  after(:each) do
    plugin.stop
  end

  shared_examples "snmp plugin return single event" do
    it "should has OID value" do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
      event = queue.pop

      expect(event).to be_a(LogStash::Event)
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance")).to be_a Integer
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysName.0")).to be_a String
      expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0")).to be_a String
    end
  end

  shared_examples "snmp plugin return one udp event and one tcp event" do |config|
    it "should has one udp from snmp1 and one tcp from snmp2" do
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

  describe "against snmp server", :integration => true do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}]})}
    it_behaves_like "snmp plugin return single event"
  end

  describe "against snmpv3 server", :integration => true do
    let(:config) { super.merge({
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
    let(:config) { super.merge({
                                   "hosts" => [{"host" => "tcp:snmp1/161", "version" => "3"}],
                                   "security_name" => "user_2",
                                   "auth_protocol" => "sha",
                                   "auth_pass" => "STrP@SSPhr@sE",
                                   "priv_protocol" => "aes",
                                   "priv_pass" => "STr0ngP@SSWRD161",
                                   "security_level" => "authPriv"
                               })}

    it "should has error log" do
      expect(plugin.logger).to receive(:error).once
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)
    end
  end

  describe "single plugin input and mix of udp tcp", :integration => true do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "tcp:snmp1/161", "community" => "public"}]})}
    it "should return two events " do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)

      host_cnt_snmp1 = queue.reduce(0) { |sum, event| sum + (event.get("host") == "snmp1"? 1: 0) }
      expect(queue.size).to eq(2)
      expect(host_cnt_snmp1).to eq(2)
    end
  end

  describe "single plugin input and multiple udp hosts", :integration => true do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "udp:snmp2/162", "community" => "public"}]})}
    it "should return two events, one per host" do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)

      hosts = queue.map { |event| event.get("host") }.sort
      expect(queue.size).to eq(2)
      expect(hosts).to eq(["snmp1", "snmp2"])
    end
  end

  describe "multiple pipelines and mix of udp tcp hosts", :integration => true do
    let(:config) { {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}]} }
    let(:config2) { {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "tcp:snmp2/162", "community" => "public"}]} }
    let(:plugin) { LogStash::Inputs::Snmp.new(config)}
    let(:plugin2) { LogStash::Inputs::Snmp.new(config2)}

    it "should return two events, one per host" do
      plugin.register
      plugin2.register
      queue = []
      t = Thread.new {
        stop_plugin_after_seconds(plugin)
        plugin.run(queue)
      }
      t2 = Thread.new {
        stop_plugin_after_seconds(plugin2)
        plugin2.run(queue)
      }
      t.join(2100)
      t2.join(2100)
      plugin2.close

      hosts = queue.map { |event| event.get("host") }.sort
      expect(queue.size).to eq(2)
      expect(hosts).to eq(["snmp1", "snmp2"])
    end
  end

  describe "multiple plugin inputs and mix of udp tcp hosts", :integration => true do
    config = <<-CONFIG
        input {
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "udp:snmp1/161" community => "public"}]
          }
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "tcp:snmp2/162" community => "public"}]
          }
        }
    CONFIG

    it_behaves_like "snmp plugin return one udp event and one tcp event", config
  end

  describe "same security name with different credentials and mix of udp tcp hosts", :integration => true do
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
          }
        }
    CONFIG

    it_behaves_like "snmp plugin return one udp event and one tcp event", config
  end

  describe "ipv6 against snmp1 server", :integration => true do
    let(:config) { super.merge({"hosts" => [{"host" => "tcp:[2001:3984:3989::161]/161"}]})}
    it_behaves_like "snmp plugin return single event"
  end

  def stop_plugin_after_seconds(plugin)
      Thread.new{
        sleep(2)
        plugin.do_stop
      }
  end

end