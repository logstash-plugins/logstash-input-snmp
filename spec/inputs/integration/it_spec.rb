require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/snmp"

describe LogStash::Inputs::Snmp, :integration => true do
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

  shared_examples "snmp plugin return events" do
    it "should has two events" do
      plugin.register
      queue = []
      stop_plugin_after_seconds(plugin)
      plugin.run(queue)

      expect(queue.size).to eq(2)
    end
  end

  describe "against snmp server" do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}]})}
    it_behaves_like "snmp plugin return single event"
  end

  describe "against snmpv3 server" do
    let(:config) { super.merge({
       "hosts" => [{"host" => "tcp:snmp1/161", "version" => "3"}],
       "security_name" => "user_1",
       "auth_protocol" => "sha",
       "auth_pass" => "STrP@SSPhr@sE",
       "priv_protocol" => "aes",
       "priv_pass" => "STr0ngP@SSWRD",
       "security_level" => "authPriv"
                               })}

    it_behaves_like "snmp plugin return single event"
  end

  describe "single plugin input and mix of udp tcp" do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "tcp:snmp1/161", "community" => "public"}]})}
    it_behaves_like "snmp plugin return events"
  end

  describe "single plugin input and multiple udp hosts" do
    let(:config) { super.merge({"hosts" => [{"host" => "udp:snmp1/161", "community" => "public"}, {"host" => "udp:snmp2/162", "community" => "public"}]})}
    it_behaves_like "snmp plugin return events"
  end


  def stop_plugin_after_seconds(plugin)
      Thread.new{
        sleep(2)
        plugin.do_stop
      }
  end
end