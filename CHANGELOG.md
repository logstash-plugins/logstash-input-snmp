## 1.3.1
  -  Refactor: handle no response(s) wout error logging [#105](https://github.com/logstash-plugins/logstash-input-snmp/pull/105)

## 1.3.0
  - Feat: ECS compliance + optional target [#99](https://github.com/logstash-plugins/logstash-input-snmp/pull/99)
  - Internal: update to Gradle 7 [#102](https://github.com/logstash-plugins/logstash-input-snmp/pull/102)

## 1.2.8
  - Fixed interval handling to only sleep off the _remainder_ of the interval (if any), and to log a helpful warning when crawling the hosts takes longer than the configured interval [#100](https://github.com/logstash-plugins/logstash-input-snmp/pull/100). Fixes [#61](https://github.com/logstash-plugins/logstash-input-snmp/issues/61).

## 1.2.7
  - Added integration tests to ensure SNMP server and IPv6 connections [#90](https://github.com/logstash-plugins/logstash-input-snmp/issues/90). Fixes[#87](https://github.com/logstash-plugins/logstash-input-snmp/issues/87).

## 1.2.6
  - Docs: example on setting IPv6 hosts [#89](https://github.com/logstash-plugins/logstash-input-snmp/pull/89)

## 1.2.5
  - Updated snmp4j library to v2.8.4 [#86](https://github.com/logstash-plugins/logstash-input-snmp/pull/86)

## 1.2.4
  - Fixed: support SNMPv3 multiple identical security name with different credentials [#84](https://github.com/logstash-plugins/logstash-input-snmp/pull/84)

## 1.2.3
  - Fixed: multithreading problem when using multiple snmp inputs with multiple v3 credentials [#80](https://github.com/logstash-plugins/logstash-input-snmp/pull/80)

## 1.2.2
  - Refactor: scope and review java_imports [#72](https://github.com/logstash-plugins/logstash-input-snmp/pull/72)

## 1.2.1
  - Fixed GAUGE32 integer overflow [#65](https://github.com/logstash-plugins/logstash-input-snmp/pull/65)

## 1.2.0
  - Adding oid_path_length config option [#59](https://github.com/logstash-plugins/logstash-input-snmp/pull/59)
  - Fixing bug with table support removing index value from OIDs [#60])https://github.com/logstash-plugins/logstash-input-snmp/issues/60)

## 1.1.1
  - Added information and other improvements to documentation [#57](https://github.com/logstash-plugins/logstash-input-snmp/pull/57)

## 1.1.0
  - Added support for querying SNMP tables [#49](https://github.com/logstash-plugins/logstash-input-snmp/pull/49)
  - Changed three error messages in the base_client to include the target address for clarity in the logs.

## 1.0.1
  - Added no_codec condition to the documentation and bumped version [#39](https://github.com/logstash-plugins/logstash-input-snmp/pull/39)
  - Changed docs to improve options layout [#38](https://github.com/logstash-plugins/logstash-input-snmp/pull/38)

## 1.0.0
  - Added improved syntax coercion [#32](https://github.com/logstash-plugins/logstash-input-snmp/pull/32)

## 0.1.0.beta5
  - Added OPAQUE type coercion [#29](https://github.com/logstash-plugins/logstash-input-snmp/pull/29)
  - Added SNMPv3 support [#27](https://github.com/logstash-plugins/logstash-input-snmp/pull/27)
  - Added support for provided MIBs [#25](https://github.com/logstash-plugins/logstash-input-snmp/pull/25)

## 0.1.0.beta4
  - Fixed missing coercions [#12](https://github.com/logstash-plugins/logstash-input-snmp/pull/12)

## 0.1.0.beta3
  - add tcp transport protocol support, https://github.com/logstash-plugins/logstash-input-snmp/pull/8
  - add SNMPv1 protocol version support, https://github.com/logstash-plugins/logstash-input-snmp/pull/9

## 0.1.0.beta2
  - add host info in metadata and host field, https://github.com/logstash-plugins/logstash-input-snmp/pull/7

## 0.1.0.beta1
  - First beta version
