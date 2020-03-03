[dionaea]
download.dir=@DIONAEA_STATEDIR@/binaries/
modules=python,pcap
processors=filter_dummy

listen.mode=getifaddrs

ssl.default.c=PL
ssl.default.cn=GBTI S.A.
ssl.default.o=GBTI S.A.
ssl.default.ou=GBTI S.A.

[logging]
default.filename=@DIONAEA_LOGDIR@/dionaea.log
default.levels=critical
default.domains=*

[processor.filter_dummy]
name=filter

[module.python]
imports=dionaea.log,dionaea.services,dionaea.ihandlers
sys_paths=default
service_configs=@DIONAEA_CONFDIR@/services-enabled/*.yaml
ihandler_configs=@DIONAEA_CONFDIR@/ihandlers-enabled/*.yaml

[module.pcap]
any.interface=any
