INCLUDES = -I$(includedir)
bin_PROGRAMS = collector
include_HEADERS = eee_flows.h

collector_SOURCES = read_tcpdump.cpp io.cpp collector.cpp flowrecord.cpp
collector_LDFLAGS = -L$(libdir)
collector_LDADD = -lpcap
EXTRA_DIST = collector.config flowrecord.h eee_flows.h io.h read_tcpdump.h
install:
	cp -f collector.config ${sysconfdir}/cfg