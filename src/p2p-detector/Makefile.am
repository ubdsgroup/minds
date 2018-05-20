LDFLAGS = -L${libdir} -L../mmrecord
LDADD = -lmmr -lxml
INCLUDES = -I${includedir} -I../mmrecord -I../tcpdump-converter
bin_PROGRAMS = p2p_detector
EXTRA_DIST = p2pdetector-config.xml p2p_detector.h
p2p_detector_SOURCES = p2p_detector.cpp p2p.cpp

install:
	cp -f p2pdetector-config.xml ${sysconfdir}/cfg