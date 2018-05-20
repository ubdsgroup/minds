LDFLAGS = -L${libdir} -L../mmrecord
LDADD = -lmmr -lxml
INCLUDES = -I${includedir} -I../mmrecord -I../tcpdump-converter
bin_PROGRAMS = feature_extractor scan_detector
EXTRA_DIST = blk.ports dark.hosts p2p.hosts p2p.ports scandetector-config.xml Count2.h  FeatureExtractor.h  LabelingUnit.h  scan_detector2.h

feature_extractor_SOURCES = feature_extractor.cpp FeatureExtractor.cpp Count2.cpp
scan_detector_SOURCES = scan_detector.cpp LabelingUnit.cpp scan_detector2.cpp

install:
	cp -f scandetector-config.xml blk.ports dark.hosts p2p.hosts p2p.ports ${sysconfdir}/cfg
