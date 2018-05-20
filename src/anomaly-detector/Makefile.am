LDFLAGS = -L${libdir} -L../mmrecord
LDADD = -lmmr -lpthread -lxml
INCLUDES = -I${includedir} -I../mmrecord -I../tcpdump-converter
bin_PROGRAMS = anomaly_detector

anomaly_detector_SOURCES = io.cpp flows.cpp anomaly_detector.cpp input_filter.cpp generate_itemsets.cpp discriminating_itemsets.cpp ordered_binning.cpp

EXTRA_DIST = anomalydetector-config.xml summarization-config.xml anomalydetector.rules README.rules README.config minds_constants io.h flows.h anomaly_detector.h input_filter.h generate_itemsets.h discriminating_itemsets.h ordered_binning.h macros.h

install:
	cp -f anomalydetector-config.xml anomalydetector.rules summarization-config.xml ${sysconfdir}/cfg