INCLUDES = -I${includedir} -I../tcpdump-converter
lib_LIBRARIES = libmmr.a
bin_PROGRAMS = e2mmrecord nf2mmrecord mm_cat merge_match nfdump2mmrecord
include_HEADERS = mm_record.h utilities.h mm_reader.h mindsconfig.h MergeMatch.h DumpRead.h

EXTRA_DIST = mergematch-config.xml macros.h MergeMatch.h mindsconfig.h minds.h mm_reader.h mm_record.h nf2mmrecord.h utilities.h DumpRead.h

libmmr_a_SOURCES = mm_record.cpp utilities.cpp mm_reader.cpp MergeMatch.cpp

nf2mmrecord_SOURCES = nf2mmrecord.cpp flow-print.c mm_record.cpp utilities.cpp
nf2mmrecord_LDFLAGS = -L${libdir}
nf2mmrecord_LDADD = -lft
e2mmrecord_SOURCES = e2mmrecord.cpp mm_record.cpp utilities.cpp
nfdump2mmrecord_SOURCES = nfdump2mmrecord.cpp DumpRead.cpp
mm_cat_SOURCES = mm_cat.cpp mm_record.cpp mm_reader.cpp utilities.cpp
merge_match_SOURCES = merge_match.cpp MergeMatch.cpp mm_record.cpp mm_reader.cpp utilities.cpp
merge_match_LDFLAGS = -L${libdir}
merge_match_LDADD = -lxml

install:
	cp -f mergematch-config.xml ${sysconfdir}/cfg