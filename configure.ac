#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)

AC_INIT([src/mmrecord/mm_record.h])
AM_INIT_AUTOMAKE([minds],[1.3],[chandola@cs.umn.edu])
AM_CONFIG_HEADER(config.h)
# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_CHECK_TOOL(RANLIB, ranlib)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([bzero strdup strerror])

AC_OUTPUT(Makefile	\
          src/Makefile	\
	  src/mmrecord/Makefile \
          src/tcpdump-converter/Makefile	\
          src/scan-detector/Makefile	\
          src/anomaly-detector/Makefile	\
          src/p2p-detector/Makefile	\
          docs/Makefile	\
	  )
