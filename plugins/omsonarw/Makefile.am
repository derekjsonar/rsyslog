pkglib_LTLIBRARIES = omsonarw.la
omsonarw_la_SOURCES = omsonarw.c
omsonarw_la_CPPFLAGS =  $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(LIBSONAR_CLIENT_CFLAGS) $(LIBMONGO_CLIENT_CFLAGS)
omsonarw_la_LDFLAGS = -module -avoid-version
omsonarw_la_LIBADD = $(LIBSONAR_CLIENT_LIBS)  $(LIBMONGO_CLIENT_LIBS)

EXTRA_DIST = 
