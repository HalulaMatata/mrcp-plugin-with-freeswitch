AM_CPPFLAGS                = $(UNIMRCP_PLUGIN_INCLUDES)

plugin_LTLIBRARIES         = alirecog.la

alirecog_la_SOURCES       = src/ali_recog_engine.cpp
alirecog_la_LDFLAGS       = $(UNIMRCP_PLUGIN_OPTS)

include $(top_srcdir)/build/rules/uniplugin.am

#add ali sdk
UNIMRCP_PLUGIN_INCLUDES += -I$(top_srcdir)/plugins/third-party/NlsCommonSdk/include \
                           -I$(top_srcdir)/plugins/third-party/NlsSdk3.X/include
alirecog_la_LDFLAGS     += -L$(top_srcdir)/plugins/third-party/NlsCommonSdk/lib \
                           -L$(top_srcdir)/plugins/third-party/NlsSdk3.X/lib \
                           -lalibabacloud-idst-common
                           -lalibabacloud-idst-speech
alirecog_ladir          = $(libdir)
alirecog_la_DATA        = $(top_srcdir)/plugins/third-party/NlsCommonSdk/lib/libalibabacloud-idst-common.so \
                          $(top_srcdir)/plugins/third-party/NlsSdk3.X/lib/libalibabacloud-idst-speech.so

