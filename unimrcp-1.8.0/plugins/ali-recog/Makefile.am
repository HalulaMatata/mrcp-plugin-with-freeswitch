AM_CPPFLAGS                = $(UNIMRCP_PLUGIN_INCLUDES)

plugin_LTLIBRARIES         = alirecog.la

alirecog_la_SOURCES       = src/ali_recog_engine.c
alirecog_la_LDFLAGS       = $(UNIMRCP_PLUGIN_OPTS)

include $(top_srcdir)/build/rules/uniplugin.am

#add ali sdk
UNIMRCP_PLUGIN_INCLUDES += -I$(top_srcdir)/plugins/ali-recog/NlsSdkCpp3.X/include
alirecog_la_LDFLAGS     += -L$(top_srcdir)/plugins/ali-recog/NlsSdkCpp3.X/lib/linux/ \
                           -lalibabacloud-idst-common \
                           -lalibabacloud-idst-speech
alirecog_ladir          = $(libdir)
alirecog_la_DATA        = $(top_srcdir)/plugins/ali-recog/NlsSdkCpp3.X/lib/linux/llalibabacloud-idst-common.so \
                          $(top_srcdir)/plugins/ali-recog/NlsSdkCpp3.X/lib/linux/llalibabacloud-idst-speech.so
