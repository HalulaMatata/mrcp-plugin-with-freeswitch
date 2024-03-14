AM_CPPFLAGS                = $(UNIMRCP_PLUGIN_INCLUDES)

plugin_LTLIBRARIES         = alisynth.la

alisynth_la_SOURCES       = src/ali_synth_engine.c
alisynth_la_LDFLAGS       = $(UNIMRCP_PLUGIN_OPTS)

include $(top_srcdir)/build/rules/uniplugin.am

#add ali sdk
UNIMRCP_PLUGIN_INCLUDES += -I$(top_srcdir)/plugins/ali-synth/NlsSdkCpp3.X/include
alisynth_la_LDFLAGS     += -L$(top_srcdir)/plugins/ali-synth/NlsSdkCpp3.X/lib/linux/ \
                           -lalibabacloud-idst-common \
                           -lalibabacloud-idst-speech
alisynth_ladir          = $(libdir)
alisynth_la_DATA        = $(top_srcdir)/plugins/ali-synth/NlsSdkCpp3.X/lib/linux/llalibabacloud-idst-common.so \
                          $(top_srcdir)/plugins/ali-synth/NlsSdkCpp3.X/lib/linux/llalibabacloud-idst-speech.so
