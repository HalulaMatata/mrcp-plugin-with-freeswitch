AM_CPPFLAGS                = $(UNIMRCP_PLUGIN_INCLUDES)

plugin_LTLIBRARIES         = alirecog.la

alirecog_la_SOURCES       = src/ali_recog_engine.cpp
alirecog_la_CPPFLAGS      = $(AM_CPPFLAGS)
alirecog_la_LDFLAGS       = $(UNIMRCP_PLUGIN_OPTS)

include $(top_srcdir)/build/rules/uniplugin.am

#add ali sdk, download from  (https://github.com/aliyun/alibabacloud-nls-cpp-sdk) and build
UNIMRCP_PLUGIN_INCLUDES += -I$(top_srcdir)/plugins/third-party/NlsSdk3.X_LINUX/include
alirecog_la_CPPFLAGS    += -D_GLIBCXX_USE_CXX11_ABI=0
alirecog_la_LDFLAGS     += -L$(top_srcdir)/plugins/third-party/NlsSdk3.X_LINUX/lib \
                           -lalibabacloud-idst-speech

alirecog_ladir          = $(libdir)
alirecog_la_DATA        = $(top_srcdir)/plugins/third-party/NlsSdk3.X_LINUX/lib/libalibabacloud-idst-speech.so

