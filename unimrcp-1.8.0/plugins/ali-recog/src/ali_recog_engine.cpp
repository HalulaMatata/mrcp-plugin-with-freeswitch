/*
 * Copyright 2008-2015 Arsen Chaloyan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
/* 
 * Mandatory rules concerning plugin implementation.
 * 1. Each plugin MUST implement a plugin/engine creator function
 *	with the exact signature and name (the main entry point)
 *		MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
 * 2. Each plugin MUST declare its version number
 *		MRCP_PLUGIN_VERSION_DECLARE
 * 3. One and only one response MUST be sent back to the received request.
 * 4. Methods (callbacks) of the MRCP engine channel MUST not block.
 *   (asynchronous response can be sent from the context of other thread)
 * 5. Methods (callbacks) of the MPF engine stream MUST not block.
 */
 
extern "C" {
#include "mrcp_recog_engine.h"
#include "mpf_activity_detector.h"
#include "apt_consumer_task.h"
#include "apt_log.h"
}  // extern C
 
#define RECOG_ENGINE_TASK_NAME "ali Recog Engine"
 
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <ctime>
#include <string>
#include <iostream>
#include <vector>
#include <fstream>
#include <sys/time.h>
#include "nlsClient.h"
#include "nlsEvent.h"
#include "speechRecognizerRequest.h"
#include "Token.h"

#define FRAME_16K_20MS 640
#define SAMPLE_RATE_16K 16000
#define DEFAULT_STRING_LEN 512
#define LOOP_TIMEOUT 60 
#define FRAME_SIZE 3200

#define FORMATLEN 8

#define ZSTR(str) (!str || *str=='\0')

using namespace AlibabaNlsCommon;
using AlibabaNls::NlsClient;
using AlibabaNls::NlsEvent;
using AlibabaNls::LogDebug;
using AlibabaNls::LogInfo;
using AlibabaNls::LogWarning;
using AlibabaNls::LogError;
using AlibabaNls::SpeechRecognizerRequest;
 
typedef struct ali_recog_engine_t ali_recog_engine_t;
typedef struct ali_recog_channel_t ali_recog_channel_t;
typedef struct ali_recog_msg_t ali_recog_msg_t;

// Recognizer识别对象的参数
typedef struct RecognizerParam_st {
	int maxStartSilence;		// 允许的最大开始静音, 可选, 单位是毫秒(0,60000], 超出后服务端将会发送RecognitionCompleted事件, 结束本次识别.注意: 需要先设置enable_voice_detection为true
	int maxEndSilence; 			// 最大结束静音时长。单位：毫秒，取值范围：200ms～6000ms, 超出后服务端将会发送RecognitionCompleted事件, 需要先设置enable_voice_detection为true
	int sample_rate;			// 设置音频数据采样率, 可选参数, 目前支持16000, 8000. 默认是16000
	//int socktimeout;			// 设置Socket接收超时时间。(2.x版本 接口)
	int sendTimeout;			// 设置发送超时时间，默认5000ms。 (3.x版本 接口)
	int recvTimeout;			// 设置接收超时时间， 默认15000ms，需setEnableRecvTimeout开启后生效 (3.x版本 接口)
	bool bIntermediate;			// 设置是否返回中间识别结果, 可选参数. 默认false
	bool bPunctuation;			// 设置是否在后处理中添加标点, 可选参数. 默认false
	bool bITN;					// 设置是否在后处理中执行ITN(数字转换), 可选参数. 默认false
	bool bvoicedetection;		// 设置是否启动自定义静音检测。默认值：false
	char format[FORMATLEN];		// 设置音频数据编码格式（PCM、OPUS、OPU，默认是PCM，推荐OPUS）
	char txtFormat[FORMATLEN];	// 设置输出文本的编码格式，编码格式UTF-8 or GBK。
}RecognizerParam_t;

// Globally maintain a service authentication token and its corresponding validity time stamp
// Before each call to the service, first determine whether the token has expired
// If it has expired, a token is regenerated based on the AccessKey ID and AccessKey Secret, and the global token and its validity timestamp are updated.
// Note: Do not regenerate a new token before calling the service, just regenerate it when the token is about to expire. All concurrent services can share a token.
std::string g_appkey = "";   //阿里的APP KEY
std::string g_akId = "";     // 阿里的access ID
std::string g_akSecret = ""; // 阿里的access secret
std::string g_token = "";
std::string g_domain = "";
std::string g_api_version = "";
std::string g_aliurl = "";
std::string g_alilog_path = "alirecog.log";

static long g_expireTime = -1;
static RecognizerParam_t g_recognizer_params;

// 阿里SDK相关函数声明
static int parse_recognizer_params(apr_table_t *params);
static int checkToken(void);
static int generateToken(std::string akId, std::string akSecret, std::string* token, long* expireTime);

void OnRecognitionStarted(NlsEvent* cbEvent, void* recog_channel);
void OnRecognitionResultChanged(NlsEvent* cbEvent, void* recog_channel);
void OnRecognitionCompleted(NlsEvent* cbEvent, void* recog_channel);
void OnRecognitionTaskFailed(NlsEvent* cbEvent, void* recog_channel);
void OnRecognitionChannelClosed(NlsEvent* cbEvent, void* recog_channel);
 
 
/** Declaration of recognizer engine methods */
static apt_bool_t ali_recog_engine_destroy(mrcp_engine_t *engine);
static apt_bool_t ali_recog_engine_open(mrcp_engine_t *engine);
static apt_bool_t ali_recog_engine_close(mrcp_engine_t *engine);
static mrcp_engine_channel_t* ali_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool);
 
static const struct mrcp_engine_method_vtable_t engine_vtable = {
	ali_recog_engine_destroy,
	ali_recog_engine_open,
	ali_recog_engine_close,
	ali_recog_engine_channel_create
};
 
 
/** Declaration of recognizer channel methods */
static apt_bool_t ali_recog_channel_destroy(mrcp_engine_channel_t *channel);
static apt_bool_t ali_recog_channel_open(mrcp_engine_channel_t *channel);
static apt_bool_t ali_recog_channel_close(mrcp_engine_channel_t *channel);
static apt_bool_t ali_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request);
 
static const struct mrcp_engine_channel_method_vtable_t channel_vtable = {
	ali_recog_channel_destroy,
	ali_recog_channel_open,
	ali_recog_channel_close,
	ali_recog_channel_request_process
};
 
/** Declaration of recognizer audio stream methods */
static apt_bool_t ali_recog_stream_destroy(mpf_audio_stream_t *stream);
static apt_bool_t ali_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec);
static apt_bool_t ali_recog_stream_close(mpf_audio_stream_t *stream);
static apt_bool_t ali_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame);
 
static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	ali_recog_stream_destroy,
	NULL,
	NULL,
	NULL,
	ali_recog_stream_open,
	ali_recog_stream_close,
	ali_recog_stream_write,
	NULL
};
 
/** Declaration of ali recognizer engine */
struct ali_recog_engine_t {
	apt_consumer_task_t	*task;
};
 
/** Declaration of ali recognizer channel */
struct ali_recog_channel_t {
	/** Back pointer to engine */
	ali_recog_engine_t	 *ali_engine;
	/** Engine channel base */
	mrcp_engine_channel_t   *channel;
 
	/** Active (in-progress) recognition request */
	mrcp_message_t		  *recog_request;
	/** Pending stop response */
	mrcp_message_t		  *stop_response;
	/** Indicates whether input timers are started */
	apt_bool_t			   timers_started;
	/** Voice activity detector */
	mpf_activity_detector_t *detector;
	/** File to write utterance to */
	FILE					*audio_out;
 
	/** Ali SpeechRecognizerRequest */
	int						ch_release;
	SpeechRecognizerRequest *ali_request;   //阿里SDK的属性
	/** Ali Recognizer Result */
	const char			  *result;          //阿里SDK返回结果存储在这
};
 
typedef enum {
	ALI_RECOG_MSG_OPEN_CHANNEL,
	ALI_RECOG_MSG_CLOSE_CHANNEL,
	ALI_RECOG_MSG_REQUEST_PROCESS
} ali_recog_msg_type_e;
 
/** Declaration of ali recognizer task message */
struct ali_recog_msg_t {
	ali_recog_msg_type_e  type;
	mrcp_engine_channel_t *channel; 
	mrcp_message_t		*request;
};
 
static apt_bool_t ali_recog_msg_signal(ali_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request);
static apt_bool_t ali_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg);

//inline 
inline bool strTrue(const char *str) {
	return str && (!strcasecmp("true", str) || !strcasecmp("yes", str) || !strcasecmp("1", str));
}

inline bool strFalse(const char *str) {
	return !(str && (!strcasecmp("false", str) || !strcasecmp("no", str) || !strcasecmp("0", str)));
}

/** Declare this macro to set plugin version */
MRCP_PLUGIN_VERSION_DECLARE
 
/**
 * Declare this macro to use log routine of the server, plugin is loaded from.
 * Enable/add the corresponding entry in logger.xml to set a cutsom log source priority.
 *	<source name="RECOG-PLUGIN" priority="DEBUG" masking="NONE"/>
 */
MRCP_PLUGIN_LOG_SOURCE_IMPLEMENT(RECOG_PLUGIN,"RECOG-PLUGIN")
 
/** Use custom log source mark */
#define RECOG_LOG_MARK   APT_LOG_MARK_DECLARE(RECOG_PLUGIN)
 
/** Create ali recognizer engine */
MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
{
	ali_recog_engine_t *ali_engine = (ali_recog_engine_t *)apr_palloc(pool,sizeof(ali_recog_engine_t));
	apt_task_t *task;
	apt_task_vtable_t *vtable;
	apt_task_msg_pool_t *msg_pool;
 
	msg_pool = apt_task_msg_pool_create_dynamic(sizeof(ali_recog_msg_t),pool);
	ali_engine->task = apt_consumer_task_create(ali_engine,msg_pool,pool);
	if(!ali_engine->task) {
		return NULL;
	}
	task = apt_consumer_task_base_get(ali_engine->task);
	apt_task_name_set(task,RECOG_ENGINE_TASK_NAME);
	vtable = apt_task_vtable_get(task);
	if(vtable) {
		vtable->process_msg = ali_recog_msg_process;
	}
 
	/* create engine base */
	return mrcp_engine_create(
				MRCP_RECOGNIZER_RESOURCE,  /* MRCP resource identifier */
				ali_engine,			   /* object to associate */
				&engine_vtable,			/* virtual methods table of engine */
				pool);					 /* pool to allocate memory from */
}
 
/** Destroy recognizer engine */
static apt_bool_t ali_recog_engine_destroy(mrcp_engine_t *engine)
{
	ali_recog_engine_t *ali_engine = (ali_recog_engine_t *)engine->obj;
	if(ali_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(ali_engine->task);
		apt_task_destroy(task);
		ali_engine->task = NULL;
	}
	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Ali engine destroy");
	return TRUE;
}
 
/** Open recognizer engine */
static apt_bool_t ali_recog_engine_open(mrcp_engine_t *engine)
{
	AlibabaNls::LogLevel loglevel = LogInfo;
	int logfilesize = 100;
	int logfilenum = 2;
	int workthread = 4;
	long syncCallTimeout = 60 * 1000;
	const char *value;

	ali_recog_engine_t *ali_engine = (ali_recog_engine_t *)engine->obj;
	if(ali_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(ali_engine->task);
		apt_task_start(task);
	}
	
	//加载引擎参数
	if (!engine->config->params) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Params 'app-key' 'app-id', 'token-secret', '', 'url' must be set");
		goto NLSERR;
	}

	value = apr_table_get(engine->config->params, "app-key"); //ali app key
	if (ZSTR(value)) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Param 'app-key' is null");
		goto NLSERR;
	}
	g_appkey = value;

	value = apr_table_get(engine->config->params, "app-id"); //ali app id
	if (ZSTR(value)) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Param 'app-id' is null");
		goto NLSERR;
	}
	g_akId = value;

	value = apr_table_get(engine->config->params, "token-secret"); //ali token secret
	if (ZSTR(value)) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Param 'token-secret' is null");
		goto NLSERR;
	}
	g_akSecret = value;

	value = apr_table_get(engine->config->params, "url"); //ali url
	if (ZSTR(value)) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Param 'url' is null");
		goto NLSERR;
	}
	g_aliurl = value;

	value = apr_table_get(engine->config->params, "ali-domain"); //ali ali-domain
	if (!ZSTR(value)) {
		g_domain = value;
	}

	value = apr_table_get(engine->config->params, "api-version"); //ali api-version
	if (!ZSTR(value)) {
		g_api_version = value;
	}

	value = apr_table_get(engine->config->params, "log-file"); //日志文件名称
	if (ZSTR(value)) {
		g_alilog_path = value;
	}

	value = apr_table_get(engine->config->params, "log-size"); //日志文件大小 MB
	if (!ZSTR(value)) {
		logfilesize = atoi(value);
		if (logfilesize < 10) {
			logfilesize = 10;
		}
	}

	value = apr_table_get(engine->config->params, "log-level"); //ali api-version
	if (value) {
		if (!strcasecmp("debug", value))
			loglevel = LogDebug;
		else if (!strcasecmp("info", value))
			loglevel = LogInfo;
		else if (!strcasecmp("warn", value))
			loglevel = LogWarning;
		else if (!strcasecmp("error", value))
			loglevel = LogError;
	}

	//set log file
	value = apr_table_get(engine->config->params, "log-num"); //ali api-version
	if (!ZSTR(value)) {
		logfilenum = atoi(value);
		if (logfilenum <= 0) {
			logfilenum = 2;
		}
	}

	value = apr_table_get(engine->config->params, "sync-call-timeout"); //同步超时时间
	if (!ZSTR(value)) {
		syncCallTimeout = atol(value);
		if (syncCallTimeout < 50) {
			syncCallTimeout = 50;
		}
	}

	value = apr_table_get(engine->config->params, "work-thread"); //工作线程
	if (!ZSTR(value)) {
		workthread = atoi(value);
		if (workthread < -1) {
			workthread = -1;
		}
		else if (!workthread) {
			workthread = 4;
		}
	}

	parse_recognizer_params(engine->config->params);

    // 初始化阿里引擎
	// Set Ali logger
	if (-1 == NlsClient::getInstance()->setLogConfig(g_alilog_path.c_str(), loglevel, logfilesize, logfilenum)) {
		printf("set log failed.\n");
	   
		return mrcp_engine_open_respond(engine,FALSE);
	}
 
	//设置同步调用模式的超时时间（ms），0则为关闭同步模式，默认0。此模式start()后收到服务端结果再return出去，stop()后收到close()回调再return出去。
	NlsClient::getInstance()->setSyncCallTimeout(syncCallTimeout);

	// Generate a new token
	if (-1 == generateToken(g_akId, g_akSecret, &g_token, &g_expireTime)) {
		goto NLSERR;
	}
 
	// 高并发的情况下推荐4, 单请求的情况推荐为1
    // 若高并发CPU占用率较高, 则可填-1启用所有CPU核
	NlsClient::getInstance()->startWorkThread(workthread);
	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Load ALi asr Instance sucessed");
	return mrcp_engine_open_respond(engine,TRUE);

NLSERR:
	NlsClient::releaseInstance();
	apt_log(RECOG_LOG_MARK,APT_PRIO_ERROR,"Load ALi asr failed, release instance");
	return mrcp_engine_open_respond(engine,FALSE);
}
 
/** Close recognizer engine */
static apt_bool_t ali_recog_engine_close(mrcp_engine_t *engine)
{
	ali_recog_engine_t *ali_engine = (ali_recog_engine_t *)engine->obj;
	if(ali_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(ali_engine->task);
		apt_task_terminate(task,TRUE);
	}
 
	NlsClient::releaseInstance();
	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Close ALi asr Instance sucessed");
	return mrcp_engine_close_respond(engine);
}
 
static mrcp_engine_channel_t* ali_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool)
{
	mpf_stream_capabilities_t *capabilities;
	mpf_termination_t *termination; 
 
	/* create ali recog channel */
	ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)apr_palloc(pool,sizeof(ali_recog_channel_t));
	recog_channel->ali_engine = (ali_recog_engine_t *)engine->obj;
	recog_channel->recog_request = NULL;
	recog_channel->stop_response = NULL;
	recog_channel->detector = mpf_activity_detector_create(pool);
	recog_channel->audio_out = NULL;
	recog_channel->ali_request = NULL;	
	
	capabilities = mpf_sink_stream_capabilities_create(pool);
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000 | MPF_SAMPLE_RATE_16000,
			"LPCM");
 
	/* create media termination */
	termination = mrcp_engine_audio_termination_create(
			recog_channel,		/* object to associate */
			&audio_stream_vtable, /* virtual methods table of audio stream */
			capabilities,		 /* stream capabilities */
			pool);				/* pool to allocate memory from */
 
	/* create engine channel base */
	recog_channel->channel = mrcp_engine_channel_create(
			engine,			   /* engine */
			&channel_vtable,	  /* virtual methods table of engine channel */
			recog_channel,		/* object to associate */
			termination,		  /* associated media termination */
			pool);				/* pool to allocate memory from */
 
	return recog_channel->channel;
}
 
/** Destroy engine channel */
static apt_bool_t ali_recog_channel_destroy(mrcp_engine_channel_t *channel)
{
	/* nothing to destrtoy */
	return TRUE;
}
 
/** Open engine channel (asynchronous response MUST be sent)*/
static apt_bool_t ali_recog_channel_open(mrcp_engine_channel_t *channel)
{
	if(channel->attribs) {
		/* process attributes */
		const apr_array_header_t *header = apr_table_elts(channel->attribs);
		apr_table_entry_t *entry = (apr_table_entry_t *)header->elts;
		int i;
		for(i=0; i<header->nelts; i++) {
			apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Attrib name [%s] value [%s]",entry[i].key,entry[i].val);
		}
	}
 
	return ali_recog_msg_signal(ALI_RECOG_MSG_OPEN_CHANNEL,channel,NULL);
}
 
/** Close engine channel (asynchronous response MUST be sent)*/
static apt_bool_t ali_recog_channel_close(mrcp_engine_channel_t *channel)
{
	return ali_recog_msg_signal(ALI_RECOG_MSG_CLOSE_CHANNEL,channel,NULL);
}
 
/** Process MRCP channel request (asynchronous response MUST be sent)*/
static apt_bool_t ali_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	return ali_recog_msg_signal(ALI_RECOG_MSG_REQUEST_PROCESS,channel,request);
}
 
/** Process RECOGNIZE request */
static apt_bool_t ali_recog_channel_recognize(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	/* process RECOGNIZE request */
	mrcp_recog_header_t *recog_header;
	ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)channel->method_obj;
	const mpf_codec_descriptor_t *descriptor = mrcp_engine_sink_stream_codec_get(channel);
 
	if(!descriptor) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Failed to Get Codec Descriptor " APT_SIDRES_FMT, MRCP_MESSAGE_SIDRES(request));
		response->start_line.status_code = MRCP_STATUS_CODE_METHOD_FAILED;
		return FALSE;
	}
 
	recog_channel->timers_started = TRUE;
 
	/* get recognizer header */
	recog_header = (mrcp_recog_header_t *)mrcp_resource_header_get(request);
	if(recog_header) {
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_START_INPUT_TIMERS) == TRUE) {
			recog_channel->timers_started = recog_header->start_input_timers;
		}
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_NO_INPUT_TIMEOUT) == TRUE) {
			mpf_activity_detector_noinput_timeout_set(recog_channel->detector,recog_header->no_input_timeout);
		}
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT) == TRUE) {
			mpf_activity_detector_silence_timeout_set(recog_channel->detector,recog_header->speech_complete_timeout);
		}
	}
 
	if(!recog_channel->audio_out) {
		const apt_dir_layout_t *dir_layout = channel->engine->dir_layout;
		char *file_name = apr_psprintf(channel->pool,"utter-%dkHz-%s.pcm",
							descriptor->sampling_rate/1000,
							request->channel_id.session_id.buf);
		char *file_path = apt_vardir_filepath_get(dir_layout,file_name,channel->pool);
		if(file_path) {
			apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Open Utterance Output File [%s] for Writing",file_path);
			recog_channel->audio_out = fopen(file_path,"wb");
			if(!recog_channel->audio_out) {
				apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Failed to Open Utterance Output File [%s] for Writing",file_path);
			}
		}
	}
 
	SpeechRecognizerRequest *ali_request = NlsClient::getInstance()->createRecognizerRequest();
	recog_channel->ali_request = ali_request;
 
    // 初始化阿里SDK的request
	if (ali_request == NULL) {
		printf("createRecognizerRequest failed\n");
		return FALSE;
	}
	ali_request->setOnRecognitionStarted(OnRecognitionStarted, recog_channel);
	ali_request->setOnTaskFailed(OnRecognitionTaskFailed, recog_channel);
	ali_request->setOnChannelClosed(OnRecognitionChannelClosed, recog_channel);
	ali_request->setOnRecognitionResultChanged(OnRecognitionResultChanged, recog_channel);
	ali_request->setOnRecognitionCompleted(OnRecognitionCompleted, recog_channel);
	ali_request->setAppKey(g_appkey.c_str());
	ali_request->setFormat("pcm");
	ali_request->setSampleRate(SAMPLE_RATE_16K);
	ali_request->setIntermediateResult(true);
	ali_request->setPunctuationPrediction(true);
	ali_request->setInverseTextNormalization(true);
	//ali_request->setEnableVoiceDetection(true); 
	//ali_request->setMaxStartSilence(5000);
	//ali_request->setMaxEndSilence(800);
	//ali_request->setCustomizationId("TestId_123");
	//ali_request->setVocabularyId("TestId_456");
	//ali_request->setPayloadParam("{\"vad_model\": \"farfield\"}");
	ali_request->setToken(g_token.c_str()); // 设置账号校验token。必填参数。
 
	if (ali_request->start() < 0) {
		printf("start() failed. may be can not connect server. please check network or firewalld\n");
		NlsClient::getInstance()->releaseRecognizerRequest(recog_channel->ali_request);
		recog_channel->ali_request = NULL;
		return FALSE;
	}
 
	response->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* send asynchronous response */
	mrcp_engine_channel_message_send(channel,response);
	recog_channel->recog_request = request;
	return TRUE;
}
 
/** Process STOP request */
static apt_bool_t ali_recog_channel_stop(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	/* process STOP request */
	ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)channel->method_obj;
	/* store STOP request, make sure there is no more activity and only then send the response */
	recog_channel->stop_response = response;
	return TRUE;
}
 
/** Process START-INPUT-TIMERS request */
static apt_bool_t ali_recog_channel_timers_start(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)channel->method_obj;
	recog_channel->timers_started = TRUE;
	return mrcp_engine_channel_message_send(channel,response);
}
 
/** Dispatch MRCP request */
static apt_bool_t ali_recog_channel_request_dispatch(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_bool_t processed = FALSE;
	mrcp_message_t *response = mrcp_response_create(request,request->pool);
	switch(request->start_line.method_id) {
		case RECOGNIZER_SET_PARAMS:
			break;
		case RECOGNIZER_GET_PARAMS:
			break;
		case RECOGNIZER_DEFINE_GRAMMAR:
			break;
		case RECOGNIZER_RECOGNIZE:
			processed = ali_recog_channel_recognize(channel,request,response);
			break;
		case RECOGNIZER_GET_RESULT:
			break;
		case RECOGNIZER_START_INPUT_TIMERS:
			processed = ali_recog_channel_timers_start(channel,request,response);
			break;
		case RECOGNIZER_STOP:
			processed = ali_recog_channel_stop(channel,request,response);
			break;
		default:
			break;
	}
	if(processed == FALSE) {
		/* send asynchronous response for not handled request */
		mrcp_engine_channel_message_send(channel,response);
	}
	return TRUE;
}
 
/** Callback is called from MPF engine context to destroy any additional data associated with audio stream */
static apt_bool_t ali_recog_stream_destroy(mpf_audio_stream_t *stream)
{
	return TRUE;
}
 
/** Callback is called from MPF engine context to perform any action before open */
static apt_bool_t ali_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec)
{
	return TRUE;
}
 
/** Callback is called from MPF engine context to perform any action after close */
static apt_bool_t ali_recog_stream_close(mpf_audio_stream_t *stream)
{
	return TRUE;
}
 
/* Raise ali START-OF-INPUT event */
static apt_bool_t ali_recog_start_of_input(ali_recog_channel_t *recog_channel)
{
	/* create START-OF-INPUT event */
	mrcp_message_t *message = mrcp_event_create(
						recog_channel->recog_request,
						RECOGNIZER_START_OF_INPUT,
						recog_channel->recog_request->pool);
	if(!message) {
		return FALSE;
	}
 
	/* set request state */
	message->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* send asynch event */
	return mrcp_engine_channel_message_send(recog_channel->channel,message);
}
 
/* Load ali recognition result */
static apt_bool_t ali_recog_result_load(ali_recog_channel_t *recog_channel, mrcp_message_t *message)
{
	mrcp_engine_channel_t *channel = recog_channel->channel;
	const apt_dir_layout_t *dir_layout = channel->engine->dir_layout;
	char *file_path = apt_datadir_filepath_get(dir_layout,"result.xml",message->pool);
	if(!file_path) {
		return FALSE;
	}
	
	/* read the ali result from result */
	mrcp_generic_header_t *generic_header;
 
	apt_string_assign_n(&message->body,recog_channel->result,strlen(recog_channel->result),message->pool);
 
	/* get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(message);
	if(generic_header) {
		/* set content types */
		apt_string_assign(&generic_header->content_type,"application/x-nlsml",message->pool);
		mrcp_generic_header_property_add(message,GENERIC_HEADER_CONTENT_TYPE);
	}
 
	return TRUE;
}
 
/* Raise ali RECOGNITION-COMPLETE event */
static apt_bool_t ali_recog_recognition_complete(ali_recog_channel_t *recog_channel, mrcp_recog_completion_cause_e cause)
{
	mrcp_recog_header_t *recog_header;
	/* create RECOGNITION-COMPLETE event */
	mrcp_message_t *message = mrcp_event_create(
						recog_channel->recog_request,
						RECOGNIZER_RECOGNITION_COMPLETE,
						recog_channel->recog_request->pool);
	if(!message) {
		return FALSE;
	}
 
	/* get/allocate recognizer header */
	recog_header = (mrcp_recog_header_t *)mrcp_resource_header_prepare(message);
	if(recog_header) {
		/* set completion cause */
		recog_header->completion_cause = cause;
		mrcp_resource_header_property_add(message,RECOGNIZER_HEADER_COMPLETION_CAUSE);
	}
	/* set request state */
	message->start_line.request_state = MRCP_REQUEST_STATE_COMPLETE;
 
	if(cause == RECOGNIZER_COMPLETION_CAUSE_SUCCESS) {
		ali_recog_result_load(recog_channel,message);
	}
 
	recog_channel->recog_request = NULL;
	/* send asynch event */
	return mrcp_engine_channel_message_send(recog_channel->channel,message);
}
 
/** Callback is called from MPF engine context to write/send new frame */
static apt_bool_t ali_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame)
{
	ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)stream->obj;
	if(recog_channel->stop_response) {
		/* send asynchronous response to STOP request */
		mrcp_engine_channel_message_send(recog_channel->channel,recog_channel->stop_response);
		recog_channel->stop_response = NULL;
		recog_channel->recog_request = NULL;
		return TRUE;
	}
 
    // 接收的数据帧转给阿里SDK
	if(recog_channel->recog_request) {
		mpf_detector_event_e det_event = mpf_activity_detector_process(recog_channel->detector,frame);
		switch(det_event) {
			case MPF_DETECTOR_EVENT_ACTIVITY:
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Voice Activity " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
				ali_recog_start_of_input(recog_channel);
				break;
			case MPF_DETECTOR_EVENT_INACTIVITY:
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Voice Inactivity " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
				//ali_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_SUCCESS);
				if(recog_channel->ali_request) {
					recog_channel->ali_request->stop();
				}
				break;
			case MPF_DETECTOR_EVENT_NOINPUT:
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Noinput " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
				if(recog_channel->timers_started == TRUE) {
					//ali_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_NO_INPUT_TIMEOUT);
					if(recog_channel->ali_request) {
						recog_channel->ali_request->stop();
					}
				}
				break;
			default:
				break;
		}
 
		if(recog_channel->recog_request) {
			if((frame->type & MEDIA_FRAME_TYPE_EVENT) == MEDIA_FRAME_TYPE_EVENT) {
				if(frame->marker == MPF_MARKER_START_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Start of Event " APT_SIDRES_FMT " id:%d",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id);
				}
				else if(frame->marker == MPF_MARKER_END_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected End of Event " APT_SIDRES_FMT " id:%d duration:%d ts",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id,
						frame->event_frame.duration);
				}
			}
		}
 
		if(recog_channel->audio_out) {
			fwrite(frame->codec_frame.buffer,1,frame->codec_frame.size,recog_channel->audio_out);
		}
 
		if(recog_channel->ali_request) {
			recog_channel->ali_request->sendAudio((const uint8_t *)frame->codec_frame.buffer, frame->codec_frame.size);
		}
	}
	return TRUE;
}
 
static apt_bool_t ali_recog_msg_signal(ali_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_bool_t status = FALSE;
	ali_recog_channel_t *ali_channel = (ali_recog_channel_t *)channel->method_obj;
	ali_recog_engine_t *ali_engine = ali_channel->ali_engine;
	apt_task_t *task = apt_consumer_task_base_get(ali_engine->task);
	apt_task_msg_t *msg = apt_task_msg_get(task);
	if(msg) {
		ali_recog_msg_t *ali_msg;
		msg->type = TASK_MSG_USER;
		ali_msg = (ali_recog_msg_t*) msg->data;
 
		ali_msg->type = type;
		ali_msg->channel = channel;
		ali_msg->request = request;
		status = apt_task_msg_signal(task,msg);
	}
	return status;
}
 
static apt_bool_t ali_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg)
{
	ali_recog_msg_t *ali_msg = (ali_recog_msg_t*)msg->data;
	switch(ali_msg->type) {
		case ALI_RECOG_MSG_OPEN_CHANNEL:
			/* open channel and send asynch response */
			mrcp_engine_channel_open_respond(ali_msg->channel,TRUE);
			break;
		case ALI_RECOG_MSG_CLOSE_CHANNEL:
		{
			/* close channel, make sure there is no activity and send asynch response */
			ali_recog_channel_t *recog_channel = (ali_recog_channel_t *)ali_msg->channel->method_obj;
			if(recog_channel->audio_out) {
				fclose(recog_channel->audio_out);
				recog_channel->audio_out = NULL;
			}
			if (recog_channel->ali_request && recog_channel->ch_release) {
				NlsClient::getInstance()->releaseRecognizerRequest(recog_channel->ali_request);
				recog_channel->ali_request = NULL;
			}
			mrcp_engine_channel_close_respond(ali_msg->channel);
			break;
		}
		case ALI_RECOG_MSG_REQUEST_PROCESS:
			ali_recog_channel_request_dispatch(ali_msg->channel,ali_msg->request);
			break;
		default:
			break;
	}
	return TRUE;
}

// Regenerate a new token base no  AccessKey ID and AccessKey Secrt, and get validity timestamp.
// All concurrent service can share a token, just Regenerate before expire.
static int parse_recognizer_params(apr_table_t *params) {
	int nTmp = 0;
	const char *value;

	memset(&g_recognizer_params, 0, sizeof(g_recognizer_params));
	g_recognizer_params.sample_rate = 8000;
	g_recognizer_params.bvoicedetection = true;
	g_recognizer_params.maxStartSilence = 3000;
	g_recognizer_params.maxEndSilence = 200;
	g_recognizer_params.sendTimeout = 5000;	//ms
	g_recognizer_params.recvTimeout = 0;	//15000ms
	g_recognizer_params.bIntermediate = true;
	g_recognizer_params.bPunctuation = true;
	g_recognizer_params.bITN = true;

	//strcpy(g_recognizer_params.format, "pcm");
	//strcpy(g_recognizer_params.txtFormat, "UTF-8");

	value = apr_table_get(params, "audio-format");
	if (value) {
		if (!strcasecmp(value, "opus") || !strcasecmp(value, "opu") || !strcasecmp(value, "pcm")) {
			strcpy(g_recognizer_params.format, value);
		}
	}
	value = apr_table_get(params, "sample-rate"); 
	if (!ZSTR(value)) {
		nTmp = atoi(value);
		if (nTmp > 0) {
			g_recognizer_params.sample_rate = nTmp;
		}
	}
	value = apr_table_get(params, "output-txtcodec");
	if (value) {
		if (!strcasecmp(value, "UTF-8") || !strcasecmp(value, "GBK")) {
			strcpy(g_recognizer_params.txtFormat, value);
		}
	}
	value = apr_table_get(params, "enable-voice-detection");
	if (false == strFalse(value)) {
		g_recognizer_params.bvoicedetection = false;
	}
	value = apr_table_get(params, "max-start-silence");
	if (!ZSTR(value)) {
		nTmp = atoi(value);
		if (nTmp > 0) {
			g_recognizer_params.maxStartSilence = nTmp;
		}
	}
	value = apr_table_get(params, "max-end-silence");
	if (!ZSTR(value)) {
		nTmp = atoi(value);
		if (nTmp > 0) {
			g_recognizer_params.maxEndSilence = nTmp;
		}
	}
	value = apr_table_get(params, "send-timeout");
	if (!ZSTR(value)) {
		nTmp = atoi(value);
		if (nTmp > 0) {
			g_recognizer_params.sendTimeout = nTmp;
		}
	}
	value = apr_table_get(params, "recv-timeout");
	if (!ZSTR(value)) {
		nTmp = atoi(value);
		if (nTmp > 0) {
			g_recognizer_params.recvTimeout = nTmp;
		}
	}
	value = apr_table_get(params, "enable-intermediate-result");
	if (false == strFalse(value)) {
		g_recognizer_params.bIntermediate = false;
	}
	value = apr_table_get(params, "enable-punctuation-prediction");
	if (false == strFalse(value)) {
		g_recognizer_params.bPunctuation = false;
	}
	value = apr_table_get(params, "enable-inverse-text-normalization");
	if (false == strFalse(value)) {
		g_recognizer_params.bITN = false;
	}

#if 0
	//设置音频数据编码格式 PCM、OPUS、OPU，默认是PCM
	if (!ZSTR(g_recognizer_params.format)) {
		request->setFormat(g_recognizer_params.format);
	}
	// 设置输出文本的编码格式
	if (!ZSTR(g_recognizer_params.txtFormat)) {
		request->setOutputFormat(g_recognizer_params.txtFormat);
	}
    // 设置音频数据采样率, 可选参数, 目前支持16000, 8000. 默认是16000
    request->setSampleRate(g_recognizer_params.sample_rate);
    // 设置是否返回中间识别结果, 可选参数. 默认false
    request->setIntermediateResult(g_recognizer_params.bIntermediate);
    // 设置是否在后处理中添加标点, 可选参数. 默认false
    request->setPunctuationPrediction(g_recognizer_params.bPunctuation);
    // 设置是否在后处理中执行ITN, 可选参数. 默认false
    request->setInverseTextNormalization(g_recognizer_params.bITN);

	//开启静音检测
	if (g_recognizer_params.bvoicedetection) {
		request->setEnableVoiceDetection(true);
    	// 允许的最大开始静音, 可选, 单位是毫秒, 
    	// 超出后服务端将会发送RecognitionCompleted事件, 结束本次识别.
    	// 注意: 需要先设置enable_voice_detection为true
    	request->setMaxStartSilence(g_recognizer_params.maxStartSilence);
    	// 允许的最大结束静音, 可选, 单位是毫秒, 
    	// 超出后服务端将会发送RecognitionCompleted事件, 结束本次识别.
    	// 注意: 需要先设置 enable_voice_detection 为true
    	request->setMaxEndSilence(g_recognizer_params.maxEndSilence);
	}

	//设置发送超时时间，默认5000ms
	if (g_recognizer_params.sendTimeout > 0) {
		request->setSendTimeout(g_recognizer_params.sendTimeout);
	}

	//设置接收超时时间， 默认15000ms，需setEnableRecvTimeout开启后生效
	if (g_recognizer_params.recvTimeout > 0) {
		request->setEnableRecvTimeout(true);
		request->setRecvTimeout(g_recognizer_params.recvTimeout);
	}
#endif
	return 0;
}

/**
* 获取当前系统时间戳，判断token是否过期
*/
static int checkToken(void) {
	std::time_t curTime = std::time(0);
	if (g_expireTime - curTime < 10) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_INFO, "the token will be expired, get new token by AccessKey-ID and AccessKey-Secret.");
		int ret = generateToken(g_akId, g_akSecret, &g_token, &g_expireTime);
		if (ret < 0) {
			apt_log(RECOG_LOG_MARK,APT_PRIO_ERROR,"generate token failed.");
			return -1;
		} else {
			if (g_token.empty() || g_expireTime < 0) {
				apt_log(RECOG_LOG_MARK,APT_PRIO_ERROR,"generate empty token.");
				return -2;
			}
    	}
  	}
	return 0;
}

static int generateToken(std::string akId, std::string akSecret, std::string* token, long* expireTime) {
	NlsToken nlsTokenRequest;
	nlsTokenRequest.setAccessKeyId(akId.c_str());
	nlsTokenRequest.setKeySecret(akSecret.c_str());
 
	if (-1 == nlsTokenRequest.applyNlsToken()) {
		// Get failure reson.
		printf("generateToken Failed: %s\n", nlsTokenRequest.getErrorMsg());
		return -1;
	}
 
	*token = nlsTokenRequest.getToken();
	*expireTime = nlsTokenRequest.getExpireTime();
	return 0;
}
 
void OnRecognitionStarted(NlsEvent* cbEvent, void* recog_channel) {
	ali_recog_channel_t* tmp_chan = (ali_recog_channel_t*)recog_channel;
	printf("OnRecognitionStarted: status code=%d, task id=%s\n", cbEvent->getStatusCode(), cbEvent->getTaskId());
}
 
// 阿里的SDK回调实现
void OnRecognitionResultChanged(NlsEvent* cbEvent, void* recog_channel) {
	ali_recog_channel_t* tmp_chan = (ali_recog_channel_t*)recog_channel;
	printf("OnRecognitionResultChanged: status code=%d, task id=%s, result=%s\n", cbEvent->getStatusCode(), cbEvent->getTaskId(), cbEvent->getResult());
	tmp_chan->result = cbEvent->getResult();	
}
 
void OnRecognitionCompleted(NlsEvent* cbEvent, void* recog_channel) {
	ali_recog_channel_t* tmp_chan = (ali_recog_channel_t*)recog_channel;
	printf("OnRecognitionCompleted: status code=%d, task id=%s, result=%s\n", cbEvent->getStatusCode(), cbEvent->getTaskId(), cbEvent->getResult());
	tmp_chan->result = cbEvent->getResult();	
	ali_recog_recognition_complete(tmp_chan, RECOGNIZER_COMPLETION_CAUSE_SUCCESS);
}
 
void OnRecognitionTaskFailed(NlsEvent* cbEvent, void* recog_channel) {
	ali_recog_channel_t* tmp_chan = (ali_recog_channel_t*)recog_channel;
	printf("OnRecognitionTaskFailed: status code=%d, task id=%s, error message=%s\n", cbEvent->getStatusCode(), cbEvent->getTaskId(), cbEvent->getErrorMessage());
}
 
void OnRecognitionChannelClosed(NlsEvent* cbEvent, void* recog_channel) {
	ali_recog_channel_t* tmp_chan = (ali_recog_channel_t*)recog_channel;
	tmp_chan->ch_release = 1;
	printf("OnRecognitionChannelClosed: response=%s\n", cbEvent->getAllResponse());
}
