/* omsonarw.c
 * Output module for jSonar sonarw.
 *
 * Copyright 2007-2017 jSonar Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define __USE_XOPEN
#define _GNU_SOURCE


#include <bson.h>
#include <bcon.h>
#include <mongoc.h>
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <json.h>

typedef off_t off64_t;
#include "typedefs.h"
#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "datetime.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "unicode-helper.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omsonarw")
/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)
DEFobjCurrIf(datetime)

typedef struct _instanceData {
	struct json_tokener *json_tokener; /* only if (tplName != NULL) */
    char *db_str;
	char *coll_str;
	char *uri_str;
	char *tplName;
	int bErrMsgPermitted;	/* only one errmsg permitted per connection */

   mongoc_client_t      *client;
   //mongoc_database_t    *database;
   mongoc_collection_t  *collection;
   bson_t *command,
	   reply,
	   *insert;
   bson_error_t          error;
   bool                  retval;

} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "db_str", eCmdHdlrGetWord, 0 },
	{ "coll_str", eCmdHdlrGetWord, 0 },
	{ "uri_str", eCmdHdlrGetWord, 0 },
	{ "template", eCmdHdlrGetWord, 0 }
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};

static pthread_mutex_t mutDoAct = PTHREAD_MUTEX_INITIALIZER;

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	/* use this to specify if select features are supported by this
	 * plugin. If not, the framework will handle that. Currently, only
	 * RepeatedMsgReduction ("last message repeated n times") is optional.
	 */
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

static void closeMongoDB(instanceData *pData)
{
   mongoc_collection_destroy (pData->collection);
   //mongoc_database_destroy (pData->database);
   mongoc_client_destroy (pData->client);
   mongoc_cleanup ();
}


BEGINfreeInstance
CODESTARTfreeInstance
	closeMongoDB(pData);
	if (pData->json_tokener != NULL) {
		json_tokener_free(pData->json_tokener);
	}
	free(pData->db_str);
	free(pData->coll_str);
	free(pData->uri_str);
	free(pData->tplName);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	/* nothing special here */
	(void)pData;
ENDdbgPrintInstInfo


/* report error that occured during *last* operation
 */


static rsRetVal initMongoDB(instanceData *pData, int bSilent)
{
	DEFiRet;

	mongoc_init();

	if (bSilent) 
	{

	}
	
	if (pData->uri_str == NULL)
	{
		DBGPRINTF("omsonarw: cannot connect due to NULL uri string\n");
	}

	pData->client = mongoc_client_new(pData->uri_str);
	if (pData->client == NULL)
	{
		DBGPRINTF("omsonarw: cannot connect due to uri string error: '%s'\n", pData->uri_str);
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}

	if (pData->coll_str == NULL)
	{
		DBGPRINTF("omsonarw: cannot connect due to NULL coll string\n");
	}

	if (pData->db_str == NULL)
	{
		DBGPRINTF("omsonarw: cannot connect due to NULL db string\n");
	}

	pData->collection = mongoc_client_get_collection(pData->client, pData->db_str, pData->coll_str);

	if (pData->collection == NULL)
	{
		DBGPRINTF("omsonarw: cannot create collection\n");

	}

finalize_it:
	RETiRet;
}


/* map syslog severity to lumberjack level
 * TODO: consider moving this to msg.c - make some dirty "friend" references...
 * rgerhards, 2012-03-19
 */
static const char *
getLumberjackLevel(short severity)
{
	switch(severity) {
		case 0: return "FATAL";
		case 1:
		case 2:
		case 3: return "ERROR";
		case 4: return "WARN";
		case 5:
		case 6: return "INFO";
		case 7: return "DEBUG";
		default:DBGPRINTF("omsonarw: invalid syslog severity %u\n", severity);
			return "INVLD";
	}
}


/* small helper: get integer power of 10 */
static int
i10pow(int exp)
{
	int r = 1;
	while(exp > 0) {
		r *= 10;
		exp--;
	}
	return r;
}
/* Return a BSON document when an user hasn't specified a template.
 * In this mode, we use the standard document format, which is somewhat
 * aligned to cee (as described in project lumberjack). Note that this is
 * a moving target, so we may run out of sync (and stay so to retain
 * backward compatibility, which we consider pretty important).
 */
static bson_t *
getDefaultBSON(smsg_t *pMsg)
{
	bson_t *doc = NULL;
	char *procid; short unsigned procid_free; rs_size_t procid_len;
	char *tag; short unsigned tag_free; rs_size_t tag_len;
	char *pid; short unsigned pid_free; rs_size_t pid_len;
	char *sys; short unsigned sys_free; rs_size_t sys_len;
	char *msg; short unsigned msg_free; rs_size_t msg_len;
	int severity, facil;
	int64 ts_gen, ts_rcv; /* timestamps: generated, received */
	int secfrac;
	msgPropDescr_t cProp; /* we use internal implementation knowledge... */

	cProp.id = PROP_PROGRAMNAME;
	procid = (char *)MsgGetProp(pMsg, NULL, &cProp, &procid_len, &procid_free, NULL);
	cProp.id = PROP_SYSLOGTAG;
	tag = (char *)MsgGetProp(pMsg, NULL, &cProp, &tag_len, &tag_free, NULL);
	cProp.id = PROP_PROCID;
	pid = (char *)MsgGetProp(pMsg, NULL, &cProp, &pid_len, &pid_free, NULL);
	cProp.id = PROP_HOSTNAME;
	sys = (char *)MsgGetProp(pMsg, NULL, &cProp, &sys_len, &sys_free, NULL);
	cProp.id = PROP_MSG;
	msg = (char *)MsgGetProp(pMsg, NULL, &cProp, &msg_len, &msg_free, NULL);

	/* TODO: move to datetime? Refactor in any case! rgerhards, 2012-03-30 */
	ts_gen = datetime.syslogTime2time_t(&pMsg->tTIMESTAMP) * 1000; /* ms! */
	DBGPRINTF("omsonarw: ts_gen is %lld\n", (long long) ts_gen);
	DBGPRINTF("omsonarw: secfrac is %d, precision %d\n",  pMsg->tTIMESTAMP.secfrac, pMsg->tTIMESTAMP.secfracPrecision);
	if(pMsg->tTIMESTAMP.secfracPrecision > 3) {
		secfrac = pMsg->tTIMESTAMP.secfrac / i10pow(pMsg->tTIMESTAMP.secfracPrecision - 3);
	} else if(pMsg->tTIMESTAMP.secfracPrecision < 3) {
		secfrac = pMsg->tTIMESTAMP.secfrac * i10pow(3 - pMsg->tTIMESTAMP.secfracPrecision);
	} else {
		secfrac = pMsg->tTIMESTAMP.secfrac;
	}
	ts_gen += secfrac;
	ts_rcv = datetime.syslogTime2time_t(&pMsg->tRcvdAt) * 1000; /* ms! */
	if(pMsg->tRcvdAt.secfracPrecision > 3) {
		secfrac = pMsg->tRcvdAt.secfrac / i10pow(pMsg->tRcvdAt.secfracPrecision - 3);
	} else if(pMsg->tRcvdAt.secfracPrecision < 3) {
		secfrac = pMsg->tRcvdAt.secfrac * i10pow(3 - pMsg->tRcvdAt.secfracPrecision);
	} else {
		secfrac = pMsg->tRcvdAt.secfrac;
	}
	ts_rcv += secfrac;

	/* the following need to be int, but are short, so we need to xlat */
	severity = pMsg->iSeverity;
	facil = pMsg->iFacility;

	doc = BCON_NEW("default",
				   "{",
				   "sys", BCON_UTF8(sys),
				   "time", BCON_DATE_TIME(ts_gen),
				   "time_rcvd", BCON_DATE_TIME(ts_rcv),
				   "msg", BCON_UTF8(msg),
				   "syslog_fac", BCON_INT32(facil),
				   "syslog_sever", BCON_INT32(severity),
				   "syslog_tag", BCON_UTF8(tag),
				   "procid", BCON_UTF8(procid),
				   "pid", BCON_UTF8(pid),
				   "level", BCON_UTF8(getLumberjackLevel(pMsg->iSeverity)),
				    "}");

	if(procid_free) free(procid);
	if(tag_free) free(tag);
	if(pid_free) free(pid);
	if(sys_free) free(sys);
	if(msg_free) free(msg);

	return doc;
}

static bson_t *BSONFromJSONArray(struct json_object *json);
static bson_t *BSONFromJSONObject(struct json_object *json);
static bool BSONAppendExtendedJSON(bson_t *doc, const char *name, struct json_object *json);

/* Append a BSON variant of json to doc using name.  Return TRUE on success */
static bool
BSONAppendJSONObject(bson_t *doc, const char *name, struct json_object *json)
{
	switch (json != NULL ? json_object_get_type(json) : json_type_null)
	{
	case json_type_null:
		return BSON_APPEND_NULL(doc, name);
	case json_type_boolean:
		return BSON_APPEND_BOOL(doc, name,
								json_object_get_boolean(json));
	case json_type_double:
		return BSON_APPEND_DOUBLE(doc, name,
								  json_object_get_double(json));
	case json_type_int:
	{
		int64_t i;

		i = json_object_get_int64(json);
		if (i >= INT32_MIN && i <= INT32_MAX)
			return BSON_APPEND_INT32(doc, name, i);
		else
			return BSON_APPEND_INT64(doc, name, i);
	}
	case json_type_object:
	{

		if (BSONAppendExtendedJSON(doc, name, json) == TRUE)
			return TRUE;

		bson_t *sub;
		bool ok;

		sub = BSONFromJSONObject(json);
		if (sub == NULL)
			return FALSE;
		ok = BSON_APPEND_DOCUMENT_BEGIN(doc, name, sub);
		bson_free(sub);
		return ok;
	}
	case json_type_array:
	{
		bson_t *sub;
		bool ok;

		sub = BSONFromJSONArray(json);
		if (sub == NULL)
			return FALSE;
		ok = BSON_APPEND_DOCUMENT_BEGIN(doc, name, sub);
		bson_destroy(sub);
		return ok;
	}
	case json_type_string:
		return BSON_APPEND_UTF8(doc, name, json_object_get_string(json));

	default:
		return FALSE;
	}
}

/* Note: this function assumes that at max a single sub-object exists. This
 * may need to be extended to cover cases where multiple objects are contained.
 * However, I am not sure about the original intent of this contribution and
 * just came across it when refactoring the json calls. As everything seems
 * to work since quite a while, I do not make any changes now.
 * rgerhards, 2016-04-09
 */
static bool
BSONAppendExtendedJSON(bson_t *doc, const char *name, struct json_object *json)
{
	struct json_object_iterator itEnd = json_object_iter_end(json);
	struct json_object_iterator it = json_object_iter_begin(json);

	if (!json_object_iter_equal(&it, &itEnd)) {
		const char *const key = json_object_iter_peek_name(&it);
		if (strcmp(key, "$date") == 0) {
			struct tm tm;
			int64 ts;
			struct json_object *val;

			val = json_object_iter_peek_value(&it);
			DBGPRINTF("omsonarw: extended json date detected %s", json_object_get_string(val));
			tm.tm_isdst = -1;
			strptime(json_object_get_string(val), "%Y-%m-%dT%H:%M:%S%z", &tm);
			ts = 1000 * mktime(&tm);
			return BSON_APPEND_DATE_TIME(doc, name, ts);
		}
	}
	return FALSE;
}

/* Return a BSON variant of json, which must be a json_type_array */
static bson_t *
BSONFromJSONArray(struct json_object *json)
{
	/* Way more than necessary */
	bson_t *doc = NULL;
	size_t i, array_len;

	doc = bson_new();
	if(doc == NULL)
		goto error;

	array_len = json_object_array_length(json);
	for (i = 0; i < array_len; i++) {
		char buf[sizeof(size_t) * CHAR_BIT + 1];

		if ((size_t)snprintf(buf, sizeof(buf), "%zu", i) >= sizeof(buf))
			goto error;
		if (BSONAppendJSONObject(doc, buf,
					 json_object_array_get_idx(json, i))
		    == FALSE)
			goto error;
	}

	return doc;

error:
	if(doc != NULL)
		bson_destroy(doc);
	return NULL;
}

/* Return a BSON variant of json, which must be a json_type_object */
static bson_t *
BSONFromJSONObject(struct json_object *json)
{
	bson_t *doc = NULL;
	doc = bson_new();
	if(doc == NULL)
		goto error;

	struct json_object_iterator it = json_object_iter_begin(json);
	struct json_object_iterator itEnd = json_object_iter_end(json);
	while (!json_object_iter_equal(&it, &itEnd)) {
		if (BSONAppendJSONObject(doc, json_object_iter_peek_name(&it),
			json_object_iter_peek_value(&it)) == FALSE)
			goto error;
		json_object_iter_next(&it);
	}

	return doc;

error:
	if(doc != NULL)
		bson_free(doc);
	return NULL;
}

BEGINtryResume
CODESTARTtryResume
	if(pWrkrData->pData->client == NULL) {
		iRet = initMongoDB(pWrkrData->pData, 1);
	}
ENDtryResume

BEGINdoAction_NoStrings
	bson_t *doc = NULL;
	instanceData *pData;
CODESTARTdoAction
	pthread_mutex_lock(&mutDoAct);
	pData = pWrkrData->pData;
	/* see if we are ready to proceed */
	if(pData->client == NULL) {
		CHKiRet(initMongoDB(pData, 0));
	}

	if(pData->tplName == NULL) {
		doc = getDefaultBSON(*(smsg_t**)pMsgData);
	} else {
		doc = BSONFromJSONObject(*(struct json_object **)pMsgData);
	}
	if(doc == NULL) {
		dbgprintf("omsonarw: error creating BSON doc\n");
		/* FIXME: is this a correct return code? */
		ABORT_FINALIZE(RS_RET_ERR);
	}
	if(mongoc_collection_insert(pData->collection, MONGOC_INSERT_NONE, doc, NULL, &(pData->error))) {
		pData->bErrMsgPermitted = 1;
	} else {
		dbgprintf("omsonarw: insert error\n");
		//reportMongoError(pData);
		/* close on insert error to permit resume */
		closeMongoDB(pData);
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}

finalize_it:
	pthread_mutex_unlock(&mutDoAct);
	if(doc != NULL)
		bson_destroy(doc);
ENDdoAction


static void
setInstParamDefaults(instanceData *pData)
{
	pData->db_str = NULL;
	pData->coll_str = NULL;
	pData->uri_str = NULL;
	pData->tplName = NULL;

	pData->client = NULL;
	//pData->database = NULL;
	pData->coll_str = NULL;
	pData->command = NULL;
	pData->insert = NULL;
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	CODE_STD_STRING_REQUESTnewActInst(1)
	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
        if(!strcmp(actpblk.descr[i].name, "db_str")) {
			pData->db_str = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "coll_str")) {
			pData->coll_str = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "uri_str")) {
			pData->uri_str = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->tplName = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("omsonarw: program error, non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
	}

	if(pData->tplName == NULL) {
		CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	} else {
		CHKiRet(OMSRsetEntry(*ppOMSR, 0, ustrdup(pData->tplName),
				     OMSR_TPL_AS_JSON));
		CHKmalloc(pData->json_tokener = json_tokener_new());
	}

	if(pData->db_str == NULL)
		CHKmalloc(pData->db_str = strdup("syslog"));
	if(pData->coll_str == NULL)
		 CHKmalloc(pData->coll_str = strdup("log"));

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(!strncmp((char*) p, ":omsonarw:", sizeof(":omsonarw:") - 1)) {
		errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
			"omsonarw supports only v6 config format, use: "
			"action(type=\"omsonarw\" server=...)");
	}
	ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
	objRelease(errmsg, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
	rsRetVal localRet;
	rsRetVal (*pomsrGetSupportedTplOpts)(unsigned long *pOpts);
	unsigned long opts;
	int bJSONPassingSupported;
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	INITChkCoreFeature(bCoreSupportsBatching, CORE_FEATURE_BATCHING);
	DBGPRINTF("omsonarw: module compiled with rsyslog version %s.\n", VERSION);

	/* check if the rsyslog core supports parameter passing code */
	bJSONPassingSupported = 0;
	localRet = pHostQueryEtryPt((uchar *)"OMSRgetSupportedTplOpts",
				    &pomsrGetSupportedTplOpts);
	if(localRet == RS_RET_OK) {
		/* found entry point, so let's see if core supports msg passing */
		CHKiRet((*pomsrGetSupportedTplOpts)(&opts));
		if(opts & OMSR_TPL_AS_JSON)
			bJSONPassingSupported = 1;
	} else if(localRet != RS_RET_ENTRY_POINT_NOT_FOUND) {
		ABORT_FINALIZE(localRet); /* Something else went wrong, not acceptable */
	}
	if(!bJSONPassingSupported) {
		DBGPRINTF("omsonarw: JSON-passing is not supported by rsyslog core, "
			  "can not continue.\n");
		ABORT_FINALIZE(RS_RET_NO_JSON_PASSING);
	}
ENDmodInit
