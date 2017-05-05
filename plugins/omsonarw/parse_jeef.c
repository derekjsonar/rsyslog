
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <bson.h>
#include <bcon.h>
#include <malloc.h>
// #include <mongoc.h>
// #include "config.h"

// #include <ctype.h>
// #include <errno.h>
// #include <assert.h>
// #include <signal.h>
// #include <stdint.h>
// #include <time.h>
// #include <json.h>

//typedef off_t off64_t;

typedef enum { CEF_STANDARD = 0 ,LEEF1_STANDARD = 1 , LEEF2_STANDARD = 2 } event_standard_t;

const int cef_hdrs_len = 7;
static const char *const cef_hdrs[] = {"Version", "Device Vendor", "Device Product",
                                        "Device Version", "Signature ID", "Name", "Severity"};

const int leef_hdrs_len = 5;
static const char *const leef_hdrs[] = {"Version", "Vendor", "Product", "Version", "EventID"};
                                        
static const char *const cef_format_hdr = "CEF:0";
static const char *const leef1_format_hdr = "LEEF:1.0";
static const char *const leef2_format_hdr = "LEEF:2.0";



#define DEFAULT_DATE_FORMAT "%b %d %Y %H:%M:%S" 

struct java_to_POSIX_date_format_tag {
  const char *java_format;
  const char *unix_format;
} java_to_POSIX_date[] = {
  { "MMM dd yyyy HH:mm:ss" , "%b %d %Y %H:%M:%S"  } ,
  { "MMM dd yyyy HH:mm:ss.SSS", "%b %d %Y %H:%M:%S.000"},
  { "MMM dd yyyy HH:mm:ss.SSS z", "%b %d %Y %H:%M:%S.000 %Z"} ,
  {NULL,NULL}
} ;

const char * convert_java_date_format_to_posix(const char *java_format)
{
  int i;
  for ( i = 0 ; java_to_POSIX_date[i].java_format ; i++ ) {
    if ( strcmp(java_to_POSIX_date[i].java_format, java_format) == 0 ) {
      return java_to_POSIX_date[i].unix_format;
    }
  }
  return DEFAULT_DATE_FORMAT;
}

#define MAX_FIELDS 1024

typedef struct  {
  const char *key;
  const char *value;
} raw_field;


typedef struct  {
  int last_field;
  raw_field fields[MAX_FIELDS];
} raw_message_fields ;

raw_message_fields *get_new_message_fields_list()
{
   raw_message_fields *ret = (raw_message_fields *) malloc(sizeof (raw_message_fields));
   ret->last_field = 0;
   return ret;
}

void
free_new_message_fields_list(raw_message_fields *g)
{
  free(g);
}


int add_field(raw_message_fields *flds, const char *key, const char *value)
{
  if (flds->last_field < MAX_FIELDS ) {
    flds->fields[flds->last_field].key = key;
    flds->fields[flds->last_field].value = value;
    flds->last_field++;
  }
  return MAX_FIELDS - flds->last_field ;
}

 const char *find_date_format(raw_message_fields *all_fields)
{
  int i = 0 ;
  for (  i = 0 ; i < all_fields->last_field ; i++ ) {
    if ( strcmp(all_fields->fields[i].key, "devTimeFormat") == 0 ) {
      return convert_java_date_format_to_posix(all_fields->fields[i].value);
    }
  }
  return DEFAULT_DATE_FORMAT ;
}





typedef struct parsing_state
{
    char attr_separator;
    event_standard_t standard;
    int hdr_offset;
} parsing_state;





struct key_to_bson_type_tag {
  const char *key;
  const char *full_name;
  bson_type_t type;
  const char *default_value;
}  key_to_bson_type[] = 
{
   { "art" , "agentReceiptTime", BSON_TYPE_DATE_TIME, NULL }, 
   { "cnt" , "baseEventCount", BSON_TYPE_INT64, NULL }, 
   { "in" , "bytesIn", BSON_TYPE_INT64, NULL }, 
   { "out" , "bytesOut", BSON_TYPE_INT64, NULL }, 
   { "dpt" , "destinationPort", BSON_TYPE_INT64, NULL }, 
   { "rt" , "deviceReceiptTime", BSON_TYPE_DATE_TIME, NULL }, 
   { "fsize" , "fileSize", BSON_TYPE_INT64, NULL }, 
   { "spt" , "sourcePort", BSON_TYPE_INT64, NULL }, 
   { "start" , "startTime", BSON_TYPE_DATE_TIME, NULL }, 

 { "cfp1" , NULL, BSON_TYPE_DOUBLE, NULL }, 
   { "cfp2" , NULL, BSON_TYPE_DOUBLE, NULL }, 
   { "cfp3" , NULL, BSON_TYPE_DOUBLE, NULL }, 
   { "cfp4" , NULL, BSON_TYPE_DOUBLE, NULL }, 
   { "cn1" , NULL, BSON_TYPE_INT64, NULL }, 
   { "cn2" , NULL, BSON_TYPE_INT64, NULL }, 
   { "cn3" , NULL, BSON_TYPE_INT64, NULL }, 
   { "cn4" , NULL, BSON_TYPE_INT64, NULL }, 
   { "destinationTranslatedPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "deviceCustomDate1" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "deviceCustomDate2" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "dstBytes" , NULL, BSON_TYPE_INT64, NULL }, 
   { "dstPackets" , NULL, BSON_TYPE_INT64, NULL }, 
   { "dstPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "dstPostNATPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "dstPreNATPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "end" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "fileCreateTime" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "fileModificationTime" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "oldFileCreateTime" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "oldFileModificationTime" , NULL, BSON_TYPE_DATE_TIME, NULL }, 
   { "oldFileSize" , NULL, BSON_TYPE_INT64, NULL }, 
   { "sev" , NULL, BSON_TYPE_INT64, NULL }, 
   { "sourceTranslatedPort" , NULL, BSON_TYPE_INT64, NULL }, 
   { "srcPackets" , NULL, BSON_TYPE_INT64, NULL }, 
   { "srcPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "srcPostNATPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "srcPreNATPort" , NULL, BSON_TYPE_INT32, NULL }, 
   { "totalPackets" , NULL, BSON_TYPE_INT64, NULL }, 
 { "agt" , "agentAddress", BSON_TYPE_UTF8, NULL }, 
   { "ahost" , "agentHost", BSON_TYPE_UTF8, NULL }, 
   { "aid" , "agentId", BSON_TYPE_UTF8, NULL }, 
   { "atz" , "agentTimeZone", BSON_TYPE_UTF8, NULL }, 
   { "at" , "agentType", BSON_TYPE_UTF8, NULL }, 
   { "av" , "agentVersion", BSON_TYPE_UTF8, NULL }, 
   { "app" , "applicationProtocol", BSON_TYPE_UTF8, NULL }, 
   { "catdt" , "categoryDeviceType", BSON_TYPE_UTF8, NULL }, 
   { "_cefVer" , "cefVersion", BSON_TYPE_UTF8, NULL }, 
   { "dst" , "destinationAddress", BSON_TYPE_UTF8, NULL }, 
   { "dhost" , "destinationHostName", BSON_TYPE_UTF8, NULL }, 
   { "dlat" , "destinationLatitude", BSON_TYPE_UTF8, NULL }, 
   { "dlong" , "destinationLongitude", BSON_TYPE_UTF8, NULL }, 
   { "dmac" , "destinationMacAddress", BSON_TYPE_UTF8, NULL }, 
   { "dntdom" , "destinationNTDomain", BSON_TYPE_UTF8, NULL }, 
   { "dpid" , "destinationProcessId", BSON_TYPE_UTF8, NULL }, 
   { "dproc" , "destinationProcessName", BSON_TYPE_UTF8, NULL }, 
   { "dtz" , "destinationTimeZone", BSON_TYPE_UTF8, NULL }, 
   { "duid" , "destinationUserId", BSON_TYPE_UTF8, NULL }, 
   { "duser" , "destinationUserName", BSON_TYPE_UTF8, NULL }, 
   { "dpriv" , "destinationUserPrivileges", BSON_TYPE_UTF8, NULL }, 
   { "act" , "deviceAction", BSON_TYPE_UTF8, NULL }, 
   { "dvc" , "deviceAddress", BSON_TYPE_UTF8, NULL }, 
   { "cat" , "deviceEventCategory", BSON_TYPE_UTF8, NULL }, 
   { "dvchost" , "deviceHostName", BSON_TYPE_UTF8, NULL }, 
   { "dvcpid" , "deviceProcessId", BSON_TYPE_UTF8, NULL }, 
   { "end" , "endTime", BSON_TYPE_UTF8, NULL }, 
   { "outcome" , "eventOutcome", BSON_TYPE_UTF8, NULL }, 
   { "fname" , "fileName", BSON_TYPE_UTF8, NULL }, 
   { "mrt" , "managerReceiptTime", BSON_TYPE_UTF8, NULL }, 
   { "msg" , "message", BSON_TYPE_UTF8, NULL }, 
   { "request" , "requestUrl", BSON_TYPE_UTF8, NULL }, 
   { "src" , "sourceAddress", BSON_TYPE_UTF8, NULL }, 
   { "shost" , "sourceHostName", BSON_TYPE_UTF8, NULL }, 
   { "slat" , "sourceLatitude", BSON_TYPE_UTF8, NULL }, 
   { "slong" , "sourceLongitude", BSON_TYPE_UTF8, NULL }, 
   { "smac" , "sourceMacAddress", BSON_TYPE_UTF8, NULL }, 
   { "sntdom" , "sourceNtDomain", BSON_TYPE_UTF8, NULL }, 
   { "spid" , "sourceProcessId", BSON_TYPE_UTF8, NULL }, 
   { "sproc" , "sourceProcessName", BSON_TYPE_UTF8, NULL }, 
   { "suid" , "sourceUserId", BSON_TYPE_UTF8, NULL }, 
   { "suser" , "sourceUserName", BSON_TYPE_UTF8, NULL }, 
   { "spriv" , "sourceUserPrivileges", BSON_TYPE_UTF8, NULL }, 
   { "proto" , "transportProtocol", BSON_TYPE_UTF8, NULL }, 


  { "devTime", "Device Time", BSON_TYPE_DATE_TIME, NULL} ,
  {NULL, BSON_TYPE_EOD }
}  ;



void
append_to_bson(bson_t **doc, raw_message_fields *all_fields, event_standard_t standard, const char *posix_date_format)
{

  int f = 0 ;

  for ( f = 0 ; f < all_fields->last_field ; f++ ) {

    struct tm tm;
    time_t event_time;

    const char *key = all_fields->fields[f].key ;
    const char *value = all_fields->fields[f].value;

    int i = 0 ;

    struct key_to_bson_type_tag * type_to_use = NULL;
    for ( i = 0 ; key_to_bson_type[i].key && !type_to_use ; i++ ) {
      if ( strcmp(key, key_to_bson_type[i].key) == 0  ) {
        type_to_use = &key_to_bson_type[i];
      }
    }


    if (type_to_use && standard == CEF_STANDARD && type_to_use->full_name ) {
      key = type_to_use->full_name;
    }

    if ( type_to_use ) {

      if ( value == NULL ) {
        value = type_to_use->default_value;
      }

      switch (type_to_use->type) {
        case BSON_TYPE_INT32:
          BCON_APPEND(*doc, BCON_UTF8(key), BCON_INT32(atoi(value)));
          break;
        case BSON_TYPE_DATE_TIME:
          if ( strptime(value,posix_date_format, &tm ) == NULL ) {
          } else {
            event_time = mktime(&tm);
            BCON_APPEND(*doc, BCON_UTF8(key), BCON_DATE_TIME(event_time*1000) );
          }
          break;
        default:
          BCON_APPEND(*doc, BCON_UTF8(key), BCON_UTF8(value));
          break;  
      }
    } else {
      BCON_APPEND(*doc, BCON_UTF8(key), BCON_UTF8(value));
    }
  }
}

char map_to_leef_separator(const char *input) {

  char *strd = strdup(input);
  char *strd_orig = strd;
  char *token = strrchr(strd, 'x');
  char ascii_code;
  ascii_code = '\t';
  if (token != NULL && token + 1 != NULL) {
    long val = strtol(token + 1, NULL, 16);
    if (val > 0) {
      ascii_code = (char)val;
    }
  } else if (strlen(input) == 1) {
      ascii_code = input[0];
  }
  free(strd_orig);
  return ascii_code;
}

int find_syslog_standard(const char *line, parsing_state *ps)
{
    if (line == NULL) {
        return -1;
    }
    if (strstr(line, cef_format_hdr)) {
        ps->attr_separator = ' ';
        ps->standard = CEF_STANDARD;
        ps->hdr_offset = 8;
        return 0;
    }
    if (strstr(line, leef1_format_hdr)) {
        ps->attr_separator = '\t';
        ps->standard = LEEF1_STANDARD;
        ps->hdr_offset = leef_hdrs_len;
        return 0;
    }
    if (strstr(line, leef2_format_hdr)) {
        ps->attr_separator = '\t';
        ps->standard = LEEF2_STANDARD;
        ps->hdr_offset = leef_hdrs_len+1;
        return 0;
    }

    return -1;
}


int parse_cef(const char *line, bson_t **doc, parsing_state *ps) 
{
    int i;
    if (line == NULL) {
        return -1;
    }
    char *cef_str = strdup(line);
    char *cef_str_orig = cef_str;
    char *tok_data, *key, *value;

    *doc = BCON_NEW(cef_hdrs[0], BCON_UTF8(strsep(&cef_str, "|")));

    for (i=1; i<cef_hdrs_len; i++) {
        BCON_APPEND(*doc, cef_hdrs[i], BCON_UTF8(strsep(&cef_str, "|")));
    }

    raw_message_fields * all_fields = get_new_message_fields_list();

    while ((tok_data = strsep(&cef_str, " ")) != NULL) 
    {
        key = strtok(tok_data, "=");
        value = strtok(NULL, "=");

        add_field(all_fields, key, value );
    } 

    const char *date_format = find_date_format(all_fields);

    append_to_bson(doc, all_fields, ps->standard, date_format);

    free_new_message_fields_list(all_fields);


    if (cef_str_orig) {
        free(cef_str_orig);
    }
    return 0;
}

int parse_leef(const char *line, bson_t **doc, parsing_state *ps) 
{
    int i;
    if (line == NULL) {
        return -1;
    }
    char *leef_str = strdup(line);
    char *leef_str_orig = leef_str;
    char *tok_data, *key, *value;
    char sep[2];

    sep[0] = '|' ;
    sep[1] = '\0' ;



    *doc = BCON_NEW(leef_hdrs[0], BCON_UTF8(strsep(&leef_str, sep)));
    for (i=1; i< ps->hdr_offset; i++) {
        if (i == ps->hdr_offset-1 && ps->standard == LEEF2_STANDARD) {
            sep[0] = map_to_leef_separator(strsep(&leef_str, sep));
        } else {
          BCON_APPEND(*doc, leef_hdrs[i], BCON_UTF8(strsep(&leef_str, sep)));
      }
    }

    if ( ps->standard == LEEF1_STANDARD ) {
      sep[0] = '\t' ;
    }

    raw_message_fields * all_fields = get_new_message_fields_list();

    while ((tok_data = strsep(&leef_str, sep)) != NULL) 
    {
        key = strtok(tok_data, "=");
        value = strtok(NULL, "=");
        add_field(all_fields, key, value );
    } 

    const char *date_format = find_date_format(all_fields);

    append_to_bson(doc, all_fields , ps->standard, date_format);
    
    free_new_message_fields_list(all_fields);

    if (leef_str_orig) {
        free(leef_str_orig);
    }    

    return 0;
}

int parse_jeef(const char *line, bson_t **doc) {
  parsing_state ps;
  
  int ret;
  if ((ret = find_syslog_standard(line, &ps))) {
    return ret;
  }

  switch (ps.standard) {
  case 0:
    parse_cef(line, doc, &ps);
    break;
  case 1:
  case 2:
    parse_leef(line, doc, &ps);
    break;
  default:
    return -1;
    break;
  }

  return 0;
}


