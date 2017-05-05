#include <bson.h>
#include <bcon.h>
// #include <mongoc.h>
// #include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// #include <ctype.h>
// #include <errno.h>
// #include <assert.h>
// #include <signal.h>
// #include <stdint.h>
// #include <time.h>
// #include <json.h>

//typedef off_t off64_t;

const int cef_hdrs_len = 7;
static const char *const cef_hdrs[] = {"Version", "Device Vendor", "Device Product",
                                        "Device Version", "Signature ID", "Name", "Severity"};

const int leef_hdrs_len = 5;
static const char *const leef_hdrs[] = {"Version", "Vendor", "Product", "Version", "EventID"};
                                        
static const char *const cef_format_hdr = "CEF:0";
static const char *const leef1_format_hdr = "LEEF:1.0";
static const char *const leef2_format_hdr = "LEEF:2.0";

typedef struct parsing_state
{
    char attr_separator;
    int standard;
    int hdr_offset;
} parsing_state;

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
        ps->standard = 0;
        ps->hdr_offset = 8;
        return 0;
    }
    if (strstr(line, leef1_format_hdr)) {
        ps->attr_separator = '\t';
        ps->standard = 1;
        ps->hdr_offset = 6;
        return 0;
    }
    if (strstr(line, leef2_format_hdr)) {
        ps->attr_separator = '\t';
        ps->standard = 2;
        ps->hdr_offset = 7;
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
    while ((tok_data = strsep(&cef_str, " ")) != NULL) 
    {
        key = strtok(tok_data, "=");
        value = strtok(NULL, "=");
        BCON_APPEND(*doc, BCON_UTF8(key), BCON_UTF8(value));
    } 

    if (cef_str_orig) {
        free(cef_str_orig);
    }
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
    char sep = '|';

    *doc = BCON_NEW(leef_hdrs[0], BCON_UTF8(strsep(&leef_str, &sep)));
    for (i=1; i< ps->hdr_offset-1; i++) {
        BCON_APPEND(*doc, leef_hdrs[i], BCON_UTF8(strsep(&leef_str, &sep)));
    }

    if (ps->standard == 2) {
        sep = map_to_leef_separator(strsep(&leef_str, &sep));
    }

    while ((tok_data = strsep(&leef_str, &sep)) != NULL) 
    {
        key = strtok(tok_data, "=");
        value = strtok(NULL, "=");
        BCON_APPEND(*doc, BCON_UTF8(key), BCON_UTF8(value));
    } 

    if (leef_str_orig) {
        free(leef_str_orig);
    }    
}

int parse_jeef(const char *line, bson_t **doc) {
  parsing_state ps;
  int i;
  int ret;
  if (ret = find_syslog_standard(line, &ps)) {
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
