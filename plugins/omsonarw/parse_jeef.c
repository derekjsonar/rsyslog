
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_jeef_util.h"
#include <bcon.h>
#include <bson.h>
#include <malloc.h>
#include <time.h>

int parse_cef(const char *line, bson_t **doc, parsing_state *ps) {
  int i;
  if (line == NULL) {
    return -1;
  }
  char *cef_str = strdup(line);
  char *cef_str_orig = cef_str;
  char *tok_data, *tmp_tok_data, *key, *value;

  *doc = BCON_NEW(cef_hdrs[0], BCON_UTF8(strsep(&cef_str, "|")));

  for (i = 1; i < cef_hdrs_len; i++) {
    BCON_APPEND(*doc, cef_hdrs[i], BCON_UTF8(strsep(&cef_str, "|")));
  }

  raw_message_fields *all_fields = get_new_message_fields_list();

  while ((tok_data = strsep(&cef_str, " ")) != NULL) {
    key = strsep(&tok_data, "=");
    value = tok_data;
    printf("key: %s \t\t value: %s\n", key, value);

    add_field(all_fields, key, value);
  }

  const char *date_format = find_date_format(all_fields);

  append_to_bson(doc, all_fields, ps->standard, date_format);

  free_new_message_fields_list(all_fields);

  if (cef_str_orig) {
    free(cef_str_orig);
  }
  return 0;
}

int parse_leef(const char *line, bson_t **doc, parsing_state *ps) {
  int i;
  if (line == NULL) {
    return -1;
  }
  char *leef_str = strdup(line);
  char *leef_str_orig = leef_str;
  char *tok_data, *key, *value;
  char sep[2];

  sep[0] = '|';
  sep[1] = '\0';

  *doc = BCON_NEW(leef_hdrs[0], BCON_UTF8(strsep(&leef_str, sep)));
  for (i = 1; i < ps->hdr_offset; i++) {
    if (i == ps->hdr_offset - 1 && ps->standard == LEEF2_STANDARD) {
      sep[0] = map_to_leef_separator(strsep(&leef_str, sep));
    } else {
      BCON_APPEND(*doc, leef_hdrs[i], BCON_UTF8(strsep(&leef_str, sep)));
    }
  }

  if (ps->standard == LEEF1_STANDARD) {
    sep[0] = '\t';
  }

  raw_message_fields *all_fields = get_new_message_fields_list();

  while ((tok_data = strsep(&leef_str, sep)) != NULL) {
    key = strsep(&tok_data, "=");
    value = tok_data;
    printf("key: %s \t\t value: %s\n", key, value);
    add_field(all_fields, key, value);
  }

  const char *date_format = find_date_format(all_fields);

  append_to_bson(doc, all_fields, ps->standard, date_format);

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
