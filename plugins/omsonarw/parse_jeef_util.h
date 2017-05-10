#ifndef INCLUDED_PARSE_JEEF_UTIL_H
#define INCLUDED_PARSE_JEEF_UTIL_H

static const int cef_hdrs_len = 7;
static const char *const cef_hdrs[] = {
    "Version",      "Device Vendor", "Device Product", "Device Version",
    "Signature ID", "Name",          "Severity"};

static const int leef_hdrs_len = 5;
static const char *const leef_hdrs[] = {"Version", "Vendor", "Product",
                                        "Version", "EventID"};

static const char *const cef_format_hdr = "CEF:0";
static const char *const leef1_format_hdr = "LEEF:1.0";
static const char *const leef2_format_hdr = "LEEF:2.0";

typedef enum {
  CEF_STANDARD = 0,
  LEEF1_STANDARD = 1,
  LEEF2_STANDARD = 2
} event_standard_t;

#define MAX_FIELDS 1024
typedef struct {
  const char *key;
  const char *value;
} raw_field;
typedef struct {
  int last_field;
  raw_field fields[MAX_FIELDS];
} raw_message_fields;

const char *convert_java_date_format_to_posix(const char *java_format);
raw_message_fields *get_new_message_fields_list();

char map_to_leef_separator(const char *input);

typedef struct parsing_state {
  event_standard_t standard;
  int hdr_offset;
} parsing_state;
int find_syslog_standard(const char *line, parsing_state *ps);

const char *find_date_format(raw_message_fields *all_fields);

#endif