#ifndef INCLUDED_PARSE_JEEF_H
#define INCLUDED_PARSE_JEEF_H
#include <bson.h>
int parse_jeef(const char *line, bson_t **doc);
char map_to_leef_separator(const char *input);
#endif