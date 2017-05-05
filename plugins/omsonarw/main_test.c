#include "parse_jeef.h"

const int test_msgs_len = 3;
static const char *const test_msgs[] = {
    "LEEF:2.0|JSONAR|SONARG|2|783748000001276892|xa6|ruleID=QUERY|ruleDesc=QUERY|severity=NOTICE \
|devTime=2017-03-28T06:00:00|serverType=MS SQL SERVER|classification=ALL|category=ALL \
|dbProtocolVersion=WINDOWS NAMED PIPES|usrName=|sourceProgram=SQLAgent - TSQL JobStep (Job 0x864584B2C24BBE4ABD5C60D81FB374E2 : Step 2)\
|start=2017-03-28T06:00:00|dbUser=NT AUTHORITY\\SYSTEM|dst=9.70.147.210|dstPort=0|src=9.70.147.210\
|srcPort=ALL|protocol=WINDOWS NAMED PIPES|type=QUERY|violationID=QUERY|sql=|error=0",
    "LEEF:1.0|QRadar|Health Agent|7.2.4|QRadarHealthMetric|\
MetricID=DiskUsage\tDeploymentID=f074e12e-132f-11e7-aac5-000c29fb351f\tHostName=qradar\tComponentType=hostcontext\t\
ComponentName=hostcontext\tdevTime=2017/04/26 16:20:59 -0400\t\
devTimeFormat=yyyy/MM/dd HH:mm:ss Z\tElement=/boot\tValue=0.49",
    "CEF:0|JSONAR|SONARG|2|58d3fccda88fe30e0005789e|QUERYSIG|5|\
rt=14902272 start=14902272 duser=DB2ADMIN dst=9.70.147.210 src=9.70.147.210 \
msg=tbl_table4_kw7g CREATE TABLE cs1Label=errors cs1=0 cs2Label=serverHost cs2=9.70.147.210 \
cs3Label=db cs3=DB2:SAMPLE cs4Label=count cs4=1 cs5Label=succeeded cs5=1"};


// const int leef_seps_len = 22;
// static const char *const leef_seps_keys[] = {
//     "xa6", "0xa6", "xA6", "0xA6", "x5e", "0x5e", "x5E", "0x5E", "x3a",
//     "0x3a", "x3A", "0x3A", "", "0x", "xxx", "123", "x0x", "x0x0x0x",
//     "^", "$", ";", "@"};

// int main(int argc, char *argv[]) {
//   int i;
//   for (i = 0; i < leef_seps_len; i++)
//   {
//       printf("input: %s ---> output: %c\n", leef_seps_keys[i], map_to_leef_separator(leef_seps_keys[i]));
//   }
//   return 0;
// }

int main(int argc, char *argv[]) {
  int i;
  int ret;
  bson_t *doc[test_msgs_len];
  for (i = 0; i < test_msgs_len; i++) {
    doc[i] = NULL;
  }
  for (i = 0; i < test_msgs_len; i++) {
    ret = parse_jeef(test_msgs[i], &(doc[i]));
    if (ret != 0) {
      return ret;
    }
    size_t length;
    char *json = bson_as_json(doc[i], &length);
    printf("parsed string: %s\n", json);
    if (json) {
      free(json);
    }
  }

  for (i = 0; i < test_msgs_len; i++) {
    if (doc[i]) {
      free(doc[i]);
    }
  }

  return ret;
}