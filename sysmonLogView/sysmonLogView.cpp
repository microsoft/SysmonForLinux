/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// SysmonLogView.cpp
//
// Viewer for Sysmon For Linux logs.
//
//====================================================================

#include "stdafx.h"
#include <string>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <getopt.h>
#include <string.h>
#include <pugixml.hpp>
#include <time.h>
#include <pthread.h>

#include "sysmonevents.h"

extern "C"
const char *eventName(unsigned int eventId);

#define SYSMON_ID " sysmon"
#define EVENT_TAG "<Event>"

using namespace std;

//--------------------------------------------------------------------
//
// usage
//
// Display help.
//
//--------------------------------------------------------------------
void usage()
{
    printf("SysmonLogView v1.0 - Converts Sysmon syslog XML to human readable form\n");
    printf("Sysinternals - www.sysinternals.com\n");
    printf("By Kevin Sheldrake\n");
    printf("Copyright (C) 2021 Microsoft Corporation\n");
    printf("\n");
    printf("Usage:\n");
    printf("            sysmonLogView [<options>]\n");
    printf("  -e   Only display events with matching eventID. Specify comma-separated list\n");
    printf("       of eventIDs and/or multiple -e switches.\n");
    printf("  -r   Only display events within the specified range of recordIDs. Specify\n");
    printf("       min,max. If min is missing, start from the beginning; if end is missing,\n");
    printf("       continue to end.\n");
    printf("  -t   Only display events within the specified time stamps. Specify start,end.\n");
    printf("       Time format is YYYY-MM-DD HH:MM[:SS[.nnn]] where nnn is milliseconds.\n");
    printf("       If start is missing, start at beginning; if end is missing, continue to\n");
    printf("       the end.\n");
    printf("  -f   For events that have a particular field, only display events that match\n");
    printf("       the given value (case sensitive). e.g. '-f Image=/bin/touch'\n");
    printf("  -E   Only display the specified fields for the specified event. Specify\n");
    printf("       <eventID>=<comma-separated list of fields>. Can use multiple times.\n");
    printf("  -X   Print a blank link between events.\n");
    printf("  -h   Display this help.\n");
    printf("  -?   Display this help.\n");
    printf("\n");
    printf("Supply input data on standard input; writes to standard output. By default all\n");
    printf("events are displayed but switches can be used to only display certain events,\n");
    printf("and to only display certain fields within the events that are displayed.\n");
    printf("\n");
    printf("Wrap arguments in quotes (e.g. \"<argument>\") if argument contains spaces.\n");
    printf("\n");
    printf("Typical usage:\n");
    printf("  sudo tail -f /var/log/syslog | sudo /opt/sysmon/sysmonLogView\n");
    printf("\n");
}

//--------------------------------------------------------------------
//
// getEventId
//
// Converts a string of comma-separated event IDs into an unordered
// set.
//
// Note, this modifies the input string.
//
//--------------------------------------------------------------------
unordered_set<unsigned int> getEventId(char *s)
{
    unordered_set<unsigned int> event;

    if (s == NULL) {
        fprintf(stderr, "getEventId invalid params\n");
        return event;
    }

    char *t = NULL;
    char *ctx = NULL;

    t = strtok_r(s, ",", &ctx);
    if (t == NULL)
        return event;

    event.insert(strtoul(t, NULL, 0));

    while ((t = strtok_r(NULL, ",", &ctx)) != NULL) {
        event.insert(strtoul(t, NULL, 0));
    }

    return event;
}

//--------------------------------------------------------------------
//
// getEventIdField
//
// Converts a string of an event ID mapped to a comma-separated list
// of field names into a pair consisting of the event ID and an
// unordered set of field name strings.
//
// Note, this modifies the input string.
//
//--------------------------------------------------------------------
pair<unsigned int, unordered_set<string>> getEventIdField(char *s)
{
    pair<unsigned int, unordered_set<string>> eventField;

    if (s == NULL) {
        fprintf(stderr, "getEventIdField invalid params\n");
        return eventField;
    }

    char *t = NULL;
    char *ctx = NULL;

    t = strtok_r(s, "=", &ctx);
    if (t == NULL)
        return eventField;

    eventField.first = strtoul(t, NULL, 0);

    while ((t = strtok_r(NULL, ",", &ctx)) != NULL) {
        eventField.second.insert(string(t));
    }

    return eventField;
}

//--------------------------------------------------------------------
//
// getRecordIdRange
//
// Converts a string representing a record ID range - two values
// separated by a comma - into a pair.
//
// Note, this modifies the input string.
//
//--------------------------------------------------------------------
pair<unsigned long, unsigned long> getRecordIdRange(char *s)
{
    pair<unsigned long, unsigned long> range(-1, -1);

    if (s == NULL) {
        fprintf(stderr, "getRecordIdRange invalid paramsn\n");
        return range;
    }

    char *t = NULL;
    char *ctx = NULL;
    bool emptyFirst = false;

    if (*s == ',')
        emptyFirst = true;

    t = strtok_r(s, ",", &ctx);
    if (t == NULL)
        return range;

    if (emptyFirst) {
        range.second = strtoul(t, NULL, 10);
        return range;
    }

    range.first = strtoul(t, NULL, 10);

    t = strtok_r(NULL, ",", &ctx);
    if (t != NULL)
        range.second = strtoul(t, NULL, 10);

    return range;
}

//--------------------------------------------------------------------
//
// tmToUl
//
// Combines a time struct and the milliseconds since into a single
// unsigned long of milliseconds since epoch.
//
//--------------------------------------------------------------------
unsigned long tmToUl(struct tm *t, unsigned long ms)
{
    if (t == NULL) {
        fprintf(stderr, "tmToUl invalid params\n");
        return 0;
    }

    return ((unsigned long)mktime(t) * 1000) + ms;
}

//--------------------------------------------------------------------
//
// timeStrToUl
//
// Converts a string representing a date time into an unsigned long
// of milliseconds since epoch.
//
//--------------------------------------------------------------------
unsigned long timeStrToUl(const char *s)
{
    if (s == NULL) {
        fprintf(stderr, "timeStrToUl invalid params\n");
        return 0;
    }

    struct tm time_s;
    char *remain = NULL;

    memset(&time_s, 0, sizeof(time_s));
    remain = strptime(s, "%F %H:%M", &time_s);
    if (remain == NULL)
        return -1;

    if (*remain != ':')
        return tmToUl(&time_s, 0);

    remain = strptime(remain+1, "%S", &time_s);
    if (remain == NULL || *remain != '.')
        return tmToUl(&time_s, 0);

    return tmToUl(&time_s, strtoul(remain+1, NULL, 10));
}

//--------------------------------------------------------------------
//
// systemTimeStrToUl
//
// Converts a string representing a date time into an unsigned long
// of milliseconds since epoch.
//
//--------------------------------------------------------------------
unsigned long systemTimeStrToUl(const char *s)
{
    if (s == NULL) {
        fprintf(stderr, "systemTimeStrToUl invalid params\n");
        return 0;
    }

    struct tm time_s;
    char *remain = NULL;

    memset(&time_s, 0, sizeof(time_s));
    remain = strptime(s, "%FT%H:%M:%S", &time_s);
    if (remain == NULL || *remain != '.')
        return -1;

    return tmToUl(&time_s, strtoul(remain+1, NULL, 10) / (1000 * 1000));
}

//--------------------------------------------------------------------
//
// getTimeRange
//
// Converts a string representing a time range to a pair of unsigned
// longs of milliseconds since epoch.
//
// Note, this modifies the input string.
//
//--------------------------------------------------------------------
pair<unsigned long, unsigned long> getTimeRange(char *s)
{
    pair<unsigned long, unsigned long> range(-1, -1);

    if (s ==  NULL) {
        fprintf(stderr, "getTimeRange invalid params\n");
        return range;
    }

    char *t = NULL;
    char *ctx = NULL;
    bool emptyFirst = false;

    if (*s == ',')
        emptyFirst = true;

    t = strtok_r(s, ",", &ctx);
    if (t == NULL)
        return range;

    if (emptyFirst) {
        range.second = timeStrToUl(t);
        return range;
    }

    range.first = timeStrToUl(t);

    t = strtok_r(NULL, ",", &ctx);
    if (t != NULL)
        range.second = timeStrToUl(t);

    return range;
}

//--------------------------------------------------------------------
//
// getFilter
//
// Converts a string representing an event filter into a pair
// consisting of the field name mapped to an unordered set of allowed
// string values.
//
// Note, this modified the input string.
//
//--------------------------------------------------------------------
pair<string, unordered_set<string>> getFilter(char *s)
{
    pair<string, unordered_set<string>> filter;

    if (s == NULL) {
        fprintf(stderr, "getFilter invalid params\n");
        return filter;
    }

    char *t = NULL;
    char *ctx = NULL;

    t = strtok_r(s, "=", &ctx);
    if (t == NULL)
        return filter;

    filter.first = t;

    while ((t = strtok_r(NULL, ",", &ctx)) != NULL) {
        filter.second.insert(string(t));
    }

    return filter;
}


//--------------------------------------------------------------------
//
// processCmdline
//
// Extract the configuration from the command line.
//
// Note, this modifies the command line array.
//
//--------------------------------------------------------------------
void processCmdline(int argc, char *argv[],
    unordered_set<unsigned int> *eventIds,
    unordered_map<unsigned int, unordered_set<string>> *eventIdFields,
    pair<unsigned long, unsigned long> *recordIdRange,
    pair<unsigned long, unsigned long> *timeRange,
    unordered_map<string, unordered_set<string>> *filters,
    bool *extraCR
    )
{
    if (argv == NULL || eventIds == NULL || eventIdFields == NULL ||
            recordIdRange == NULL || timeRange == NULL || filters == NULL
            || extraCR == NULL) {
        fprintf(stderr, "processCmdline invalid params\n");
        return;
    }

    int c;

    while ((c = getopt(argc, argv, "h?e:r:t:f:E:XT")) != -1) {
        switch (c) {
            case 'e':
            {
                unordered_set<unsigned int> newEventId = getEventId(optarg);
                eventIds->insert(newEventId.begin(), newEventId.end());
                break;
            }
            case 'r':
            {
                pair<unsigned long, unsigned long> newRecordIdRange = getRecordIdRange(optarg);
                if (newRecordIdRange.first != (unsigned long)-1)
                    recordIdRange->first = newRecordIdRange.first;
                if (newRecordIdRange.second != (unsigned long)-1)
                    recordIdRange->second = newRecordIdRange.second;
                break;
            }
            case 't':
            {
                pair<unsigned long, unsigned long> newTimeRange = getTimeRange(optarg);
                if (newTimeRange.first != (unsigned long)-1)
                    timeRange->first = newTimeRange.first;
                if (newTimeRange.second != (unsigned long)-1)
                    timeRange->second = newTimeRange.second;
                break;
            }
            case 'f':
            {
                pair<string, unordered_set<string>> newFilter = getFilter(optarg);
                if (!newFilter.first.empty() && !newFilter.second.empty()) {
                    auto it = filters->find(newFilter.first);
                    if (it != filters->end()) {
                        it->second.insert(newFilter.second.begin(), newFilter.second.end());
                    } else {
                        filters->insert(newFilter);
                    }
                }
                break;
            }
            case 'E':
            {
                pair<unsigned int, unordered_set<string>> newEventIdField = getEventIdField(optarg);
                auto it = eventIdFields->find(newEventIdField.first);
                if (it != eventIdFields->end()) {
                    it->second.insert(newEventIdField.second.begin(), newEventIdField.second.end());
                } else {
                    eventIdFields->insert(newEventIdField);
                }
                break;
            }
            case 'X':
                *extraCR = true;
                break;
            case 'T': // print out the switch settings processed up to this point
            {
                printf("Event Ids: ");
                for (const auto it : *eventIds) {
                    printf("%d ", it);
                }
                printf("\n");
                printf("Event Id Fields:\n");
                for (const auto& it : *eventIdFields) {
                    printf("  %d (", it.first);
                    for (const auto& it2 : it.second) {
                        printf("%s ", it2.c_str());
                    }
                    printf(")\n");
                }
                printf("\n");
                printf("Record Id range = %ld, %ld\n", recordIdRange->first, recordIdRange->second);
                printf("Time range = ");
                char timeMinS[128], timeMaxS[128];
                struct tm tmMin, tmMax;
                time_t timeMin, timeMax;
                if (timeRange->first != (unsigned long)-1) {
                    timeMin = timeRange->first / 1000;
                    gmtime_r(&timeMin, &tmMin);
                    strftime(timeMinS, 128, "%F %T", &tmMin);
                    printf("%s.%03ld - ", timeMinS, timeRange->first % 1000);
                } else {
                    printf("-1 - ");
                }
                if (timeRange->second != (unsigned long)-1) {
                    timeMax = timeRange->second / 1000;
                    gmtime_r(&timeMax, &tmMax);
                    strftime(timeMaxS, 128, "%F %T", &tmMax);
                    printf("%s.%03ld\n", timeMaxS, timeRange->second % 1000);
                } else {
                    printf("-1\n");
                }
                printf("Filters:\n");
                for (const auto& it2 : *filters) {
                    printf("  %s:\n", it2.first.c_str());
                    for (const auto& it3 : it2.second) {
                        printf("    %s\n", it3.c_str());
                    }
                }

                exit(0);
            }
            case 'h':
            case '?':
            default:
                usage();
                exit(0);
        }
    }
}

//--------------------------------------------------------------------
//
// isInRange
//
// Checks if the given value is within the specified range.
//
//--------------------------------------------------------------------
bool isInRange(pair<unsigned long, unsigned long> range, unsigned long value)
{
    if ((range.first != (unsigned long)-1 && range.first > value) ||
            (range.second != (unsigned long)-1 && range.second < value)) {
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
//
// main
//
// The main program.
//
//--------------------------------------------------------------------
int main(int argc, char *argv[])
{
    unordered_set<unsigned int> eventIds;
    unordered_map<unsigned int, unordered_set<string>> eventIdFields;
    pair<unsigned long, unsigned long> recordIdRange(-1, -1);
    pair<unsigned long, unsigned long> timeRange(-1, -1); // time in ms since epoch
    unordered_map<string, unordered_set<string>> filters;
    bool extraCR = false;

    char *line = NULL;
    size_t line_len = 0;
    const char *ptr = NULL;
    const char eventIdQuery[] = "/Event/System/EventID";
    const char recordIdQuery[] = "/Event/System/EventRecordID";
    const char timeCreatedQuery[] = "/Event/System/TimeCreated";
    const char eventDataQuery[] = "/Event/EventData";
    const char systemTime[] = "SystemTime";
    const char dataString[] = "Data";
    const char dataName[] = "Name";

    unsigned int eventId;
    unsigned long recordId;
    unsigned long timeCreated;
    bool filterOut = false;
    const char *name;
    const char *value;

    processCmdline(argc, argv, &eventIds, &eventIdFields, &recordIdRange, &timeRange, &filters, &extraCR);

    while (getline(&line, &line_len, stdin) != -1) {
        ptr = strstr(line, SYSMON_ID);
        if (ptr == NULL)
            continue;

        ptr += strlen(SYSMON_ID);

        ptr = strstr(ptr, EVENT_TAG);
        if (ptr == NULL)
            continue;

        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_string(ptr);
        if (!result) {
            fprintf(stderr, "XML parse failed\n");
            continue;
        }

        pugi::xpath_node eventIdNode = doc.select_node(eventIdQuery);
        if (!eventIdNode) {
            continue;
        }
        eventId = (unsigned int)(strtoul(eventIdNode.node().child_value(), NULL, 0));

        if (!eventIds.empty() && eventIds.find(eventId) == eventIds.end()) {
            continue;
        }

        pugi::xpath_node recordIdNode = doc.select_node(recordIdQuery);
        if (!recordIdNode) {
            continue;
        }
        recordId = strtoul(recordIdNode.node().child_value(), NULL, 0);

        if (recordIdRange.first != (unsigned long)-1 || recordIdRange.second != (unsigned long)-1) {
            if (!isInRange(recordIdRange, recordId)) {
                continue;
            }
        }

        if (timeRange.first != (unsigned long)-1 || timeRange.second != (unsigned long)-1) {
            pugi::xpath_node timeCreatedNode = doc.select_node(timeCreatedQuery);
            if (!timeCreatedNode) {
                continue;
            }
            timeCreated = systemTimeStrToUl(timeCreatedNode.node().attribute(systemTime).value());
            if (!isInRange(timeRange, timeCreated)) {
                continue;
            }
        }

        pugi::xpath_node eventDataNode = doc.select_node(eventDataQuery);
        if (!eventDataNode) {
            continue;
        }

        filterOut = false;
        for (pugi::xml_node data = eventDataNode.node().first_child(); data && !filterOut; data = data.next_sibling()) {
            if (data.type() != pugi::node_element || strcmp(data.name(), dataString) != 0)
                continue;
            name = data.attribute(dataName).value();
            const auto filter = filters.find(string(name));
            if (filter != filters.end()) {
                value = data.child_value();
                if (filter->second.find(string(value)) == filter->second.end()) {
                    filterOut = true;
                }
            }
        }

        if (filterOut) {
            continue;
        }

        const auto eventIdDisplay = eventIdFields.find(eventId);

        printf("Event %s\n", eventName(eventId));

        for (pugi::xml_node data = eventDataNode.node().first_child(); data; data = data.next_sibling()) {
            if (data.type() != pugi::node_element || strcmp(data.name(), dataString) != 0)
                continue;
            name = data.attribute(dataName).value();
            if (eventIdDisplay != eventIdFields.end() && eventIdDisplay->second.find(string(name)) == eventIdDisplay->second.end())
                continue;
            value = data.child_value();
            if (value == NULL || value[0] == 0x00) {
                printf("\t%s: --NULL--\n", name);
            } else {
                printf("\t%s: %s\n", name, value);
            }
        }

        if (extraCR)
            printf("\n");
    }

    return 0;
}




