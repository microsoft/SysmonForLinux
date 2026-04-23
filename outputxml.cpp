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
// outputxml.cpp
//
// Event output formatting for Syslog
//
//====================================================================

#include <pugixml.hpp>
#include <assert.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <sstream>
#include <cstdio>

#include "linuxTypes.h"
#include "sysmonevents.h"
#include "linuxHelpers.h"
#include "sysmon_defs.h"

extern uint64_t *eventIdAddr;

//--------------------------------------------------------------------
//
// FormatSyslogString
//
// Format an event into an XML string.
//
//--------------------------------------------------------------------
extern "C"
VOID FormatSyslogString(
    PCHAR                           EventStr,
    size_t                          EventMax,
    CONST PSYSMON_EVENT_TYPE_FMT    EventType,
    CONST EVENT_DATA_DESCRIPTOR*    Fields,
    unsigned int                    FieldCount
    )
{
    if (EventStr != NULL) {
        *EventStr = 0x00;
    }

    if (EventStr == NULL || EventType == NULL || Fields == NULL) {
        fprintf(stderr, "FormatSyslogString invalid params\n");
        return;
    }

    uint64_t eventId = 0;

    unsigned int index = 0;
    const char *field = NULL;
    PCTSTR *fieldNames = NULL;
    char providerGuid[40];
    LARGE_INTEGER curTime;
    char systemTime[32];
    char hostname[HOST_NAME_MAX + 1];
    char tmpBuf[64];

    if (eventIdAddr != NULL && eventIdAddr != MAP_FAILED) {
        eventId = (*eventIdAddr)++;
        msync(eventIdAddr, sizeof(eventId), MS_ASYNC);
    } else {
        eventId = 0;
    }

    assert(StringFromGUID2(SYSMON_PROVIDER, providerGuid, sizeof(providerGuid)) != 0);
    
    GetSystemTimeAsLargeInteger(&curTime);
    LargeIntegerToSystemTimeString(systemTime, 32, &curTime);

    if (gethostname(hostname, HOST_NAME_MAX + 1) < 0) {
        hostname[0] = 0x00;
    }

    pugi::xml_document doc;

    pugi::xml_node eventNode = doc.append_child("Event");

    pugi::xml_node systemNode = eventNode.append_child("System");

    pugi::xml_node providerNode = systemNode.append_child("Provider");
    providerNode.append_attribute("Name").set_value("Linux-Sysmon");
    providerNode.append_attribute("Guid").set_value(providerGuid);

    snprintf(tmpBuf, sizeof(tmpBuf), "%d", EventType->EventDescriptor->Id);
    systemNode.append_child("EventID").append_child(pugi::node_pcdata).set_value(tmpBuf);

    snprintf(tmpBuf, sizeof(tmpBuf), "%d", EventType->EventDescriptor->Version);
    systemNode.append_child("Version").append_child(pugi::node_pcdata).set_value(tmpBuf);

    snprintf(tmpBuf, sizeof(tmpBuf), "%d", EventType->EventDescriptor->Level);
    systemNode.append_child("Level").append_child(pugi::node_pcdata).set_value(tmpBuf);

    snprintf(tmpBuf, sizeof(tmpBuf), "%d", EventType->EventDescriptor->Task);
    systemNode.append_child("Task").append_child(pugi::node_pcdata).set_value(tmpBuf);

    snprintf(tmpBuf, sizeof(tmpBuf), "%d", EventType->EventDescriptor->Opcode);
    systemNode.append_child("Opcode").append_child(pugi::node_pcdata).set_value(tmpBuf);

    snprintf(tmpBuf, sizeof(tmpBuf), "0x%lx", EventType->EventDescriptor->Keyword);
    systemNode.append_child("Keywords").append_child(pugi::node_pcdata).set_value(tmpBuf);

    pugi::xml_node timeCreated = systemNode.append_child("TimeCreated");
    timeCreated.append_attribute("SystemTime").set_value(systemTime);

    snprintf(tmpBuf, sizeof(tmpBuf), "%lu", eventId);
    systemNode.append_child("EventRecordID").append_child(pugi::node_pcdata).set_value(tmpBuf);

    systemNode.append_child("Correlation");

    pugi::xml_node execution = systemNode.append_child("Execution");
    snprintf(tmpBuf, sizeof(tmpBuf), "%d", getpid());
    execution.append_attribute("ProcessID").set_value(tmpBuf);
    snprintf(tmpBuf, sizeof(tmpBuf), "%d", GetTid());
    execution.append_attribute("ThreadID").set_value(tmpBuf);

    systemNode.append_child("Channel").append_child(pugi::node_pcdata).set_value("Linux-Sysmon/Operational");
    systemNode.append_child("Computer").append_child(pugi::node_pcdata).set_value(hostname);

    pugi::xml_node security = systemNode.append_child("Security");
    snprintf(tmpBuf, sizeof(tmpBuf), "%d", geteuid());
    security.append_attribute("UserId").set_value(tmpBuf);

    pugi::xml_node eventData = eventNode.append_child("EventData");

    fieldNames = (PCTSTR *)EventType->FieldNames;
    for( index = 0; index < FieldCount; index++ ) {

        field = (const char *)Fields[index].Ptr;
        pugi::xml_node dataNode = eventData.append_child("Data");
        dataNode.append_attribute("Name").set_value(fieldNames[index]);
        dataNode.append_child(pugi::node_pcdata).set_value(field != NULL ? field : "");
    }

    std::ostringstream oss;
    doc.save(oss, "", pugi::format_raw | pugi::format_no_declaration);
    snprintf(EventStr, EventMax, "%s", oss.str().c_str());
}