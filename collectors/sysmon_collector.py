import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import win32evtlog


CHANNEL = "Microsoft-Windows-Sysmon/Operational"

ROOT = Path(__file__).resolve().parents[1]

OUTPUT_DIR = ROOT / "dataset" / "windows" / "raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "live_sysmon_events.jsonl"


EVENT_NAMES = {
    1: "PROCESS_CREATE",
    3: "NETWORK_CONNECTION",
    5: "PROCESS_TERMINATE",
    7: "IMAGE_LOAD",
    8: "CREATE_REMOTE_THREAD",
    10: "PROCESS_ACCESS",
    11: "FILE_CREATE",
    12: "REGISTRY_CREATE_DELETE",
    13: "REGISTRY_VALUE_SET",
    14: "REGISTRY_RENAME",
    17: "PIPE_CREATE",
    18: "PIPE_CONNECT",
    22: "DNS_QUERY",
    23: "FILE_DELETE",
    25: "PROCESS_TAMPERING",
}


def parse_event(event):

    xml = win32evtlog.EvtRender(
        event,
        win32evtlog.EvtRenderEventXml
    )

    root = ET.fromstring(xml)

    namespace = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    system = root.find("e:System", namespace)

    event_id = int(
        system.find("e:EventID", namespace).text
    )

    time_node = system.find("e:TimeCreated", namespace)

    timestamp = (
        time_node.attrib.get("SystemTime")
        if time_node is not None
        else None
    )

    data = {}

    event_data = root.find(
        "e:EventData",
        namespace
    )

    if event_data is not None:

        for item in event_data:

            name = item.attrib.get(
                "Name",
                "unknown"
            )

            data[name] = item.text or ""

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": EVENT_NAMES.get(
            event_id,
            f"EVENT_{event_id}"
        ),
        "data": data
    }


def print_event(event):

    event_type = event["event_type"]

    data = event["data"]

    print("\n" + "=" * 70)

    print(
        f"[{event['timestamp']}] "
        f"{event_type}"
    )

    print("=" * 70)

    important_fields = [
        "Image",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "TargetFilename",
        "DestinationIp",
        "DestinationPort",
        "DestinationHostname",
        "QueryName",
        "TargetObject",
    ]

    found = False

    for field in important_fields:

        value = data.get(field)

        if value:

            print(
                f"{field:<20}: {value}"
            )

            found = True

    if not found:
        print(
            f"Event ID: {event['event_id']}"
        )


def save_event(event):

    with open(
        OUTPUT_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                event,
                ensure_ascii=False
            )
            + "\n"
        )


def main():

    print("=" * 70)
    print("MALGUARD WINDOWS TELEMETRY COLLECTOR")
    print("=" * 70)

    print(f"\nChannel : {CHANNEL}")
    print(f"Output  : {OUTPUT_FILE}")

    print("\nListening for new Sysmon events...")
    print("Press CTRL+C to stop.\n")

    query = "*"

    flags = (
        win32evtlog.EvtQueryChannelPath
        | win32evtlog.EvtQueryReverseDirection
    )

    # Get the newest existing event first
    handle = win32evtlog.EvtQuery(
        CHANNEL,
        flags,
        query
    )

    initial = win32evtlog.EvtNext(
        handle,
        1
    )

    last_record_id = None

    if initial:

        xml = win32evtlog.EvtRender(
            initial[0],
            win32evtlog.EvtRenderEventXml
        )

        root = ET.fromstring(xml)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        record = root.find(
            "e:System/e:EventRecordID",
            namespace
        )

        if record is not None:
            last_record_id = int(
                record.text
            )

    try:

        while True:

            forward_flags = (
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryForwardDirection
            )

            if last_record_id is None:
                query = "*"
            else:
                query = (
                    f"*[System/EventRecordID>"
                    f"{last_record_id}]"
                )

            handle = win32evtlog.EvtQuery(
                CHANNEL,
                forward_flags,
                query
            )

            events = win32evtlog.EvtNext(
                handle,
                100
            )

            for raw_event in events:

                event = parse_event(
                    raw_event
                )

                xml = win32evtlog.EvtRender(
                    raw_event,
                    win32evtlog.EvtRenderEventXml
                )

                root = ET.fromstring(xml)

                namespace = {
                    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                }

                record = root.find(
                    "e:System/e:EventRecordID",
                    namespace
                )

                if record is not None:
                    last_record_id = int(
                        record.text
                    )

                print_event(event)
                save_event(event)

            time.sleep(1)

    except KeyboardInterrupt:

        print("\n\nCollector stopped.")

        print(
            f"Events saved to:\n{OUTPUT_FILE}"
        )


if __name__ == "__main__":
    main()