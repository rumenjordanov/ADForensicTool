"""
Synthetic Windows Security event XML, shaped like the XML rendering
python-evtx's Record.xml() returns for a real Security.evtx record.

Used to unit test parser.evtx_parser.normalize_record (and, downstream,
rules.engine) without needing a real .evtx binary fixture.
"""
from __future__ import annotations

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def make_event_xml(
    event_id: int,
    timestamp: str,
    computer: str = "DC01.contoso.local",
    data: dict[str, str] | None = None,
    user_data: tuple[str, str, dict[str, str]] | None = None,
) -> str:
    """Build a synthetic <Event> XML string for the given Event ID.

    `timestamp` should be an ISO-8601 UTC string, e.g. "2026-06-08T02:14:00.000000Z".
    `data` maps EventData "Name" attributes to values, matching what a real
    Security event of that Event ID would carry.

    `user_data`, if given, is (element_name, xmlns, fields) and renders a
    <UserData> block instead of <EventData> -- the shape some events (e.g.
    a real 1102 audit-log-cleared) actually use.
    """
    data = data or {}
    if user_data is not None:
        element, xmlns, fields = user_data
        children = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
        payload = f'  <UserData>\n    <{element} xmlns="{xmlns}">{children}</{element}>\n  </UserData>'
    else:
        data_elements = "\n".join(f'    <Data Name="{name}">{value}</Data>' for name, value in data.items())
        payload = f"  <EventData>\n{data_elements}\n  </EventData>"

    return f"""<Event xmlns="{_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}"/>
    <EventRecordID>1</EventRecordID>
    <Correlation/>
    <Execution ProcessID="656" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>{computer}</Computer>
    <Security/>
  </System>
{payload}
</Event>"""


def failed_logon_xml(timestamp: str, user: str = "jsmith", ip: str = "203.0.113.44", computer: str = "DC01.contoso.local") -> str:
    """A 4625 (failed logon) event."""
    return make_event_xml(
        4625,
        timestamp,
        computer=computer,
        data={
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "TargetUserName": user,
            "TargetDomainName": "CONTOSO",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            "LogonType": "3",
            "WorkstationName": "WORKSTATION1",
            "ProcessName": "-",
            "IpAddress": ip,
            "IpPort": "0",
        },
    )


def kerberos_preauth_failed_xml(
    timestamp: str, user: str = "jsmith", ip: str = "203.0.113.44", computer: str = "DC01.contoso.local"
) -> str:
    """A 4771 (Kerberos pre-authentication failed) event.

    This is the Kerberos-path equivalent of a 4625 -- a domain logon
    attempted against a hostname (rather than a bare IP, which forces
    NTLM) fails here instead, with a wrong password showing as
    Status "0x18".
    """
    return make_event_xml(
        4771,
        timestamp,
        computer=computer,
        data={
            "TargetUserName": user,
            "TargetDomainName": "CONTOSO.LOCAL",
            "ServiceName": "krbtgt/CONTOSO.LOCAL",
            "TicketOptions": "0x40810010",
            "Status": "0x18",
            "PreAuthType": "2",
            "IpAddress": ip,
            "IpPort": "0",
        },
    )


def successful_logon_xml(timestamp: str, user: str = "jsmith", ip: str = "203.0.113.44", computer: str = "DC01.contoso.local") -> str:
    """A 4624 (successful logon) event."""
    return make_event_xml(
        4624,
        timestamp,
        computer=computer,
        data={
            "SubjectUserSid": "S-1-0-0",
            "TargetUserName": user,
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "WorkstationName": "WORKSTATION1",
            "ProcessName": "-",
            "IpAddress": ip,
        },
    )


def group_membership_change_xml(
    timestamp: str,
    member: str = "jsmith",
    group: str = "Domain Admins",
    performed_by: str = "administrator",
    computer: str = "DC01.contoso.local",
    event_id: int = 4728,
) -> str:
    """A member-added-to-group event.

    event_id defaults to 4728 (global group, e.g. Domain Admins) but the
    privilege_escalation rule also watches 4732 (domain local group, e.g.
    built-in Administrators) and 4756 (universal group, e.g. Enterprise
    Admins) -- pass either of those to exercise the other two.
    """
    return make_event_xml(
        event_id,
        timestamp,
        computer=computer,
        data={
            "MemberName": f"CN={member},CN=Users,DC=contoso,DC=local",
            "MemberSid": "S-1-5-21-1-2-3-1234",
            "TargetUserName": group,
            "SubjectUserName": performed_by,
        },
    )


def audit_log_cleared_xml(timestamp: str, performed_by: str = "administrator", computer: str = "DC01.contoso.local") -> str:
    """A 1102 (audit log cleared) event, in the real UserData/LogFileCleared shape."""
    return make_event_xml(
        1102,
        timestamp,
        computer=computer,
        user_data=(
            "LogFileCleared",
            "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
            {
                "SubjectUserSid": "S-1-5-21-1-2-3-500",
                "SubjectUserName": performed_by,
                "SubjectDomainName": "CONTOSO",
                "SubjectLogonId": "0x3e7",
            },
        ),
    )


def kerberoasting_xml(timestamp: str, user: str = "svc_sql", service: str = "MSSQLSvc/db01.contoso.local", computer: str = "DC01.contoso.local") -> str:
    """A 4769 (Kerberos service ticket requested) event with RC4 encryption."""
    return make_event_xml(
        4769,
        timestamp,
        computer=computer,
        data={
            "TargetUserName": user,
            "ServiceName": service,
            "TicketEncryptionType": "0x17",
            "IpAddress": "10.0.0.5",
        },
    )
