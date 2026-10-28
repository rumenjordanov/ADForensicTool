"""
Synthetic Windows Security event XML, shaped like the XML rendering
python-evtx's Record.xml() returns for a real Security.evtx record.

Used to unit test parser.evtx_parser.normalize_record (and, downstream,
rules.engine) without needing a real .evtx binary fixture.
"""
from __future__ import annotations

import zlib

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def sid_for(account: str) -> str:
    """A stable, distinct domain SID per account name (as real accounts have).

    Fixtures used to hardcode one SID for everyone, which made unrelated
    accounts look like the same principal to anything joining on SIDs.
    """
    if account.lower() == "administrator":
        return "S-1-5-21-1-2-3-500"
    return f"S-1-5-21-1-2-3-{1000 + zlib.crc32(account.lower().encode()) % 90000}"


def make_event_xml(
    event_id: int,
    timestamp: str,
    computer: str = "DC01.contoso.local",
    data: dict[str, str] | None = None,
    user_data: tuple[str, str, dict[str, str]] | None = None,
    channel: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
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
    <Provider Name="{provider}"/>
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
    <Channel>{channel}</Channel>
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
            "MemberSid": sid_for(member),
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
                "SubjectUserSid": sid_for(performed_by),
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
            "Status": "0x0",
            "IpAddress": "10.0.0.5",
        },
    )


# -- Events for the extended detection set --------------------------------
# Field names/values follow what Windows actually logs for each Event ID.

DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def asrep_tgt_xml(timestamp: str, user: str = "svc_legacy", preauth: str = "0", ip: str = "::ffff:203.0.113.44") -> str:
    """A 4768 (TGT requested). PreAuthType 0 = no pre-authentication."""
    return make_event_xml(
        4768,
        timestamp,
        data={
            "TargetUserName": user,
            "TargetDomainName": "CONTOSO.LOCAL",
            "TargetSid": sid_for(user),
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40800010",
            "Status": "0x0",
            "TicketEncryptionType": "0x17",
            "PreAuthType": preauth,
            "IpAddress": ip,
            "IpPort": "49712",
        },
    )


def directory_access_xml(timestamp: str, performed_by: str = "jsmith", guid: str = DS_REPLICATION_GET_CHANGES_ALL) -> str:
    """A 4662 (operation performed on a directory object) exercising a control access right."""
    return make_event_xml(
        4662,
        timestamp,
        data={
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "SubjectLogonId": "0x5a3c1",
            "ObjectServer": "DS",
            "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
            "ObjectName": "%{2d3c4f1a-1111-2222-3333-444455556666}",
            "OperationType": "Object Access",
            "AccessList": "%%7688",
            "AccessMask": "0x100",
            "Properties": f"%%7688\n\t\t{{{guid}}}\n\t{{19195a5b-6da0-11d0-afd3-00c04fd930c9}}",
        },
    )


def account_created_xml(timestamp: str, new_account: str = "helpdesk2", performed_by: str = "jsmith") -> str:
    """A 4720 (user account created)."""
    return make_event_xml(
        4720,
        timestamp,
        data={
            "TargetUserName": new_account,
            "TargetDomainName": "CONTOSO",
            "TargetSid": sid_for(new_account),
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "SamAccountName": new_account,
        },
    )


def scheduled_task_xml(timestamp: str, performed_by: str = "jsmith", task: str = "\\Microsoft\\Windows\\Updater") -> str:
    """A 4698 (scheduled task created)."""
    return make_event_xml(
        4698,
        timestamp,
        data={
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "TaskName": task,
            "TaskContent": "&lt;Task&gt;...&lt;/Task&gt;",
        },
    )


def service_installed_xml(timestamp: str, performed_by: str = "jsmith", service: str = "PSEXESVC") -> str:
    """A 4697 (service installed, Security log)."""
    return make_event_xml(
        4697,
        timestamp,
        data={
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "ServiceName": service,
            "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe",
            "ServiceType": "0x10",
            "ServiceStartType": "3",
            "ServiceAccount": "LocalSystem",
        },
    )


def system_service_installed_xml(timestamp: str, service: str = "PSEXESVC") -> str:
    """A 7045 (service installed, System log)."""
    return make_event_xml(
        7045,
        timestamp,
        channel="System",
        provider="Service Control Manager",
        data={
            "ServiceName": service,
            "ImagePath": "%SystemRoot%\\PSEXESVC.exe",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": "LocalSystem",
        },
    )


def audit_policy_changed_xml(timestamp: str, changes: str = "%%8448", performed_by: str = "jsmith") -> str:
    """A 4719 (system audit policy changed). %%8448 = Success removed, %%8449 = Success added."""
    return make_event_xml(
        4719,
        timestamp,
        data={
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "CategoryId": "%%8274",
            "SubcategoryId": "%%12544",
            "SubcategoryGuid": "{0cce9215-69ae-11d9-bed3-505054503030}",
            "AuditPolicyChanges": changes,
        },
    )


def dsrm_password_set_xml(timestamp: str, performed_by: str = "jsmith") -> str:
    """A 4794 (attempt to set the Directory Services Restore Mode admin password)."""
    return make_event_xml(
        4794,
        timestamp,
        data={
            "SubjectUserSid": sid_for(performed_by),
            "SubjectUserName": performed_by,
            "SubjectDomainName": "CONTOSO",
            "Workstation": "DC01",
            "Status": "0x0",
        },
    )


def account_lockout_xml(timestamp: str, user: str = "jsmith", caller: str = "WORKSTATION1") -> str:
    """A 4740 (user account locked out). TargetDomainName holds the caller computer."""
    return make_event_xml(
        4740,
        timestamp,
        data={
            "TargetUserName": user,
            "TargetDomainName": caller,
            "TargetSid": sid_for(user),
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "DC01$",
            "SubjectDomainName": "CONTOSO",
        },
    )


def new_credentials_logon_xml(timestamp: str, user: str = "jsmith", process: str = "seclogo") -> str:
    """A 4624 with LogonType 9 (NewCredentials), as runas /netonly or sekurlsa::pth produce."""
    return make_event_xml(
        4624,
        timestamp,
        data={
            "SubjectUserName": user,
            "TargetUserName": user,
            "TargetDomainName": "CONTOSO",
            "TargetUserSid": sid_for(user),
            "LogonType": "9",
            "LogonProcessName": process,
            "AuthenticationPackageName": "Negotiate",
            "TargetOutboundUserName": "administrator",
            "IpAddress": "::1",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        },
    )
