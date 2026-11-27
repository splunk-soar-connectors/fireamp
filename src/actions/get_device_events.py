# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import get_client, paginate
from ..models import APIResponse

# Contract correction: The legacy file_found summary is inapplicable: this action reports total_events, not a file lookup.


class GetDeviceEventsParams(Params):
    connector_guid: str | None = Param(
        description="Connector GUID on endpoint",
        primary=True,
        cef_types=["fireamp connector guid"],
        default=None,
    )
    detection_sha256: str | None = Param(
        description="Filter by detection sha256",
        primary=True,
        cef_types=["hash"],
        default=None,
    )
    application_sha256: str | None = Param(
        description="Filter by application sha256",
        primary=True,
        cef_types=["hash"],
        default=None,
    )
    group_guid: str | None = Param(description="Filter by group GUID", default=None)
    start_date: str | None = Param(
        description="Filter by event start date", default=None
    )
    offset: int | None = Param(description="Results offset", default=None)
    event_type: str | None = Param(description="Filter by event type", default=None)
    limit: int | None = Param(
        description="Limit number of results returned", default=None
    )


# Contract correction: scalar IP/group/technique array paths are inapplicable;
# Secure Endpoint returns arrays, represented by standard SDK list fields.


class GetDeviceEventsOutputEventCloudIoc(APIResponse):
    description: str | None = OutputField(
        example_values=[
            "A named pipe was created in a manner similar to that used for local privilege escalation through named pipe impersonation. Tools such as meterpreter often use this technique to escalate to NT Authority\\System."
        ]
    )
    short_description: str | None = OutputField(
        example_values=["W32.PossibleNamedPipeImpersonation.ioc"]
    )


class GetDeviceEventsOutputEventComputerLink(APIResponse):
    computer: str | None = OutputField(
        cef_types=["ip"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/71841cfb-1892-46b5-b7d7-b18d068246b4"
        ],
    )
    group: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/groups/20701584-ff6f-4b78-afed-e2e801366a82"
        ],
    )
    trajectory: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/computers/71841cfb-1892-46b5-b7d7-b18d068246b4/trajectory"
        ],
    )


class GetDeviceEventsOutputEventComputerNetworkAddress(APIResponse):
    ip: str | None = OutputField(example_values=["105.186.48.59"])
    mac: str | None = OutputField(example_values=["0e:12:c4:de:70:ee"])


class GetDeviceEventsOutputEventComputer(APIResponse):
    active: bool | None = OutputField(example_values=[True, False])
    connector_guid: str | None = OutputField(
        example_values=["71841cfb-1892-46b5-b7d7-b18d068246b4"]
    )
    external_ip: str | None = OutputField(
        cef_types=["ip"], example_values=["174.138.94.48"]
    )
    links: GetDeviceEventsOutputEventComputerLink | None = None
    network_addresses: list[GetDeviceEventsOutputEventComputerNetworkAddress] | None = (
        None
    )
    user: str | None = OutputField(example_values=["pwned@W10-CUCKOO-MC"])
    hostname: str | None = OutputField(
        cef_types=["host name"],
        example_values=["W10-CUCKOO-MC"],
        column_name="Hostname",
    )


class GetDeviceEventsOutputEventFileArchivedFileIdentity(APIResponse):
    sha256: str | None = OutputField(
        example_values=[
            "0a99238e1ebebc47d7a89b2ccddfae537479f7f77322b5d4941315d3f7e5ca48"  # pragma: allowlist secret
        ]
    )


class GetDeviceEventsOutputEventFileArchivedFile(APIResponse):
    disposition: str | None = OutputField(example_values=["Malicious"])
    identity: GetDeviceEventsOutputEventFileArchivedFileIdentity | None = None


class GetDeviceEventsOutputEventFileAttackDetailIndicator(APIResponse):
    description: str | None = OutputField(
        example_values=[
            "DealPly is adware, which claims to improve your online shopping experience. It is often bundled into other legitimate installers and is difficult to uninstall. It creates pop-up advertisements and injects advertisements on webpages. Adware has also been known to download and install malware."
        ]
    )
    id: str | None = OutputField(
        example_values=["44cfe1c4-3dc4-4619-be6b-88c9d69c2a97"]
    )
    severity: str | None = OutputField(example_values=["medium"])
    short_description: str | None = OutputField(
        example_values=["Dealply adware detected"]
    )


class GetDeviceEventsOutputEventFileAttackDetail(APIResponse):
    application: str | None = OutputField(example_values=["firefox.exe"])
    attacked_module: str | None = OutputField(
        example_values=["C:\\Program Files\\Mozilla Firefox\\xul.dll"]
    )
    base_address: str | None = OutputField(example_values=["0x7D1E0000"])
    indicators: list[GetDeviceEventsOutputEventFileAttackDetailIndicator] | None = None


class GetDeviceEventsOutputEventFileIdentity(APIResponse):
    md5: str | None = OutputField(
        cef_types=["md5"],
        example_values=["8b2bd6352e0ffe8b0e2bad20b49c8682"],  # pragma: allowlist secret
    )
    sha1: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "b307e0b8035287e15ac473d70e54566e462596c1"  # pragma: allowlist secret
        ],
    )
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "b81302bc5cbfeddf3b608a60b25f86944eddcef617e733cddf0fc93ee4ccc7ab"  # pragma: allowlist secret
        ],
    )


class GetDeviceEventsOutputEventFileParentIdentity(APIResponse):
    md5: str | None = OutputField(
        cef_types=["md5"],
        example_values=["f7dc8a74e30e08b9510380274cfb9288"],  # pragma: allowlist secret
    )
    sha1: str | None = OutputField(
        cef_types=["sha1"],
        example_values=[
            "c893cf07e5f65749cd66e17d9523638b132c87b2"  # pragma: allowlist secret
        ],
    )
    sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "c5e88d778c0b118d49bef467ed059c09b61deea505d2a3d5ca1dcc0a5cdf752f"  # pragma: allowlist secret
        ],
    )


class GetDeviceEventsOutputEventFileParent(APIResponse):
    disposition: str | None = OutputField(example_values=["Clean"])
    file_name: str | None = OutputField(
        cef_types=["file name"], example_values=["explorer.exe"]
    )
    identity: GetDeviceEventsOutputEventFileParentIdentity | None = None
    process_id: int | None = OutputField(example_values=[3124])


class GetDeviceEventsOutputEventFile(APIResponse):
    archived_file: GetDeviceEventsOutputEventFileArchivedFile | None = None
    attack_details: GetDeviceEventsOutputEventFileAttackDetail | None = None
    disposition: str | None = OutputField(example_values=["Malicious"])
    file_name: str | None = OutputField(
        cef_types=["file name"], example_values=["$RY69ASX.exe"]
    )
    file_path: str | None = OutputField(
        cef_types=["file name", "file path"],
        example_values=[
            "\\\\?\\C:\\$Recycle.Bin\\S-1-5-21-2502938909-339922712-2837714241-1001\\$RY69ASX.exe"
        ],
    )
    identity: GetDeviceEventsOutputEventFileIdentity | None = None
    parent: GetDeviceEventsOutputEventFileParent | None = None


class GetDeviceEventsOutputEventIsolation(APIResponse):
    duration: int | None = OutputField(example_values=[46])
    user: str | None = OutputField(example_values=["User"])


class GetDeviceEventsOutputEventNetworkInfoNfm(APIResponse):
    direction: str | None = OutputField(example_values=["Outgoing connection from"])
    protocol: str | None = OutputField(example_values=["TCP"])


class GetDeviceEventsOutputEventNetworkInfoParentIdentity(APIResponse):
    md5: str | None = OutputField(example_values=["b3581f426dc500a51091cdd5bacf0454"])
    sha1: str | None = OutputField(
        example_values=[
            "8de30174cebc8732f1ba961e7d93fe5549495a80"  # pragma: allowlist secret
        ]
    )
    sha256: str | None = OutputField(
        example_values=[
            "b4e5c2775de098946b4e11aba138b89d42b88c1dbd4d5ec879ef6919bf018132"  # pragma: allowlist secret
        ]
    )


class GetDeviceEventsOutputEventNetworkInfoParent(APIResponse):
    disposition: str | None = OutputField(example_values=["Clean"])
    file_name: str | None = OutputField(example_values=["iexplore.exe"])
    identity: GetDeviceEventsOutputEventNetworkInfoParentIdentity | None = None
    process_id: int | None = OutputField(example_values=[3136])


class GetDeviceEventsOutputEventNetworkInfo(APIResponse):
    dirty_url: str | None = OutputField(
        example_values=["http://dak1otavola1ndos.com/h/index.php"]
    )
    local_ip: str | None = OutputField(example_values=["192.168.1.3"])
    local_port: int | None = OutputField(example_values=[55810])
    nfm: GetDeviceEventsOutputEventNetworkInfoNfm | None = None
    parent: GetDeviceEventsOutputEventNetworkInfoParent | None = None
    remote_ip: str | None = OutputField(example_values=["75.102.25.76"])
    remote_port: int | None = OutputField(example_values=[443])


class GetDeviceEventsOutputEventScan(APIResponse):
    clean: bool | None = OutputField(example_values=[True])
    description: str | None = OutputField(
        example_values=["C:\\Program Files\\DVD Maker"]
    )
    malicious_detections: int | None = OutputField(example_values=[0])
    scanned_files: int | None = OutputField(example_values=[9])
    scanned_paths: int | None = OutputField(example_values=[2])
    scanned_processes: int | None = OutputField(example_values=[0])


class GetDeviceEventsOutputEventTactic(APIResponse):
    description: str | None = OutputField(
        example_values=[
            "<p>The adversary is trying to avoid being detected.</p>\n\n<p>Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics' techniques are cross-listed here when those techniques include the added benefit of subverting defenses.</p>\n"
        ]
    )
    external_id: str | None = OutputField(example_values=["TA0005"])
    mitre_name: str | None = OutputField(example_values=["tactic"])
    mitre_url: str | None = OutputField(
        example_values=["https://attack.mitre.org/tactics/TA0005"]
    )
    name: str | None = OutputField(example_values=["Defense Evasion"])


class GetDeviceEventsOutputEventTechnique(APIResponse):
    data_sources: list[str] | None = OutputField(
        example_values=[
            "File: File Content, File: File Metadata, File: File Creation, Process: Process Creation, Command: Command Execution, Command: Command Execution"
        ]
    )
    description: str | None = OutputField(
        example_values=[
            '<p>Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.</p>\n\n<p>Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user\'s action may be required to open and <a href="https://attack.mitre.org/techniques/T1140">Deobfuscate/Decode Files or Information</a> for <a href="https://attack.mitre.org/techniques/T1204">User Execution</a>. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as JavaScript.</p>\n\n<p>Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)</p>\n\n<p>Adversaries may also obfuscate commands executed from payloads or directly via a <a href="https://attack.mitre.org/techniques/T1059">Command and Scripting Interpreter</a>. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017)(Citation: PaloAlto EncodedCommand March 2017)</p>\n'
        ]
    )
    external_id: str | None = OutputField(example_values=["T1027"])
    mitre_name: str | None = OutputField(example_values=["technique"])
    mitre_url: str | None = OutputField(
        example_values=["https://attack.mitre.org/techniques/T1027"]
    )
    name: str | None = OutputField(example_values=["Obfuscated Files or Information"])
    permissions: list[str] | None = None
    platforms: list[str] | None = OutputField(example_values=["Linux, macOS, Windows"])
    system_requirements: list[str] | None = None
    tactics_names: list[str] | None = OutputField(example_values=["Defense Evasion"])


class GetDeviceEventsOutputEventThreatHuntingTactic(APIResponse):
    description: str | None = OutputField(
        example_values=[
            "<p>The adversary is trying to avoid being detected.</p>\n\n<p>Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics' techniques are cross-listed here when those techniques include the added benefit of subverting defenses.</p>\n"
        ]
    )
    external_id: str | None = OutputField(example_values=["TA0005"])
    mitre_name: str | None = OutputField(example_values=["tactic"])
    mitre_url: str | None = OutputField(
        example_values=["https://attack.mitre.org/tactics/TA0005"]
    )
    name: str | None = OutputField(example_values=["Defense Evasion"])


class GetDeviceEventsOutputEventThreatHuntingTechnique(APIResponse):
    data_sources: list[str] | None = OutputField(
        example_values=[
            "File: File Content, File: File Metadata, File: File Creation, Process: Process Creation, Command: Command Execution, Command: Command Execution"
        ]
    )
    description: str | None = OutputField(
        example_values=[
            '<p>Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.</p>\n\n<p>Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user\'s action may be required to open and <a href="https://attack.mitre.org/techniques/T1140">Deobfuscate/Decode Files or Information</a> for <a href="https://attack.mitre.org/techniques/T1204">User Execution</a>. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as JavaScript.</p>\n\n<p>Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)</p>\n\n<p>Adversaries may also obfuscate commands executed from payloads or directly via a <a href="https://attack.mitre.org/techniques/T1059">Command and Scripting Interpreter</a>. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017)(Citation: PaloAlto EncodedCommand March 2017)</p>\n'
        ]
    )
    external_id: str | None = OutputField(example_values=["T1027"])
    mitre_name: str | None = OutputField(example_values=["technique"])
    mitre_url: str | None = OutputField(
        example_values=["https://attack.mitre.org/techniques/T1027"]
    )
    name: str | None = OutputField(example_values=["Obfuscated Files or Information"])
    permissions: list[str] | None = None
    platforms: list[str] | None = OutputField(example_values=["Linux, macOS, Windows"])
    system_requirements: list[str] | None = None
    tactics_names: list[str] | None = OutputField(example_values=["Defense Evasion"])


class GetDeviceEventsOutputEventThreatHunting(APIResponse):
    incident_end_time: int | None = OutputField(example_values=[1621498185])
    incident_hunt_guid: str | None = OutputField(
        example_values=["00712651-e534-4851-ac6d-d4017f9c1714"]
    )
    incident_remediation: str | None = OutputField(
        example_values=[
            "We recommend the following:\r\n\r\n- Isolation of the affected hosts from the network\r\n- Perform forensic investigation\r\n\t- Review all activity performed by host users\r\n\t- Review all activities of affected hosts\r\n\t- Upload all files found under the following folders to ThreatGrid for analysis, then delete all malicious files\r\n- Reimage the affected systems if necessary.\r\n\r\nIf you feel your organization needs assistance with any aspect of Incident Response, we do have Cisco Talos Incident Response available. Please reach out to your Cisco Account Manager about a Talos IR Retainer, or reach out to 1-844-831-7715 for emergencies 24 hours a day.  For more information visit https://talosintelligence.com/incident_response."
        ]
    )
    incident_report_guid: str | None = OutputField(
        example_values=["54259a50-d6bf-483a-bc49-979f12cfa591"]
    )
    incident_start_time: int | None = OutputField(example_values=[1621498117])
    incident_summary: str | None = OutputField(
        example_values=[
            "The affected host executed schtasks.exe to schedule the launch of certutil.exe.  The surrounding data of this hunt lead are as follows:\r\n\r\n- The user opened a malicious Word document from a phishing email\r\n- The Word document dropped two VBScripts\r\n- Word created a scheduled task to launch certutil.exe, which is unusual for parent-child relationships\r\n- Word executes one of the VBScripts it had dropped earlier using WMIC. (AMP detects launching of WScript by Word)\r\n- WScript runs reconnaissance commands to discover the network information, domain controller list etc. and stores data in recon.txt\r\n- WScript creates an archive called sweetz.cab of stolen data using makecab utility\r\n- WScript uploads that cab file to a suspicious FTP server\r\n- WScript starts collecting sensitive information such as passwords in a file called goodies.txt\r\n- WScript makes an archive and uploads it via FTP\r\n- Certutil.exe executes via the earlier scheduled task, due to COM hijacking, it launches a PowerShell script (simply shows a dialog box demonstrating arbitrary code execution)"
        ]
    )
    incident_title: str | None = OutputField(
        example_values=["Certutil.exe Executed by Schtasks.exe (Demo Data)"]
    )
    severity: str | None = OutputField(example_values=["critical"])
    tactics: list[GetDeviceEventsOutputEventThreatHuntingTactic] | None = None
    techniques: list[GetDeviceEventsOutputEventThreatHuntingTechnique] | None = None


class GetDeviceEventsOutputEventVulnerability(APIResponse):
    cve: str | None = OutputField(example_values=["CVE-2015-7204"])
    name: str | None = OutputField(example_values=["Mozilla Firefox"])
    score: str | None = OutputField(example_values=["6.8"])
    url: str | None = OutputField(
        example_values=[
            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-7204"
        ]
    )
    version: str | None = OutputField(example_values=["41.0"])


class GetDeviceEventsOutputEvent(APIResponse):
    cloud_ioc: GetDeviceEventsOutputEventCloudIoc | None = None
    computer: GetDeviceEventsOutputEventComputer | None = None
    event_type: str | None = OutputField(
        example_values=["Uninstall"], column_name="Event Type"
    )
    id: int | None = OutputField(example_values=[17965765], column_name="ID")
    connector_guid: str | None = OutputField(
        example_values=["71841cfb-1892-46b5-b7d7-b18d068246b4"],
        column_name="Connector GUID",
    )
    date: str | None = OutputField(example_values=["2020-04-06T13:03:50+00:00"])
    detection: str | None = OutputField(
        example_values=["Doc.Dropper.Valyria::in03.talos"], column_name="Detection"
    )
    detection_id: str | None = OutputField(
        example_values=["6812581201115613122"], column_name="Detection ID"
    )
    event_type_id: int | None = OutputField(example_values=[553648166])
    file: GetDeviceEventsOutputEventFile | None = None
    group_guids: list[str] | None = OutputField(
        example_values=["20701584-ff6f-4b78-afed-e2e801366a82"]
    )
    isolation: GetDeviceEventsOutputEventIsolation | None = None
    network_info: GetDeviceEventsOutputEventNetworkInfo | None = None
    scan: GetDeviceEventsOutputEventScan | None = None
    severity: str | None = OutputField(example_values=["Medium"])
    start_date: str | None = OutputField(example_values=["2016-09-22T19:39:33+00:00"])
    start_timestamp: int | None = OutputField(example_values=[1474573173])
    tactics: list[GetDeviceEventsOutputEventTactic] | None = None
    techniques: list[GetDeviceEventsOutputEventTechnique] | None = None
    threat_hunting: GetDeviceEventsOutputEventThreatHunting | None = None
    timestamp: int | None = OutputField(example_values=[1586178230])
    timestamp_nanoseconds: int | None = OutputField(example_values=[619724887])
    vulnerabilities: list[GetDeviceEventsOutputEventVulnerability] | None = None


class GetDeviceEventsOutputMetadataLink(APIResponse):
    next: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/events?limit=10&connector_guid=71841cfb-1892-46b5-b7d7-b18d068246b4&offset=10"
        ],
    )
    self: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://api.amp.sourcefire.com/v1/events?limit=10&connector_guid=71841cfb-1892-46b5-b7d7-b18d068246b4"
        ],
    )


class GetDeviceEventsOutputMetadataResult(APIResponse):
    current_item_count: int | None = OutputField(example_values=[10])
    index: int | None = OutputField(example_values=[0])
    items_per_page: int | None = OutputField(example_values=[10])
    total: int | None = OutputField(example_values=[14595])


class GetDeviceEventsOutputMetadata(APIResponse):
    links: GetDeviceEventsOutputMetadataLink | None = None
    results: GetDeviceEventsOutputMetadataResult | None = None


class GetDeviceEventsOutput(APIResponse):
    events: list[GetDeviceEventsOutputEvent] | None = None
    metadata: GetDeviceEventsOutputMetadata | None = None
    version: str | None = OutputField(example_values=["v1.2.0"])


class GetDeviceEventsSummary(ActionOutput):
    total_events: int


def get_device_events(
    params: GetDeviceEventsParams,
    soar: SOARClient[GetDeviceEventsSummary],
    asset: Asset,
) -> GetDeviceEventsOutput:
    """Retrieve all matching events, starting at the requested offset."""
    query = params.model_dump(exclude_none=True)
    with get_client(asset) as client:
        response = paginate(client, "/v1/events", params=query)
    response["events"] = response.pop("data")
    soar.set_summary(GetDeviceEventsSummary(total_events=len(response["events"])))
    return GetDeviceEventsOutput.model_validate(response)
