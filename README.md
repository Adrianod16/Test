index=* host=test sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 OR EventCode=5 OR EventCode=7 OR EventCode=10 OR EventCode=11 OR EventCode=12 OR EventCode=13 OR EventCode=14 OR EventCode=22 OR EventCode=23 OR EventCode=24 OR EventCode=25)
| eval sysmon_event=case(
    EventCode=1,"Process Create",
    EventCode=5,"Process Terminate",
    EventCode=7,"Image Load",
    EventCode=10,"Process Access",
    EventCode=11,"File Create",
    EventCode=12,"Registry Create/Delete",
    EventCode=13,"Registry Value Set",
    EventCode=14,"Registry Key Rename",
    EventCode=22,"DNS Query",
    EventCode=23,"File Delete",
    EventCode=24,"Clipboard",
    EventCode=25,"Process Tampering",
    1=1,"Other"
  )
| table _time sysmon_event EventCode Image CommandLine ParentImage User TargetImage GrantedAccess TargetFilename DestinationIp DestinationHostname QueryName
| sort _time
