index=* host=test sourcetype="WinEventLog:Application" (EventCode=1000 OR EventID=1000) "splunk-winevtlog.exe"
| stats max(_time) as crash_time
| eval earliest=crash_time-600, latest=crash_time+600
| map maxsearches=1 search="
  search index=* host=test sourcetype=\"XmlWinEventLog\" source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\"
  earliest=$earliest$ latest=$latest$
  (EventCode IN (1,5,7,10,11,12,13,14,22,23,25) OR EventID IN (1,5,7,10,11,12,13,14,22,23,25))
  | eval EID=coalesce(EventCode, EventID)
  | eval Image=coalesce(Image, ProcessImage, process_path, 'EventData.Image', 'EventData.ProcessName', 'EventData.ImagePath')
  | eval ParentImage=coalesce(ParentImage, 'EventData.ParentImage')
  | eval CommandLine=coalesce(CommandLine, 'EventData.CommandLine')
  | eval TargetImage=coalesce(TargetImage, 'EventData.TargetImage')
  | eval GrantedAccess=coalesce(GrantedAccess, 'EventData.GrantedAccess')
  | eval sysmon_event=case(
      EID=1,\"Process Create\",
      EID=5,\"Process Terminate\",
      EID=7,\"Image Load\",
      EID=10,\"Process Access\",
      EID=11,\"File Create\",
      EID=12,\"Registry Create/Delete\",
      EID=13,\"Registry Value Set\",
      EID=14,\"Registry Key Rename\",
      EID=22,\"DNS Query\",
      EID=23,\"File Delete\",
      EID=25,\"Process Tampering\",
      1=1,\"Other\"
    )
  | table _time sysmon_event EID Image ParentImage CommandLine TargetImage GrantedAccess User
  | sort _time
"
