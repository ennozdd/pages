# Detection Rules

|Host                        |Rule                                                                |OS     | Severity  |
|---                         |---|---|---|
|Ulterius RDP Tool Detection | process_name:daemonmanager.exe or digsig_publisher:"Andrew Sampson"|Windows| Critical  |
|CVE-2020-10713 GRUB boothole detection| os_type:linux filemod:/boot/grub2/grub.cfg -cmdline:insights_client -cmdline:sosreport| Linux | Suspicious|
|Ntds Dump Activity|(cmdline:powershell and cmdline:ntdsutil and cmdline:create) AND os_type:"windows"|Windows|Suspicious|
|Linux Privilege Escalation Tool Detection|(os_type:linux) AND (process_name:bash) AND (cmdline:lse.sh OR cmdline:LinEnum.sh OR cmdline:linux-exploit-suggester.sh OR cmdline:linuxprivchecker.sh OR cmdline:linpeas.sh OR cmdline:sliver.sh)|Linux|Suspicious|
|Windows system sam file export process|(cmdline:reg AND cmdline:save AND cmdline:hklm\sam) AND os_type:"windows"|Windows|Suspicious|
|Windows system hive file export process|(cmdline:reg AND cmdline:save AND cmdline:hklm\system) AND os_type:"windows"|Windows|Suspicious|
|Windows logs cleared| os_type:"windows" AND (process_name:wevtutil.exe AND cmdline:cl)|Windows|Suspicious|
|CVE-2020-10713 GRUB boothole detection|os_type:linux filemod:/boot/grub2/grub.cfg -cmdline:insights_client -cmdline:sosreport|Windows|Suspicios|
