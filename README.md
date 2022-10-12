# PPL-Duck

You can still run as PPL after june 2022 patch, this PoC remove the patch by replacing ntdll.dll in SysWow64 therefore causing the patch to be no longer effective but it unfortunately requires you to reboot two times so if you're plannig to dump lsass while it's running as PPL this may not be perfect for you because the credentials are cleared when rebooting.
This was mainly done to take down antimalware products so you can ransomware everything with ease, with the privilege of PPL you can run as the kernel by using this PoC
https://github.com/SecIdiot/ANGRYORCHARD and from you can remove kernel callbacks and kill antimalware/EDR or whatever kind of lie is running on the target machine.
The PoC was designed to work with windows 10 21H2, it can be backported to all versions as well as windows 11, all you need is a signed ntdll.dll from Microsoft which was shipped with that specific OS you're targeting. You can find older dll versions in winbindex.

I can't remember how the PoC works nor do I care, I'm moving to another implementation which doesn't required rebooting which will be possibly disclosed in the future.

Steps to reproduce:

Create a folder and place x64 version of "PPL duck.exe" as well as an x86 version of ntdll.dll which was shipped with the OS you're targeting before june 2022 patch and lastly place service.exe and sspicli.dll which will be loaded as PPL when rebooting.

In some rare instances I noticed windows crashing but as I said it's really rare and to note, the poc will create a log file in the current directory so you can investigate any bug and unfortunately the PoC can be only used on x64 version of windows (possibly ARM too) but who uses x86 anyway ?
