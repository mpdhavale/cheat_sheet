[sed](https://github.com/mpdhavale/cheat_sheet#sed-examples)

-------------------
# Setup

## Set hostname
```
hostnamectl set-hostname HOSTNAME
```

## Set keyboard and language.  Can set different keyboards for VNC or X11. 
```
localectl status  
```

## Detailed time/date info.  Includes NTP info.
```
timedatectl     
```

## Manually set time. Updates system and RTC. `date` does system clock only.
```
timedatectl set-time HH:MM:SS     
```

## Manually set date.
```
timedatectl set-time 'YYYY-MM-DD HH:MM:SS'  
```

## List available timezones
```
timedatectl list-timezones     
```

## Set timezone 
```
timedatectl set-timezone TIMEZONE   
```

## Enable ntp.  Ntpd must be installed.
```
timedatectl set-ntp yes       
```

## Whenever changing NTP config:
```
systemctl restart systemd-timedated.services  
```

## Convert epoch time to normal:
```
date -d@${EPOCH}
```


-------------------
# Troubleshooting:

## Get a list of all processes sorted by memory used:
```
top -M -a -n1 -b
```
... where:
- `-M`  shows memory sizes in human-readable format
- `-a`  sorts the list by memory usage
- `-n1` shows one iteration
- `-b`  batch mode, used with `-n`

Notes:
The above shows memory columns VIRT and RES:
- VIRT is total virtual memory.
- RES is actual physical memory.
The calculation of "memory used" in top/free is according to RES.


-------------------
# Vim:

## Minimal ~/.vimrc config:
Turns off colors and beeps. 
```
syntax off
set belloff=all
```

## If paste is screwed up (adding extra whitespace), use this command, then insert/append:
```
:set paste
```

## Remove DOS endline characters (^M):
```
:set ff=unix
```
Sometimes neither this nor dos2unix work.  Try this instead:
```
:%s/[CTRL+v][CTRL+m]//g
```
... where the stuff in brackets is stuff that you do, not what you type.  It will look like this when you're done: 
```
:%s/^M//g
```

-------------------
# LDAP

## Example ldapsearch:
```
ldapsearch -v -h ${IDM/AD_HOST} -b "CN=users,cn=accounts,DC=${DOMAIN},DC=com" -D "uid=${BIND_ACCOUNT},CN=users,CN=accounts,DC=${DOMAIN},DC=com" -x -w '${BIND_ACCOUNT_PASSWORD}' -ZZ
CN=users,CN=accounts,DC=${DOMAIN},DC=com
```
Notes:
 - Use as many `DC` entries as are part of your domain.  EX: "DC=google,DC=com"
 - `-b` is the search base (where you want to find entries).
 - `-D` is the bind DN account used to connect to the IDM/AD host.
 - Everything at the end is what you want to find (in this case, all users).
 

-------------------
# Networking

## Displaying connections:
```
netstat -pantuw
```

## Setting up bridged interfaces:

If the interface to be bridged is currently running it should be taken down before proceeding:
```
ifdown eth0
```
Add a script file to establish the bridge for the physical network device. In this example the device is eth0 so we need to create a file name ifcfg-eth0 and add the following lines to it. For the purposes of this example we will name the interface br0:
```
DEVICE=eth0
ONBOOT=yes
BRIDGE=br0
```
The next step is to create a script file for the bridge interface. The name of this file must take the form ifcfg-<bridgename> where <bridgename> matches the name of the bridge defined in the BRIDGE= directive outlined above. Given this requirement, we will name the file ifcfg-br0. The contents of this file for this example will read as follows:
```
DEVICE=br0
ONBOOT=yes
TYPE=Bridge
BOOTPROTO=dhcp
STP=on
DELAY=0
```
Note that the DEVICE= line must refer to the bridge name previously specified (i.e. bridge0 in this instance). Save the file and then start up both interfaces:
```
ifup eth0
ifup br0
```
Using the ifconfig command, the new bridge interface should now be visible.

## Updating DNS on a chrooted named server:
```
/var/named/chroot/var/named/data2/${IP}.zone
/var/named/chroot/var/named/data2/${FQDN}.zone
```

## Adding a static route:
```
ip route add ${SUBNET} via ${GATEWAY} dev ${DEVICE}
```

## Creating a persistent static route:
IPv4: Create `/etc/sysconfig/network-scripts/route-eth#`:
```
default via ${IP} [advmss $DESIRED_MSS_MINUS_40]
```
IPv6: Create `/etc/sysconfig/network-scripts/route6-eth#`:
```
default via ${IP} [advmss $DESIRED_MSS]
```

## Show route info:
IPv4:  `netstat -rn`
IPv6:  `ip -6 route show`

## Scan all ports on a host (to see if an IP address is in use):
```
nmap -Pn [IP_ADDRESS]
```

## Two methods to check if a port is open without telnet:
```
cat < /dev/tcp/${IP}/${PORT}
curl -v telnet://${IP}:${PORT}
```

## Get detailed domain info (exclude original query for easier grepping):
```
dig +noquestion $FQDN
```

## Get a list of all the hosts in the domain (assuming the DNS server allows you):
```
dig DOMAIN axfr [@SERVER]
```
EX: `dig ad.ORG axfr @10.23.219.161`

## Disable ipv6 (RH6 only.  For RH7, use https://access.redhat.com/solutions/8709#rhel7disable).
```
# /etc/modprobe.d/disable.conf (IBM’s preferred naming convention)
install ipv6 /bin/true
# /etc/modprobe.d/blacklist.conf:
blacklist net-pf-10
blacklist ipv6
#/etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
#Uninstall ip6tables:
yum erase iptables-ipv6 
# Reboot and once back up, run 
lsmod |grep ipv6
```

##Test multicast:
```
yum install sockperf (epel package)
# Server:
sockperf server -i 228.0.0.5 -p 45564
# Client:
sockperf ping-pong -i 228.0.0.5 -p 45564
# other commands:
netstat -g
cat /proc/net/igmp
```

## firewalld
```
## Input rules (/etc/firewalld/zones/public.xml):
<port protocol="tcp" port="1521"/>
## To enable only outgoing port 80 (assumes default policy of drop):
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT_direct 0 -p tcp -m tcp --dport=80 -j ACCEPT
firewall-cmd --reload
# Here's what the rule looks like (/etc/firewalld/direct.xml):
<rule priority="0" table="filter" ipv="ipv4" chain="OUTPUT_direct">-p tcp -m tcp --dport=80 -j ACCEPT</rule>
## Displaying rules:
# To display permanent rules:
firewall-cmd --permanent --direct --get-all-rules
# To display runtime rules:
firewall-cmd --direct --get-all-rules
```

## Flash the LED on a NIC:
```
ethtool --identify eth0 
```

## Identify a network card:
Look at the device under /sys/net/...
`carrier` shows whether or not a link is connected (1) or not (0)

## Network monitoring bridge:
```
## With a bridge, both interfaces have the same IP, and the server is a man-in-the-middle.
## Interface config:
 #/etc/sysconfig/network-scripts/ifcfg-br0
  DEVICE=br0
  TYPE=Bridge
  BOOTPROTO=dhcp
  ONBOOT=yes
 #/etc/sysconfig/network-scripts/ifcfg-eth0
  DEVICE=eth0
  TYPE=Ethernet
  BRIDGE=br0
  ONBOOT=yes
 #/etc/sysconfig/network-scripts/ifcfg-eth1
  DEVICE=eth1
  TYPE=Ethernet
  BRIDGE=br0
  ONBOOT=yes

## Once you have a bridge set up, use tcpdump to capture traffic.
## This should create a file of unlimited size:
tcpdump -s 0 -i br0 -w mycap.pcap
## This should rotate files for you (50 files total at 10MB each):
tcpdump -W 50 -C 10 -i br0 -w mycap.pcap
```

## Get your IP address:
```
curl checkip.amazonaws.com
```

## Get your IP address through TOR / curl over a proxy:
```
curl --socks5 localhost:9050 checkip.amazonaws.com
```

## Remove an eth:
This has to be done after each boot (it's not persistent).  Put these in /etc/rc.local.
The below example removes eth7:
```
driver="$(ethtool -i eth7 | grep '^driver:' | awk '{ print $2 }')"
bus="$(ethtool -i eth7 | grep '^bus-info:' | awk '{ print $2 }')"
echo "$bus" > /sys/module/${driver}/drivers/pci:${driver}/unbind
## OR ##
echo 1 > $(find /sys/devices -name '*eth7' | sed -e 's,/net/eth7,/remove,')
```


-------------------
# KVM

## Necessary packages:
```
yum install kvm virt-manager libvirt libvirt-python python-virtinst
```

##  Determine if the machine you're in is virtual:
```
virt-what
```

## Magic to fix virt-manager if it throws errors about nfs locks or ORBit:
```
dbus-uuidgen > /var/lib/dbus/machine-id
virt-manager
```


-------------------
# Text manipulation

##  Use diff to view files side by side, with changes noted:
```
diff --side-by-side -W 200 file1 file2 | less
diff -yW200 file1 file2 | less
```

##  Create (or append, if ">> file.txt") a file in-line with a heredoc:
NOTE: You must escape dollar signs and tick marks!
```
/bin/cat << EOF > file.txt
#This is a commented line
This is a real line
EOF
```

## Create a multi-line variable wiht a heredoc:
NOTE: You must escape dollar signs and tick marks!
```
read -r -d '' VAR << EOF
This is line 1.
This is line 2.
This is line 3.
EOF
# Call with:
echo "$VAR"
```

## Use tail to show you everything after a certain line (inclusive):
```
tail -n +${NUM} file.txt
```

## Take a colummn and turn it into a delimited string
This can be done with awk output or a multiline variable:
```
awk '{print $1}' file.txt | paste -d\, -s
```

## uniq
- In order for uniq to work, stuff must be sorted first.
- `uniq -u` will give you ONLY the unique lines (ones that are NOT duplicate).  

## tr
Compress all consecutive horizontal spaces into a single space.
Without the -s, consecutive blanks will not be consolidated.
```
cat file.txt | tr -s [:blank:] ' ' 
```
Delete characters with tr. Example: delete all hash marks:
```
cat file.txt | tr -d \#
```

## Format text into a certain width without breaking words across lines:
```
cat file.txt | fold -s -w ${WIDTH}
```

## Take multiline output and turn it into a delimited single line:
```
cat file.txt | paste -sd? -
```
... where `?` is the delimiter you want to separate the values with.

## Take multiline output and align columns to widest element:
```
column -t file.txt
```


-------------------
# SSH / X11 / vnc

## List SSH sessions:
```
w
```

## File locations:
Client:  /etc/ssh/ssh_config
Server:  /etc/ssh/sshd_config

## Speed up SSH login:
Add the following to /etc/ssh/sshd_config:
```
UseDNS no
GSSAPIAuthentication no
```

## Copy key to a new host
```
ssh-copy-id hostname
echo "LogLevel QUIET" >> ~/.ssh/config
```

## Disable hostkey checking
Add the following to:  ~/.ssh/config
1) Automatically adds host key if it isn't there already
2) Will continue to warn if key exists
```
StrictHostKeyChecking no
```

## Resolve known_hosts conflicts
```
ssh-keygen -R $HOSTNAME
```

## Generate id_rsa.pub from id_rsa:
```
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub
```

## Getting graphical stuff to work:
```
yum install xorg-x11-apps xorg-x11-xauth xorg-x11-fonts-*
#Full blown desktop:
yum install gdm
#... then set up X11 forwarding in sshd_config and in your PuTTY session.
```

## Resolving magic cookie issues (xauth tunnelling):
```
Server> su – root
Server> xauth list
10-111-11-11/unix:10 MIT-MAGIC-COOKIE-1 cf4967d5a6c0e6d5f33285aa0e483643
Server> su – oracle
Server> xauth add 10-111-11-11/unix:10 MIT-MAGIC-COOKIE-1 cf4967d5a6c0e6d5f33285aa0e483643
```

## Create an SSH tunnel using putty:
```
putty -ssh -L 8443:localhost:8443 account@destination
```

## Create an SSH tunnel using ssh (Local port forwarding):

Situation:
- Host B is inside a firewall.
- You want to access a service on host B from host A.
- Host A can SSH to host B, but host B cannot SSH to host A.

This example maps port 16379 on host A to 6379 on host B:
```
# On host A:
ssh -fN -L 16379:localhost:6379 $HOST_B 
```

## Tunnel from the inside out (Remote port forwarding):

Situation:
- Host B is inside a firewall.
- You want to expose a service on host B to host A.
- Host B can SSH to host A, but host A cannot SSH to host B.

This example maps port 80 on host B to port 50001 on host A:
```
# On host B:
ssh -fN -R 50001:localhost:80 $HOST_A
```

## Reverse DynamicForwarding:

Situation:
- Host A has access to the internet but B doesn't.
- Host A can SSH to host B, but host B can't SSH to host A.

If B *could* SSH to A, you could just use the following from host B:
`ssh -D localhost:12345 $HOST_A`
... which would set up a socks proxy from B to A.

Here is how you can expose A's SSH to B, then use B to connect to A's SSH to proxy. 
Note: this requires AllowTcpForwarding to be enabled on both hosts.
```
# On host A:
ssh -fN -R 56789:localhost:22 $HOST_B
# On host B (log in with A's credentials):
ssh -fN -D localhost:12345 localhost -p 56789
```
The end result is that B now has A's proxy on B's localhost:12345.

## Multiplexing an SSH connection with cm_socket:
Put this in your ~/.ssh/config:
```
Host ${HOSTNAME}
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlMaster auto
  ControlPersist 10m
```
When you SSH, a session is set up once (under ~/.ssh/cm-%r@%h:%p).
All future connections to ${HOSTNAME} will use that SSH connection.
This would be good for things like Ansible where many discrete SSH commands are performed.
ControlPersist dictates how long the tunnel should remain open if left idle.
Host list could also be:  *


## Tunneling through a proxy using ProxyCommand:
```
Host bastion
  Hostname server.example.com		    # Is this needed?
  ForwardAgent yes			    # Is this needed?
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlMaster auto
  ControlPersist 10m

Host 192.168.*
  ProxyCommand ssh user@bastion -W %h:%p    # Is -W needed?
```
Whenever you SSH to anything in the 192.168.* range, ProxyCommand is run to attach to the bastion.
The bastion in this example is using a multiplexed connection.

Good resource for multiplexing:
https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing

NOTE: PuTTY cannot make use of multiplexing on its own (plink is required).  If that is desired, see setup here:
https://stackoverflow.com/questions/28926612/putty-configuration-equivalent-to-openssh-proxycommand

## Ensure that an SSH connection stays up:
Invoke with autossh. Example:
```
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -L 5000:localhost:3306 user@somehost
```
Without the monitoring port specified (-M 0), autossh will only restart the SSH connection if it dies, but not if it hangs.
Turning it off and specifying the other two ServerAlive parameters is an alternative.
The example above sets up local port forwarding such that localhost:5000 exposes remote host 3306. 

## Get a list of sessions from Putty, and create a batch file that will open all of them:
```
grep Sessions putty_backup.reg | cut -f6 -d \\ | sed -e 's/\%20/\ /g' | tr \] \ | grep -v ^$ | while read SESSION
do
  echo "start \"\" putty.exe -load \"${SESSION}\""
done
```

## Remote admin of systems with PermitRootLogin is disabled, but you have a user account with sudo:
```
# visudo changes:
  #Defaults    requiretty
  %groupname    ALL=(ALL)       NOPASSWD:ALL
# Run a remote command as root using another (sudo-capable) remote account:
  ssh -t ${USER}@${HOST} 'sudo ${COMMAND}''
```

## Run rsync as root using another (sudo-capable) remote account:
```
#rsync -av --delete --rsync-path="sudo /usr/bin/rsync" SOURCE ACCOUNT@${HOST}:/DESTINATION
rsync -av --delete --rsync-path="sudo /usr/bin/rsync" /etc/hosts mdhavale@${HOST}:/etc
```

## Updating a line in /etc/shadow from another host:
```
ssh $HOST "echo 'user:\$6\$salt\$hash:num:num:num:num:num::' >> /etc/shadow"
```

## Run X apps while SSHed from one host to another:
```
# EX:
# A SSHs to B, B SSHs to C, execute X apps on C and have them render on A. 
1) On A, do local port forwarding to C: 
   A#  ssh -L [localPort]:C:22 B
   (PuTTY: add this locally forwarded port. C's address is relative to B (could be non routeable)).
2) On A (in a separate shell), connect to C through the local port:
   A#  ssh -X -p [localPort] localhost
   (PuTTY: create a new session to localhost at [localport], then login with C's credentials)
3) Through that window, run x apps:
   C#  xclock
### In order for this to work:
# - All hosts must have X11Forwarding and AllowTcpForwarding set to yes.
# - The middle host (B) must have GatewayPorts set to yes.
```

## Kill SSH sessions older than 2 days regardless of activity:
```
find /proc/*/cmdline -mtime +2 -exec grep -il pts {} \; | cut -f3 -d\/ | xargs kill 
```

## Encrypt a file using a SSH key:
```
# Create a public key from the SSH key:
openssl rsa -in ~/.ssh/id_rsa -out id_rsa.pub.key -outform pem -pubout
# All other steps are the same, just specify ~/.ssh/id_rsa as the -inkey. 
```

## Using tmux:
- Create a new session:
```
tmux [-n $SESSION_NAME]
```
- Detach from a session:  Ctrl+B, then d
- List sessions:
```
tmux ls
```
- Attach to a session:
```
tmux a $SESSION_NUMBER
```
Alternatively, if just a single session:
```
tmux a
```
- Create a pane:  Ctrl+B, then % to split vertically, or " to split horizontally. 
- Switch panes:   Ctrl+B, then an arrow key.
- Kill a pane:  Ctrl+B, then x
Alternatively: Ctrl+B, then :, then type:  `kill-pane`


## Using screen to share SSH sessions
```
# Note:  the screen utility must have suid!
chmod u+s /usr/bin/screen
chmod 755 /var/run/screen
## Set up sharing:
screen -S NewSession
ctrl-a
:multiuser on
ctrl-a
acladd USERACCOUNT   # where USERACCOUNT is the username of the person who will join the session
## Joining shared session (as USERACCOUNT):
screen -x root/NewSession
```

## VNC setup:
```
chkconfig iptables off
service iptables stop
yum -y install tigervnc-server xrdp
yum -y groupinstall "Desktop" "Desktop Platform"
/root/vncconfig.sh  # https://access.redhat.com/labs/vncconfig/
chkconfig vncserver on
service vncserver start
chkconfig xrdp on
service xrdp start
# In SSH, disable terminal beep
```

## VNC setup (multiuser, RH7)
Adapted from https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-tigervnc
```
yum groupinstall "Server with GUI"
yum install gdm tigervnc tigervnc-server xorg-x11-apps
systemctl enable xinetd.service
systemctl set-default graphical.target

vi /etc/gdm/custom.conf:
[xdmcp]
Enable=true

vi /etc/xinetd.d/xvncserver:
service xvncserver
{
  disable = no
  protocol = tcp
  socket_type = stream
  wait = no
  user = nobody
  server = /usr/bin/Xvnc
  server_args = -inetd -query localhost -once securitytypes=none -localhost -Log *:syslog:100
}
# Note: the server_args line is taken from the DMZ (known working). RH docs suggest:
server_args = -inetd -query localhost -once -geometry selected_geometry -depth selected_depth securitytypes=none

vi /etc/services:
xvncserver      5950/tcp                # Xvnc server

vi /root/.bashrc:
alias startvnc='xauth add $(xauth -f /home/${SUDO_USER}/.Xauthority list|tail -1);vncviewer localhost:5950'

# Source .bashrc:
. ~/.bashrc

# Reload graphical:
init 3
init 5

# Ensure UDP port 177 is listening:
netstat -anu|grep 177

# Restart xinetd:
systemctl restart xinetd.service

# Test with:
xclock

# Invoke desktop with:
startvnc
```


-------------------
# Files and directories:

## Using mkdir to create multiple directories at once:
```
mkdir path/{subdir1,subdir2,subdir3}
```

## Getting just the filename with xargs:
```
ls -1 $PATH | xargs -n1 basename
```

## Robocopy example:
```
robocopy "\\x7022499\VMs\rhel7-hardened-safe-server-10282019" C:\Users\AC43487\Documents /TBD /V /S /E /DCOPY:DA /COPY:DAT /Z /MT:16 /R:5 /W:5
```
/TBD	System will wait for share names to be defined
/V	Verbose output
/S /E	Traverse subdirectories and include empty directories
/DCOPY	Directory permissions to copy. DA: data, attributes
/COPY	File permissins to copy. DAT: data, attributes, timestamps
/Z	Copy files in restartable mode.
/MT	Number of threads.  Defaults to 8.
/R	Number of times to retry a file.
/W	Number of seconds to wait between retries. 


-------------------
# sed examples

## Drop everything, up to the first "/"" in the line (useful for parsing out paths/files in configuration files)
```
sed -e 's/^[^\/]*//'  
      # Start at the beginning:  ^stuff
      # Match everything that's not a slash...:  [^\/]
      # ...and multiple instances of that:  [stuff]*
      # and then delete it: s/stuff//
```

## strip DOS endlines from a file:
```
sed -i 's/\r//g' name_of_file_to_strip
```

## Print lines 25 through 28 using sed:
```
cat file.txt | sed -n '25,28p;29q'
```

## Have sed act on a certain line or lines:
The following will act ONLY on line 40:
```
cat file.txt | sed -e '40s/bad/good/'
```
You can also do a comma-delimited range.  Regex is also valid! 
The following starts at line 40 and ends at the end of the file:
```
cat file.txt | sed -e '40,$s/bad/good/g'
```

##  Replace multiple things for lines that match a particular pattern
Example:
  - For lines that begin with PASS
  - Replace 99999 with 60, and 5 with 14
  - create a backup of the file named (original name).bak
```
/bin/sed -i.bak '{/^PASS_/ {N; s/99999/60/; s/5/14/ }}' /etc/login.defs
```

##  Replace a single item in a single line that matches a pattern
```
/bin/sed -i '/^PASS_MIN_AGE/ {s/[0-9]/7/ }' /etc/login.defs
```

##  Append something to the end of a line:
```
/bin/sed -i "/^data/ s/$/,${USER}/" file
```

## Skip everything up until the first instance of SOMESTRING:
```
sed -n '/SOMESTRING/,//p' file
```

## Add a line after a match:
```
sed -i '/SOMESTRING/a This is what gets added' file
```
Note that you don't need quotes for the added line. Not sure if escaping something gives you the literal \.

## Comment out lines that contain a certain string:
```
sed -i '/SOMESTRING/ s/^/\#/g' file
```

## Delete lines containing a certain string:
```
sed -i '/SOMESTRING/d' file
```

-------------------
# awk examples

## awk syntax:
Print line if:
 - 1st column has any two characters, then a 5,  AND
 - 2nd column does not equal "c"
```
awk '$1 ~ /..5/ && $2 != "c"' 
```

## Sum a column with awk:
```
awk '{sum+=$1} END {print sum}'
```

## Average a column with awk:
```
awk '{sum+=$1} END {print sum/NR}'
```

## Use awk to get rows where a column is over a specific value:
```
cut -f3 -d\: /etc/passwd | awk '$1>500'
```

## Another example:
```
/bin/awk -F ':' '$3<500 {print $1}' /etc/passwd   # gets account name ($1) where UID ($3) is less than 500
```

## Getting just the filename using awk field separator:
NOTE: FS can be more than one character!!!
```
ls -1 $PATH | awk 'BEGIN { FS = "/" } ; { print $NF }'
```


## Seeing if a particular column is null:
```
awk -F, '!length($3)' filename.txt
```

### Making sure a row meets certain criteria:
```
awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ && $4 < 1 {print $1}' /etc/shadow
```
  - `$1 !~ /^root$/`     - 1st column (delimited by `:`) is not "root"
  - `$2 !~ /^[!*]/`      - 2nd column doesn't begin with a `!` or a `*`
  - `$4 !~ < 1`          - 4th column is less than 1
  
This gives you all users whose "time between password changes" is set to zero days. 


-------------------
# find

## Getting just the filename with find:
```
find $PATH -type f -printf "%f\n"
```

## Use find to find everything with group or world writeable permissions:
```
find . \( -type f  -o -type d \) \( -perm -020 -o -perm -002 \) -exec ls -la {} \;
```

## Find everything modified between two dates
```
find . -newermt "2019-09-30 00:00:00" ! -newermt "2019-10-01 00:00:00"
```


-------------------
# Bash cheat sheet:
http://mywiki.wooledge.org/BashFAQ


-------------------
# Flow control:

##  Using a find command to properly process files/directories that have spaces:
```
find . -type f -print0 | while read -d $'\0' FILE
do
  ls -lad "$FILE"
done
```

## Bash Built-In Variables
$0   name of the script
$n   positional parameters to script/function
$$   PID of the script
$!    PID of the last command executed (and run in the background)
$?   exit status of the last command  (${PIPESTATUS} for pipelined commands)
$#   number of parameters to script/function
$@  all parameters to script/function (sees arguments as separate word)
$*    all parameters to script/function (sees arguments as single word)
# Note
$*   is rarely the right choice.
$@ handles empty parameter list and white-space within parameters correctly
$@ should usually be quoted like so "$@"

## Bash Double-bracket operators 
||      logical or (double brackets only)
&&      logical and (double brackets only)
<       string comparison (no escaping necessary within double brackets)
-lt     numerical comparison
=       string matching with globbing
==      string matching with globbing (double brackets only, see below)
=~      string matching with regular expressions (double brackets only , see below)
-n      string is non-empty        
-z      string is empty
-eq     numerical equality
-ne     numerical inequality

## Numerical comparison:
Use double parentheses instead of double brackets:
```
if (( $VAR1 >= $VAR2 ))
then
   # stuff
fi
```

## While loop on multiple lines:
```
while read LINE
do
   echo "LINE"
done < <(cat file.txt)
```

## Producing a sequence of numbers:
```
for i in {1..99}; do
```
This is a lot easier than using `seq`.  It even allows leading zeros:
```
for i in {001..999}; do
```


-------------------
# grep

## When using grep twice sequentially after a streaming command like tcpdump/tail:
```
tail -F logfile.log | grep --line-buffered $SOMETEXT | grep $SOMEOTHERTEXT
```

## Exclude lines that begin with # or $ (with zero to any whitespace prior to those characters):
```
grep -v '^[[:space:]]*\(\#\|\$\|$\)' file.txt
```
* Whole thing must be in sinqle quotes because of the `(option1|option2|option3)` syntax (this or this or this).
* `^[[:space:]]*` matches lines beginning with zero to any whitespace (tabs or spaces).
* `\(` starts the list of OR matches. The options are separated by `\|`.  
	 * `\#` matches lines that start with `#` (or any amount of whitespace and `#`). 
	 * `\$` matches lines that start with `$` (or any amount of whitespace and `$`). 
	 * `$` matches the end of the line (empty lines, or lines with only whitespace). 

## Same as above, but only for # comments:
```
grep -v '^[[:space:]]*\(\#\|$\)' file.txt
```

## Match any whitespace between text:
```
grep sometext[[:space:]]*someothertext file.txt
```

## Recursively search through files with grep
Essentially, a replacement for `find . -exec grep string {} \;`
```
grep -r sometext /absolutepath
```

-------------------
# yum

## Exclude a repo:
```
yum --disablerepo=${REPONAME} update
```

## Downloading packages but not installing them:
```
yum install yum-plugin-downloadonly   # allows yum to do this:
yum [re]install --downloadonly --downloaddir=. [package]
```

## Extracting the contents of an RPM (does not include spec file):
```
rpm2cpio ${RPM_FILE} | cpio -idmv 
```

## Generating a spec file from an existing RPM:
```
yum install rpmrebuild   # from EPEL
rpmrebuild --package --notest-install -e ${RPM_FILE}
```

## Listing the files that a RPM installs 
NOTE: this only displays the files contained in the RPM.  It's possible that the RPM dynamically creates files in its post-install step.  
```
rpm -qlp ${PACKAGE}.rpm
```

## Verify what package files have been changed:
```
yum -c /etc/yum.local.conf whatprovides [file]
rpm -V [Package]
```
       c %config configuration file.
       d %doc documentation file.
       g %ghost file (i.e. the file contents are not included in the package payload).
       l %license license file.
       r %readme readme file.


       S file Size differs
       M Mode differs (includes permissions and file type)
       5 digest (formerly MD5 sum) differs
       D Device major/minor number mismatch
       L readLink(2) path mismatch
       U User ownership differs
       G Group ownership differs
       T mTime differs
       P caPabilities differ

## List what packages will be updated with yum update:
```
yum check-update
```

## Get a local copy of epel:
```
wget -r -np -R "index.html*" https://archive.fedoraproject.org/pub/epel/7Server/x86_64/
```

## Reposync (https://access.redhat.com/solutions/23016)
```
reposync --gpgcheck --downloadcomps --download-metadata -d -n -l -r $REPO -p /data/repos
createrepo /data/repos/${REPO} -g comps.xml | tee -a ${0}.log
chcon -Rv --type=httpd_sys_content_t /data    # if hosting via selinux'd httpd
```

## Entry for a local repo in /etc/yum.repos.d:
```
[Local-Install]
name=Local Install
baseurl=file:///root/Desktop/CD/
enabled=1
gpgcheck=0
```

## Complete unfinished yum transactions:
```
yum-complete-transaction
# Discard transactions:
yum-complete-transaction --cleanup-only
```

## Function library used by systemd, but usable/callable by your own scripts, if desired:
```
. /etc/rc.d/init.d/functions
	success/failure: Logging functions to track any errors that may occour.
	echo_failure/echo_success: Outputs either [FAILED] or [OK] in Red or Green lettering on the right of the terminal
	pidofproc: a function to get the PID of a program when given the path to the executable
	killproc: a function to kill a program when given the path to the executable

	if [ -n "`pidofproc $PATH`" ] ; then
  	   killproc $PATH
	else
    	   failure "Stopping <service>"
	fi
```

# View output of previous yum commands:
```
yum history
```
This generates a numbered list of the sessions that yum knows about. Pick which number you want, then:
```
yum history info ${NUM}
```

# Clean up an old local repo:
```
rm $(repomanage -o /path/to/repo)
createrepo /path/to/repo
```


-------------------
# Processes/limits/monitoring

##  Count number of CPUs:
```
lscpu
```
If system is hyperthreaded, number of cores is doubled. 

##  Get average CPU utilzation:
```
sar
```

##  Get total CPU utilzation (sum of utilization of each core):
```
for i in {0..?}
do
   sar -P ${i} | grep ^Average
done | awk '{s+=$3} END {print s}'
```
... where "?" is the total number of cores (n-1)

##  List number of processes for a user:
```
ps -U [user] | wc -l
```

##  List number of open files for a user:
```
lsof | grep [user] | wc -l
```

##  List number of threads for a user:
```
ps -eLF -U [user] | wc -l
```

## grepping processes:
```
pgrep -f string
#... should be equivalent to 
ps -ef | grep string | grep -v grep
```

## Limits information is stored in:
```
/etc/security/limits.conf 
/etc/security/limits.d/90-nproc.conf
```
## Look at the output of a command, and highlight changes:
```
watch -dc "command"
```

## Look at a log file while it's spooling:
```
tail -f $FILE
```

## Figuring out what is taking up space in root file system:
```
find / -xdev -type f -size +100M
```

## View process info for all listening ports/addresses:
```
# NOTE: also contains an example of reading a whole line (setting IFS to null for just the while loop):
netstat -pant | grep LISTEN | while IFS= read LINE
do
   ADDRESS=$(echo $LINE | awk '{print $4}')
   PID=$(echo $LINE | awk '{print $NF}' | cut -f1 -d \/)
   PROCESS=$(ps -fq $PID)
   echo "====================================="
   echo "-- Listening address: ${ADDRESS}"
   echo "-- Process info:"
   echo $PROCESS
   echo 
done
```

## See what libraries an executable relies on (list dynamic dependencies): 
```
ldd $PATH_TO_EXECUTABLE
```


-------------------
# User accounts

## One-liner to create an /etc/password compliant password string:
```
python -c "import crypt, getpass, pwd; print(crypt.crypt('PASSWORDGOESHERE', '\$6\$SALTGOESHERE\$'))"
```

## Get user information:
Gives UID and all group memberships:
```
id $USER
```
Gives what /etc/passwd entry would look like:
```
getent passwd $USER
```

-------------------
# Downloading

## Download a file:
```
curl -o $FILENAME $URL
wget $URL
```

## Download page source (use -k if https):
```
curl [-k] $URL
```

## Download just the headers:
```
curl -I $URL
```

## Use a socks5 proxy:
```
curl --socks5 localhost:9050 checkip.amazonaws.com
```

## Follow redirects:
```
curl -L $URL
```


-------------------
# Encoding

## uuencoding a binary file into ascii text:
```
base64 filename.bin > filename.out
base64 -d filename.out > filename.bin
```

## A one time base64 encode/decode is:
```
echo -n 'string_to_encode' | base64
echo -n 'encoded string' | base64 -d
```

## Generate a base64 or hex string of arbitrary length (suitable for password generation):
```
openssl rand -base64 ${LENGTH}
openssl rand -hex ${LENGTH_DIVIDED_BY_TWO}
```

## Base64 encoding/decoding in Windows:
```
certutil -encode putty.txt putty.tmp && findstr /v /c:- putty.tmp > putty.txt
certutil -decode putty.txt putty.exe
```


-------------------
# Kerberos / Samba

## Test samba is working:
```
wbinfo -g (run as user; should return list of groups)
net ads testjoin (run as root)
```


-------------------
# Windows

## Forcekill a windows task:
```
taskkill /pid ${PID} /f
```

## Send mail from power shell:
```
PS> Send-MailMessage -SMTPServer ${SMTP_SERVER} -To ${DESTINATION_EMAIL} -From ${SOURCE_EMAIL} -Subject “This is a test”
```

## md5sum in windows:
```
certutil -hashfile $1 MD5
```

## grep equivalent:
```
findstr [/S] [/I] $STRING $FILES
```
... where:
`/S` searches directory and all subdirectories
`/I` is case-insensitive


-------------------
# Databases

## Oracle: Figure out what service names are registered (referenced by tnsnames.ora):
```
SQL> show parameter service_name
```

## Oracle: Disable password expiration and password reuse limitations:
```
alter profile DEFAULT limit password_reuse_max unlimited;
alter profile DEFAULT limit password_reuse_time unlimited;
#... assuming that the user is assigned to the DEFAULT profile.  Check by running:
select username, profile from dba_users;
#... and reassigning by:
alter user [username] identified by "[password]";
```

## Postgres: Connect locally:
```
psql -h localhost -U enterprisedb -d postgres
```

## Postgres: Connect to a different database from within psql:
```
\c DATABASENAME
```
## Postgres: List (or describe) tables:
```
\d [table_name]
```

## Postgres: Run a script from within psql:
```
\i /path/to/file.sql
```

## Postgres: Create a role:
```
create role "${ROLENAME}" LOGIN ENCRYPTED PASSWORD 'password1234' NOREPLICATION;
```

## Postgres: Show roles:
```
SELECT rolname FROM pg_roles;
```


-------------------
# Certificates

## Create a hash symlink for a CA:
```
ln -s $CA_FILE $(openssl x509 -hash -noout -in $CA_FILE).0
```

## Get the SHA1 fingerprint of a cert:
```
openssl x509 -noout -fingerprint -sha1 -in $CERTNAME
```

## Extract certs from a p7 file:
```
openssl pkcs7 -in Certificates_PKCS7_v4.1u2_DoD.pem.p7b -print_certs -out DoD_CAs.crt
```

## List contents of JKS file:
```
keytool -list -keystore file.jks
```

## List contents of P12 file (including trusted certs, which aren't displayed by default like they are with a JKS):
```
keytool -list -keystore file.p12 -storetype pkcs12 -deststorepass p12_password -v | grep -e ^Owner -e ^Issuer
```

## Add cert to a JKS file:
```
keytool -import -v -alias CA_NAME -file CA_NAME.crt -keystore keystore.jks -storetype JKS -storepass jks_password
```

## Delete entry from JKS:
```
keytool -delete -alias mydomain -keystore keystore.jks
```

## Notes on cert usage... most certs have this:
```
X509v3 Key Usage: critical
       Digital Signature, Key Encipherment
X509v3 Extended Key Usage:
       TLS Web Server Authentication , TLS Web Client Authentication
```
In openssl.cnf, this would be configured as:
```
keyUsage = critical, digitalSignature , keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
```

## Block to create a self-signed cert and put it into a P12 and JKS:
```
# Create key and self-signed cert:
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj "/C=US/ST=VA/O=ORG/CN=$(hostname)" -reqexts EXTRA -extensions EXTRA -config <(cat /etc/pki/tls/openssl.cnf ; printf '[ EXTRA ]\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment\nextendedKeyUsage = critical, serverAuth, clientAuth\n') -keyout $(hostname).key -out $(hostname).crt
# Note: if so desired, you could specify the same destination for both the key and the cert, and it'd put it in one file.  FWIW.
# Create intermediate P12:
openssl pkcs12 -export -in $(hostname).crt -inkey $(hostname).key -certfile $(hostname).crt -name $(hostname) -out $(hostname).p12 -passout pass:changeit
# Verify contents:
keytool -list -keystore $(hostname).p12 -storetype pkcs12 -deststorepass changeit
# Create JKS:
keytool -importkeystore -srckeystore $(hostname).p12 -srcstoretype pkcs12 -destkeystore $(hostname).jks -deststoretype JKS -srcstorepass changeit -deststorepass changeit
# Import the same cert as CA cert:
keytool -import -v -alias $(hostname)_ca -file $(hostname).crt -keystore $(hostname).jks -storetype JKS -deststorepass changeit -srcstorepass changeit -noprompt
# Verify contents:
keytool -list -keystore $(hostname).jks -deststorepass changeit
```

## Create JKS file with a self-signed cert and key already in it:
```
keytool -genkey -keyalg RSA -alias selfsigned -dname "C=US, ST=VA, O=ORG, CN=$(hostname)" -keystore keystore.jks -storepass password -validity 360 -keysize 2048
```

## Validate a connection:
```
openssl s_client -connect 10.67.131.246:443 -verify 9 -showcerts -CAfile /etc/pki/tls/certs/DTE_CA.crt -cert /etc/pki/tls/certs/localhost.crt -key /etc/pki/tls/private/localhost.key 1>/dev/null
```

## Export cert from a JKS file:
```
keytool -exportcert -alias ALIAS -file OUTPUT.crt -rfc -keystore KEYSTORE.jks
keytool -exportcert -alias racdbkey -file cartesian.crt -rfc -keystore owfRACDBtrust.jks
```

## See what certificate a server presents upon connection:
```
echo | openssl s_client -showcerts -connect localhost:8443  < /dev/null | openssl x509
openssl s_client -showcerts -connect localhost:8443 </dev/null
```

## List contents of certificate:
```
openssl x509 -text -noout -in file.crt
```

## List contents of a key:
```
openssl rsa -text -noout -in file.key
```

## Subject alternative names (SANs) using openssl
```
# Create key:
openssl genrsa -aes128 -out ${HOST}.key 2048
# Gen csr (all one command):
openssl req -new -key ./private/${HOST}.key -subj \
"/C=US/ST=VA/O=DHS/CN=${HOST}/emailAddress=root@localhost" -reqexts SAN \
-config <(cat /root/projectname/certs/openssl.cnf <(printf "[SAN]\nsubjectAltName=IP:$(grep ${HOST} /etc/hosts | awk '{print $1}')")) \
-out ${HOST}.csr
# Gen crt (all one command).  If needed, use -cert and -keyfile to specify the CA.
openssl ca -policy policy_anything -extensions SAN \
-in ${HOST}.csr -config <(cat /root/projectname/certs/openssl.cnf \
 <(printf "[SAN]\nbasicConstraints = CA:FALSE\nnsComment=OpenSSL_Generated_Certificate\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=IP:$(grep ${HOST} /etc/hosts | awk '{print $1}')")) -out ${HOST}.crt
```

## Encrypt a file using a server's key:
```
#Create a public key from the server key:
openssl rsa -in server.key -out server.pub.key -outform pem -pubout
#Encrypt a file using the server key:
openssl rsautl -encrypt -pubin -inkey server.pub.key -in file.txt -out file.txt.enc
#Decrypt the file using the server key:
openssl rsautl -decrypt -inkey server.key -in file.txt.enc -out file.txt
```

## Make sure your cert matches your key:
```
diff <(openssl x509 -noout -modulus -in /etc/pki/tls/certs/localhost.crt | openssl md5) \
<(openssl rsa -noout -modulus -in /etc/pki/tls/private/localhost.key | openssl md5) && echo 'Cert and key match!'
#Alternate method (shorter):
diff <(openssl x509 -modulus -noout -in /etc/pki/tls/certs/localhost.crt) <(openssl rsa -modulus -noout -in /etc/pki/tls/private/localhost.key)
```

## Make sure your cert CN matches your hostname:
```
diff <(hostname) <(openssl x509 -noout -text -in /etc/pki/tls/certs/localhost.crt | grep Subject | head -n 1 | cut -f7 -d\=)
```

## Connect to a server manually with openssl, offering your local cert and key:
```
openssl s_client -connect hostname:443 -cert certs/localhost.crt -key private/localhost.key  [-CAfile certs/CA.crt]
```

## Check what ciphers are supported by OpenSSL
```
openssl ciphers -V ALL | grep -v SSLv
```

## Map openssl ciphers to Java ciphers:
```
https://testssl.sh/openssl-iana.mapping.html
```

## Suggestions for strong ciphers:
The A list of:
```
https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
```

## Have openssl listen for a server connection, and verify client:
```
openssl s_server -accept 443 -verify 2 -cert certs/localhost.crt -key private/localhost.key -CAfile certs/CA.crt
```

## Remove a password from a key file:
```
openssl rsa -in server.key.pass -out server.key.nopass
```

## Create p12 file, import into JKS, and verify contents:
```
openssl pkcs12 -export -in ./certs/$(hostname).crt -inkey ./private/$(hostname).key -certfile ./certs/ORG_CA.crt -name $(hostname) -out ./private/$(hostname).p12
keytool -list -keystore ./private/$(hostname).p12 -storetype pkcs12
keytool -importkeystore -srckeystore ./private/$(hostname).p12 -srcstoretype pkcs12 -destkeystore ./private/$(hostname).jks -deststoretype JKS
keytool -list -keystore ./private/$(hostname).jks
```

## Make sure a cert is validated by its CA:
```
openssl verify -verbose -CAfile CA.crt  server.crt
```
This is what it looks like when the immediate cert is validated, but the complete chain is missing:
```
#  - error 2 at 1 depth lookup:unable to get issuer certificate
```
This is what it looks like when the cert is NOT validated:
```
#  - error 20 at 0 depth lookup:unable to get local issuer certificate
```
This is what it looks like if you have the entire necessary chain (i.e., you've catted all necessary certs into CA.crt):
```
#  - $CERTNAME: OK
```

## Extract server's private key from the P12 file.  You will need the password of the P12 file.
```
openssl pkcs12 -in hostname.p12 -nocerts -nodes -out hostname.key
```

## Extract server's certificate (public key) from the P12 file.   You will need the password of the P12 file.
```
openssl pkcs12 -in hostname.p12 -clcerts -nokeys -out hostname.crt
```

## Extract CA certificates from the P12 file.  You will need the password of the P12 file. 
```
openssl pkcs12 -in hostname.p12 -cacerts -nokeys -chain -out ca_certs.crt
```

## Verify cert hashing algorithm (should be SHA2 or SHA256).
```
openssl x509 -text -noout -in hostname.crt | grep "Signature Algorithm"
```

## Verify RSA key strength (should be at least 2048 bits).
```
openssl rsa -text -noout -in hostname.key | grep "Private-Key"
```
This can also be determined from the cert:
```
openssl x509 -text -noout -in hostname.crt | grep "Public-Key"
```

## Change password of keystore:
```
keytool -storepasswd -new [new password] -keystore [path to key store]
```

## Change password of private key within a keystore:
```
keytool -keypasswd -alias [Alias name for private key] -keystore [path to key store]
```

## View contents of jceks:
```
keytool -list –keystore [path to keystore] –storetype jceks –list -v
```

##  Automated generation of certs, assuming you have the CA set up properly.  Run in the top level of the CA folder. Reads from a file of common names.
```
#!/bin/bash
# The CA file is assumed to be in ./certs:
CA_FILE=PROJECTNAME_CA_combined.crt
if [[ -z "$1" ]]
then
  echo "Usage:  $0 file_name"
  echo " ... where file_name contains a list of common names (without spaces):"
  echo "         EX:  Alpha"
  echo "              Beta"
  echo "              Gamma"
  echo "              ..."
  exit
fi
NAME=$1
while read LINE
do
# Generate key
openssl genrsa -aes128 -out ./private/${LINE}.key -passout pass:changeit 2048
# Remove password from key
mv ./private/${LINE}.key ./private/${LINE}.key.pass
openssl rsa -in ./private/${LINE}.key.pass -passin pass:changeit -out ./private/${LINE}.key.nopass
# Create CSR
openssl req -new -subj "/C=US/ST=VA/O=DHS/CN=${LINE}" -key ./private/${LINE}.key.nopass -out ./certs/${LINE}.csr
# Sign CSR
openssl ca -batch -in ./certs/${LINE}.csr -out ./certs/${LINE}.crt -config openssl.cnf -passin pass:changeit
# Make P12 file
openssl pkcs12 -export -inkey ./private/${LINE}.key.nopass -in ./certs/${LINE}.crt -certfile ./certs/${CA_FILE} -name "${LINE}" -out ./private/${LINE}.p12 -passout pass:changeit
# Make JKS file
keytool -importkeystore -srckeystore ./private/${LINE}.p12 -srcstoretype pkcs12 -srcstorepass changeit -destkeystore ./private/${LINE}.jks -deststoretype JKS -deststorepass changeit
keytool -noprompt -import -alias $(basename ${CA_FILE} .crt) -file ./certs/${CA_FILE} -keystore ./private/${LINE}.jks -storetype JKS -storepass changeit
echo
done < $1
```

## Create blank CRL:
```
cd /etc/pki/tls/PROJECTNAME_CA
echo 01 > crlnumber
openssl ca -config ../openssl.cnf -gencrl -keyfile ./private/PROJECTNAME_CA.key -cert ./certs/PROJECTNAME_CA.crt -out PROJECTNAME_CA.crl.pem
openssl crl -inform PEM -in PROJECTNAME_CA.crl.pem -outform DER -out PROJECTNAME_CA.crl
```

## Revoke a server cert:
```
cd /etc/pki/tls/PROJECTNAME_CA
openssl ca -config ../openssl.cnf -revoke ./certs/[SERVER_CERT] -keyfile ./private/PROJECTNAME_CA.key -cert ./certs/PROJECTNAME_CA.crt
openssl ca -config ../openssl.cnf -gencrl -keyfile ./private/PROJECTNAME_CA.key -cert ./certs/PROJECTNAME_CA.crt -out PROJECTNAME_CA.crl.pem
openssl crl -inform PEM -in PROJECTNAME_CA.crl.pem -outform DER -out PROJECTNAME_CA.crl
```

## List contents of crl:
```
for CERT in $(openssl crl -text -noout -in PROJECTNAME_CA.crl.pem | grep Serial | awk '{print $NF}')
do
  openssl x509 -text -noout -in ./newcerts/${CERT}.pem | grep Subject | grep CN
done
```

## Verify that a CRL belongs to a CA:
```
openssl crl -in DHS_CA.crl -inform der -CAfile DHS-CA3.crt -noout
```


-------------------
# NSS

## Set up NSS database:
```
# Create p12 file
openssl pkcs12 -export -inkey $(hostname).key -in ../certs/$(hostname).crt -name $(hostname) -out $(hostname).p12
service httpd stop
# Create NSS database
cd /etc/httpd/alias
certutil -N -d /etc/httpd/alias
modutil -fips true -dbdir /etc/httpd/alias
pk12util -d /etc/httpd/alias -i /etc/pki/tls/private/$(hostname).p12
certutil -d /etc/httpd/alias -A -t "CT,," -n PROJECTNAME_ROOT_CA -i /etc/pki/tls/certs/PROJECTNAME_ROOT_CA.crt
certutil -d /etc/httpd/alias -A -t "CT,," -n PROJECTNAME_CA -i /etc/pki/tls/certs/PROJECTNAME_CA.crt
certutil -d /etc/httpd/alias -A -t "CT,," -n "DC3 Root CA 1" -i /etc/pki/tls/certs/dc3-root-ca.crt
certutil -d /etc/httpd/alias -A -t "CT,," -n "DC3 CA-2" -i /etc/pki/tls/certs/dc3-ca.crt
certutil -d /etc/httpd/alias -A -t "CT,," -n "DoD JITC Root CA 2" -i /etc/pki/tls/certs/DODJITC-root-ca.crt
certutil -d /etc/httpd/alias -A -t "CT,," -n "DOD JITC CA-27" -i /etc/pki/tls/certs/DODJITC-ca.crt
certutil -d /etc/httpd/alias -L
service httpd start
```

## Delete a certificate
```
certutil -d /etc/httpd/alias -D -n ${FQDN} -f /etc/pki/nssdb/token
```

## Delete all CRLs:
```
crlutil -E -d /etc/httpd/alias
```

## Delete a single CRL:
```
crlutil -D -d /etc/httpd/alias -n NAME_OF_CRT -f /etc/pki/nssdb/token
```

## Add CRLs (note: you need the corresponding CA already in NSS):
```
crlutil -I -d /etc/httpd/alias -i /etc/pki/tls/certs/CRLs/DODCA_27.crl -f /etc/pki/nssdb/token
```

## View CRLs:
```
crlutil -L -d /etc/httpd/alias -f /etc/pki/nssdb/token
```


-------------------
# NFS

## Set up an NFS mount:
```
mkdir -p /rpms
yum -y install nfs-utils
## -- /etc/fstab:
	nfs:/rpms       /rpms           nfs     rsize=8192,wsize=8192,timeo=14,intr 0 0
## -- /etc/hosts:
	10.23.218.193 nfs.unobtanium.us-cert.gov      nfs
## -- /etc/syconfig/iptables:
	#-----------------------------NFS
	-A OUTPUT -p tcp -m tcp --dport 2049 -j ACCEPT
```

## List shares on a server:
```
showmount -e $HOST
```


-------------------
# Python

## Compile py files into pyc and pyo:
```
python -c "import py_compile; py_compile.compile(file=\"${FILE}\", doraise=True)"
python -O -c "import py_compile; py_compile.compile(file=\"${FILE}\", doraise=True)"
```

## Using pip to download packages without installing:
```
# install pip:
yum install python-pip
pip install packagename --download="/path/to/save"
# EX: 
# pip install zope.interface --download="/root/py_pkgs"
```
Note: the dependencies will be zip files, but they will have random URLs as their extensions.
Setup is usually:  python ./setup.py install
Note:  setup may require installation of python-devel package!
See what you've already got installed with:  pip list


-------------------
# selinux

## Get detailed output:
```
yum install setroubleshoot
```
... then in /var/log/messages, grep for sealert
Great resource:  http://wiki.centos.org/HowTos/SELinux

## Adding an selinux module
```
grep SOMETHING /var/log/audit/audit.log | audit2allow -M SOMETHING
#EX: grep httpd.worker /var/log/audit/audit.log | audit2allow -M httpd_worker
#    ... creates httpd_worker.pp and httpd_worker.te.  The *.pp file is the compiled binary.  The *.te file is the source.
# Add that module:
semodule -i SOMETHING.pp
# Remove a module:
semodule -r SOMETHING.pp
# Check module presence with:
semodule -l | grep SOMETHING
# If you want to fix something in the .te file, edit it, then create a mod file that can be turned into a new pp file:
checkmodule -M -m -o SOMETHING.mod SOMETHING.te
semodule_package -o SOMETHING.pp -m SOMETHING.mod
semodule -i SOMETHING.pp 
```

## Gotchas:

- Logrotate can only normally only operate in /var directories.  If you want to logrotate files outside of that (such as mailboxes), you might as well just disable it:
```
semanage permissive -a logrotate_t
```

-------------------
# Systemd

## Installing a daemon as a service
Example:
```
# vi cloudscan.service:

[Unit]
Description=Establish Fortify Cloudscan connection from Sensor to Cloud Controller
After=default.target

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
ExecStart=/opt/Fortify/Fortify_SCA_and_Apps_18.10/bin/cloudscan -url http://192.168.0.249:8080/cloud-ctrl worker

[Install]
WantedBy=default.target

cp cloudscan.service /etc/systemd/system
chmod 755 /etc/systemd/system/cloudscan.service
chown root:root /etc/systemd/system/cloudscan.service
systemctl daemon-reload
systemctl enable cloudscan
```

## Installing a one-shot command as a service
Example:
```
# vi after-boot.service:

[Unit]
Description=Last service to run after booting for adhoc commands
After=default.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/after-boot

[Install]
WantedBy=default.target


cp after-boot.service /etc/systemd/system
chmod 755 /etc/systemd/system/after-boot.service
chown root:root /etc/systemd/system/after-boot.service
systemctl daemon-reload
systemctl enable after-boot
cp after-boot /usr/local/sbin
chmod 700 /usr/local/sbin/after-boot
chown root:root /usr/local/sbin/after-boot 
```


-------------------
# Disks / file systems

## Mount a UNC path:
```
mount -t drvfs '\\server\share' /mnt/share
```

## Reclaim 5% admin space on ext4 file systems:
```
tune2fs -m 0 /path/to/lvol
```

## Create a logical volume using all available space:
```
lvcreate -n $LV_NAME -l 100%FREE $VG_NAME
```

## Creating a new volume group and logical volume (RH7):
```
# Create PV
pvcreate /dev/sdb
# Create VG
vgcreate vg_data /dev/sdb
# Create LV
lvcreate -n lv_data -l 100%FREE vg_data
# Create FS
mkfs.xfs /dev/vg_data/lv_data
# Set up mount:
mkdir -p /data
mount /dev/vg_data/lv_data /data
echo '/dev/mapper/vg_data-lv_data /data xfs defaults 0 0' >> /etc/fstab
mount -a
```

## Creating a new logical volume on an encrypted system:
```
# lvcreate -L 5G -n lv_data vg_root
# cat /etc/crypttab
  Do this to see where the password file is, and what the password is.  Make note of both.
# cryptsetup luksFormat /dev/vg_root/lv_data
  When prompted, enter the password. 
# blkid /dev/vg_root/lv_data
  Make note of the UUID.
# cryptsetup luksOpen /dev/vg_root/lv_data luks-414d9009-2ab4-4a0c-9bc7-a421ab50e20c
  When prompted, enter the password.
# mkfs.ext4 /dev/mapper/luks-414d9009-2ab4-4a0c-9bc7-a421ab50e20c
# vi /etc/crypttab
  Add the following line:
  luks-414d9009-2ab4-4a0c-9bc7-a421ab50e20c UUID=414d9009-2ab4-4a0c-9bc7-a421ab50e20c /etc/lukspw.txt
# cryptsetup luksAddKey /dev/vg_root/lv_data /etc/lukspw.txt
  When prompted, enter the password.
# vi /etc/fstab
  Add the following line:
  /dev/mapper/luks-414d9009-2ab4-4a0c-9bc7-a421ab50e20c /data ext4 defaults 1 2
# mkdir /data
# mount /data
```

## Increase logical volume size and resize file system simultaneously
```
lvextend -r -L ${GB_SIZE}G /dev/mapper/${LV_NAME}

#EX:
lvextend -r -L 60G /dev/mapper/vg_bilsvruv-lv_var
```

## Extend file system
```
# Specific number of extents:
lvextend -l [TOTAL LE DESIRED] /path/to/lv

# All free extents:
lvextend -l 100%FREE /path/to/lv

# RHEL6:
resize2fs /path/to/lv

# RHEL7:
xfs_growfs /mountpoint
```


-------------------
# git

## Start/stop gitlab services:
```
gitlab-ctl restart
# Alternative, less recommended method:  initctl stop gitlab-runsvdir
```

## Starting/stopping individual gitlab components:
```
gitlab-ctl restart COMPONENT_NAME
gitlab-ctl status COMPONENT_NAME
gitlab-ctl list COMPONENT_NAME
```

## Built-in help
```
git help [feature]
```

## See what's going on with your current project (must be in project directory):
```
git status
```

## Show the commit history for the current branch:
```
git log
```

## Show a pretty view of commits and branches:
```
git log --graph
```

## Git global setup
```
git config --global user.name "Firstname Lastname"
git config --global user.email "Firstname.Lastname@YourDomain"
git config --list			
# NOTE: that last command is context sensitive (knows if you are in a git-controlled directory!)
```

## Pull a repository down, make a change, and push it back up:
```
git clone [-b branch] git@${GITSERVER}:${GROUP}/${PROJECT}.git
cd ${PROJECT}
touch README.md 
git add README.md (can also add using wildcards)
git commit -a -m "add README"
git push -u origin master
```

## Take an existing folder and turn it into a git project
```
cd existing_folder
git init				# creates git folder
git add *				# adds all contents to the project.  If you modify files, run add on them again!!! 
git commit -m "initial commit"		# commits the additions
git remote add origin git@${GITSERVER}:${GROUP}/${PROJECT}.git
git push -u origin master
```

## Make sure your repository is up to date:
```
git pull
```

## view files associated with a local project:
```
git ls-files 
```

## view tags associated with a remote project:
```
git ls-remote --tags git@${GITSERVER}:${GROUP}/${PROJECT} | grep -v \}$ | cut -f3 -d\/
```

## Revert a file from a particular commit:
```
git reset COMMIT_ID PATH_TO_FILE 
git checkout COMMIT_ID PATH_TO_FILE 
```

## Revert to a specific commit:
```
git reset COMMIT_ID 
git checkout COMMIT_ID
```

## Revert to a specific commit, then reapply only certain things that came after that commit:
```
git rebase -i COMMIT_ID		# rewrites history - make this a new branch
git branch NEW_NAME			# create a new branch so you don't screw anyone
git checkout NEW_NAME		# switch to the new branch		
git push origin  			# puts it on the server
```

## Rebase with master (i.e., you have been working on a branch that's now stale b/c someone committed to master in the interim):
```
git rebase master
```

## Other stuff
- Most thorough way to git add files: find . -type f -exec git add {} \;				
- Git will not add empty directories, so create a dummy file in each folder you want to create.
- In order for deletions to be registered, you can either specify those manually, 
  or simply run: commit -a -m "comment"
  The -a says "update everything I know about, and remove what's been deleted from the working directory".
- If you are working on a branch and master has been recommitted since then, rebase with master. 
  You should rebase with master anytime a commit to master has been made! 
- For other disaster mitigation, see: http://ohshitgit.com


-------------------
# MySQL

## Pick a database:
```
use test;
```

## Drop a user:
```
DROP USER ''@'localhost';
```

## Create a table:
```
create table testtable (textcolumn VARCHAR(20), datecolumn DATE);
```

## Add a row:
```
insert into testtable values ("Hello world!",curdate());
```

## Create a user, grant privs:
```
create user 'testuser'@'%' identified by 'Password!12345';
grant all privileges on test.* to 'testuser'@'%' with grant option;
flush privileges;
select user, host from mysql.user;
```

## Installation:
```
yum -y install mysql
```

## Connect:
```
mysql -u testuser -h ${IP} -p			
mysql -u testuser -h localhost -p	
```


-------------------
# Postfix

## Configure postfix to send mail through Gmail (requires an account):  
https://www.howtoforge.com/tutorial/configure-postfix-to-use-gmail-as-a-mail-relay/



-------------------
# Postgres

## Necessary packages:

From default repo:
postgresql.x86_64                       
postgresql-libs.x86_64                 
postgresql-server.x86_64

NOTE: some applications have very specific requirements.  Other versions are available from other repos.                

## Admin console:
```
sudo -u postgres psql
```

## List databases:
```
\l
```

## Let ops run a command as postgres:
```
# Add to /etc/sudoers.d/ops:
%unixops	ALL=(postgres)	/path/to/script

# Invoke with:
sudo -u postgres /path/to/script
```

-------------------
# User account management

## Unlock accounts:
```
passwd -u ${USER}
faillock --user ${USER} --reset
pam_tally2 --user=${USER} --reset
```

-------------------
# OSCAP

Source:
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sect-using_oscap

Install pre-reqs:
```
yum install openscap-utils scap-security-guide
```

View available scan profiles:
```
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel7-xccdf.xml
```

Scan using DISA content:
```
oscap xccdf eval [--fetch-remote-resources] --profile stig-rhel7-disa --results pre_scan.xml --report --pre_scan.html /usr/share/xml/scap/ssg/content/ssg-rhel7-xccdf.xml
```

Perform remediation in one of two ways:
1) Create shell script with SSG content:
```
oscap xccdf generate fix --template urn:xccdf:fix:script:sh --profile stig-rhel7-disa --output remediation-script.sh /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
```
2) Automatic remediation with SSG content (not recommended):
```
oscap xccdf eval --remediate --profile stig-rhel7-disa --results scan-sccdf-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
```

Re-scan with DISA content:
```
oscap xccdf eval [--fetch-remote-resources] --profile stig-rhel7-disa --results post_scan.xml --report --post_scan.html /usr/share/xml/scap/ssg/content/ssg-rhel7-xccdf.xml
```


-------------------
# Kubernetes

## Kubernetes windows installation

via:  https://www.lynda.com/Kubernetes-tutorials/Getting-up-running-Windows-install/647663/703705-4.html

Put minikube and kubectl in a folder together.  Add this folder to your PATH.  Minikube is an exe download from github, but as of this writing, kubectl had to be downloaded by scoop (https://scoop.sh).

Ensure Hyper-V is up and running.

In Hyper-V, create a virtual switch (internal) called "Minikube".  

Add this switch to your network interface (Wifi or wired).

Start up minikube. In Powershell:
```
minikube start --kubernetes-version="v1.13.0" --vm-driver="hyperv" --hyperv-virtual-switch="Minikube"
```

## Kubernetes via Google Cloud
https://cloud.google.com/kubernetes-engine/

Create cluster:
```
gcloud container clusters create myCluster
```

Grant admin permissions to current user:
```
kubectl create clusterrolebinding cluster-admin-binding \
--clusterrole=cluster-admin \
--user=$(gcloud config get-value core/account)
```

Pull an app from an existing image:
```
kubectl run myApp --image gcr.io/google-samples/hello-app:1.0
```

Scale replicas:
```
kubectl scale deployment myApp --replicas 3
```

Expose ports for the app:
```
kubectl expose deployment myApp --port 80 --type=LoadBalancer
```

Get info on service:
```
kubectl get service myApp
```

Update app with a newer version of the image:
```
kubectl set image deployment myApp app=gcr.io/google-samples/hello-app:2.0
```


-------------------
# Ansible

## Inventory files
Inventory files can be separated into groups like so:
```
[staging-webservers]
stg-web-1.example.com
stg-web-2.example.com

[production-webservers]
prod-web-1.example.com
prod-web-2.example.com

[staging-dbservers]
stg-db-1.example.com
stg-db-2.example.com

[production-dbservers]
prod-db-1.example.com
prod-db-2.example.com

# All webservers
[webservers:children]
staging-webservers
production-webservers

# All databases
[dbservers:children]
staging-dbservers
production-dbservers

# All staging
[staging:children]
staging-webservers
staging-dbservers

# All production
[production:children]
production-webservers
production-dbservers
```
That said, it's probably better to break these into their own inventory files:
- more clean from an organizational standpoint
- you don't have to use `--limit` to limit the playbook to a particular group
- use `--list-hosts` just to be sure!

Having created these groups, you can then assign individual variables to each environment by creating appropriately named files under `groupvars`:
```
groupvars/webservers
groupvars/dbservers
groupvars/staging
groupvars/production
groupvars/staging-webservers
groupvars/production-webservers
groupvars/staging-dbservers
groupvars/production-dbservers
```

You can pass per-host parameters inline.  For example, here is how you set up your inventory file so you can run ansible commands against a vagrant host:
```
192.168.33.10 ansible_user=vagrant ansible_ssh_private_key_file=.vagrant/machines/default/virtualbox/private_key
```

You can also pass custom variables inline. For example, here are two different inventories for the same host(s) that use environment-specific variables:
```
$ cat staging-inventory
alpha.example.com database_name=staging_db

$ cat production-inventory
alpha.example.com database_name=prod

$ ansible-playbook –i production-inventory playbook.yml
```

## Check if hosts are up using the ping module:
```
ansible $HOSTGROUP [-i $INVENTORY] -m ping
```

## Run a shell command on a host with the shell module:
```
ansible $HOSTGROUP [-i $INVENTORY] -m shell [-o] [-b] -a "$COMMAND"
```
- The -o option will keep output all on one line. 
- The -b option will run the command as root.

NOTE: you can use the `shell` or `command` module. Shell is preferred:
- shell gets run through a shell, and so picks up environment variables like $HOME.
- shell allows redirection, command does not.


## Get facts about hosts using the setup module:
```
ansible $HOSTGROUP [-i $INVENTORY] -m setup
```
You can use facts as a condition (e.g., figure out which OS you're one to make playbooks OS-independent):
```
- include_tasks: setup-RedHat.yml
  when: ansible_os_family == 'RedHat'
```

## Using the Package module: 
http://docs.ansible.com/ansible/package_module.html

### Install a specific version (even if out of date):
```
ansible $HOSTGROUP [-i $INVENTORY] -m package -b -a "name=${PACKAGE}-${VERSION} state=present" 
```
EX:   `ansible web [-i $INVENTORY] -m package -b -a "name=subversion-1.7.14-11.el7_4 state=present"` 

### Install packages:
Install a package on all hosts:
```
ansible $HOSTGROUP [-i $INVENTORY] -m package -b -a "name=${PACKAGE} state=latest"	
```
Note: "present" and "installed" are equivalent to each other, but will disregard version.

### Remove packages:
```
ansible $HOSTGROUP [-i $INVENTORY] -m package -b -a "name=${PACKAGE} state=absent"
```
Note: "removed" and "absent" are equivalent.

### Command that is essentially a `yum update` equivalent:
```
ansible $HOSTGROUP [-i $INVENTORY] -m package -b -a "name=* state=latest"
```

## Using the Service module to start/stop a service:
```
ansible $HOSTGROUP [-i $INVENTORY] -m service -b -a "name=${SERVICE} state=started" 
ansible $HOSTGROUP [-i $INVENTORY] -m service -b -a "name=${SERVICE} state=stopped" 
```

## Other modules:

### Check out a repo onto a node:
```
ansible $HOSTGROUP [-i $INVENTORY] -m git -a "repo=${REPO_URL} dest=${DESTINATION_FOLDER}"
```
EX: `ansible web [-i $INVENTORY] -m git -a "repo=https://github.com/jboss-developer/jboss-eap-quickstarts.git dest=/tmp/checkout"`

### Have the node test a connection to a website:
```
ansible $HOSTGROUP [-i $INVENTORY] -m uri -a "url=${URL} return_content=yes"
```

## One-liners:
Via http://www.pidramble.com/wiki/setup/test-ansible

Reboot all hosts in an inventory file:
```
ansible all [-i $INVENTORY] -m shell -a "sleep 1s; shutdown -r now" -b -B 60 -P 0
```
Get disk usage of everything in an inventory file:
```
ansible all [-i $INVENTORY] -a "df -h"
```
Get current memory usage of everything in an inventory file:
```
ansible all [-i $INVENTORY] -a "free -m"
```

## ansible vs ansible-playbook
`ansible`:
- Uses a hostgroup and an inventory file (that describes the hostgroup)
- Is used to run one single playbook task
- Mostly useful for gathering/listing facts or forcing a single change
`ansible-playbook`:
- Uses only an inventory file; the hostgroup is in the playbook being called
- Runs a whole series of tasks

## Playbooks:
Best practices:  http://docs.ansible.com/ansible/playbooks_best_practices.html

### Running a playbook:
```
ansible-playbook -i $PATH_TO_INVENTORY_FILE --private-key=${PATH_TO_PRIVATE_KEY} ${PLAYBOOK}
```
EX:  `ansible-playbook -i inventory --private-key=~/.ssh/westfields-tower stop_apache.yml`

Notes:
- Facts are gathered by default (always the first task).
- You don't have to specify the inventory file if it's in the same directory where you're running the ansible-playbook command, but you'd be dumb not to.
- You don't have to specify a private key if you are running in the home directory of the same user. 
EX:  cd ~; ansible-playbook ${PATH_TO_PLAYBOOK}

You can check playbook syntax with `--syntax-check `:
```
ansible-playbook -i inventory playbook.yml --syntax-check 
```

You can also specify `--list-tasks` and `--list-hosts` to see what tasks/hosts your playbook will affect!
```
# confirm what task names would be run if I ran this command and said "just ntp tasks"
ansible-playbook -i inventory playbook.yml --tags ntp --list-tasks

# confirm what hostnames might be communicated with if I said "limit to boston"
ansible-playbook -i inventory playbook.yml --limit boston --list-hosts
```

Running a playbook on the local host:
```
ansible-playbook –i 'localhost,'  -c 'local' playbook.yml
```

ALTERNATIVELY:  Running a downloaded playbook/role on the local host:
1) Clone the playbook/role with git. 
2) Create `local.yml` in the playbook/role directory with the following contents:
```
---
- hosts: localhost
  connection: local
  become: yes
  vars:
      is_container: false
  roles:
      - role: "{{ playbook_dir }}"
```
3) Run the following:
```
ansible-playbook local.yml
```

Pulling a playbook from git and running it locally on the host:
```
ansible-pull -U git@example.com/ansible-site.git -i 'localhost,' –c 'local' playbook.yml
```

Using ansible to create a cron does the above (reference only, don't actually do this):
```
ansible all -i inventory -m setup -a 'name="Ansible Pull" minute="*/30" job="ansible-pull -U git@example.com/ansible-site.git -i \\'localhost,\\' –c \\'local\\' playbook.yml"'
```


### Playbook structure / examples:
```
---
- hosts: ${HOSTGROUP}		# defaults to "all"
  name:  ${PLAYBOOK_NAME}
  serial: ${VALUE}		# Integer: how many hosts to do at once. Defaults to all. 
  max_fail_percent: 0		# If any host fails, abort processing.
  become: true			# Needed so everything below can run as root

  vars:
    install_packages:		# Can be anything, just has to match what's in "with_items"
      - ${VAL1}
      - ${VAL2}
    $VARNAME: ${VALUE}		# Some other variable(s)

  tasks:

    - name: Install packages
      package: name="{{ item }}" state=latest
      with_items: "{{ install_packages }}"
      notify: ${HANDLER_NAME}			# Kicks off a handler

    - name: Create a directory
      file:
        name: ${ABS_PATH_TO_DIRECTORY}
        state: directory
	
    - name: Run a command and capture the output as a variable
      command: ${SOME_COMMAND}
        creates: ${ABS_PATH_OF_A_FILE_YOU_DON'T_WANT_TO_CLOBBER}
      register: ${SOME_VARIABLE_TO_HOLD_COMMAND_OUTPUT}
    - debug: msg="{{ REGISTER_NAME.stdout }}"	# If you want to see the command's stdout.
    - debug: msg="{{ REGISTER_NAME.stderr }}"   # If you want to see the command's stderr.  
      
    - name: Run a command, only once, on a server of your choosing:
      command: ${SOME_COMMAND}
      run_once: true				# Run this command exactly once per playbook execution
      delegate_to: ${HOSTNAME}			# Otherwise, the command will run once on the first host in the inventory.
      
    - name: Unzip a file
      unarchive: 
        src: files/${NAME_OF_ARCHIVE} 		# Local copy of the file in case it's not on the local machine
	dest: ${ABS_PATH} 			# Destination for extraction
	copy: no 				# Don't copy the file from local machine (file is already there)
	creates: ${ABS_PATH_OF_A_FILE_YOU_DON'T_WANT_TO_CLOBBER}	# This file will get created if it doesn't already exist.
      
    - name: Fetch a URL checksum and capture the output as a variable
      uri: 
        url: https://${SOME_WEBSITE}/${SOME_FILE}.sha1 
	return_content: true
      register: file_checksum			# This will be used in the next step
      
    - name: Download a file from the web and check it against a previously collected checksum
      get_url: 
        url: https://${SOME_WEBSITE}/${SOME_FILE}
	dest: ${ABS_PATH_TO_FILE} 
	checksum: "sha1:{{file_checksum.content}}"

    - name: Copy some $FILE to a destination
      copy:  
        src: files/${FILE}
	dest: ${ABS_PATH_TO_FILE}
      notify: ${HANDLER_NAME}			# Kicks off a handler
      # Note: if the copy statement is being called from a module, you don't have to specify "files/" 
      #       as part of the src path (this directory is checked for you automatically). Both should work, though?
      
    - name: Check if a port is up yet
      wait_for:					# By default, checks every second (this is configurable).
        host: ${HOSTNAME}
        port: ${PORT}				# Default is if port is open, but you can also check if closed.
        delay: 3				# Number of seconds to wait before starting to poll
	
    # Include an additional task file per some condition:
    - include_tasks: file.yml			# This file can be a list of tasks that just begins with "---"
      when: ${VARIABLE} == '${SOMEVALUE}'       # Example variable: anything returned by setup module (no special formatting)
      
    - name: Copy some template $FILE to a destination
      template:
        src: templates/${FILE}			# Jinja template (*.j2) - files that reference/substitute:   {{ $VARNAME }}
        dest: ${ABS_PATH_TO_FILE}	
	owner: ${USER}
        group: ${GROUP}
        mode: 0###
      notify: ${HANDLER_NAME}			# Kicks off a handler
      # Note: if the template statement is being called from a module, you don't have to specify "templates/" 
      #       as part of the src path (this directory is checked for you automatically). Both should work, though?
      
    - name: Update/create a single line in a file
      lineinfile:
        create: true				# Creates file if it isn't there already
        dest: /etc/ssh/sshd_config		# File to be modified
        regexp: ^PermitUserEnvironment		# How to find the file to modify
        line: PermitUserEnvironment no		# What to update the line to be 
        validate: /usr/sbin/sshd -t -f %s	# Command to run to validate the file syntax
      notify: ${HANDLER_NAME}			# Kicks off handler (restart SSH)

    # This is an explicit restart at the end.  However, the handler is also doing this. 
    - name: Start service ${SERVICE_NAME}
      service:
        name: ${SERVICE_NAME}
        state: started
	enabled: yes
	
    # Send a summary email, only once per playbook execution, from the host running ansible:
    - name: Send summary mail
      local_action:			# Run this task on the server running ansible, not the host being acted upon
        module: mail
        subject: "Summary Mail"
        to: "{{ mail_recipient }}"
        body: "{{ mail_body }}"
      run_once: true			# Will execute this task only once per playbook execution

  handlers:

    - name: ${HANDLER_NAME}			# Example: "Start nginx", or whatever the service name is.
      service:
        name: ${SERVICE_NAME}
        state: restarted
        enabled: yes
```

### Playbook snippet for setting up mysql:
```
# The following checks for existence of /root/.my.cnf.
# If the file exists, then mysql_new_root_pass.changed is false, and consequently
# the rest of the commands are not run.  This prevents the mysql root password
# from changing each time you run the playbook!

- name: Remove anonymous users
  mysql_user: name="" state=absent
  when: mysql_new_root_pass.changed
  
- name: Remove test database
  mysql_db: name=test state=absent
  when: mysql_new_root_pass.changed

### Optional database/user commands:
- name: Create adhoc database
  mysql_db: name=wordpress state=present
- name: Create adhoc user
  mysql_user: name=wordpress host=localhost password=bananas priv=wordpress.*:ALL
### End optional commands. 

- name: Generate new root password
  command: openssl rand -hex 8 creates=/root/.my.cnf
  register: mysql_new_root_pass
  
- name: Output new root password
  debug: msg="New root password is {{mysql_new_root_pass.stdout}}"
  when: mysql_new_root_pass.changed
  
- name: Update root password
  mysql_user: name=root host={{item}} password={{mysql_new_root_pass.stdout}}
  with_items:
    - "{{ ansible_hostname }}"
    - 127.0.0.1
    - ::1
    - localhost
  when: mysql_new_root_pass.changed
  
- name: Create my.cnf
  template: src=templates/mysql/my.cnf.j2 dest=/root/.my.cnf
  when: mysql_new_root_pass.changed
```
Note: this requires the existence of a template called `templates/mysql/my.cnf.j2` with the following contents:
```
[client]
user=root
password={{ mysql_new_root_pass.stdout }}
```

Other mysql commands:
```
- name: Check database existence
  command: mysql -u root wordpress -e "SELECT ID FROM wordpress.wp_users LIMIT 1;"
  register: db_exist
  ignore_errors: true
  changed_when: false			# This check will always show up as "OK" and never "Changed". 
  					# Handlers will not be triggered!
  
  # Copy and restore database from backup if database doesn't exist:
- name: Copy WordPress DB
  copy: src=files/wp-database.sql dest=/tmp/wp-database.sql
  when: db_exist.rc > 0
- name: Import WordPress DB
  mysql_db: target=/tmp/wp-database.sql state=import name=wordpress
  when: db_exist.rc > 0
```

### Blocks
Blocks allow you to specify `become` and `when` statements for groups of tasks.  One use case is if you don't want to run everything as root (`become=false`).
```
---
- hosts: all
  tasks:
    - block:
        - apt: name=apache2 state=installed
        - template: name=vhost.conf dest=/etc/apache2/sites-enabled/vhost.conf
      become: true
    - copy: name=s3.cfg dest=∼/.s3.cfg			# This task is run without elevated privileges.
```

Blocks also allow you to perform certain tasks if something in the block fails. Subsequent tasks in the block will not be executed.
```
---
- hosts: all
  tasks:
    - block:
        - debug: msg="This runs no matter what happens"
        - command: /bin/false
        - debug: msg="I will never run because the task above fails"
      rescue:
        - debug: msg="This will run because the block failed"
      always:
        - debug: msg="This runs no matter what happens"
```


## Roles
Create directory structure for a role:
```
cd $PROJECT
mkdir roles
cd roles
ansible-galaxy init $ROLENAME
```
NOTES:
- This creates all the necessary subdirectories in roles/${ROLENAME} and their corresponding main.yml files.  You will have to populate everything yourself.
- The module intentionally has nothing to call it.  You can call it with your own playbook, or by putting a site.yml (the conventional master playbook) in the same directory as the modules folder.  Your playbook will contain the following at a minimum:
```
---
- hosts: all
  become: true
  name: This playbook is calling a role
  roles:
    - roles/${ROLENAME}
```
- Under each directory of the module there's a main.yml. Here are the expected contents of that file for each directory:
   - defaults	Default variables that aren't expected to change.
   - vars	Variables that are configurable.
   - handlers	All handlers (start/stop services). 
   - files	Files that are static / won't change.
   - templates	Files that have configurable aspects.
   - tasks	Where all of the work is actually taking place.  
   - tests	This is where you would put test playbooks that consume your role.
   - meta	This is where you specify dependencies. Assumes those specified roles are installed. Exmample:
```
---
dependencies:
  - common
  - php
  - mysql
  - nginx
```

More on variable precedence here:
http://docs.ansible.com/ansible/latest/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable


## Using ansible galaxy:
```
ansible-galaxy [-c] install ${USER}.${ROLENAME} -p ${PATH_TO_ROLE_DIRECTORY}
```
The `-c` is necessary for RHEL6 which can't properly do SSL validation.

You can specify a certain list of requirements (pulling from different sources) via:
```
ansible-galaxy install -r requirements.yml
```
... where requirements.yml has the following format:
```
# package from galaxy
- src: yatesr.timezone
# package from GitHub
- src: https://github.com/bennojoy/nginx
# package from GitHub, overriding the name and specifying a specific tag
- src: https://github.com/bennojoy/nginx
  version: master
  name: nginx_role
# package from a webserver, where the role is packaged in a tar.gz
- src: https://some.webserver.example.com/files/master.tar.gz
  name: http-role
# from GitLab or other git-based scm
- src: git@gitlab.company.com:mygroup/ansible-base.git
  scm: git
  version: 0.1.0
```
List what roles you have installed:
```
ansible-galaxy list -p ${PATH_TO_ROLE_DIRECTORY}
```
Search for new roles (limiting to RHEL):
```
ansible-galaxy search ${SEARCH_TERM} --platforms=EL
```

## Applying STIG to RHEL7 (via RH module):
Module site: https://galaxy.ansible.com/redhatofficial/rhel7_disa_stig
Source site: https://github.com/RedHatOfficial/ansible-rhel7-disa-stig-role

Install the role:
```
ansible-galaxy install redhatofficial.rhel7_disa_stig [-p /etc/ansible/roles]
```
Create a project with this git project / download this playbook:
```
https://github.com/ajacocks/rhel7_disa_stig.git
```
Create a template.  Run the playbook, but supply these Skip Tags:
```
CCE-27361-5
CCE-27485-2
CCE-27311-0
CCE-80546-5
```

## Using ansible-vault
```
ansible-vault encrypt ${NAME_OF_YML_FILE}
```
Use this to encrypt a variable file that contains secrets. You will be interactively prompted for a password.

To edit that file:
```
ansible-vault edit ${NAME_OF_YML_FILE}
```
Other supported commands are `decrypt`, `rekey`, `view`, and `create`.

When running a playbook that references a vault file, use `--ask-vault-pass`.  Alternatively, specify a password file with `--vault-password-file`.

NOTE: if there are multiple encrypted files, they ALL must have the same decryption key (password).


-------------------
# Vagrant
Requires the installation of both vagrant and virtualbox. 
https://www.vagrantup.com/downloads.html
http://download.virtualbox.org/virtualbox/rpm/rhel/7/x86_64/

Vagrant commands:
```
vagrant init centos/7		# Creates Vagrantfile in directory
vagrant up			# Downloads and brings up VM
vagrant status			# Shows status of machine
vagrant ssh			# Connects to machine
vagrant halt			# Shut down machine
vagrant destroy			# Removes machine
```

Add the following to Vagrantfile:
```
 # Set private network:
 config.vm.network "private_network", ip: "192.168.33.10"

 # Set provider-specific VM options:
 config.vm.provider "virtualbox" do |vb|
  vb.memory = "1024"
 end

 # Use ansible to provisioning (called during instantiation, or by `vagrant provision`):
 config.vm.provision "ansible" do |ansible|
  ansible.playbook = "provisioning/playbook.yml"
 end
```
Requires creation of the following in the current directory:
`provisioning/playbook.yml` 
Run the `vagrant provision` command to use the playbook.

Having done the above, you can make an alias to SSH into the VM without using `vagrant ssh`:
```
alias vs='ssh -i .vagrant/machines/default/virtualbox/private_key vagrant@192.168.33.10'
```

For manual ansible commands from your machine, you also need an `./inventory` file.
Example:
```
192.168.33.10 ansible_user=vagrant ansible_ssh_private_key_file=.vagrant/machines/default/virtualbox/private_key
```

You can then reference the inventory as follows to run the provisioning playbook:
```
ansible-playbook -i ./inventory provisioning/playbook.yml
```

-------------------
# Cloud

## Google

Google storage buckets:
https://cloud.google.com/storage/

Google kubernetes engine:
https://cloud.google.com/kubernetes-engine/


-------------------
# Fun

## Create a file that has zero length, but actually takes up space:
```
fallocate -n -l $SIZE $FILENAME
```
A file created in this way consumes space per df, but is entirely undetectable.  
God knows why you can do this.


## Discordian date (RH6 only):
```
ddate 
```

## Banner font:
```
yum install figlet
figlet "your text here"
```

## Steam locomotive
```
yum install sl
sl
```

## Matrix
```
git clone https://github.com/abishekvashok/cmatrix.git
yum install ncurses-devel automake
cd cmatrix
autoreconf -i
./configure
make
make install
/usr/local/bin/cmatrix
```

## Fire (B&W, console)
```
yum -y install aalib; aafire
```

## Fire (color, X)
```
# Have xming running:
yum -y install caca-utils; cacafire  
```

## Snow:
```
yum -y install ruby
ruby -e 'C=`stty size`.scan(/\d+/)[1].to_i;S=["2743".to_i(16)].pack("U*");a={};puts "\033[2J";loop{a[rand(C)]=0;a.each{|x,o|;a[x]+=1;print "\033[#{o};#{x}H \033[#{a[x]};#{x}H#{S} \033[0;0H"};$stdout.flush;sleep 0.1}'
```

## Display random garbage on someone else's screen:
Figure out what pts number they're using with `who`, then:
```
echo "garbage" >> /dev/pts/$X
```
You can even send the bell sound!
```
echo -e '\a' >> /dev/pts/$X
```

## Cycle text through ANSI colors:
```
while true
do
   for i in {30..37} {90..97}
   do
      echo -n -e "\e[${i}m COLORS"
   done
done
```
List of colors:
```
\e[39m  Default
\e[30m  Black
\e[31m  Red
\e[32m  Green
\e[33m  Yellow
\e[34m  Blue
\e[35m  Magenta
\e[36m  Cyan
\e[37m  Light gray
\e[90m  Dark gray
\e[91m  Light red
\e[92m  Light green
\e[93m  Light yellow
\e[94m  Light blue
\e[95m  Light magenta
\e[96m  Light cyan
\e[97m  White
```
