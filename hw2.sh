#!/bin/sh
#
# To download this script directly from freeBSD:
# $ pkg install curl
# $ curl -LO https://raw.githubusercontent.com/dkmcgrath/sysadmin/main/freebsd_setup.sh
#
#The following features are added:
# - switching (internal to the network) via FreeBSD pf
# - DHCP server, DNS server via dnsmasq
# - firewall via FreeBSD pf
# - NAT layer via FreeBSD pf
#


# Set your network interfaces names; set these as they appear in ifconfig
# they will not be renamed during the course of installation
WAN="hn0"
LAN="hn1"

# Install dnsmasq
pkg install -y dnsmasq

# Enable forwarding
sysrc gateway_enable="YES"
# Enable immediately
sysctl net.inet.ip.forwarding=1

# Set LAN IP
ifconfig ${LAN} inet 192.168.33.1 netmask 255.255.255.0
# Make IP setting persistent
sysrc "ifconfig_${LAN}=inet 192.168.33.1 netmask 255.255.255.0"

ifconfig ${LAN} up
ifconfig ${LAN} promisc

# Enable dnsmasq on boot
sysrc dnsmasq_enable="YES"

# Edit dnsmasq configuration
echo "interface=${LAN}" >> /usr/local/etc/dnsmasq.conf
echo "dhcp-range=192.168.33.50,192.168.33.150,12h" >> /usr/local/etc/dnsmasq.conf
echo "dhcp-option=option:router,192.168.33.1" >> /usr/local/etc/dnsmasq.conf

# Configure PF for NAT
echo "
ext_if=\"${WAN}\"
int_if=\"${LAN}\"

icmp_types = \"{ echoreq, unreach }\"
services = \"{ ssh, domain, http, ntp, https }\"
server = \"192.168.33.63\"
ssh_rdr = \"2222\"
table <rfc6890> { 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16          \\
                  172.16.0.0/12 192.0.0.0/24 192.0.0.0/29 192.0.2.0/24 192.88.99.0/24    \\
                  192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24            \\
                  240.0.0.0/4 255.255.255.255/32 }
table <bruteforce> persist


#options                                                                                                                         
set skip on lo0

#normalization
scrub in all fragment reassemble max-mss 1440

#NAT rules
nat on \$ext_if from \$int_if:network to any -> (\$ext_if)

#blocking rules
antispoof quick for \$ext_if
block in quick on egress from <rfc6890>
block return out quick on egress to <rfc6890>
block log all

#pass rules
pass in quick on \$int_if inet proto udp from any port = bootpc to 255.255.255.255 port = bootps keep state label \"allow access to DHCP server\"
pass in quick on \$int_if inet proto udp from any port = bootpc to \$int_if:network port = bootps keep state label \"allow access to DHCP server\"
pass out quick on \$int_if inet proto udp from \$int_if:0 port = bootps to any port = bootpc keep state label \"allow access to DHCP server\"

pass in quick on \$ext_if inet proto udp from any port = bootps to \$ext_if:0 port = bootpc keep state label \"allow access to DHCP client\"
pass out quick on \$ext_if inet proto udp from \$ext_if:0 port = bootpc to any port = bootps keep state label \"allow access to DHCP client\"

pass in on \$ext_if proto tcp to port { ssh } keep state (max-src-conn 15, max-src-conn-rate 3/1, overload <bruteforce> flush global)
pass out on \$ext_if proto { tcp, udp } to port \$services
pass out on \$ext_if inet proto icmp icmp-type \$icmp_types
pass in on \$int_if from \$int_if:network to any
" >> /etc/pf.conf

# Start dnsmasq
service dnsmasq start

# Enable PF on boot
sysrc pf_enable="YES"
sysrc pflog_enable="YES"

# Start PF
service pf start

# Load PF rules
pfctl -f /etc/pf.conf
# End of the script

pkg install -y vim
pkg install -y snort
pkg install -y git

### Firewall stuff
## You will need to manually changes the outgoing port to match the target box being forwarded to before running
    ## redirect
    header="#redirect rules"
    rdr22="rdr log on \$ext_if proto tcp to (\$ext_if) port 22 -> 192.168.33.84 port 22"
    rdr445="rdr log on \$ext_if proto tcp to (\$ext_if) port 445 -> 192.168.33.84 port 445"
    rdr137="rdr log on \$ext_if proto { tcp, udp } to (\$ext_if) port 137 -> 192.168.33.84 port 137"
    rdr138="rdr log on \$ext_if proto { tcp, udp } to (\$ext_if) port 138 -> 192.168.33.84 port 138"
    rdr139="rdr log on \$ext_if proto { tcp, udp } to (\$ext_if) port 139 -> 192.168.33.84 port 139"

    pf_conf="/etc/pf.conf"
    target_phrase="#blocking rules"
    sed -i.bak -e "/$target_phrase/ {
        i\\
        $header\\
        $rdr22\\
        $rdr137\\
        $rdr138\\
        $rdr139\\
        $rdr445
    }" $pf_conf

    ### pass
    passin22="pass in on \$ext_if proto tcp to (\$ext_if) port 22"
    passout22="pass out on \$int_if proto { tcp } to 192.168.33.84 port 22"

    passin445="pass in on \$ext_if proto tcp to (\$ext_if) port 445"
    passout445="pass out on \$int_if proto { tcp } to 192.168.33.84 port 445"

    passin137="pass in on \$ext_if proto tcp to (\$ext_if) port 137"
    passout137="pass out on \$int_if proto { tcp } to 192.168.33.84 port 137"

    passin138="pass in on \$ext_if proto tcp to (\$ext_if) port 138"
    passout138="pass out on \$int_if proto { tcp } to 192.168.33.84 port 138"

    passin139="pass in on \$ext_if proto tcp to (\$ext_if) port 139"
    passout139="pass out on \$int_if proto { tcp } to 192.168.33.84 port 139"

    echo -e "$passin22\n$passout22\n$passin445\n$passout445\n$passin137\n$passout137\n$passin138\n$passout138\n$passin139\n$passout139" >> "$pf_conf"

    #change services to include relevant ones
    sed -i.bak -e 's/^services = .*/services = "{ ssh, domain, http, ntp, https, microsoft-ds, netbios-ns, netbios-dgm, netbios-ssn }"/' "$pf_conf"

    #change pass in on $ext_if proto tcp to port { ssh } keep state -> $ext_if proto tcp to port { ssh, microsoft-ds }
    sed -i.bak -e 's/^pass in on \$ext_if proto tcp to port { ssh } keep state (max-src-conn 15, max-src-conn-rate 3\/1, overload <bruteforce> flush global)/pass in on \$ext_if proto tcp to port { ssh, microsoft-ds } keep state (max-src-conn 15, max-src-conn-rate 3\/1, overload <bruteforce> flush global)/' "$pf_conf"

    #reload the firewall after changes
    pfctl -vf /etc/pf.conf

# Modify the local ssh server to move it to a different port for management purposes. <works>
    sshd_config="/etc/ssh/sshd_config"
    sed -i.bak -e 's/^#Port 22/Port 2222/' "$sshd_config"

    ssh_config="/etc/ssh/ssh_config"
    sed -i.bak -E 's/^#[[:space:]]*Port[[:space:]]+22/Port 2222/' "$sshd_config"

# Snort conf installation + configuration
    snort_conf="/usr/local/etc/snort/snort.conf"
    ip_address=$(ifconfig hn0 | awk '/inet / {print $2}')

    #set ipvar HOME_NET to hn0 in snort.conf
    sed -i.bak "/^ipvar HOME_NET/s/.*/ipvar HOME_NET $ip_address/" "$snort_conf"

    #comment out reputation preprocessor section <broke>
    sed -i.bak -e "/preprocessor reputation/,/^$/ s/^/#/" "$snort_conf"

    #add $RULE_PATH/rules.rules after # site specific rules 
    sed -i.bak '/# site specific rules/ s/# site specific rules/# site specific rules\
include $RULE_PATH\/rules.rules/' "$snort_conf"

    #comment out include include $RULE_PATH/local.rules -> include $RULE_PATH/x11.rules
    sed -i '' '/include $RULE_PATH\/local.rules/,/include $RULE_PATH\/x11.rules/ s/^/#/' "$snort_conf"

    #rewrite var RULE_PATH from ./rules -> rules 
    sed -i '' 's/var RULE_PATH .\/rules/var RULE_PATH rules/' "$snort_conf"
    
    #rewrite var SO_RULE_PATH from ./so_rules -> so_rules
    sed -i '' 's/var SO_RULE_PATH .\/so_rules/var SO_RULE_PATH so_rules/' "$snort_conf"

    #rewrite var PREPROC_RULE_PATH from ./preproc_rules -> preproc_rules
    sed -i '' 's/var PREPROC_RULE_PATH .\/preproc_rules/var PREPROC_RULE_PATH preproc_rules/' "$snort_conf"

    #snort rules configuration
    rules_location="/usr/local/etc/snort/rules"
    cd "$rules_location" || exit 1

    #<works but might rework bc doubling text>
    rule1='alert tcp any any -> any 445 (msg:\"SMBv3 Used with compression - Client to server\"; content:\"|fc 53 4d 42|\"; offset: 0; depth: 10; sid:1000001; rev:1;)'
    echo "$rule1" >> rules.rules

    rule2='alert tcp any 445 -> any any (msg:"SMBv3 Used with compression - Server to client"; content:"|fc 53 4d 42|"; offset: 0; depth: 10; sid:1000002; rev:1;)'
    echo "$rule2" >> rules.rules

#Snort at boot <looks ok on test1>
    firstflag="snort_enable=\"YES\""
    # echo "$firstflag" >> /etc/rc.conf
    sed -i '$ a\${firstflag}'

    secondFlag="snort_flags=\"-A full -l /var/log/snort -i hn0 -c /usr/local/etc/snort/snort.conf\""
    # echo "$secondFlag" >> /etc/rc.conf
    sed -i '$ a\${secondFlag}'


    