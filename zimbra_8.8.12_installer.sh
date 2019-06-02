#!/bin/bash -x

if [[ "$(id -u)" != "0" ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

if [[ ${1} == "" ]] ; then
    echo "Please, inform the mail server hostname and admin password. e.g. ./install.sh mail.mydomain.com"
    exit 0
fi

# Basic packages
apt update -qq && apt dist-upgrade && apt install vim-nox nload htop atop vim-nox imapsync pv ncdu language-pack-pt tmux -y

# Change timezone
dpkg-reconfigure tzdata

if [[ `lsb_release -rs` == "16.04" ]]; then
    ZIMBRA_DOWNLOAD_URL="https://files.zimbra.com/downloads/8.8.12_GA/zcs-8.8.12_GA_3794.UBUNTU16_64.20190329045002.tgz"
else
    echo "This installer runs on Ubuntu 16.04"
    exit 0
fi

## Preparing all the variables like IP, Hostname, etc, all of them from the container
set -e
RANDOMHAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMSPAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMVIRUS=$(date +%s|sha256sum|base64|head -c 10)
PUBLICIP=$(dig +short myip.opendns.com @resolver1.opendns.com)

echo "==============================================="
echo "Setting variables and hostname"
MAIL_HOSTNAME=${1}
MAIL_SECRET=$(date +%s|sha256sum|base64|head -c 16)
hostnamectl set-hostname ${MAIL_HOSTNAME} &>/dev/null

#Install a DNS Server
echo "Installing dnsmasq DNS Server"
apt update &>/dev/null && apt install dnsmasq -y &>/dev/null
echo "Installed..."

echo "Configuring DNS Server"
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old

cat <<EOF >>/etc/dnsmasq.conf
server=8.8.8.8
listen-address=127.0.0.1
domain=${MAIL_HOSTNAME}
mx-host=${MAIL_HOSTNAME},0
address=/${MAIL_HOSTNAME}/${PUBLICIP}
EOF

echo "nameserver 127.0.0.1" > /etc/resolv.conf
service dnsmasq restart
echo "DNS configured..."

##Preparing the config files to inject
echo "Creating the Scripts files"
mkdir /tmp/zcs && cd /tmp/zcs
touch /tmp/zcs/installZimbraScript

cat <<EOF >/tmp/zcs/installZimbraScript
AVDOMAIN="${MAIL_HOSTNAME}"
AVUSER="admin@${MAIL_HOSTNAME}"
CREATEADMIN="admin@${MAIL_HOSTNAME}"
CREATEADMINPASS="${MAIL_SECRET}"
CREATEDOMAIN="${MAIL_HOSTNAME}"
DOCREATEADMIN="yes"
DOCREATEDOMAIN="yes"
DOTRAINSA="yes"
EXPANDMENU="no"
HOSTNAME="${MAIL_HOSTNAME}"
HTTPPORT="8080"
HTTPPROXY="TRUE"
HTTPPROXYPORT="80"
HTTPSPORT="8443"
HTTPSPROXYPORT="443"
IMAPPORT="7143"
IMAPPROXYPORT="143"
IMAPSSLPORT="7993"
IMAPSSLPROXYPORT="993"
INSTALL_WEBAPPS="service zimlet zimbra zimbraAdmin"
JAVAHOME="/opt/zimbra/common/lib/jvm/java"
LDAPAMAVISPASS="${MAIL_SECRET}"
LDAPPOSTPASS="${MAIL_SECRET}"
LDAPROOTPASS="${MAIL_SECRET}"
LDAPADMINPASS="${MAIL_SECRET}"
LDAPREPPASS="${MAIL_SECRET}"
LDAPBESSEARCHSET="set"
LDAPDEFAULTSLOADED="1"
LDAPHOST="${MAIL_HOSTNAME}"
LDAPPORT="389"
LDAPREPLICATIONTYPE="master"
LDAPSERVERID="2"
MAILBOXDMEMORY="512"
MAILPROXY="TRUE"
MODE="https"
MYSQLMEMORYPERCENT="30"
POPPORT="7110"
POPPROXYPORT="110"
POPSSLPORT="7995"
POPSSLPROXYPORT="995"
PROXYMODE="https"
REMOVE="no"
RUNARCHIVING="no"
RUNAV="yes"
RUNCBPOLICYD="no"
RUNDKIM="yes"
RUNSA="yes"
RUNVMHA="no"
SERVICEWEBAPP="yes"
SMTPDEST="admin@${MAIL_HOSTNAME}"
SMTPHOST="${MAIL_HOSTNAME}"
SMTPNOTIFY="yes"
SMTPSOURCE="admin@${MAIL_HOSTNAME}"
SNMPNOTIFY="yes"
SNMPTRAPHOST="${MAIL_HOSTNAME}"
SPELLURL="http://${MAIL_HOSTNAME}:7780/aspell.php"
STARTSERVERS="yes"
SYSTEMMEMORY="3.8"
TRAINSAHAM="ham.${RANDOMHAM}@${MAIL_HOSTNAME}"
TRAINSASPAM="spam.${RANDOMSPAM}@${MAIL_HOSTNAME}"
UIWEBAPPS="yes"
UPGRADE="yes"
USEKBSHORTCUTS="TRUE"
USESPELL="yes"
VERSIONUPDATECHECKS="TRUE"
VIRUSQUARANTINE="virus-quarantine.${RANDOMVIRUS}@${MAIL_HOSTNAME}"
ZIMBRA_REQ_SECURITY="yes"
ldap_bes_searcher_password="${MAIL_SECRET}"
ldap_dit_base_dn_config="cn=zimbra"
ldap_nginx_password="${MAIL_SECRET}"
ldap_url="ldap://${MAIL_HOSTNAME}:389"
mailboxd_directory="/opt/zimbra/mailboxd"
mailboxd_keystore="/opt/zimbra/mailboxd/etc/keystore"
mailboxd_keystore_password="${MAIL_SECRET}"
mailboxd_server="jetty"
mailboxd_truststore="/opt/zimbra/common/lib/jvm/java/jre/lib/security/cacerts"
mailboxd_truststore_password="changeit"
postfix_mail_owner="postfix"
postfix_setgid_group="postdrop"
ssl_default_digest="sha256"
zimbraDNSMasterIP=""
zimbraDNSTCPUpstream="no"
zimbraDNSUseTCP="yes"
zimbraDNSUseUDP="yes"
zimbraDefaultDomainName="${MAIL_HOSTNAME}"
zimbraFeatureBriefcasesEnabled="Enabled"
zimbraFeatureTasksEnabled="Enabled"
zimbraIPMode="ipv4"
zimbraMailProxy="FALSE"
zimbraMtaMyNetworks="127.0.0.0/8 ${PUBLICIP}/32 [::1]/128 [fe80::]/64"
zimbraPrefTimeZoneId="America/Sao_Paulo"
zimbraReverseProxyLookupTarget="TRUE"
zimbraVersionCheckInterval="1d"
zimbraVersionCheckNotificationEmail="admin@${MAIL_HOSTNAME}"
zimbraVersionCheckNotificationEmailFrom="admin@${MAIL_HOSTNAME}"
zimbraVersionCheckSendNotifications="TRUE"
zimbraWebProxy="FALSE"
zimbra_ldap_userdn="uid=zimbra,cn=admins,cn=zimbra"
zimbra_require_interprocess_security="1"
zimbra_server_hostname="${MAIL_HOSTNAME}"
INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-snmp zimbra-store zimbra-apache zimbra-spell zimbra-memcached zimbra-proxy"
EOF
    
touch /tmp/zcs/installZimbra-keystrokes

cat <<EOF >/tmp/zcs/installZimbra-keystrokes
y
y
y
y
y
n
y
y
y
y
y
y
y
n
y
y
EOF

echo "Downloading Zimbra Collaboration for Ubuntu 16.04"
wget ${ZIMBRA_DOWNLOAD_URL} -O /tmp/zcs/zimbra-zcs.tar.gz
tar -zxvf zimbra-zcs.tar.gz

echo "Installing Zimbra Collaboration just the Software"
cd /tmp/zcs/zcs-* && ./install.sh -s < /tmp/zcs/installZimbra-keystrokes

echo "Installing Zimbra Collaboration injecting the configuration"
/opt/zimbra/libexec/zmsetup.pl -c /tmp/zcs/installZimbraScript
cp /tmp/zcs/installZimbraScript /root
rm -rf /tmp/zcs

su - zimbra -c "zmcontrol restart"

echo "===============================================" >> /root/zimbra_installed.txt
echo "You can access now to your Zimbra Collaboration Server" >> /root/zimbra_installed.txt
echo "Mail server hostname: ${MAIL_HOSTNAME}" >> /root/zimbra_installed.txt
echo "Mail admin username: admin" >> /root/zimbra_installed.txt
echo "Mail admin password: ${MAIL_SECRET}" >> /root/zimbra_installed.txt
echo "Admin Console: https://${MAIL_HOSTNAME}:7071 OR https://${PUBLICIP}:7071" >> /root/zimbra_installed.txt
echo "Web Client: https://${MAIL_HOSTNAME} OR https://${PUBLICIP}" >> /root/zimbra_installed.txt
echo "===============================================" >> /root/zimbra_installed.txt
