#!/bin/bash -x

if [[ "$(id -u)" != "0" ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

if [[ ${1} == "" ]] ; then
    echo "Please, inform the mail server hostname and admin password. e.g. ./install.sh mail.mydomain.com"
    exit 0
fi

# Change timezone
dpkg-reconfigure tzdata

# Basic packages
apt update -qq && apt dist-upgrade
apt install vim-nox nload htop atop vim-nox pv ncdu language-pack-pt tmux makepasswd rcs perl-doc libio-tee-perl git libmail-imapclient-perl libdigest-md5-file-perl libclass-load-perl libterm-readkey-perl libdate-manip-perl libdist-checkconflicts-perl libfile-copy-recursive-perl libio-tee-perl libjson-perl libmodule-implementation-perl libmodule-runtime-perl libpackage-stash-perl libpackage-stash-xs-perl libsys-meminfo-perl libtest-fatal-perl libtest-mock-guard-perl libtest-mockobject-perl libtest-requires-perl libtry-tiny-perl libfile-copy-recursive-perl build-essential make automake libunicode-string-perl libauthen-ntlm-perl libcrypt-ssleay-perl libcrypt-openssl-rsa-perl libdigest-hmac-perl libfile-copy-recursive-perl libio-compress-perl libio-socket-inet6-perl libio-socket-ssl-perl libdata-uniqid-perl libio-tee-perl libmodule-scandeps-perl libnet-ssleay-perl libpar-packer-perl libreadonly-perl libterm-readkey-perl libtest-pod-perl libtest-simple-perl libunicode-string-perl liburi-perl cpanminus -y
cpanm CGI JSON::WebToken JSON::WebToken::Crypt::RSA Regexp::Common Test::NoWarnings Test::Deep Test::Warn

# Imapsync
git clone git://github.com/imapsync/imapsync.git
cd imapsync
mkdir dist
make install

if [[ `lsb_release -rs` == "16.04" ]]; then
    ZIMBRA_DOWNLOAD_URL="https://files.zimbra.com/downloads/8.8.12_GA/zcs-8.8.12_GA_3794.UBUNTU16_64.20190329045002.tgz"
else
    echo "This installer runs on Ubuntu 16.04"
    exit 0
fi

## Preparing all the variables
set -e
RANDOMHAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMSPAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMVIRUS=$(date +%s|sha256sum|base64|head -c 10)
PUBLICIP=$(dig +short myip.opendns.com @resolver1.opendns.com)
MAIL_TMP_DIR="/tmp/zcs" && mkdir -p ${MAIL_TMP_DIR}

echo "==============================================="
echo "Setting variables and hostname"
MAIL_HOSTNAME=${1}
MAIL_SECRET=$(date +%s|sha256sum|base64|head -c 16)
hostnamectl set-hostname ${MAIL_HOSTNAME} &>/dev/null

#Install a DNS Server
echo "Installing dnsmasq DNS Server"
apt update &>/dev/null && apt install dnsmasq -y &>/dev/null

echo "Configuring DNS Server"
echo "nameserver 127.0.0.1" > /etc/resolv.conf
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old

cat <<EOF >>/etc/dnsmasq.conf
server=8.8.8.8
listen-address=127.0.0.1
domain=${MAIL_HOSTNAME}
mx-host=${MAIL_HOSTNAME},0
address=/${MAIL_HOSTNAME}/${PUBLICIP}
EOF

service dnsmasq restart

##Preparing the config files to inject
echo "Creating the Scripts files"

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
wget ${ZIMBRA_DOWNLOAD_URL} -O ${MAIL_TMP_DIR}/zimbra-zcs.tar.gz
tar -C ${MAIL_TMP_DIR} -zxvf ${MAIL_TMP_DIR}/zimbra-zcs.tar.gz

echo "Installing Zimbra Collaboration just the Software"
cd ${MAIL_TMP_DIR}/zcs-* && ./install.sh -s < ${MAIL_TMP_DIR}/installZimbra-keystrokes

echo "Installing Zimbra Collaboration injecting the configuration"
/opt/zimbra/libexec/zmsetup.pl -c ${MAIL_TMP_DIR}/installZimbraScript
su - zimbra -c "zmcontrol restart"

cp ${MAIL_TMP_DIR}/installZimbraScript ${HOME} && rm -rf ${MAIL_TMP_DIR}

echo "===============================================" >> ${HOME}/zimbra_installed.txt
echo "You can access now to your Zimbra Collaboration Server" >> ${HOME}/zimbra_installed.txt
echo "Mail server hostname: ${MAIL_HOSTNAME}" >> ${HOME}/zimbra_installed.txt
echo "Mail admin username: admin" >> ${HOME}/zimbra_installed.txt
echo "Mail admin password: ${MAIL_SECRET}" >> ${HOME}/zimbra_installed.txt
echo "Admin Console: https://${MAIL_HOSTNAME}:7071 OR https://${PUBLICIP}:7071" >> ${HOME}/zimbra_installed.txt
echo "Web Client: https://${MAIL_HOSTNAME} OR https://${PUBLICIP}" >> ${HOME}/zimbra_installed.txt
echo "===============================================" >> ${HOME}/zimbra_installed.txt
