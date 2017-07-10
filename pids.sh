#!/usr/bin/env bash
_scriptDir="$(dirname `readlink -f $0`)"

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi

function Info {
  echo -e -n '\e[7m'
  echo "$@"
  echo -e -n '\e[0m'
}

function Error {
  echo -e -n '\e[41m'
  echo "$@"
  echo -e -n '\e[0m'
}

echo "Please enter your Critical Stack API Key: "
read api

read -p "Please enter your SMTP server (smtp.google.com): " smtp_server
smtp_server=${smtp_server:-smtp.google.com}

read -p "Please enter your SMTP Port (587): " smtp_port
smtp_port=${smtp_port:-587}

read -p "Please enter your email Address (email@gmail.com): " smtp_email
smtp_email=${smtp_email:-email@google.com}

read -p "Please enter your email Password (P@55word): " smtp_pass
smtp_pass=${smtp_pass:-P@55word}

Info  "Creating directories"
mkdir -p /pids
mkdir -p /pids/scripts/
mkdir -p /pids/bro/
mkdir -p /pids/bro/extracted/
if [ ! -d /opt/ ]; then
	mkdir -p /opt/
fi

function install_packages() {
	Info "Installing Required Pre-Requisites"
	apt-get update && apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev ssmtp htop vim libgeoip-dev ethtool git tshark tcpdump nmap mailutils python-pip autoconf libtool ant zip

	if [ $? -ne 0 ]; then
		Error "Error. Please check that apt-get can install needed packages."
		exit 2;
	fi
} 

function install_geoip() {
	Info "Installing GEO-IP"
	wget  http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz 
	wget  http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz 
	gunzip GeoLiteCity.dat.gz 
	gunzip GeoLiteCityv6.dat.gz 
	mv GeoLiteCity* /usr/share/GeoIP/
	ln -s /usr/share/GeoIP/GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
	ln -s /usr/share/GeoIP/GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat 
} 
 
function config_ssmtp() {
	Info "Configuring SSMTP"
	echo "
	root=$smtp_email
	mailhub=$smtp_server:587
	hostname=pids
	FromLineOverride=YES
	UseTLS=NO
	UseSTARTTLS=YES
	AuthUser=$smtp_email
	AuthPass=$smtp_pass" \ > /etc/ssmtp/ssmtp.conf
}


function install_loki() {
	Info "Installing YARA packages"
	Info "Installing Pylzma"
	pushd /opt/
		wget  https://pypi.python.org/packages/fe/33/9fa773d6f2f11d95f24e590190220e23badfea3725ed71d78908fbfd4a14/pylzma-0.4.8.tar.gz 
		tar -zxvf pylzma-0.4.8.tar.gz
		pushd pylzma-0.4.8/
			python ez_setup.py
			python setup.py
		popd
		Info "Installing YARA"
		git clone  https://github.com/VirusTotal/yara.git
		pushd yara/
			./bootstrap.sh
			./configure
			make && make install
		popd
	popd
	Info "Installing PIP LOKI Packages"
	pip install psutil
	pip install yara-python
	pip install gitpython
	pip install pylzma
	pip install netaddr
	Info "Installing LOKI"
	git clone  https://github.com/Neo23x0/Loki.git /pids/Loki
	git clone  https://github.com/Neo23x0/signature-base.git /pids/Loki/signature-base/
	echo "export PATH=/pids/Loki:$PATH" >> /etc/profile
	chmod +x /pids/Loki/loki.py
	echo "
#!/bin/sh
/usr/bin/python /pids/Loki/loki.py --noprocscan --dontwait --onlyrelevant -p /pids/bro/extracted -l /pids/Loki/log
" \ > /pids/scripts/scan
	chmod +x /pids/scripts/scan
}

function install_bro() {
	Info "Installing Bro"
	pushd /opt/
		wget https://www.bro.org/downloads/bro-2.5.1.tar.gz
		tar -xzf bro-2.5.1.tar.gz
		pushd bro-2.5.1
			./configure --localstatedir=/pids/bro/
			make -j 4
			make install
		popd
		Info "Setting Bro variables"
		echo "export PATH=/usr/local/bro/bin:$PATH" >> /etc/profile
		source ~/.bashrc
		Info "Cleaning up Bro"
		rm bro-2.5.1.tar.gz
		rm -rf bro-2.5.1/
	popd
}

function install_criticalstack() {
	Info "Installing Critical Stack Agent"
	wget  http://intel.criticalstack.com/client/critical-stack-intel-arm.deb
	dpkg -i critical-stack-intel-arm.deb
	sudo -u critical-stack critical-stack-intel api $api
	rm critical-stack-intel-arm.deb
	sudo -u critical-stack critical-stack-intel list
	sudo -u critical-stack critical-stack-intel pull
	#Deploy and start BroIDS
	export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/bro/bin:\$PATH"
	echo "Deploying and starting BroIDS"
	broctl deploy
	broctl cron enable
	#Create update script
echo "
echo \"#### Pulling feed update ####\"
sudo -u critical-stack critical-stack-intel pull
echo \"#### Applying the updates to the bro config ####\"
broctl check
broctl install
echo \"#### Restarting bro ####\"
broctl restart
python /pids/Loki/loki.py --update
python /pids/scripts/pullTorIP.py
python /pids/scripts/pullMaliciousIP.py
" \ > /pids/scripts/update
	sudo chmod +x /pids/scripts/update
}

# TODO: Update ES to latest: 5.5
function install_es() {
	Info "Installing ElasticSearch"
	pushd /opt/
		wget  wget https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-2.3.2.deb
		dpkg -i elasticsearch-2.3.2.deb
		rm elasticsearch-2.3.2.deb
		update-rc.d elasticsearch defaults
	popd
}

# Update Logstash to latest
function install_logstash() {
	Info "Installing Logstash"
	pushd /opt/
		wget https://download.elastic.co/logstash/logstash/packages/debian/logstash_2.3.2-1_all.deb
		dpkg -i logstash_2.3.2-1_all.deb
		rm logstash_2.3.2-1_all.deb
		git clone https://github.com/jnr/jffi.git
		pushd jffi
			ant jar
			cp build/jni/libjffi-1.2.so /opt/logstash/vendor/jruby/lib/jni/arm-Linux
		popd
		pushd /opt/logstash/vendor/jruby/lib
			zip -g jruby-complete-1.7.11.jar jni/arm-Linux/libjffi-1.2.so
		popd
		rm -rf jffi/
	popd
	update-rc.d logstash defaults
	/opt/logstash/bin/plugin install logstash-filter-translate
	cp $_scriptDir/logstash.conf /etc/logstash/conf.d
	mkdir /etc/logstash/custom_patterns
	cp $_scriptDir/bro.rule /etc/logstash/custom_patterns
	mkdir /etc/logstash/translate
	sed -i -- "s/SMTP_HOST/"$smtp_server"/g" /opt/logstash/logstash.conf
	sed -i -- "s/SMTP_PORT/"$smtp_port"/g" /opt/logstash/logstash.conf
	sed -i -- "s/EMAIL_USER/"$smtp_email"/g" /opt/logstash/logstash.conf
	sed -i -- "s/EMAIL_PASS/"$smtp_pass"/g" /opt/logstash/logstash.conf
}

# Update Kibana to latest
function install_kibana() {
	Info "Installing Kibana"
	wget https://download.elastic.co/kibana/kibana/kibana-4.5.0-linux-x86.tar.gz
	tar -xzf kibana-4.5.0-linux-x86.tar.gz
	mv kibana-4.5.0-linux-x86/ /opt/kibana/
	apt-get -y remove nodejs-legacy nodejs nodered		#Remove nodejs on Pi3
	wget http://node-arm.herokuapp.com/node_latest_armhf.deb
	dpkg -i node_latest_armhf.deb
	mv /opt/kibana/node/bin/node /opt/kibana/node/bin/node.orig
	mv /opt/kibana/node/bin/npm /opt/kibana/node/bin/npm.orig
	ln -s /usr/local/bin/node /opt/kibana/node/bin/node
	ln -s /usr/local/bin/npm /opt/kibana/node/bin/npm
	rm node_latest_armhf.deb
	cp $_scriptDir/init.d/kibana /etc/init.d
	chmod 755 /etc/init.d/kibana
	update-rc.d kibana defaults
}

function install_bro_reporting() {
	Info "Bro Reporting Requirements"
	pushd /opt/
		#PYSUBNETREE
		git clone  git://git.bro-ids.org/pysubnettree.git 
		pushd pysubnettree/
			python setup.py install
		popd
		#IPSUMDUMP
		wget http://www.read.seas.harvard.edu/~kohler/ipsumdump/ipsumdump-1.85.tar.gz 
		tar -zxvf ipsumdump-1.85.tar.gz
		pushd ipsumdump-1.85/
			./configure && make && make install
		popd
	popd
}

function config_bro_scripts() {
	Info "Configuring BRO scripts"
	#PULL BRO SCRIPTS
	pushd /usr/local/bro/share/bro/site/
		if [ ! -d /usr/local/bro/share/bro/site/bro-scripts/ ]; then
			rm -rf /usr/local/bro/share/bro/site/bro-scripts/
		fi
		git clone https://github.com/sneakymonk3y/bro-scripts.git 
		echo "@load bro-scripts/geoip"  >> /usr/local/bro/share/bro/site/local.bro
		echo "@load bro-scripts/extract"  >> /usr/local/bro/share/bro/site/local.bro
		broctl deploy
	popd
}

function config_sweet_security_scripts() {
	Info "Configuring Sweet Security Scripts"
	cp $_scriptDir/pullMaliciousIP.py /pids/scripts/
	cp $_scriptDir/pullTorIP.py /pids/scripts/
	cp $_scriptDir/networkDiscovery.py /pids/scripts/
	cp $_scriptDir/SweetSecurityDB.py /pids/scripts/
	#Configure Network Discovery Scripts
	sed -i -- "s/SMTP_HOST/"$smtp_server"/g" /opt/SweetSecurity/networkDiscovery.py
	sed -i -- "s/SMTP_PORT/"$smtp_port"/g" /opt/SweetSecurity/networkDiscovery.py
	sed -i -- "s/EMAIL_USER/"$smtp_email"/g" /opt/SweetSecurity/networkDiscovery.py
	sed -i -- "s/EMAIL_PASS/"$smtp_pass"/g" /opt/SweetSecurity/networkDiscovery.py

	#Run scripts for the first time
	python /pids/scripts/pullTorIP.py
	python /pids/scripts/pullMaliciousIP.py
}

install_packages
install_geoip
config_ssmtp
install_loki
install_bro
install_criticalstack
install_es
install_logstash
install_kibana
install_bro_reporting
config_bro_scripts
config_sweet_security_scripts

#Restart services
Info "Restarting ELK services"
service elasticsearch restart
service kibana restart
service logstash restart

#CRON JOBS
echo "0-59/5 * * * * root /usr/local/bro/bin/broctl cron" >> /etc/crontab
echo "00 7/19 * * *  root /pids/scripts/update" >> /etc/crontab
echo "0-59/5 * * * * root python /pids/scripts/scan" >> /etc/crontab 

#Add cron for starting elk

Info "Please reboot"