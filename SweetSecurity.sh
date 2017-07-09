

#Configure Sweet Security Scripts
sudo mkdir /opt/SweetSecurity
sudo cp SweetSecurity/pullMaliciousIP.py /opt/SweetSecurity/
sudo cp SweetSecurity/pullTorIP.py /opt/SweetSecurity/
#Run scripts for the first time
sudo python /opt/SweetSecurity/pullTorIP.py
sudo python /opt/SweetSecurity/pullMaliciousIP.py

#Configure Logstash Conf File
sudo sed -i -- "s/SMTP_HOST/"$smtpHost"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/SMTP_PORT/"$smtpPort"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/EMAIL_USER/"$emailAddr"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/EMAIL_PASS/"$emailPwd"/g" /opt/logstash/logstash.conf


cd /home/pi
sudo cp SweetSecurity/networkDiscovery.py /opt/SweetSecurity/networkDiscovery.py
sudo cp SweetSecurity/SweetSecurityDB.py /opt/SweetSecurity/SweetSecurityDB.py
#Configure Network Discovery Scripts
sudo sed -i -- "s/SMTP_HOST/"$smtpHost"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/SMTP_PORT/"$smtpPort"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/EMAIL_USER/"$emailAddr"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/EMAIL_PASS/"$emailPwd"/g" /opt/SweetSecurity/networkDiscovery.py


#Restart services
echo "Restarting ELK services"
sudo service elasticsearch restart
sudo service kibana restart
sudo service logstash restart


#Deploy and start BroIDS
echo "Deploying and starting BroIDS"
sudo /opt/nsm/bro/bin/broctl deploy
sudo /opt/nsm/bro/bin/broctl start
