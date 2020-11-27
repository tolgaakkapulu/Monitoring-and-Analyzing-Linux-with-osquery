# Monitoring and Analyzing Linux with Osquery

Actions to be taken to monitor and analyze Linux with osquery:

<b>Installation</b>
- <b>CentOS</b>
   - export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
   - sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
   - sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
   - sudo apt-get update
   - sudo apt-get install osquery
   
- <b>Ubuntu/Debian</b>
   - curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
   - sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
   - sudo yum-config-manager --enable osquery-s3-rpm
   - sudo yum install osquery
    
<b>Usage</b>
- For <b>file_events</b>, the following lines are added into <b>sysctl</b> if they are not available, if their values are lower, they are updated according to the specified values.
   - vi /etc/sysctl.conf
      - fs.inotify.max_user_watches = 524288
      - fs.inotify.max_user_instances = 256
      - fs.inotify.max_queued_events = 32768
   - systctl -p

- The configuration file is copied under the <b>/etc/osquery</b> directory and the service is restarted.
   - cp osquery.conf /etc/osquery/osquery.conf
   - systemctl restart osqueryd

- The logs are displayed in the directory below.
   - tail -f /var/log/osquery/osqueryd.results.log


<b>Sample Query and Log Outputs</b>
   - <b>proccesses_monitoring:</b> SELECT *, ROUND(( (user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)) * 100, 2) AS cpu_usage FROM processes, (SELECT (  SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0) AS tsb,  SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb  FROM cpu_time) AS cpu_time;
      - {"name":"proccesses_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:52:15 2020 UTC","unixTime":1605772335,"epoch":0,"counter":999,"numerics":false,"columns":{"cmdline":"/usr/sbin/NetworkManager --no-daemon","cpu_usage":"0.48999999999999999","cwd":"/","disk_bytes_read":"4367360","disk_bytes_written":"3448832","egid":"0","euid":"0","gid":"0","itsb":"75202416","name":"NetworkManager","nice":"0","on_disk":"0","parent":"1","path":"/usr/sbin/NetworkManager","pgroup":"815","pid":"815","resident_size":"14692000","root":"/","sgid":"0","start_time":"1605520669","state":"S","suid":"0","system_time":"61980","threads":"3","total_size":"600536000","tsb":"99375244.0","uid":"0","user_time":"55580","wired_size":"0"},"action":"added"}
      
   - <b>mounts_monitoring:</b> SELECT  * FROM mounts;
      - {"name":"mounts_monitoring","hostIdentifier":"osquery-host","calendarTime":"Wed Nov 18 13:31:20 2020 UTC","unixTime":1605706280,"epoch":0,"counter":8,"numerics":false,"decorations":{"host_uuid":"948e5d71-9b3f-4c18-9d61-ba16a67926d0","username":"root"},"columns":{"blocks":"12835960","blocks_available":"11758103","blocks_free":"12417559","blocks_size":"4096","device":"/dev/sda3","device_alias":"/dev/sda3","flags":"rw,seclabel,relatime","inodes":"3276800","inodes_free":"3276315","path":"/data","type":"ext4"},"action":"added"}
      
   - <b>logged_in_users_monitoring: </b>SELECT * FROM logged_in_users WHERE type='user';
      - {"name":"logged_in_users_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:55:00 2020 UTC","unixTime":1605772500,"epoch":0,"counter":4,"numerics":false,"columns":{"host":"X.X.X.X","pid":"2639936","time":"1605766121","tty":"pts/1","type":"user","user":"root"},"action":"removed"}
	  - {"name":"logged_in_users_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:55:00 2020 UTC","unixTime":1605772500,"epoch":0,"counter":4,"numerics":false,"columns":{"host":"X.X.X.X","pid":"2818432","time":"1605772475","tty":"pts/1","type":"user","user":"root"},"action":"added"}
    
   - <b>application_monitoring on CentOS       :</b> SELECT * FROM rpm_packages;<br><b>application_monitoring on Ubuntu/Debian:</b> SELECT * FROM rpm_packages;SELECT * FROM deb_packages;
      - {"name":"application_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 06:41:38 2020 UTC","unixTime":1605768098,"epoch":0,"counter":0,"numerics":false,"columns":{"arch":"x86_64","epoch":"","install_time":"1599812188","name":"xz","package_group":"Unspecified","release":"3.el8","sha1":"5d84e5ff96d36f921231179ce61fdd334820326f","size":"432832","source":"xz-5.2.4-3.el8.src.rpm","vendor":"CentOS","version":"5.2.4"},"action":"added"}
      
   - <b>system_info_monitoring:</b> SELECT * FROM system_info;
      - {"name":"system_info_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:00:18 2020 UTC","unixTime":1605769218,"epoch":0,"counter":2,"numerics":false,"columns":{"board_model":"","board_serial":"","board_vendor":"","board_version":"","computer_name":"osquery-host","cpu_brand":"Common KVM processor","cpu_logical_cores":"4","cpu_microcode":"0x1000065","cpu_physical_cores":"4","cpu_subtype":"6","cpu_type":"x86_64","hardware_model":"Standard PC (i440FX + PIIX, 1996)","hardware_serial":"","hardware_vendor":"QEMU","hardware_version":"pc-i440fx-5.0","hostname":"osquery-host","local_hostname":"osquery-host","physical_memory":"16644755456","uuid":"948e5d71-9b3f-4c18-9d61-ba16a67926d0"},"action":"added"}
      
   - <b>usb_devices_monitoring:</b> SELECT * FROM usb_devices;
      - {"name":"usb_devices_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:02:06 2020 UTC","unixTime":1605769326,"epoch":0,"counter":0,"numerics":false,"columns":{"class":"9","model":"1.1 root hub","model_id":"0001","protocol":"0","removable":"-1","serial":"0000:00:01.2","subclass":"0","usb_address":"1","usb_port":"1","vendor":"Linux Foundation","vendor_id":"1d6b","version":"0418"},"action":"added"}
      - {"name":"usb_devices_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:02:06 2020 UTC","unixTime":1605769326,"epoch":0,"counter":0,"numerics":false,"columns":{"class":"0","model":"QEMU_USB_Tablet","model_id":"0001","protocol":"0","removable":"-1","serial":"28754-0000:00:01.2-1","subclass":"0","usb_address":"1","usb_port":"2","vendor":"Adomax Technology Co., Ltd","vendor_id":"0627","version":"0000"},"action":"added"}
      
   - <b>file_events_monitoring:</b> SELECT * FROM file_events;
      - {"name":"file_events_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:49:22 2020 UTC","unixTime":1605772162,"epoch":0,"counter":0,"numerics":false,"columns":{"action":"ATTRIBUTES_MODIFIED","atime":"1605772112","category":"etc","ctime":"1605772112","gid":"0","hashed":"0","inode":"103361629","md5":"","mode":"0644","mtime":"1605772112","sha1":"","sha256":"","size":"2820","target_path":"/etc/osquery/osquery.conf","time":"1605772112","transaction_id":"0","uid":"0"},"action":"added"}
	  - {"name":"file_events_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:49:22 2020 UTC","unixTime":1605772162,"epoch":0,"counter":0,"numerics":false,"columns":{"action":"UPDATED","atime":"","category":"etc","ctime":"","gid":"","hashed":"-1","inode":"","md5":"","mode":"","mtime":"","sha1":"","sha256":"","size":"","target_path":"/etc/osquery/.osquery.conf.swp","time":"1605772112","transaction_id":"0","uid":""},"action":"added"}
	  - {"name":"file_events_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:49:22 2020 UTC","unixTime":1605772162,"epoch":0,"counter":0,"numerics":false,"columns":{"action":"DELETED","atime":"","category":"etc","ctime":"","gid":"","hashed":"0","inode":"","md5":"","mode":"","mtime":"","sha1":"","sha256":"","size":"","target_path":"/etc/osquery/osquery.conf~","time":"1605772112","transaction_id":"0","uid":""},"action":"added"}
	  - {"name":"file_events_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 07:50:24 2020 UTC","unixTime":1605772224,"epoch":0,"counter":0,"numerics":false,"columns":{"action":"CREATED","atime":"1605772184","category":"etc","ctime":"1605772184","gid":"0","hashed":"1","inode":"103790942","md5":"d41d8cd98f00b204e9800998ecf8427e","mode":"0644","mtime":"1605772184","sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":"0","target_path":"/etc/osquery/test.conf","time":"1605772184","transaction_id":"0","uid":"0"},"action":"added"}
    
   - <b>network_procces_open_sockets_monitoring:</b> SELECT DISTINCT 'CONNECT' AS action, pid, local_address, local_port, remote_address, remote_port, family, protocol, path, NULL AS timestamp FROM process_open_sockets WHERE remote_address <> '' AND remote_port != 0 AND pid > 0;
      - {"name":"network_pos_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 11:51:28 2020 UTC","unixTime":1605786688,"epoch":0,"counter":5,"numerics":false,"columns":{"action":"CONNECT","family":"2","local_address":"X.X.X.X","local_port":"41750","path":"","pid":"3082888","protocol":"6","remote_address":"X.X.X.X","remote_port":"123","timestamp":""},"action":"added"}
      
   - <b>network_listening_ports_monitoring:</b> SELECT * FROM listening_ports WHERE port>0 and address!='::';
      - {"name":"network_lip_monitoring","hostIdentifier":"osquery-host","calendarTime":"Thu Nov 19 11:44:30 2020 UTC","unixTime":1605786270,"epoch":0,"counter":0,"numerics":false,"columns":{"address":"0.0.0.0","family":"2","fd":"6","net_namespace":"4026531992","path":"","pid":"3198844","port":"514","protocol":"6","socket":"30079398"},"action":"added"}
      
   - <b>shadow_monitoring:</b> <u>SELECT * FROM shadow WHERE password_status='active';</u>
      - {"name":"shadow_monitoring","hostIdentifier":"osquery-host","calendarTime":"Fri Nov 20 12:51:03 2020 UTC","unixTime":1605876663,"epoch":0,"counter":1,"numerics":false,"columns":{"expire":"-1","flag":"","hash_alg":"6","inactive":"-1","last_change":"18585","max":"99999","min":"0","password_status":"active","username":"root","warning":"7"},"action":"removed"}
	  - {"name":"shadow_monitoring","hostIdentifier":"osquery-host","calendarTime":"Fri Nov 20 12:51:03 2020 UTC","unixTime":1605876663,"epoch":0,"counter":1,"numerics":false,"columns":{"expire":"-1","flag":"","hash_alg":"6","inactive":"-1","last_change":"18586","max":"99999","min":"0","password_status":"active","username":"root","warning":"7"},"action":"added"
