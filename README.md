# Linux Server Configuration
_Configuring a Linux server to host a web app securely._

# Server details
IP address: `18.194.136.3`

SSH port: `2200`

URL: http://18.194.136.3


# Configuration changes
## Add user
Add user `grader` with command: `sudo adduser grader`
password: grader

## Check for `grader` info
`finger grader`

## Update all currently installed packages

`apt-get update` - to update the package indexes

`apt-get upgrade` - to actually upgrade the installed packages

If at login the message `*** System restart required ***` is display, run the followingOnt
command to reboot the machine:

`reboot`

## Set-up SSH keys for user grader
As root user do:
```
sudo cat /etc/sudoers
sudo ls /etc/sudoers.d
```
Give sudo access to grader:
```
sudo cat /etc/sudoers
sudo cp /etc/sudoers.d/vagrant /ect/sudoers.d/student
sudo nano /etc/sudoers.d/student
```
Change the word vagrant to student

On the local machine, generate key pair:
ssh keygen
/Users/williamdelrosario/.ssh/linuxCourse
There's no passphrase, just press the return key


As root user do:
``` mkdir .ssh
    touch .ssh/authorized_keys
```
On local machine, copy the text in this command
`cat .ssh/linuxCourse.pub`

to server and save it:
``` nano .ssh/authorized_keys
    chmod 700 .ssh
    chmod 644 .ssh/authorized_keys
```

Can now login as the `grader` user using the command:
`ssh grader@18.194.136.3 -p 2200 -i .ssh/linuxCourse`



## Disable root login
Change the following line in the file `/etc/ssh/sshd_config`:

From `PermitRootLogin without-password` to `PermitRootLogin no`.

Also, uncomment the following line so it reads:
```
PasswordAuthentication no
```

Do `service ssh restart` for the changes to take effect.

Will now do all commands using the `grader` user, using `sudo` when required.

## Change timezone to UTC
Check the timezone with the `date` command. This will display the current timezone after the time.
If it's not UTC change it like this:

`sudo timedatectl set-timezone UTC`

## Change SSH port from 22 to 2200
Edit the file `/etc/ssh/sshd_config` and change the line `Port 22` to:

`Port 2200`

Then restart the SSH service:

`sudo service ssh restart`

Will now need to use the following command to login to the server:

`ssh grader@18.194.136.3 -p 2200 -i .ssh/linuxCourse`

## Configuration Uncomplicated Firewall (UFW)
By default, block all incoming connections on all ports:

`sudo ufw default deny incoming`

Allow outgoing connection on all ports:

`sudo ufw default allow outgoing`

Allow incoming connection for SSH on port 2200:

`sudo ufw allow 2200/tcp`

Allow incoming connections for HTTP on port 80:

`sudo ufw allow www`

Allow incoming connection for NTP on port 123:

`sudo ufw allow ntp`

To check the rules that have been added before enabling the firewall use:

`sudo ufw show added`

To enable the firewall, use:

`sudo ufw enable`

To check the status of the firewall, use:

`sudo ufw status`

## Install Apache to serve a Python mod_wsgi application
Install Apache:

`sudo apt-get install apache2`

Install the `libapache2-mod-wsgi` package:

`sudo apt-get install libapache2-mod-wsgi`

## Install and configure PostgreSQL
Install PostgreSQL with:

`sudo apt-get install postgresql postgresql-contrib`

Create a PostgreSQL user called `catalog` with:

`sudo -u postgres createuser -P catalog`

You are prompted for a password. This creates a normal user that can't create
databases, roles (users).

Create an empty database called `catalog` with:

`sudo -u postgres createdb -O catalog catalog`


## Install Flask, SQLAlchemy, etc
Issue the following commands:
```
sudo apt-get install python-psycopg2 python-flask
sudo apt-get install python-sqlalchemy python-pip
sudo pip install oauth2client
sudo pip install requests
sudo pip install httplib2
sudo pip install flask-seasurf
```

An alternative to installing system-wide python modules is to create a virtual
environment for each application using the [virualenv][4] package.

## Install Git version control software
`sudo apt-get install git`

## Clone the repository that contains Project 3 Catalog app
Move to the `/srv` directory and clone the repository as the `www-data` user.
The `www-data` user will be used to run the catalog app.
```
cd /srv
sudo mkdir FavApps
sudo chown grader:grader FavApps/
sudo -u grader git clone https://github.com/william251082/FavApps.git FavApps
```
On ```/srv/FavApps$```
Create a ```FavApps.conf``` file using this command:
```sudo nano /etc/apache2/sites-available/FavApps.conf```

```
<VirtualHost *:80>
                ServerAdmin admin@mywebsite.com
                WSGIScriptAlias / /srv/FavApps/FavApps.wsgi
                <Directory /srv/FavApps>
                        Require all granted
                </Directory>
                Alias /static /srv/FavApps/static
                <Directory /srv/FavApps/static/>
                        Require all granted
                </Directory>
                ErrorLog ${APACHE_LOG_DIR}/error.log
                LogLevel warn
                CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

Disable 000-default.conf file in /etc/apache2/sites-available.
```sudo a2dissite 000-default.conf```


Enable FavApps.conf file in /etc/apache2/sites-available.
```sudo a2ensite FavApps.conf```


Restart apache2 server with
```sudo service apache2 restart```


Create FavApps.wsgi file inside FavApps.
```
#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/srv/FavApps/")

from FavApps import app as application
application.secret_key = ‘SECRET KEY’
```

Update the permissions for the uploads folder to enable read and write.
```chmod 777 /srv/FavApps/```
```chown grader:grader /srv/FavApps/```


Restart the apache2 server.
```sudo service apache2 restart```

Check for errors
```sudo tail /var/log/apache2/error.log```

## Edit and run the files using sqlite to PostgreSql

Edit the lines of these files

```/srv/FavApps$ sudo nano database_setup.py```
```/srv/FavApps$ sudo nano finalProject.py```
```/srv/FavApps$ sudo nano lotsofapps.py```


From 
```engine = create_engine('sqlite:///appmakerinfowithusers.db')```

To
```engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine```

## Change the PostgreSql's password

```/srv/FavApps$ sudo -u postgres psql```

```
psql (9.5.9)
Type "help" for help.

postgres=# \du
postgres=# alter role catalog with password 'catalog';
ALTER ROLE
```

Check Database

```
postgres=# \l
postgres=# \q
```

## Edit JSON and FavaApps.wsgi files' path to ```/srv/FavApps```

```/srv/FavApps$ sudo nano client_secrets.json```
```/srv/FavApps$ sudo nano FavApps.wsgi```

```sudo service apache2 restart```





