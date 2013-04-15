#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Python script to perform server configuration files backup over
an SSH connection. For information on how to install, see the
README file.

Author: Renato Candido <renato@liria.com.br>
Copyright 2013 Liria Tecnologia <http://www.liria.com.br>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Changelog:

2013-03-28
Initial commit.

2013-04-15
Added backup of shadow and gshadow files.
"""

from fabric.api import *
from textwrap import dedent
import re
import sys
import ConfigParser

def backup_passwd_group():
    """
    Backup of Linux users, groups and passwords files.
    """
    sudo('cp /etc/passwd ~/config', shell=False)
    sudo('cp /etc/group ~/config', shell=False)
    sudo('cp /etc/shadow ~/config', shell=False)
    sudo('cp /etc/gshadow ~/config', shell=False)

def backup_interfaces():
    """
    Backup of Debian network configuration files.
    """
    sudo('cp /etc/network/interfaces ~/config', shell=False)

def backup_resolv_conf():
    """
    Backup of resolv.conf.
    """
    sudo('cp /etc/resolv.conf ~/config', shell=False)

def backup_rc_local():
    """
    Backup of rc.local.
    """
    sudo('cp /etc/rc.local ~/config', shell=False)

def backup_sudoers():
    """
    Backup of sudo configuration file (sudoers).
    """
    sudo('cp /etc/sudoers ~/config', shell=False)

def backup_crontab():
    """
    Backup of the main crontab file (/etc/crontab).
    """
    sudo('cp /etc/crontab ~/config', shell=False)

def backup_apache():
    """
    Backup of Apache configuration files.
    """
    sudo('cp -R /etc/apache2 ~/config', shell=False)

def backup_varwww():
    """
    Backup of websites' files hosted in /var/www.
    """
    sudo('cp -R /var/www ~/config', shell=False)

def backup_wpaddat():
    """
    Backup of wpadt.dat file (auto proxy configuration).
    """
    sudo('cp /var/www/wpad.dat ~/config', shell=False)

def backup_bind():
    """
    Backup of Bind configuration files.
    """
    sudo('cp -R /etc/bind ~/config', shell=False)

def backup_freedns():
    """
    Backup of Free DNS dynamic DNS service configuration files
    located at /root/freedns.
    """
    sudo('cp -R /root/freedns ~/config', shell=False)

def backup_samba():
    """
    Backup of Samba configuration files.
    """
    sudo('cp -R /etc/samba ~/config', shell=False)

def backup_squid():
    """
    Backup of Squid configuration files.
    """
    sudo('cp -R /etc/squid ~/config', shell=False)

def backup_sarg():
    """
    Backup of Sarg configuration files.
    """
    sudo('cp -R /etc/sarg ~/config', shell=False)

def backup_openvpn():
    """
    Backup of OpenVPN configuration files.
    """
    sudo('cp -R /etc/openvpn ~/config', shell=False)

def backup_dhcp():
    """
    Backup of DHCP configuration files.
    """
    debian_version_str = str(sudo('cat /etc/issue', shell=False))
    debian_version = re.search(r'\d+\.\d+', debian_version_str).group()
    if debian_version == '6.0':
        sudo('cp -R /etc/dhcp ~/config', shell=False)
    elif debian_version == '5.0':
        sudo('cp -R /etc/dhcp3 ~/config', shell=False)

def backup_backup():
    """
    Backup of backup scripts located at /home/backup. This function
    copies all files under /home/backup.
    """
    sudo('mkdir -p ~/config/backup', shell=False)
    sudo('cp /usr/local/bin/backup.sh ~/config/backup', shell=False)
    sudo(dedent("""\
    find /home/backup -maxdepth 1 -type f -exec cp '{}' ~/config/backup \;\
    """), shell=False)

def backup_ssh():
    """
    Backup up of SSH configuration files.
    """
    sudo('cp -R /etc/ssh ~/config', shell=False)

def backup(user, host, key_filename, passphrase,
           user_password, services):
    """
    Main backup function. Based on a set of parameters to connect to a
    server and a list of services, this function connects to the server
    and backs up the configuration files of the services one by one. At
    the end, it compresses the set of configuration files and downloads
    it to the local machine. Everything is done using Fabric.

    The connection is made to the server considering a general user (not
    root), an IP address, an SSH key with a passphrase and the user's
    password to allow the execution of the backup commands using sudo.
    Therefore, it is necessary to configure sudo to allow the user to
    execute a certain set of commands used for backup tasks. Currently,
    the following commands are necessary:

    /bin/cp, /bin/rm, /bin/mkdir, /bin/tar, /bin/cat, /usr/bin/find

    For each service, there must exist a 'backup_<service name>' function
    defined above to copy the configuration files of the service to the
    directory ~/config/backup.
    """

    host_string = user + "@" + host
    with settings(host_string = host_string, key_filename = key_filename,
                  password = passphrase):
        run(':')
        with settings(password = user_password):
            sudo('mkdir -p ~/config', shell=False)
            for service in services:
                func_name = "backup_"+service+"()"
                try:
                    exec func_name
                except:
                    print ("Error on backup of " + service
                           + ". Check if the service is installed")
                    sudo('rm -rf ~/config', shell=False)
                    sys.exit(1)                    
            sudo('tar -C ~/ -czvf config.tar.gz config/*', shell=False)
            sudo('rm -rf ~/config', shell=False)
            get('~/config.tar.gz', './')
            sudo('rm ~/config.tar.gz', shell=False)

def backup_server(config_file):
    """
    Reads a configuration where it is set the parameters of the server to
    connect and the list of services to backup. Based on this information,
    this function calls the main backup function, which performs the backup
    of the services's configuration files. This function can be imported and
    called from another Python scripts.
    """

    config = ConfigParser.ConfigParser()
    try:
        config.read(config_file)
    except:
        print "Error reading config file. Check syntax and spelling errors"
    sections = config.sections()
    if 'server' and 'services' in sections:
        if ('user' and 'host' and 'key_filename' and 'passphrase'
            and 'user_password' in config.options('server')):
            user = config.get('server','user')
            host = config.get('server','host')
            key_filename = config.get('server','key_filename')
            passphrase = config.get('server','passphrase')
            user_password = config.get('server', 'user_password')
            services = config.options('services')
            services_enabled = services[:]
            parse_services_ok = True
            for service in services:
                service_enabled = False
                func_name = "backup_" + service
                if func_name in globals():
                    try:
                        service_enabled = config.getboolean('services',
                                                            service)
                    except:
                        print ("Services must be boolean. Check \""
                               + service + "\"")
                        parse_services_ok = False

                    if not service_enabled:
                        services_enabled.remove(service)
                else:
                    print "Unrecognized service: " + service
                    parse_services_ok = False

            if parse_services_ok:
                backup(user, host, key_filename, passphrase,
                       user_password, services_enabled)

        else:
            print dedent("""\
            Section [server] must have the options: user,\
            host, key_filename, passphrase and user_password.\
            """)

def main():
    """
    Main function of the program. Reads a configuration file passed as
    argument to the program and calls backup_server using this configuration
    file as argument.
    """
    if len(sys.argv) != 2:
        print "Usage " + __file__ + "config-file.conf"
    else:
        config_file = sys.argv[1]
        backup_server(config_file)

if __name__ == '__main__':
    main()
