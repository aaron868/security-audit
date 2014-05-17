require 'spec_helper'

describe "Red Hat Enterprise Linux 6 Security Technical Implementation Guide Audit for #{ENV['TARGET_HOST']}" do

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38437
    it "V-38437 Automated file system mounting tools must not be enabled unless needed." do
        # Check: To verify the "autofs" service is disabled, run the following command: 
        #       chkconfig --list autofs
        #       If properly configured, the output should be the following: 
        #       autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Verify the "autofs" service is not running:
        #       # service autofs status
        #       If the autofs service is enabled or running, this is a finding.
        expect( package('autofs')).not_to be_installed
        expect( service('autofs')).not_to be_enabled
        expect( service('autofs')).not_to be_running
        # Fix: If the "autofs" service is not needed to dynamically mount NFS filesystems or removable media, 
        #      disable the service for all runlevels: 
        #       # chkconfig --level 0123456 autofs off
        #       Stop the service if it is already running: 
        #       # service autofs stop
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38438
    it "V-38438 Auditing must be enabled at boot by setting a kernel parameter." do
        # Check: Inspect the kernel boot arguments (which follow the word "kernel") in "/etc/grub.conf". If they include "audit=1", 
        # then auditing is enabled at boot time. 
        #       If auditing is not enabled at boot time, this is a finding.
        expect( command('grep audit=1 /etc/grub.conf') ).not_to return_stdout ""
        # Fix: To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument "audit=1" 
        #      to the kernel line in "/etc/grub.conf", in the manner below: 
        #       kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38439
    it "V-38439 The system must provide automated support for account management functions." do
        # Check: Interview the SA to determine if there is an automated system for managing user accounts, preferably integrated with 
        #        an existing enterprise user management system.
        #       If there is not, this is a finding.
        pending( "Manual step" )
        # Fix: Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate. 
        #      If possible, this system should integrate with an existing enterprise user management system, such as, one based Active 
        #      Directory or Kerberos.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38443
    it "V-38443 The /etc/gshadow file must be owned by root." do
        # Check: To check the ownership of "/etc/gshadow", run the command: 
        #       $ ls -l /etc/gshadow
        #       If properly configured, the output should indicate the following owner: "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/gshadow')).to be_owned_by 'root'
        # Fix: To properly set the owner of "/etc/gshadow", run the command: 
        #       # chown root /etc/gshadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38444
    it "V-38444 The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets." do
        # Check: Inspect the file "/etc/sysconfig/ip6tables" to determine the default policy for the INPUT chain. It should be set to DROP. 
        #       # grep ":INPUT" /etc/sysconfig/ip6tables
        #       If the default policy for the INPUT chain is not set to DROP, this is a finding.
        if $environment['ipv6Enabled']
            expect( command('grep \':INPUT ACCEPT [0:0]\' /etc/sysconfig/ip6tables') ).not_to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/ip6tables": 
        #       :INPUT DROP [0:0]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38445
    it "V-38445 Audit log files must be group-owned by root." do
        # Check: Run the following command to check the group owner of the system audit logs: 
        #       grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n
        #       Audit logs must be group-owned by root. 
        #       If they are not, this is a finding.
        expect( file('/etc/audit/auditd.conf')).to be_grouped_into 'root'
        # Fix: Change the group owner of the audit log files with the following command: 
        #       # chgrp root [audit_file]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38446
    it "V-38446 The mail system must forward all mail for root to one or more system administrators." do
        # Check: Find the list of alias maps used by the Postfix mail server:
        #       # postconf alias_maps
        #       Query the Postfix alias maps for an alias for "root":
        #       # postmap -q root <alias_map>
        #       If there are no aliases configured for root that forward to a monitored email address, this is a finding.
        expect( mail_alias('root')).to be_aliased_to $environment['rootEmailAddress']
        # Fix: Set up an alias for root that forwards to a monitored email address:
        #       # echo "root: <system.administrator>@mail.mil" >> /etc/aliases
        #       # newaliases
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38447
    it "V-38447 The system package management tool must verify contents of all files associated with packages.", :slow => true do
        # Check: The following command will list which files on the system have file hashes different from what is expected 
        #        by the RPM database. 
        #       # rpm -Va | grep '$1 ~ /..5/ && $2 != "c"'
        #       If there is output, this is a finding.
        expect( command('rpm -Va | grep \'$1 ~ /..5/ && $2 != "c"\'') ).to return_stdout ""
        # Fix: The RPM package management system can check the hashes of installed software packages, including many that are important 
        #       to system security. Run the following command to list which files on the system have hashes that differ from what is expected
        #       by the RPM database: 
        #       # rpm -Va | grep '^..5'
        #       A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If 
        #       the file that has changed was not expected to then refresh from distribution media or online repositories. 
        #       rpm -Uvh [affected_package]
        #       OR 
        #       yum reinstall [affected_package]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38448
    it "V-38448 The /etc/gshadow file must be group-owned by root." do
        # Check: To check the group ownership of "/etc/gshadow", run the command: 
        #       $ ls -l /etc/gshadow
        #       If properly configured, the output should indicate the following group-owner. "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/gshadow')).to be_grouped_into 'root'
        # Fix: To properly set the group owner of "/etc/gshadow", run the command: 
        #       # chgrp root /etc/gshadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38449
    it "V-38449 The /etc/gshadow file must have mode 0000." do
        # Check: To check the permissions of "/etc/gshadow", run the command: 
        #       $ ls -l /etc/gshadow
        #       If properly configured, the output should indicate the following permissions: "----------" 
        #       If it does not, this is a finding.
        expect( file('/etc/shadow')).to be_mode 000
        # Fix: To properly set the permissions of "/etc/gshadow", run the command: 
        #       # chmod 0000 /etc/gshadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38450
    it "V-38450 The /etc/passwd file must be owned by root." do
        # Check: To check the ownership of "/etc/passwd", run the command: 
        #       $ ls -l /etc/passwd
        #       If properly configured, the output should indicate the following owner: "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/passwd')).to be_owned_by 'root'
        # Fix: To properly set the owner of "/etc/passwd", run the command: 
        #       # chown root /etc/passwd
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38451
    it "V-38451 The /etc/passwd file must be group-owned by root." do
        # Check: To check the group ownership of "/etc/passwd", run the command: 
        #       $ ls -l /etc/passwd
        #       If properly configured, the output should indicate the following group-owner. "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/passwd')).to be_grouped_into 'root'
        # Fix: To properly set the group owner of "/etc/passwd", run the command: 
        #       # chgrp root /etc/passwd
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38452
    it "V-38452 The system package management tool must verify permissions on all files and directories associated with packages.", :slow => true do
        # Check: The following command will list which files and directories on the system have
        # permissions different from what is         expected by the RPM database:        # rpm -Va
        # | grep '^.M'       If there is any output, for each file or directory found, find the
        # associated RPM package and compare the RPM-expected permissions with the actual
        # permissions on the file or directory:       # rpm -qf [file or directory name]       # rpm
        # -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" [package] | grep  [filename]
        # # ls -lL [filename]       If the existing permissions are more permissive than those
        # expected by RPM, this is a finding.
        expect( command('rpm -Va  | grep \'^.M\'') ).to return_stdout ""
        # Fix: The RPM package management system can restore file access permissions of package files and directories. The following 
        #      command will update permissions on files and directories with permissions different from what is expected by the RPM database: 
        #       # rpm --setperms [package]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38453
    it "V-38453 The system package management tool must verify group-ownership on all files and directories associated with packages.", :slow => true do
        # Check: The following command will list which files on the system have group-ownership different from what is expected by the 
        #        RPM database: 
        #       # rpm -Va | grep '^......G'
        #       If there is output, this is a finding.
        expect( command('rpm -Va  | grep \'^......G\'') ).to return_stdout ""
        # Fix: The RPM package management system can restore group-ownership of the package files and directories. The following command will 
        #      update files and directories with group-ownership different from what is expected by the RPM database: 
        #       # rpm -qf [file or directory name]
        #       # rpm --setugids [package]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38454
    it "V-38454 The system package management tool must verify ownership on all files and directories associated with packages.", :slow => true do
        # Check: The following command will list which files on the system have ownership different from what is expected by the RPM database: 
        #       # rpm -Va | grep '^.....U'
        #       If there is output, this is a finding.
        expect( command('rpm -Va  | grep \'^.....U\'') ).to return_stdout ""
        # Fix: The RPM package management system can restore ownership of package files and directories. The following command will update files and directories with ownership different from what is expected by the RPM database: 
        #       # rpm -qf [file or directory name]
        #       # rpm --setugids [package]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38455
    it "V-38455 The system must use a separate file system for /tmp." do
        # Check: Run the following command to determine if "/tmp" is on its own partition or logical volume: 
        #       $ mount | grep "on /tmp "
        #       If "/tmp" has its own partition or volume group, a line will be returned. 
        #       If no line is returned, this is a finding.
        expect( command('grep "[[:space:]]/tmp[[:space:]]" /etc/fstab') ).not_to return_stdout ""
        # Fix: The "/tmp" directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38456
    it "V-38456 The system must use a separate file system for /var." do
        # Check: Run the following command to determine if "/var" is on its own partition or logical volume: 
        #       $ mount | grep "on /var "
        #       If "/var" has its own partition or volume group, a line will be returned. 
        #       If no line is returned, this is a finding.
        expect( command('grep "[[:space:]]/var[[:space:]]" /etc/fstab') ).not_to return_stdout ""
        # Fix: The "/var" directory is used by daemons and other system services to store frequently-changing data. Ensure that "/var" has its own partition or logical volume at installation time, or migrate it using LVM.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38457
    it "V-38457 The /etc/passwd file must have mode 0644 or less permissive." do
        # Check: To check the permissions of "/etc/passwd", run the command: 
        #       $ ls -l /etc/passwd
        #       If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
        #       If it does not, this is a finding.
        expect( file('/etc/passwd')).to be_mode 644
        # Fix: To properly set the permissions of "/etc/passwd", run the command: 
        #       # chmod 0644 /etc/passwd
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38458
    it "V-38458 The /etc/group file must be owned by root." do
        # Check: To check the ownership of "/etc/group", run the command: 
        #       $ ls -l /etc/group
        #       If properly configured, the output should indicate the following owner: "root" 
        #       If it does not, this is a finding.
         expect( file('/etc/group')).to be_owned_by 'root'
        # Fix: To properly set the owner of "/etc/group", run the command: 
        #       # chown root /etc/group
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38459
    it "V-38459 The /etc/group file must be group-owned by root." do
        # Check: To check the group ownership of "/etc/group", run the command: 
        #       $ ls -l /etc/group
        #       If properly configured, the output should indicate the following group-owner. "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/group')).to be_grouped_into 'root'
        # Fix: To properly set the group owner of "/etc/group", run the command: 
        #       # chgrp root /etc/group
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38460
    it "V-38460 The NFS server must not have the all_squash option enabled." do
        # Check: If the NFS server is read-only, in support of unrestricted access to organizational content, this is not applicable.
        #       The related "root_squash" option provides protection against remote administrator-level access to NFS server content.  Its use is not a finding.
        #       To verify the "all_squash" option has been disabled, run the following command:
        #       # grep all_squash /etc/exports
        #       If there is output, this is a finding.
        if property[:roles].include? 'nfsServer'
            expect( command('grep all_squash /etc/exports') ).to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: Remove any instances of the "all_squash" option from the file "/etc/exports".  Restart the NFS daemon for the changes to take effect.
        #       # service nfs restart
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38461
    it "V-38461 The /etc/group file must have mode 0644 or less permissive." do
        # Check: To check the permissions of "/etc/group", run the command: 
        #       $ ls -l /etc/group
        #       If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
        #       If it does not, this is a finding.
        expect( file('/etc/group')).to be_mode 644
        # Fix: To properly set the permissions of "/etc/group", run the command: 
        #       # chmod 644 /etc/group
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38462
    it "V-38462 The RPM package management tool must cryptographically verify the authenticity of all software packages during installation." do
        # Check: Verify RPM signature validation is not disabled:
        #       # grep nosignature /etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc
        #       If any configuration is found, this is a finding.
        expect( file('/etc/rpmrc')).not_to be_file
        expect( file('/root/.rpmrc')).not_to be_file
        expect( command('grep nosignature /usr/lib/rpm/rpmrc') ).to return_stdout ""
        # Fix: Edit the RPM configuration files containing the "nosignature" option and remove the option.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38463
    it "V-38463 The system must use a separate file system for /var/log." do
        # Check: Run the following command to determine if "/var/log" is on its own partition or logical volume: 
        #       $ mount | grep "on /var/log "
        #       If "/var/log" has its own partition or volume group, a line will be returned. 
        #       If no line is returned, this is a finding.
        expect( command('grep "[[:space:]]/var/log[[:space:]]" /etc/fstab') ).not_to return_stdout ""
        # Fix: System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38464
    it "V-38464 The audit system must take appropriate action when there are disk errors on the audit storage volume." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when disk errors occur:
        #       # grep disk_error_action /etc/audit/auditd.conf
        #       disk_error_action = [ACTION]
        #       If the system is configured to "suspend" when disk errors occur or "ignore" them, this is a finding.
        expect( command('grep --ignore-case \'disk_error_action = SUSPEND\' /etc/audit/auditd.conf') ).to return_stdout ""
        expect( command('grep --ignore-case \'disk_error_action = IGNORE\' /etc/audit/auditd.conf') ).to return_stdout ""
        # Fix: Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 
        #       disk_error_action = [ACTION]
        #       Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 
        #       "ignore"
        #       "syslog"
        #       "exec"
        #       "suspend"
        #       "single"
        #       "halt"
        #       Set this to "syslog", "exec", "single", or "halt".
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38465
    it "V-38465 Library files must have mode 0755 or less permissive." do
        # Check: System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 
        #       /lib
        #       /lib64
        #       /usr/lib
        #       /usr/lib64
        #       Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable. To find shared libraries that are group-writable or world-writable, run the following command for each directory [DIR] which contains shared libraries: 
        #       $ find -L [DIR] -perm /022
        #       If any of these files are group-writable or world-writable, this is a finding.
        expect( file('/lib')).to be_mode 555
        expect( file('/lib64')).to be_mode 555
        expect( file('/usr/lib')).to be_mode 555
        expect( file('/usr/lib64')).to be_mode 555
        # Fix: System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 
        #       /lib
        #       /lib64
        #       /usr/lib
        #       /usr/lib64
        #       If any file in these directories is found to be group-writable or world-writeable correct its permission with the following command: 
        #       # chmod go-w [FILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38466
    it "V-38466 Library files must be owned by root." do
        # Check: System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 
        #       /lib
        #       /lib64
        #       /usr/lib
        #       /usr/lib64
        #       Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable.  To find shared libraries that are not owned by "root", run the following command for each directory [DIR] which contains shared libraries: 
        #       $ find -L [DIR] \! -user root
        #       If any of these files are not owned by root, this is a finding.
        expect( file('/lib')).to be_owned_by 'root'
        expect( file('/lib64')).to be_owned_by 'root'
        expect( file('/usr/lib')).to be_owned_by 'root'
        expect( file('/usr/lib64')).to be_owned_by 'root'
    # Fix: System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 
        #       /lib
        #       /lib64
        #       /usr/lib
        #       /usr/lib64
        #       If any file in these directories is found to be owned by a user other than root, correct its ownership with the following command: 
        #       # chown root [FILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38467
    it "V-38467 The system must use a separate file system for the system audit data path." do
        # Check: Run the following command to determine if "/var/log/audit" is on its own partition or logical volume: 
        #       $ mount | grep "on /var/log/audit "
        #       If "/var/log/audit" has its own partition or volume group, a line will be returned. 
        #       If no line is returned, this is a finding.
        expect( command('grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab') ).not_to return_stdout ""
        # Fix: Audit logs are stored in the "/var/log/audit" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38468
    it "V-38468 The audit system must take appropriate action when the audit storage volume is full." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when the audit storage volume is full:
        #       # grep disk_full_action /etc/audit/auditd.conf
        #       disk_full_action = [ACTION]
        #       If the system is configured to "suspend" when the volume is full or "ignore" that it is full, this is a finding.
        expect( command('grep --ignore-case \'disk_full_action = SUSPEND\' /etc/audit/auditd.conf') ).to return_stdout ""
        expect( command('grep --ignore-case \'disk_full_action = IGNORE\' /etc/audit/auditd.conf') ).to return_stdout ""
        # Fix: The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 
        #       disk_full_action = [ACTION]
        #       Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 
        #       "ignore"
        #       "syslog"
        #       "exec"
        #       "suspend"
        #       "single"
        #       "halt"
        #       Set this to "syslog", "exec", "single", or "halt".
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38469
    it "V-38469 All system command files must have mode 0755 or less permissive." do
        # Check: System executables are stored in the following directories by default: 
        #       /bin
        #       /usr/bin
        #       /usr/local/bin
        #       /sbin
        #       /usr/sbin
        #       /usr/local/sbin
        #       All files in these directories should not be group-writable or world-writable. To find system executables that are group-writable or world-writable, run the following command for each directory [DIR] which contains system executables: 
        #       $ find -L [DIR] -perm /022
        #       If any system executables are found to be group-writable or world-writable, this is a finding.
        expect( file('/bin')).to be_mode 555
        expect( file('/usr/bin')).to be_mode 555
        expect( file('/usr/local/bin')).to be_mode 555
        expect( file('/sbin')).to be_mode 555
        expect( file('/usr/sbin')).to be_mode 555
        expect( file('/usr/local/sbin')).to be_mode 555
        # Fix: System executables are stored in the following directories by default: 
        #       /bin
        #       /usr/bin
        #       /usr/local/bin
        #       /sbin
        #       /usr/sbin
        #       /usr/local/sbin
        #       If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command: 
        #       # chmod go-w [FILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38470
    it "V-38470 The audit system must alert designated staff members when the audit storage volume approaches capacity." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low: 
        #       # grep space_left_action /etc/audit/auditd.conf
        #       space_left_action = email
        #       If the system is not configured to send an email to the system administrator when disk space is starting to run low, this is a finding.
        expect( command('grep --ignore-case "^space_left_action = email" /etc/audit/auditd.conf') ).not_to return_stdout ""
        # Fix: The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 
        #       space_left_action = [ACTION]
        #       Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 
        #       "ignore"
        #       "syslog"
        #       "email"
        #       "exec"
        #       "suspend"
        #       "single"
        #       "halt"
        #       Set this to "email" (instead of the default, which is "suspend") as it is more likely to get prompt attention.
        #       RHEL-06-000521 ensures that the email generated through the operation "space_left_action" will be sent to an administrator.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38471
    it "V-38471 The system must forward audit records to the syslog service." do
        # Check: Verify the audispd plugin is active:
        #       # grep active /etc/audisp/plugins.d/syslog.conf
        #       If the "active" setting is missing or set to "no", this is a finding.
        expect( command('grep "^active = yes" /etc/audisp/plugins.d/syslog.conf')).not_to return_stdout ""
        # Fix: Set the "active" line in "/etc/audisp/plugins.d/syslog.conf" to "yes".  Restart the auditd process.
        #       # service auditd restart
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38472
    it "V-38472 All system command files must be owned by root." do
        # Check: System executables are stored in the following directories by default: 
        #       /bin
        #       /usr/bin
        #       /usr/local/bin
        #       /sbin
        #       /usr/sbin
        #       /usr/local/sbin
        #       All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by "root", run the following command for each directory [DIR] which contains system executables: 
        #       $ find -L [DIR] \! -user root
        #       If any system executables are found to not be owned by root, this is a finding.
        expect( file('/bin')).to be_owned_by 'root'
        expect( file('/usr/bin')).to be_owned_by 'root'
        expect( file('/usr/local/bin')).to be_owned_by 'root'
        expect( file('/sbin')).to be_owned_by 'root'
        expect( file('/usr/sbin')).to be_owned_by 'root'
        expect( file('/usr/local/sbin')).to be_owned_by 'root'
        # Fix: System executables are stored in the following directories by default: 
        #       /bin
        #       /usr/bin
        #       /usr/local/bin
        #       /sbin
        #       /usr/sbin
        #       /usr/local/sbin
        #       If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command: 
        #       # chown root [FILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38473
    it "V-38473 The system must use a separate file system for user home directories." do
        # Check: Run the following command to determine if "/home" is on its own partition or logical volume: 
        #       $ mount | grep "on /home "
        #       If "/home" has its own partition or volume group, a line will be returned. 
        #       If no line is returned, this is a finding.
        expect( command('grep "[[:space:]]/home[[:space:]]" /etc/fstab') ).not_to return_stdout ""
        # Fix: If user home directories will be stored locally, create a separate partition for "/home" at installation time (or migrate it later using LVM). If "/home" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38474
    it "V-38474 The system must allow locking of graphical desktop sessions." do
        # Check: Verify the keybindings for the Gnome screensaver:
        #       # gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver
        #       If no output is visible, this is a finding.
        if property[:gnomeInstalled] 
            expect( command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver') ).not_to return_stdout ""
        else    
            pending( "Not Applicable" )
        end
        # Fix: Run the following command to set the Gnome desktop keybinding for locking the screen:
        #       # gconftool-2
        #       --direct \
        #       --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
        #       --type string \
        #       --set /apps/gnome_settings_daemon/keybindings/screensaver "<Control><Alt>l"
        #       Another keyboard sequence may be substituted for "<Control><Alt>l", which is the default for the Gnome desktop.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38475
    it "V-38475 The system must require passwords to contain a minimum of 14 characters." do
        # Check: To check the minimum password length, run the command: 
        #       $ grep PASS_MIN_LEN /etc/login.defs
        #       The DoD requirement is "14". 
        #       If it is not set to the required value, this is a finding.
        expect( file('/etc/login.defs')).to contain /^PASS_MIN_LEN 14/
        # Fix: To specify password length requirements for new accounts, edit the file "/etc/login.defs" and add or correct the following lines: 
        #       PASS_MIN_LEN 14
        #       The DoD requirement is "14". If a program consults "/etc/login.defs" and also another PAM module (such as "pam_cracklib") during a password change operation, then the most restrictive must be satisfied.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38476
    it "V-38476 Vendor-provided cryptographic certificates must be installed to verify the integrity of system software." do
        # Check: To ensure that the GPG key is installed, run: 
        #       $ rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey
        #       The command should return the string below: 
        #       gpg(Red Hat, Inc. (release key <security@redhat.com>)
        #       If the Red Hat GPG Key is not installed, this is a finding.
        if $environment['linuxFlavor'] == 'centos'
            expect( command('gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6| grep fingerprint') ).to return_stdout "Key fingerprint = C1DA C52D 1664 E8A4 386D  BA43 0946 FCA2 C105 B9DE"
            expect( command('rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey| grep "gpg(CentOS-6 Key (CentOS 6 Official Signing Key) <centos-6-key@centos.org>)"') ).not_to return_stdout ""
        elsif $environment['linuxFlavor'] == 'redhat'
            expect( command('rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey| grep "gpg(Red Hat, Inc. (release key <security@redhat.com>)"') ).not_to return_stdout ""
        elsif $environment['linuxFlavor'] == 'oracle'
            expect( command('rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey| grep "gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)"') ).not_to return_stdout ""
        else
            fail("linuxFlavor set to unknown value")
        end 
        # Fix: To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them if desired), the Red Hat GPG key must properly be installed. To ensure the GPG key is installed, run: 
        #       # rhn_register
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38477
    it "V-38477 Users must not be able to change passwords more than once every 24 hours." do
        # Check: To check the minimum password age, run the command: 
        #       $ grep PASS_MIN_DAYS /etc/login.defs
        #       The DoD requirement is 1. 
        #       If it is not set to the required value, this is a finding.
        expect( file('/etc/login.defs')).to contain /^PASS_MIN_DAYS 1/
        # Fix: To specify password minimum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 
        #       PASS_MIN_DAYS [DAYS]
        #       A value of 1 day is considered sufficient for many environments. The DoD requirement is 1.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38478
    it "V-38478 The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite." do
        # Check: If the system uses RHN or is an RHN Satellite, this is not applicable.
        #       To check that the "rhnsd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "rhnsd" --list
        #       Output should indicate the "rhnsd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "rhnsd" --list
        #       "rhnsd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "rhnsd" is disabled through current runtime configuration: 
        #       # service rhnsd status
        #       If the service is disabled the command will return the following output: 
        #       rhnsd is stopped
        #       If the service is running, this is a finding.
        if $environment['linuxFlavor'] == 'centos'
            pending("Not applicable")
        elsif $environment['linuxFlavor'] == 'redhat'
            if property[:roles].include? 'redHatNetworkService'
                pending("Not applicable")
            else
                expect( service('rhnsd')).not_to be_enabled
                expect( service('rhnsd')).not_to be_running
            end
        elsif $environment['linuxFlavor'] == 'oracle'
            pending("Not applicable")
        else
            fail("linuxFlavor set to unknown value")
        end 
        # Fix: The Red Hat Network service automatically queries Red Hat Network servers to determine whether there are any actions that should be executed, such as package updates. This only occurs if the system was registered to an RHN server or satellite and managed as such. The "rhnsd" service can be disabled with the following command: 
        #       # chkconfig rhnsd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38479
    it "V-38479 User passwords must be changed at least every 60 days." do
        # Check: To check the maximum password age, run the command: 
        #       $ grep PASS_MAX_DAYS /etc/login.defs
        #       The DoD requirement is 60. 
        #       If it is not set to the required value, this is a finding.
        expect( file('/etc/login.defs')).to contain /^PASS_MAX_DAYS 60/
        # Fix: To specify password maximum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 
        #       PASS_MAX_DAYS [DAYS]
        #       The DoD requirement is 60.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38480
    it "V-38480 Users must be warned 7 days in advance of password expiration." do
        # Check: To check the password warning age, run the command: 
        #       $ grep PASS_WARN_AGE /etc/login.defs
        #       The DoD requirement is 7. 
        #       If it is not set to the required value, this is a finding.
        expect( file('/etc/login.defs')).to contain /^PASS_WARN_AGE 7/
        # Fix: To specify how many days prior to password expiration that a warning will be issued to users, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 
        #       PASS_WARN_AGE [DAYS]
        #       The DoD requirement is 7.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38481
    it "V-38481 System security patches and updates must be installed and up-to-date." do
        # Check: If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available: 
        #       # yum check-update
        #       If the system is not configured to update from one of these sources, run the following command to list when each package was last updated: 
        #       $ rpm -qa -last
        #       Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates. 
        #       If updates are not installed, this is a finding.
        expect( command('yum check-update') ).to return_exit_status 0
        # Fix: If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates: 
        #       # yum update
        #       If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using "rpm".
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38482
    it "V-38482 The system must require passwords to contain at least one numeric character." do
        # Check: To check how many digits are required in a password, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       The "dcredit" parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as "dcredit=-1". 
        #       If dcredit is not found or not set to the required value, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac')).to contain "dcredit=-1"
        # Fix: The pam_cracklib module's "dcredit" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit. Add "dcredit=-1" after pam_cracklib.so to require use of a digit in passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38483
    it "V-38483 The system package management tool must cryptographically verify the authenticity of system software packages during installation." do
        # Check: To determine whether "yum" is configured to use "gpgcheck", inspect "/etc/yum.conf" and ensure the following appears in the "[main]" section: 
        #       gpgcheck=1
        #       A value of "1" indicates that "gpgcheck" is enabled. Absence of a "gpgcheck" line or a setting of "0" indicates that it is disabled. 
        #       If GPG checking is not enabled, this is a finding.
        #       If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
        expect( command('grep "^gpgcheck=1" /etc/yum.conf') ).not_to return_stdout ""
        # Fix: The "gpgcheck" option should be used to ensure checking of an RPM package's signature always occurs prior to its installation. To configure yum to check package signatures before installing them, ensure the following line appears in "/etc/yum.conf" in the "[main]" section: 
        #       gpgcheck=1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38484
    it "V-38484 The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh." do
        # Check: Verify the value associated with the "PrintLastLog" keyword in /etc/ssh/sshd_config:
        #       # grep -i PrintLastLog /etc/ssh/sshd_config
        #       If the value is not set to "yes", this is a finding.  If the "PrintLastLog" keyword is not present, this is not a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^PrintLastLog yes/
        # Fix: Update the "PrintLastLog" keyword to "yes" in /etc/ssh/sshd_config:
        #       PrintLastLog yes
        #       While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last login date and time, it is preferred to have the value explicitly documented.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38485
    it "V-38485 The operating system, upon successful logon, must display to the user the date and time of the last logon or access via a local console or tty." do
        # Check: Verify there are no "hushlogin" files active on the system:
        #       # ls -l /etc/hushlogins
        #       For each home directory stored in "/etc/passwd":
        #       # ls ~<userid>/.hushlogin
        #       If there are any "hushlogin" files on the system, this is a finding.
        expect( file('/etc/hushlogins')).not_to be_file
        expect( command('find /home -name \'.hushlogin\'') ).to return_stdout ""
        # Fix: Remove any "hushlogin" files from the system:
        #       # rm /etc/hushlogins
        #       # rm ~<userid>/.hushlogin
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38486
    it "V-38486 The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives." do
        # Check: Ask an administrator if a process exists to back up OS data from the system, including configuration data. 
        #       If such a process does not exist, this is a finding.
        pending( "Manual step" )
        # Fix: Procedures to back up OS data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.
        #       Implement a process whereby OS data is backed up from the system in accordance with local policies.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38487
    it "V-38487 The system package management tool must cryptographically verify the authenticity of all software packages during installation." do
        # Check: To determine whether "yum" has been configured to disable "gpgcheck" for any repos, inspect all files in "/etc/yum.repos.d" and ensure the following does not appear in any sections: 
        #       gpgcheck=0
        #       A value of "0" indicates that "gpgcheck" has been disabled for that repo. 
        #       If GPG checking is disabled, this is a finding.
        #       If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
        expect( command('grep ^gpgcheck=0 /etc/yum.repos.d/*.repo') ).to return_stdout ""
        # Fix: To ensure signature checking is not disabled for any repos, remove any lines from files in "/etc/yum.repos.d" of the form: 
        #       gpgcheck=0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38488
    it "V-38488 The operating system must conduct backups of user-level information contained in the operating system per organization defined frequency to conduct backups consistent with recovery time and recovery point objectives." do
        # Check: Ask an administrator if a process exists to back up user data from the system. 
        #       If such a process does not exist, this is a finding.
        pending( "Manual step" )
        # Fix: Procedures to back up user data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.
        #       Implement a process whereby user data is backed up from the system in accordance with local policies.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38489
    it "V-38489 A file integrity tool must be installed." do
        # Check: If another file integrity tool is installed, this is not a finding.
        #       Run the following command to determine if the "aide" package is installed: 
        #       # rpm -q aide
        #       If the package is not installed, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( package('ossec-hids') ).to be_installed
        elsif $environment['ids'] == 'aide'
            expect( package('aide') ).to be_installed
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: Install the AIDE package with the command: 
        #       # yum install aide
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38490
    it "V-38490 The operating system must enforce requirements for the connection of mobile devices to operating systems." do
        # Check: If the system is configured to prevent the loading of the "usb-storage" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command('grep -r usb-storage /etc/modprobe.d') ).not_to return_stdout ""
        # Fix: To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the "usb-storage" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 
        #       install usb-storage /bin/true
        #       This will prevent the "modprobe" program from loading the "usb-storage" module, but will not prevent an administrator (or another program) from using the "insmod" program to load the module manually.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38491
    it "V-38491 There must be no .rhosts or hosts.equiv files on the system." do
        # Check: The existence of the file "/etc/hosts.equiv" or a file named ".rhosts" inside a user home directory indicates the presence of an Rsh trust relationship. 
        #       If these files exist, this is a finding.
        expect( file('/etc/hosts.equiv')).not_to be_file
        expect( command('find /home -name \'.rhosts\'') ).to return_stdout ""
        # Fix: The files "/etc/hosts.equiv" and "~/.rhosts" (in each user's home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location. 
        #       # rm /etc/hosts.equiv
        #       $ rm ~/.rhosts
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38492
    it "V-38492 The system must prevent the root account from logging in from virtual consoles." do
        # Check: To check for virtual console entries which permit root login, run the following command: 
        #       # grep '^vc/[0-9]' /etc/securetty
        #       If any output is returned, then root logins over virtual console devices is permitted. 
        #       If root login over virtual console devices is permitted, this is a finding.
        expect( file('/etc/securetty')).not_to contain /^vc\/[0-9]/
        # Fix: To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in "/etc/securetty": 
        #       vc/1
        #       vc/2
        #       vc/3
        #       vc/4
        #       Note:  Virtual console entries are not limited to those listed above.  Any lines starting with "vc/" followed by numerals should be removed.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38493
    it "V-38493 Audit log directories must have mode 0755 or less permissive." do
        # Check: Run the following command to check the mode of the system audit directories: 
        #       grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n
        #       Audit directories must be mode 0755 or less permissive. 
        #       If any are more permissive, this is a finding.
        expect( file('/var/log/audit')).to be_mode 750
        # Fix: Change the mode of the audit log directories with the following command: 
        #       # chmod go-w [audit_directory]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38494
    it "V-38494 The system must prevent the root account from logging in from serial consoles." do
        # Check: To check for serial port entries which permit root login, run the following command: 
        #       # grep '^ttyS[0-9]' /etc/securetty
        #       If any output is returned, then root login over serial ports is permitted. 
        #       If root login over serial ports is permitted, this is a finding.
        expect( file('/etc/securetty')).not_to contain /^ttyS[0-9]/
        # Fix: To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty": 
        #       ttyS0
        #       ttyS1
        #       Note:  Serial port entries are not limited to those listed above.  Any lines starting with "ttyS" followed by numerals should be removed
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38495
    it "V-38495 Audit log files must be owned by root." do
        # Check: Run the following command to check the owner of the system audit logs: 
        #       grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n
        #       Audit logs must be owned by root. 
        #       If they are not, this is a finding.
        expect( file('/var/log/audit/audit.log')).to be_owned_by 'root'
        # Fix: Change the owner of the audit log files with the following command: 
        #       # chown root [audit_file]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38496
    it "V-38496 Default system accounts, other than root, must be locked." do
        # Check: To obtain a listing of all users and the contents of their shadow password field, run the command: 
        #       $ awk -F: '{print $1 ":" $2}' /etc/shadow
        #       Identify the system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root. 
        #       If any system account (other than root) has a valid password hash, this is a finding.
        expect( command('egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $3<500 && $2!="x") {print}\'')).to return_stdout ""

        # Fix: Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts. 
        #       Disable login access to these accounts with the command: 
        #       # passwd -l [SYSACCT]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38497
    it "V-38497 The system must not have accounts configured with blank or null passwords." do
        # Check: To verify that null passwords cannot be used, run the following command: 
        #       # grep nullok /etc/pam.d/system-auth /etc/pam.d/system-auth-ac
        #       If this produces any output, it may be possible to log into accounts with empty passwords. 
        #       If NULL passwords can be used, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac')).not_to contain "nullok"
        # Fix: If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication. Remove any instances of the "nullok" option in "/etc/pam.d/system-auth-ac" to prevent logins with empty passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38498
    it "V-38498 Audit log files must have mode 0640 or less permissive." do
        # Check: Run the following command to check the mode of the system audit logs: 
        #       grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n
        #       Audit logs must be mode 0640 or less permissive. 
        #       If any are more permissive, this is a finding.
        expect( file('/var/log/audit/audit.log')).to be_mode 600
        # Fix: Change the mode of the audit log files with the following command: 
        #       # chmod 0640 [audit_file]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38499
    it "V-38499 The /etc/passwd file must not contain password hashes." do
        # Check: To check that no password hashes are stored in "/etc/passwd", run the following command: 
        #       # awk -F: '($2 != "x") {print}' /etc/passwd
        #       If it produces any output, then a password hash is stored in "/etc/passwd". 
        #       If any stored hashes are found in /etc/passwd, this is a finding.
        expect( command('awk -F: \'($2 != "x") {print}\' /etc/passwd') ).to return_stdout ""
        # Fix: If any password hashes are stored in "/etc/passwd" (in the second field, instead of an "x"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38500
    it "V-38500 The root account must be the only account having a UID of 0." do
        # Check: To list all password file entries for accounts with UID 0, run the following command: 
        #       # awk -F: '($3 == "0") {print}' /etc/passwd
        #       This should print only one line, for the user root. 
        #       If any account other than root has a UID of 0, this is a finding.
        expect( command('/bin/cat /etc/passwd | /bin/awk -F: \'($3 == 0) { print $1 }\'')).to return_stdout "root"
        # Fix: If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38501
    it "V-38501 The system must disable accounts after excessive login failures within a 15-minute interval." do
        # Check: To ensure the failed password attempt policy is configured correctly, run the following command: 
        #       # grep pam_faillock /etc/pam.d/system-auth-ac
        #       The output should show "fail_interval=<interval-in-seconds>" where "interval-in-seconds" is 900 (15 minutes) or greater. If the "fail_interval" parameter is not set, the default setting of 900 seconds is acceptable. 
        #       If that is not the case, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac')).to contain "fail_interval=900"
        ####@TODO Need to test if it is empty or check if the 2 lines have the same value and that value is above 900

        # Fix: To configure the system to lock out accounts after a number of incorrect login attempts within a 15-minute interval using "pam_faillock.so": 
        #       Add the following lines immediately below the "pam_env.so" statement in the AUTH section of
        #       "/etc/pam.d/system-auth-ac": 
        #       auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900
        #       auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900
        #       Note that any updates made to "/etc/pam.d/system-auth-ac" will be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38502
    it "V-38502 The /etc/shadow file must be owned by root." do
        # Check: To check the ownership of "/etc/shadow", run the command: 
        #       $ ls -l /etc/shadow
        #       If properly configured, the output should indicate the following owner: "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/shadow')).to be_owned_by 'root'
        # Fix: To properly set the owner of "/etc/shadow", run the command: 
        #       # chown root /etc/shadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38503
    it "V-38503 The /etc/shadow file must be group-owned by root." do
        # Check: To check the group ownership of "/etc/shadow", run the command: 
        #       $ ls -l /etc/shadow
        #       If properly configured, the output should indicate the following group-owner. "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/shadow')).to be_grouped_into 'root'
        # Fix: To properly set the group owner of "/etc/shadow", run the command: 
        #       # chgrp root /etc/shadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38504
    it "V-38504 The /etc/shadow file must have mode 0000." do
        # Check: To check the permissions of "/etc/shadow", run the command: 
        #       $ ls -l /etc/shadow
        #       If properly configured, the output should indicate the following permissions: "----------" 
        #       If it does not, this is a finding.
        expect( file('/etc/shadow')).to be_mode 000
        # Fix: To properly set the permissions of "/etc/shadow", run the command: 
        #       # chmod 0000 /etc/shadow
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38511
    it "V-38511 IP forwarding for IPv4 must not be enabled, unless the system is a router." do
        # Check: If the system serves as a router, this is not applicable.
        #       The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.ip_forward
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        if property[:roles].include? 'router'
            expect( linux_kernel_parameter('net.ipv4.ip_forward').value).to equal(1)
        else
            expect( linux_kernel_parameter('net.ipv4.ip_forward').value ).to equal(0)
        end
        # Fix: To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.ip_forward=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.ip_forward = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38512
    it "V-38512 The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices." do
        # Check: If the system is a cross-domain system, this is not applicable.
        #       Run the following command to determine the current status of the "iptables" service: 
        #       # service iptables status
        #       If the service is enabled, it should return the following: 
        #       iptables is running...
        #       If the service is not running, this is a finding.
        expect( service('iptables')).to be_enabled
        expect( service('iptables')).to be_running
        if $environment['ipv6Enabled']
            expect( service('ip6tables')).to be_enabled
            expect( service('ip6tables')).to be_running
        end
        # Fix: The "iptables" service can be enabled with the following command: 
        #       # chkconfig iptables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38513
    it "V-38513 The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets." do
        # Check: Inspect the file "/etc/sysconfig/iptables" to determine the default policy for the INPUT chain. It should be set to DROP. 
        #       # grep ":INPUT" /etc/sysconfig/iptables
        #       If the default policy for the INPUT chain is not set to DROP, this is a finding.
        expect( file('/etc/sysconfig/iptables')).to contain /^\:INPUT DROP \[0\:0\]/
        if $environment['ipv6Enabled']
            expect( file('/etc/sysconfig/ip6tables')).to contain /^\:INPUT DROP \[0\:0\]/
        end
        # Fix: To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/iptables": 
        #       :INPUT DROP [0:0]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38514
    it "V-38514 The Datagram Congestion Control Protocol (DCCP) must be disabled unless required." do
        # Check: If the system is configured to prevent the loading of the "dccp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r dccp /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command('grep -r dccp /etc/modprobe.d') ).not_to return_stdout ""
        # Fix: The Datagram Congestion Control Protocol (DCCP) is a relatively new transport layer protocol, designed to support streaming media and telephony. To configure the system to prevent the "dccp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 
        #       install dccp /bin/true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38515
    it "V-38515 The Stream Control Transmission Protocol (SCTP) must be disabled unless required." do
        # Check: If the system is configured to prevent the loading of the "sctp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r sctp /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command('grep -r sctp /etc/modprobe.d') ).not_to return_stdout ""
        # Fix: The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the "sctp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 
        #       install sctp /bin/true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38516
    it "V-38516 The Reliable Datagram Sockets (RDS) protocol must be disabled unless required." do
        # Check: If the system is configured to prevent the loading of the "rds" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r rds /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command('grep -r rds /etc/modprobe.d')).not_to return_stdout ""
        # Fix: The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high- bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the "rds" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 
        #       install rds /bin/true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38517
    it "V-38517 The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required." do
        # Check: If the system is configured to prevent the loading of the "tipc" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r tipc /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command('grep -r tipc /etc/modprobe.d') ).not_to return_stdout ""
        # Fix: The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 
        #       install tipc /bin/true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38518
    it "V-38518 All rsyslog-generated log files must be owned by root." do
        # Check: The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's owner: 
        #       $ ls -l [LOGFILE]
        #       If the owner is not root, this is a finding.
        $environment['logFiles'].each do |log|
            expect( file(log)).to be_owned_by 'root'
        end
        # Fix: The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's owner:
        #       $ ls -l [LOGFILE]
        #       If the owner is not "root", run the following command to correct this:
        #       # chown root [LOGFILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38519
    it "V-38519 All rsyslog-generated log files must be group-owned by root." do
        # Check: The group-owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's group owner: 
        #       $ ls -l [LOGFILE]
        #       If the group-owner is not root, this is a finding.
        $environment['logFiles'].each do |log|
            expect( file(log)).to be_grouped_into 'root'
        end
        # Fix: The group-owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's group owner:
        #       $ ls -l [LOGFILE]
        #       If the owner is not "root", run the following command to correct this:
        #       # chgrp root [LOGFILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38520
    it "V-38520 The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited." do
        # Check: To ensure logs are sent to a remote host, examine the file "/etc/rsyslog.conf". If using UDP, a line similar to the following should be present: 
        #       *.* @[loghost.example.com]
        #       If using TCP, a line similar to the following should be present: 
        #       *.* @@[loghost.example.com]
        #       If using RELP, a line similar to the following should be present: 
        #       *.* :omrelp:[loghost.example.com]
        #       If none of these are present, this is a finding.
        if $environment['logger'] == 'syslog-ng'
            expect( file('/etc/syslog-ng/syslog-ng.conf')).to contain "log { source(s_sys); destination(d_log_server); };"
        elsif $environment['logger'] == 'rsyslog'
            expect( command('grep "^\*\.\* @@" /etc/rsyslog.conf')).not_to return_stdout ""
        else
            fail("The value of the logger variable is unknown.")
        end
            
        # Fix: To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments. 
        #       To use UDP for log message delivery: 
        #       *.* @[loghost.example.com]
        #       To use TCP for log message delivery: 
        #       *.* @@[loghost.example.com]
        #       To use RELP for log message delivery: 
        #       *.* :omrelp:[loghost.example.com]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38521
    it "V-38521 The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components." do
        # Check: To ensure logs are sent to a remote host, examine the file "/etc/rsyslog.conf". If using UDP, a line similar to the following should be present: 
        #       *.* @[loghost.example.com]
        #       If using TCP, a line similar to the following should be present: 
        #       *.* @@[loghost.example.com]
        #       If using RELP, a line similar to the following should be present: 
        #       *.* :omrelp:[loghost.example.com]
        #       If none of these are present, this is a finding.
        if $environment['logger'] == 'syslog-ng'
            expect( file('/etc/syslog-ng/syslog-ng.conf')).to contain "log { source(s_sys); destination(d_log_server); };"
        elsif $environment['logger'] == 'rsyslog'
            expect( command('grep "^\*\.\* @@" /etc/rsyslog.conf')).not_to return_stdout ""
        else
            fail("The value of the logger variable is unknown.")
        end        # Fix: To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments. 
        #       To use UDP for log message delivery: 
        #       *.* @[loghost.example.com]
        #       To use TCP for log message delivery: 
        #       *.* @@[loghost.example.com]
        #       To use RELP for log message delivery: 
        #       *.* :omrelp:[loghost.example.com]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38522
    it "V-38522 The audit system must be configured to audit all attempts to alter system time through settimeofday." do
        # Check: To determine if the system is configured to audit calls to the "settimeofday" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep settimeofday
        #       If the system is configured to audit this activity, it will return a line. 
        #       If the system is not configured to audit time changes, this is a finding.
        expect( command('auditctl -l | grep syscall | grep settimeofday') ).not_to return_stdout ""
        # Fix: On a 32-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b32 -S settimeofday -k audit_time_rules
        #       On a 64-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b64 -S settimeofday -k audit_time_rules
        #       The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 
        #       -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime 
        #       -k audit_time_rules
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38523
    it "V-38523 The system must not accept IPv4 source-routed packets on any interface." do
        # Check: The status of the "net.ipv4.conf.all.accept_source_route" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.accept_source_route
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.accept_source_route').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.accept_source_route" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.accept_source_route=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.accept_source_route = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38524
    it "V-38524 The system must not accept ICMPv4 redirect packets on any interface." do
        # Check: The status of the "net.ipv4.conf.all.accept_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.accept_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.accept_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.accept_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.accept_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.accept_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38525
    it "V-38525 The audit system must be configured to audit all attempts to alter system time through stime." do
        # Check: To determine if the system is configured to audit calls to the "stime" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep stime
        #       If the system is configured to audit this activity, it will return a line. 
        #       If the system is not configured to audit time changes, this is a finding.
       pending("Not applicable")
        # Fix: On a 32-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b32 -S stime -k audit_time_rules
        #       On a 64-bit system, the "-S stime" is not necessary. The -k option allows for the specification of a key in string form that can be used for better reporting 
        #       capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example
        #       of multiple combined syscalls: 
        #       -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime 
        #       -k audit_time_rules
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38526
    it "V-38526 The system must not accept ICMPv4 secure redirect packets on any interface." do
        # Check: The status of the "net.ipv4.conf.all.secure_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.secure_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.secure_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.secure_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.secure_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.secure_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38527
    it "V-38527 The audit system must be configured to audit all attempts to alter system time through clock_settime." do
        # Check: To determine if the system is configured to audit calls to the "clock_settime" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep clock_settime
        #       If the system is configured to audit this activity, it will return a line. 
        #       If the system is not configured to audit time changes, this is a finding.
        expect( command('auditctl -l | grep syscall | grep clock_settime') ).not_to return_stdout ""
        # Fix: On a 32-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b32 -S clock_settime -k audit_time_rules
        #       On a 64-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b64 -S clock_settime -k audit_time_rules
        #       The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 
        #       -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime 
        #       -k audit_time_rules
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38528
    it "V-38528 The system must log Martian packets." do
        # Check: The status of the "net.ipv4.conf.all.log_martians" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.log_martians
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.log_martians').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.log_martians=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.log_martians = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38529
    it "V-38529 The system must not accept IPv4 source-routed packets by default." do
        # Check: The status of the "net.ipv4.conf.default.accept_source_route" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.default.accept_source_route
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.default.accept_source_route').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.default.accept_source_route" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.default.accept_source_route=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.default.accept_source_route = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38530
    it "V-38530 The audit system must be configured to audit all attempts to alter system time through /etc/localtime." do
        # Check: To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command: 
        #       # auditctl -l | grep "watch=/etc/localtime"
        #       If the system is configured to audit this activity, it will return a line. 
        #       If the system is not configured to audit time changes, this is a finding.
        expect( command('auditctl -l | grep "watch=/etc/localtime') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules": 
        #       -w /etc/localtime -p wa -k audit_time_rules
        #       The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38531
    it "V-38531 The operating system must automatically audit account creation." do
        # Check: To determine if the system is configured to audit account changes, run the following command: 
        #       auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'
        #       If the system is configured to watch for account changes, lines should be returned for each file specified (and with "perm=wa" for each). 
        #       If the system is not configured to audit account changes, this is a finding.
        expect( command(' auditctl -l | egrep \'/etc/passwd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/shadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/group\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/gshadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/security/opasswd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 
        #       # audit_account_changes
        #       -w /etc/group -p wa -k audit_account_changes
        #       -w /etc/passwd -p wa -k audit_account_changes
        #       -w /etc/gshadow -p wa -k audit_account_changes
        #       -w /etc/shadow -p wa -k audit_account_changes
        #       -w /etc/security/opasswd -p wa -k audit_account_changes
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38532
    it "V-38532 The system must not accept ICMPv4 secure redirect packets by default." do
        # Check: The status of the "net.ipv4.conf.default.secure_redirects"  kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.default.secure_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.default.secure_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.default.secure_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.default.secure_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.default.secure_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38533
    it "V-38533 The system must ignore IPv4 ICMP redirect messages." do
        # Check: The status of the "net.ipv4.conf.default.accept_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.default.accept_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.default.accept_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.default.accept_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.default.accept_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.default.accept_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38534
    it "V-38534 The operating system must automatically audit account modification." do
        # Check: To determine if the system is configured to audit account changes, run the following command: 
        #       auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'
        #       If the system is configured to watch for account changes, lines should be returned for each file specified (and with "perm=wa" for each). 
        #       If the system is not configured to audit account changes, this is a finding.
        expect( command(' auditctl -l | egrep \'/etc/passwd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/shadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/group\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/gshadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/security/opasswd\'|grep \'perm=wa\'') ).not_to return_stdout ""

        # Fix: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 
        #       # audit_account_changes
        #       -w /etc/group -p wa -k audit_account_changes
        #       -w /etc/passwd -p wa -k audit_account_changes
        #       -w /etc/gshadow -p wa -k audit_account_changes
        #       -w /etc/shadow -p wa -k audit_account_changes
        #       -w /etc/security/opasswd -p wa -k audit_account_changes
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38535
    it "V-38535 The system must not respond to ICMPv4 sent to a broadcast address." do
        # Check: The status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.icmp_echo_ignore_broadcasts
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.icmp_echo_ignore_broadcasts = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38536
    it "V-38536 The operating system must automatically audit account disabling actions." do
        # Check: To determine if the system is configured to audit account changes, run the following command: 
        #       auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'
        #       If the system is configured to watch for account changes, lines should be returned for each file specified (and with "perm=wa" for each). 
        #       If the system is not configured to audit account changes, this is a finding.
        expect( command(' auditctl -l | egrep \'/etc/passwd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/shadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/group\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/gshadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/security/opasswd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 
        #       # audit_account_changes
        #       -w /etc/group -p wa -k audit_account_changes
        #       -w /etc/passwd -p wa -k audit_account_changes
        #       -w /etc/gshadow -p wa -k audit_account_changes
        #       -w /etc/shadow -p wa -k audit_account_changes
        #       -w /etc/security/opasswd -p wa -k audit_account_changes
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38537
    it "V-38537 The system must ignore ICMPv4 bogus error responses." do
        # Check: The status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.icmp_ignore_bogus_error_responses
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.icmp_ignore_bogus_error_responses = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38538
    it "V-38538 The operating system must automatically audit account termination." do
        # Check: To determine if the system is configured to audit account changes, run the following command: 
        #       auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'
        #       If the system is configured to watch for account changes, lines should be returned for each file specified (and with "perm=wa" for each). 
        #       If the system is not configured to audit account changes, this is a finding.
        expect( command(' auditctl -l | egrep \'/etc/passwd\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/shadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/group\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/gshadow\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/security/opasswd\'|grep \'perm=wa\'') ).not_to return_stdout ""
 
        # Fix: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 
        #       # audit_account_changes
        #       -w /etc/group -p wa -k audit_account_changes
        #       -w /etc/passwd -p wa -k audit_account_changes
        #       -w /etc/gshadow -p wa -k audit_account_changes
        #       -w /etc/shadow -p wa -k audit_account_changes
        #       -w /etc/security/opasswd -p wa -k audit_account_changes
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38539
    it "V-38539 The system must be configured to use TCP syncookies." do
        # Check: The status of the "net.ipv4.tcp_syncookies" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.tcp_syncookies
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.tcp_syncookies').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.tcp_syncookies=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.tcp_syncookies = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38540
    it "V-38540 The audit system must be configured to audit modifications to the systems network configuration." do
        # Check: To determine if the system is configured to audit changes to its network configuration, run the following command: 
        #       auditctl -l | egrep '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)'
        #       If the system is configured to watch for network configuration changes, a line should be returned for each file specified (and "perm=wa" should be indicated for each). 
        #       If the system is not configured to audit changes of the network configuration, this is a finding.
        expect( file('/etc/audit/audit.rules') ).to contain "-S sethostname"
        expect( file('/etc/audit/audit.rules') ).to contain "-S setdomainname"
        expect( command(' auditctl -l | egrep \'/etc/issue\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/issue.net\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/hosts\'|grep \'perm=wa\'') ).not_to return_stdout ""
        expect( command(' auditctl -l | egrep \'/etc/sysconfig/network\'|grep \'perm=wa\'') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 
        #       # audit_network_modifications
        #       -a exit,always -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications
        #       -w /etc/issue -p wa -k audit_network_modifications
        #       -w /etc/issue.net -p wa -k audit_network_modifications
        #       -w /etc/hosts -p wa -k audit_network_modifications
        #       -w /etc/sysconfig/network -p wa -k audit_network_modifications
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38541
    it "V-38541 The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux)." do
        # Check: To determine if the system is configured to audit changes to its SELinux configuration files, run the following command: 
        #       # auditctl -l | grep "dir=/etc/selinux"
        #       If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including "perm=wa" indicating permissions that are watched). 
        #       If the system is not configured to audit attempts to change the MAC policy, this is a finding.
        expect( command('auditctl -l | grep "dir=/etc/selinux"|grep \'perm=wa\'') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules": 
        #       -w /etc/selinux/ -p wa -k MAC-policy
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38542
    it "V-38542 The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces." do
        # Check: The status of the "net.ipv4.conf.all.rp_filter" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.rp_filter
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.rp_filter').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.rp_filter" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.rp_filter=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.rp_filter = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38543
    it "V-38543 The audit system must be configured to audit all discretionary access control permission modifications using chmod." do
        # Check: To determine if the system is configured to audit calls to the "chmod" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep chmod
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep chmod') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S chmod -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S chmod -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38544
    it "V-38544 The system must use a reverse-path filter for IPv4 network traffic when possible by default." do
        # Check: The status of the "net.ipv4.conf.default.rp_filter" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.default.rp_filter
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.default.rp_filter').value ).to equal(1)
        # Fix: To set the runtime status of the "net.ipv4.conf.default.rp_filter" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.default.rp_filter=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.default.rp_filter = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38545
    it "V-38545 The audit system must be configured to audit all discretionary access control permission modifications using chown." do
        # Check: To determine if the system is configured to audit calls to the "chown" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep chown
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep chown') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S chown -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S chown -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38546
    it "V-38546 The IPv6 protocol handler must not be bound to the network stack unless needed." do
        # Check: If the system uses IPv6, this is not applicable.
        #       If the system is configured to prevent the loading of the "ipv6" kernel module, it will contain a line of the form: 
        #       options ipv6 disable=1
        #       Such lines may be inside any file in "/etc/modprobe.d" or the deprecated "/etc/modprobe.conf". This permits insertion of the IPv6 kernel module (which other parts of the system expect to be present), but otherwise keeps it inactive. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r ipv6 /etc/modprobe.conf /etc/modprobe.d
        #       If the IPv6 kernel module is loaded, this is a finding.
        if $environment['ipv6Enabled']
            pending("Not applicable")
        else
            expect( command('grep -r ipv6 /etc/modprobe.d') ).not_to return_stdout ""
        end
        # Fix: To prevent the IPv6 kernel module ("ipv6") from loading the IPv6 networking stack, add the following line to "/etc/modprobe.d/disabled.conf" (or another file in "/etc/modprobe.d"): 
        #       options ipv6 disable=1
        #       This permits the IPv6 module to be loaded (and thus satisfy other modules that depend on it), while disabling support for the IPv6 protocol.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38547
    it "V-38547 The audit system must be configured to audit all discretionary access control permission modifications using fchmod." do
        # Check: To determine if the system is configured to audit calls to the "fchmod" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fchmod
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fchmod') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fchmod -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fchmod -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38548
    it "V-38548 The system must ignore ICMPv6 redirects by default." do
        # Check: The status of the "net.ipv6.conf.default.accept_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv6.conf.default.accept_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        if $environment['ipv6Enabled']
            expect( linux_kernel_parameter('net.ipv6.conf.default.accept_redirects').value ).to equal(0)
        else
            pending("Not applicable")
        end
        # Fix: To set the runtime status of the "net.ipv6.conf.default.accept_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv6.conf.default.accept_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv6.conf.default.accept_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38549
    it "V-38549 The system must employ a local IPv6 firewall." do
        # Check: If IPv6 is disabled, this is not applicable.
        #       Run the following command to determine the current status of the "ip6tables" service: 
        #       # service ip6tables status
        #       If the service is enabled, it should return the following: 
        #       ip6tables is running...
        #       If the service is not running, this is a finding.
        if $environment['ipv6Enabled']
            expect( linux_kernel_parameter('net.ipv6.conf.default.accept_redirects').value ).to equal(0)
        else
            pending("Not applicable")
        end
        # Fix: The "ip6tables" service can be enabled with the following command: 
        #       # chkconfig ip6tables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38550
    it "V-38550 The audit system must be configured to audit all discretionary access control permission modifications using fchmodat." do
        # Check: To determine if the system is configured to audit calls to the "fchmodat" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fchmodat
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fchmodat') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fchmodat -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fchmodat -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38551
    it "V-38551 The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture." do
        # Check: If IPv6 is disabled, this is not applicable.
        #       Run the following command to determine the current status of the "ip6tables" service: 
        #       # service ip6tables status
        #       If the service is enabled, it should return the following: 
        #       ip6tables is running...
        #       If the service is not running, this is a finding.
        if $environment['ipv6Enabled']
            expect( service('ip6tables')).to be_running
        else
            pending("Not applicable")
        end
        # Fix: The "ip6tables" service can be enabled with the following command: 
        #       # chkconfig ip6tables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38552
    it "V-38552 The audit system must be configured to audit all discretionary access control permission modifications using fchown." do
        # Check: To determine if the system is configured to audit calls to the "fchown" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fchown
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fchown') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fchown -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fchown -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38553
    it "V-38553 The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices." do
        # Check: If IPv6 is disabled, this is not applicable.
        #       Run the following command to determine the current status of the "ip6tables" service: 
        #       # service ip6tables status
        #       If the service is enabled, it should return the following: 
        #       ip6tables is running...
        #       If the service is not running, this is a finding.
        if $environment['ipv6Enabled']
            expect( service('ip6tables')).to be_enabled
        else
            pending("Not applicable")
        end
        # Fix: The "ip6tables" service can be enabled with the following command: 
        #       # chkconfig ip6tables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38554
    it "V-38554 The audit system must be configured to audit all discretionary access control permission modifications using fchownat." do
        # Check: To determine if the system is configured to audit calls to the "fchownat" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fchownat
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fchownat') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fchownat -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fchownat -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38555
    it "V-38555 The system must employ a local IPv4 firewall." do
        # Check: If the system is a cross-domain system, this is not applicable.
        #       Run the following command to determine the current status of the "iptables" service: 
        #       # service iptables status
        #       If the service is enabled, it should return the following: 
        #       iptables is running...
        #       If the service is not running, this is a finding.
        expect( service('iptables')).to be_running
        if $environment['ipv6Enabled']
            expect( service('ip6tables')).to be_running
        end
        # Fix: The "iptables" service can be enabled with the following command: 
        #       # chkconfig iptables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38556
    it "V-38556 The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr." do
        # Check: To determine if the system is configured to audit calls to the "fremovexattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fremovexattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fremovexattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fremovexattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fremovexattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38557
    it "V-38557 The audit system must be configured to audit all discretionary access control permission modifications using fsetxattr." do
        # Check: To determine if the system is configured to audit calls to the "fsetxattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep fsetxattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep fsetxattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S fsetxattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S fsetxattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38558
    it "V-38558 The audit system must be configured to audit all discretionary access control permission modifications using lchown." do
        # Check: To determine if the system is configured to audit calls to the "lchown" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep lchown
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep lchown') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S lchown -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S lchown -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38559
    it "V-38559 The audit system must be configured to audit all discretionary access control permission modifications using lremovexattr." do
        # Check: To determine if the system is configured to audit calls to the "lremovexattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep lremovexattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep lremovexattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S lremovexattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S lremovexattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38560
    it "V-38560 The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture." do
        # Check: If the system is a cross-domain system, this is not applicable.
        #       Run the following command to determine the current status of the "iptables" service: 
        #       # service iptables status
        #       If the service is enabled, it should return the following: 
        #       iptables is running...
        #       If the service is not running, this is a finding.
        expect( service('iptables')).to be_enabled
        if $environment['ipv6Enabled']
            expect( service('ip6tables')).to be_enabled
        end
        # Fix: The "iptables" service can be enabled with the following command: 
        #       # chkconfig iptables on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38561
    it "V-38561 The audit system must be configured to audit all discretionary access control permission modifications using lsetxattr." do
        # Check: To determine if the system is configured to audit calls to the "lsetxattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep lsetxattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep lsetxattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S lsetxattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S lsetxattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38563
    it "V-38563 The audit system must be configured to audit all discretionary access control permission modifications using removexattr." do
        # Check: To determine if the system is configured to audit calls to the "removexattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep removexattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep removexattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S removexattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S removexattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38565
    it "V-38565 The audit system must be configured to audit all discretionary access control permission modifications using setxattr." do
        # Check: To determine if the system is configured to audit calls to the "setxattr" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep setxattr
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no lines are returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep setxattr') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b32 -S setxattr -F auid==0 -k perm_mod
        #       If the system is 64-bit, then also add the following: 
        #       -a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 \
        #       -k perm_mod
        #       -a always,exit -F arch=b64 -S setxattr -F auid==0 -k perm_mod
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38566
    it "V-38566 The audit system must be configured to audit failed attempts to access files and programs." do
        # Check: To verify that the audit system collects unauthorized file accesses, run the following commands: 
        #       # grep EACCES /etc/audit/audit.rules
        #       # grep EPERM /etc/audit/audit.rules
        #       If either command lacks output, this is a finding.
        expect( command('grep EACCES /etc/audit/audit.rules') ).not_to return_stdout ""
        expect( command('grep EPERM /etc/audit/audit.rules') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 
        #       -a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
        #       -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
        #       -a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
        #       -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
        #       -a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
        #       -S ftruncate -F exit=-EACCES -F auid==0 -k access
        #       -a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
        #       -S ftruncate -F exit=-EPERM -F auid==0 -k access
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38567
    it "V-38567 The audit system must be configured to audit all use of setuid programs." do
        # Check: To verify that auditing of privileged command use is configured, run the following command to find relevant setuid programs: 
        #       # find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null
        #       Run the following command to verify entries in the audit rules for all programs found with the previous command: 
        #       # grep path /etc/audit/audit.rules
        #       It should be the case that all relevant setuid programs have a line in the audit rules. 
        #       If it is not the case, this is a finding.
        pathLines = command('find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null').stdout.strip
        pathLines.each_line do |line| 
            expect( command("grep '#{line.chomp}' /etc/audit/audit.rules")).not_to return_stdout "" 
        end 
        # Fix: At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid programs: 
        #       # find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null
        #       Then, for each setuid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid program in the list: 
        #       -a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38568
    it "V-38568 The audit system must be configured to audit successful file system mounts." do
        # Check: To verify that auditing is configured for all media exportation events, run the following command: 
        #       # auditctl -l | grep syscall | grep mount
        #       If there is no output, this is a finding.
        expect( command('auditctl -l | grep syscall | grep mount') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect media exportation events for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 
        #       -a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export
        #       -a always,exit -F arch=ARCH -S mount -F auid==0 -k export
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38569
    it "V-38569 The system must require passwords to contain at least one uppercase alphabetic character." do
        # Check: To check how many uppercase characters are required in a password, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       The "ucredit" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as "ucredit=-1". 
        #       If ucredit is not found or not set to the required value, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "ucredit=-1"
        # Fix: The pam_cracklib module's "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. Add "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38570
    it "V-38570 The system must require passwords to contain at least one special character." do
        # Check: To check how many special characters are required in a password, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       The "ocredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one special character in a password. This would appear as "ocredit=-1". 
        #       If ocredit is not found or not set to the required value, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "ocredit=-1"
        # Fix: The pam_cracklib module's "ocredit=" parameter controls requirements for usage of special (or ``other'') characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character. Add "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38571
    it "V-38571 The system must require passwords to contain at least one lowercase alphabetic character." do
        # Check: To check how many lowercase characters are required in a password, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       The "lcredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one lowercase character in a password. This would appear as "lcredit=-1". 
        #       If lcredit is not found or not set to the required value, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "lcredit=-1"
        # Fix: The pam_cracklib module's "lcredit=" parameter controls requirements for usage of lowercase letters in a password. When set to a negative number, any password will be required to contain that many lowercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each lowercase character. Add "lcredit=-1" after pam_cracklib.so to require use of a lowercase character in passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38572
    it "V-38572 The system must require at least four characters be changed between the old and new passwords during a password change." do
        # Check: To check how many characters must differ during a password change, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       The "difok" parameter will indicate how many characters must differ. The DoD requires four characters differ during a password change. This would appear as "difok=4". 
        #       If difok is not found or not set to the required value, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "difok=4"
        # Fix: The pam_cracklib module's "difok" parameter controls requirements for usage of different characters during a password change. Add "difok=[NUM]" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 4.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38573
    it "V-38573 The system must disable accounts after three consecutive unsuccessful login attempts." do
        # Check: To ensure the failed password attempt policy is configured correctly, run the following command: 
        #       # grep pam_faillock /etc/pam.d/system-auth-ac
        #       The output should show "deny=3". 
        #       If that is not the case, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "deny=3"
        # Fix: To configure the system to lock out accounts after a number of incorrect login attempts using "pam_faillock.so": 
        #       Add the following lines immediately below the "pam_unix.so" statement in the AUTH section of "/etc/pam.d/system-auth-ac": 
        #       auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900
        #       auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900
        #       Note that any updates made to "/etc/pam.d/system-auth-ac" will be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38574
    it "V-38574 The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth)." do
        # Check: Inspect the "password" section of "/etc/pam.d/system-auth" and ensure that the "pam_unix.so" module includes the argument "sha512".
        #       $ grep sha512 /etc/pam.d/system-auth" 
        #       If it does not, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac') ).to contain "sha512"
        # Fix: In "/etc/pam.d/system-auth", the "password" section of the file controls which PAM modules execute during a password change. Set the "pam_unix.so" module in the "password" section to include the argument "sha512", as shown below: 
        #       password sufficient pam_unix.so sha512 [other arguments...]
        #       This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.
        #       Note that any updates made to "/etc/pam.d/system-auth" will be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38575
    it "V-38575 The audit system must be configured to audit user deletions of files and programs." do
        # Check: To determine if the system is configured to audit calls to the "unlink" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep unlink | grep -v unlinkat
        #       If the system is configured to audit this activity, it will return several lines. 
        #       To determine if the system is configured to audit calls to the "unlinkat" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep unlinkat
        #       If the system is configured to audit this activity, it will return several lines. To determine if the system is configured to audit calls to the "rename" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep rename | grep -v renameat
        #       If the system is configured to audit this activity, it will return several lines. To determine if the system is configured to audit calls to the "renameat" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep renameat
        #       If the system is configured to audit this activity, it will return several lines. 
        #       If no line is returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep unlink') ).not_to return_stdout ""
        expect( command('auditctl -l | grep syscall | grep unlinkat') ).not_to return_stdout ""
        expect( command('auditctl -l | grep syscall | grep rename') ).not_to return_stdout ""
        expect( command('auditctl -l | grep syscall | grep renameat') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect file deletion events for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 
        #       -a always,exit -F arch=ARCH -S unlink -S unlinkat -S rename -S renameat \
        #       -F auid>=500 -F auid!=4294967295 -k delete
        #       -a always,exit -F arch=ARCH -S unlink -S unlinkat -S rename -S renameat \
        #       -F auid==0 -k delete
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38576
    it "V-38576 The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs)." do
        # Check: Inspect "/etc/login.defs" and ensure the following line appears: 
        #       ENCRYPT_METHOD SHA512
        #       If it does not, this is a finding.
        expect( file('/etc/login.defs') ).to contain /^ENCRYPT_METHOD SHA512/
        # Fix: In "/etc/login.defs", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm: 
        #       ENCRYPT_METHOD SHA512
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38577
    it "V-38577 The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf)." do
        # Check: Inspect "/etc/libuser.conf" and ensure the following line appears in the "[default]" section: 
        #       crypt_style = sha512
        #       If it does not, this is a finding.
        expect( file('/etc/libuser.conf') ).to contain /^crypt_style = sha512/
        # Fix: In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing: 
        #       crypt_style = sha512
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38578
    it "V-38578 The audit system must be configured to audit changes to the /etc/sudoers file." do
        # Check: To verify that auditing is configured for system administrator actions, run the following command: 
        #       # auditctl -l | grep "watch=/etc/sudoers"
        #       If there is no output, this is a finding.
        expect( command('auditctl -l | grep "watch=/etc/sudoers"') ).not_to return_stdout ""
        # Fix: At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules": 
        #       -w /etc/sudoers -p wa -k actions
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38579
    it "V-38579 The system boot loader configuration file(s) must be owned by root." do
        # Check: To check the ownership of "/etc/grub.conf", run the command: 
        #       $ ls -lL /etc/grub.conf
        #       If properly configured, the output should indicate the following owner: "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/grub.conf')).to be_owned_by 'root'
        # Fix: The file "/etc/grub.conf" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/etc/grub.conf", run the command: 
        #       # chown root /etc/grub.conf
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38580
    it "V-38580 The audit system must be configured to audit the loading and unloading of dynamic kernel modules." do
        # Check: To determine if the system is configured to audit calls to the "init_module" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep init_module
        #       If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "delete_module" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep delete_module
        #       If the system is configured to audit this activity, it will return a line. 
        #       If no line is returned, this is a finding.
        expect( command('auditctl -l | grep syscall | grep init_module') ).not_to return_stdout ""
        expect( command('auditctl -l | grep syscall | grep delete_module') ).not_to return_stdout ""
        # Fix: Add the following to "/etc/audit/audit.rules" in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system: 
        #       -w /sbin/insmod -p x -k modules
        #       -w /sbin/rmmod -p x -k modules
        #       -w /sbin/modprobe -p x -k modules
        #       -a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38581
    it "V-38581 The system boot loader configuration file(s) must be group-owned by root." do
        # Check: To check the group ownership of "/etc/grub.conf", run the command: 
        #       $ ls -lL /etc/grub.conf
        #       If properly configured, the output should indicate the following group-owner. "root" 
        #       If it does not, this is a finding.
        expect( file('/etc/grub.conf')).to be_grouped_into 'root'
        # Fix: The file "/etc/grub.conf" should be group-owned by the "root" group to prevent destruction or modification of the file. To properly set the group owner of "/etc/grub.conf", run the command: 
        #       # chgrp root /etc/grub.conf
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38582
    it "V-38582 The xinetd service must be disabled if no network services utilizing it are enabled." do
        # Check: If network services are using the xinetd service, this is not applicable.
        #       To check that the "xinetd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "xinetd" --list
        #       Output should indicate the "xinetd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "xinetd" --list
        #       "xinetd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "xinetd" is disabled through current runtime configuration: 
        #       # service xinetd status
        #       If the service is disabled the command will return the following output: 
        #       xinetd is stopped
        #       If the service is running, this is a finding.
        expect( service('xinetd')).not_to be_enabled
        expect( service('xinetd')).not_to be_running
        # Fix: The "xinetd" service can be disabled with the following command: 
        #       # chkconfig xinetd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38583
    it "V-38583 The system boot loader configuration file(s) must have mode 0600 or less permissive." do
        # Check: To check the permissions of "/etc/grub.conf", run the command: 
        #       $ ls -lL /etc/grub.conf
        #       If properly configured, the output should indicate the following permissions: "-rw-------" 
        #       If it does not, this is a finding.
        expect( file('/etc/grub.conf')).to be_mode 600
        # Fix: File permissions for "/etc/grub.conf" should be set to 600, which is the default. To properly set the permissions of "/etc/grub.conf", run the command: 
        #       # chmod 600 /etc/grub.conf
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38584
    it "V-38584 The xinetd service must be uninstalled if no network services utilizing it are enabled." do
        # Check: If network services are using the xinetd service, this is not applicable.
        #       Run the following command to determine if the "xinetd" package is installed: 
        #       # rpm -q xinetd
        #       If the package is installed, this is a finding.
        expect( package('xinetd') ).not_to be_installed
        # Fix: The "xinetd" package can be uninstalled with the following command: 
        #       # yum erase xinetd
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38585
    it "V-38585 The system boot loader must require authentication." do
        # Check: To verify the boot loader password has been set and encrypted, run the following command: 
        #       # grep password /etc/grub.conf
        #       The output should show the following: 
        #       password --encrypted "$6$[rest-of-the-password-hash]"
        #       If it does not, this is a finding.
        expect( command('grep password /etc/grub.conf') ).to return_stdout /password --encrypted \$6\$.*/
        # Fix: The grub boot loader should have password protection enabled to protect boot-time settings. To do so, 
        #       select a password and then generate a hash from it by running the following command: 
        #       # grub-crypt --sha-512
        #       When prompted to enter a password, insert the following line into "/etc/grub.conf" immediately after 
        #       the header comments. (Use the output from "grub-crypt" as the value of [password-hash]): 
        #       password --encrypted [password-hash]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38586
    it "V-38586 The system must require authentication upon booting into single-user and maintenance modes." do
        # Check: To check if authentication is required for single-user mode, run the following command: 
        #       $ grep SINGLE /etc/sysconfig/init
        #       The output should be the following: 
        #       SINGLE=/sbin/sulogin
        #       If the output is different, this is a finding.
        expect( command('grep SINGLE /etc/sysconfig/init') ).to return_stdout /^SINGLE=\/sbin\/sulogin/
        # Fix: Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected. 
        #       To require entry of the root password even if the system is started in single-user mode, add or correct the following line in the file "/etc/sysconfig/init": 
        #       SINGLE=/sbin/sulogin
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38587
    it "V-38587 The telnet-server package must not be installed." do
        # Check: Run the following command to determine if the "telnet-server" package is installed: 
        #       # rpm -q telnet-server
        #       If the package is installed, this is a finding.
        expect( package('telnet-server') ).not_to be_installed
        # Fix: The "telnet-server" package can be uninstalled with the following command: 
        #       # yum erase telnet-server
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38588
    it "V-38588 The system must not permit interactive boot." do
        # Check: To check whether interactive boot is disabled, run the following command: 
        #       $ grep PROMPT /etc/sysconfig/init
        #       If interactive boot is disabled, the output will show: 
        #       PROMPT=no
        #       If it does not, this is a finding.
        expect( command('grep PROMPT /etc/sysconfig/init') ).to return_stdout /^PROMPT=no/
        # Fix: To disable the ability for users to perform interactive startups, edit the file "/etc/sysconfig/init". Add or correct the line: 
        #       PROMPT=no
        #       The "PROMPT" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38589
    it "V-38589 The telnet daemon must not be running." do
        # Check: To check that the "telnet" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "telnet" --list
        #       Output should indicate the "telnet" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "telnet" --list
        #       "telnet" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "telnet" is disabled through current runtime configuration: 
        #       # service telnet status
        #       If the service is disabled the command will return the following output: 
        #       telnet is stopped
        #       If the service is running, this is a finding.
        expect( service('telnet')).not_to be_enabled
        expect( service('telnet')).not_to be_running
        # Fix: The "telnet" service can be disabled with the following command: 
        #       # chkconfig telnet off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38590
    it "V-38590 The system must allow locking of the console screen in text mode." do
        # Check: Run the following command to determine if the "screen" package is installed: 
        #       # rpm -q screen
        #       If the package is not installed, this is a finding.
        expect( package('screen')).to be_installed
        # Fix: To enable console screen locking when in text mode, install the "screen" package: 
        #       # yum install screen
        #       Instruct users to begin new terminal sessions with the following command: 
        #       $ screen
        #       The console can now be locked with the following key combination: 
        #       ctrl+a x
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38591
    it "V-38591 The rsh-server package must not be installed." do
        # Check: Run the following command to determine if the "rsh-server" package is installed: 
        #       # rpm -q rsh-server
        #       If the package is installed, this is a finding.
        expect( package('rsh-server')).not_to be_installed
        # Fix: The "rsh-server" package can be uninstalled with the following command: 
        #       # yum erase rsh-server
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38592
    it "V-38592 The system must require administrator action to unlock an account locked by excessive failed login attempts." do
        # Check: To ensure the failed password attempt policy is configured correctly, run the following command: 
        #       # grep pam_faillock /etc/pam.d/system-auth-ac
        #       The output should show "unlock_time=<some-large-number>"; the largest acceptable value is 604800 
        #       seconds (one week). 
        #       If that is not the case, this is a finding.
        expect( file('/etc/pam.d/system-auth-ac')).to contain "unlock_time=604800"
        # Fix: To configure the system to lock out accounts after a number of incorrect login attempts and require an 
        #       administrator to unlock the account using "pam_faillock.so": 
        #       Add the following lines immediately below the "pam_unix.so" statement in the AUTH section of
        #       "/etc/pam.d/system-auth-ac": 
        #       auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900
        #       auth required pam_faillock.so authsucc deny=3 unlock_time=604800  fail_interval=900
        #       Note that any updates made to "/etc/pam.d/system-auth-ac" will be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38593
    it "V-38593 The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts." do
        # Check: To check if the system login banner is compliant, run the following command: 
        #       $ cat /etc/issue
        #       If it does not display the required banner, this is a finding.
        expect( file('/etc/issue')).to be_file
        expect( command('cat /etc/issue')).not_to return_stdout ""
        # Fix: To configure the system login banner: 
        #       Edit "/etc/issue". Replace the default text with a message compliant with the local site policy or a legal disclaimer. The DoD required text is either: 
        #       "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
        #       -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
        #       -At any time, the USG may inspect and seize data stored on this IS. 
        #       -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
        #       -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. 
        #       -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
        #       OR: 
        #       "I've read & consent to terms in IS user agreem't."
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38594
    it "V-38594 The rshd service must not be running." do
        # Check: To check that the "rsh" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "rsh" --list
        #       Output should indicate the "rsh" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "rsh" --list
        #       "rsh" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "rsh" is disabled through current runtime configuration: 
        #       # service rsh status
        #       If the service is disabled the command will return the following output: 
        #       rsh is stopped
        #       If the service is running, this is a finding.
        expect( service('rsh')).not_to be_enabled
        expect( service('rsh')).not_to be_running
        # Fix: The "rsh" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rsh" service can be disabled with the following command: 
        #       # chkconfig rsh off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38595
    it "V-38595 The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication." do
        # Check: Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. For DoD systems, the following systems and accounts are exempt from using smart card (CAC) authentication: 
        #       SIPRNET systems
        #       Standalone systems
        #       Application accounts
        #       Temporary employee accounts, such as students or interns, who cannot easily receive a CAC or PIV
        #       Operational tactical locations that are not collocated with RAPIDS workstations to issue CAC or ALT
        #       Test systems, such as those with an Interim Approval to Test (IATT) and use a separate VPN, firewall, or security measure preventing access to network and system components from outside the protection boundary documented in the IATT.
        #       If non-exempt accounts are not using CAC authentication, this is a finding.
        pending( "Manual step" )
        # Fix: To enable smart card authentication, consult the documentation at: 
        #       https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Managing_Smart_Cards/enabling-smart-card-login.html
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38596
    it "V-38596 The system must implement virtual address space randomization." do
        # Check: The status of the "kernel.randomize_va_space" kernel parameter can be queried by running the following command: 
        #       $ sysctl kernel.randomize_va_space
        #       The output of the command should indicate a value of at least "1" (preferably "2"). If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('kernel.randomize_va_space').value ).to equal(2)
        # Fix: To set the runtime status of the "kernel.randomize_va_space" kernel parameter, run the following command: 
        #       # sysctl -w kernel.randomize_va_space=2
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       kernel.randomize_va_space = 2
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38597
    it "V-38597 The system must limit the ability of processes to have simultaneous write and execute access to memory." do
        # Check: The status of the "kernel.exec-shield" kernel parameter can be queried by running the following command: 
        #       $ sysctl kernel.exec-shield
        #       The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('kernel.exec-shield').value ).to equal(1)
        # Fix: To set the runtime status of the "kernel.exec-shield" kernel parameter, run the following command: 
        #       # sysctl -w kernel.exec-shield=1
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       kernel.exec-shield = 1
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38598
    it "V-38598 The rexecd service must not be running." do
        # Check: To check that the "rexec" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "rexec" --list
        #       Output should indicate the "rexec" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "rexec" --list
        #       "rexec" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "rexec" is disabled through current runtime configuration: 
        #       # service rexec status
        #       If the service is disabled the command will return the following output: 
        #       rexec is stopped
        #       If the service is running, this is a finding.
        expect( service('rexec')).not_to be_enabled
        expect( service('rexec')).not_to be_running
        # Fix: The "rexec" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rexec" service can be disabled with the following command: 
        #       # chkconfig rexec off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38599
    it "V-38599 The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner." do
        # Check: To verify this configuration, run the following command: 
        #       grep "banner_file" /etc/vsftpd/vsftpd.conf
        #       The output should show the value of "banner_file" is set to "/etc/issue", an example of which is shown below. 
        #       # grep "banner_file" /etc/vsftpd/vsftpd.conf
        #       banner_file=/etc/issue
        #       If it does not, this is a finding.
        if package('vsftpd').installed?("rpm",nil)
            expect( file('/etc/vsftpd/vsftpd.conf')).to contain "banner_file=/etc/issue"
        else
            pending('Not applicable')
        end
        # Fix: Edit the vsftpd configuration file, which resides at "/etc/vsftpd/vsftpd.conf" by default. Add or correct the following configuration options. 
        #       banner_file=/etc/issue
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38600
    it "V-38600 The system must not send ICMPv4 redirects by default." do
        # Check: The status of the "net.ipv4.conf.default.send_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.default.send_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.default.send_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.default.send_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.default.send_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.default.send_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38601
    it "V-38601 The system must not send ICMPv4 redirects from any interface." do
        # Check: The status of the "net.ipv4.conf.all.send_redirects" kernel parameter can be queried by running the following command: 
        #       $ sysctl net.ipv4.conf.all.send_redirects
        #       The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
        #       If the correct value is not returned, this is a finding.
        expect( linux_kernel_parameter('net.ipv4.conf.all.send_redirects').value ).to equal(0)
        # Fix: To set the runtime status of the "net.ipv4.conf.all.send_redirects" kernel parameter, run the following command: 
        #       # sysctl -w net.ipv4.conf.all.send_redirects=0
        #       If this is not the system's default value, add the following line to "/etc/sysctl.conf": 
        #       net.ipv4.conf.all.send_redirects = 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38602
    it "V-38602 The rlogind service must not be running." do
        # Check: To check that the "rlogin" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "rlogin" --list
        #       Output should indicate the "rlogin" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "rlogin" --list
        #       "rlogin" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "rlogin" is disabled through current runtime configuration: 
        #       # service rlogin status
        #       If the service is disabled the command will return the following output: 
        #       rlogin is stopped
        #       If the service is running, this is a finding.
        expect( service('rlogin')).not_to be_enabled
        expect( service('rlogin')).not_to be_running
        # Fix: The "rlogin" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rlogin" service can be disabled with the following command: 
        #       # chkconfig rlogin off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38603
    it "V-38603 The ypserv package must not be installed." do
        # Check: Run the following command to determine if the "ypserv" package is installed: 
        #       # rpm -q ypserv
        #       If the package is installed, this is a finding.
        expect( package('ypserv')).not_to be_installed
        # Fix: The "ypserv" package can be uninstalled with the following command: 
        #       # yum erase ypserv
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38604
    it "V-38604 The ypbind service must not be running." do
        # Check: To check that the "ypbind" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "ypbind" --list
        #       Output should indicate the "ypbind" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "ypbind" --list
        #       "ypbind" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "ypbind" is disabled through current runtime configuration: 
        #       # service ypbind status
        #       If the service is disabled the command will return the following output: 
        #       ypbind is stopped
        #       If the service is running, this is a finding.
        expect( service('ypbind')).not_to be_enabled
        expect( service('ypbind')).not_to be_running
        # Fix: The "ypbind" service, which allows the system to act as a client in a NIS or NIS+ domain, should be disabled. The "ypbind" service can be disabled with the following command: 
        #       # chkconfig ypbind off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38605
    it "V-38605 The cron service must be running." do
        # Check: Run the following command to determine the current status of the "crond" service: 
        #       # service crond status
        #       If the service is enabled, it should return the following: 
        #       crond is running...
        #       If the service is not running, this is a finding.
        expect( service('crond')).to be_enabled
        expect( service('crond')).to be_running
        # Fix: The "crond" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The "crond" service can be enabled with the following command: 
        #       # chkconfig crond on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38606
    it "V-38606 The tftp-server package must not be installed." do
        # Check: Run the following command to determine if the "tftp-server" package is installed: 
        #       # rpm -q tftp-server
        #       If the package is installed, this is a finding.
        expect( package('tftp-server')).not_to be_installed
        # Fix: The "tftp-server" package can be removed with the following command: 
        #       # yum erase tftp-server
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38607
    it "V-38607 The SSH daemon must be configured to use only the SSHv2 protocol." do
        # Check: To check which SSH protocol version is allowed, run the following command: 
        #       # grep Protocol /etc/ssh/sshd_config
        #       If configured properly, output should be 
        #       Protocol 2
        #       If it is not, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^Protocol 2/
        # Fix: Only SSH protocol version 2 connections should be permitted. The default setting in "/etc/ssh/sshd_config" is correct, and can be verified by ensuring that the following line appears: 
        #       Protocol 2
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38608
    it "V-38608 The SSH daemon must set a timeout interval on idle sessions." do
        # Check: Run the following command to see what the timeout interval is: 
        #       # grep ClientAliveInterval /etc/ssh/sshd_config
        #       If properly configured, the output should be: 
        #       ClientAliveInterval 900
        #       If it is not, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^ClientAliveInterval 900/
        # Fix: SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out. 
        #       To set an idle timeout interval, edit the following line in "/etc/ssh/sshd_config" as follows: 
        #       ClientAliveInterval [interval]
        #       The timeout [interval] is given in seconds. To have a timeout of 15 minutes, set [interval] to 900. 
        #       If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38609
    it "V-38609 The TFTP service must not be running." do
        # Check: To check that the "tftp" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "tftp" --list
        #       Output should indicate the "tftp" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "tftp" --list
        #       "tftp" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "tftp" is disabled through current runtime configuration: 
        #       # service tftp status
        #       If the service is disabled the command will return the following output: 
        #       tftp is stopped
        #       If the service is running, this is a finding.
        expect( service('tftp')).not_to be_enabled
        expect( service('tftp')).not_to be_running
        # Fix: The "tftinstalled?p" service should be disabled. The "tftp" service can be disabled with the following command: 
        #       # chkconfig tftp off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38610
    it "V-38610 The SSH daemon must set a timeout count on idle sessions." do
        # Check: To ensure the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command: 
        #       # grep ClientAliveCountMax /etc/ssh/sshd_config
        #       If properly configured, output should be: 
        #       ClientAliveCountMax 0
        #       If it is not, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^ClientAliveCountMax 0/
        # Fix: To ensure the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, edit "/etc/ssh/sshd_config" as follows: 
        #       ClientAliveCountMax 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38611
    it "V-38611 The SSH daemon must ignore .rhosts files." do
        # Check: To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command: 
        #       # grep -i IgnoreRhosts /etc/ssh/sshd_config
        #       If no line, a commented line, or a line indicating the value "yes" is returned, then the required value is set. 
        #       If the required value is not set, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^IgnoreRhosts/
        # Fix: SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files. 
        #       To ensure this behavior is disabled, add or correct the following line in "/etc/ssh/sshd_config": 
        #       IgnoreRhosts yes
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38612
    it "V-38612 The SSH daemon must not allow host-based authentication." do
        # Check: To determine how the SSH daemon's "HostbasedAuthentication" option is set, run the following command: 
        #       # grep -i HostbasedAuthentication /etc/ssh/sshd_config
        #       If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
        #       If the required value is not set, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^HostbasedAuthentication no/
        # Fix: SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization. 
        #       To disable host-based authentication, add or correct the following line in "/etc/ssh/sshd_config": 
        #       HostbasedAuthentication no
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38613
    it "V-38613 The system must not permit root logins using remote access programs such as ssh." do
        # Check: To determine how the SSH daemon's "PermitRootLogin" option is set, run the following command: 
        #       # grep -i PermitRootLogin /etc/ssh/sshd_config
        #       If a line indicating "no" is returned, then the required value is set. 
        #       If the required value is not set, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^PermitRootLogin no/
        # Fix: The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in "/etc/ssh/sshd_config": 
        #       PermitRootLogin no
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38614
    it "V-38614 The SSH daemon must not allow authentication using an empty password." do
        # Check: To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command: 
        #       # grep -i PermitEmptyPasswords /etc/ssh/sshd_config
        #       If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
        #       If the required value is not set, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^PermitEmptyPasswords no/
        # Fix: To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config": 
        #       PermitEmptyPasswords no
        #       Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38615
    it "V-38615 The SSH daemon must be configured with the Department of Defense (DoD) login banner." do
        # Check: To determine how the SSH daemon's "Banner" option is set, run the following command: 
        #       # grep -i Banner /etc/ssh/sshd_config
        #       If a line indicating /etc/issue is returned, then the required value is set. 
        #       If the required value is not set, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^Banner \/etc\/issue/
        # Fix: To enable the warning banner and ensure it is consistent across the system, add or correct the following line in "/etc/ssh/sshd_config": 
        #       Banner /etc/issue
        #       Another section contains information on how to create an appropriate system-wide warning banner.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38616
    it "V-38616 The SSH daemon must not permit user environment settings." do
        # Check: To ensure users are not able to present environment daemons, run the following command: 
        #       # grep PermitUserEnvironment /etc/ssh/sshd_config
        #       If properly configured, output should be: 
        #       PermitUserEnvironment no
        #       If it is not, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^PermitUserEnvironment no/
        # Fix: To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in "/etc/ssh/sshd_config": 
        #       PermitUserEnvironment no
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38617
    it "V-38617 The SSH daemon must be configured to use only FIPS 140-2 approved ciphers." do
        # Check: Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 
        #       # grep Ciphers /etc/ssh/sshd_config
        #       The output should contain only those ciphers which are FIPS-approved, namely, the AES and 3DES ciphers. 
        #       If that is not the case, this is a finding.
        expect( file('/etc/ssh/sshd_config')).to contain /^Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc/
        # Fix: Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The following line in "/etc/ssh/sshd_config" demonstrates use of FIPS-approved ciphers: 
        #       Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
        #       The man page "sshd_config(5)" contains a list of supported ciphers.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38618
    it "V-38618 The avahi service must be disabled." do
        # Check: To check that the "avahi-daemon" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "avahi-daemon" --list
        #       Output should indicate the "avahi-daemon" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "avahi-daemon" --list
        #       "avahi-daemon" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "avahi-daemon" is disabled through current runtime configuration: 
        #       # service avahi-daemon status
        #       If the service is disabled the command will return the following output: 
        #       avahi-daemon is stopped
        #       If the service is running, this is a finding.
        expect( service('avahi-daemon')).not_to be_enabled
        expect( service('avahi-daemon')).not_to be_running
        # Fix: The "avahi-daemon" service can be disabled with the following command: 
        #       # chkconfig avahi-daemon off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38619
    it "V-38619 There must be no .netrc files on the system." do
        # Check: To check the system for the existence of any ".netrc" files, run the following command: 
        #       # find /home -xdev -name .netrc
        #       If any .netrc files exist, this is a finding.
        expect( command('find /home -xdev -name .netrc')).to return_stdout ""
        # Fix: The ".netrc" files contain login information used to auto-login into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any ".netrc" files should be removed.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38620
    it "V-38620 The system clock must be synchronized continuously, or at least daily." do
        # Check: Run the following command to determine the current status of the "ntpd" service: 
        #       # service ntpd status
        #       If the service is enabled, it should return the following: 
        #       ntpd is running...
        #       If the service is not running, this is a finding.
        expect( service('ntpd')).to be_enabled
        expect( service('ntpd')).to be_running
        # Fix: The "ntpd" service can be enabled with the following command: 
        #       # chkconfig ntpd on
        #       # service ntpd start
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38621
    it "V-38621 The system clock must be synchronized to an authoritative DoD time source." do
        # Check: A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file. 
        #       /etc/ntp.conf
        #       In the file, there should be a section similar to the following: 
        #       # --- OUR TIMESERVERS -----
        #       server [ntpserver]
        #       If this is not the case, this is a finding.
        pending( "Optional step" )
        # Fix: To specify a remote NTP server for time synchronization, edit the file "/etc/ntp.conf". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver. 
        #       server [ntpserver]
        #       This instructs the NTP software to contact that remote server to obtain time data.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38622
    it "V-38622 Mail relaying must be restricted." do
        # Check: Run the following command to ensure postfix accepts mail messages from only the local system: 
        #       $ grep inet_interfaces /etc/postfix/main.cf
        #       If properly configured, the output should show only "localhost". 
        #       If it does not, this is a finding.
        expect( file('/etc/postfix/main.cf')).to contain /^inet_interfaces = localhost$/
        # Fix: Edit the file "/etc/postfix/main.cf" to ensure that only the following "inet_interfaces" line appears: 
        #       inet_interfaces = localhost
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38623
    it "V-38623 All rsyslog-generated log files must have mode 0600 or less permissive." do
        # Check: The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions: 
        #       $ ls -l [LOGFILE]
        #       The permissions should be 600, or more restrictive. 
        #       If the permissions are not correct, this is a finding.
         $environment['logFiles'].each do |log|
            expect( file(log)).to be_mode 600
        end
        # Fix: The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions:
        #       $ ls -l [LOGFILE]
        #       If the permissions are not 600 or more restrictive, run the following command to correct this:
        #       # chmod 0600 [LOGFILE]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38624
    it "V-38624 System logs must be rotated daily." do
        # Check: Run the following commands to determine the current status of the "logrotate" service: 
        #       # grep logrotate /var/log/cron*
        #       If the logrotate service is not run on a daily basis by cron, this is a finding.
        expect(package('logrotate')).to be_installed
        expect( file('/etc/cron.daily/logrotate')).to be_file
        expect( file('/etc/logrotate.d/syslog')).to be_file
        expect( file('/etc/logrotate.conf')).to contain /^daily$/
        # Fix: The "logrotate" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:
        #       # yum reinstall logrotate
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38625
    it "V-38625 If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms." do
        # Check: If the system does not use LDAP for authentication or account information, this is not applicable.
        #       To ensure LDAP is configured to use TLS for all transactions, run the following command: 
        #       $ grep start_tls /etc/pam_ldap.conf
        #       If no lines are returned, this is a finding.
        if property[:roles].include? 'ldapClient'
            expect( file('/etc/pam_ldap.conf')).to contain /^ssl start_tls$/
        else
            pending("Not applicable")
        end
        # Fix: Configure LDAP to enforce TLS use. First, edit the file "/etc/pam_ldap.conf", and add or correct the following lines: 
        #       ssl start_tls
        #       Then review the LDAP server and ensure TLS has been configured.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38626
    it "V-38626 The LDAP client must use a TLS connection using trust certificates signed by the site CA." do
        # Check: If the system does not use LDAP for authentication or account information, this is not applicable.
        #       To ensure TLS is configured with trust certificates, run the following command: 
        #       # grep cert /etc/pam_ldap.conf
        #       If there is no output, or the lines are commented out, this is a finding.
         if property[:roles].include? 'ldapClient'
            expect( file('/etc/pki/tls/CA/cacert.pem')).to be_file
            expect( file('/etc/pam_ldap.conf')).to contain /^tls_cacertfile \/etc\/pki\/tls\/CA\/cacert.pem$/
        else
            pending("Not applicable")
        end
        # Fix: Ensure a copy of the site's CA certificate has been placed in the file "/etc/pki/tls/CA/cacert.pem". Configure LDAP to enforce 
        #       TLS use and to trust certificates signed by the site's CA. First, edit the file "/etc/pam_ldap.conf", and add or correct either of the following lines: 
        #       tls_cacertdir /etc/pki/tls/CA
        #       or 
        #       tls_cacertfile /etc/pki/tls/CA/cacert.pem
        #       Then review the LDAP server and ensure TLS has been configured.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38627
    it "V-38627 The openldap-servers package must not be installed unless required." do
        # Check: To verify the "openldap-servers" package is not installed, run the following command: 
        #       $ rpm -q openldap-servers
        #       The output should show the following. 
        #       package openldap-servers is not installed
        #       If it does not, this is a finding.
        expect(package('openldap-servers')).not_to be_installed
        # Fix: The "openldap-servers" package should be removed if not in use. Is this machine the OpenLDAP server? If not, remove the package. 
        #       # yum erase openldap-servers
        #       The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38628
    it "V-38628 The operating system must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event." do
        # Check: Run the following command to determine the current status of the "auditd" service: 
        #       # service auditd status
        #       If the service is enabled, it should return the following: 
        #       auditd is running...
        #       If the service is not running, this is a finding.
        expect( service('auditd')).to be_enabled
        expect( service('auditd')).to be_running
        # Fix: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following command: 
        #       # chkconfig auditd on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38629
    it "V-38629 The graphical desktop environment must set the idle timeout to no more than 15 minutes." do
        # Check: To check the current idle time-out value, run the following command: 
        #       $ gconftool-2 -g /apps/gnome-screensaver/idle_delay
        #       If properly configured, the output should be "15". 
        #       If it is not, this is a finding.
        if property[:gnomeInstalled]
            expect( command('gconftool-2 -g /apps/gnome-screensaver/idle_delay')).to return_stdout "15"
        else
            pending( "Not applicable" )
        end
        # Fix: Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes: 
        #       # gconftool-2 \
        #       --direct \
        #       --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
        #       --type int \
        #       --set /apps/gnome-screensaver/idle_delay 15
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38630
    it "V-38630 The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user to re-authenticate to unlock the environment." do
        # Check: To check the screensaver mandatory use status, run the following command: 
        #       $ gconftool-2 -g /apps/gnome-screensaver/idle_activation_enabled
        #       If properly configured, the output should be "true". 
        #       If it is not, this is a finding.
        if property[:gnomeInstalled]
            expect( command('gconftool-2 -g /apps/gnome-screensaver/idle_activation_enabled')).to return_stdout "true"
        else
            pending( "Not applicable" )
        end
        # Fix: Run the following command to activate the screensaver in the GNOME desktop after a period of inactivity: 
        #       # gconftool-2 --direct \
        #       --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
        #       --type bool \
        #       --set /apps/gnome-screensaver/idle_activation_enabled true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38631
    it "V-38631 The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods." do
        # Check: Run the following command to determine the current status of the "auditd" service: 
        #       # service auditd status
        #       If the service is enabled, it should return the following: 
        #       auditd is running...
        #       If the service is not running, this is a finding.
        expect( service('auditd')).to be_enabled
        expect( service('auditd')).to be_running
        # Fix: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following command: 
        #       # chkconfig auditd on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38632
    it "V-38632 The operating system must produce audit records containing sufficient information to establish what type of events occurred." do
        # Check: Run the following command to determine the current status of the "auditd" service: 
        #       # service auditd status
        #       If the service is enabled, it should return the following: 
        #       auditd is running...
        #       If the service is not running, this is a finding.
        expect( service('auditd')).to be_enabled
        expect( service('auditd')).to be_running
        # Fix: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following command: 
        #       # chkconfig auditd on
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38633
    it "V-38633 The system must set a maximum audit log file size." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine how much data the system will 
        #       retain in each audit log file: "# grep max_log_file /etc/audit/auditd.conf" 
        #       max_log_file = 6
        #       If the system audit data threshold hasn't been properly set up, this is a finding.
        expect( command("grep '^max_log_file = [0-9]' /etc/audit/auditd.conf")).not_to return_stdout ""        
        maxFileRegex = '^max_log_file = (?<value>\d+)$'
        maxLogFile = command("grep '^max_log_file = [0-9]' /etc/audit/auditd.conf").stdout.strip
        parts = maxLogFile.match(maxFileRegex)
        expect( Integer(parts['value']) ).to be >= 6
        # Fix: Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting the correct value for [STOREMB]: 
        #       max_log_file = [STOREMB]
        #       Set the value to "6" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38634
    it "V-38634 The system must rotate audit log files that reach the maximum file size." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to rotate 
        #       logs when they reach their maximum size: "# grep max_log_file_action /etc/audit/auditd.conf" 
        #       max_log_file_action "rotate"
        #       If the system has not been properly set up to rotate audit logs, this is a finding.
        expect( command("grep -i '^max_log_file_action = rotate' /etc/audit/auditd.conf")).not_to return_stdout ""
        # Fix: The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by "auditd", add or correct the line in "/etc/audit/auditd.conf": 
        #       max_log_file_action = [ACTION]
        #       Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 
        #       "ignore"
        #       "syslog"
        #       "suspend"
        #       "rotate"
        #       "keep_logs"
        #       Set the "[ACTION]" to "rotate" to ensure log rotation occurs. This is the default. The setting is case-insensitive.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38635
    it "V-38635 The audit system must be configured to audit all attempts to alter system time through adjtimex." do
        # Check: To determine if the system is configured to audit calls to the "adjtimex" system call, run the following command: 
        #       # auditctl -l | grep syscall | grep adjtimex
        #       If the system is configured to audit this activity, it will return a line. 
        #       If the system is not configured to audit time changes, this is a finding.
        expect( command("auditctl -l | grep syscall | grep adjtimex")).not_to return_stdout ""
        # Fix: On a 32-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b32 -S adjtimex -k audit_time_rules
        #       On a 64-bit system, add the following to "/etc/audit/audit.rules": 
        #       # audit_time_rules
        #       -a always,exit -F arch=b64 -S adjtimex -k audit_time_rules
        #       The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 
        #       -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime 
        #       -k audit_time_rules
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38636
    it "V-38636 The system must retain enough rotated audit logs to cover the required log retention period." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine how many logs the system is configured to retain after 
        #        rotation: "# grep num_logs /etc/audit/auditd.conf" 
        #       num_logs = 5
        #       If the overall system log file(s) retention hasn't been properly set up, this is a finding.
        expect( command("grep '^num_logs = [0-9]' /etc/audit/auditd.conf")).not_to return_stdout ""        
        maxFileRegex = '^num_logs = (?<value>\d+)$'
        maxLogFile = command("grep '^num_logs = [0-9]' /etc/audit/auditd.conf").stdout.strip
        parts = maxLogFile.match(maxFileRegex)
        expect( Integer(parts['value']) ).to be >= 5

        # Fix: Determine how many log files "auditd" should retain when it rotates logs. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [NUMLOGS] with the correct value: 
        #       num_logs = [NUMLOGS]
        #       Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38637
    it "V-38637 The system package management tool must verify contents of all files associated with the audit package." do
        # Check: The following command will list which audit files on the system have file hashes different from what is expected by the RPM database. 
        #       # rpm -V audit | grep '$1 ~ /..5/ && $2 != "c"'
        #       If there is output, this is a finding.
        expect( command('rpm -V audit | grep \'$1 ~ /..5/ && $2 != "c"\'')).to return_stdout ""    
        # Fix: The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database: 
        #       # rpm -V audit | grep '^..5'
        #       A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories. 
        #       rpm -Uvh [affected_package]
        #       OR 
        #       yum reinstall [affected_package]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38638
    it "V-38638 The graphical desktop environment must have automatic lock enabled." do
        # Check: To check the status of the idle screen lock activation, run the following command: 
        #       $ gconftool-2 -g /apps/gnome-screensaver/lock_enabled
        #       If properly configured, the output should be "true". 
        #       If it is not, this is a finding.
        if property[:gnomeInstalled]
            expect( command('gconftool-2 -g /apps/gnome-screensaver/lock_enabled')).to return_stdout "true"
        else
            pending( "Not applicable" )
        end
 
        # Fix: Run the following command to activate locking of the screensaver in the GNOME desktop when it is activated: 
        #       # gconftool-2 --direct \
        #       --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
        #       --type bool \
        #       --set /apps/gnome-screensaver/lock_enabled true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38639
    it "V-38639 The system must display a publicly-viewable pattern during a graphical desktop environment session lock." do
        # Check: To ensure the screensaver is configured to be blank, run the following command: 
        #       $ gconftool-2 -g /apps/gnome-screensaver/mode
        #       If properly configured, the output should be "blank-only" 
        #       If it is not, this is a finding.
        if property[:gnomeInstalled]
            expect( command('gconftool-2 -g /apps/gnome-screensaver/mode')).to return_stdout "blank-only"
        else
            pending( "Not applicable" )
        end

        # Fix: Run the following command to set the screensaver mode in the GNOME desktop to a blank screen: 
        #       # gconftool-2
        #       --direct \
        #       --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
        #       --type string \
        #       --set /apps/gnome-screensaver/mode blank-only
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38640
    it "V-38640 The Automatic Bug Reporting Tool (abrtd) service must not be running." do
        # Check: To check that the "abrtd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "abrtd" --list
        #       Output should indicate the "abrtd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "abrtd" --list
        #       "abrtd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "abrtd" is disabled through current runtime configuration: 
        #       # service abrtd status
        #       If the service is disabled the command will return the following output: 
        #       abrtd is stopped
        #       If the service is running, this is a finding.
        expect( service('abrtd')).not_to be_enabled
        expect( service('abrtd')).not_to be_running
        # Fix: The Automatic Bug Reporting Tool ("abrtd") daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The "abrtd" service can be disabled with the following command: 
        #       # chkconfig abrtd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38641
    it "V-38641 The atd service must be disabled." do
        # Check: If the system uses the "atd" service, this is not applicable.
        #       To check that the "atd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "atd" --list
        #       Output should indicate the "atd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "atd" --list
        #       "atd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "atd" is disabled through current runtime configuration: 
        #       # service atd status
        #       If the service is disabled the command will return the following output: 
        #       atd is stopped
        #       If the service is running, this is a finding.
        expect( service('atd')).not_to be_enabled
        expect( service('atd')).not_to be_running
        # Fix: The "at" and "batch" commands can be used to schedule tasks that are meant to be executed only once. This allows delayed execution in a manner similar to cron, except that it is not recurring. The daemon "atd" keeps track of tasks scheduled via "at" and "batch", and executes them at the specified time. The "atd" service can be disabled with the following command: 
        #       # chkconfig atd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38642
    it "V-38642 The system default umask for daemons must be 027 or 022." do
        # Check: To check the value of the "umask", run the following command: 
        #       $ grep umask /etc/init.d/functions
        #       The output should show either "022" or "027". 
        #       If it does not, this is a finding.
       expect( command("grep -i '^umask 022\\|027' /etc/init.d/functions")).not_to return_stdout ""
        # Fix: The file "/etc/init.d/functions" includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for [UMASK] appropriately: 
        #       umask [UMASK]
        #       Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38643
    it "V-38643 There must be no world-writable files on the system." do
        # Check: To find world-writable files, run the following command: 
        #       # find / -xdev -type f -perm -002
        #       If there is output, this is a finding.
        expect( command("find / -xdev -type f -perm -002")).to return_stdout ""
        # Fix: It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38644
    it "V-38644 The ntpdate service must not be running." do
        # Check: To check that the "ntpdate" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "ntpdate" --list
        #       Output should indicate the "ntpdate" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "ntpdate" --list
        #       "ntpdate" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "ntpdate" is disabled through current runtime configuration: 
        #       # service ntpdate status
        #       If the service is disabled the command will return the following output: 
        #       ntpdate is stopped
        #       If the service is running, this is a finding.
        expect( service('ntpdate')).not_to be_enabled
        expect( service('ntpdate')).not_to be_running
        # Fix: The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in "/etc/ntp/step-tickers" or "/etc/ntp.conf" and then sets the local hardware clock to the newly synchronized system time. The "ntpdate" service can be disabled with the following command: 
        #       # chkconfig ntpdate off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38645
    it "V-38645 The system default umask in /etc/login.defs must be 077." do
        # Check: Verify the "umask" setting is configured correctly in the "/etc/login.defs" file by running the following command: 
        #       # grep -i "umask" /etc/login.defs
        #       All output must show the value of "umask" set to 077, as shown in the below: 
        #       # grep -i "umask" /etc/login.defs
        #       UMASK 077
        #       If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
        expect( command("grep -i '^umask[[:space:]]\\+077' /etc/login.defs")).not_to return_stdout ""
        # Fix: To ensure the default umask controlled by "/etc/login.defs" is set properly, add or correct the "umask" setting in "/etc/login.defs" to read as follows: 
        #       UMASK 077
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38646
    it "V-38646 The oddjobd service must not be running." do
        # Check: To check that the "oddjobd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "oddjobd" --list
        #       Output should indicate the "oddjobd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "oddjobd" --list
        #       "oddjobd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "oddjobd" is disabled through current runtime configuration: 
        #       # service oddjobd status
        #       If the service is disabled the command will return the following output: 
        #       oddjobd is stopped
        #       If the service is running, this is a finding.
        expect( service('oddjobd')).not_to be_enabled
        expect( service('oddjobd')).not_to be_running
        # Fix: The "oddjobd" service exists to provide an interface and access control mechanism through which specified privileged tasks can run tasks for unprivileged client applications. Communication with "oddjobd" is through the system message bus. The "oddjobd" service can be disabled with the following command: 
        #       # chkconfig oddjobd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38647
    it "V-38647 The system default umask in /etc/profile must be 077." do
        # Check: Verify the "umask" setting is configured correctly in the "/etc/profile" file by running the following command: 
        #       # grep "umask" /etc/profile
        #       All output must show the value of "umask" set to 077, as shown in the below: 
        #       # grep "umask" /etc/profile
        #       umask 077
        #       If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
        expect( command("grep -i '^umask[[:space:]]\\+077' /etc/lprofile")).not_to return_stdout ""
        # Fix: To ensure the default umask controlled by "/etc/profile" is set properly, add or correct the "umask" setting in "/etc/profile" to read as follows: 
        #       umask 077
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38648
    it "V-38648 The qpidd service must not be running." do
        # Check: To check that the "qpidd" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "qpidd" --list
        #       Output should indicate the "qpidd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "qpidd" --list
        #       "qpidd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "qpidd" is disabled through current runtime configuration: 
        #       # service qpidd status
        #       If the service is disabled the command will return the following output: 
        #       qpidd is stopped
        #       If the service is running, this is a finding.
        expect( service('qpidd')).not_to be_enabled
        expect( service('qpidd')).not_to be_running
        # Fix: The "qpidd" service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The "qpidd" service can be disabled with the following command: 
        #       # chkconfig qpidd off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38649
    it "V-38649 The system default umask for the csh shell must be 077." do
        # Check: Verify the "umask" setting is configured correctly in the "/etc/csh.cshrc" file by running the following command: 
        #       # grep "umask" /etc/csh.cshrc
        #       All output must show the value of "umask" set to 077, as shown in the below: 
        #       # grep "umask" /etc/csh.cshrc
        #       umask 077
        #       If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
        expect( command("grep -i '^umask[[:space:]]\\+077' /etc/csh.cshrc")).not_to return_stdout ""
        matches = command("grep -i '^umask[[:space:]]\\+077' /etc/csh.cshrc").stdout.strip
        expect( matches.lines.count ).to equal(1)
        # Fix: To ensure the default umask for users of the C shell is set properly, add or correct the "umask" setting in "/etc/csh.cshrc" to read as follows: 
        #       umask 077
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38650
    it "V-38650 The rdisc service must not be running." do
        # Check: To check that the "rdisc" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "rdisc" --list
        #       Output should indicate the "rdisc" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "rdisc" --list
        #       "rdisc" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "rdisc" is disabled through current runtime configuration: 
        #       # service rdisc status
        #       If the service is disabled the command will return the following output: 
        #       rdisc is stopped
        #       If the service is running, this is a finding.
        expect( service('rdisc')).not_to be_enabled
        expect( service('rdisc')).not_to be_running
        # Fix: The "rdisc" service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The "rdisc" service can be disabled with the following command: 
        #       # chkconfig rdisc off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38651
    it "V-38651 The system default umask for the bash shell must be 077." do
        # Check: Verify the "umask" setting is configured correctly in the "/etc/bashrc" file by running the following command: 
        #       # grep "umask" /etc/bashrc
        #       All output must show the value of "umask" set to 077, as shown below: 
        #       # grep "umask" /etc/bashrc
        #       umask 077
        #       umask 077
        #       If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
        expect( command("grep -i '^[[:space:]]\\+umask[[:space:]]\\+077' /etc/bashrc")).not_to return_stdout ""
        matches = command("grep -i '^[[:space:]]\\+umask[[:space:]]\\+077' /etc/bashrc").stdout.strip
        expect( matches.lines.count ).to equal(1)
        # Fix: To ensure the default umask for users of the Bash shell is set properly, add or correct the "umask" setting in "/etc/bashrc" to read as follows: 
        #       umask 077
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38652
    it "V-38652 Remote file systems must be mounted with the nodev option." do
        # Check: To verify the "nodev" option is configured for all NFS mounts, run the following command: 
        #       $ mount | grep nfs
        #       All NFS mounts should show the "nodev" setting in parentheses. 
        #       If the setting does not show, this is a finding.
        if property[:roles].include? 'nfsClient'
            expect( command("mount | grep nfs | grep nodev")).not_to return_stdout ""
        else
            pending( "Not applicable" )
        end
        # Fix: Add the "nodev" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38653
    it "V-38653 The snmpd service must not use a default password." do
        # Check: To ensure the default password is not set, run the following command: 
        #       # grep -v "^#" /etc/snmp/snmpd.conf| grep public
        #       There should be no output. 
        #       If there is output, this is a finding.
        if property[:roles].include? 'snmpClient'
            expect( command('grep -v "^#" /etc/snmp/snmpd.conf| grep public')).to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: Edit "/etc/snmp/snmpd.conf", remove default community string "public". Upon doing that, restart the SNMP service: 
        #       # service snmpd restart
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38654
    it "V-38654 Remote file systems must be mounted with the nosuid option." do
        # Check: To verify the "nosuid" option is configured for all NFS mounts, run the following command: 
        #       $ mount | grep nfs
        #       All NFS mounts should show the "nosuid" setting in parentheses. 
        #       If the setting does not show, this is a finding.
        if property[:roles].include? 'nfsClient'
            expect( command("mount | grep nfs | grep nosuid")).not_to return_stdout ""
        else
            pending( "Not applicable" )
        end
        # Fix: Add the "nosuid" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38655
    it "V-38655 The noexec option must be added to removable media partitions." do
        # Check: To verify that binaries cannot be directly executed from removable media, run the following command: 
        #       # grep noexec /etc/fstab
        #       The output should show "noexec" in use. 
        #       If it does not, this is a finding.
        pending( "Optional step" )
        # Fix: The "noexec" mount option prevents the direct execution of binaries on the mounted filesystem. Users 
        #      should not be allowed to execute binaries that exist on partitions mounted from removable media (such as 
        #      a USB key). The "noexec" option prevents code from being executed directly from the media itself, and may 
        #      therefore provide a line of defense against certain types of worms or malicious code. Add the "noexec" option 
        #      to the fourth column of "/etc/fstab" for the line which controls mounting of any removable media partitions.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38656
    it "V-38656 The system must use SMB client signing for connecting to samba servers using smbclient." do
        # Check: To verify that Samba clients running smbclient must use packet signing, run the following command: 
        #       # grep signing /etc/samba/smb.conf
        #       The output should show: 
        #       client signing = mandatory
        #       If it is not, this is a finding.
        if property[:roles].include? 'sambaClient'
            expect( command("grep signing /etc/samba/smb.conf | grep 'client signing = mandatory'")).not_to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: To require samba clients running "smbclient" to use packet signing, add the following to the "[global]" section of the Samba configuration file in "/etc/samba/smb.conf": 
        #       client signing = mandatory
        #       Requiring samba clients such as "smbclient" to use packet signing ensures they can only communicate with servers that support packet signing.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38657
    it "V-38657 The system must use SMB client signing for connecting to samba servers using mount.cifs." do
        # Check: To verify that Samba clients using mount.cifs must use packet signing, run the following command: 
        #       # grep sec /etc/fstab
        #       The output should show either "krb5i" or "ntlmv2i" in use. 
        #       If it does not, this is a finding.
        if property[:roles].include? 'sambaClient'
            expect( command("grep sec /etc/fstab | grep 'krb5i\\|ntlmv2i'")).not_to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: Require packet signing of clients who mount Samba shares using the "mount.cifs" program (e.g., those 
        #      who specify shares in "/etc/fstab"). To do so, ensure signing options (either "sec=krb5i" or "sec=ntlmv2i") are used. 
        #      See the "mount.cifs(8)" man page for more information. A Samba client should only communicate with servers who 
        #      can support SMB packet signing.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38658
    it "V-38658 The system must prohibit the reuse of passwords within twenty-four iterations." do
        # Check: To verify the password reuse setting is compliant, run the following command: 
        #       $ grep remember /etc/pam.d/system-auth
        #       The output should show the following at the end of the line: 
        #       remember=24
        #       If it does not, this is a finding.
        expect( command("grep 'remember=24' /etc/pam.d/system-auth-ac")).not_to return_stdout ""
        # Fix: Do not allow users to reuse recent passwords. This can be accomplished by using the "remember" option for the "pam_unix" PAM module. In the file "/etc/pam.d/system-auth", append "remember=24" to the line which refers to the "pam_unix.so" module, as shown: 
        #       password sufficient pam_unix.so [existing_options] remember=24
        #       The DoD requirement is 24 passwords.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38659
    it "V-38659 The operating system must employ cryptographic mechanisms to protect information in storage." do
        # Check: Determine if encryption must be used to protect data on the system. 
        #       If encryption must be used and is not employed, this is a finding.
        pending( "Optional step" )
        # Fix: Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 
        #       For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 
        #       For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 
        #       part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]
        #       Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 
        #       Detailed information on encrypting partitions using LUKS can be found on the Red Had Documentation web site:
        #       https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38660
    it "V-38660 The snmpd service must use only SNMP protocol version 3 or newer." do
        # Check: To ensure only SNMPv3 or newer is used, run the following command: 
        #       # grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'
        #       There should be no output. 
        #       If there is output, this is a finding.
        if property[:roles].include? 'snmpClient'
            expect( command("grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'")).to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: Edit "/etc/snmp/snmpd.conf", removing any references to "v1", "v2c", or "com2sec". Upon doing that, restart the SNMP service: 
        #       # service snmpd restart
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38661
    it "V-38661 The operating system must protect the confidentiality and integrity of data at rest." do
        # Check: Determine if encryption must be used to protect data on the system. 
        #       If encryption must be used and is not employed, this is a finding.
        pending( "Optional step" )
        # Fix: Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 
        #       For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 
        #       For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 
        #       part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]
        #       Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 
        #       Detailed information on encrypting partitions using LUKS can be found on the Red Had Documentation web site:
        #       https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38662
    it "V-38662 The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures." do
        # Check: Determine if encryption must be used to protect data on the system. 
        #       If encryption must be used and is not employed, this is a finding.
        pending( "Optional step" )
        # Fix: Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 
        #       For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 
        #       For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 
        #       part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]
        #       Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 
        #       Detailed information on encrypting partitions using LUKS can be found on the Red Had Documentation web site:
        #       https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38663
    it "V-38663 The system package management tool must verify permissions on all files and directories associated with the audit package." do
        # Check: The following command will list which audit files on the system have permissions different from what is expected by the RPM database: 
        #       # rpm -V audit | grep '^.M'
        #       If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:
        #       # rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep  [filename]
        #       # ls -lL [filename]
        #       If the existing permissions are more permissive than those expected by RPM, this is a finding.
        expect( command("rpm -V audit | grep '^.M'")).to return_stdout ""
        # Fix: The RPM package management system can restore file access permissions of the audit package files and directories. The following command will update audit files with permissions different from what is expected by the RPM database: 
        #       # rpm --setperms audit
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38664
    it "V-38664 The system package management tool must verify ownership on all files and directories associated with the audit package." do
        # Check: The following command will list which audit files on the system have ownership different from what is expected by the RPM database: 
        #       # rpm -V audit | grep '^.....U'
        #       If there is output, this is a finding.
        expect( command("rpm -V audit | grep '^.....U'")).to return_stdout ""
        # Fix: The RPM package management system can restore file ownership of the audit package files and directories. The following command will update audit files with ownership different from what is expected by the RPM database: 
        #       # rpm --setugids audit
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38665
    it "V-38665 The system package management tool must verify group-ownership on all files and directories associated with the audit package." do
        # Check: The following command will list which audit files on the system have group-ownership different from what is expected by the RPM database: 
        #       # rpm -V audit | grep '^......G'
        #       If there is output, this is a finding.
        expect( command("rpm -V audit | grep '^......G'")).to return_stdout ""
        # Fix: The RPM package management system can restore file group-ownership of the audit package files and directories. The following command will update audit files with group-ownership different from what is expected by the RPM database: 
        #       # rpm --setugids audit
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38666
    it "V-38666 The system must use and update a DoD-approved virus scan program." do
        # Check: Inspect the system for a cron job or system service which executes a virus scanning tool regularly. 
        #       To verify the McAfee command line scan tool (uvscan) is scheduled for regular execution, run the following command to check for a cron job: 
        #       # grep uvscan /etc/cron* /var/spool/cron/*
        #       This will reveal if and when the uvscan program will be run. 
        #       To check on the age of uvscan virus definition files, run the following command: 
        #       # cd /usr/local/uvscan
        #       # ls -la avvscan.dat avvnames.dat avvclean.dat
        #       The uvscan virus definitions should not be older than seven days.
        #       If virus scanning software does not run daily, or has signatures that are out of date, this is a finding.
        expect( package("clamav")).to be_installed
        ### Couldn't get this to work in bash. Had to bring out the big guns.
        daysOld = command('python -c "import os.path, time;print (time.time() - os.path.getmtime(\"/var/lib/clamav/daily.cld\")) / (24 * 60 * 60)"').stdout.strip
        expect( Float(daysOld)).to be <= 7.0
        # Fix: Install virus scanning software, which uses signatures to search for the presence of viruses on the filesystem. 
        #      The McAfee uvscan virus scanning tool is provided for DoD systems. Ensure virus definition files are no older than 
        #      7 days, or their last release. Configure the virus scanning software to perform scans dynamically on all accessed 
        #      files. If this is not possible, configure the system to scan all altered files on the system on a daily basis. If 
        #      the system processes inbound SMTP mail, configure the virus scanner to scan all received mail.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38667
    it "V-38667 The system must have a host-based intrusion detection tool installed." do
        # Check: Inspect the system to determine if intrusion detection software has been installed. Verify the intrusion 
        # detection software is active. 
        #       If no host-based intrusion detection tools are installed, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( package('ossec-hids') ).to be_installed
        elsif $environment['ids'] == 'aide'
            expect( package('aide') ).to be_installed
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: The base Red Hat platform already includes a sophisticated auditing system that can detect intruder activity, as 
        #      well as SELinux, which provides host-based intrusion prevention capabilities by confining privileged programs and 
        #      user sessions which may become compromised. 
        #      Install an additional intrusion detection tool to provide complementary or duplicative monitoring, reporting, and 
        #      reaction capabilities to those of the base platform. For DoD systems, the McAfee Host-based Security System is 
        #      provided to fulfill this role.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38668
    it "V-38668 The x86 Ctrl-Alt-Delete key sequence must be disabled." do
        # Check: Determine what actions the system takes when the Ctrl-Alt-Delete key sequence is pressed, run the following command:
        #       #  cat `grep -l control-alt-delete /etc/init/*`
        #       Examine all lines following the "start on control-alt-delete" line in any files found.  By default, the system uses 
        #      "/etc/init/control-alt-delete.conf" to reboot the system with the following command when the Ctrl-Alt-Delete key sequence is pressed: 
        #       exec /sbin/shutdown -r now "Control-Alt-Delete pressed"
        #       If the system is configured to run any shutdown command, this is a finding.
        expect( file('/etc/init/control-alt-delete.override')).to be_file
        expect( file('/etc/init/control-alt-delete.override')).to contain /^exec \/usr\/bin\/logger -p security.info "Ctrl-Alt-Delete pressed"/
        matches = command("cat /etc/init/control-alt-delete.override").stdout.strip
        expect( matches.lines.count ).to equal(1)
        # Fix: Configure the system to log a message instead of rebooting the system by altering the "shutdown" line in "/etc/init/control-alt-delete.conf" to read as follows: 
        #       exec /usr/bin/logger -p security.info "Ctrl-Alt-Delete pressed"
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38669
    it "V-38669 The postfix service must be enabled for mail delivery." do
        # Check: Run the following command to determine the current status of the "postfix" service:
        #       # service postfix status
        #       If the service is enabled, it should return the following:
        #       postfix is running...
        #       If the service is not enabled, this is a finding.
        expect( service('postfix')).to be_enabled
        expect( service('postfix')).to be_running
        # Fix: The Postfix mail transfer agent is used for local mail delivery within the system. The default configuration only listens for connections to the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is recommended to leave this service enabled for local mail delivery. The "postfix" service can be enabled with the following command: 
        #       # chkconfig postfix on
        #       # service postfix start
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38670
    it "V-38670 The operating system must detect unauthorized changes to software and information." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38671
    it "V-38671 The sendmail package must be removed." do
        # Check: Run the following command to determine if the "sendmail" package is installed: 
        #       # rpm -q sendmail
        #       If the package is installed, this is a finding.
       expect( package('sendmail')).not_to be_installed
        # Fix: Sendmail is not the default mail transfer agent and is not installed by default. The "sendmail" package can be removed with the following command: 
        #       # yum erase sendmail
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38672
    it "V-38672 The netconsole service must be disabled unless required." do
        # Check: To check that the "netconsole" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "netconsole" --list
        #       Output should indicate the "netconsole" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "netconsole" --list
        #       "netconsole" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "netconsole" is disabled through current runtime configuration: 
        #       # service netconsole status
        #       If the service is disabled the command will return the following output: 
        #       netconsole is stopped
        #       If the service is running, this is a finding.
        expect( service('netconsole')).not_to be_enabled
        expect( service('netconsole')).not_to be_running
        # Fix: The "netconsole" service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The "netconsole" service can be disabled with the following command: 
        #       # chkconfig netconsole off
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38673
    it "V-38673 The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38674
    it "V-38674 X Windows must not be enabled unless required." do
        # Check: To verify the default runlevel is 3, run the following command: 
        #       # grep initdefault /etc/inittab
        #       The output should show the following: 
        #       id:3:initdefault:
        #       If it does not, this is a finding.
        expect( command("grep initdefault /etc/inittab| grep 'id:3:initdefault:'")).not_to return_stdout ""
        # Fix: Setting the system's runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in "/etc/inittab" features a "3" as shown: 
        #       id:3:initdefault:
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38675
    it "V-38675 Process core dumps must be disabled unless needed." do
        # Check: To verify that core dumps are disabled for all users, run the following command: 
        #       $ grep core /etc/security/limits.conf
        #       The output should be: 
        #       * hard core 0
        #       If it is not, this is a finding.
        expect( command("grep '^* hard core 0' /etc/security/limits.conf")).not_to return_stdout ""
        # Fix: To disable core dumps for all users, add the following line to "/etc/security/limits.conf": 
        #       * hard core 0
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38676
    it "V-38676 The xorg-x11-server-common (X Windows) package must not be installed, unless required." do
        # Check: To ensure the X Windows package group is removed, run the following command: 
        #       $ rpm -qi xorg-x11-server-common
        #       The output should be: 
        #       package xorg-x11-server-common is not installed
        #       If it is not, this is a finding.
        expect( command("rpm -qi xorg-x11-server-common")).to return_stdout "package xorg-x11-server-common is not installed"
        # Fix: Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command: 
        #       # yum groupremove "X Window System"
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38677
    it "V-38677 The NFS server must not have the insecure file locking option enabled." do
        # Check: To verify insecure file locking has been disabled, run the following command: 
        #       # grep insecure_locks /etc/exports
        #       If there is output, this is a finding.
        if property[:roles].include? 'nfsServer'
            expect( command("grep insecure_locks /etc/exports")).to return_stdout ""
        else
            pending( "Not applicable" )
        end
        # Fix: By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files. To get around this, the "insecure_locks" option can be used so these clients can access the desired export. This poses a security risk by potentially allowing the client access to data for which it does not have authorization. Remove any instances of the "insecure_locks" option from the file "/etc/exports".
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38678
    it "V-38678 The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine whether the system is configured to email 
        #       the administrator when disk space is starting to run low: 
        #       # grep space_left /etc/audit/auditd.conf 
        #       space_left = [num_megabytes]
        #       If the "num_megabytes" value does not correspond to a documented value for remaining audit partition capacity 
        #       or if there is no locally documented value for remaining audit partition capacity, this is a finding.
        expect( command("grep ^space_left /etc/audit/auditd.conf ")).not_to return_stdout ""
        maxFileRegex = '^space_left = (?<value>\d+)$'
        maxLogFile = command("grep '^space_left = [0-9]' /etc/audit/auditd.conf").stdout.strip
        parts = maxLogFile.match(maxFileRegex)
        expect( Integer(parts['value']) ).to equal($environment['auditSpaceLeftInMegabytes'])
        # Fix: The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file 
        #       "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 
        #       space_left = [num_megabytes]
        #       The "num_megabytes" value should be set to a fraction of the total audit storage capacity available that will allow 
        #       a system administrator to be notified with enough time to respond to the situation causing the capacity issues.  
        #       This value must also be documented locally.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38679
    it "V-38679 The DHCP client must be disabled if not needed." do
        # Check: To verify that DHCP is not being used, examine the following file for each interface. 
        #       # /etc/sysconfig/network-scripts/ifcfg-[IFACE]
        #       If there is any network interface without a associated "ifcfg" file, this is a finding.
        #       Look for the following:
        #       BOOTPROTO=static
        #       Also verify the following, substituting the appropriate values based on your site's addressing scheme:
        #       NETMASK=[local LAN netmask]
        #       IPADDR=[assigned IP address]
        #       GATEWAY=[local LAN default gateway]
        #       If it does not, this is a finding.
        property[:networks].each do |nic| 
            expect( file("/etc/sysconfig/network-scripts/ifcfg-eth#{nic['device_id']}#{nic['vlan_id']}")).to be_file
            if nic['boot_protocol'] == "dhcp"
                expect( command("grep -i '^BOOTPROTO=#{nic['boot_protocol']}' /etc/sysconfig/network-scripts/ifcfg-eth#{nic['device_id']}#{nic['vlan_id']}")).not_to return_stdout "" 
            else
                expect( command("grep -i '^BOOTPROTO=#{nic['boot_protocol']}' /etc/sysconfig/network-scripts/ifcfg-eth#{nic['device_id']}#{nic['vlan_id']}")).not_to return_stdout "" 
                expect( command("grep -i '^PREFIX=#{nic['prefix']}' /etc/sysconfig/network-scripts/ifcfg-eth#{nic['device_id']}#{nic['vlan_id']}")).not_to return_stdout "" 
                expect( command("grep -i '^IPADDR=#{nic['ip_address']}' /etc/sysconfig/network-scripts/ifcfg-eth#{nic['device_id']}#{nic['vlan_id']}")).not_to return_stdout ""
            end
        end
        # Fix: For each interface [IFACE] on the system (e.g. eth0), edit "/etc/sysconfig/network-scripts/ifcfg-[IFACE]" and 
        #       make the following changes. 
        #       Correct the BOOTPROTO line to read:
        #       BOOTPROTO=static
        #       Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:
        #       NETMASK=[local LAN netmask]
        #       IPADDR=[assigned IP address]
        #       GATEWAY=[local LAN default gateway]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38680
    it "V-38680 The audit system must identify staff members to receive notifications of audit log storage volume capacity issues." do
        # Check: Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator: 
        #       action_mail_acct = root
        #       If auditd is not configured to send emails per identified actions, this is a finding.
        expect( command("grep -i '^action_mail_acct = root' /etc/audit/auditd.conf")).not_to return_stdout ""
        # Fix: The "auditd" service can be configured to send email to a designated account in certain situations. Add or correct the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 
        #       action_mail_acct = root
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38681
    it "V-38681 All GIDs referenced in /etc/passwd must be defined in /etc/group" do
        # Check: To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command: 
        #       # pwck -rq
        #       There should be no output. 
        #       If there is output, this is a finding.
        expect( command("pwck -rq")).to return_stdout ""
        # Fix: Add a group to the system for each GID referenced without a corresponding group.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38682
    it "V-38682 The Bluetooth kernel module must be disabled." do
        # Check: If the system is configured to prevent the loading of the "bluetooth" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d
        #       If the system is configured to prevent the loading of the "net-pf-31" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 
        #       $ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d
        #       If no line is returned, this is a finding.
        expect( command("grep -r bluetooth /etc/modprobe.d")).not_to return_stdout ""
        expect( command("grep -r net-pf-31 /etc/modprobe.d")).not_to return_stdout ""
        # Fix: The kernel's module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate "/etc/modprobe.d" configuration file to prevent the loading of the Bluetooth module: 
        #       install net-pf-31 /bin/true
        #       install bluetooth /bin/true
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38683
    it "V-38683 All accounts on the system must have unique user or account names" do
        # Check: Run the following command to check for duplicate account names: 
        #       # pwck -rq
        #       If there are no duplicate names, no line will be returned. 
        #       If a line is returned, this is a finding.
        expect( command("pwck -rq")).to return_stdout ""
        # Fix: Change usernames, or delete accounts, so each has a unique name.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38684
    it "V-38684 The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements." do
        # Check: Run the following command to ensure the "maxlogins" value is configured for all users on the system: 
        #       # grep "maxlogins" /etc/security/limits.conf
        #       You should receive output similar to the following: 
        #       * hard maxlogins 10
        #       If it is not set to 10 or a documented site-defined number, this is a finding.
        expect( command("grep '^* hard maxlogins 10' /etc/security/limits.conf")).not_to return_stdout ""
        # Fix: Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in "/etc/security/limits.conf": 
        #       * hard maxlogins 10
        #       A documented site-defined number may be substituted for 10 in the above.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38685
    it "V-38685 Temporary accounts must be provisioned with an expiration date." do
        # Check: For every temporary account, run the following command to obtain its account aging and expiration information: 
        #       # chage -l [USER]
        #       Verify each of these accounts has an expiration date set as documented. 
        #       If any temporary accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
        pending( "Manual step" )
        # Fix: In the event temporary accounts are required, configure the system to terminate them after a documented time period. For every temporary account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 
        #       # chage -E [YYYY-MM-DD] [USER]
        #       "[YYYY-MM-DD]" indicates the documented expiration date for the account.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38686
    it "V-38686 The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets." do
        # Check: Run the following command to ensure the default "FORWARD" policy is "DROP": 
        #       grep ":FORWARD" /etc/sysconfig/iptables
        #       The output must be the following: 
        #       # grep ":FORWARD" /etc/sysconfig/iptables
        #       :FORWARD DROP [0:0]
        #       If it is not, this is a finding.
        if property[:roles].include? 'router'
            pending("Not applicable")
        else
            expect( file('/etc/sysconfig/iptables')).to contain /^\:FORWARD DROP \[0\:0\]/
            if $environment['ipv6Enabled']
                expect( file('/etc/sysconfig/ip6tables')).to contain /^\:FORWARD DROP \[0\:0\]/
            end
        end
        # Fix: To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in "/etc/sysconfig/iptables": 
        #       :FORWARD DROP [0:0]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38687
    it "V-38687 The system must provide VPN connectivity for communications over untrusted networks." do
        # Check: Run the following command to determine if the "openswan" package is installed: 
        #       # rpm -q openswan
        #       If the package is not installed, this is a finding.
        if property[:roles].include? 'VPN'
            expect( package("openswan")).to be_installed
        else
            pending( "Not applicable" )
        end
        # Fix: The Openswan package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The "openswan" package can be installed with the following command: 
        #       # yum install openswan
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38688
    it "V-38688 A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts." do
        # Check: To ensure a login warning banner is enabled, run the following: 
        #       $ gconftool-2 -g /apps/gdm/simple-greeter/banner_message_enable
        #       Search for the "banner_message_enable" schema. If properly configured, the "default" value should be "true". 
        #       If it is not, this is a finding.
        if property[:gnomeInstalled]
            expect( command("gconftool-2 -g /apps/gdm/simple-greeter/banner_message_enable")).to return_stdout "true"
        else
            pending("Not applicable")
        end
        # Fix: To enable displaying a login warning banner in the GNOME Display Manager's login screen, run the following command: 
        #       sudo -u gdm gconftool-2 \
        #       --type bool \
        #       --set /apps/gdm/simple-greeter/banner_message_enable true
        #       To display a banner, this setting must be enabled and then banner text must also be set.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38689
    it "V-38689 The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts." do
        # Check: To ensure login warning banner text is properly set, run the following: 
        #       $ gconftool-2 -g /apps/gdm/simple-greeter/banner_message_text
        #       If properly configured, the proper banner text will appear within this schema. 
        #       The DoD required text is either: 
        #       "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
        #       -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
        #       -At any time, the USG may inspect and seize data stored on this IS. 
        #       -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
        #       -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. 
        #       -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
        #       OR: 
        #       "I've read & consent to terms in IS user agreem't."
        #       If the DoD required banner text is not appear in the schema, this is a finding.
        if property[:gnomeInstalled]
            expect( command("gconftool-2 -g /apps/gdm/simple-greeter/banner_message_text")).not_to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: To set the text shown by the GNOME Display Manager in the login screen, run the following command: 
        #       sudo -u gdm gconftool-2 \
        #       --type string \
        #       --set /apps/gdm/simple-greeter/banner_message_text \
        #       "[DoD required text]"
        #       Where the DoD required text is either: 
        #       "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
        #       -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
        #       -At any time, the USG may inspect and seize data stored on this IS. 
        #       -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
        #       -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. 
        #       -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
        #       OR: 
        #       "I've read & consent to terms in IS user agreem't."
        #       When entering a warning banner that spans several lines, remember to begin and end the string with """. This command writes directly to the file "/var/lib/gdm/.gconf/apps/gdm/simple-greeter/%gconf.xml", and this file can later be edited directly if necessary.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38690
    it "V-38690 Emergency accounts must be provisioned with an expiration date." do
        # Check: For every emergency account, run the following command to obtain its account aging and expiration information: 
        #       # chage -l [USER]
        #       Verify each of these accounts has an expiration date set as documented. 
        #       If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
        pending( "Manual step" )
        # Fix: In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 
        #       # chage -E [YYYY-MM-DD] [USER]
        #       "[YYYY-MM-DD]" indicates the documented expiration date for the account.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38691
    it "V-38691 The Bluetooth service must be disabled." do
        # Check: To check that the "bluetooth" service is disabled in system boot configuration, run the following command: 
        #       # chkconfig "bluetooth" --list
        #       Output should indicate the "bluetooth" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 
        #       # chkconfig "bluetooth" --list
        #       "bluetooth" 0:off 1:off 2:off 3:off 4:off 5:off 6:off
        #       Run the following command to verify "bluetooth" is disabled through current runtime configuration: 
        #       # service bluetooth status
        #       If the service is disabled the command will return the following output: 
        #       bluetooth is stopped
        #       If the service is running, this is a finding.
        expect( service('bluetooth')).not_to be_enabled
        expect( service('bluetooth')).not_to be_running
        # Fix: The "bluetooth" service can be disabled with the following command: 
        #       # chkconfig bluetooth off
        #       # service bluetooth stop
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38692
    it "V-38692 Accounts must be locked upon 35 days of inactivity." do
        # Check: To verify the "INACTIVE" setting, run the following command: 
        #       grep "INACTIVE" /etc/default/useradd
        #       The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 
        #       # grep "INACTIVE" /etc/default/useradd
        #       INACTIVE=35
        #       If it does not, this is a finding.
        expect( command("grep -i '^INACTIVE=35' /etc/default/useradd")).not_to return_stdout ""
        # Fix: To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 
        #       INACTIVE=[NUM_DAYS]
        #       A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the "useradd" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38693
    it "V-38693 The system must require passwords to contain no more than three consecutive repeating characters." do
        # Check: To check the maximum value for consecutive repeating characters, run the following command: 
        #       $ grep pam_cracklib /etc/pam.d/system-auth
        #       Look for the value of the "maxrepeat" parameter. The DoD requirement is 3. 
        #       If maxrepeat is not found or not set to the required value, this is a finding.
        expect( command("grep pam_cracklib /etc/pam.d/system-auth-ac | grep 'maxrepeat=3' ")).not_to return_stdout ""
        # Fix: The pam_cracklib module's "maxrepeat" parameter controls requirements for consecutive repeating characters. Edit the "/etc/pam.d/system-auth" file to include the following line prior to the "password include system-auth-ac" line: 
        #       password required pam_cracklib.so maxrepeat=3
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38694
    it "V-38694 The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity." do
        # Check: To verify the "INACTIVE" setting, run the following command: 
        #       grep "INACTIVE" /etc/default/useradd
        #       The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 
        #       # grep "INACTIVE" /etc/default/useradd
        #       INACTIVE=35
        #       If it does not, this is a finding.
        expect( command("grep -i '^INACTIVE=35' /etc/default/useradd")).not_to return_stdout ""
        # Fix: To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 
        #       INACTIVE=[NUM_DAYS]
        #       A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the "useradd" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38695
    it "V-38695 A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output or if aide is not run at least weekly, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38696
    it "V-38696 The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38697
    it "V-38697 The sticky bit must be set on all public directories." do
        # Check: To find world-writable directories that lack the sticky bit, run the following command: 
        #       # find / -xdev -type d -perm 002 ! -perm 1000
        #       If any world-writable directories are missing the sticky bit, this is a finding.
        expect( command("find / -xdev -type d -perm 002 ! -perm 1000")).to return_stdout ""
        # Fix: When the so-called 'sticky bit' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory. Setting the sticky bit prevents users from removing each other's files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit. However, if a directory is used by a particular application, consult that application's documentation instead of blindly changing modes. 
        #       To set the sticky bit on a world-writable directory [DIR], run the following command: 
        #       # chmod +t [DIR]
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38698
    it "V-38698 The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38699
    it "V-38699 All public directories must be owned by a system account." do
        # Check: The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a uid lower than 500. Run it once for each local partition [PART]: 
        #       # find [PART] -xdev -type d -perm 0002 -uid +500 -print
        #       If there is output, this is a finding.
        expect( command("find / -xdev -type d -perm 0002 -uid +500 -print")).to return_stdout ""
        # Fix: All directories in local partitions which are world-writable should be owned by root or another system account. If any world-writable directories are not owned by a system account, this should be investigated. Following this, the files should be deleted or assigned to an appropriate group.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38700
    it "V-38700 The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs." do
        # Check: To determine that periodic AIDE execution has been scheduled, run the following command: 
        #       # grep aide /etc/crontab
        #       If there is no output, this is a finding.
        if $environment['ids'] == 'ossec'
            expect( service('ossec-hids')).to be_enabled
            expect( service('ossec-hids')).to be_running
        elsif $environment['ids'] == 'aide'
            expect( command("grep aide /etc/crontab")).not_to return_stdout ""
        else
            fail("IDS variable set to unknown value")
        end
        # Fix: AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 
        #       05 4 * * * root /usr/sbin/aide --check
        #       AIDE can be executed periodically through other means; this is merely one example.
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38701
    it "V-38701 The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system." do
        # Check: Verify "tftp" is configured by with the "-s" option by running the following command: 
        #       grep "server_args" /etc/xinetd.d/tftp
        #       The output should indicate the "server_args" variable is configured with the "-s" flag, matching the example below:
        #       # grep "server_args" /etc/xinetd.d/tftp
        #       server_args = -s /var/lib/tftpboot
        #       If it does not, this is a finding.
        if property[:roles].include? 'tftpServer'
            expect( command("find / -xdev -type d -perm 0002 -uid +500 -print")).to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: If running the "tftp" service is necessary, it should be configured to change its root directory at startup. To do so, ensure "/etc/xinetd.d/tftp" includes "-s" as a command line argument, as shown in the following example (which is also the default): 
        #       server_args = -s /var/lib/tftpboot
    end

    # STIG Viewer Link: http://www.stigviewer.com/check/V-38702
    it "V-38702 The FTP daemon must be configured for logging or verbose mode." do
        # Check: Find if logging is applied to the ftp daemon. 
        #       Procedures: 
        #       If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file. 
        #       # grep vsftpd /etc/xinetd.d/*
        #       # grep server_args [vsftpd xinetd.d startup file]
        #       This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line 
        #       is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) 
        #       is used. 
        #       # grep xferlog_enable [vsftpd config file]
        #       If xferlog_enable is missing, or is not set to yes, this is a finding.
        if property[:roles].include? 'ftpServer'
            expect( command("grep xferlog_enable /etc/vsftpd/vsftpd.conf")).not_to return_stdout ""
        else
            pending("Not applicable")
        end
        # Fix: Add or correct the following configuration options within the "vsftpd" configuration file, located at "/etc/vsftpd/vsftpd.conf". 
        #       xferlog_enable=YES
        #       xferlog_std_format=NO
        #       log_ftp_protocol=YES
    end

end
