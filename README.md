# Automated Security Auditing of EL Based Linux Systems #

## Introduction##
This is a guide to automating a security audit of EL based Linux systems. It applies to 64bit versions of 6.5 by Red Hat, CentOS, and Oracle Linux systems. This automated security audit uses the publicly available [DISA STIG version 1 release 2](http://iase.disa.mil/stigs/os/unix/red_hat.html). The security tests are implemented using the [serverspec](http://serverspec.org/) framework. 

## Benefits
Security audits are a vital part of the security management process. There are many Linux security configurations to choose from as a starting point for an audit. For example the Center for Internet Security (CIS) has a set of [benchmarks](https://benchmarks.cisecurity.org/)and Red Hat publishes its [security guidelines](https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/index.html). The DISA STIG was chosen for its strictness and comprehensiveness. It has 251 security checks. 

Using serverspec to automate the audit has a number of advantages over other methods. The most important is that it is non-invasive. It does not require you to install any software on the servers undergoing the audit. It only requires an SSH connection to that server. serverspec is a general purpose server testing framework and therefore it can be used for other types of configuration testing as well. It is ideally suited, for instance, for a continuous integration and deployment process.

serverspec is a lightweight framework with a number of built-in commands that make implementing security check much easier. It is designed for this type of testing. serverspec has a relatively user friendly syntax. And, serverspec is highly portable since it is implemented in Ruby. 

## Disadvantages
The disadvantages of using servespec are that it does not product user friendly reports and it requires knowledge of Ruby. It produces console output that can be stored and archived in text files, however, it does not produce nicely formatted reports like the dedicated open source and commercial auditing tools. serverspec is a minimalistic, "bare metal" approach: effective but with few bells and whistles. You will need to pipe its output to a text file to save it.

The syntax of serverspec is relatively user friendly, for example, this tests that the `/etc/gshadow` file is owned by root:

`expect( file('/etc/gshadow')).to be_owned_by 'root'`

Nevertheless, using it does requires some familiarity with Ruby and its tool-chain. It can be difficult to get it working, especially with sudo. It can test multiple servers in one run but will stop on a failure. In short, it has many minor annoyances. 

On the other hand, every audit tool will require you to learn its testing language. Learning Ruby has the benefit of being applicable to other domains. Ruby is also the language of the configuration management tools such as Chef and Puppet.

## Warning
None of these automated tests make changes to the server. They are checks only. Nevertheless, you should not take my word for it and should review each one to verify this for yourself. Every test that uses `command` runs a command on the remote server. At the very least review each one of these. 

While I have tested these test, there will be bugs. Consider this a beta version. There are also, I'm sure, poorly written tests and perhaps even incorrect tests. Feedback and corrections are welcome. My intent is for these to be high quality and comprehensive. 

I highly recommend that you experiment with the tests in a development environment. 

## Performance
On my servers (micro CentOS instances running as Xen VMs) running the complete set of tests takes about 2.5 minutes per server. If the slow tests are excluded then the tests take about 30 seconds. They consume about 10% of a single vCPU. During the tests OSSEC and auditd CPU usage will spike as well. They are always watching and recording what you do, which is exactly what you want.  

# Conducting the audit
I will explain how to install and run the audit from the beginning. I do not assume that you are familiar with Ruby and serverspec. If you are, then you can skip ahead to step 3.

## Test architecture
Basically, you install Ruby, serverspec, and the STIG tests on a workstation. The tests are run from this workstation which then connects to each server being audited and runs the tests over SSH remotely. It is a simple client-server architecture. 

## Process Overview 
The steps are:

1. Install Ruby version 1.9.x or above
2. Install serverspec and supporting gems
3. Download the tests from GitHub
4. Configure the tests for your environment
5. Run the tests
6. Correct the deficiencies

## Prerequisites
To use these tests you must be familiar with the Unix command line tools and SSH. You do not need to be a Ruby programmer. It will certainly help if you know a bit of Ruby and RSpec (the unit test framework that serverspec is built on). I hope you will be inspired to write your own your own tests. serverspec can do much more than security testing, it can test all your server settings.

The tests can be run from any workstation that supports Ruby 1.9.x and serverspec. I have successfully run them from CentOS and Mac OS X. They should run from Solaris and *BSD as well. They might run from Windows but I have not tried it. 

The servers you want to audit must have the OpenSSH server running and the workstation you run the tests from must have SSH access to those servers. You must have `sudo` access to the servers as well. Many of these tests require access to sensitive files. They do not modify them in any way but they do need to read their contents.

## Detailed Steps

### Install Ruby 1.9.x
For CentOS see my posting [here](http://wp.me/p4iDAr-5U). CentOS comes with Ruby 1.8.x by default which does not seem to work. 

Mac v 10.8 also has an old version of Ruby. I recommend you use [Mac ports](https://www.macports.org/) to install the a newer version of Ruby. Using Mac ports the steps are:
- Install the Mac ports software
- Open a terminal to run the following commands
- `sudo port selfupdate`
- `sudo port install ruby19`
- `sudo port select --set ruby ruby19`
- Close the terminal

To check the version of Ruby installed run this command from a terminal" `ruby -v`. It should return "ruby 1.9.3.xxxx".

### Install serverspec and supporting Ruby gems
On all platforms, from a terminal run:
- 'sudo yum install rubygems'
- `gem install serverspec`
- `gem install rake`
- `gem install bundler`
- `bundle install`
- `gem update`
- [Optional but recommended unless you require older libraries] `gem clean`

If you have get errors you can try running these with `sudo`.

### Download the security tests from GitHub
First install git if you don't already have it.
CentOS: `sudo yum install git`
Mac OS: `sudo port install git-core`

Then:
- Open a terminal
- `cd` to or create the directory you want to hold the tests
- `git clone git@github.com:aaron868/security-audit.git`
- The tests and supporting files will be in a directory called "security-audit"

### Configure the tests for your environment
There are several files you will need to change to configure the tests for your environment. I named the files so that your changes will not be overwritten as the tests are updated on GitHub. You must create your own version of each file that ends in ".example". These are:

- security-audit/spec/spec_helper.rb.sudo-example
- security-audit/spec/spec_helper.rb.root-example
- security-audit/environment.yml.example
- security-audit/properties.yml.example

For each of these, make a copy in the same directory as the example and then delete the ".example" extension. These are YAML format files so whitespace counts. You will get syntax errors if the indentation isn't exact. Uses spaces instead of tabs.

Edit each as follows.

**environment.yml**
This file sets your environmental variables. They apply to all the tests including any you add yourself. Think of them as global variables. You can create multiple environment files to set different value for production, staging, dev, etc. If you create multiple environment files remember to change the file name in `spec/spec_helper.rb`.

See the example file for the definitions and accepted values of the environmental variables.

**spec_helper.rb**
This file contains your login settings. It allows you to configure root or sudo based login. sudo is the preferred method since the STIG requires that root access via SSH be disabled. Examples are provided for both cases.

First set the name of the login user (user  = "X"). This could be "root" if you want to login as root or another user if you login and then sudo. If you login as root then comment out the two lines that contain "sudo_password". Leave them as is for sudo access.

If you use key based SSH access you can comment out the lines that ask for and set the login password.

When you start test-fix-test mode to correct security issues you may want to run the tests many times. The slower tests can be aggravating when you do this. You can disable the few slow tests by uncommenting line 23. These are the in-depth rpm file checks. Comment this line back out when you want to run these tests again.

**properties.yml**
This file is where you set host-specific attributes. Its key sections are roles and network settings. Certain tests will only be run if the server supports a specific role. For example, if the server is an NFS server (has the role 'nfsServer') then NFS server security settings will be tested. Otherwise those settings will be ignored and will show up in the report as "Pending". The network variables specify the TCP/IP settings for the network adapters installed on the server. See the comments in the example for accepted values.

Optional roles are listed at the top of the `properties.yml.example` file. If your server implements one or more of these roles then add it as `- theRole` under `:roles:`. The indentation for all the roles must be the same. For example, if your server acts as a router then add `- router` under `:roles:`. 

Using this method allows you to add new role-based test later. Simple add a folder under `spec` with the same name as the role. Then add a test file in this folder called `X_spec.rb` which will hold router-specific serverspec tests. See the `simple` folder and the `simple_spec.rb` file for how this is done.

Some of the security test require a network configuration check. Therefore you must add the server's network configuration in the `properties.yml` file. If the server has more that one NIC you can add a `- device: X` block for each. If the server uses DHCP then many of the lines are optional. These settings also support VLANs and will handle them properly; for example, `ifcfg-eth0.20`. 

Currently serverspec only supports one properties file so if you want to keep separate ones for each environment you will have to rename the one you want to use to `properties.yml` before running the tests.

### Run the tests
Once your configuration is complete you can run the tests. I recommend you first try the `simple` test only. Leave `- stig` commented out and only run `simple`. The `spec_helper.rb` configuration is a bit fussy so it may take some experimentation to get it right for your environment. Once `simple` runs correctly then you should be able to run the full STIG test suite. I also recommend uncommenting the `c.filter` line at first because this will exclude the slow tests. 

The example `spec_helper.rb` files assume you use the same passwords for all your servers. If this is not the case then you can modify it by moving the `ask(xxx)` statements inside the `Spec.configure do |c|` block. For example, when running the tests as root change `options[:password] = password` to `options[:password] = ask("Enter login password: ") { |q| q.echo = false }` and then delete the `ask` line above it. The same pattern applies to the sudo password lines.

To run the tests:

- `cd` into the `security-audit` directory
- type `rake -T`
- This should list all the servers you entered in your properties file
- type `rake serverspec:X` to run the tests against a single server
- type `rake spec` to run them against all servers

serverspec will produce a lot of output. At the end of it it will list the failures along with the reason why they failed. Running these tests against a default EL install will generate a lot of failures. 

### Correct deficiencies
Now correct the problems that caused the failed tests. With the slow tests disabled you can run these against a single server quickly. Therefore, I recommend that you correct one at a time: correct it then run the test, then repeat. If you do this then congratulations, you are using TDD for your IT infrastructure. This is a core DevOps practice. These tests can be run from a continuous integration server like Bamboo or Jenkins. This allows your IT configuration to be managed just like a software development project. 

I highly recommend that you correct the deficiencies using an automated systems administration tool such as Ansible, Chef, or Puppet. My other GitHub repository, "management", has the Ansible commands to configure a CentOS server to meet the STIG requirements. You can use that as an example to create your own. Using an automated tool allows you to configure it once and then re-use as many times as needed. There is no longer any reason to do this manually. 

## Conclusion 
Everyone benefits from secure servers. I hope this makes it easier for you to secure yours. I would be happy to accept changes to the test via git "pull requests". If there is interest I could expand this to cover security tests from other guides as well. Please post bug reports and issues to the GitHub "issues" page. Good luck!


