require 'spec_helper'


describe "Simple tests to the installation"
	
	it "The SSH server package is installed"
		expect( package('openssh-server')).to be_installed
	end

	it "The SSH server is running"
        expect( service('sshd')).to be_running
	end

end