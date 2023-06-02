config = {
	"attacker_site": b"attack.com", # attack.com
	"legitimate_site_address": b"canvas@sjtu.edu.cn", # From header address displayed to the end-user
	"victim_address": b"kr2256671169@163.com", # RCPT TO and message.To header address,
	"case_id": b"client_a1", #  You can find all case_id using -l option.

	# The following fields are optional
	"server_mode":{
		"recv_mail_server": "", # If no value, espoofer will query the victim_address to get the mail server ip
		"recv_mail_server_port": 25,
		"starttls": False,
	},
	"client_mode": {
		"sending_server": ("smtp.sjtu.edu.cn", 25),
		# "sending_server": ("smtp.163.com", 25),
		"username": b"kr2256671169@sjtu.edu.cn",
		"password": b"cenkangrui123",
	},

	# Optional. You can leave them empty or customize the email message header or body here
	"subject_header": b"",  # Subject: Test espoofer\r\n
	"to_header": b"", # To: <alice@example.com>\r\n
	"body": b"", # Test Body.

	# Optional. Set the raw email message you want to sent. It's usually used for replay attacks
	"raw_email": b"", 
}



