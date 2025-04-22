from flask import Flask, request, jsonify
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import datetime
import json
import tempfile
import importlib.util
import sys
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# .env dosyasından parolayı al
password = os.getenv("SECRET_PASSWORD")


def derive_key(password: str):
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=b'',  # The same empty byte string as salt
		iterations=100000,
		backend=default_backend()
	)
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	return key

def encrypt_message(message: str, password: str):
	key = derive_key(password)
	f = Fernet(key)
	encrypted = f.encrypt(message.encode())
	# Encode the encrypted byte string to Base64 to make it a regular string
	return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_message(encrypted_message: str, password: str):
	key = derive_key(password)
	f = Fernet(key)
	# Decode the Base64 encoded string back into bytes
	encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
	decrypted = f.decrypt(encrypted_message_bytes)
	return decrypted.decode()

def kaydet_ip_ve_mesaj(ip, gelen_mesaj):
	zaman_damgasi = datetime.datetime.now().isoformat()
	try:
		with open("kayit.json", 'r') as dosya:
			veriler = json.load(dosya)
	except FileNotFoundError:
		veriler = []
	
	mac_adresi = gelen_mesaj.get("MAC")
	
	# MAC adresine göre kaydı bul veya yeni kayıt oluştur
	mevcut_kayit = None
	for kayit in veriler:
		if kayit["GelenMesaj"].get("MAC") == mac_adresi:
			mevcut_kayit = kayit
			break
	
	if mevcut_kayit:
		# Mevcut kaydın IP'sini ve zaman damgasını güncelle
		mevcut_kayit["IP"] = ip
		mevcut_kayit["ZamanDamgasi"] = zaman_damgasi
	else:
		# Yeni kayıt ekle
		veriler.append({
			"GelenMesaj": gelen_mesaj,
			"IP": ip,
			"ZamanDamgasi": zaman_damgasi
		})
	
	# Güncellenmiş verileri JSON dosyasına yaz
	with open("kayit.json", 'w') as dosya:
		json.dump(veriler, dosya, indent=4)

# Aktif kullanıcı sayısını hesaplama fonksiyonu
def aktif_kullanici_sayisini_hesapla():
	try:
		with open("kayit.json", 'r') as dosya:
			veriler = json.load(dosya)
		
		aktif_kullanici_sayisi = 0
		simdi = datetime.datetime.now()
		for kayit in veriler:
			son_aktif_zaman = datetime.datetime.fromisoformat(kayit["ZamanDamgasi"])
			if (simdi - son_aktif_zaman).total_seconds() <= 3600 * 24:  # Son 1 saat içinde aktifse
				aktif_kullanici_sayisi += 1
		
		return aktif_kullanici_sayisi
	except Exception as e:
		print(f"Hata: {e}")
		return 0

def load_blocked_devices():
	if os.path.exists(blocked_devices_file):
		with open(blocked_devices_file, 'r') as file:
			return json.load(file)
	else:
		return {}

def save_blocked_devices(data):
	with open(blocked_devices_file, 'w') as file:
		json.dump(data, file)

def block_device(mac, cpu, disk):
	blocked_devices = load_blocked_devices()
	blocked_devices[mac] = {"MAC": mac, "CPU": cpu, "DISK": disk}
	save_blocked_devices(blocked_devices)

def load_blocked_ips():
	if os.path.exists(blocked_ips_file):
		with open(blocked_ips_file, 'r') as file:
			return json.load(file)
	else:
		return {}

def save_blocked_ips(data):
	with open(blocked_ips_file, 'w') as file:
		json.dump(data, file)

def load_ban_logs():
	if os.path.exists(ban_logs_file):
		with open(ban_logs_file, 'r') as file:
			return json.load(file)
	else:
		return []

def save_ban_log(log):
	logs = load_ban_logs()
	logs.append(log)
	with open(ban_logs_file, 'w') as file:
		json.dump(logs, file, indent=4)

app = Flask(__name__)


@app.route('/server_status', methods=['POST'])
def check_server_status():
	encrypted_message = request.json.get('encrypted_message')
	if not encrypted_message:
		return jsonify({"error": "Mesaj sağlanmadı"}), 400
	
	try:
		decrypted_message = decrypt_message(encrypted_message, password)
		message_dict = json.loads(decrypted_message)
		
		ip = request.remote_addr
		kaydet_ip_ve_mesaj(ip, message_dict)
		
		with open('version_info.json', 'r', encoding='utf-8') as file:
			version_info = json.load(file)
		
		version = message_dict.get("Version")
		if version in version_info:
			info = version_info[version]
			response_data = {
				"status": info["status"],
				"message": info.get("message", ""),
				"warning": info.get("warning", ""),
				"discord_link": info.get("discord_link", "")
			}
			encrypted_response = encrypt_message(json.dumps(response_data, ensure_ascii=False), password)
			return jsonify({"encrypted_response": encrypted_response})
		else:
			response_data = {"status": "denied"}
			encrypted_response = encrypt_message(json.dumps(response_data), password)
			return jsonify({"encrypted_response": encrypted_response})
	
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@app.route('/online_users', methods=['POST'])
def online_users():
	try:
		encrypted_data = request.json.get('encrypted_data')
		if not encrypted_data:
			return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
		
		# Şifreli veriyi çöz (Bu örnekte bu veri kullanılmıyor, ancak güvenlik amacıyla eklendi)
		decrypted_data = decrypt_message(encrypted_data, password)
		
		aktif_kullanici_sayisi = aktif_kullanici_sayisini_hesapla()
		
		# Şifreli yanıtı oluştur
		encrypted_response = encrypt_message(json.dumps({"online_users": aktif_kullanici_sayisi}), password)
		
		# Yanıtı döndür
		return jsonify({"encrypted_response": encrypted_response}), 200
	except Exception as e:
		# Hata durumunda hata mesajını yazdır
		return jsonify({"error": str(e)}), 500


@app.route('/shutdown', methods=['POST'])
def shutdown():
	encrypted_data = request.json.get('encrypted_data')
	
	try:
		# Şifreli veriyi çöz
		decrypted_data = decrypt_message(encrypted_data, password)
		data = json.loads(decrypted_data)
		
		# Gelen veriyi al (örneğin: MAC adresi ve çalışma süresi)
		mac_address = data.get('mac_address')
		duration = data.get('duration')
		
		# kayit.json dosyasını oku ve güncelle
		try:
			with open("kayit.json", 'r') as dosya:
				veriler = json.load(dosya)
		except FileNotFoundError:
			veriler = []
		
		# MAC adresine göre kaydı bul veya yeni kayıt oluştur
		mevcut_kayit = None
		for kayit in veriler:
			if kayit["GelenMesaj"].get("MAC") == mac_address:
				mevcut_kayit = kayit
				break
		
		if mevcut_kayit:
			# Mevcut kaydın süresini güncelle
			mevcut_kayit["duration"] = mevcut_kayit.get("duration", 0) + duration
		else:
			# Yeni kayıt ekle
			veriler.append({
				"GelenMesaj": {"MAC": mac_address},
				"duration": duration
			})
		
		# Güncellenmiş verileri JSON dosyasına yaz
		with open("kayit.json", 'w') as dosya:
			json.dump(veriler, dosya, indent=4)
		
		# Başarılı bir yanıt döndür
		return jsonify({"message": "Kapanış bilgileri başarıyla alındı ve kaydedildi."}), 200
	
	except Exception as e:
		# Hata durumunda uygun yanıtı döndür
		return jsonify({"error": str(e)}), 500


@app.route('/top_users', methods=['POST'])
def top_users():
	try:
		encrypted_data = request.json.get('encrypted_data')
		if not encrypted_data:
			return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
		
		# Şifreli veriyi çöz
		decrypted_data = decrypt_message(encrypted_data, password)
		request_data = json.loads(decrypted_data)
		
		user_count = request_data.get('user_count', 10)  # Varsayılan olarak 10 kullanıcı
		
		# kayit.json dosyasını oku
		with open("kayit.json", 'r') as dosya:
			veriler = json.load(dosya)
		
		# Kullanıcıları 'duration' değerine göre sırala
		sorted_users = sorted(veriler, key=lambda x: x.get("duration", 0), reverse=True)
		
		# İstenen sayıda kullanıcıyı al
		top_users = sorted_users[:user_count]
		
		# Şifreli yanıtı oluştur
		encrypted_response = encrypt_message(json.dumps(top_users), password)
		return jsonify({"encrypted_response": encrypted_response}), 200
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@app.route('/delete_version', methods=['POST'])
def delete_version():
	try:
		encrypted_data = request.json.get('encrypted_data')
		if not encrypted_data:
			return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
		
		# Şifreli veriyi çöz
		decrypted_data = decrypt_message(encrypted_data, password)
		version_to_delete = json.loads(decrypted_data).get('version')
		
		# Eğer versiyon belirtilmemişse hata ver
		if not version_to_delete:
			return jsonify({"error": "Silinecek versiyon belirtilmedi"}), 400
		
		# JSON dosyasını oku
		try:
			with open('version_info.json', 'r', encoding='utf-8') as file:
				version_info = json.load(file)
		except FileNotFoundError:
			return jsonify({"error": "Versiyon bilgisi bulunamadı"}), 404
		
		# Belirtilen versiyonu kontrol et ve sil
		if version_to_delete in version_info:
			del version_info[version_to_delete]
		else:
			return jsonify({"error": "Belirtilen versiyon bulunamadı"}), 404
		
		# Güncellenmiş veriyi JSON dosyasına yaz
		with open('version_info.json', 'w', encoding='utf-8') as file:
			json.dump(version_info, file, ensure_ascii=False, indent=4)
		
		return jsonify({"message": "Versiyon başarıyla silindi."}), 200
	
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@app.route('/load_encrypted_module', methods=['POST'])
def load_encrypted_module():
	encrypted_data = request.json.get('encrypted_data')
	if not encrypted_data:
		return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
	
	try:
		# Şifreli veriyi çöz
		decrypted_data = decrypt_message(encrypted_data, password)
		module_data = json.loads(decrypted_data)
		
		# Modül ismini al
		module_name = module_data.get('name')
		if not module_name:
			return jsonify({"error": "Modül ismi eksik"}), 400
		
		# Modül dosyasının varlığını ve yolunu kontrol et
		module_path = os.path.join(os.getcwd(), f"{module_name}.py")
		if not os.path.exists(module_path):
			return jsonify({"error": "Modül dosyası bulunamadı"}), 404
		
		# Modülü yükle
		spec = importlib.util.spec_from_file_location(module_name, module_path)
		module = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(module)
		
		# Modülü sisteme ekle
		sys.modules[module_name] = module
		
		return jsonify({"success": True, "message": f"{module_name} modülü başarıyla yüklendi"})
	except Exception as e:
		return jsonify({"error": f"Modül yüklenirken hata: {str(e)}"}), 500


@app.route('/get_pedal_device_module', methods=['GET'])
def get_pedal_device_module():
	with open('pedal_device.py', 'r', encoding='utf8') as file:
		pedal_device_code = file.read()
	print(pedal_device_code)
	code_file = jsonify({"module_code": pedal_device_code})
	
	return code_file


@app.route('/update_version_info', methods=['POST'])
def update_version_info():
	encrypted_data = request.json.get('encrypted_data')
	if not encrypted_data:
		return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
	
	try:
		decrypted_data = decrypt_message(encrypted_data, password)
		version_data = json.loads(decrypted_data)
		
		# JSON dosyasını kontrol et, yoksa yeni dosya oluştur
		try:
			with open('version_info.json', 'r', encoding='utf-8') as file:
				current_data = json.load(file)
		except (FileNotFoundError, json.JSONDecodeError):
			current_data = {}
		
		# Güncel verileri dosyaya yaz
		with open('version_info.json', 'w', encoding='utf-8') as file:
			current_data.update(version_data)
			json.dump(current_data, file, ensure_ascii=False, indent=4)
		
		return jsonify({"message": "Versiyon bilgileri başarıyla güncellendi."}), 200
	
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@app.route('/verify_checksum_and_version', methods=['POST'])
def verify_checksum_and_version():
	encrypted_data = request.json.get('encrypted_data')
	if not encrypted_data:
		return jsonify({"error": "Şifreli veri sağlanmadı"}), 400
	
	try:
		decrypted_data = decrypt_message(encrypted_data, password)
		data = json.loads(decrypted_data)
		
		exe_checksum = data.get('exe_checksum')
		code_checksum = data.get('code_checksum')
		version = data.get('version')
		print(exe_checksum)
		print(code_checksum)
		with open('version_info.json', 'r', encoding='utf-8') as file:
			version_info = json.load(file)
		
		if version in version_info and \
				version_info[version].get('exe_checksum') == exe_checksum and \
				version_info[version].get('code_checksum') == code_checksum:
			return jsonify({"status": "success",
			                "message": version_info[version].get("message", "Checksum ve versiyon doğrulandı.")})
		else:
			return jsonify({"status": "failure", "message": "Checksum veya versiyon uyuşmuyor."})
	
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@app.route('/list_versions', methods=['POST'])
def list_versions():
	print("'/list_versions' endpoint'ine sorgu geldi.")
	
	try:
		# 'version_info.json' dosyasını oku
		with open('version_info.json', 'r', encoding='utf-8') as file:
			version_info = json.load(file)
			print("Okunan Versiyon Bilgisi:", version_info)
		
		# Versiyon bilgilerini şifrele ve geri dön
		encrypted_version_info = encrypt_message(json.dumps(version_info, ensure_ascii=False), password)
		return jsonify({"encrypted_version_info": encrypted_version_info}), 200
	
	except FileNotFoundError:
		print("Hata: 'version_info.json' dosyası bulunamadı.")
		return jsonify({"error": "Versiyon bilgisi bulunamadı"}), 404
	
	except json.JSONDecodeError:
		print("Hata: 'version_info.json' dosyası okunurken JSON hatası.")
		return jsonify({"error": "Versiyon bilgisi okunurken hata oluştu"}), 500
	
	except Exception as e:
		print(f"Hata: {str(e)}")
		return jsonify({"error": str(e)}), 500


@app.route('/install_key', methods=['POST'])
def install_key():
	try:
		data = request.get_json()
		encrypted_data = data.get('encrypted_data')
		decrypted_data = decrypt_message(encrypted_data, password)
		data = json.loads(decrypted_data)
		
		key = data.get('key')
		unique_id = data.get('unique_id')
		
		client_devices = json.loads(decrypt_message(unique_id, password))
		print(client_devices)
		print(client_devices['CPU'])
		
		# Load keys.json
		with open('keys.json', 'r') as file:
			keys = json.load(file)
		
		if key in keys:
			users_file_path = 'users.json'
			
			# Check if users.json exists, if not create it
			if not os.path.exists(users_file_path):
				with open(users_file_path, 'w') as file:
					json.dump({}, file)
			
			# Load or initialize users data
			with open(users_file_path, 'r+') as file:
				try:
					users = json.load(file)
				except json.JSONDecodeError:
					users = {}
			
			start_date = datetime.datetime.now()
			expiration = start_date + datetime.timedelta(days=keys[key]['duration'])
			
			# Update user data
			users[client_devices["MAC"]] = {
				'key': key,
				'start_date': start_date.strftime('%Y-%m-%d %H:%M:%S'),
				'expiration_date': expiration.strftime('%Y-%m-%d %H:%M:%S'),
				'CPU': client_devices['CPU'],
				'DISK': client_devices['DISK']
			}
			
			# Remove the key from keys.json
			del keys[key]
			with open('keys.json', 'w') as keys_file:
				json.dump(keys, keys_file, indent=4)
			
			# Save updated users data
			with open(users_file_path, 'w') as users_file:
				json.dump(users, users_file, indent=4)
			
			response = {
				"status": "success",
				"start_date": start_date.strftime('%Y-%m-%d %H:%M:%S'),
				"expiration_date": expiration.strftime('%Y-%m-%d %H:%M:%S')
			}
		else:
			response = {"status": "failure", "message": "Invalid key"}
	except Exception as e:
		response = {"status": "failure", "message": str(e)}
	
	encrypted_response = encrypt_message(json.dumps(response), password)
	return jsonify({"encrypted_response": encrypted_response})


@app.route('/verify_license', methods=['POST'])
def verify_licence():
	try:
		data = request.get_json()
		encrypted_data = data.get('encrypted_data')
		decrypted_data = decrypt_message(encrypted_data, password)
		data = json.loads(decrypted_data)
		unique_id = data.get('unique_id')
		client_devices = json.loads(decrypt_message(unique_id, password))
		MAC = client_devices.get('MAC')
		CPU = client_devices.get('CPU')
		DISK = client_devices.get('DISK')
		
		with open('users.json', 'r') as file:
			users = json.load(file)
		
		if MAC in users:
			print("MAC in Users...")
			user_data = users[MAC]
			
			current_datetime = datetime.datetime.now()
			print("current_datetime:", current_datetime)
			
			start_date = datetime.datetime.strptime(user_data['start_date'], '%Y-%m-%d %H:%M:%S')
			print("start_date:", start_date)
			
			expiration_date = datetime.datetime.strptime(user_data['expiration_date'], '%Y-%m-%d %H:%M:%S')
			print("expiration_date:", expiration_date)
			
			if (start_date <= current_datetime <= expiration_date) and \
					(CPU == user_data['CPU']) and (DISK == user_data['DISK']):
				response = {"status": "approved", "message": "License is valid",
				            "expiration_date": f"{user_data['expiration_date']}"}
			else:
				response = {"status": "rejected", "message": "License has expired"}
		else:
			response = {"status": "rejected", "message": "License not found"}
	
	except Exception as e:
		response = {"status": "rejected", "message": str(e)}
	
	encrypted_response = encrypt_message(json.dumps(response), password)
	return jsonify({"encrypted_response": encrypted_response})


@app.route('/upload_key', methods=['POST'])
def upload_key():
	try:
		data = request.get_json()
		encrypted_data = data.get('encrypted_data')
		decrypted_data = decrypt_message(encrypted_data, password)
		new_key_data = json.loads(decrypted_data)
		
		keys_file_path = 'keys.json'
		keys = {}
		
		# Check if the file exists, if not create an empty file with an empty dictionary
		if not os.path.exists(keys_file_path):
			with open(keys_file_path, 'w') as file:
				json.dump(keys, file)
		
		# Load existing keys
		with open(keys_file_path, 'r+') as file:
			keys = json.load(file)
			keys.update(new_key_data)
		
		# Save updated keys
		with open(keys_file_path, 'w') as file:
			json.dump(keys, file, indent=4)
		
		return jsonify({"message": "Key successfully uploaded"}), 200
	
	except Exception as e:
		return jsonify({"error": str(e)}), 500


ban_logs_file = 'ban_logs.json'
blocked_ips_file = 'blocked_ips.json'
blocked_devices_file = 'blocked_devices.json'
allowed_endpoints = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint != 'static']


@app.before_request
def block_ip_and_device():
	ip = request.remote_addr
	request_path = request.path  # İstek yapılan URL yolunu al
	blocked_ips = load_blocked_ips()
	blocked_devices = load_blocked_devices()
	
	# URL yolunun izin verilenler listesinde olup olmadığını kontrol et
	if request_path not in allowed_endpoints:
		save_ban_log({"ip": ip, "reason": "Unauthorized URL access", "url": request_path,
		              "timestamp": datetime.datetime.now().isoformat()})
		return jsonify({"error": "Unauthorized URL access"}), 403
	
	# IP adresi kontrolü
	if ip in blocked_ips:
		save_ban_log({"ip": ip, "reason": "Blocked IP", "timestamp": datetime.datetime.now().isoformat()})
		return jsonify({"error": "This IP address is blocked"}), 403
	
	# Donanım kimlikleri kontrolü
	device_info = request.json.get('GelenMesaj', {})
	mac = device_info.get('MAC')
	cpu = device_info.get('CPU')
	disk = device_info.get('DISK')
	
	if mac in blocked_devices or cpu in blocked_devices.values() or disk in blocked_devices.values():
		save_ban_log({"ip": ip, "MAC": mac, "CPU": cpu, "DISK": disk, "reason": "Blocked Device",
		              "timestamp": datetime.datetime.now().isoformat()})
		return jsonify({"error": "This device is blocked"}), 403


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000, debug=False)  # Burada port numarasını da belirtebilirsiniz.
# app.run(debug=True)
