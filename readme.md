# 🔐 Flask Şifreli Sunucu

Flask tabanlı güvenli sunucu. Şifreli mesaj işler, lisans doğrular, aktif kullanıcıları izler, cihaz/versiyon yönetir. Şifreleme `cryptography` ile, ortam değişkenleri `.env` ile. Sadece `main.py` Git’e yüklenir, diğer `.py`’ler hariç tutulur.

## ✨ Özellikler
- 🔒 Şifreli iletişim
- 🛡️ MAC/CPU/DISK lisans kontrolü
- 📊 24 saat aktif kullanıcı takibi
- 📝 Versiyon yönetimi
- 🚫 IP/cihaz engelleme
- 🧩 Dinamik modül yükleme

## 🛠️ Gereksinimler
- Python 3.8+
- Flask, cryptography, python-dotenv, werkzeug

## 🚀 Kurulum ve API’ler
```bash
git clone <depo-url>
cd <proje-dizini>
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
echo "SECRET_PASSWORD=<gizli-anahtar>" > .env
python main.py
# Sunucu http://0.0.0.0:5000’de çalışır
# 📡 POST /server_status: Versiyon kontrolü, şifreli yanıt
# 📊 POST /online_users: Aktif kullanıcı sayısı
# 🛑 POST /shutdown: Kapanış bilgisi kaydı
# 🏆 POST /top_users: En aktif kullanıcılar
# 🗑️ POST /delete_version: Versiyon silme
# 📦 POST /load_encrypted_module: Şifreli modül yükleme
# 📄 GET /get_pedal_device_module: pedal_device.py içeriği
# 🔄 POST /update_version_info: Versiyon güncelleme
# ✅ POST /verify_checksum_and_version: Checksum/versiyon doğrulama
# 📋 POST /list_versions: Versiyon listesi
# 🔑 POST /install_key: Lisans anahtarı kurma
# ✔️ POST /verify_license: Lisans kontrolü
# ⬆️ POST /upload_key: Yeni lisans anahtarı yükleme
# Örnek Kullanım
curl -X POST http://localhost:5000/server_status -H "Content-Type: application/json" -d '{"encrypted_message": "<şifreli_mesaj>"}'
# 🔒 Güvenlik
# .env Git’e yüklenmez
# Sadece main.py yüklenir
# Yasak IP/cihazlar: blocked_ips.json, blocked_devices.json
# 📂 Proje Yapısı
# ├── .env
# ├── .gitignore
# ├── main.py
# ├── kayit.json
# ├── version_info.json
# ├── keys.json
# ├── users.json
# ├── ban_logs.json
# ├── blocked_ips.json
# ├── blocked_devices.json
# ├── requirements.txt