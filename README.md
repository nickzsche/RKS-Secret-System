# RKS Encryption Web App / RKS Şifreleme Web Uygulaması

## Overview / Genel Bakış

**English:**  
RKS Encryption is an experimental project that utilizes a custom encryption algorithm to encrypt and decrypt text. The algorithm performs several steps on byte-level data: shuffle, substitution, modular transformation, and XOR operations. It supports UTF-8 for handling Unicode characters and outputs encrypted data in Base64 format for improved readability.

**Türkçe:**  
RKS Şifreleme, metinlerin şifrelenmesi ve çözümlenmesi için özgün bir şifreleme algoritması kullanan deneysel bir projedir. Algoritma, bayt düzeyinde işlemler olarak karıştırma, substitüsyon, modüler dönüşüm ve XOR işlemlerini gerçekleştirir. UTF-8 desteği sayesinde Unicode karakterler doğru şekilde işlenir ve şifreli çıktı Base64 formatında sunularak okunabilirlik sağlanır.

---

## Features / Özellikler

**English:**
- **Custom Encryption Algorithm:** Combines shuffle, substitution, modular transformation, and XOR operations.
- **UTF-8 Support:** Proper handling of Unicode characters.
- **Base64 Output:** Encrypted data is encoded in Base64 for readability.
- **Flask Web Interface:** A simple web interface for encryption and decryption.

**Türkçe:**
- **Özel Şifreleme Algoritması:** Karıştırma, substitüsyon, modüler dönüşüm ve XOR işlemlerini bir araya getirir.
- **UTF-8 Desteği:** Unicode karakterlerin doğru şekilde işlenmesi.
- **Base64 Çıktı:** Şifrelenmiş veri Base64 formatında sunularak okunabilir hale getirilir.
- **Flask Web Arayüzü:** Şifreleme ve deşifreleme işlemleri için basit bir web arayüzü.

---

## Requirements / Gereksinimler

**English:**
- Python 3.7 or higher
- [Flask](https://flask.palletsprojects.com/)
- Standard Python libraries: `base64` (no additional installation required)

**Türkçe:**
- Python 3.7 veya üstü
- [Flask](https://flask.palletsprojects.com/)
- Python'un standart kütüphaneleri: `base64` (ekstra kurulum gerekmez)

---

## Installation / Kurulum

**English:**
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/rks-encryption.git
   cd rks-encryption
