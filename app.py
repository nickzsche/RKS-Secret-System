from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import base64

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Modüler ters mevcut değil.")

def key_expansion(key):
    key_bytes = key.encode('utf8')
    expanded = []
    for i in range(16):
        expanded.append((key_bytes[i % len(key_bytes)] + i) % 256)
    return expanded

def split_into_blocks(data, block_size=8):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def shuffle_block(block, expanded_key):
    block = block.copy()
    n = len(block)
    for i in range(n):
        swap_idx = (expanded_key[i % len(expanded_key)] + i) % n
        block[i], block[swap_idx] = block[swap_idx], block[i]
    return block

def shuffle_block_inverse(block, expanded_key):
    block = block.copy()
    n = len(block)
    swaps = []
    for i in range(n):
        swap_idx = (expanded_key[i % len(expanded_key)] + i) % n
        swaps.append((i, swap_idx))
    for i, swap_idx in reversed(swaps):
        block[i], block[swap_idx] = block[swap_idx], block[i]
    return block

def substitute_block(block, expanded_key):
    result = []
    for i, val in enumerate(block):
        result.append((val + expanded_key[i % len(expanded_key)]) % 256)
    return result

def substitute_block_inverse(block, expanded_key):
    result = []
    for i, val in enumerate(block):
        result.append((val - expanded_key[i % len(expanded_key)]) % 256)
    return result

def modular_transform(block, expanded_key):
    result = []
    for i, val in enumerate(block):
        factor = expanded_key[i % len(expanded_key)] | 1
        result.append((val * factor) % 256)
    return result

def modular_transform_inverse(block, expanded_key):
    result = []
    for i, val in enumerate(block):
        factor = expanded_key[i % len(expanded_key)] | 1
        inv_factor = mod_inverse(factor, 256)
        result.append((val * inv_factor) % 256)
    return result

def xor_operation(block, expanded_key):
    result = []
    for i, val in enumerate(block):
        result.append(val ^ expanded_key[i % len(expanded_key)])
    return result

def RKS_encrypt(plaintext, key):
    expanded_key = key_expansion(key)
    plaintext_bytes = plaintext.encode('utf8')
    data = list(plaintext_bytes)
    blocks = split_into_blocks(data)
    encrypted_data = []
    for block in blocks:
        b1 = shuffle_block(block, expanded_key)
        b2 = substitute_block(b1, expanded_key)
        b3 = modular_transform(b2, expanded_key)
        encrypted_block = xor_operation(b3, expanded_key)
        encrypted_data.extend(encrypted_block)
    encrypted_bytes = bytes(encrypted_data)
    return base64.b64encode(encrypted_bytes).decode('utf8')

def RKS_decrypt(ciphertext, key):
    expanded_key = key_expansion(key)
    encrypted_bytes = base64.b64decode(ciphertext)
    data = list(encrypted_bytes)
    blocks = split_into_blocks(data)
    decrypted_data = []
    for block in blocks:
        b3 = xor_operation(block, expanded_key)
        b2 = modular_transform_inverse(b3, expanded_key)
        b1 = substitute_block_inverse(b2, expanded_key)
        decrypted_block = shuffle_block_inverse(b1, expanded_key)
        decrypted_data.extend(decrypted_block)
    decrypted_bytes = bytes(decrypted_data)
    return decrypted_bytes.decode('utf8')

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

@app.before_request
def create_session():
    if 'user_id' not in session:
        session['user_id'] = secrets.token_hex(16)

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'})

@app.route('/stats')
def get_stats():
    return jsonify({
        'encryption_count': session.get('encryption_count', 0),
        'decryption_count': session.get('decryption_count', 0)
    })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
@limiter.limit("10 per minute")
def encrypt():
    data = request.get_json()
    plaintext = data.get('text', '').strip()
    key = data.get('key', '').strip()
    
    if not plaintext or not key:
        return jsonify({'success': False, 'error': 'Metin veya anahtar boş olamaz'})
    
    try:
        encrypted_text = RKS_encrypt(plaintext, key)
        session['encryption_count'] = session.get('encryption_count', 0) + 1
        return jsonify({
            'success': True, 
            'result': encrypted_text,
            'stats': {
                'text_length': len(plaintext),
                'encrypted_length': len(encrypted_text)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    ciphertext = data.get('text')
    key = data.get('key')
    try:
        decrypted_text = RKS_decrypt(ciphertext, key)
        return jsonify({'success': True, 'result': decrypted_text})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
