import base64
import json
import os
import secrets
import string
from typing import Dict, List, Tuple
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constantes de Seguridad
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000


def generate_secure_password(
    length: int = 16,
    use_digits: bool = True,
    use_symbols: bool = True,
    use_uppercase: bool = True,
) -> str:
    """
    Genera una contraseña usando exclusivamente el módulo secrets (CS-PRNG).
    Garantiza que contenga al menos un carácter de cada conjunto seleccionado.
    """
    if length < 8:
        raise ValueError("La longitud mínima recomendada es de 8 caracteres.")

    lowercase = string.ascii_lowercase
    digits = string.digits if use_digits else ""
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?" if use_symbols else ""
    uppercase = string.ascii_uppercase if use_uppercase else ""

    alphabet = lowercase + digits + symbols + uppercase
    if not alphabet:
        raise ValueError("Debes seleccionar al menos un tipo de carácter.")

    # Asegurar al menos un carácter de cada tipo seleccionado
    password = []
    password.append(secrets.choice(lowercase))
    if use_digits:
        password.append(secrets.choice(digits))
    if use_symbols:
        password.append(secrets.choice(symbols))
    if use_uppercase:
        password.append(secrets.choice(uppercase))

    # Completar el resto de la longitud deseada
    remaining_length = length - len(password)
    password.extend(secrets.choice(alphabet) for _ in range(remaining_length))

    # Mezclar la lista de manera segura
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes criptográficamente fuerte a partir de la 
    Contraseña Maestra usando PBKDF2HMAC con SHA-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    # Fernet requiere que la clave esté codificada en URL-safe Base64
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_vault_data(master_password: str, data: List[Dict]) -> bytes:
    """
    Serializa los datos de la bóveda a JSON y los cifra con AES-256 (Fernet).
    Estructura de salida: [SALT (16 bytes)] + [PAYLOAD CIFRADO].
    """
    salt = secrets.token_bytes(SALT_SIZE)
    derived_key = derive_key(master_password, salt)
    fernet = Fernet(derived_key)

    json_payload = json.dumps(data).encode("utf-8")
    encrypted_payload = fernet.encrypt(json_payload)

    # Prepend del salt al inicio del bloque binario
    return salt + encrypted_payload


def decrypt_vault_data(master_password: str, encrypted_bytes: bytes) -> List[Dict]:
    """
    Extrae el salt del bloque binario, deriva la clave y desencripta el payload JSON.
    Retorna la lista de credenciales o lanza una excepción en caso de clave incorrecta.
    """
    if len(encrypted_bytes) <= SALT_SIZE:
        raise ValueError("El archivo cifrado está corrupto o inválido.")

    # Extraer el salt original y el payload
    salt = encrypted_bytes[:SALT_SIZE]
    encrypted_payload = encrypted_bytes[SALT_SIZE:]

    derived_key = derive_key(master_password, salt)
    fernet = Fernet(derived_key)

    try:
        decrypted_payload = fernet.decrypt(encrypted_payload)
        return json.loads(decrypted_payload.decode("utf-8"))
    except InvalidToken:
        raise ValueError("Contraseña maestra incorrecta o datos alterados.")