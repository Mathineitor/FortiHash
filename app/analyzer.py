import math
import re
import hashlib
import requests
from typing import Dict, Any

def calculate_entropy(password: str) -> float:
    """
    Calcula la entropía de Shanon en bits basada en el espacio de caracteres usado.
    Fórmula: E = L * log2(R) , Mide cuanta informacion contiene en bits . 
    """
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def analyze_strength(password: str) -> Dict[str, Any]:
    """
    Evalúa la fuerza de la contraseña usando Regex y Entropía.
    """
    entropy = calculate_entropy(password)
    
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    length = len(password)

    # Clasificación por entropía en bits
    if entropy < 40:
        score = "Débil"
    elif entropy < 60:
        score = "Media"
    elif entropy < 80:
        score = "Fuerte"
    else:
        score = "Excelente"

    return {
        "entropy_bits": entropy,
        "score": score,
        "length": length,
        "checks": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
        }
    }


def check_pwned_k_anonymity(password: str) -> int:
    """
    Consulta Have I Been Pwned usando k-Anonymity.
    Solo envía los primeros 5 caracteres del hash SHA-1 a la API.
    Retorna la cantidad de veces que la clave ha sido expuesta.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return 0  # Si la API no responde, degradamos de forma segura

        hashes = (line.split(":") for line in response.text.splitlines())
        for h_suffix, count in hashes:
            if h_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return 0
