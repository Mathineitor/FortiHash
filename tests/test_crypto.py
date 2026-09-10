from app.FortiHash import (
    generate_secure_password,
    encrypt_vault_data,
    decrypt_vault_data,
)

def test_flow():
    # 1. Probar Generación
    pwd = generate_secure_password(length=16)
    print(f"[+] Contraseña generada: {pwd}")

    # 2. Datos simulados
    master_key = "MiClaveSuperSegura123!"
    vault_sample = [{"service": "GitHub", "username": "user", "password": pwd}]

    # 3. Cifrar
    encrypted_blob = encrypt_vault_data(master_key, vault_sample)
    print(f"[+] Bóveda Cifrada (Primeros bytes en Hex): {encrypted_blob[:32].hex()}...")

    # 4. Descifrar con clave correcta
    decrypted = decrypt_vault_data(master_key, encrypted_blob)
    assert decrypted == vault_sample
    print("[+] Test de Descifrado Exitoso: Los datos coinciden.")

    # 5. Descifrar con clave incorrecta
    try:
        decrypt_vault_data("ClaveErronea", encrypted_blob)
    except ValueError as e:
        print(f"[+] Control de Error Exitoso: {e}")

if __name__ == "__main__":
    test_flow()
