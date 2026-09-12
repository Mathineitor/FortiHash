from app.analyzer import analyze_strength, check_pwned_k_anonymity

def test_analyzer():
    # Test de contraseña débil común
    weak_res = analyze_strength("011001")
    print(f"[+] '011001' -> Entropía: {weak_res['entropy_bits']} bits | Score: {weak_res['score']}")
    
    pwned_count = check_pwned_k_anonymity("011001")
    print(f"[!] '011001' filtrada en brechas: {pwned_count} veces.")

    # Test de contraseña fuerte
    strong_res = analyze_strength("xK9#mP2$vL8@qW1!")
    print(f"[+] Fuerte -> Entropía: {strong_res['entropy_bits']} bits | Score: {strong_res['score']}")
    
    pwned_count2 = check_pwned_k_anonymity("xK9#mP2$vL8@qW1!")
    print(f"[!] 'xK9#mP2$vL8@qW1!' filtrada en brechas: {pwned_count2} veces.")

if __name__ == "__main__":
    test_analyzer()
