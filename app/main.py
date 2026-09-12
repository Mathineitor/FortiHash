import os
from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional

from app.FortiHash import (
    generate_secure_password,
    encrypt_vault_data,
    decrypt_vault_data,
)
from app.analyzer import analyze_strength, check_pwned_k_anonymity

app = FastAPI(
    title="FortiHash API",
    description="(Backend)API local para generación, análisis y almacenamiento seguro de contraseñas.",
    version="1.0.0"
)

# Ruta del archivo de persistencia cifrada
VAULT_FILE = "vault.enc"

# ------------------------------------------------------------------
# Esquemas Pydantic para Validación Estricta de Entradas
# ------------------------------------------------------------------

class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128, description="Longitud entre 8 y 128")
    use_digits: bool = True
    use_symbols: bool = True
    use_uppercase: bool = True


class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Contraseña a analizar")


class VaultItem(BaseModel):
    service: str = Field(..., min_length=1, description="Nombre del servicio o sitio")
    username: str = Field(..., min_length=1, description="Usuario o correo asociado")
    password: str = Field(..., min_length=1, description="Contraseña")


class VaultSaveRequest(BaseModel):
    master_password: str = Field(..., min_length=6, description="Clave maestra")
    items: List[VaultItem]


class VaultUnlockRequest(BaseModel):
    master_password: str = Field(..., min_length=6, description="Clave maestra")


# ------------------------------------------------------------------
# Endpoints de la API REST
# ------------------------------------------------------------------

@app.post("/api/generate", tags=["Crypto"])
def api_generate_password(payload: GenerateRequest):
    """Genera una contraseña criptográficamente segura (CS-PRNG)."""
    try:
        pwd = generate_secure_password(
            length=payload.length,
            use_digits=payload.use_digits,
            use_symbols=payload.use_symbols,
            use_uppercase=payload.use_uppercase
        )
        return {"password": pwd}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/analyze", tags=["Analyzer"])
def api_analyze_password(payload: AnalyzeRequest):
    """Evalúa la entropía en bits, fuerza por Regex y verifica brechas en HIBP."""
    analysis = analyze_strength(payload.password)
    pwned_count = check_pwned_k_anonymity(payload.password)
    analysis["pwned_count"] = pwned_count
    return analysis


@app.post("/api/vault/save", tags=["Vault"])
def api_save_vault(payload: VaultSaveRequest):
    """Cifra los datos con AES-256 (PBKDF2) y los persiste localmente en vault.enc."""
    data_dict = [item.dict() for item in payload.items]
    encrypted_bytes = encrypt_vault_data(payload.master_password, data_dict)
    
    try:
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted_bytes)
        return {"status": "success", "message": "Bóveda guardada y cifrada correctamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error guardando el archivo: {str(e)}")


@app.post("/api/vault/unlock", tags=["Vault"])
def api_unlock_vault(payload: VaultUnlockRequest):
    """Lee el archivo cifrado y lo descifra con la clave maestra proporcionada."""
    if not os.path.exists(VAULT_FILE):
        return {"status": "empty", "items": []}
    
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_bytes = f.read()
        
        items = decrypt_vault_data(payload.master_password, encrypted_bytes)
        return {"status": "success", "items": items}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error leyendo la bóveda: {str(e)}")


# Serve static files for frontend if index.html exists
if os.path.exists("app/static"):
    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    @app.get("/")
    def read_index():
        return FileResponse("app/static/index.html")