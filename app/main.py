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
    version="2.0.0"
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
    service: str = Field(..., min_length=1, description="Nombre del servicio")
    username: str = Field(..., min_length=1, description="Correo o usuario asociado")
    password: str = Field(..., min_length=1, description="Contraseña guardada")
    description: Optional[str] = Field(default="", description="Notas o descripción")


class VaultSaveRequest(BaseModel):
    master_password: str = Field(..., min_length=6, description="Clave maestra")
    items: List[VaultItem]


class VaultUnlockRequest(BaseModel):
    master_password: str = Field(..., min_length=6, description="Clave maestra")
    
class ChangeMasterKeyRequest(BaseModel):
    old_master_password: str = Field(..., min_length=6, description="Clave maestra actual")
    new_master_password: str = Field(..., min_length=6, description="Nueva clave maestra")


# ------------------------------------------------------------------
# Endpoints de la API REST
# ------------------------------------------------------------------

@app.post("/api/generate")
def api_generate_password(payload: GenerateRequest):
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

@app.post("/api/analyze")
def api_analyze_password(payload: AnalyzeRequest):
    analysis = analyze_strength(payload.password)
    pwned_count = check_pwned_k_anonymity(payload.password)
    analysis["pwned_count"] = pwned_count
    return analysis

@app.post("/api/vault/unlock")
def api_unlock_vault(payload: VaultUnlockRequest):
    if not os.path.exists(VAULT_FILE):
        return {"status": "empty", "items": []}
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_bytes = f.read()
        items = decrypt_vault_data(payload.master_password, encrypted_bytes)
        return {"status": "success", "items": items}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/api/vault/save")
def api_save_vault(payload: VaultSaveRequest):
    data_dict = [item.dict() for item in payload.items]
    encrypted_bytes = encrypt_vault_data(payload.master_password, data_dict)
    try:
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted_bytes)
        return {"status": "success", "message": "Bóveda cifrada y guardada correctamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/vault/change-master")
def api_change_master(payload: ChangeMasterKeyRequest):
    """Reemplaza la contraseña maestra re-cifrando la bóveda existente."""
    if not os.path.exists(VAULT_FILE):
        # Si no existe, crea una bóveda vacía con la nueva contraseña maestra
        encrypted_bytes = encrypt_vault_data(payload.new_master_password, [])
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted_bytes)
        return {"status": "success", "message": "Nueva contraseña maestra configurada."}

    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_bytes = f.read()
        items = decrypt_vault_data(payload.old_master_password, encrypted_bytes)
        
        # Re-cifrar con la nueva contraseña
        new_encrypted_bytes = encrypt_vault_data(payload.new_master_password, items)
        with open(VAULT_FILE, "wb") as f:
            f.write(new_encrypted_bytes)
        return {"status": "success", "message": "Contraseña maestra actualizada y bóveda re-cifrada."}
    except ValueError as e:
        raise HTTPException(status_code=401, detail="La contraseña maestra actual es incorrecta.")

@app.delete("/api/vault/clear")
def api_clear_vault():
    if os.path.exists(VAULT_FILE):
        os.remove(VAULT_FILE)
    return {"status": "success", "message": "Bóveda eliminada por completo."}

if os.path.exists("app/static"):
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    @app.get("/")
    def read_index():
        return FileResponse("app/static/index.html")