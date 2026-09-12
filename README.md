FortiHash
Descripción del Proyecto
FortiHash es una aplicación diseñada para la gestión segura de contraseñas y datos sensibles. Su objetivo es proporcionar un entorno confiable y aislado para la generación, análisis y validación de credenciales, integrando prácticas modernas de ciberseguridad con una arquitectura modular y mantenible.

El proyecto combina cifrado AES‑256, derivación de claves mediante PBKDF2, análisis de entropía de contraseñas y verificación de filtraciones con el protocolo de privacidad k‑Anonymity de Have I Been Pwned.

Estructura del Repositorio
plaintext
FortiHash/
│
├── app/
│   ├── __init__.py
│   ├── main.py              # Configuración y servidor FastAPI (localhost only)
│   ├── crypto_engine.py     # Generación criptográfica y cifrado AES-256
│   ├── analyzer.py          # Expresiones regulares y cálculo de entropía
│   ├── hibp_client.py       # Cliente para HIBP usando k-Anonymity
│   └── static/
│       ├── index.html       # UI del Dashboard
│       ├── styles.css       # Estilos (CSS / Tailwind)
│       └── app.js           # Lógica del cliente y peticiones fetch
│
├── tests/                   # Pruebas unitarias para motores de seguridad
│   ├── test_crypto.py
│   └── test_analyzer.py
│
├── .gitignore               # Exclusión de entornos, cachés y archivos cifrados
├── CONTRIBUTING.md          # Guía para colaboradores
├── LICENSE                  # Licencia de código abierto (MIT)
├── README.md                # Documentación técnica del proyecto
└── requirements.txt         # Dependencias del proyecto

Características Principales
Cifrado AES‑256 con claves derivadas mediante PBKDF2HMAC.

Servidor local aislado en 127.0.0.1 para evitar exposición en red.

Generación aleatoria segura con la librería estándar secrets.

Validación de contraseñas mediante expresiones regulares y cálculo de entropía.

Consulta a Have I Been Pwned usando k‑Anonymity para proteger la privacidad.

Pruebas unitarias que garantizan la fiabilidad del motor criptográfico y del analizador.

Interfaz web ligera con HTML, CSS y JavaScript para interacción básica.

Requisitos Previos
Python 3.10 o superior

Git instalado

Librerías: cryptography, fastapi, uvicorn, pydantic, requests

Instalación y Configuración
Clonar el repositorio:

bash
git clone         
cd FortiHash
Crear y activar entorno virtual:

bash
python3 -m venv venv
source venv/bin/activate
Instalar dependencias:

bash
pip install -r requirements.txt
Ejecución del Servidor
Inicia el servidor en modo local:

bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
Accede a la interfaz en http://127.0.0.1:8000.

Seguridad y Privacidad
El servidor escucha únicamente en 127.0.0.1.

Las contraseñas nunca se almacenan en texto plano.

La clave derivada se mantiene solo durante la sesión activa.

La verificación en HIBP se realiza con k‑Anonymity, enviando únicamente los primeros 5 caracteres del hash SHA‑1.
