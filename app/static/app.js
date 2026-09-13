let currentVaultItems = [];
let activeMasterPassword = "";
let autoLockTimer = null;
let secondsRemaining = 60;

// Init Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('passInput').addEventListener('input', (e) => {
        if (e.target.value.length > 0) analyzePassword(e.target.value);
    });
});

// Switch Tabs
function switchTab(tabName) {
    document.getElementById('tab-generator').classList.add('hidden');
    document.getElementById('tab-vault').classList.add('hidden');
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');

    // Actualiza qué botón se ve como activo
    document.getElementById('tabBtn-generator').classList.toggle('active', tabName === 'generator');
    document.getElementById('tabBtn-vault').classList.toggle('active', tabName === 'vault');

    if (tabName === 'vault' && !activeMasterPassword) {
        showLockOverlay(true);
    }
}

// ------------------------------------------------------------------
// Generador y Analizador
// ------------------------------------------------------------------
async function generatePassword() {
    const payload = {
        length: parseInt(document.getElementById('lengthRange').value),
        use_digits: document.getElementById('chkDigits').checked,
        use_symbols: document.getElementById('chkSymbols').checked,
        use_uppercase: document.getElementById('chkUpper').checked
    };

    const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();
    document.getElementById('passInput').value = data.password;
    analyzePassword(data.password);
}

async function analyzePassword(password) {
    const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    });
    const data = await res.json();

    document.getElementById('metricsArea').classList.remove('hidden');
    document.getElementById('entropyVal').innerText = data.entropy_bits;
    document.getElementById('scoreVal').innerText = data.score;

    const bar = document.getElementById('entropyBar');
    const percentage = Math.min((data.entropy_bits / 100) * 100, 100);
    bar.style.width = `${percentage}%`;

    const alertBox = document.getElementById('pwnedAlert');
    if (data.pwned_count > 0) {
        alertBox.innerText = `⚠️ Filtrada ${data.pwned_count.toLocaleString()} veces en brechas de seguridad.`;
        alertBox.classList.remove('hidden');
    } else {
        alertBox.classList.add('hidden');
    }
}

// ------------------------------------------------------------------
// Bóveda Cifrada (Sesión + Auto-lock)
// ------------------------------------------------------------------
async function unlockVault() {
    const master = document.getElementById('masterAuthInput').value;
    if (!master) return alert("Ingresa tu contraseña maestra.");

    const res = await fetch('/api/vault/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ master_password: master })
    });

    if (!res.ok) {
        return alert("Contraseña maestra incorrecta.");
    }

    const data = await res.json();
    activeMasterPassword = master;
    currentVaultItems = data.items || [];
    document.getElementById('masterAuthInput').value = '';

    showLockOverlay(false);
    renderVault();
    startAutoLockTimer();
}

function startAutoLockTimer() {
    stopAutoLockTimer();
    secondsRemaining = 60;
    updateTimerDisplay();

    autoLockTimer = setInterval(() => {
        secondsRemaining--;
        updateTimerDisplay();

        if (secondsRemaining <= 0) {
            lockVaultSession();
            alert("La sesión de la bóveda ha expirado (60s). Vuelve a ingresar tu clave maestra.");
        }
    }, 1000);
}

function stopAutoLockTimer() {
    if (autoLockTimer) clearInterval(autoLockTimer);
}

function updateTimerDisplay() {
    const timerElem = document.getElementById('sessionTimer');
    if (timerElem) timerElem.innerText = `${secondsRemaining}s`;
}

function lockVaultSession() {
    stopAutoLockTimer();
    activeMasterPassword = "";
    currentVaultItems = [];
    showLockOverlay(true);
}

function showLockOverlay(show) {
    const overlay = document.getElementById('vaultLockOverlay');
    const content = document.getElementById('vaultContent');
    if (show) {
        overlay.classList.remove('hidden');
        content.classList.add('hidden');
    } else {
        overlay.classList.add('hidden');
        content.classList.remove('hidden');
    }
}

async function saveNewCredential() {
    if (!activeMasterPassword) return alert("La sesión está bloqueada.");

    const service = document.getElementById('inputService').value;
    const username = document.getElementById('inputUser').value;
    const password = document.getElementById('inputPass').value;
    const description = document.getElementById('inputDesc').value;

    if (!service || !username || !password) {
        return alert("Completa el servicio, correo/usuario y la contraseña.");
    }

    currentVaultItems.push({ service, username, password, description });

    const res = await fetch('/api/vault/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            master_password: activeMasterPassword,
            items: currentVaultItems
        })
    });

    if (res.ok) {
        alert("¡Credencial cifrada y guardada!");
        document.getElementById('inputService').value = '';
        document.getElementById('inputUser').value = '';
        document.getElementById('inputPass').value = '';
        document.getElementById('inputDesc').value = '';
        renderVault();
        startAutoLockTimer(); // Reiniciar el temporizador tras una acción
    } else {
        alert("Error al guardar la credencial.");
    }
}

async function deleteSingleItem(index) {
    if (!confirm("¿Eliminar este registro de la bóveda?")) return;

    currentVaultItems.splice(index, 1);

    const res = await fetch('/api/vault/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            master_password: activeMasterPassword,
            items: currentVaultItems
        })
    });

    if (res.ok) {
        renderVault();
        startAutoLockTimer();
    }
}

async function clearEntireVault() {
    const confirmDelete = confirm("¿ESTÁS SEGURO? Esto eliminará PERMANENTEMENTE toda la bóveda.");
    if (!confirmDelete) return;

    const res = await fetch('/api/vault/clear', { method: 'DELETE' });
    if (res.ok) {
        alert("Bóveda eliminada por completo.");
        lockVaultSession();
    }
}

async function changeMasterKey() {
    const oldKey = prompt("Ingresa tu Contraseña Maestra Actual:");
    if (!oldKey) return;
    const newKey = prompt("Ingresa tu NUEVA Contraseña Maestra (mínimo 6 caracteres):");
    if (!newKey || newKey.length < 6) return alert("Clave inválida.");

    const res = await fetch('/api/vault/change-master', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            old_master_password: oldKey,
            new_master_password: newKey
        })
    });

    const data = await res.json();
    if (res.ok) {
        alert("¡Contraseña Maestra cambiada con éxito! Inicia sesión con tu nueva clave.");
        lockVaultSession();
    } else {
        alert(data.detail || "Error al actualizar la contraseña maestra.");
    }
}

function renderVault() {
    const container = document.getElementById('vaultItemsContainer');
    container.innerHTML = '';

    currentVaultItems.forEach((item, index) => {
        container.innerHTML += `
            <div class="bg-slate-900 border border-slate-700 p-3 rounded flex justify-between items-center">
                <div>
                    <strong class="text-cyan-400 text-sm">${escapeHtml(item.service)}</strong>
                    <div class="text-xs text-slate-300">${escapeHtml(item.username)}</div>
                    <div class="text-xs text-slate-500 italic">${escapeHtml(item.description || '')}</div>
                    <div class="text-xs text-slate-600 mt-1">Contraseña: <span class="tracking-widest">••••••••</span></div>
                </div>
<div class="flex gap-2 items-center">
    <button onclick="copyToClipboard('${escapeJs(item.password)}')" class="bg-cyan-600 hover:bg-cyan-500 text-white text-xs px-2.5 py-1 rounded">Copiar</button>
    <button id="viewBtn-${index}" onclick="revealPassword(${index})" class="bg-base-700 hover:bg-base-600 border border-base-600 text-slate-200 text-xs px-2.5 py-1 rounded">Ver</button>
    <span id="revealed-${index}" class="hidden data-text text-brass-400 text-xs px-1"></span>
    <button onclick="deleteSingleItem(${index})" class="bg-red-900/60 hover:bg-red-700 text-red-200 text-xs px-2 py-1 rounded border border-red-700">Borrar</button>
</div>
            </div>
        `;
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    alert("¡Contraseña copiada al portapapeles!");
}

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));
}

function escapeJs(str) {
    return str.replace(/'/g, "\\'");
}
let revealTimers = {};

function revealPassword(index) {
    const confirmPass = prompt("Vuelve a ingresar tu contraseña maestra para ver esta contraseña:");
    if (confirmPass === null) return; // canceló
    if (confirmPass !== activeMasterPassword) {
        return alert("Contraseña maestra incorrecta.");
    }

    const revealEl = document.getElementById(`revealed-${index}`);
    const viewBtn = document.getElementById(`viewBtn-${index}`);

    if (revealTimers[index]) clearTimeout(revealTimers[index]);

    revealEl.innerText = currentVaultItems[index].password;
    revealEl.classList.remove('hidden');
    if (viewBtn) viewBtn.classList.add('hidden');

    revealTimers[index] = setTimeout(() => {
        revealEl.classList.add('hidden');
        revealEl.innerText = '';
        if (viewBtn) viewBtn.classList.remove('hidden');
    }, 10000);
}