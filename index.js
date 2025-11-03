import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "crypto";
import { URLSearchParams } from "url";
import axios from "axios"; // 🚨 Nueva dependencia para GitHub

dotenv.config();

const app = express();
// Nota: Express.json() no es estrictamente necesario para GET con query params, pero se mantiene por convención.
app.use(express.json());

// --- Configuración de CORS ---
const corsOptions = {
  origin: "*", 
  methods: "GET", // Solo permitimos GET como solicitado
  allowedHeaders: ["Content-Type", "x-api-key"], 
  exposedHeaders: ["x-api-key"],
  credentials: true, 
};

app.use(cors(corsOptions));

// -------------------- VARIABLES DE ENTORNO REQUERIDAS --------------------
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_REPO = process.env.GITHUB_REPO; // Formato: 'usuario/repositorio'
const GITHUB_OWNER = GITHUB_REPO ? GITHUB_REPO.split('/')[0] : 'owner';
const GITHUB_REPO_NAME = GITHUB_REPO ? GITHUB_REPO.split('/')[1] : 'repo';

// Validación básica de GitHub
if (!GITHUB_TOKEN || !GITHUB_REPO) {
    console.warn("⚠️ Advertencia: GITHUB_TOKEN o GITHUB_REPO no están configurados. El registro en GitHub será omitido.");
}

// -------------------- FIREBASE ADMIN SDK --------------------
// Inicialización de Firebase
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log("🟢 Firebase Admin SDK inicializado correctamente.");
  } catch (error) {
    console.error("🔴 Error al inicializar Firebase Admin SDK:", error.message);
  }
}

const db = admin.firestore();

// -------------------- UTILERÍAS DE SEGURIDAD Y CÓDIGO EXISTENTE --------------------

/**
 * MOCK: Cifra un texto para simular E2E.
 * ADVERTENCIA: En un sistema real, esta función usaría una clave maestra (derivada con PBKDF2)
 * que NUNCA debería enviarse al servidor. La encriptación ocurre LOCALMENTE en el cliente.
 * Aquí simplemente almacenamos un blob cifrado conceptualmente.
 * @param {string} text - El texto a cifrar (que ya debería estar cifrado desde el cliente).
 * @returns {string} - El texto cifrado.
 */
const MOCK_ENCRYPT = (text) => {
    // Esto debería ser un algoritmo robusto como AES-256-GCM.
    // Usamos Base64 simple para el mock conceptual, asumiendo que el cliente ya hizo la encriptación real.
    return Buffer.from(text).toString('base64');
};

/**
 * MOCK: Descifra un texto.
 * ADVERTENCIA: El servidor NO PUEDE descifrar datos cifrados con la clave maestra del usuario.
 * Esta función se incluye solo para simular una posible reversión (ej. para auditoría en el server si no fuera E2E)
 * o para demostrar la estructura de almacenamiento.
 * @param {string} encryptedText - El texto cifrado.
 * @returns {string} - El texto descifrado.
 */
const MOCK_DECRYPT = (encryptedText) => {
    try {
        return Buffer.from(encryptedText, 'base64').toString('utf8');
    } catch (e) {
        return "Error de descifrado (Mock)";
    }
};


/**
 * Calcula un score de seguridad y asigna un nivel con color.
 * El score (0-100) y el nivel (Muy Baja, Baja, Media, Alta, Muy Alta) son devueltos.
 * @param {string} password - La contraseña a evaluar (o el texto descifrado en el cliente).
 * @returns {object} - { score: number, level: string, color: string }
 */
const calculateSecurityScore = (password) => {
    // Mantenemos la lógica de scoring de la función original, es robusta.
    let score = 0;
    const length = password.length;
    
    // 1. Puntos por longitud
    if (length >= 8) score += 10;
    if (length >= 12) score += 20;
    if (length >= 16) score += 30;

    // 2. Puntos por tipos de caracteres
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) score += 10;
    if (hasUpper) score += 10;
    if (hasNumbers) score += 10;
    if (hasSpecial) score += 10;

    // 3. Puntos adicionales por combinación
    if (length >= 12 && hasUpper && hasNumbers) score += 10;
    if (length >= 16 && hasUpper && hasNumbers && hasSpecial) score += 20;

    score = Math.min(score, 100);

    let level, color;
    if (score >= 90) { level = "Muy Alta"; color = "#10b981"; } // Esmeralda
    else if (score >= 70) { level = "Alta"; color = "#84cc16"; } // Lima
    else if (score >= 50) { level = "Media"; color = "#facc15"; } // Amarillo
    else if (score >= 30) { level = "Baja"; color = "#f97316"; } // Naranja
    else { level = "Muy Baja"; color = "#ef4444"; } // Rojo

    return { score, level, color };
};

// -------------------- GENERADOR AVANZADO Y ESPECÍFICO (Función 2. Generación de Contraseñas Específicas) --------------------
/**
 * Lógica para adaptar la generación a servicios comunes.
 * @param {string} serviceName - Nombre del servicio (ej: 'Email', 'SocialMedia', 'Bank').
 * @returns {object} - Opciones de generación preestablecidas.
 */
const getServiceSpecificOptions = (serviceName) => {
    switch (serviceName.toLowerCase()) {
        case 'email':
        case 'bank':
            // Políticas estrictas: longitud mayor, todos los tipos
            return { length: 20, includeSpecial: true, excludeLookalikes: true };
        case 'socialmedia':
            // Un poco más relajada en longitud, pero fuerte
            return { length: 16, includeSpecial: true };
        case 'ecommerce':
            return { length: 14, includeSpecial: false };
        default:
            return { length: 16, includeSpecial: true }; // Por defecto
    }
};

/**
 * 🔐 Generador de contraseñas seguras y personalizables (Función 1 + 2. Generación Específica)
 * @param {number} length - Longitud de la contraseña.
 * @param {object} options - Opciones de generación.
 * @param {string} serviceType - Tipo de servicio para aplicar reglas preestablecidas.
 * @returns {string} - Contraseña generada.
 */
const generateSecurePasswordAdvanced = (length = 16, options = {}, serviceType = null) => {
    let finalOptions = { ...options };

    // 🚨 Aplicar reglas específicas si se define un tipo de servicio.
    if (serviceType) {
        const serviceRules = getServiceSpecificOptions(serviceType);
        length = serviceRules.length || length;
        finalOptions = { ...finalOptions, ...serviceRules };
    }

    const { 
        includeLower = true,
        includeUpper = true,
        includeNumbers = true,
        includeSpecial = true,
        excludeLookalikes = true,
        passphrase = false // Función 18
    } = finalOptions;

    if (passphrase) {
        // MOCK: Generación de frases seguras (Passphrases - Función 18)
        const nouns = ["Sol", "Llave", "Gato", "Nube", "Taza", "Mundo"];
        const verbs = ["Salta", "Vuela", "Canta", "Come", "Duerme", "Escribe"];
        const adj = ["Fuerte", "Rápido", "Azul", "Nuevo", "Viejo", "Magico"];
        const year = crypto.randomInt(1980, 2024);
        
        return `${nouns[crypto.randomInt(nouns.length)]}-${verbs[crypto.randomInt(verbs.length)]}-${adj[crypto.randomInt(adj.length)]}-${year}`;
    }


    let lower = 'abcdefghijklmnopqrstuvwxyz';
    let upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let numbers = '0123456789';
    let special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    // Opción para excluir caracteres parecidos (como O y 0)
    if (excludeLookalikes) {
        lower = lower.replace(/[lo]/g, '');
        upper = upper.replace(/[IO]/g, '');
        numbers = numbers.replace(/[01]/g, '');
        special = special.replace(/[|]/g, ''); // Ejemplo
    }

    let chars = '';
    if (includeLower) chars += lower;
    if (includeUpper) chars += upper;
    if (includeNumbers) chars += numbers;
    if (includeSpecial) chars += special;
    
    if (chars.length === 0) {
        throw new Error("Debe incluir al menos un tipo de caracter.");
    }

    let password = '';
    
    // Asegurar que la contraseña cumpla con los tipos seleccionados (mínimo 1 de cada)
    const requiredChars = [];
    if (includeLower) requiredChars.push(lower);
    if (includeUpper) requiredChars.push(upper);
    if (includeNumbers) requiredChars.push(numbers);
    if (includeSpecial) requiredChars.push(special);

    // Añadir los caracteres requeridos
    for (const type of requiredChars) {
        password += type[crypto.randomInt(type.length)];
    }

    // Rellenar el resto de la longitud
    for (let i = password.length; i < length; i++) {
        password += chars[crypto.randomInt(chars.length)];
    }

    // Mezclar y devolver
    return password.split('').sort(() => 0.5 - Math.random()).join('').substring(0, length);
};

// -------------------- LOG DE ACTIVIDAD Y GITHUB (Función 8. Historial de Cambios) --------------------

/**
 * 📂 Guarda el log de actividad en un archivo de GitHub.
 * @param {string} userId - ID del usuario.
 * @param {object} logEntry - Objeto de actividad.
 */
const saveToGitHub = async (userId, logEntry) => {
    if (!GITHUB_TOKEN || !GITHUB_REPO) {
        console.warn("⚠️ Omitiendo registro en GitHub: Variables de entorno faltantes.");
        return;
    }

    const filePath = `public/${userId}_activity.json`;
    const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${filePath}`;
    const headers = {
        Authorization: `token ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
    };

    let existingContent = [];
    let sha = null;

    try {
        // 1. Intentar obtener el archivo existente
        const response = await axios.get(apiUrl, { headers });
        const contentBase64 = response.data.content;
        sha = response.data.sha;
        existingContent = JSON.parse(Buffer.from(contentBase64, 'base64').toString('utf8'));
    } catch (error) {
        // Si el archivo no existe (error 404), se ignora y existingContent se mantiene como []
        if (error.response && error.response.status !== 404) {
            console.error(`🔴 Error al leer archivo de GitHub para ${userId}:`, error.message);
            // Si hay otro error, salimos para evitar la sobreescritura incorrecta.
            return;
        }
    }

    // 2. Añadir el nuevo registro
    existingContent.push(logEntry);
    
    // 3. Preparar el contenido para subir (Base64)
    const newContentBase64 = Buffer.from(JSON.stringify(existingContent, null, 2)).toString('base64');

    try {
        // 4. Subir el nuevo contenido
        const commitMessage = `Historial de Cambios: ${logEntry.action} por el usuario ${userId}`;
        const uploadData = {
            message: commitMessage,
            content: newContentBase64,
            sha: sha // Necesario si es una actualización
        };

        await axios.put(apiUrl, uploadData, { headers });
        console.log(`✅ Actividad de ${userId} guardada en GitHub: ${filePath}`);

    } catch (error) {
        console.error(`🔴 Error al subir el archivo a GitHub para ${userId}:`, error.response ? error.response.data : error.message);
    }
};


/**
 * 🧾 Registra actividad del usuario (Función 9 + 8. Historial de Cambios)
 * @param {string} userId - ID del usuario.
 * @param {string} action - Acción realizada (ej: 'ACCESS', 'UPDATE', 'LOGIN_FAIL').
 * @param {string} details - Detalles de la acción.
 * @param {string} byUser - El usuario que realizó el cambio (para gestión de equipos).
 */
const logActivity = async (userId, action, details, byUser = userId) => {
    const logEntry = {
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        action: action,
        details: details,
        ipAddress: 'MOCK_IP', 
        success: action.includes('FAIL') ? false : true,
        byUser: byUser, // 🚨 Nuevo campo para el historial de cambios/equipo
    };

    try {
        const activityRef = db.collection('users').doc(userId).collection('activity');
        await activityRef.add(logEntry);
        
        // 🚨 Guardar el log en GitHub de forma asíncrona (Función 8)
        const logEntryForGithub = {
             ...logEntry,
             timestamp: new Date().toISOString() // Usar ISO para GitHub
        };
        saveToGitHub(userId, logEntryForGithub);

    } catch (error) {
        console.error("🔴 Error al registrar actividad en Firestore:", error);
    }
};

// -------------------- FUNCIONES DE SEGURIDAD AVANZADAS --------------------

/**
 * 🛡️ Envía alertas de seguridad al cliente (Función 5. Alertas de seguridad)
 * Esta función es un MOCK de lo que el servidor podría enviar al cliente (e.g., por una notificación push).
 * @param {string} userId - ID del usuario.
 * @param {string} type - Tipo de alerta (e.g., 'WEAK_PASSWORD', 'SUSPICIOUS_LOGIN', 'REUSED_PASSWORD').
 * @param {string} message - Mensaje detallado.
 */
const sendSecurityAlert = async (userId, type, message) => {
    // En un sistema real, esto se integraría con un servicio de notificaciones Push (Firebase Cloud Messaging, etc.)
    const alertData = {
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        type: type,
        message: message,
        read: false,
    };
    try {
        await db.collection('users').doc(userId).collection('alerts').add(alertData);
        await logActivity(userId, "SECURITY_ALERT_SENT", `Alerta de ${type}: ${message}`);
        console.log(`🔔 Alerta de seguridad enviada a ${userId}: ${type}`);
    } catch (error) {
        console.error("🔴 Error al guardar alerta de seguridad:", error);
    }
};


// -------------------- MIDDLEWARE --------------------

/**
 * Middleware para validar el token de API (x-api-key) del usuario y cargar datos.
 */
const authMiddleware = async (req, res, next) => {
  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({ ok: false, error: "Falta el token de API (x-api-key)" });
  }

  try {
    const usersRef = db.collection("users");
    // Usamos el token como un identificador único para el usuario.
    const snapshot = await usersRef.where("apiKey", "==", token).limit(1).get();

    if (snapshot.empty) {
      await logActivity("unknown", "LOGIN_FAIL", `Intento de acceso con API Key inválida: ${token}`);
      // 🚨 Simulación de alerta de inicio de sesión sospechoso (Función 5)
      await sendSecurityAlert("unknown_user", "SUSPICIOUS_LOGIN", `Intento de acceso fallido con API Key: ${token}`);
      return res.status(403).json({ ok: false, error: "Token inválido o usuario no encontrado" });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const userId = userDoc.id;

    req.user = { id: userId, ...userData };
    // Registrar acceso exitoso
    await logActivity(userId, "LOGIN_SUCCESS", "Acceso a la API principal.");
    next();
  } catch (error) {
    console.error("🔴 Error en authMiddleware:", error);
    res.status(500).json({ ok: false, error: "Error interno al validar el token" });
  }
};


// -------------------- ENDPOINTS (TODOS GET) --------------------

// Endpoint de prueba simple
app.get("/", (req, res) => {
    res.json({
        ok: true,
        message: "🚀 Gestor de Contraseñas API funcionando. Todos los endpoints son GET.",
    });
});

/**
 * GET /api/passwords/generate (Función 1 + 2. Generación Específica)
 * Genera una contraseña o una frase segura (passphrase), opcionalmente para un servicio específico.
 * Query Params: length, includeLower, includeUpper, includeNumbers, includeSpecial, excludeLookalikes, passphrase, serviceType
 */
app.get("/api/passwords/generate", authMiddleware, (req, res) => {
    const { 
        length = 16, 
        passphrase = 'false',
        serviceType = null, // 🚨 Nuevo parámetro para generación específica
        ...options 
    } = req.query;
    
    // Parsear booleanos y números de los query params (que son strings)
    const parsedLength = parseInt(length, 10);
    const parsedOptions = {
        ...options,
        passphrase: passphrase === 'true',
        // Asegurar que las opciones de inclusión son booleanos
        includeLower: options.includeLower !== 'false',
        includeUpper: options.includeUpper !== 'false',
        includeNumbers: options.includeNumbers !== 'false',
        includeSpecial: options.includeSpecial !== 'false',
        excludeLookalikes: options.excludeLookalikes === 'true',
    };

    if (isNaN(parsedLength) || parsedLength < 8 || parsedLength > 64) {
        return res.status(400).json({ ok: false, error: "La longitud debe ser un número entre 8 y 64." });
    }

    try {
        const generatedPassword = generateSecurePasswordAdvanced(parsedLength, parsedOptions, serviceType);
        const security = calculateSecurityScore(generatedPassword);

        // 🚨 Registro de actividad
        logActivity(req.user.id, "GENERATE", `Contraseña generada para ${serviceType || 'General'} (Score: ${security.score}).`);

        res.json({
            ok: true,
            message: `Contraseña generada.`,
            password: generatedPassword,
            security: security,
            type: parsedOptions.passphrase ? "Passphrase" : "Password",
            service: serviceType
        });
    } catch (error) {
        console.error("🔴 Error al generar contraseña:", error);
        res.status(400).json({ ok: false, error: error.message });
    }
});


/**
 * GET /api/passwords/create (Función 1-2, 6, 8, 11)
 * Crea una nueva credencial.
 * Query Params: name, username, password (el blob cifrado), url, category, notes, expiryDate
 */
app.get("/api/passwords/create", authMiddleware, async (req, res) => {
    // Extraemos los datos del query string (simulando body en POST)
    const { name, username, password, url, category, notes, expiryDate } = req.query;

    if (!name || !username || !password) {
        return res.status(400).json({ ok: false, error: "Faltan campos obligatorios: name, username, password (cifrada)." });
    }
    
    // Desciframos el mock para calcular el score (para fines de demostración del score).
    const decryptedMock = MOCK_DECRYPT(password);
    const security = calculateSecurityScore(decryptedMock);
    
    // Creación del objeto de credencial
    const newCredential = {
        name,
        username,
        // Almacenamos el BLOB CIFRADO
        password: password, 
        url: url || null,
        category: category || "General", // Función 2: Categorías
        isFavorite: false, // Función 3: Favoritos
        notes: notes || null, // Función 11: Notas seguras
        expiryDate: expiryDate ? new Date(expiryDate) : null, // Función 24: Vencimiento
        securityScore: security.score,
        securityLevel: security.level,
        securityColor: security.color,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    try {
        const passwordsRef = db.collection('users').doc(req.user.id).collection('passwords');
        const docRef = await passwordsRef.add(newCredential);
        
        await logActivity(req.user.id, "CREATE", `Credencial ${name} (${docRef.id}) creada.`);

        res.status(201).json({ 
            ok: true, 
            message: "Credencial guardada exitosamente.", 
            id: docRef.id,
            data: newCredential 
        });
    } catch (error) {
        console.error("🔴 Error al guardar credencial:", error);
        res.status(500).json({ ok: false, error: "Error interno al guardar la credencial." });
    }
});


/**
 * GET /api/passwords/all (Función 2, 3)
 * Obtiene todas las credenciales. Permite filtrar por favoritos y categoría.
 * Query Params: favorite, category
 */
app.get("/api/passwords/all", authMiddleware, async (req, res) => {
    const isFavorite = req.query.favorite === 'true';
    const category = req.query.category;

    try {
        let query = db.collection('users').doc(req.user.id).collection('passwords');

        // Filtrar por favoritos (Función 3)
        if (isFavorite) {
            query = query.where('isFavorite', '==', true);
        }

        // Filtrar por categoría (Función 2)
        if (category) {
            query = query.where('category', '==', category);
        }

        const snapshot = await query.get();
        
        let passwords = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // Ordenar en memoria (se evita el uso de orderBy para no requerir índices, como se sugirió)
        passwords.sort((a, b) => {
            const dateA = a.createdAt ? a.createdAt.toDate().getTime() : 0;
            const dateB = b.createdAt ? b.createdAt.toDate().getTime() : 0;
            return dateB - dateA; 
        });

        res.json({
            ok: true,
            message: `Mostrando ${passwords.length} credenciales.`,
            count: passwords.length,
            passwords: passwords
        });

    } catch (error) {
        console.error("🔴 Error al obtener credenciales:", error);
        res.status(500).json({ ok: false, error: "Error interno al obtener las credenciales." });
    }
});

/**
 * GET /api/passwords/update/:id (Función 3 - favorito, Función 11 - notas)
 * Endpoint general para actualizar una credencial.
 * Query Params: isFavorite (boolean), name, username, password, category, notes, expiryDate, action=update
 */
app.get("/api/passwords/update/:id", authMiddleware, async (req, res) => {
    const passwordId = req.params.id;
    const updateData = req.query; // Todos los datos vienen del query.

    // No se permite actualizar sin ningún campo, o sin el indicador 'action'
    if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ ok: false, error: "No se proporcionaron campos para actualizar." });
    }

    const docRef = db.collection('users').doc(req.user.id).collection('passwords').doc(passwordId);
    const updates = {};
    let oldName = '';
    
    // Mapeo de query params a campos de Firestore, con validación/conversión
    if (updateData.isFavorite !== undefined) {
        updates.isFavorite = updateData.isFavorite === 'true'; // Función 3
    }
    if (updateData.name) updates.name = updateData.name;
    if (updateData.username) updates.username = updateData.username;
    if (updateData.url) updates.url = updateData.url;
    if (updateData.category) updates.category = updateData.category; // Función 2
    if (updateData.notes) updates.notes = updateData.notes; // Función 11
    if (updateData.expiryDate) updates.expiryDate = new Date(updateData.expiryDate);

    // Si se actualiza la contraseña (el blob cifrado), recalculamos el score de demostración.
    if (updateData.password) {
        updates.password = updateData.password;
        const decryptedMock = MOCK_DECRYPT(updateData.password);
        const security = calculateSecurityScore(decryptedMock);
        updates.securityScore = security.score;
        updates.securityLevel = security.level;
        updates.securityColor = security.color;

        // 🚨 Alerta de seguridad si la nueva contraseña es muy débil (Función 5)
        if (security.score < 30) {
            sendSecurityAlert(req.user.id, "WEAK_PASSWORD_ADDED", `La contraseña para ${updateData.name || 'una credencial'} es muy débil después de la actualización.`);
        }
    }

    updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    try {
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ ok: false, error: "Credencial no encontrada." });
        }
        oldName = doc.data().name; // Guardamos el nombre anterior para el log

        await docRef.update(updates);
        await logActivity(req.user.id, "UPDATE", `Credencial ${oldName} (${passwordId}) actualizada. Campos: ${Object.keys(updates).join(', ')}.`, req.user.id);

        res.json({ 
            ok: true, 
            message: `Credencial '${passwordId}' actualizada exitosamente.`,
            updates: updates
        });

    } catch (error) {
        console.error("🔴 Error al actualizar credencial:", error);
        res.status(500).json({ ok: false, error: "Error interno al actualizar la credencial." });
    }
});


/**
 * GET /api/passwords/delete/:id
 * Elimina una credencial específica. (Simulando DELETE con GET).
 */
app.get("/api/passwords/delete/:id", authMiddleware, async (req, res) => {
    const passwordId = req.params.id;

    try {
        const docRef = db.collection('users').doc(req.user.id).collection('passwords').doc(passwordId);
        
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ ok: false, error: "Credencial no encontrada." });
        }

        await docRef.delete();
        await logActivity(req.user.id, "DELETE", `Credencial ${doc.data().name} (${passwordId}) eliminada.`, req.user.id);

        res.json({ 
            ok: true, 
            message: `Credencial '${passwordId}' eliminada exitosamente.` 
        });

    } catch (error) {
        console.error("🔴 Error al eliminar credencial:", error);
        res.status(500).json({ ok: false, error: "Error interno al eliminar la credencial." });
    }
});

/**
 * GET /api/passwords/search (Función 4)
 * Búsqueda rápida con inteligencia por nombre, dominio o tipo.
 * Query Params: term
 */
app.get("/api/passwords/search", authMiddleware, async (req, res) => {
    const searchTerm = req.query.term?.toLowerCase();

    if (!searchTerm || searchTerm.length < 3) {
        return res.status(400).json({ ok: false, error: "El término de búsqueda debe tener al menos 3 caracteres." });
    }

    try {
        const passwordsRef = db.collection('users').doc(req.user.id).collection('passwords');
        // Firestore no permite búsquedas 'OR' complejas o de texto completo fácilmente.
        // Hacemos una búsqueda limitada en Firestore y el filtrado "inteligente" en memoria.
        // En una app real se usaría ElasticSearch o Algolia.

        const snapshot = await passwordsRef.get();
        
        const results = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        })).filter(pass => 
            pass.name?.toLowerCase().includes(searchTerm) || 
            pass.url?.toLowerCase().includes(searchTerm) || 
            pass.category?.toLowerCase().includes(searchTerm) ||
            pass.username?.toLowerCase().includes(searchTerm)
        );
        
        await logActivity(req.user.id, "SEARCH", `Búsqueda de '${searchTerm}' - ${results.length} resultados.`);


        res.json({
            ok: true,
            message: `Resultados encontrados para '${searchTerm}'.`,
            count: results.length,
            passwords: results
        });

    } catch (error) {
        console.error("🔴 Error en la búsqueda:", error);
        res.status(500).json({ ok: false, error: "Error interno en la búsqueda." });
    }
});


/**
 * GET /api/security/audit (Función 5. Alertas, 6. Análisis Avanzado, 12, 19)
 * Revisa contraseñas débiles, repetidas y patrones. Genera el Panel de Seguridad.
 */
app.get("/api/security/audit", authMiddleware, async (req, res) => {
    try {
        const passwordsRef = db.collection('users').doc(req.user.id).collection('passwords');
        const snapshot = await passwordsRef.get();
        
        const passwords = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        const weakPasswords = [];
        const repeatedPasswords = [];
        const passwordCount = {}; 
        const patternDetection = []; // 🚨 Para Función 6

        // Auditoría
        for (const pass of passwords) {
            const decryptedPass = MOCK_DECRYPT(pass.password);
            
            // 1. Revisión de debilidad (score < 50)
            if (pass.securityScore < 50) {
                weakPasswords.push({
                    id: pass.id,
                    name: pass.name,
                    score: pass.securityScore,
                    level: pass.securityLevel,
                    reason: "Contraseña débil (Score bajo)."
                });
                // 🚨 Generar alerta (Función 5)
                sendSecurityAlert(req.user.id, "WEAK_PASSWORD", `La contraseña para ${pass.name} es débil.`);
            }

            // 2. Revisión de repetición
            if (passwordCount[decryptedPass]) {
                passwordCount[decryptedPass].count += 1;
                passwordCount[decryptedPass].names.push(pass.name);
                // 🚨 Generar alerta (Función 5)
                if (passwordCount[decryptedPass].count === 2) {
                    sendSecurityAlert(req.user.id, "REUSED_PASSWORD", `La contraseña para ${pass.name} está repetida.`);
                }
            } else {
                passwordCount[decryptedPass] = { count: 1, names: [pass.name] };
            }

            // 3. 🚨 Análisis Avanzado: Detección de patrones simples (Función 6)
            if (decryptedPass.includes(pass.username) && pass.username.length > 3) {
                 patternDetection.push({
                    id: pass.id,
                    name: pass.name,
                    reason: "Contiene el nombre de usuario."
                });
            }
            if (/(123|abc|qwerty)/i.test(decryptedPass)) {
                 patternDetection.push({
                    id: pass.id,
                    name: pass.name,
                    reason: "Contiene secuencia común/palabra prohibida."
                });
            }
        }

        // Mapeo de contraseñas repetidas
        for (const [password, data] of Object.entries(passwordCount)) {
            if (data.count > 1) {
                repeatedPasswords.push({
                    password: password,
                    count: data.count,
                    usedFor: data.names
                });
            }
        }
        
        // Panel de seguridad (Función 19)
        const totalPasswords = passwords.length;
        const strong = passwords.filter(p => p.securityScore >= 70).length;
        const medium = passwords.filter(p => p.securityScore >= 50 && p.securityScore < 70).length;
        const weak = passwords.filter(p => p.securityScore < 50).length;
        
        const securityScoreAverage = totalPasswords > 0 
            ? passwords.reduce((sum, p) => sum + p.securityScore, 0) / totalPasswords
            : 0;
        
        const panel = {
            totalPasswords,
            strong: strong,
            medium: medium,
            weak: weak,
            repeatedCount: repeatedPasswords.length,
            patternCount: patternDetection.length, // 🚨 Nuevo para Función 6
            securityScoreAverage: Math.round(securityScoreAverage),
            securityRating: calculateSecurityScore(securityScoreAverage.toFixed(0)).level 
        };

        await logActivity(req.user.id, "SECURITY_AUDIT", "Auditoría de seguridad ejecutada.");


        res.json({
            ok: true,
            message: "Auditoría de seguridad completada. Revise los hallazgos.",
            panel: panel,
            weakPasswords: weakPasswords,
            repeatedPasswords: repeatedPasswords,
            advancedPatternDetection: patternDetection // 🚨 Resultados Función 6
        });

    } catch (error) {
        console.error("🔴 Error en la auditoría de seguridad:", error);
        res.status(500).json({ ok: false, error: "Error interno en la auditoría." });
    }
});


/**
 * GET /api/activity (Función 9 + 8. Historial de Cambios)
 * Obtiene el registro de actividad del usuario.
 */
app.get("/api/activity", authMiddleware, async (req, res) => {
    try {
        const activityRef = db.collection('users').doc(req.user.id).collection('activity');
        // Ordenamos por timestamp descendente para ver lo más reciente primero
        const snapshot = await activityRef.orderBy('timestamp', 'desc').limit(50).get();
        
        const activityLog = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            timestamp: doc.data().timestamp ? doc.data().timestamp.toDate().toISOString() : 'N/A'
        }));

        res.json({
            ok: true,
            message: `Mostrando los últimos ${activityLog.length} registros de actividad.`,
            count: activityLog.length,
            log: activityLog
        });
    } catch (error) {
        console.error("🔴 Error al obtener actividad:", error);
        res.status(500).json({ ok: false, error: "Error interno al obtener el registro de actividad." });
    }
});


// -------------------- FUNCIONES ADICIONALES DE SEGURIDAD Y COMPARTIR --------------------

/**
 * GET /api/sync/status (Función 4. Sincronización entre dispositivos)
 * Reporta el estado de sincronización y el último dispositivo sincronizado.
 * Query Params: deviceId, deviceType
 */
app.get("/api/sync/status", authMiddleware, async (req, res) => {
    const { deviceId, deviceType } = req.query;

    if (!deviceId || !deviceType) {
         return res.status(400).json({ ok: false, error: "Faltan parámetros: deviceId, deviceType." });
    }

    const syncInfo = {
        lastSync: new Date().toISOString(),
        lastDevice: `${deviceType} (${deviceId})`,
        status: "OK",
    };

    try {
        // Simular la actualización de un registro de sincronización
        await db.collection('users').doc(req.user.id).update({
            lastSync: syncInfo.lastSync,
            lastDevice: syncInfo.lastDevice,
        });
        
        await logActivity(req.user.id, "SYNC_UPDATE", `Dispositivo ${deviceType} (${deviceId}) sincronizado.`);

        res.json({
            ok: true,
            message: "Estado de sincronización reportado y actualizado.",
            syncInfo: syncInfo
        });
    } catch (error) {
        console.error("🔴 Error al actualizar estado de sincronización:", error);
        res.status(500).json({ ok: false, error: "Error interno al actualizar el estado de sincronización." });
    }
});


/**
 * GET /api/security/protection (Función 2. Autenticación Biométrica, 3. Análisis de Malware, 4. Protección contra phishing)
 * Reporta el estado de las protecciones del cliente (MOCK/Informativo).
 * Query Params: checkBiometric, checkMalware, checkPhishing
 */
app.get("/api/security/protection", authMiddleware, async (req, res) => {
    const { checkBiometric, checkMalware, checkPhishing } = req.query;

    const protectionStatus = {};

    // 🚨 Autenticación Biométrica (Función 2. Seguridad Adicional)
    if (checkBiometric === 'true') {
        // El servidor verifica si la clave biométrica está habilitada en la cuenta
        protectionStatus.biometricEnabled = req.user.biometricKeyId ? true : false; 
    }

    // 🚨 Análisis de Malware (Función 3. Seguridad Adicional)
    if (checkMalware === 'true') {
        // El servidor recibe el reporte de riesgo de malware del cliente
        protectionStatus.malwareThreats = Math.random() < 0.1 ? 1 : 0; // MOCK de detección de amenaza
        if (protectionStatus.malwareThreats > 0) {
            sendSecurityAlert(req.user.id, "MALWARE_DETECTED", "Amenaza de malware detectada en el dispositivo.");
        }
    }

    // 🚨 Protección contra Phishing (Función 4. Seguridad Adicional)
    if (checkPhishing === 'true') {
        // MOCK: El cliente puede enviar la URL para una verificación de reputación
        protectionStatus.phishingProtection = {
             status: "Active",
             lastCheck: new Date().toISOString()
        };
    }
    
    await logActivity(req.user.id, "SECURITY_CHECK", "Revisión de protecciones de seguridad.");

    res.json({
        ok: true,
        message: "Estado de protección de seguridad reportado.",
        protectionStatus: protectionStatus
    });
});


/**
 * GET /api/share/password/:id (Función 1. Compartir contraseñas)
 * Crea un enlace de compartición segura con permisos y vencimiento.
 * Query Params: targetUserEmail, expirationDate, readOnly
 */
app.get("/api/share/password/:id", authMiddleware, async (req, res) => {
    const passwordId = req.params.id;
    const { targetUserEmail, expirationDate, readOnly = 'true' } = req.query;

    if (!targetUserEmail || !expirationDate) {
        return res.status(400).json({ ok: false, error: "Faltan parámetros: targetUserEmail, expirationDate." });
    }

    try {
        const docRef = db.collection('users').doc(req.user.id).collection('passwords').doc(passwordId);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ ok: false, error: "Credencial no encontrada." });
        }

        // 1. Encontrar el ID del usuario objetivo
        const targetSnapshot = await db.collection("users").where("email", "==", targetUserEmail).limit(1).get();
        if (targetSnapshot.empty) {
            return res.status(404).json({ ok: false, error: "Usuario objetivo no encontrado." });
        }
        const targetUserId = targetSnapshot.docs[0].id;

        // 2. Crear el registro de compartición segura
        const shareToken = crypto.randomBytes(16).toString('hex'); // Token seguro
        const shareRecord = {
            ownerId: req.user.id,
            targetId: targetUserId,
            passwordId: passwordId,
            passwordBlob: doc.data().password, // Compartimos el blob cifrado E2E original
            sharedAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: new Date(expirationDate),
            readOnly: readOnly === 'true',
            active: true,
        };

        await db.collection('shares').doc(shareToken).set(shareRecord);
        
        const credentialName = doc.data().name;
        await logActivity(req.user.id, "SHARE_PASSWORD", `Contraseña '${credentialName}' compartida con ${targetUserEmail}.`, req.user.id);


        // 3. Crear el enlace de compartición (MOCK)
        const shareLink = `${req.protocol}://password-manager-api/api/share/access?token=${shareToken}`;

        res.json({
            ok: true,
            message: `Contraseña '${credentialName}' compartida de forma segura con ${targetUserEmail}.`,
            shareLink: shareLink,
            shareToken: shareToken
        });

    } catch (error) {
        console.error("🔴 Error al compartir contraseña:", error);
        res.status(500).json({ ok: false, error: "Error interno al compartir la contraseña." });
    }
});

// -------------------- FUNCIONES DE GESTIÓN DE EQUIPOS --------------------

/**
 * GET /api/team/add-member (Función 2. Gestión de equipos)
 * Permite a un administrador añadir un nuevo miembro al equipo.
 * Query Params: memberEmail, role (admin/member), teamId (asumimos que el admin ya está autenticado)
 */
app.get("/api/team/add-member", authMiddleware, async (req, res) => {
    // 🚨 Se asume que req.user tiene un campo 'role' (e.g., 'teamAdmin' o 'user')
    if (req.user.role !== 'admin' && req.user.role !== 'teamAdmin') {
        return res.status(403).json({ ok: false, error: "Acceso denegado. Solo administradores de equipo pueden añadir miembros." });
    }

    const { memberEmail, role = 'member', teamId } = req.query;

    if (!memberEmail || !teamId) {
        return res.status(400).json({ ok: false, error: "Faltan parámetros: memberEmail, teamId." });
    }

    try {
        // MOCK: Buscar el usuario por email.
        const targetSnapshot = await db.collection("users").where("email", "==", memberEmail).limit(1).get();
        if (targetSnapshot.empty) {
            return res.status(404).json({ ok: false, error: "Usuario a añadir no encontrado." });
        }
        const memberId = targetSnapshot.docs[0].id;
        
        // 1. Actualizar el perfil del miembro con el teamId y rol
        await db.collection('users').doc(memberId).update({
            teamId: teamId,
            teamRole: role,
        });
        
        // 2. Añadir al miembro a la lista del equipo (para una búsqueda rápida)
        await db.collection('teams').doc(teamId).collection('members').doc(memberId).set({
            email: memberEmail,
            role: role,
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        // 3. 🚨 Notificación de equipo (Función 3. Notificaciones de equipo)
        const teamNotification = {
            type: "MEMBER_ADDED",
            message: `${memberEmail} ha sido añadido al equipo con el rol: ${role}.`,
            adminId: req.user.id,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        };
        await db.collection('teams').doc(teamId).collection('notifications').add(teamNotification);


        await logActivity(req.user.id, "TEAM_ADD_MEMBER", `Miembro ${memberEmail} añadido al equipo ${teamId} con rol ${role}.`, req.user.id);

        res.json({
            ok: true,
            message: `Miembro ${memberEmail} añadido a ${teamId} con éxito.`
        });

    } catch (error) {
        console.error("🔴 Error al añadir miembro al equipo:", error);
        res.status(500).json({ ok: false, error: "Error interno al añadir miembro al equipo." });
    }
});


/**
 * GET /api/team/notifications (Función 3. Notificaciones de equipo)
 * Permite a un administrador de equipo ver las notificaciones del equipo.
 * Query Params: teamId
 */
app.get("/api/team/notifications", authMiddleware, async (req, res) => {
    // 🚨 Se verifica que el usuario es un administrador de un equipo.
    const teamId = req.query.teamId || req.user.teamId;
    
    if (!teamId || (req.user.teamId !== teamId || req.user.teamRole !== 'admin')) {
         return res.status(403).json({ ok: false, error: "Acceso denegado. No es un administrador del equipo especificado." });
    }

    try {
        const notificationsRef = db.collection('teams').doc(teamId).collection('notifications');
        const snapshot = await notificationsRef.orderBy('timestamp', 'desc').limit(20).get();

        const notifications = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            timestamp: doc.data().timestamp ? doc.data().timestamp.toDate().toISOString() : 'N/A'
        }));
        
        await logActivity(req.user.id, "TEAM_VIEW_NOTIFS", `Revisó ${notifications.length} notificaciones del equipo ${teamId}.`);

        res.json({
            ok: true,
            message: `Mostrando las últimas ${notifications.length} notificaciones para el equipo ${teamId}.`,
            count: notifications.length,
            notifications: notifications
        });

    } catch (error) {
        console.error("🔴 Error al obtener notificaciones de equipo:", error);
        res.status(500).json({ ok: false, error: "Error interno al obtener notificaciones del equipo." });
    }
});


// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor de Password Manager API corriendo en http://localhost:${PORT}`);
});

