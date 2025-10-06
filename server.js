// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const STORAGE_DIR = path.join(__dirname, 'storage');
const DATA_DIR = path.join(__dirname, 'data');
const FILES_JSON = path.join(DATA_DIR, 'files.json');
const USERS_JSON = path.join(DATA_DIR, 'users.json');

const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Middlewares
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

// CORS: permitir frontends que usen este backend (ajusta origin en producción)
app.use(cors({
  origin: true,
  credentials: true
}));

// --- Helpers para manejo de JSON "DB" simple ---
async function ensureDataFiles() {
  if (!fssync.existsSync(DATA_DIR)) await fs.mkdir(DATA_DIR, { recursive: true });
  if (!fssync.existsSync(STORAGE_DIR)) await fs.mkdir(STORAGE_DIR, { recursive: true });
  if (!fssync.existsSync(FILES_JSON)) await fs.writeFile(FILES_JSON, JSON.stringify([]));
  if (!fssync.existsSync(USERS_JSON)) await fs.writeFile(USERS_JSON, JSON.stringify([]));
}
async function readJSON(file) {
  const txt = await fs.readFile(file, 'utf8');
  return JSON.parse(txt || '[]');
}
async function writeJSON(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// Initialize
(async () => { await ensureDataFiles(); })();

// --- Auth helpers ---
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}
async function authMiddleware(req, res, next) {
  const token = req.cookies['token'];
  if (!token) return res.redirect('/login');
  const payload = verifyToken(token);
  if (!payload) return res.clearCookie('token').redirect('/login');
  // load user
  const users = await readJSON(USERS_JSON);
  const user = users.find(u => u.id === payload.id);
  if (!user) return res.clearCookie('token').redirect('/login');
  req.user = user;
  next();
}

// --- Multer setup ---
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    // storage folder already ensured
    cb(null, STORAGE_DIR);
  },
  filename: (req, file, cb) => {
    // use uuid + ext to avoid collisions
    const ext = path.extname(file.originalname);
    const filename = uuidv4() + ext;
    cb(null, filename);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 } // 200MB max (ajusta)
});

// --- Routes ---

// Home: vista pública con lista de archivos
app.get('/', async (req, res) => {
  const files = await readJSON(FILES_JSON);
  // mostrar solo archivos marcados como public (true) o todos si quieres mostrar todo
  const publicFiles = files.filter(f => f.public === true);
  res.render('index', { files: publicFiles, user: null });
});

// Login form
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login handler
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await readJSON(USERS_JSON);
  const user = users.find(u => u.email === email);
  if (!user) return res.render('login', { error: 'Credenciales inválidas' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.render('login', { error: 'Credenciales inválidas' });

  const token = signToken({ id: user.id, email: user.email, role: user.role });
  const cookieOptions = {
    httpOnly: true,
    // secure en producción
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días
  };
  res.cookie('token', token, cookieOptions);
  res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Admin panel - protegido
app.get('/admin', authMiddleware, async (req, res) => {
  // solo roles con privilegio: role === 'admin' o 'uploader'
  if (!['admin', 'uploader'].includes(req.user.role)) {
    return res.status(403).send('Acceso denegado');
  }
  const files = await readJSON(FILES_JSON);
  res.render('admin', { user: req.user, files });
});

// Seed route para crear admin (solo para desarrollo). Elimina o protege en producción.
app.get('/seed-admin', async (req, res) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'jruben2222@gmail.com.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Alistonca*1';
  const users = await readJSON(USERS_JSON);
  if (users.find(u => u.email === adminEmail)) {
    return res.send('Admin ya existe');
  }
  const hash = await bcrypt.hash(adminPassword, 10);
  const admin = { id: uuidv4(), email: adminEmail, passwordHash: hash, role: 'admin', createdAt: new Date().toISOString() };
  users.push(admin);
  await writeJSON(USERS_JSON, users);
  res.send(`Admin creado: ${adminEmail} - password: ${adminPassword} (cámbialo)`);
});

// Upload archivo (admin/uploader)
app.post('/admin/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!['admin', 'uploader'].includes(req.user.role)) return res.status(403).send('Acceso denegado');
  if (!req.file) return res.status(400).send('Archivo requerido');

  // Sanea metadata
  const safeOriginalName = path.basename(req.file.originalname);
  const files = await readJSON(FILES_JSON);
  const meta = {
    id: uuidv4(),
    originalName: safeOriginalName,
    filename: req.file.filename,
    mime: req.file.mimetype,
    size: req.file.size,
    uploader: req.user.email,
    public: req.body.public === 'on' || req.body.public === 'true' || req.body.public === true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  files.push(meta);
  await writeJSON(FILES_JSON, files);
  res.redirect('/admin');
});

// Edit metadata (ej: cambiar nombre mostrado o visibilidad)
app.post('/admin/file/:id/edit', authMiddleware, async (req, res) => {
  if (!['admin', 'uploader'].includes(req.user.role)) return res.status(403).send('Acceso denegado');
  const id = req.params.id;
  const { originalName, public } = req.body;
  const files = await readJSON(FILES_JSON);
  const file = files.find(f => f.id === id);
  if (!file) return res.status(404).send('Archivo no encontrado');
  file.originalName = typeof originalName === 'string' ? originalName.trim() : file.originalName;
  file.public = public === 'on' || public === 'true' || public === true;
  file.updatedAt = new Date().toISOString();
  await writeJSON(FILES_JSON, files);
  res.redirect('/admin');
});

// Delete archivo (elimina metadata + archivo físico)
app.post('/admin/file/:id/delete', authMiddleware, async (req, res) => {
  if (!['admin', 'uploader'].includes(req.user.role)) return res.status(403).send('Acceso denegado');
  const id = req.params.id;
  let files = await readJSON(FILES_JSON);
  const file = files.find(f => f.id === id);
  if (!file) return res.status(404).send('Archivo no encontrado');
  const filePath = path.join(STORAGE_DIR, file.filename);

  // protección: aseguramos que filePath está dentro de STORAGE_DIR
  const normalized = path.normalize(filePath);
  if (!normalized.startsWith(STORAGE_DIR)) {
    return res.status(400).send('Ruta inválida');
  }
  try {
    if (fssync.existsSync(filePath)) await fs.unlink(filePath);
  } catch (e) {
    console.error('error borrando archivo', e);
  }
  files = files.filter(f => f.id !== id);
  await writeJSON(FILES_JSON, files);
  res.redirect('/admin');
});

// Descargar archivo (público) por id
app.get('/files/download/:id', async (req, res) => {
  const id = req.params.id;
  const files = await readJSON(FILES_JSON);
  const file = files.find(f => f.id === id);
  if (!file) return res.status(404).send('Archivo no encontrado');

  // si está marcado como private, podrías exigir auth; en este ejemplo lo dejamos público solo si public === true
  if (!file.public) {
    return res.status(403).send('Archivo no público');
  }

  const filePath = path.join(STORAGE_DIR, file.filename);
  const normalized = path.normalize(filePath);
  if (!normalized.startsWith(STORAGE_DIR)) return res.status(400).send('Ruta inválida');

  if (!fssync.existsSync(filePath)) return res.status(404).send('Fichero físico no encontrado');
  // Forzar descarga con nombre original
  res.download(filePath, file.originalName);
});

// API pública para lista JSON
app.get('/api/files', async (req, res) => {
  const files = await readJSON(FILES_JSON);
  const publicFiles = files.filter(f => f.public === true).map(({ filename, ...rest }) => rest);
  res.json(publicFiles);
});

// API privada ejemplo: lista para admin
app.get('/api/admin/files', authMiddleware, async (req, res) => {
  if (!['admin', 'uploader'].includes(req.user.role)) return res.status(403).send('Acceso denegado');
  const files = await readJSON(FILES_JSON);
  res.json(files);
});

// Crear usuario (solo admin)
/*
  curl -X POST -H "Content-Type: application/json" -d '{"email":"u@u.com","password":"1234","role":"uploader"}' http://localhost:3000/admin/create-user
*/
app.post('/admin/create-user', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Acceso denegado');
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).send('email y password requeridos');
  const users = await readJSON(USERS_JSON);
  if (users.find(u => u.email === email)) return res.status(400).send('Usuario ya existe');
  const hash = await bcrypt.hash(password, 10);
  const newUser = { id: uuidv4(), email, passwordHash: hash, role: role || 'uploader', createdAt: new Date().toISOString() };
  users.push(newUser);
  await writeJSON(USERS_JSON, users);
  res.redirect('/admin');
});

// Starting server
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log('Seed admin: GET /seed-admin');
});
