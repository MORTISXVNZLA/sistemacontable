'use strict';
/**
 * Sistema de Registro Contable · Bs / USD
 * Servidor sin dependencias externas: Node.js >= 22.5 (usa node:sqlite integrado).
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SESION_HORAS = Number(process.env.SESSION_HOURS) || 12;
const MAX_BODY = 20 * 1024 * 1024;
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'contable.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

const CUENTAS_BASE = [
  [1101, 'Caja Bs', 'Activo corriente'], [1102, 'Caja USD', 'Activo corriente'], [1103, 'Bancos Bs', 'Activo corriente'],
  [1104, 'Bancos USD', 'Activo corriente'], [1201, 'Cuentas por cobrar clientes', 'Activo corriente'],
  [1301, 'Inventario de mercancías', 'Activo corriente'], [2101, 'Cuentas por pagar proveedores', 'Pasivo corriente'],
  [2102, 'IVA por pagar', 'Pasivo corriente'], [3101, 'Capital social', 'Patrimonio'],
  [4101, 'Ingresos por venta de bienes', 'Ingreso'], [4102, 'Ingresos por prestación de servicios', 'Ingreso'],
  [4201, 'Otros ingresos', 'Ingreso'], [5101, 'Costo de ventas', 'Costo'], [6101, 'Sueldos y salarios', 'Gasto operativo'],
  [6102, 'Alquileres', 'Gasto operativo'], [6103, 'Servicios públicos', 'Gasto operativo'], [6104, 'Publicidad y mercadeo', 'Gasto operativo'],
  [6105, 'Honorarios profesionales', 'Gasto operativo'], [6106, 'Gastos bancarios', 'Gasto operativo'],
  [6107, 'Depreciación', 'Gasto operativo'], [6108, 'Otros gastos', 'Gasto operativo']
];
const CLASIFICACIONES = ['Activo corriente', 'Pasivo corriente', 'Patrimonio', 'Ingreso', 'Costo', 'Gasto operativo'];

db.exec(`
CREATE TABLE IF NOT EXISTS config (clave TEXT PRIMARY KEY, valor TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT NOT NULL UNIQUE COLLATE NOCASE, nombre TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('Admin','Usuario')), activo INTEGER NOT NULL DEFAULT 1,
  hash TEXT NOT NULL, creadoEn TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sesiones (
  token TEXT PRIMARY KEY, usuarioId INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE, expira INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auditoria (
  id INTEGER PRIMARY KEY AUTOINCREMENT, cuando TEXT NOT NULL, usuario TEXT NOT NULL, accion TEXT NOT NULL, detalle TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tasas (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, tasa REAL NOT NULL, creadoPor TEXT);
CREATE TABLE IF NOT EXISTS cuentas (codigo INTEGER PRIMARY KEY, nombre TEXT NOT NULL, clasificacion TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS productos (
  codigo TEXT PRIMARY KEY, descripcion TEXT NOT NULL, unidad TEXT, categoria TEXT,
  metodo TEXT NOT NULL DEFAULT 'PEPS', minimo REAL NOT NULL DEFAULT 0, vnr REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS movs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, codigo TEXT NOT NULL, tipo TEXT NOT NULL,
  cantidad REAL NOT NULL, moneda TEXT NOT NULL, costo REAL NOT NULL DEFAULT 0, tasaManual REAL,
  precio REAL NOT NULL DEFAULT 0, creadoPor TEXT
);
CREATE TABLE IF NOT EXISTS registros (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, tipo TEXT NOT NULL, cuenta INTEGER NOT NULL,
  descripcion TEXT, tercero TEXT, documento TEXT, moneda TEXT NOT NULL, monto REAL NOT NULL, tasaManual REAL, creadoPor TEXT
);
CREATE TABLE IF NOT EXISTS presup (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, codigo TEXT NOT NULL, unidades REAL NOT NULL, precio REAL NOT NULL DEFAULT 0, creadoPor TEXT
);
CREATE INDEX IF NOT EXISTS ix_movs_fecha ON movs(fecha);
CREATE INDEX IF NOT EXISTS ix_reg_fecha ON registros(fecha);
CREATE INDEX IF NOT EXISTS ix_tasas_fecha ON tasas(fecha);
`);

function sembrarCuentas() {
  const ins = db.prepare('INSERT OR IGNORE INTO cuentas (codigo,nombre,clasificacion) VALUES (?,?,?)');
  for (const c of CUENTAS_BASE) ins.run(...c);
}
sembrarCuentas();

// ---------- Utilidades ----------
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const ahora = () => new Date().toISOString();
const fechaOk = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
const numPos = n => typeof n === 'number' && isFinite(n) && n > 0;
const numNoNeg = n => typeof n === 'number' && isFinite(n) && n >= 0;
const txt = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const cfgGet = k => (db.prepare('SELECT valor FROM config WHERE clave=?').get(k) || {}).valor || '';
const cfgSet = (k, v) => db.prepare('INSERT INTO config (clave,valor) VALUES (?,?) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor').run(k, v);
function auditar(usuario, accion, detalle) {
  db.prepare('INSERT INTO auditoria (cuando,usuario,accion,detalle) VALUES (?,?,?,?)').run(ahora(), usuario || '-', accion, String(detalle || '').slice(0, 500));
}
function transaccion(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}

// ---------- Contraseñas y sesiones ----------
function hashClave(clave) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(clave, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + h.toString('hex');
}
function verificarClave(clave, guardado) {
  const [alg, salt, h] = String(guardado).split('$');
  if (alg !== 'scrypt') return false;
  const calc = crypto.scryptSync(clave, Buffer.from(salt, 'hex'), 64);
  const real = Buffer.from(h, 'hex');
  return calc.length === real.length && crypto.timingSafeEqual(calc, real);
}
const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');
function validarClaveNueva(c) {
  if (typeof c !== 'string' || c.length < 8) throw new HttpError(400, 'La contraseña debe tener al menos 8 caracteres.');
  if (c.length > 200) throw new HttpError(400, 'La contraseña es demasiado larga.');
}
function validarUsuario(u) {
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(u || '')) throw new HttpError(400, 'Usuario inválido: use 3 a 40 letras, números, punto o guion.');
}
function crearSesion(usuarioId, res, req) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sesiones (token,usuarioId,expira) VALUES (?,?,?)').run(hashToken(token), usuarioId, Date.now() + SESION_HORAS * 3600e3);
  const seguro = esHttps(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESION_HORAS * 3600}${seguro}`);
}
function esHttps(req) { return req.headers['x-forwarded-proto'] === 'https' || !!req.socket.encrypted; }
function leerCookie(req, nombre) {
  const c = req.headers.cookie || '';
  for (const p of c.split(';')) { const [k, ...v] = p.trim().split('='); if (k === nombre) return v.join('='); }
  return null;
}
function usuarioDeSesion(req) {
  const t = leerCookie(req, 'sid');
  if (!t) return null;
  const s = db.prepare(`SELECT u.id,u.usuario,u.nombre,u.rol,u.activo,s.expira FROM sesiones s JOIN usuarios u ON u.id=s.usuarioId WHERE s.token=?`).get(hashToken(t));
  if (!s || !s.activo || s.expira < Date.now()) { if (s) db.prepare('DELETE FROM sesiones WHERE token=?').run(hashToken(t)); return null; }
  return { id: s.id, usuario: s.usuario, nombre: s.nombre, rol: s.rol };
}
setInterval(() => { try { db.prepare('DELETE FROM sesiones WHERE expira<?').run(Date.now()); } catch (_) {} }, 3600e3).unref();

// Limitador de intentos de acceso (por IP)
const intentos = new Map();
function ipDe(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function limiteLogin(ip) {
  const r = intentos.get(ip);
  if (r && r.bloqueadoHasta > Date.now()) throw new HttpError(429, 'Demasiados intentos. Espere unos minutos e intente de nuevo.');
}
function falloLogin(ip) {
  const r = intentos.get(ip) || { n: 0, bloqueadoHasta: 0 };
  r.n++; if (r.n >= 8) { r.bloqueadoHasta = Date.now() + 10 * 60e3; r.n = 0; }
  intentos.set(ip, r);
}

// ---------- Datos ----------
function cargarDatos() {
  return {
    empresa: cfgGet('empresa'), rif: cfgGet('rif'),
    tasas: db.prepare('SELECT id,fecha,tasa FROM tasas ORDER BY fecha,id').all(),
    cuentas: db.prepare('SELECT codigo,nombre,clasificacion FROM cuentas ORDER BY codigo').all(),
    productos: db.prepare('SELECT * FROM productos ORDER BY codigo').all(),
    movs: db.prepare('SELECT * FROM movs ORDER BY fecha,id').all(),
    registros: db.prepare('SELECT * FROM registros ORDER BY fecha,id').all(),
    presup: db.prepare('SELECT * FROM presup ORDER BY fecha,id').all()
  };
}
function puedeBorrar(user, fila) { return user.rol === 'Admin' || fila.creadoPor === user.usuario; }
function borrarPropio(tabla, id, user, etiqueta) {
  const f = db.prepare(`SELECT * FROM ${tabla} WHERE id=?`).get(id);
  if (!f) throw new HttpError(404, 'El registro no existe.');
  if (!puedeBorrar(user, f)) throw new HttpError(403, 'Solo puede eliminar lo que usted registró.');
  db.prepare(`DELETE FROM ${tabla} WHERE id=?`).run(id);
  auditar(user.usuario, 'Eliminar ' + etiqueta, '#' + id);
}
const cuentaExiste = c => !!db.prepare('SELECT 1 FROM cuentas WHERE codigo=?').get(c);
const productoExiste = c => !!db.prepare('SELECT 1 FROM productos WHERE codigo=?').get(c);

// ---------- Rutas ----------
const rutas = [];
const ruta = (metodo, patron, opts, fn) => rutas.push({ metodo, re: new RegExp('^' + patron.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), opts, fn });
const PUB = { auth: false }, USR = { auth: true }, ADM = { auth: true, admin: true };

ruta('GET', '/healthz', PUB, () => ({ ok: true }));
ruta('GET', '/api/estado', PUB, () => ({ inicializado: db.prepare('SELECT COUNT(*) n FROM usuarios').get().n > 0 }));
ruta('GET', '/api/me', USR, (c) => ({ usuario: c.user }));

ruta('POST', '/api/setup', PUB, (c) => {
  if (db.prepare('SELECT COUNT(*) n FROM usuarios').get().n > 0) throw new HttpError(403, 'El sistema ya fue configurado.');
  const { nombre, usuario, clave } = c.body;
  validarUsuario(usuario); validarClaveNueva(clave);
  if (!txt(nombre)) throw new HttpError(400, 'Indique el nombre completo.');
  const r = db.prepare('INSERT INTO usuarios (usuario,nombre,rol,activo,hash,creadoEn) VALUES (?,?,?,?,?,?)')
    .run(usuario, txt(nombre, 100), 'Admin', 1, hashClave(clave), ahora());
  auditar(usuario, 'Configuración inicial', 'Administrador creado');
  crearSesion(Number(r.lastInsertRowid), c.res, c.req);
  return { usuario: { id: Number(r.lastInsertRowid), usuario, nombre: txt(nombre, 100), rol: 'Admin' } };
});

ruta('POST', '/api/login', PUB, (c) => {
  const ip = ipDe(c.req); limiteLogin(ip);
  const { usuario, clave } = c.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE usuario=?').get(txt(usuario, 40));
  const ok = u && u.activo && verificarClave(String(clave ?? ''), u.hash);
  if (!u) crypto.scryptSync(String(clave ?? ''), 'x'.repeat(16), 64); // iguala tiempos
  if (!ok) { falloLogin(ip); auditar(txt(usuario, 40), 'Acceso fallido', ip); throw new HttpError(401, 'Usuario o contraseña incorrectos.'); }
  intentos.delete(ip);
  crearSesion(u.id, c.res, c.req);
  auditar(u.usuario, 'Ingreso', '');
  return { usuario: { id: u.id, usuario: u.usuario, nombre: u.nombre, rol: u.rol } };
});

ruta('POST', '/api/logout', PUB, (c) => {
  const t = leerCookie(c.req, 'sid');
  if (t) db.prepare('DELETE FROM sesiones WHERE token=?').run(hashToken(t));
  c.res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  return { ok: true };
});

ruta('GET', '/api/datos', USR, (c) => Object.assign(cargarDatos(), { usuario: c.user }));

ruta('DELETE', '/api/datos', ADM, (c) => {
  transaccion(() => {
    for (const t of ['movs', 'registros', 'presup', 'tasas', 'productos']) db.exec(`DELETE FROM ${t}`);
    db.exec('DELETE FROM cuentas'); sembrarCuentas();
  });
  auditar(c.user.usuario, 'Borrar datos operativos', '');
  return { ok: true };
});

ruta('PUT', '/api/empresa', ADM, (c) => {
  cfgSet('empresa', txt(c.body.empresa, 150)); cfgSet('rif', txt(c.body.rif, 30));
  auditar(c.user.usuario, 'Datos de empresa', txt(c.body.empresa, 150));
  return { ok: true };
});

ruta('POST', '/api/tasas', USR, (c) => {
  const { fecha, tasa } = c.body;
  if (!fechaOk(fecha) || !numPos(tasa)) throw new HttpError(400, 'Indique la fecha valor y una tasa mayor que cero.');
  const dup = db.prepare('SELECT id FROM tasas WHERE fecha=?').get(fecha);
  if (dup) {
    if (c.user.rol !== 'Admin') throw new HttpError(409, 'Ya existe una tasa para esa fecha. Solo el administrador puede reemplazarla.');
    db.prepare('UPDATE tasas SET tasa=?,creadoPor=? WHERE id=?').run(tasa, c.user.usuario, dup.id);
  } else db.prepare('INSERT INTO tasas (fecha,tasa,creadoPor) VALUES (?,?,?)').run(fecha, tasa, c.user.usuario);
  auditar(c.user.usuario, 'Tasa BCV', `${fecha} = ${tasa}`);
  return { ok: true };
});
ruta('DELETE', '/api/tasas/:id', ADM, (c) => {
  db.prepare('DELETE FROM tasas WHERE id=?').run(Number(c.params.id));
  auditar(c.user.usuario, 'Eliminar tasa', '#' + c.params.id); return { ok: true };
});

ruta('POST', '/api/cuentas', ADM, (c) => {
  const { codigo, nombre, clasificacion } = c.body;
  if (!Number.isInteger(codigo) || codigo <= 0 || !txt(nombre)) throw new HttpError(400, 'Indique código y nombre.');
  if (!CLASIFICACIONES.includes(clasificacion)) throw new HttpError(400, 'Clasificación inválida.');
  if (cuentaExiste(codigo)) throw new HttpError(409, 'Ya existe una cuenta con ese código.');
  db.prepare('INSERT INTO cuentas (codigo,nombre,clasificacion) VALUES (?,?,?)').run(codigo, txt(nombre, 120), clasificacion);
  auditar(c.user.usuario, 'Agregar cuenta', `${codigo} ${txt(nombre, 120)}`); return { ok: true };
});
ruta('DELETE', '/api/cuentas/:cod', ADM, (c) => {
  const cod = Number(c.params.cod);
  if (CUENTAS_BASE.some(x => x[0] === cod)) throw new HttpError(400, 'Las cuentas base no se pueden eliminar.');
  if (db.prepare('SELECT 1 FROM registros WHERE cuenta=?').get(cod)) throw new HttpError(409, 'La cuenta tiene registros asociados.');
  db.prepare('DELETE FROM cuentas WHERE codigo=?').run(cod);
  auditar(c.user.usuario, 'Eliminar cuenta', String(cod)); return { ok: true };
});

ruta('POST', '/api/productos', ADM, (c) => {
  const b = c.body, codigo = txt(b.codigo, 40), des = txt(b.descripcion, 150);
  if (!codigo || !des) throw new HttpError(400, 'Código y descripción son obligatorios.');
  if (!['PEPS', 'Promedio'].includes(b.metodo)) throw new HttpError(400, 'Método de valuación inválido.');
  if (!numNoNeg(b.minimo) || !numNoNeg(b.vnr)) throw new HttpError(400, 'Stock mínimo y precio deben ser números no negativos.');
  if (productoExiste(codigo)) throw new HttpError(409, 'Ya existe un producto con ese código.');
  db.prepare('INSERT INTO productos (codigo,descripcion,unidad,categoria,metodo,minimo,vnr) VALUES (?,?,?,?,?,?,?)')
    .run(codigo, des, txt(b.unidad, 30), txt(b.categoria, 60), b.metodo, b.minimo, b.vnr);
  auditar(c.user.usuario, 'Agregar producto', `${codigo} ${des}`); return { ok: true };
});
ruta('DELETE', '/api/productos/:cod', ADM, (c) => {
  const cod = decodeURIComponent(c.params.cod);
  if (db.prepare('SELECT 1 FROM movs WHERE codigo=?').get(cod) || db.prepare('SELECT 1 FROM presup WHERE codigo=?').get(cod))
    throw new HttpError(409, 'El producto tiene movimientos o presupuestos; elimínelos primero.');
  db.prepare('DELETE FROM productos WHERE codigo=?').run(cod);
  auditar(c.user.usuario, 'Eliminar producto', cod); return { ok: true };
});

ruta('POST', '/api/movimientos', USR, (c) => {
  const b = c.body;
  if (!fechaOk(b.fecha)) throw new HttpError(400, 'Fecha inválida.');
  if (!productoExiste(b.codigo)) throw new HttpError(400, 'Seleccione un producto válido.');
  if (!['Entrada', 'Salida'].includes(b.tipo)) throw new HttpError(400, 'Tipo inválido.');
  if (!['Bs', 'USD'].includes(b.moneda)) throw new HttpError(400, 'Moneda inválida.');
  if (!numPos(b.cantidad)) throw new HttpError(400, 'La cantidad debe ser mayor que cero.');
  if (b.tipo === 'Entrada' && !numPos(b.costo)) throw new HttpError(400, 'Indique el costo unitario de la entrada.');
  if (b.tasaManual != null && !numPos(b.tasaManual)) throw new HttpError(400, 'Tasa manual inválida.');
  if (b.tipo === 'Salida' && !numNoNeg(b.precio)) throw new HttpError(400, 'Precio de venta inválido.');
  db.prepare('INSERT INTO movs (fecha,codigo,tipo,cantidad,moneda,costo,tasaManual,precio,creadoPor) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(b.fecha, b.codigo, b.tipo, b.cantidad, b.moneda, b.tipo === 'Entrada' ? b.costo : 0, b.tasaManual ?? null, b.tipo === 'Salida' ? (b.precio || 0) : 0, c.user.usuario);
  auditar(c.user.usuario, 'Movimiento ' + b.tipo, `${b.codigo} x ${b.cantidad} (${b.fecha})`); return { ok: true };
});
ruta('DELETE', '/api/movimientos/:id', USR, (c) => { borrarPropio('movs', Number(c.params.id), c.user, 'movimiento'); return { ok: true }; });

ruta('POST', '/api/presupuesto', USR, (c) => {
  const b = c.body;
  if (!fechaOk(b.fecha)) throw new HttpError(400, 'Fecha inválida.');
  if (!productoExiste(b.codigo)) throw new HttpError(400, 'Seleccione un producto válido.');
  if (!numPos(b.unidades)) throw new HttpError(400, 'Las unidades presupuestadas deben ser mayores que cero.');
  if (!numNoNeg(b.precio ?? 0)) throw new HttpError(400, 'Precio inválido.');
  db.prepare('INSERT INTO presup (fecha,codigo,unidades,precio,creadoPor) VALUES (?,?,?,?,?)').run(b.fecha, b.codigo, b.unidades, b.precio || 0, c.user.usuario);
  auditar(c.user.usuario, 'Presupuesto', `${b.codigo} x ${b.unidades} (${b.fecha})`); return { ok: true };
});
ruta('DELETE', '/api/presupuesto/:id', USR, (c) => { borrarPropio('presup', Number(c.params.id), c.user, 'presupuesto'); return { ok: true }; });

ruta('POST', '/api/registros', USR, (c) => {
  const b = c.body;
  if (!fechaOk(b.fecha)) throw new HttpError(400, 'Fecha inválida.');
  if (!['Ingreso', 'Egreso'].includes(b.tipo)) throw new HttpError(400, 'Tipo inválido.');
  if (!cuentaExiste(b.cuenta)) throw new HttpError(400, 'Seleccione una cuenta válida.');
  if (!['Bs', 'USD'].includes(b.moneda)) throw new HttpError(400, 'Moneda inválida.');
  if (!numPos(b.monto)) throw new HttpError(400, 'El monto debe ser mayor que cero.');
  if (b.tasaManual != null && !numPos(b.tasaManual)) throw new HttpError(400, 'Tasa manual inválida.');
  db.prepare('INSERT INTO registros (fecha,tipo,cuenta,descripcion,tercero,documento,moneda,monto,tasaManual,creadoPor) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(b.fecha, b.tipo, b.cuenta, txt(b.descripcion, 200), txt(b.tercero, 120), txt(b.documento, 60), b.moneda, b.monto, b.tasaManual ?? null, c.user.usuario);
  auditar(c.user.usuario, b.tipo, `${b.cuenta} ${b.moneda} ${b.monto} (${b.fecha})`); return { ok: true };
});
ruta('DELETE', '/api/registros/:id', USR, (c) => { borrarPropio('registros', Number(c.params.id), c.user, 'registro'); return { ok: true }; });

// Usuarios
ruta('GET', '/api/usuarios', ADM, () => db.prepare('SELECT id,usuario,nombre,rol,activo,creadoEn FROM usuarios ORDER BY id').all());
ruta('POST', '/api/usuarios', ADM, (c) => {
  const { nombre, usuario, clave, rol } = c.body;
  validarUsuario(usuario); validarClaveNueva(clave);
  if (!txt(nombre)) throw new HttpError(400, 'Indique el nombre.');
  if (!['Admin', 'Usuario'].includes(rol)) throw new HttpError(400, 'Rol inválido.');
  if (db.prepare('SELECT 1 FROM usuarios WHERE usuario=?').get(usuario)) throw new HttpError(409, 'Ese usuario ya existe.');
  db.prepare('INSERT INTO usuarios (usuario,nombre,rol,activo,hash,creadoEn) VALUES (?,?,?,?,?,?)').run(usuario, txt(nombre, 100), rol, 1, hashClave(clave), ahora());
  auditar(c.user.usuario, 'Crear usuario', `${usuario} (${rol})`); return { ok: true };
});
ruta('PUT', '/api/usuarios/:id', ADM, (c) => {
  const id = Number(c.params.id), b = c.body;
  const u = db.prepare('SELECT * FROM usuarios WHERE id=?').get(id);
  if (!u) throw new HttpError(404, 'Usuario no encontrado.');
  const rol = b.rol ?? u.rol, activo = b.activo === undefined ? u.activo : (b.activo ? 1 : 0);
  if (!['Admin', 'Usuario'].includes(rol)) throw new HttpError(400, 'Rol inválido.');
  const pierdeAdmin = u.rol === 'Admin' && u.activo && (rol !== 'Admin' || !activo);
  if (pierdeAdmin && db.prepare("SELECT COUNT(*) n FROM usuarios WHERE rol='Admin' AND activo=1").get().n <= 1)
    throw new HttpError(400, 'Debe existir al menos un administrador activo.');
  if (id === c.user.id && !activo) throw new HttpError(400, 'No puede desactivar su propio usuario.');
  let hash = u.hash;
  if (b.clave) { validarClaveNueva(b.clave); hash = hashClave(b.clave); }
  transaccion(() => {
    db.prepare('UPDATE usuarios SET nombre=?,rol=?,activo=?,hash=? WHERE id=?').run(txt(b.nombre ?? u.nombre, 100), rol, activo, hash, id);
    if (!activo || b.clave) db.prepare('DELETE FROM sesiones WHERE usuarioId=?').run(id);
  });
  auditar(c.user.usuario, 'Actualizar usuario', u.usuario); return { ok: true };
});
ruta('POST', '/api/mi-clave', USR, (c) => {
  const u = db.prepare('SELECT * FROM usuarios WHERE id=?').get(c.user.id);
  if (!verificarClave(String(c.body.actual ?? ''), u.hash)) throw new HttpError(400, 'La contraseña actual no es correcta.');
  validarClaveNueva(c.body.nueva);
  db.prepare('UPDATE usuarios SET hash=? WHERE id=?').run(hashClave(c.body.nueva), u.id);
  auditar(u.usuario, 'Cambio de contraseña', ''); return { ok: true };
});

ruta('GET', '/api/auditoria', ADM, () => db.prepare('SELECT cuando,usuario,accion,detalle FROM auditoria ORDER BY id DESC LIMIT 500').all());

// Respaldo
ruta('GET', '/api/respaldo', ADM, (c) => {
  auditar(c.user.usuario, 'Descargar respaldo', '');
  return { __raw: true, data: Object.assign({ version: 1, generado: ahora() }, cargarDatos()) };
});
ruta('POST', '/api/respaldo', ADM, (c) => {
  const d = c.body;
  for (const k of ['tasas', 'cuentas', 'productos', 'movs', 'registros', 'presup'])
    if (!Array.isArray(d[k])) throw new HttpError(400, 'El archivo no es un respaldo válido.');
  transaccion(() => {
    for (const t of ['movs', 'registros', 'presup', 'tasas', 'productos', 'cuentas']) db.exec(`DELETE FROM ${t}`);
    sembrarCuentas();
    cfgSet('empresa', txt(d.empresa, 150)); cfgSet('rif', txt(d.rif, 30));
    const iCta = db.prepare('INSERT OR IGNORE INTO cuentas (codigo,nombre,clasificacion) VALUES (?,?,?)');
    for (const x of d.cuentas) if (Number.isInteger(x.codigo) && CLASIFICACIONES.includes(x.clasificacion)) iCta.run(x.codigo, txt(x.nombre, 120), x.clasificacion);
    const iT = db.prepare('INSERT INTO tasas (fecha,tasa,creadoPor) VALUES (?,?,?)');
    for (const x of d.tasas) if (fechaOk(x.fecha) && numPos(Number(x.tasa))) iT.run(x.fecha, Number(x.tasa), txt(x.creadoPor, 40));
    const iP = db.prepare('INSERT OR REPLACE INTO productos (codigo,descripcion,unidad,categoria,metodo,minimo,vnr) VALUES (?,?,?,?,?,?,?)');
    for (const x of d.productos) iP.run(txt(x.codigo, 40), txt(x.descripcion, 150), txt(x.unidad, 30), txt(x.categoria, 60), x.metodo === 'Promedio' ? 'Promedio' : 'PEPS', Number(x.minimo) || 0, Number(x.vnr) || 0);
    const iM = db.prepare('INSERT INTO movs (fecha,codigo,tipo,cantidad,moneda,costo,tasaManual,precio,creadoPor) VALUES (?,?,?,?,?,?,?,?,?)');
    for (const x of d.movs) if (fechaOk(x.fecha) && ['Entrada', 'Salida'].includes(x.tipo)) iM.run(x.fecha, txt(x.codigo, 40), x.tipo, Number(x.cantidad) || 0, x.moneda === 'USD' ? 'USD' : 'Bs', Number(x.costo) || 0, Number(x.tasaManual) > 0 ? Number(x.tasaManual) : null, Number(x.precio) || 0, txt(x.creadoPor, 40));
    const iR = db.prepare('INSERT INTO registros (fecha,tipo,cuenta,descripcion,tercero,documento,moneda,monto,tasaManual,creadoPor) VALUES (?,?,?,?,?,?,?,?,?,?)');
    for (const x of d.registros) if (fechaOk(x.fecha) && ['Ingreso', 'Egreso'].includes(x.tipo)) iR.run(x.fecha, x.tipo, Number(x.cuenta) || 0, txt(x.descripcion, 200), txt(x.tercero, 120), txt(x.documento, 60), x.moneda === 'USD' ? 'USD' : 'Bs', Number(x.monto) || 0, Number(x.tasaManual) > 0 ? Number(x.tasaManual) : null, txt(x.creadoPor, 40));
    const iV = db.prepare('INSERT INTO presup (fecha,codigo,unidades,precio,creadoPor) VALUES (?,?,?,?,?)');
    for (const x of d.presup) if (fechaOk(x.fecha)) iV.run(x.fecha, txt(x.codigo, 40), Number(x.unidades) || 0, Number(x.precio) || 0, txt(x.creadoPor, 40));
  });
  auditar(c.user.usuario, 'Restaurar respaldo', ''); return { ok: true };
});

// ---------- Servidor HTTP ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function cabecerasSeguridad(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");
}
function enviarJson(res, status, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(s);
}
function leerCuerpo(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const partes = [];
    req.on('data', ch => { n += ch.length; if (n > MAX_BODY) { reject(new HttpError(413, 'El archivo es demasiado grande.')); req.destroy(); } else partes.push(ch); });
    req.on('end', () => {
      if (!partes.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(partes).toString('utf8'))); } catch (_) { reject(new HttpError(400, 'JSON inválido.')); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  cabecerasSeguridad(res);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (p.startsWith('/api/') || p === '/healthz') {
      const r = rutas.find(x => x.metodo === req.method && x.re.test(p));
      if (!r) throw new HttpError(404, 'Ruta no encontrada.');
      const params = p.match(r.re).groups || {};
      let user = null;
      if (r.opts.auth) {
        user = usuarioDeSesion(req);
        if (!user) throw new HttpError(401, 'Sesión no válida.');
        if (r.opts.admin && user.rol !== 'Admin') throw new HttpError(403, 'Acción reservada al administrador.');
      }
      let body = {};
      if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const origin = req.headers.origin;
        if (origin) { // protección CSRF: el origen debe coincidir con el host
          let host; try { host = new URL(origin).host; } catch (_) { host = ''; }
          if (host !== req.headers.host) throw new HttpError(403, 'Origen no permitido.');
        }
        body = await leerCuerpo(req);
      }
      const out = r.fn({ req, res, body, params, user });
      if (out && out.__raw) {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="respaldo.json"', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify(out.data, null, 2));
      }
      return enviarJson(res, 200, out);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Método no permitido.');
    let f = p === '/' ? '/index.html' : p;
    const abs = path.normalize(path.join(PUBLIC_DIR, f));
    if (!abs.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(abs) || fs.statSync(abs).isDirectory()) throw new HttpError(404, 'No encontrado.');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(abs)] || 'application/octet-stream', 'Cache-Control': abs.endsWith('index.html') ? 'no-cache' : 'public, max-age=3600' });
    fs.createReadStream(abs).pipe(res);
  } catch (e) {
    if (e instanceof HttpError) return enviarJson(res, e.status, { error: e.message });
    console.error(e);
    enviarJson(res, 500, { error: 'Error interno del servidor.' });
  }
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => console.log(`Sistema contable escuchando en el puerto ${PORT} · datos en ${DATA_DIR}`));
  const cerrar = () => server.close(() => { try { db.close(); } catch (_) {} process.exit(0); });
  process.on('SIGTERM', cerrar); process.on('SIGINT', cerrar);
}
module.exports = { server };
