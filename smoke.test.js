'use strict';
const os = require('node:os'), path = require('node:path'), fs = require('node:fs'), assert = require('node:assert');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'contable-'));
const { server } = require('../server.js');

(async () => {
  await new Promise(r => server.listen(0, r));
  const base = 'http://127.0.0.1:' + server.address().port;
  let cookie = '';
  const call = async (m, u, b) => {
    const r = await fetch(base + u, { method: m, headers: { 'Content-Type': 'application/json', cookie }, body: b === undefined ? undefined : JSON.stringify(b) });
    const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    let j = {}; try { j = await r.json(); } catch (_) {}
    return { s: r.status, j };
  };
  const ok = (r, s = 200) => assert.strictEqual(r.s, s, JSON.stringify(r.j));

  ok(await call('GET', '/healthz'));
  assert.strictEqual((await call('GET', '/api/estado')).j.inicializado, false);
  ok(await call('GET', '/api/datos'), 401);
  ok(await call('POST', '/api/setup', { nombre: 'Admin', usuario: 'Admin', clave: 'corta' }), 400);
  ok(await call('POST', '/api/setup', { nombre: 'Admin', usuario: 'Admin', clave: 'ClaveSegura1' }));
  ok(await call('POST', '/api/setup', { nombre: 'X', usuario: 'Otro', clave: 'ClaveSegura1' }), 403);
  let d = (await call('GET', '/api/datos')).j; assert.strictEqual(d.cuentas.length, 21);

  ok(await call('PUT', '/api/empresa', { empresa: 'Mi Empresa C.A.', rif: 'J-1' }));
  ok(await call('POST', '/api/tasas', { fecha: '2026-11-07', tasa: 40.5 }));
  ok(await call('POST', '/api/productos', { codigo: 'P-1', descripcion: 'Prod', unidad: 'U', categoria: 'G', metodo: 'PEPS', minimo: 1, vnr: 100 }));
  ok(await call('POST', '/api/movimientos', { fecha: '2026-11-07', codigo: 'P-1', tipo: 'Entrada', cantidad: 10, moneda: 'USD', costo: 2, tasaManual: null, precio: 0 }));
  ok(await call('POST', '/api/movimientos', { fecha: '2026-11-07', codigo: 'P-1', tipo: 'Salida', cantidad: 3, moneda: 'Bs', costo: 0, tasaManual: null, precio: 150 }));
  ok(await call('POST', '/api/presupuesto', { fecha: '2026-11-07', codigo: 'P-1', unidades: 5, precio: 0 }));
  ok(await call('POST', '/api/registros', { fecha: '2026-11-07', tipo: 'Ingreso', cuenta: 4102, descripcion: 'Serv', tercero: '', documento: '', moneda: 'USD', monto: 10, tasaManual: null }));
  ok(await call('POST', '/api/registros', { fecha: '2026-11-07', tipo: 'Ingreso', cuenta: 9999, moneda: 'Bs', monto: 10 }), 400);
  ok(await call('DELETE', '/api/productos/P-1'), 409);

  d = (await call('GET', '/api/datos')).j;
  assert.strictEqual(d.movs.length, 2); assert.strictEqual(d.empresa, 'Mi Empresa C.A.');

  // usuarios y permisos
  ok(await call('POST', '/api/usuarios', { nombre: 'Op', usuario: 'operador', clave: 'OtraClave123', rol: 'Usuario' }));
  ok(await call('POST', '/api/logout', {}));
  ok(await call('POST', '/api/login', { usuario: 'operador', clave: 'mala' }), 401);
  ok(await call('POST', '/api/login', { usuario: 'operador', clave: 'OtraClave123' }));
  ok(await call('GET', '/api/usuarios'), 403);
  ok(await call('POST', '/api/productos', { codigo: 'X', descripcion: 'x', metodo: 'PEPS', minimo: 0, vnr: 0 }), 403);
  ok(await call('DELETE', '/api/movimientos/' + d.movs[0].id), 403); // creado por Admin
  ok(await call('POST', '/api/movimientos', { fecha: '2026-11-07', codigo: 'P-1', tipo: 'Salida', cantidad: 1, moneda: 'Bs', precio: 150 }));
  const mine = (await call('GET', '/api/datos')).j.movs.find(m => m.creadoPor === 'operador');
  ok(await call('DELETE', '/api/movimientos/' + mine.id));

  // respaldo / restauración
  ok(await call('POST', '/api/login', { usuario: 'admin', clave: 'ClaveSegura1' }));
  const resp = await fetch(base + '/api/respaldo', { headers: { cookie } }); assert.strictEqual(resp.status, 200);
  const backup = await resp.json();
  ok(await call('DELETE', '/api/datos'));
  assert.strictEqual((await call('GET', '/api/datos')).j.movs.length, 0);
  ok(await call('POST', '/api/respaldo', backup));
  assert.strictEqual((await call('GET', '/api/datos')).j.movs.length, 2);

  // protección: no se puede quitar el último admin
  const me = (await call('GET', '/api/me')).j.usuario;
  ok(await call('PUT', '/api/usuarios/' + me.id, { rol: 'Usuario' }), 400);
  // CSRF
  const r = await fetch(base + '/api/tasas', { method: 'POST', headers: { 'Content-Type': 'application/json', cookie, Origin: 'https://evil.example' }, body: '{}' });
  assert.strictEqual(r.status, 403);
  // archivos estáticos y traversal
  assert.strictEqual((await fetch(base + '/')).status, 200);
  assert.strictEqual((await fetch(base + '/..%2fserver.js')).status, 404);
  console.log('OK: todas las pruebas pasaron');
  server.close(); process.exit(0);
})().catch(e => { console.error('FALLÓ:', e.message); process.exit(1); });
