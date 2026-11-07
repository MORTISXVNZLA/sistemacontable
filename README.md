# Sistema de Registro Contable · Bs / USD

Aplicación web (frontend + API) para kárdex PEPS / promedio ponderado, tasas BCV, presupuesto de ventas,
ingresos y egresos de caja/bancos, cierre diario, usuarios con roles, auditoría y respaldos.

- **Sin dependencias**: solo Node.js ≥ 22.13 (SQLite integrado). No hay `npm install`.
- **Datos**: archivo SQLite en `DATA_DIR` (por defecto `./data`). **Debe estar en un disco persistente.**
- **Seguridad**: contraseñas con scrypt, sesiones por cookie HttpOnly, bloqueo tras 8 intentos fallidos, protección CSRF por origen.

## Probar en local
```bash
npm start          # http://localhost:3000
npm test
```
En el primer ingreso el sistema pide crear el usuario **Administrador**.

## Subir a GitHub
```bash
git init && git add . && git commit -m "Sistema contable"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
git push -u origin main
```
Usa un repositorio **privado** (el código no contiene datos, pero es buena práctica).

## Desplegar (elige una opción)
> Importante: GitHub Pages **no sirve**, porque la app necesita servidor y base de datos.

**Render** (incluido `render.yaml`): New → Blueprint → elige el repo. Crea un disco de 1 GB en `/data` (requiere plan de pago).

**Railway**: New Project → Deploy from GitHub. Añade un *Volume* montado en `/data` y la variable `DATA_DIR=/data`.

**Fly.io / VPS con Docker**:
```bash
docker build -t contable .
docker run -d -p 3000:3000 -v contable_data:/data contable
```
Ponga HTTPS delante (Render/Railway/Fly ya lo incluyen).

## Variables de entorno
| Variable | Por defecto | Uso |
|---|---|---|
| `PORT` | 3000 | Puerto (lo asigna la plataforma) |
| `DATA_DIR` | `./data` | Carpeta de la base de datos |
| `SESSION_HOURS` | 12 | Duración de la sesión |

## Respaldos
Menú **Respaldo** (solo Admin): descargue el `.json` periódicamente. Sin disco persistente, los datos se pierden en cada despliegue.
