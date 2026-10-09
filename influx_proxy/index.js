// influx_proxy/index.js
// Proxy inverso transparente y seguro para InfluxDB v2 en dashboards y presentaciones web.
// Habilita soporte de iframes cross-domain (SameSite=None, Secure, Partitioned) y
// mantiene sesión activa para renderizado sin fricciones en modo interactivo de solo lectura.

const http = require('http');

const INFLUX_HOST = process.env.INFLUX_HOST || 'influxdb';
const INFLUX_PORT = parseInt(process.env.INFLUX_PORT || '8086', 10);
const PROXY_PORT = parseInt(process.env.PROXY_PORT || '8085', 10);

const adminUser = process.env.INFLUXDB_ADMIN_USER || 'admin';
const adminPass = process.env.INFLUXDB_ADMIN_PASSWORD || 'haizelab2024seguro';
const adminToken = process.env.INFLUXDB_ADMIN_TOKEN || '';
const readToken = process.env.INFLUXDB_READ_TOKEN || '';

let cachedSessionCookie = '';
let lastCookieFetch = 0;

// Renovar y cachear sesión activa con InfluxDB
function refrescarSesionAdmin() {
  const authHeader = 'Basic ' + Buffer.from(`${adminUser}:${adminPass}`).toString('base64');
  const req = http.request({
    hostname: INFLUX_HOST,
    port: INFLUX_PORT,
    path: '/api/v2/signin',
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'Content-Length': '0'
    }
  }, (res) => {
    const cookies = res.headers['set-cookie'];
    if (cookies) {
      for (const c of cookies) {
        if (c.includes('influxdb-oss-session=')) {
          const match = c.match(/influxdb-oss-session=([^;]+)/);
          if (match) {
            cachedSessionCookie = match[1];
            lastCookieFetch = Date.now();
            console.log('[InfluxProxy] Sesion InfluxDB renovada con exito.');
          }
        }
      }
    }
  });
  req.on('error', (e) => console.error('[InfluxProxy] Error renovando sesion InfluxDB:', e.message));
  req.end();
}

// Inicializar sesión y programar renovación periódica cada 30 minutos
refrescarSesionAdmin();
setInterval(refrescarSesionAdmin, 30 * 60 * 1000);

// Rutas administrativas que alteran o borran configuraciones críticas
const RUTAS_ADMIN_PROHIBIDAS = [
  '/api/v2/setup',
  '/api/v2/delete',
  '/api/v2/authorizations',
  '/api/v2/users'
];

const server = http.createServer((req, res) => {
  const method = (req.method || 'GET').toUpperCase();
  const urlPath = req.url ? req.url.split('?')[0] : '/';

  // 1. Bloqueo estricto de métodos destructivos
  if (method === 'DELETE' || method === 'PUT' || method === 'PATCH') {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Operacion no permitida por politica de seguridad.' }));
    return;
  }

  // 2. Bloqueo de rutas de administración y borrado
  const esRutaAdmin = RUTAS_ADMIN_PROHIBIDAS.some(p => urlPath.startsWith(p));
  if (esRutaAdmin && method !== 'GET') {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Acceso denegado a rutas administrativas.' }));
    return;
  }

  // 3. Control de métodos POST: solo se permite consultar datos (/api/v2/query) y autenticar (/api/v2/signin)
  if (method === 'POST') {
    const esPostPermitido = urlPath.startsWith('/api/v2/query') || urlPath.startsWith('/api/v2/signin');
    if (!esPostPermitido) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Escritura no permitida en entorno interactivo.' }));
      return;
    }
  }

  const clientCookies = req.headers['cookie'] || '';
  const tieneSesionCookie = clientCookies.includes('influxdb-oss-session=');
  const headers = { ...req.headers };
  headers.host = `${INFLUX_HOST}:${INFLUX_PORT}`;

  // 4. Inyección de autenticación si el navegador no envía cookie (bloqueo Third-Party Cookies en iframes)
  if (req.url.startsWith('/api/v2/')) {
    if (!tieneSesionCookie && !headers['authorization']) {
      if (cachedSessionCookie) {
        headers['cookie'] = clientCookies
          ? `${clientCookies}; influxdb-oss-session=${cachedSessionCookie}`
          : `influxdb-oss-session=${cachedSessionCookie}`;
      } else if (adminToken) {
        headers['authorization'] = `Token ${adminToken}`;
      } else if (readToken && urlPath.startsWith('/api/v2/query')) {
        headers['authorization'] = `Token ${readToken}`;
      }
    }
  }

  const proxyReq = http.request({
    hostname: INFLUX_HOST,
    port: INFLUX_PORT,
    path: req.url,
    method: req.method,
    headers: headers
  }, (proxyRes) => {
    const resHeaders = { ...proxyRes.headers };

    // Sanitización de cabeceras para permitir incrustación en iframes cross-domain
    delete resHeaders['x-frame-options'];
    resHeaders['x-content-type-options'] = 'nosniff';
    resHeaders['access-control-allow-origin'] = '*';
    resHeaders['access-control-allow-credentials'] = 'true';

    // Reescribir cookies para soporte en iframes cross-site modernos (CHIPS Partitioned)
    if (resHeaders['set-cookie']) {
      resHeaders['set-cookie'] = resHeaders['set-cookie'].map((c) => {
        let mod = c.replace(/SameSite=(Strict|Lax)/gi, 'SameSite=None');
        if (!mod.includes('SameSite=')) mod += '; SameSite=None';
        if (!mod.includes('Secure')) mod += '; Secure';
        if (!mod.includes('Partitioned')) mod += '; Partitioned';
        mod = mod.replace(/Path=\/api\//gi, 'Path=/');
        return mod;
      });
    }

    // Auto-login: inyectar cookie de sesión activa si accede a páginas HTML sin sesión previa
    const isHtmlRoute = req.url === '/' || req.url.startsWith('/signin') || req.url.startsWith('/orgs');
    if (isHtmlRoute && !tieneSesionCookie && cachedSessionCookie) {
      const autoCookie = `influxdb-oss-session=${cachedSessionCookie}; Path=/; SameSite=None; Secure; Partitioned; Max-Age=2592000; HttpOnly`;
      if (resHeaders['set-cookie']) {
        if (!resHeaders['set-cookie'].some(c => c.includes('influxdb-oss-session='))) {
          resHeaders['set-cookie'].push(autoCookie);
        }
      } else {
        resHeaders['set-cookie'] = [autoCookie];
      }
    }

    res.writeHead(proxyRes.statusCode, resHeaders);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[InfluxProxy] Error en peticion:', err.message);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Servicio InfluxDB no disponible temporalmente.' }));
  });

  req.pipe(proxyReq);
});

server.listen(PROXY_PORT, '0.0.0.0', () => {
  console.log(`[InfluxProxy Seguro] Escuchando en 0.0.0.0:${PROXY_PORT} -> http://${INFLUX_HOST}:${INFLUX_PORT}`);
});
