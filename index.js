const EXPIRY_SECONDS = 10 * 60;

function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function sign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

function hex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function makeToken(exp, secret) {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const payload = `${exp}.${nonce}`;
  const sig = hex(await sign(payload, secret));
  return `${exp}.${nonce}.${sig}`;
}

async function validToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [exp, nonce, sig] = parts;
  if (!/^\d+$/.test(exp) || !/^[a-f0-9]{32}$/i.test(nonce) || !/^[a-f0-9]{64}$/i.test(sig)) return false;
  const expiry = Number(exp);
  if (!Number.isSafeInteger(expiry) || Math.floor(Date.now() / 1000) >= expiry) return false;
  const expected = hex(await sign(`${exp}.${nonce}`, secret));
  const a = new TextEncoder().encode(sig.toLowerCase());
  const b = new TextEncoder().encode(expected);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function expiredPage() {
  return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invitation expired</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#111;color:#fff;font-family:system-ui,-apple-system,Segoe UI,sans-serif;text-align:center;padding:24px;box-sizing:border-box}main{max-width:420px}h1{font-size:30px;margin:0 0 12px}p{font-size:17px;line-height:1.5;opacity:.9}</style></head><body><main><h1>⏳ This invitation has expired</h1><p>The 10-minute invitation link is no longer active. ❤️</p></main></body></html>`, {status:410, headers:{'content-type':'text/html;charset=UTF-8','cache-control':'no-store'}});
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const secret = env.LINK_SECRET;
    if (!secret) return new Response('LINK_SECRET is not configured.', {status:500});

    if (url.pathname === '/new') {
      const exp = Math.floor(Date.now() / 1000) + EXPIRY_SECONDS;
      const token = await makeToken(exp, secret);
      const link = `${url.origin}/i/${token}`;
      return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Create invitation</title><style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:720px;margin:40px auto;padding:20px;line-height:1.5}input{width:100%;padding:14px;box-sizing:border-box;font-size:16px}button{margin-top:12px;padding:12px 18px;font-size:16px}small{color:#666}</style></head><body><h1>💕 10-minute invitation link</h1><p>Copy this link and send it on WhatsApp. It expires 10 minutes after this page generated it.</p><input id="link" value="${link.replace(/&/g,'&amp;').replace(/"/g,'&quot;')}" readonly><button onclick="navigator.clipboard.writeText(document.getElementById('link').value);this.textContent='Copied ✓'">Copy link</button><p><small>Each visit to /new creates a fresh 10-minute link.</small></p></body></html>`, {headers:{'content-type':'text/html;charset=UTF-8','cache-control':'no-store'}});
    }

    const match = url.pathname.match(/^\/i\/([^/]+)$/);
    if (match) {
      if (!(await validToken(match[1], secret))) return expiredPage();
      const assetRequest = new Request(new URL('/index.html', url), request);
      const response = await env.ASSETS.fetch(assetRequest);
      return new Response(response.body, response);
    }

    return new Response('Use /new to create a 10-minute invitation link.', {status:404});
  }
};
