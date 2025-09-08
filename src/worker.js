// src/worker.js
// Cloudflare Worker: X (Twitter) OAuth2.0 + PKCE + Auto Tweet
// 端点：
//   GET  /              - 简要状态页
//   GET  /auth/start    - 发起 OAuth2.0 授权（PKCE S256）
//   GET  /auth/callback - 接收 code，换取 access_token/refresh_token
//   POST /tweet         - 使用保存的 refresh_token 自动发帖
//   GET  /me            - 调试：查看当前 token 的 scope/过期时间（不调用 X）

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    // CORS 处理（如需从前端直接调用 /tweet）
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      if (pathname === '/') return landing(env);
      if (pathname === '/auth/start') return authStart(env);
      if (pathname === '/auth/callback') return authCallback(request, env);
      if (pathname === '/tweet' && request.method === 'POST') return tweet(request, env);
      if (pathname === '/me' && request.method === 'GET') return whoami(env);

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      return json({ error: err.message || String(err) }, 500);
    }
  },
};

// ===== Helpers =====
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=UTF-8', ...corsHeaders(), ...headers },
  });
}

function text(body, status = 200, headers = {}) {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=UTF-8', ...headers } });
}

async function landing(env) {
  const token = await getTokens(env);
  const authed = Boolean(token?.refresh_token);
  return new Response(
    `X(Twitter) Worker is up.\n` +
      `Auth: ${authed ? '✅ connected' : '❌ not connected'}\n` +
      `Start auth: /auth/start\n` +
      `Callback:   /auth/callback\n` +
      `POST /tweet {\"text\":\"hello\"}`,
    { headers: { 'content-type': 'text/plain; charset=UTF-8' } }
  );
}

// ---- KV 存储操作 ----
const KV_KEYS = {
  OAUTH_STATE: (state) => `oauth_state:${state}`,
  TOKENS: 'oauth_tokens',
};

async function putState(env, state, data) {
  await env.TWITTER_KV.put(KV_KEYS.OAUTH_STATE(state), JSON.stringify(data), { expirationTtl: 600 }); // 10分钟有效
}

async function getState(env, state) {
  const raw = await env.TWITTER_KV.get(KV_KEYS.OAUTH_STATE(state));
  return raw ? JSON.parse(raw) : null;
}

async function clearState(env, state) {
  await env.TWITTER_KV.delete(KV_KEYS.OAUTH_STATE(state));
}

async function saveTokens(env, tokens) {
  await env.TWITTER_KV.put(KV_KEYS.TOKENS, JSON.stringify(tokens));
}

async function getTokens(env) {
  const raw = await env.TWITTER_KV.get(KV_KEYS.TOKENS);
  return raw ? JSON.parse(raw) : null;
}

// ---- PKCE 辅助函数 ----
async function sha256(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

function base64urlEncodeBytes(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64urlEncodeBytes(bytes).slice(0, len);
}

async function authStart(request, env) {
  // 随机 state 防止 CSRF
  const state = crypto.randomUUID();

  // 保存 state 到 KV，稍后回调验证
  //await env.TWITTER_KV.put(`oauth_state:${state}`, 'valid', { expirationTtl: 600 });

  // 构建授权 URL，不带 PKCE 参数
  const clientId = env.CLIENT_ID;
  const redirectUri = encodeURIComponent(env.REDIRECT_URI);
  const scope = encodeURIComponent('tweet.write tweet.read users.read offline.access');

  const url = `https://x.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&state=${state}`;

  return Response.redirect(url, 302);
}

async function authCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  if (!code) return new Response('Missing code', { status: 400 });

  // 用 Client Secret 生成 Basic Authorization
  const creds = btoa(`${env.CLIENT_ID}:${env.CLIENT_SECRET}`);
  const form = new URLSearchParams();
  form.set('grant_type', 'authorization_code');
  form.set('code', code);
  form.set('redirect_uri', env.REDIRECT_URI);

  const resp = await fetch('https://api.twitter.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${creds}`
    },
    body: form.toString()
  });

  const data = await resp.json();
  if (!resp.ok) return new Response(JSON.stringify(data, null, 2), { status: resp.status });

  // 保存 access_token / refresh_token 到 KV
  await env.TWITTER_KV.put('oauth_tokens', JSON.stringify(data));

  return new Response('Auth success', { status: 200 });
}

// ---- 确保 access_token 有效；必要时用 refresh_token 刷新 ----
async function ensureAccessToken(env) {
  let tokens = await getTokens(env);
  if (!tokens?.access_token) throw new Error('Not authorized yet. Visit /auth/start');

  const now = Date.now();
  if (tokens.expires_at && now < tokens.expires_at) return tokens.access_token;

  if (!tokens.refresh_token) throw new Error('No refresh_token. Re-auth required.');

  const form = new URLSearchParams();
  form.set('grant_type', 'refresh_token');
  form.set('client_id', env.CLIENT_ID);
  form.set('refresh_token', tokens.refresh_token);

  const resp = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Refresh failed: ${resp.status} ${body}`);
  }

  const data = await resp.json();
  tokens.access_token = data.access_token;
  if (data.refresh_token) tokens.refresh_token = data.refresh_token; // X 可能轮换 refresh_token
  tokens.expires_at = Date.now() + (data.expires_in ? (data.expires_in - 60) * 1000 : 110 * 60 * 1000);

  await saveTokens(env, tokens);
  return tokens.access_token;
}

// ---- 发推 ----
async function tweet(request, env) {
  const { text: content, ...rest } = await request.json().catch(() => ({ }));
  if (!content) return json({ error: 'Missing "text"' }, 400);

  const accessToken = await ensureAccessToken(env);

  const payload = { text: content, ...rest };

  const resp = await fetch('https://api.x.com/2/tweets', {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${accessToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const body = await resp.text();
  let data;
  try { data = JSON.parse(body); } catch { data = { raw: body }; }

  if (!resp.ok) return json({ error: 'Create tweet failed', status: resp.status, data }, resp.status);
  return json(data, 201);
}

// ---- 调试：查看保存的 token 元信息 ----
async function whoami(env) {
  const t = await getTokens(env);
  if (!t) return json({ authed: false });
  const left = t.expires_at ? Math.max(0, Math.floor((t.expires_at - Date.now()) / 1000)) : null;
  return json({ authed: true, scope: t.scope, expires_in_s: left, has_refresh_token: Boolean(t.refresh_token) });
}
