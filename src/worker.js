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
      if (pathname === '/auth/start11') return authStart11(env);
      if (pathname === '/auth/callback') return authCallback(request, env);
      if (pathname === '/tweet' && request.method === 'POST') return tweet(request, env);
      if (pathname === '/me' && request.method === 'GET') return whoami(env);

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      return json({ error: err.message || String(err) }, 500);
    }
  },

  // 每小时自动发推：从另一个 KV 读取最新数据，取前5条构造推文
  async scheduled(event, env, ctx) {
    try {
      // 读取另一个 KV namespace 的 key
      const raw = await env.btcrank.get('api_data_latest-utxo');
      if (!raw) return;
      const obj = JSON.parse(raw);
      const arr = Array.isArray(obj.data) ? obj.data.slice(0, 5) : [];
      if (!arr.length) return;

      const accessToken = await ensureAccessToken(env);

      for (const item of arr) {
        let text = '';
        if (item.blockHeight) {
          text = `blockHeight：${item.blockHeight}`;
        } else {
          const [addr, val] = Object.entries(item)[0];
          text = `Address: ${addr} UTXO: ${val}`;
        }
        const payload = { text };
        await fetch('https://api.x.com/2/tweets', {
          method: 'POST',
          headers: {
            'authorization': `Bearer ${accessToken}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify(payload),
        });
      }
    } catch (err) {
    }
  },
};

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

async function saveTokens(env, tokens) {
  await env.TWITTER_KV.put(KV_KEYS.TOKENS, JSON.stringify(tokens));
}

async function getTokens(env) {
  const raw = await env.TWITTER_KV.get(KV_KEYS.TOKENS);
  return raw ? JSON.parse(raw) : null;
}

async function authStart11(env) {
  const state = randomString(32);
  const codeVerifier = randomString(64);
  const codeChallenge = base64urlEncodeBytes(await sha256(codeVerifier)); // S256


  await putState(env, state, { codeVerifier, createdAt: Date.now() });


  const authorize = new URL('https://x.com/i/oauth2/authorize');
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', env.CLIENT_ID);
  authorize.searchParams.set('redirect_uri', env.REDIRECT_URI);
  authorize.searchParams.set('scope', env.SCOPES || 'tweet.write tweet.read users.read offline.access');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', codeChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');


  return Response.redirect(authorize.toString(), 302);
}

async function authStart(env) {
  const state = crypto.randomUUID();
  await env.TWITTER_KV.put(`oauth_state:${state}`, 'valid', { expirationTtl: 600 });

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

async function whoami(env) {
  const t = await getTokens(env);
  if (!t) return json({ authed: false });
  const left = t.expires_at ? Math.max(0, Math.floor((t.expires_at - Date.now()) / 1000)) : null;
  return json({ authed: true, scope: t.scope, expires_in_s: left, has_refresh_token: Boolean(t.refresh_token) });
}
