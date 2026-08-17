const axios = require('axios');
const { pool, initDb } = require('./helpers/db');

function normalizePhone(value) {
  const raw = String(value || '').trim();
  if (!/^\+?[0-9\s-]+$/.test(raw)) return null;
  let phone = raw.replace(/\D/g, '');
  if (phone.startsWith('0')) phone = `254${phone.slice(1)}`;
  else if (phone.length === 9) phone = `254${phone}`;
  return /^254[17]\d{8}$/.test(phone) ? phone : null;
}

function normalizeLabel(value) {
  const label = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$/.test(label)) return null;
  return label;
}

function getConfig() {
  return {
    baseDomain: String(process.env.BLACKLORD_SUBDOMAIN_BASE || 'blacklord.tech').trim().toLowerCase(),
    zoneId: String(process.env.CLOUDFLARE_ZONE_ID || '').trim(),
    apiToken: String(process.env.CLOUDFLARE_API_TOKEN || '').trim(),
    target: String(process.env.BLACKLORD_SUBDOMAIN_TARGET || '').trim(),
    priceSd: Math.max(0, Number(process.env.BLACKLORD_SUBDOMAIN_PRICE_SD || 10))
  };
}

function configured(config) {
  return Boolean(config.zoneId && config.apiToken && config.target);
}

function hostname(label, config) {
  return `${label}.${config.baseDomain}`;
}

async function cloudflare(config, method, path, data) {
  const response = await axios({
    method,
    url: `https://api.cloudflare.com/client/v4${path}`,
    headers: { Authorization: `Bearer ${config.apiToken}`, 'Content-Type': 'application/json' },
    data,
    timeout: 15000
  });
  if (!response.data?.success) {
    const detail = response.data?.errors?.map(item => item.message).join(', ') || 'Cloudflare request failed';
    const error = new Error(detail);
    error.statusCode = 502;
    throw error;
  }
  return response.data.result;
}

module.exports = async function handler(req, res) {
  const method = String(req.method || 'GET').toUpperCase();
  const query = req.query || {};
  const body = req.body || {};
  const action = String(method === 'GET' ? (query.action || 'list') : (body.action || 'register')).toLowerCase();
  const config = getConfig();

  try {
    await initDb();
    const client = await pool.connect();
    try {
      if (action === 'availability') {
        const label = normalizeLabel(query.name);
        if (!label || label.length < 3) return res.status(400).json({ success: false, error: 'Use 3–63 lowercase letters, numbers, or hyphens.' });
        const existing = await client.query("SELECT 1 FROM subdomains WHERE label = $1 AND status = 'active' LIMIT 1", [label]);
        return res.status(200).json({ success: true, name: label, hostname: hostname(label, config), available: existing.rowCount === 0, configured: configured(config) });
      }

      const phone = normalizePhone(method === 'GET' ? query.phone : body.phone);
      if (!phone) return res.status(400).json({ success: false, error: 'Enter a valid Kenyan phone number.' });

      if (action === 'list') {
        const result = await client.query('SELECT id, label, hostname, target, price_sd, status, expires_at, created_at FROM subdomains WHERE phone = $1 ORDER BY created_at DESC', [phone]);
        return res.status(200).json({ success: true, configured: configured(config), baseDomain: config.baseDomain, priceSd: config.priceSd, domains: result.rows });
      }

      if (!configured(config)) return res.status(503).json({ success: false, error: 'Domain marketplace is not configured. Add CLOUDFLARE_ZONE_ID, CLOUDFLARE_API_TOKEN, and BLACKLORD_SUBDOMAIN_TARGET in Vercel.' });

      const userRes = await client.query('SELECT phone, balance, registered_at FROM users WHERE phone = $1', [phone]);
      const user = userRes.rows[0];
      if (!user?.registered_at) return res.status(403).json({ success: false, error: 'Register before using the domain marketplace.', requiresRegistration: true });

      if (action === 'register') {
        const label = normalizeLabel(body.name);
        if (!label || label.length < 3) return res.status(400).json({ success: false, error: 'Use 3–63 lowercase letters, numbers, or hyphens.' });
        if (Number(user.balance || 0) < config.priceSd) return res.status(402).json({ success: false, error: `You need ${config.priceSd} SD to register this subdomain.` });
        const duplicate = await client.query("SELECT 1 FROM subdomains WHERE label = $1 AND status = 'active' LIMIT 1", [label]);
        if (duplicate.rowCount) return res.status(409).json({ success: false, error: 'That subdomain is already taken.' });
        const host = hostname(label, config);
        const record = await cloudflare(config, 'POST', `/zones/${encodeURIComponent(config.zoneId)}/dns_records`, { type: 'CNAME', name: host, content: config.target, ttl: 1, proxied: false, comment: 'Blacklord Tech Inc customer subdomain' });
        try {
          await client.query('BEGIN');
          await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [config.priceSd, phone]);
          const result = await client.query("INSERT INTO subdomains (phone, label, hostname, target, cloudflare_record_id, price_sd, status, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days') RETURNING id, label, hostname, target, price_sd, status, expires_at, created_at", [phone, label, host, config.target, record.id, config.priceSd]);
          await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['SUBDOMAIN_PURCHASE', `${host} registered for ${phone}.`]);
          await client.query('COMMIT');
          return res.status(201).json({ success: true, domain: result.rows[0], message: `${host} is now active.` });
        } catch (error) {
          try { await client.query('ROLLBACK'); } catch (_) {}
          try { await cloudflare(config, 'DELETE', `/zones/${encodeURIComponent(config.zoneId)}/dns_records/${encodeURIComponent(record.id)}`); } catch (_) {}
          throw error;
        }
      }

      if (action === 'delete') {
        const id = Number(body.id);
        if (!Number.isInteger(id)) return res.status(400).json({ success: false, error: 'A valid domain ID is required.' });
        const result = await client.query("SELECT * FROM subdomains WHERE id = $1 AND phone = $2 AND status = 'active'", [id, phone]);
        const domain = result.rows[0];
        if (!domain) return res.status(404).json({ success: false, error: 'Active subdomain not found.' });
        if (domain.cloudflare_record_id) await cloudflare(config, 'DELETE', `/zones/${encodeURIComponent(config.zoneId)}/dns_records/${encodeURIComponent(domain.cloudflare_record_id)}`);
        await client.query("UPDATE subdomains SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = $1", [id]);
        return res.status(200).json({ success: true, message: `${domain.hostname} was deleted.` });
      }

      return res.status(400).json({ success: false, error: 'Unsupported domain action.' });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Domain API error:', error);
    return res.status(error.statusCode || 500).json({ success: false, error: error.message || 'Domain request failed.' });
  }
};

module.exports.normalizePhone = normalizePhone;
module.exports.normalizeLabel = normalizeLabel;

// End of file
