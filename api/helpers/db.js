const { Pool } = require('pg');

let pool;
const dbUrl = process.env.DATABASE_URL;
if (dbUrl) {
  pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false }
  });
} else {
  console.warn('DATABASE_URL is not set. Database operations will fail.');
}

async function initDb() {
  if (!pool) return;
  const client = await pool.connect();
  try {
    // Basic setup
    await client.query(`
      CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
      CREATE TABLE IF NOT EXISTS users (
        phone TEXT PRIMARY KEY,
        username TEXT,
        balance NUMERIC DEFAULT 0,
        referred_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS pairing_requests (
        id SERIAL PRIMARY KEY,
        request_id TEXT UNIQUE NOT NULL,
        phone TEXT,
        whatsapp_phone TEXT NOT NULL,
        server_id INTEGER,
        status TEXT NOT NULL DEFAULT 'pending',
        pairing_code TEXT,
        pairing_expires_at TIMESTAMP,
        bot_session_id TEXT,
        bot_type TEXT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        action TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        used_number TEXT,
        used_by TEXT,
        used_at TIMESTAMP,
        expires_at TIMESTAMP,
        issued_for TEXT DEFAULT 'telegram',
        telegram_user TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS subdomains (
        id SERIAL PRIMARY KEY,
        phone TEXT NOT NULL,
        label TEXT NOT NULL,
        hostname TEXT NOT NULL UNIQUE,
        target TEXT NOT NULL,
        cloudflare_record_id TEXT,
        price_sd NUMERIC NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Add columns one by one to avoid total failure if one exists
    const columns = [
      ['users', 'firstname', 'TEXT'],
      ['users', 'lastname', 'TEXT'],
      ['users', 'email', 'TEXT'],
      ['users', 'password_hash', 'TEXT'],
      ['users', 'last_login_at', 'TIMESTAMP'],
      ['users', 'referral_code', 'TEXT'],
      ['users', 'reseller_tier', "TEXT DEFAULT 'standard'"],
      ['pairing_requests', 'bot_type', 'TEXT'],
      ['keys', 'type', 'TEXT'],
      ['keys', 'used_number', 'TEXT'],
      ['keys', 'used_by', 'TEXT'],
      ['keys', 'used_at', 'TIMESTAMP'],
      ['keys', 'expires_at', 'TIMESTAMP'],
      ['keys', 'issued_for', "TEXT DEFAULT 'telegram'"],
      ['keys', 'telegram_user', 'TEXT'],
      ['keys', 'created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'],
      ['subdomains', 'phone', 'TEXT'],
      ['subdomains', 'label', 'TEXT'],
      ['subdomains', 'hostname', 'TEXT'],
      ['subdomains', 'target', 'TEXT'],
      ['subdomains', 'cloudflare_record_id', 'TEXT'],
      ['subdomains', 'price_sd', 'NUMERIC DEFAULT 0'],
      ['subdomains', 'status', "TEXT DEFAULT 'active'"],
      ['subdomains', 'expires_at', 'TIMESTAMP'],
      ['subdomains', 'created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'],
      ['subdomains', 'updated_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP']
    ];
    for (const [table, col, type] of columns) {
      try {
        await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${col} ${type}`);
      } catch (e) {
        // Ignore errors for existing columns
      }
    }
  } finally {
    client.release();
  }
}

async function logActivity(action, details) {
  try {
    if (!pool) return;
    await pool.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', [action, details]);
  } catch (e) {
    console.error('Log Activity Error:', e);
  }
}

async function sendTelegramNotification(message) {
  // Placeholder for Telegram notifications
  console.log('Telegram Notification:', message);
}

module.exports = {
  query: (text, params) => {
    if (!pool) throw new Error('DATABASE_URL is not configured');
    return pool.query(text, params);
  },
  initDb,
  logActivity,
  sendTelegramNotification,
  pool // Export pool directly so destructuring works
};
