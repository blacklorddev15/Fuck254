const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_7qSEZpOcw2rm@ep-blue-mode-ansl4ioi-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(32) UNIQUE NOT NULL,
        username VARCHAR(80) UNIQUE,
        email VARCHAR(120),
        password_hash VARCHAR(255),
        firstname VARCHAR(64),
        lastname VARCHAR(64),
        balance NUMERIC(10, 2) DEFAULT 0.00,
        referral_code VARCHAR(32) UNIQUE,
        referred_by VARCHAR(32),
        registration_bonus_ksh NUMERIC(10, 2) DEFAULT 0.00,
        registration_bonus_granted BOOLEAN DEFAULT FALSE,
        registered_at TIMESTAMP,
        last_login_at TIMESTAMP,
        language VARCHAR(8) DEFAULT 'en',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        phone VARCHAR(32) NOT NULL,
        user_agent VARCHAR(500),
        ip_address VARCHAR(100),
        expires_at TIMESTAMP NOT NULL,
        revoked_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(32),
        action VARCHAR(64) NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS pairing_requests (
        id SERIAL PRIMARY KEY,
        request_id VARCHAR(64) UNIQUE NOT NULL,
        phone VARCHAR(32),
        whatsapp_phone VARCHAR(32) NOT NULL,
        server_id BIGINT,
        bot_type VARCHAR(64) DEFAULT 'blacklord',
        status VARCHAR(32) DEFAULT 'pending',
        pairing_code VARCHAR(64),
        pairing_expires_at TIMESTAMP,
        bot_session_id VARCHAR(255),
        message TEXT,
        linked_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS vouchers (
        id SERIAL PRIMARY KEY,
        code VARCHAR(64) UNIQUE NOT NULL,
        amount NUMERIC(10, 2) NOT NULL DEFAULT 10.00,
        is_used BOOLEAN DEFAULT FALSE,
        used_by VARCHAR(32),
        created_by VARCHAR(64),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query('ALTER TABLE pairing_requests ADD COLUMN IF NOT EXISTS linked_at TIMESTAMP');
    await client.query('CREATE INDEX IF NOT EXISTS pairing_requests_phone_status_idx ON pairing_requests (whatsapp_phone, status, created_at)');
  } finally {
    client.release();
  }
}

async function logActivity(phone, action, details) {
  try {
    await pool.query('INSERT INTO activity_logs (phone, action, details) VALUES ($1, $2, $3)', [phone, action, details]);
  } catch (e) {
    // ignore logging failure
  }
}

async function sendTelegramNotification(text) {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (token && chatId) {
      const axios = require('axios');
      await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, { chat_id: chatId, text }, { timeout: 5000 });
    }
  } catch (e) {
    // ignore
  }
}

module.exports = { pool, initDb, logActivity, sendTelegramNotification };
