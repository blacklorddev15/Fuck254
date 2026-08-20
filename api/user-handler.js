const axios = require('axios');
const crypto = require('crypto');
const { promisify } = require('util');
const { pool, initDb, logActivity, sendTelegramNotification } = require('./helpers/db');
const scryptAsync = promisify(crypto.scrypt);

function normalizeKenyanPhone(value) {
  const raw = String(value || '').trim();
  if (!/^\+?[0-9\s-]+$/.test(raw)) return null;
  let phone = raw.replace(/\D/g, '');
  if (phone.startsWith('0')) phone = `254${phone.slice(1)}`;
  else if (phone.length === 9) phone = `254${phone}`;
  if (!/^254[17]\d{8}$/.test(phone)) return null;
  return phone;
}

function makeCourtneyReference(phone) {
  return `TP${phone.slice(-6)}${Date.now().toString().slice(-4)}`.slice(0, 12);
}

function makeCourtneyDescription(amountSD) {
  return `Topup ${amountSD}`.replace(/[^A-Za-z0-9 ]/g, '').slice(0, 13) || 'Wallet topup';
}

function getCourtneyConfig(dbSettings) {
  const apiKey = process.env.COURTNEY_API_KEY || dbSettings.COURTNEY_API_KEY;
  const apiSecret = process.env.COURTNEY_API_SECRET || dbSettings.COURTNEY_API_SECRET;
  const accountId = Number(process.env.COURTNEY_ACCOUNT_ID || dbSettings.COURTNEY_ACCOUNT_ID);
  const baseUrl = (process.env.COURTNEY_BASE_URL || dbSettings.COURTNEY_BASE_URL || 'https://courtneytech.xyz/api').replace(/\/$/, '');
  if (!apiKey || !apiSecret || !Number.isInteger(accountId) || accountId <= 0) {
    const error = new Error('Courtney Tech is not configured. Set COURTNEY_API_KEY, COURTNEY_API_SECRET, and COURTNEY_ACCOUNT_ID.');
    error.statusCode = 503;
    throw error;
  }
  return { apiKey, apiSecret, accountId, baseUrl };
}

function courtneyHeaders(config) {
  return {
    'X-API-Key': config.apiKey,
    'X-API-Secret': config.apiSecret,
    'Content-Type': 'application/json'
  };
}

function makeBlacklordReference(phone) {
  return `blacklord-${phone.slice(-6)}-${Date.now().toString().slice(-6)}`;
}

function getBlacklordConfig(dbSettings, headers = {}) {
  const baseUrl = (process.env.BLACKLORD_STK_BASE_URL || dbSettings.BLACKLORD_STK_BASE_URL || '').replace(/\/$/, '');
  const apiKey = process.env.BLACKLORD_STK_API_KEY || dbSettings.BLACKLORD_STK_API_KEY;
  const apiSecret = process.env.BLACKLORD_STK_API_SECRET || dbSettings.BLACKLORD_STK_API_SECRET || '';
  const initiatePath = process.env.BLACKLORD_STK_INITIATE_PATH || dbSettings.BLACKLORD_STK_INITIATE_PATH || '/v2/stkpush';
  const statusPath = process.env.BLACKLORD_STK_STATUS_PATH || dbSettings.BLACKLORD_STK_STATUS_PATH || '/v2/status';
  const callbackUrl = process.env.BLACKLORD_STK_CALLBACK_URL || dbSettings.BLACKLORD_STK_CALLBACK_URL || `${process.env.PUBLIC_APP_URL || (headers.host ? `https://${headers.host}` : '')}/api/user/callback`;
  if (!baseUrl || !apiKey) {
    const error = new Error('Blacklord STK is not configured. Set BLACKLORD_STK_BASE_URL and BLACKLORD_STK_API_KEY.');
    error.statusCode = 503;
    throw error;
  }
  return { baseUrl, apiKey, apiSecret, initiatePath, statusPath, callbackUrl };
}

function blacklordHeaders(config) {
  const headers = {
    Authorization: `Bearer ${config.apiKey}`,
    'X-API-Key': config.apiKey,
    'Content-Type': 'application/json'
  };
  if (config.apiSecret) headers['X-API-Secret'] = config.apiSecret;
  return headers;
}

function providerStatus(payload = {}) {
  const nested = payload.data || payload.result || payload.Body?.stkCallback || {};
  const rawStatus = payload.status || payload.payment_status || payload.paymentStatus || nested.status || nested.payment_status || (Number(payload.resultCode ?? nested.ResultCode) === 0 ? 'completed' : '');
  const normalized = String(rawStatus || 'pending').toLowerCase();
  const transactionId = payload.transactionId || payload.transaction_id || payload.receipt || payload.mpesaReceipt || payload.mpesa_receipt || nested.MpesaReceiptNumber || nested.mpesaReceipt || null;
  return { status: normalized === 'paid' || normalized === 'success' || normalized === 'succeeded' ? 'completed' : normalized, transactionId };
}

function makeFeatureReference(prefix) {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
}

function normalizeLanguage(value) {
  const language = String(value || 'en').toLowerCase();
  return ['en', 'sw'].includes(language) ? language : null;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, encoded) {
  try {
    const [scheme, nValue, rValue, pValue, salt, storedHex] = String(encoded || '').split('$');
    if (scheme !== 'scrypt' || !salt || !storedHex) return false;
    const stored = Buffer.from(storedHex, 'hex');
    const derivedKey = await scryptAsync(password, salt, stored.length, { N: Number(nValue), r: Number(rValue), p: Number(pValue), maxmem: 64 * 1024 * 1024 });
    return stored.length === derivedKey.length && crypto.timingSafeEqual(stored, derivedKey);
  } catch (error) {
    return false;
  }
}

function sessionTokenFromRequest(req) {
  const cookieHeader = req.headers?.cookie || req.headers?.Cookie || '';
  const cookieMatch = String(cookieHeader).match(/(?:^|;\s*)blacklord_session=([^;]+)/);
  if (cookieMatch) return decodeURIComponent(cookieMatch[1]);
  const authorization = req.headers?.authorization || req.headers?.Authorization || '';
  if (String(authorization).startsWith('Bearer ')) return String(authorization).slice(7).trim();
  return null;
}

function sessionTokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

async function issueSession(client, phone, req) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = sessionTokenHash(token);
  await client.query('DELETE FROM user_sessions WHERE phone = $1 AND (expires_at <= CURRENT_TIMESTAMP OR revoked_at IS NOT NULL)', [phone]);
  await client.query("INSERT INTO user_sessions (token_hash, phone, expires_at, user_agent, ip_address) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '30 days', $3, $4)", [tokenHash, phone, String(req.headers?.['user-agent'] || '').slice(0, 500), String(req.headers?.['x-forwarded-for'] || '').split(',')[0].trim().slice(0, 100)]);
  return token;
}

async function sessionUser(client, req) {
  const token = sessionTokenFromRequest(req);
  if (!token) return null;
  const result = await client.query(`SELECT u.phone, u.username, u.email, u.balance, u.referral_code, u.registered_at, u.registration_bonus_granted, u.language
    FROM user_sessions s JOIN users u ON u.phone = s.phone
    WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP LIMIT 1`, [sessionTokenHash(token)]);
  return result.rows[0] || null;
}

function setSessionCookie(res, token) {
  if (typeof res.setHeader === 'function') res.setHeader('Set-Cookie', `blacklord_session=${encodeURIComponent(token)}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearSessionCookie(res) {
  if (typeof res.setHeader === 'function') res.setHeader('Set-Cookie', 'blacklord_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax');
}

function publicUser(user) {
  if (!user) return null;
  return { phone: user.phone, username: user.username, email: user.email, balance: user.balance, referral_code: user.referral_code, registered_at: user.registered_at, registration_bonus_granted: user.registration_bonus_granted, language: user.language || 'en' };
}

function getPairingConfig() {
  return {
    panelUrl: (process.env.PTERODACTYL_PANEL_URL || process.env.PANEL_DOMAIN || '').replace(/\/$/, ''),
    clientApiKey: process.env.PTERODACTYL_CLIENT_API_KEY || '',
    serverIdentifier: process.env.PTERODACTYL_SERVER_IDENTIFIER || '',
    botEndpoint: (process.env.BOT_PAIRING_ENDPOINT || '').replace(/\/$/, ''),
    botSecret: process.env.BOT_PAIRING_SECRET || process.env.PAIRING_WEBHOOK_SECRET || '',
    webhookSecret: process.env.PAIRING_WEBHOOK_SECRET || process.env.BOT_PAIRING_SECRET || ''
  };
}

function pairingRequestId() {
  return `PAIR-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
}

function activationKey(botType) {
  const prefix = String(botType || 'blacklord').replace(/[^a-z0-9]/gi, '').slice(0, 8).toUpperCase() || 'BLACKLORD';
  return `BL-${prefix}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

function normalizeKeyType(value) {
  const type = String(value || 'blacklord').trim().toLowerCase();
  return ['blacklord', 'samsung', 'talkless', 'skylar', 'rita'].includes(type) ? type : null;
}

function normalizePairingStatus(value) {
  const status = String(value || 'pending').toLowerCase();
  return ['pending', 'processing', 'waiting', 'paired', 'connected', 'completed', 'failed', 'expired', 'cancelled'].includes(status) ? status : 'pending';
}

function secretMatches(supplied, expected) {
  const left = Buffer.from(String(supplied || ''));
  const right = Buffer.from(String(expected || ''));
  return Boolean(left.length && right.length && left.length === right.length && crypto.timingSafeEqual(left, right));
}

async function getPterodactylResourceStatus(config) {
  if (!config.panelUrl || !config.clientApiKey || !config.serverIdentifier) {
    return { configured: false, status: 'unconfigured', message: 'Add PTERODACTYL_PANEL_URL, PTERODACTYL_CLIENT_API_KEY, and PTERODACTYL_SERVER_IDENTIFIER in the staging project.' };
  }
  try {
    const response = await axios.get(`${config.panelUrl}/api/client/servers/${encodeURIComponent(config.serverIdentifier)}/resources`, {
      headers: { Authorization: `Bearer ${config.clientApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json' },
      timeout: 10000
    });
    const attributes = response.data?.attributes || {};
    return { configured: true, status: attributes.current_state || 'unknown', resources: attributes.resources || null };
  } catch (error) {
    return { configured: true, status: 'unreachable', message: error.response?.data?.errors?.[0]?.detail || error.message };
  }
}

async function dispatchPairingRequest(config, payload) {
  if (!config.botEndpoint) {
    const error = new Error('The bot pairing bridge is not configured. Add BOT_PAIRING_ENDPOINT in the staging project.');
    error.statusCode = 503;
    throw error;
  }
  const headers = { 'Content-Type': 'application/json' };
  if (config.botSecret) headers['X-Blacklord-Pairing-Secret'] = config.botSecret;
  const bridgeTimeout = Math.min(5000, Math.max(1000, Number(process.env.PAIRING_BRIDGE_TIMEOUT_MS || 2500)));
  const response = await axios.post(config.botEndpoint, payload, { headers, timeout: bridgeTimeout });
  return response.data || {};
}

async function creditDeposit(client, deposit, mpesaReceipt) {
  if (!deposit) return false;
  await client.query('BEGIN');
  try {
    const claim = await client.query(
      'UPDATE deposits SET status = $1 WHERE reference = $2 AND status <> $1 RETURNING *',
      ['success', deposit.reference]
    );
    if (claim.rowCount === 0) {
      await client.query('ROLLBACK');
      return false;
    }
    const creditedDeposit = claim.rows[0];
    const userRes = await client.query('SELECT * FROM users WHERE phone = $1 FOR UPDATE', [creditedDeposit.phone]);
    const user = userRes.rows[0];
    const uname = creditedDeposit.username || user?.username || `user_${creditedDeposit.phone.slice(-4)}`;
    const email = `${creditedDeposit.phone.replace(/\D/g, '')}@blacklord.tech`;
    const resellerPercent = Math.max(0, Number(user?.reseller_bonus_percent || 0));
    const resellerBonus = user ? Math.round(Number(creditedDeposit.amount_sd || 0) * resellerPercent) / 100 : 0;
    if (user) {
      await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1, total_topup_sd = COALESCE(total_topup_sd, 0) + $2 WHERE phone = $3', [Number(creditedDeposit.amount_sd || 0) + resellerBonus, creditedDeposit.amount_sd, creditedDeposit.phone]);
      if (creditedDeposit.username) {
        await client.query('UPDATE users SET username = $1 WHERE phone = $2', [creditedDeposit.username, creditedDeposit.phone]);
      }
    } else {
      await client.query(
        'INSERT INTO users (firstname, lastname, email, phone, balance, username) VALUES ($1, $2, $3, $4, $5, $6)',
        ['User', creditedDeposit.phone.slice(-4), email, creditedDeposit.phone, creditedDeposit.amount_sd, uname]
      );
    }
    const registeredUserRes = await client.query('SELECT referred_by FROM users WHERE phone = $1', [creditedDeposit.phone]);
    const referrerPhone = registeredUserRes.rows[0]?.referred_by;
    if (resellerBonus > 0) {
      await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['RESELLER_BONUS', `Reseller bonus of ${resellerBonus.toFixed(2)} SD credited to ${creditedDeposit.phone}.`]);
    }
    if (referrerPhone) {
      const rewardSd = Math.max(0, Number(creditedDeposit.amount_sd || 0) * 0.05);
      const rewardRes = await client.query('INSERT INTO referral_ledger (referrer_phone, referred_phone, source_deposit_reference, reward_sd) VALUES ($1, $2, $3, $4) ON CONFLICT (referred_phone) DO NOTHING RETURNING id', [referrerPhone, creditedDeposit.phone, creditedDeposit.reference, rewardSd]);
      if (rewardRes.rowCount > 0 && rewardSd > 0) {
        await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE phone = $2', [rewardSd, referrerPhone]);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['REFERRAL_REWARD', `Referral reward credited to ${referrerPhone}: ${rewardSd.toFixed(2)} SD.`]);
      }
    }
    await client.query('COMMIT');
    logActivity('DEPOSIT_CALLBACK_SUCCESS', `User ${uname} (${creditedDeposit.phone}) topped up ${creditedDeposit.amount_sd} SD. Receipt: ${mpesaReceipt || 'N/A'}`);
    sendTelegramNotification(`✅ Payment Confirmed! User: ${uname}; Phone: ${creditedDeposit.phone}; Amount: ${creditedDeposit.amount_sd} SD`);
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

module.exports = async function handler(req, res) {
  const { url, method, body = {}, query = {}, headers = {} } = req;
  const path = url.split('?')[0].replace('/api/user/', '');

  try {
    try {
      await initDb();
    } catch (dbError) {
      console.error('Database Init Error:', dbError);
      return res.status(500).json({ error: 'Database connection failed', details: dbError.message });
    }
    const client = await pool.connect();

    if (path === 'callback') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const payload = body;
      const checkoutRequestId = payload.checkout_request_id || payload.checkoutRequestId || payload.CheckoutRequestID || payload.data?.checkout_request_id || payload.data?.checkoutRequestId;
      const transactionId = payload.transactionId || payload.transaction_id || payload.data?.transactionId || payload.data?.transaction_id;
      const reference = payload.reference || payload.accountReference || payload.account_reference || payload.data?.reference || payload.data?.accountReference;
      if (!checkoutRequestId && !transactionId && !reference) { client.release(); return res.status(400).json({ error: 'Invalid payload' }); }
      const depRes = await client.query('SELECT * FROM deposits WHERE checkout_request_id = $1 OR transaction_id = $2 OR reference = $3 LIMIT 1', [checkoutRequestId || null, transactionId || null, reference || null]);
      const deposit = depRes.rows[0];
      if (!deposit || deposit.status === 'success') { client.release(); return res.status(200).json({ message: 'Handled' }); }
      const parsed = providerStatus(payload);
      const callbackTransactionId = transactionId || parsed.transactionId;
      if (callbackTransactionId) await client.query('UPDATE deposits SET transaction_id = $1 WHERE reference = $2', [callbackTransactionId, deposit.reference]);
      const status = parsed.status;
      const resultCode = payload.resultCode ?? payload.ResultCode ?? payload.Body?.stkCallback?.ResultCode;
      const isSuccess = status === 'completed' || Number(resultCode) === 0;
      const receipt = payload.mpesaReceipt || payload.mpesa_receipt || payload.MpesaReceiptNumber || parsed.transactionId || 'N/A';
      if (isSuccess) await creditDeposit(client, deposit, receipt);
      else if (status === 'failed' || status === 'cancelled' || resultCode !== undefined) await client.query('UPDATE deposits SET status = $1 WHERE reference = $2', [status === 'cancelled' ? 'cancelled' : 'failed', deposit.reference]);
      client.release();
      return res.status(200).json({ success: isSuccess });
    }

    if (path === 'login') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const identifier = String(body.identifier || body.email || body.username || body.phone || '').trim();
      const password = String(body.password || '');
      if (!identifier || !password) { client.release(); return res.status(400).json({ error: 'Enter your email, username, or phone number and password.' }); }
      const phoneIdentifier = normalizeKenyanPhone(identifier);
      const lookup = phoneIdentifier
        ? await client.query('SELECT * FROM users WHERE phone = $1 LIMIT 1', [phoneIdentifier])
        : await client.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($1) LIMIT 1', [identifier]);
      const user = lookup.rows[0];
      if (!user || !user.password_hash || !(await verifyPassword(password, user.password_hash))) {
        client.release();
        return res.status(401).json({ error: 'Invalid login details.' });
      }
      let welcomeGranted = user.registration_bonus_granted;
      let addedSd = 0;
      if (!welcomeGranted) {
        addedSd = 10 / 5; // $2 USD (10 KSH equivalent)
        await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1, registration_bonus_granted = TRUE, registration_bonus_ksh = 10, last_login_at = CURRENT_TIMESTAMP WHERE phone = $2', [addedSd, user.phone]);
        user.balance = parseFloat(user.balance || 0) + addedSd;
        user.registration_bonus_granted = true;
        logActivity(user.phone, 'FIRST_LOGIN_BONUS', `User ${user.username} received $${addedSd} USD welcome bonus on first login.`);
        sendTelegramNotification(`🎉 *Welcome Bonus Claimed!*\nUser: \`${user.username}\` received *$${addedSd} USD* on first login.`);
      } else {
        await client.query('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE phone = $1', [user.phone]);
      }
      const sessionToken = await issueSession(client, user.phone, req);
      setSessionCookie(res, sessionToken);
      client.release();
      return res.status(200).json({ success: true, user: publicUser(user), welcomeBonusAdded: !welcomeGranted, addedSd, expiresInDays: 30 });
    }

    if (path === 'session') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      client.release();
      if (!user) return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
      return res.status(200).json({ success: true, user: publicUser(user), expiresInDays: 30 });
    }

    if (path === 'logout') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const token = sessionTokenFromRequest(req);
      if (token) await client.query('UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = $1', [sessionTokenHash(token)]);
      clearSessionCookie(res);
      client.release();
      return res.status(200).json({ success: true });
    }

    if (path === 'register') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(body.phone);
      const username = String(body.username || '').trim().replace(/[\u0000-\u001F\u007F]/g, '');
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const referralCode = String(body.referralCode || '').trim().toUpperCase();
      if (!phone) { client.release(); return res.status(400).json({ error: 'Enter a valid Kenyan phone number.' }); }
      if (!username || username.length > 80) { client.release(); return res.status(400).json({ error: 'Username must be between 1 and 80 characters.' }); }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { client.release(); return res.status(400).json({ error: 'Enter a valid email address.' }); }
      if (password.length < 8 || password.length > 128 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) { client.release(); return res.status(400).json({ error: 'Password must be 8–128 characters and include at least one letter and one number.' }); }
      const passwordHash = await hashPassword(password);
      await client.query('BEGIN');
      try {
        const currentRes = await client.query('SELECT * FROM users WHERE phone = $1 FOR UPDATE', [phone]);
        const current = currentRes.rows[0];
        if (current?.registered_at && current.password_hash) {
          await client.query('ROLLBACK');
          client.release();
          return res.status(409).json({ error: 'This phone number is already registered. Use Log in instead.', registered: true });
        }
        const credentialUpgrade = Boolean(current?.registered_at && !current.password_hash);
        const duplicateRes = await client.query('SELECT phone FROM users WHERE (LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)) AND phone <> $3 LIMIT 1', [username, email, phone]);
        if (duplicateRes.rowCount > 0) {
          await client.query('ROLLBACK');
          client.release();
          return res.status(409).json({ error: 'That username or email is already in use.' });
        }
        const referrerRes = !credentialUpgrade && referralCode ? await client.query('SELECT phone FROM users WHERE referral_code = $1', [referralCode]) : { rows: [] };
        const referrerPhone = credentialUpgrade ? current.referred_by : (referrerRes.rows[0]?.phone && referrerRes.rows[0].phone !== phone ? referrerRes.rows[0].phone : null);
        let newReferralCode = `BL-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
        for (let attempt = 0; attempt < 5; attempt += 1) {
          const codeCheck = await client.query('SELECT 1 FROM users WHERE referral_code = $1', [newReferralCode]);
          if (codeCheck.rows.length === 0) break;
          newReferralCode = `BL-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
        }
        const welcomeKsh = credentialUpgrade ? 0 : 10;
        const welcomeSd = credentialUpgrade ? 0 : welcomeKsh / 5;
        let userRes;
        if (current) {
          if (credentialUpgrade) {
            userRes = await client.query('UPDATE users SET username = $1, email = $2, password_hash = $3, last_login_at = CURRENT_TIMESTAMP WHERE phone = $4 RETURNING phone, username, email, balance, referral_code, registered_at, registration_bonus_granted, language', [username, email, passwordHash, phone]);
          } else {
            userRes = await client.query('UPDATE users SET username = $1, email = $2, password_hash = $3, referred_by = $4, registered_at = CURRENT_TIMESTAMP, referral_code = $5, registration_bonus_ksh = $6, registration_bonus_granted = TRUE, balance = COALESCE(balance, 0) + $7, last_login_at = CURRENT_TIMESTAMP WHERE phone = $8 RETURNING phone, username, email, balance, referral_code, registered_at, registration_bonus_granted, language', [username, email, passwordHash, referrerPhone, newReferralCode, welcomeKsh, welcomeSd, phone]);
          }
        } else {
          userRes = await client.query(`INSERT INTO users (firstname, lastname, email, phone, username, password_hash, balance, referred_by, registered_at, referral_code, registration_bonus_ksh, registration_bonus_granted, last_login_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, $9, $10, TRUE, CURRENT_TIMESTAMP) RETURNING phone, username, email, balance, referral_code, registered_at, registration_bonus_granted, language`, ['User', phone.slice(-4), email, phone, username, passwordHash, welcomeSd, referrerPhone, newReferralCode, welcomeKsh]);
        }
        const sessionToken = await issueSession(client, phone, req);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', [credentialUpgrade ? 'ACCOUNT_CREDENTIALS_UPGRADED' : 'REGISTRATION_BONUS', credentialUpgrade ? `User ${username} completed secure account credentials.` : `User ${username} registered and received ${welcomeKsh} KSH welcome credit (${welcomeSd} SD).`]);
        await client.query('COMMIT');
        setSessionCookie(res, sessionToken);
        client.release();
        sendTelegramNotification(credentialUpgrade ? `🔐 User ${username} (${phone}) completed secure login credentials.` : `📝 New registration: ${username} (${phone}) received ${welcomeKsh} KSH welcome credit.`);
        return res.status(credentialUpgrade ? 200 : 201).json({ success: true, user: userRes.rows[0], bonus: { ksh: welcomeKsh, sd: welcomeSd }, referralCode: userRes.rows[0].referral_code || newReferralCode, expiresInDays: 30 });
      } catch (registrationError) {
        await client.query('ROLLBACK');
        client.release();
        throw registrationError;
      }
    }

    if (path === 'wallet') {
      const phone = method === 'POST' ? body.phone : query.phone;
      const action = method === 'POST' ? body.action : 'get';
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      let userRes = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
      if (userRes.rows.length === 0) {
        const username = 'blacklord_' + Math.random().toString(36).substring(2, 7);
        await client.query('INSERT INTO users (firstname, lastname, email, phone, username, balance) VALUES ($1, $2, $3, $4, $5, $6)', ['User', String(phone).slice(-4), `${String(phone).replace(/\D/g, '')}@blacklord.tech`, phone, username, 0]);
        userRes = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
      }
      const user = userRes.rows[0];
      if (action === 'get') { client.release(); return res.status(200).json({ success: true, balance: user.balance, username: user.username }); }
      if (action === 'redeem') {
        const code = String(body.code || '').toUpperCase();
        const vRes = await client.query('SELECT * FROM vouchers WHERE code = $1 AND is_used = FALSE', [code]);
        if (vRes.rows.length === 0) { client.release(); return res.status(400).json({ error: 'Invalid or used voucher' }); }
        const voucher = vRes.rows[0];
        const newBalance = parseFloat(user.balance) + parseFloat(voucher.amount);
        await client.query('UPDATE users SET balance = $1 WHERE phone = $2', [newBalance, phone]);
        await client.query('UPDATE vouchers SET is_used = TRUE, used_by = $1 WHERE code = $2', [phone, code]);
        logActivity('VOUCHER_REDEEM', `User ${user.username} (${phone}) redeemed ${voucher.amount} SD.`);
        sendTelegramNotification(`🎟️ *Voucher Redeemed!*\nUser: \`${user.username}\`\nAmount: *${voucher.amount} SD*`);
        client.release();
        return res.status(200).json({ success: true, newBalance });
      }
    }

    if (path === 'broadcast') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const broadcastRes = await client.query("SELECT id, message, kind, starts_at, ends_at FROM broadcasts WHERE active = TRUE AND starts_at <= CURRENT_TIMESTAMP AND (ends_at IS NULL OR ends_at > CURRENT_TIMESTAMP) ORDER BY created_at DESC LIMIT 1");
      client.release();
      return res.status(200).json({ success: true, broadcast: broadcastRes.rows[0] || null });
    }

    if (path === 'language') {
      const phone = normalizeKenyanPhone(method === 'POST' ? body.phone : query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      if (method === 'GET') {
        const userRes = await client.query('SELECT language FROM users WHERE phone = $1', [phone]);
        client.release();
        return res.status(200).json({ success: true, language: userRes.rows[0]?.language || 'en' });
      }
      if (method === 'POST') {
        const language = normalizeLanguage(body.language);
        if (!language) { client.release(); return res.status(400).json({ error: 'Language must be en or sw.' }); }
        await client.query('UPDATE users SET language = $1 WHERE phone = $2', [language, phone]);
        client.release();
        return res.status(200).json({ success: true, language });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'leaderboard') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const leaderboardRes = await client.query(`SELECT u.username, COUNT(r.id)::int AS referrals, COALESCE(SUM(r.reward_sd), 0) AS rewards_sd FROM users u LEFT JOIN referral_ledger r ON r.referrer_phone = u.phone WHERE u.registered_at IS NOT NULL GROUP BY u.phone, u.username ORDER BY referrals DESC, rewards_sd DESC LIMIT 20`);
      client.release();
      return res.status(200).json({ success: true, leaderboard: leaderboardRes.rows });
    }

    if (path === 'transfer') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const senderPhone = normalizeKenyanPhone(body.phone);
      const recipientPhone = normalizeKenyanPhone(body.recipientPhone);
      const amount = Number(body.amountSD);
      if (!senderPhone || !recipientPhone || senderPhone === recipientPhone) { client.release(); return res.status(400).json({ error: 'Enter two different valid Kenyan phone numbers.' }); }
      if (!Number.isFinite(amount) || amount <= 0) { client.release(); return res.status(400).json({ error: 'Transfer amount must be greater than zero.' }); }
      try {
        await client.query('BEGIN');
        const senderRes = await client.query('SELECT phone, username, balance, registered_at FROM users WHERE phone = $1 FOR UPDATE', [senderPhone]);
        const sender = senderRes.rows[0];
        if (!sender?.registered_at) { await client.query('ROLLBACK'); client.release(); return res.status(403).json({ error: 'Register before sending SD.', requiresRegistration: true }); }
        if (Number(sender.balance || 0) < amount) { await client.query('ROLLBACK'); client.release(); return res.status(402).json({ error: 'Insufficient SD balance.' }); }
        await client.query("INSERT INTO users (firstname, lastname, email, phone, username, balance) VALUES ('User', $1, $2, $3, $4, 0) ON CONFLICT (phone) DO NOTHING", [recipientPhone.slice(-4), `${recipientPhone}@blacklord.tech`, recipientPhone, `blacklord_${recipientPhone.slice(-4)}`]);
        const reference = makeFeatureReference('BL-TR');
        await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [amount, senderPhone]);
        await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE phone = $2', [amount, recipientPhone]);
        await client.query('INSERT INTO balance_transfers (sender_phone, recipient_phone, amount_sd, reference) VALUES ($1, $2, $3, $4)', [senderPhone, recipientPhone, amount, reference]);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['BALANCE_TRANSFER', `${amount.toFixed(2)} SD transferred from ${senderPhone} to ${recipientPhone}.`]);
        await client.query('COMMIT');
        client.release();
        return res.status(200).json({ success: true, reference, amountSD: amount });
      } catch (transferError) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        client.release();
        throw transferError;
      }
    }

    if (path === 'gift-card') {
      if (method !== 'POST' || String(body.action || 'redeem') !== 'redeem') { client.release(); return res.status(405).json({ error: 'Only gift-card redemption is available here.' }); }
      const phone = normalizeKenyanPhone(body.phone);
      const code = String(body.code || '').trim().toUpperCase();
      if (!phone || !code) { client.release(); return res.status(400).json({ error: 'Phone and gift-card code are required.' }); }
      try {
        await client.query('BEGIN');
        const cardRes = await client.query('SELECT * FROM gift_cards WHERE code = $1 AND is_used = FALSE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) FOR UPDATE', [code]);
        if (!cardRes.rows[0]) { await client.query('ROLLBACK'); client.release(); return res.status(400).json({ error: 'Invalid, expired, or already-used gift card.' }); }
        const card = cardRes.rows[0];
        const userRes = await client.query('SELECT phone FROM users WHERE phone = $1 FOR UPDATE', [phone]);
        if (!userRes.rows[0]) { await client.query("INSERT INTO users (firstname, lastname, email, phone, username, balance) VALUES ('User', $1, $2, $3, $4, 0)", [phone.slice(-4), `${phone}@blacklord.tech`, phone, `blacklord_${phone.slice(-4)}`]); }
        await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE phone = $2', [card.amount_sd, phone]);
        await client.query('UPDATE gift_cards SET is_used = TRUE, redeemed_by = $1 WHERE code = $2', [phone, code]);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['GIFT_CARD_REDEEM', `${phone} redeemed a ${card.amount_sd} SD gift card.`]);
        await client.query('COMMIT');
        client.release();
        return res.status(200).json({ success: true, amountSD: card.amount_sd });
      } catch (giftError) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        client.release();
        throw giftError;
      }
    }

    if (path === 'addons') {
      if (method === 'GET') {
        const addonRes = await client.query('SELECT id, slug, name, description, price_sd FROM addons WHERE active = TRUE ORDER BY id ASC');
        client.release();
        return res.status(200).json({ success: true, addons: addonRes.rows });
      }
      if (method === 'POST') {
        const phone = normalizeKenyanPhone(body.phone);
        const addonId = Number(body.addonId);
        if (!phone || !Number.isInteger(addonId)) { client.release(); return res.status(400).json({ error: 'Phone and add-on are required.' }); }
        try {
          await client.query('BEGIN');
          const userRes = await client.query('SELECT phone, balance, registered_at FROM users WHERE phone = $1 FOR UPDATE', [phone]);
          const user = userRes.rows[0];
          const addonRes = await client.query('SELECT * FROM addons WHERE id = $1 AND active = TRUE', [addonId]);
          const addon = addonRes.rows[0];
          if (!user?.registered_at) { await client.query('ROLLBACK'); client.release(); return res.status(403).json({ error: 'Register before buying add-ons.', requiresRegistration: true }); }
          if (!addon) { await client.query('ROLLBACK'); client.release(); return res.status(404).json({ error: 'Add-on not found.' }); }
          if (Number(user.balance || 0) < Number(addon.price_sd)) { await client.query('ROLLBACK'); client.release(); return res.status(402).json({ error: 'Insufficient SD balance.' }); }
          await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [addon.price_sd, phone]);
          await client.query('INSERT INTO user_addons (phone, addon_id, server_id, amount_sd) VALUES ($1, $2, $3, $4)', [phone, addon.id, body.serverId ? Number(body.serverId) : null, addon.price_sd]);
          await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['ADDON_PURCHASE', `${phone} purchased ${addon.name} for ${addon.price_sd} SD.`]);
          await client.query('COMMIT');
          client.release();
          return res.status(200).json({ success: true, addon: addon.name, amountSD: addon.price_sd });
        } catch (addonError) {
          try { await client.query('ROLLBACK'); } catch (_) {}
          client.release();
          throw addonError;
        }
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'customizer') {
      const phone = normalizeKenyanPhone(method === 'POST' ? body.phone : query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      if (method === 'GET') {
        const profileRes = await client.query('SELECT id, phone, server_id, bot_name, bot_bio, welcome_message, tone, updated_at FROM bot_profiles WHERE phone = $1 ORDER BY updated_at DESC', [phone]);
        client.release();
        return res.status(200).json({ success: true, profiles: profileRes.rows });
      }
      if (method === 'POST') {
        const userRes = await client.query('SELECT registered_at FROM users WHERE phone = $1', [phone]);
        if (!userRes.rows[0]?.registered_at) { client.release(); return res.status(403).json({ error: 'Register before customizing a bot.', requiresRegistration: true }); }
        const serverId = body.serverId ? Number(body.serverId) : null;
        const botName = String(body.botName || '').trim().slice(0, 60);
        const botBio = String(body.botBio || '').trim().slice(0, 240);
        const welcomeMessage = String(body.welcomeMessage || '').trim().slice(0, 500);
        const tone = ['friendly', 'professional', 'funny', 'minimal'].includes(body.tone) ? body.tone : 'friendly';
        if (!botName && !botBio && !welcomeMessage) { client.release(); return res.status(400).json({ error: 'Add a bot name, bio, or welcome message.' }); }
        const result = await client.query(`INSERT INTO bot_profiles (phone, server_id, bot_name, bot_bio, welcome_message, tone, updated_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) ON CONFLICT (phone, server_id) DO UPDATE SET bot_name = EXCLUDED.bot_name, bot_bio = EXCLUDED.bot_bio, welcome_message = EXCLUDED.welcome_message, tone = EXCLUDED.tone, updated_at = CURRENT_TIMESTAMP RETURNING *`, [phone, serverId, botName || null, botBio || null, welcomeMessage || null, tone]);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['BOT_PROFILE_UPDATE', `Bot profile updated for ${phone}.`]);
        client.release();
        return res.status(200).json({ success: true, profile: result.rows[0], message: 'Bot profile saved. Your panel bot can read this profile when its customization hook is enabled.' });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'insurance') {
      const phone = normalizeKenyanPhone(method === 'POST' ? body.phone : query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      if (method === 'GET') {
        const result = await client.query("SELECT id, server_id, price_sd, status, next_billing_date, created_at FROM insurance_subscriptions WHERE phone = $1 ORDER BY created_at DESC", [phone]);
        client.release();
        return res.status(200).json({ success: true, subscriptions: result.rows });
      }
      if (method === 'POST') {
        const action = String(body.action || 'subscribe');
        const serverId = body.serverId ? Number(body.serverId) : null;
        if (action === 'cancel') {
          await client.query("UPDATE insurance_subscriptions SET status = 'cancelled' WHERE phone = $1 AND ($2::int IS NULL OR server_id = $2) AND status = 'active'", [phone, serverId]);
          client.release();
          return res.status(200).json({ success: true, status: 'cancelled' });
        }
        const userRes = await client.query('SELECT balance, registered_at FROM users WHERE phone = $1 FOR UPDATE', [phone]);
        const user = userRes.rows[0];
        const priceSd = 2;
        if (!user?.registered_at) { client.release(); return res.status(403).json({ error: 'Register before adding bot insurance.', requiresRegistration: true }); }
        if (Number(user.balance || 0) < priceSd) { client.release(); return res.status(402).json({ error: 'You need 2 SD to activate bot insurance.' }); }
        const existing = await client.query("SELECT id FROM insurance_subscriptions WHERE phone = $1 AND ($2::int IS NULL OR server_id = $2) AND status = 'active'", [phone, serverId]);
        if (existing.rows[0]) { client.release(); return res.status(409).json({ error: 'Insurance is already active for this service.' }); }
        await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [priceSd, phone]);
        const result = await client.query("INSERT INTO insurance_subscriptions (phone, server_id, price_sd, status, next_billing_date) VALUES ($1, $2, $3, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days') RETURNING *", [phone, serverId, priceSd]);
        await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['INSURANCE_ACTIVATED', `Bot insurance activated for ${phone}.`]);
        client.release();
        return res.status(200).json({ success: true, subscription: result.rows[0], message: 'Bot insurance activated. It includes priority re-setup support after a bot connection loss.' });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'login/start') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(body.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Enter a valid Kenyan phone number.' }); }
      const code = String(Math.floor(100000 + Math.random() * 900000));
      const hash = crypto.createHash('sha256').update(code).digest('hex');
      await client.query("UPDATE whatsapp_login_codes SET used_at = CURRENT_TIMESTAMP WHERE phone = $1 AND used_at IS NULL", [phone]);
      await client.query("INSERT INTO whatsapp_login_codes (phone, code_hash, expires_at) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '10 minutes')", [phone, hash]);
      const botLink = process.env.WHATSAPP_LOGIN_BOT_URL || 'https://wa.me/254700000000';
      let deliveryConfigured = false;
      if (process.env.WHATSAPP_LOGIN_DELIVERY_URL) {
        deliveryConfigured = true;
        try {
          await axios.post(process.env.WHATSAPP_LOGIN_DELIVERY_URL, { phone, code, expiresInMinutes: 10 }, { timeout: 10000 });
        } catch (deliveryError) {
          console.error('WhatsApp login delivery warning:', deliveryError.message);
        }
      }
      sendTelegramNotification(`🔐 WhatsApp login code generated for ${phone}. Delivery configured: ${deliveryConfigured ? 'yes' : 'no'}.`);
      client.release();
      const response = { success: true, phone, botLink, deliveryConfigured, message: deliveryConfigured ? 'Your one-time code was sent through the configured WhatsApp provider. It expires in 10 minutes.' : 'Open the WhatsApp bot link and request your login code. A WhatsApp delivery provider must be configured for production delivery.' };
      if (process.env.NODE_ENV !== 'production') response.devCode = code;
      return res.status(200).json(response);
    }

    if (path === 'login/verify') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(body.phone);
      const code = String(body.code || '').trim();
      if (!phone || !/^\d{6}$/.test(code)) { client.release(); return res.status(400).json({ error: 'Phone and six-digit code are required.' }); }
      const hash = crypto.createHash('sha256').update(code).digest('hex');
      const codeRes = await client.query("SELECT id FROM whatsapp_login_codes WHERE phone = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC LIMIT 1", [phone, hash]);
      if (!codeRes.rows[0]) { client.release(); return res.status(401).json({ error: 'Invalid or expired login code.' }); }
      await client.query('UPDATE whatsapp_login_codes SET used_at = CURRENT_TIMESTAMP WHERE id = $1', [codeRes.rows[0].id]);
      const userRes = await client.query('SELECT phone, username, registered_at FROM users WHERE phone = $1', [phone]);
      client.release();
      return res.status(200).json({ success: true, user: userRes.rows[0] || { phone }, session: crypto.randomBytes(24).toString('hex') });
    }

    if (path === 'pairing/start') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      const whatsappPhone = normalizeKenyanPhone(body.whatsappPhone || body.phone || user?.phone);
      if (!whatsappPhone) { client.release(); return res.status(400).json({ error: 'Enter a valid WhatsApp phone number.' }); }

      // Every unlinked request follows the Telegram-style two-minute lifetime.
      // This cleanup also clears legacy rows that were incorrectly left as active
      // without a confirmed linked session.
      await client.query(`
        UPDATE pairing_requests
        SET status = 'expired',
            pairing_code = NULL,
            message = 'Pairing request expired after two minutes. Please request a new code.',
            updated_at = CURRENT_TIMESTAMP
        WHERE whatsapp_phone = $1
          AND (
            (linked_at IS NULL AND status IN ('paired', 'connected', 'active', 'completed'))
            OR (linked_at IS NULL AND status IN ('pending', 'processing', 'waiting'))
          )
          AND created_at <= NOW() - INTERVAL '2 minutes'
      `, [whatsappPhone]);

      // A linked session is the only permanent block. Pending requests are
      // blocked only during their two-minute lifetime so users can retry after
      // an abandoned or unsuccessful attempt.
      const activeCheck = await client.query(`
        SELECT request_id, status FROM pairing_requests
        WHERE whatsapp_phone = $1
          AND (
            (status IN ('connected', 'active', 'completed') AND linked_at IS NOT NULL)
            OR (status IN ('pending', 'processing', 'waiting') AND linked_at IS NULL AND created_at > NOW() - INTERVAL '2 minutes')
          )
        ORDER BY created_at DESC
        LIMIT 1
      `, [whatsappPhone]);

      if (activeCheck.rows[0]) {
        client.release();
        return res.status(409).json({
          error: activeCheck.rows[0].status === 'pending' || activeCheck.rows[0].status === 'processing' || activeCheck.rows[0].status === 'waiting'
            ? 'A pairing request is already in progress. It expires in two minutes; please wait or retry after it expires.'
            : 'This number already has a linked active session. Unlink it before requesting another code.',
          requestId: activeCheck.rows[0].request_id,
          status: activeCheck.rows[0].status
        });
      }
      
      const requestedServerId = body.serverId ? Number(body.serverId) : 10640078;
      const rawBotType = body.botType || body.type;
      const requestedBotType = String(rawBotType || 'blacklord').trim().toLowerCase().replace(/[\s_-]+/g, '');
      const allowedBots = ['blacklord', 'samsung', 'talkless', 'skylar', 'rita', 'titan'];
      if (!allowedBots.includes(requestedBotType)) { client.release(); return res.status(400).json({ error: 'Please select a valid bot type.' }); }
      
      let serverId = requestedServerId;
      let botType = requestedBotType;

      if (user?.phone) {
        const serverRes = requestedServerId === null
          ? await client.query("SELECT server_id, bot_type, status FROM servers WHERE phone = $1 AND status NOT IN ('suspended', 'deleted') ORDER BY created_at DESC LIMIT 1", [user.phone])
          : await client.query("SELECT server_id, bot_type, status FROM servers WHERE phone = $1 AND server_id = $2 AND status NOT IN ('suspended', 'deleted') LIMIT 1", [user.phone, requestedServerId]);
        const server = serverRes.rows[0];
        if (server) {
          serverId = server.server_id;
          // Only use server bot_type if user didn't explicitly select one via dashboard
          if (!rawBotType) {
            botType = server.bot_type || botType;
          }
        }
      }

      const config = getPairingConfig();
      const requestId = pairingRequestId();
      await client.query("INSERT INTO pairing_requests (request_id, phone, whatsapp_phone, server_id, bot_type, status, pairing_expires_at, message) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP + INTERVAL '2 minutes', $7)", [requestId, user?.phone || null, whatsappPhone, serverId || null, botType, 'pending', 'Pairing request sent to the bot.']);
      try {
        const callbackBase = process.env.PUBLIC_APP_URL || (headers.host ? `https://${headers.host}` : '');
        const botData = await dispatchPairingRequest(config, {
          requestId,
          userPhone: user?.phone || null,
          whatsappPhone,
          serverId: serverId || null,
          botType: botType || null,
          callbackUrl: `${callbackBase}/api/user/pairing/callback`
        });
        const status = normalizePairingStatus(botData.status || botData.state || 'pending');
        const pairingCode = String(botData.pairingCode || botData.pairing_code || botData.code || '').trim().slice(0, 64) || null;
        const expiresAt = botData.expiresAt || botData.expires_at || null;
        const botMessage = String(botData.message || (pairingCode ? 'Pairing code ready.' : 'Pairing request accepted.')).slice(0, 500);
        const bridgeSessionId = String(botData.sessionId || botData.session_id || '').slice(0, 200) || null;
        const result = await client.query("UPDATE pairing_requests SET status = $1, pairing_code = $2, pairing_expires_at = LEAST(COALESCE(pairing_expires_at, created_at + INTERVAL '2 minutes'), COALESCE($3::timestamp, created_at + INTERVAL '2 minutes')), bot_session_id = $4, linked_at = CASE WHEN $1 IN ('connected', 'active', 'completed') AND $2 IS NULL THEN COALESCE(linked_at, CURRENT_TIMESTAMP) ELSE linked_at END, message = $5, updated_at = CURRENT_TIMESTAMP WHERE request_id = $6 RETURNING request_id, whatsapp_phone, server_id, bot_type, status, pairing_code, pairing_expires_at, bot_session_id, linked_at, message, created_at, updated_at", [status, pairingCode, expiresAt ? new Date(expiresAt) : null, bridgeSessionId, botMessage, requestId]);
        client.release();
        return res.status(202).json({ success: true, pairing: result.rows[0], message: botMessage });
      } catch (pairingError) {
        // If the bridge is just not configured or unreachable, we fallback to the polling bridge
        if (pairingError.statusCode === 503 || !config.botEndpoint || pairingError.code === 'ECONNREFUSED' || pairingError.code === 'ETIMEDOUT' || pairingError.code === 'ECONNABORTED' || pairingError.message?.includes('timeout')) {
          const result = await client.query('SELECT * FROM pairing_requests WHERE request_id = $1', [requestId]);
          client.release();
          return res.status(202).json({ success: true, pairing: result.rows[0], message: 'Pairing request queued. The bot will process it shortly.' });
        }
        await client.query("UPDATE pairing_requests SET status = 'failed', message = $1, updated_at = CURRENT_TIMESTAMP WHERE request_id = $2", [String(pairingError.message || 'Bot bridge request failed').slice(0, 500), requestId]);
        client.release();
        return res.status(pairingError.statusCode || 502).json({ error: pairingError.response?.data?.error || pairingError.message || 'The bot pairing bridge is unavailable (v2).' });
      }
    }

    if (path === 'panel/create') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      const { package_id, ptero_username, ptero_password, firstname, lastname, nest_id, egg_id } = body;
      if (!ptero_username || !ptero_password || !firstname || !lastname) {
        client.release();
        return res.status(400).json({ error: 'Username, password, first name, and last name are required.' });
      }

      const pteroUrl = process.env.PTERODACTYL_URL || 'https://panels.tnppanels.top';
      const pteroKey = process.env.PTERODACTYL_API_KEY || 'ptla_placeholder_key';

      try {
        // Create user on Pterodactyl panel
        const email = `${ptero_username.toLowerCase()}_${Date.now()}@blacklord.tech`;
        const userRes = await fetch(`${pteroUrl}/api/application/users`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${pteroKey}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            email,
            username: ptero_username,
            first_name: firstname,
            last_name: lastname,
            password: ptero_password
          })
        });

        const userData = await userRes.json();
        let pteroUserId = userData?.attributes?.id;
        
        if (!pteroUserId && userRes.status !== 201) {
          // If user already exists, fetch list to find ID
          const listRes = await fetch(`${pteroUrl}/api/application/users?filter[username]=${encodeURIComponent(ptero_username)}`, {
            headers: { 'Authorization': `Bearer ${pteroKey}`, 'Accept': 'application/json' }
          });
          const listData = await listRes.json();
          pteroUserId = listData?.data?.[0]?.attributes?.id;
        }

        if (!pteroUserId) {
          client.release();
          return res.status(400).json({ error: 'Could not create or locate Pterodactyl user account. Please check panel credentials.' });
        }

        // Create server instance
        const serverRes = await fetch(`${pteroUrl}/api/application/servers`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${pteroKey}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            name: `${ptero_username}-server`,
            user: pteroUserId,
            egg: egg_id || 15,
            docker_image: 'ghcr.io/pterodactyl/yolks:nodejs_20',
            startup: 'npm start',
            environment: { INSTANCE_NAME: ptero_username },
            limits: { memory: 2048, swap: 0, disk: 10240, io: 500, cpu: 100 },
            feature_limits: { databases: 1, backups: 1, allocations: 1 }
          })
        });

        const serverData = await serverRes.json();
        if (!serverRes.ok) {
          client.release();
          return res.status(400).json({ error: serverData.errors?.[0]?.detail || 'Failed to provision server container on panel.' });
        }

        const serverId = serverData?.attributes?.id || 10640078;
        if (user?.phone) {
          await client.query(`
            INSERT INTO servers (server_id, phone, bot_type, status, created_at)
            VALUES ($1, $2, $3, 'active', CURRENT_TIMESTAMP)
            ON CONFLICT (server_id) DO UPDATE SET status = 'active'
          `, [serverId, user.phone, 'blacklord']);
        }

        client.release();
        return res.status(201).json({ success: true, server_id: serverId, message: 'Pterodactyl server created successfully.' });
      } catch (err) {
        client.release();
        return res.status(502).json({ error: 'Pterodactyl connection failed: ' + err.message });
      }
    }

    if (path === 'pairing/status') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      const requestId = String(query.requestId || '').trim();
      if (!requestId) { client.release(); return res.status(400).json({ error: 'requestId is required.' }); }

      // Every unlinked pairing request expires after two minutes, even if the
      // bridge never responds. This makes retry behavior deterministic.
      await client.query(`
        UPDATE pairing_requests
        SET status = 'expired', pairing_code = NULL,
            message = 'Pairing request expired after two minutes. Please request a new code.',
            updated_at = CURRENT_TIMESTAMP
        WHERE request_id = $1
          AND (
            (linked_at IS NULL AND status IN ('pending', 'processing', 'waiting'))
            OR (linked_at IS NULL AND bot_session_id IS NULL AND status IN ('paired', 'connected', 'active', 'completed'))
          )
          AND (created_at <= NOW() - INTERVAL '2 minutes' OR pairing_expires_at <= CURRENT_TIMESTAMP)
      `, [requestId]);

      const requestRes = await client.query('SELECT request_id, whatsapp_phone, server_id, bot_type, status, pairing_code, pairing_expires_at, bot_session_id, linked_at, message, created_at, updated_at FROM pairing_requests WHERE request_id = $1 LIMIT 1', [requestId]);
      client.release();
      if (!requestRes.rows[0]) return res.status(404).json({ error: 'No pairing request found.' });
      return res.status(200).json({ success: true, pairing: requestRes.rows[0] });
    }

    if (path === 'pairing/health') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Log in before checking bot status.' }); }
      const config = getPairingConfig();
      const panel = await getPterodactylResourceStatus(config);
      client.release();
      return res.status(200).json({ success: true, bridge: { configured: Boolean(config.botEndpoint), endpointConfigured: Boolean(config.botEndpoint) }, panel });
    }

    if (path === 'pairing/callback') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const config = getPairingConfig();
      const suppliedSecret = headers['x-blacklord-pairing-secret'] || headers['X-Blacklord-Pairing-Secret'] || headers['x-bot-secret'] || headers['X-Bot-Secret'] || headers.authorization?.replace(/^Bearer\s+/i, '');
      if (!config.webhookSecret) { client.release(); return res.status(503).json({ error: 'Pairing webhook secret is not configured.' }); }
      if (!secretMatches(suppliedSecret, config.webhookSecret)) { client.release(); return res.status(401).json({ error: 'Invalid pairing callback signature.' }); }
      const requestId = String(body.requestId || body.request_id || '').trim();
      const status = normalizePairingStatus(body.status || body.state);
      if (!requestId) { client.release(); return res.status(400).json({ error: 'requestId is required.' }); }
      const pairingCode = String(body.pairingCode || body.pairing_code || body.code || '').trim().slice(0, 64) || null;
      const expiresAt = body.expiresAt || body.expires_at || null;
      const message = String(body.message || '').trim().slice(0, 500) || null;
      const result = await client.query("UPDATE pairing_requests SET status = $1::varchar, pairing_code = CASE WHEN $1::varchar IN ('expired', 'failed', 'cancelled') THEN NULL ELSE COALESCE($2::varchar, pairing_code) END, pairing_expires_at = CASE WHEN $1::varchar IN ('expired', 'failed', 'cancelled') THEN CURRENT_TIMESTAMP ELSE LEAST(COALESCE(pairing_expires_at, created_at + INTERVAL '2 minutes'), COALESCE($3::timestamp, created_at + INTERVAL '2 minutes')) END, bot_session_id = COALESCE($4::varchar, bot_session_id), linked_at = CASE WHEN $1::varchar IN ('connected', 'active', 'completed') AND $2::varchar IS NULL THEN COALESCE(linked_at, CURRENT_TIMESTAMP) ELSE linked_at END, message = COALESCE($5::text, message), updated_at = CURRENT_TIMESTAMP WHERE request_id = $6::varchar RETURNING request_id, status, pairing_code, pairing_expires_at, bot_session_id, linked_at, message, updated_at", [status, pairingCode, expiresAt ? new Date(expiresAt) : null, String(body.sessionId || body.session_id || '').slice(0, 200) || null, message, requestId]);
      client.release();
      if (!result.rows[0]) return res.status(404).json({ error: 'Pairing request not found.' });
      return res.status(200).json({ success: true, pairing: result.rows[0] });
    }

    if (path === 'pairing/poll') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const config = getPairingConfig();
      const suppliedSecret = headers['x-blacklord-pairing-secret'] || headers['X-Blacklord-Pairing-Secret'] || headers['x-bot-secret'] || headers['X-Bot-Secret'] || headers.authorization?.replace(/^Bearer\s+/i, '');
      if (!config.botSecret) { client.release(); return res.status(503).json({ error: 'Pairing secret is not configured.' }); }
      if (!secretMatches(suppliedSecret, config.botSecret)) { client.release(); return res.status(401).json({ error: 'Invalid pairing secret.' }); }
      
      const requestedBotType = String(query.bot_type || query.botType || headers['x-bot-type'] || headers['X-Bot-Type'] || '').trim().toLowerCase().replace(/[\s_-]+/g, '');
      const requestedServerIdRaw = query.server_id ?? query.serverId ?? headers['x-server-id'] ?? headers['X-Server-Id'];
      const requestedServerIdNumber = requestedServerIdRaw === undefined || requestedServerIdRaw === '' ? null : Number(requestedServerIdRaw);
      const requestedServerId = Number.isInteger(requestedServerIdNumber) ? requestedServerIdNumber : null;

      // Expire old pending work before claiming the next request.
      await client.query(`
        UPDATE pairing_requests
        SET status = 'expired', pairing_code = NULL,
            message = 'Pairing request expired after two minutes. Please request a new code.',
            updated_at = CURRENT_TIMESTAMP
          WHERE status = 'pending'
          AND linked_at IS NULL
          AND (created_at <= NOW() - INTERVAL '2 minutes' OR pairing_expires_at <= CURRENT_TIMESTAMP)
      `);

      // Atomically claim one request so six bot workers cannot process the same request.
      // The processing state is also visible to the website while Baileys creates the code.
      const result = await client.query(`
        UPDATE pairing_requests
        SET status = 'processing', updated_at = CURRENT_TIMESTAMP,
            message = COALESCE(message, 'Pairing request claimed by the bot bridge.')
        WHERE request_id = (
          SELECT request_id
          FROM pairing_requests
          WHERE status = 'pending'
            AND linked_at IS NULL
            AND created_at > NOW() - INTERVAL '2 minutes'
            AND (pairing_expires_at IS NULL OR pairing_expires_at > CURRENT_TIMESTAMP)
            AND ($1 = '' OR LOWER(bot_type) = $1)
            AND ($2::bigint IS NULL OR server_id = $2)
          ORDER BY created_at ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
        )
        RETURNING request_id, phone, whatsapp_phone, server_id, bot_type, status, created_at, pairing_expires_at
      `, [requestedBotType, requestedServerId]);
      client.release();
      return res.status(200).json({ success: true, pending: result.rows[0] || null });
    }

    if (path === 'chat') {
      if (method === 'GET') {
        const since = query.since ? new Date(query.since) : new Date(Date.now() - 24 * 60 * 60 * 1000);
        const chatRes = await client.query('SELECT id, phone, username, body, is_admin, created_at FROM chat_messages WHERE is_hidden = FALSE AND created_at >= $1 ORDER BY created_at ASC LIMIT 100', [since]);
        client.release();
        return res.status(200).json({ success: true, messages: chatRes.rows.map(item => ({ ...item, phone: item.phone ? 'verified member' : null })) });
      }
      if (method === 'POST') {
        const phone = normalizeKenyanPhone(body.phone);
        const bodyText = String(body.body || '').trim();
        if (!phone || !bodyText || bodyText.length > 500) { client.release(); return res.status(400).json({ error: 'Phone and a message of 1–500 characters are required.' }); }
        const userRes = await client.query('SELECT username FROM users WHERE phone = $1', [phone]);
        const result = await client.query('INSERT INTO chat_messages (phone, username, body) VALUES ($1, $2, $3) RETURNING id, username, body, is_admin, created_at', [phone, userRes.rows[0]?.username || `member_${phone.slice(-4)}`, bodyText]);
        client.release();
        return res.status(201).json({ success: true, message: result.rows[0] });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'giveaways') {
      if (method === 'GET') {
        const giveawayRes = await client.query(`SELECT g.id, g.title, g.description, g.entry_fee_sd, g.prize_sd, g.draw_at, g.status, COUNT(e.id)::int AS entries FROM giveaways g LEFT JOIN giveaway_entries e ON e.giveaway_id = g.id WHERE g.status IN ('scheduled', 'active') AND g.draw_at > CURRENT_TIMESTAMP GROUP BY g.id ORDER BY g.draw_at ASC`);
        client.release();
        return res.status(200).json({ success: true, giveaways: giveawayRes.rows });
      }
      if (method === 'POST') {
        const phone = normalizeKenyanPhone(body.phone);
        const giveawayId = Number(body.giveawayId);
        if (!phone || !Number.isInteger(giveawayId)) { client.release(); return res.status(400).json({ error: 'Phone and giveaway are required.' }); }
        try {
          await client.query('BEGIN');
          const userRes = await client.query('SELECT balance, registered_at FROM users WHERE phone = $1 FOR UPDATE', [phone]);
          const giveawayRes = await client.query("SELECT * FROM giveaways WHERE id = $1 AND status IN ('scheduled', 'active') AND draw_at > CURRENT_TIMESTAMP FOR UPDATE", [giveawayId]);
          const user = userRes.rows[0];
          const giveaway = giveawayRes.rows[0];
          if (!user?.registered_at) { await client.query('ROLLBACK'); client.release(); return res.status(403).json({ error: 'Register before entering a giveaway.', requiresRegistration: true }); }
          if (!giveaway) { await client.query('ROLLBACK'); client.release(); return res.status(404).json({ error: 'Giveaway is closed or not found.' }); }
          if (Number(user.balance || 0) < Number(giveaway.entry_fee_sd)) { await client.query('ROLLBACK'); client.release(); return res.status(402).json({ error: `You need ${giveaway.entry_fee_sd} SD to enter.` }); }
          await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [giveaway.entry_fee_sd, phone]);
          await client.query('INSERT INTO giveaway_entries (giveaway_id, phone, amount_sd) VALUES ($1, $2, $3)', [giveawayId, phone, giveaway.entry_fee_sd]);
          await client.query('UPDATE giveaways SET status = CASE WHEN status = \'scheduled\' THEN \'active\' ELSE status END WHERE id = $1', [giveawayId]);
          await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['GIVEAWAY_ENTRY', `${phone} entered giveaway ${giveawayId}.`]);
          await client.query('COMMIT');
          client.release();
          return res.status(201).json({ success: true, message: 'Your giveaway entry is confirmed.', drawAt: giveaway.draw_at });
        } catch (entryError) {
          try { await client.query('ROLLBACK'); } catch (_) {}
          client.release();
          if (entryError.code === '23505') return res.status(409).json({ error: 'You have already entered this giveaway.' });
          throw entryError;
        }
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'analytics') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      const userRes = await client.query('SELECT phone, username, balance, total_topup_sd, reseller_tier, registered_at FROM users WHERE phone = $1', [phone]);
      if (!userRes.rows[0]) { client.release(); return res.status(404).json({ error: 'User not found.' }); }
      const [depositsRes, serversRes, keysRes, referralsRes, chatRes, addonRes] = await Promise.all([
        client.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount_sd), 0) AS total_sd FROM deposits WHERE phone = $1 AND status = 'success'", [phone]),
        client.query("SELECT COUNT(*)::int AS count, COUNT(*) FILTER (WHERE status = 'active')::int AS active_count FROM servers WHERE phone = $1", [phone]),
        client.query('SELECT COUNT(*)::int AS count FROM keys WHERE used_number = $1 OR used_by = $1', [phone]),
        client.query('SELECT COUNT(*)::int AS count, COALESCE(SUM(reward_sd), 0) AS rewards_sd FROM referral_ledger WHERE referrer_phone = $1', [phone]),
        client.query('SELECT COUNT(*)::int AS count FROM chat_messages WHERE phone = $1', [phone]),
        client.query('SELECT COUNT(*)::int AS count, COALESCE(SUM(amount_sd), 0) AS total_sd FROM user_addons WHERE phone = $1', [phone])
      ]);
      client.release();
      return res.status(200).json({ success: true, user: userRes.rows[0], deposits: depositsRes.rows[0], servers: serversRes.rows[0], keys: keysRes.rows[0], referrals: referralsRes.rows[0], chat: chatRes.rows[0], addons: addonRes.rows[0] });
    }

    if (path === 'affiliate') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      const userRes = await client.query('SELECT phone, username, referral_code, registered_at FROM users WHERE phone = $1', [phone]);
      if (!userRes.rows[0]?.registered_at) { client.release(); return res.status(403).json({ error: 'Register first to access your referral dashboard.', requiresRegistration: true }); }
      const referralRes = await client.query('SELECT COUNT(*)::int AS referrals, COALESCE(SUM(reward_sd), 0) AS rewards_sd FROM referral_ledger WHERE referrer_phone = $1', [phone]);
      client.release();
      return res.status(200).json({ success: true, user: userRes.rows[0], referrals: referralRes.rows[0] });
    }

    if (path === 'activity') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const activityRes = await client.query(`SELECT action, details, created_at FROM activity_logs WHERE action IN ('REGISTRATION_BONUS', 'DEPOSIT_CALLBACK_SUCCESS', 'VOUCHER_REDEEM', 'SERVER_CREATE', 'SUPPORT_TICKET_CREATED', 'BALANCE_TRANSFER', 'GIFT_CARD_REDEEM', 'ADDON_PURCHASE', 'TRIAL_PANEL_CREATE', 'TRIAL_EXPIRED', 'RESELLER_BONUS') ORDER BY created_at DESC LIMIT 30`);
      const activities = activityRes.rows.map(item => ({ ...item, details: String(item.details || '').replace(/254[17]\d{8}/g, 'a verified user').replace(/\b(?:\+?254|0)?[17]\d{8}\b/g, 'a verified user') }));
      client.release();
      return res.status(200).json({ success: true, activities });
    }

    if (path === 'auto-renew') {
      const phone = normalizeKenyanPhone(method === 'POST' ? body.phone : query.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      const userRes = await client.query('SELECT phone, username, registered_at, auto_renew_enabled, balance FROM users WHERE phone = $1', [phone]);
      const user = userRes.rows[0];
      if (!user?.registered_at) { client.release(); return res.status(403).json({ error: 'Register first to manage auto-renewal.', requiresRegistration: true }); }
      if (method === 'GET') {
        const serverRes = await client.query('SELECT id, bot_type, subdomain, status, next_billing_date, auto_renew_enabled, renewal_price_sd FROM servers WHERE phone = $1 ORDER BY created_at DESC', [phone]);
        client.release();
        return res.status(200).json({ success: true, enabled: Boolean(user.auto_renew_enabled), balance: user.balance, servers: serverRes.rows });
      }
      if (method === 'POST') {
        const enabled = Boolean(body.enabled);
        await client.query('UPDATE users SET auto_renew_enabled = $1 WHERE phone = $2', [enabled, phone]);
        if (body.serverId) await client.query('UPDATE servers SET auto_renew_enabled = $1 WHERE id = $2 AND phone = $3', [enabled, Number(body.serverId), phone]);
        client.release();
        return res.status(200).json({ success: true, enabled });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'topup') {
      const { action, phone, amountSD, gateway, paymentMethod, checkoutRequestId } = body;
      const settingsRes = await client.query('SELECT * FROM site_settings');
      const dbSettings = Object.fromEntries(settingsRes.rows.map(row => [row.key, row.value]));

      if (action === 'initiate') {
        const { username } = body;
        const sd = Number(amountSD);
        const amountKsh = Math.round(sd * 5);
        if (!Number.isFinite(sd) || sd <= 0 || amountKsh < 1 || amountKsh > 70000) { client.release(); return res.status(400).json({ error: 'Top-up must convert to between KES 1 and KES 70,000.' }); }
        const fPhone = normalizeKenyanPhone(phone);
        if (!fPhone) { client.release(); return res.status(400).json({ error: 'Enter a valid Kenyan phone number.' }); }
        const selectedPayment = String(paymentMethod || gateway || 'blacklord_paybill').toLowerCase();
        const provider = selectedPayment === 'bank' ? 'bank' : selectedPayment.startsWith('blacklord') ? 'blacklord' : selectedPayment;
        const blacklordMode = selectedPayment === 'blacklord_till' ? 'till' : selectedPayment === 'blacklord_paybill' ? 'paybill' : String(process.env.BLACKLORD_STK_PAYMENT_MODE || dbSettings.BLACKLORD_STK_PAYMENT_MODE || 'paybill').toLowerCase();
        const reference = provider === 'blacklord' || provider === 'bank' ? makeBlacklordReference(fPhone) : makeCourtneyReference(fPhone);
        if (provider === 'bank') {
          await client.query('INSERT INTO deposits (reference, phone, amount_sd, amount_ksh, checkout_request_id, status, username, gateway) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [reference, phone, sd, amountKsh, reference, 'pending_bank', username || null, 'bank']);
          client.release();
          return res.status(200).json({ success: true, reference, checkoutRequestId: reference, gateway: 'bank', status: 'pending_bank', bank: { name: process.env.BANK_NAME || dbSettings.BANK_NAME || '', accountName: process.env.BANK_ACCOUNT_NAME || dbSettings.BANK_ACCOUNT_NAME || '', accountNumber: process.env.BANK_ACCOUNT_NUMBER || dbSettings.BANK_ACCOUNT_NUMBER || '', branchSwift: process.env.BANK_BRANCH_SWIFT || dbSettings.BANK_BRANCH_SWIFT || '', instructions: process.env.BANK_INSTRUCTIONS || dbSettings.BANK_INSTRUCTIONS || 'Make the transfer and send proof with the reference to Support.' } });
        }
        if (provider === 'paystack') {
          const paystackSecret = dbSettings.PAYSTACK_SECRET || process.env.PAYSTACK_SECRET;
          if (!paystackSecret) { client.release(); return res.status(503).json({ error: 'Paystack is not configured.' }); }
          const payRes = await axios.post('https://api.paystack.co/transaction/initialize', { email: `${fPhone}@blacklord.tech`, amount: amountKsh * 100, currency: 'KES', reference, callback_url: `https://${headers.host}/` }, { headers: { Authorization: `Bearer ${paystackSecret}` } });
          const checkoutId = payRes.data.data.reference;
          await client.query('INSERT INTO deposits (reference, phone, amount_sd, amount_ksh, checkout_request_id, status, username, gateway) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [reference, phone, sd, amountKsh, checkoutId, 'pending', username || null, provider]);
          client.release();
          return res.status(200).json({ success: true, reference, checkoutRequestId: checkoutId, authorizationUrl: payRes.data.data.authorization_url, gateway: provider });
        }
        if (provider === 'blacklord') {
          const config = getBlacklordConfig(dbSettings, headers);
          const stkRes = await axios.post(`${config.baseUrl}${config.initiatePath.startsWith('/') ? '' : '/'}${config.initiatePath}`, {
            phone: fPhone,
            amount: amountKsh,
            accountReference: reference,
            account_reference: reference,
            reference,
            description: `BLACKLORD wallet top-up ${sd} SD`,
            paymentMethod: blacklordMode,
            payment_mode: blacklordMode,
            businessShortcode: process.env.BLACKLORD_STK_SHORTCODE || dbSettings.BLACKLORD_STK_SHORTCODE || '',
            shortcode: process.env.BLACKLORD_STK_SHORTCODE || dbSettings.BLACKLORD_STK_SHORTCODE || '',
            tillNumber: process.env.BLACKLORD_STK_TILL_NUMBER || dbSettings.BLACKLORD_STK_TILL_NUMBER || '',
            callbackUrl: config.callbackUrl,
            callback_url: config.callbackUrl
          }, { headers: blacklordHeaders(config), timeout: 15000 });
          const checkoutId = stkRes.data.checkout_request_id || stkRes.data.checkoutRequestId || stkRes.data.data?.checkout_request_id || stkRes.data.data?.checkoutRequestId || stkRes.data.requestId;
          if (!checkoutId) { client.release(); return res.status(502).json({ error: 'Blacklord STK did not return a checkout request ID.' }); }
          await client.query('INSERT INTO deposits (reference, phone, amount_sd, amount_ksh, checkout_request_id, transaction_id, status, username, gateway) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)', [reference, phone, sd, amountKsh, checkoutId, null, 'pending', username || null, provider]);
          client.release();
          return res.status(200).json({ success: true, reference, checkoutRequestId: checkoutId, gateway: provider, message: stkRes.data.message || 'Blacklord STK Push sent.' });
        }
        const config = getCourtneyConfig(dbSettings);
        const stkRes = await axios.post(`${config.baseUrl}/v2/stkpush`, {
          payment_account_id: config.accountId,
          phone: fPhone,
          amount: amountKsh,
          reference,
          description: makeCourtneyDescription(sd)
        }, { headers: courtneyHeaders(config), timeout: 15000 });
        const checkoutId = stkRes.data.checkout_request_id || stkRes.data.checkoutRequestId;
        if (!checkoutId) { client.release(); return res.status(502).json({ error: 'Courtney Tech did not return a checkout request ID.' }); }
        await client.query('INSERT INTO deposits (reference, phone, amount_sd, amount_ksh, checkout_request_id, transaction_id, status, username, gateway) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)', [reference, phone, sd, amountKsh, checkoutId, null, 'pending', username || null, provider]);
        client.release();
        return res.status(200).json({ success: true, reference, checkoutRequestId: checkoutId, gateway: provider });
      }
      if (action === 'verify') {
        const depRes = await client.query('SELECT * FROM deposits WHERE checkout_request_id = $1', [checkoutRequestId]);
        const deposit = depRes.rows[0];
        if (!deposit) { client.release(); return res.status(404).json({ error: 'Deposit not found' }); }
        if (deposit.status === 'success') { client.release(); return res.status(200).json({ success: true, status: 'success', balanceAdded: deposit.amount_sd }); }
        const selectedPayment = String(gateway || deposit.gateway || 'courtney').toLowerCase();
        const provider = selectedPayment.startsWith('blacklord') ? 'blacklord' : selectedPayment;
        if (provider === 'paystack' || provider === 'bank') { client.release(); return res.status(200).json({ success: true, status: deposit.status }); }
        let status;
        let transactionId;
        let receipt;
        if (provider === 'blacklord') {
          const config = getBlacklordConfig(dbSettings, headers);
          const statusRes = await axios.post(`${config.baseUrl}${config.statusPath.startsWith('/') ? '' : '/'}${config.statusPath}`, { checkout_request_id: checkoutRequestId, checkoutRequestId, reference: deposit.reference }, { headers: blacklordHeaders(config), timeout: 15000 });
          const parsed = providerStatus(statusRes.data);
          status = parsed.status;
          transactionId = parsed.transactionId;
          receipt = parsed.transactionId;
        } else {
          const config = getCourtneyConfig(dbSettings);
          const statusRes = await axios.post(`${config.baseUrl}/v2/status`, { checkout_request_id: checkoutRequestId }, { headers: courtneyHeaders(config), timeout: 15000 });
          status = String(statusRes.data.status || 'pending').toLowerCase();
          transactionId = statusRes.data.transactionId || statusRes.data.transaction_id;
          receipt = statusRes.data.mpesaReceipt || statusRes.data.mpesa_receipt;
        }
        if (transactionId) await client.query('UPDATE deposits SET transaction_id = $1 WHERE reference = $2', [transactionId, deposit.reference]);
        if (status === 'completed') {
          await creditDeposit(client, deposit, receipt);
          client.release();
          return res.status(200).json({ success: true, status: 'success', balanceAdded: deposit.amount_sd });
        }
        if (status === 'failed' || status === 'cancelled') await client.query('UPDATE deposits SET status = $1 WHERE checkout_request_id = $2', [status, checkoutRequestId]);
        client.release();
        return res.status(200).json({ success: true, status });
      }
    }

    if (path === 'servers') {
      const phone = method === 'POST' ? body.phone : query.phone;
      const action = method === 'POST' ? body.action : 'list';
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      if (action === 'list') { const srvRes = await client.query('SELECT * FROM servers WHERE phone = $1 ORDER BY created_at DESC', [phone]); client.release(); return res.status(200).json({ success: true, servers: srvRes.rows }); }
    }

    if (path === 'settings') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const result = await client.query("SELECT key, value FROM site_settings WHERE key LIKE 'TELEGRAM_%'");
      client.release();
      const settings = {};
      result.rows.forEach(row => { settings[row.key] = row.value; });
      return res.status(200).json({ success: true, settings });
    }

    if (path === 'keys') {
      const action = String(method === 'GET' ? (query.action || 'list') : (body.action || 'generate')).toLowerCase();

      if (method === 'POST' && (action === 'validate' || action === 'consume')) {
        const telegramKeySecret = process.env.TELEGRAM_KEY_API_SECRET || '';
        const suppliedSecret = headers['x-telegram-key-secret'] || headers['X-Telegram-Key-Secret'] || body.telegramKeySecret || '';
        if (telegramKeySecret && !secretMatches(suppliedSecret, telegramKeySecret)) { client.release(); return res.status(401).json({ success: false, valid: false, error: 'Telegram key service authentication failed.' }); }
        const suppliedKey = String(body.key || '').trim().toUpperCase();
        const telegramUser = String(body.telegramUser || body.telegramUsername || body.telegramId || '').trim().slice(0, 120) || null;
        const requestedType = body.botType ? normalizeKeyType(body.botType) : null;
        if (!suppliedKey) { client.release(); return res.status(400).json({ error: 'Activation key is required.' }); }
        const keyRes = await client.query('SELECT key, type, used_number, used_by, used_at, expires_at, issued_for, telegram_user, created_at FROM keys WHERE key = $1 LIMIT 1', [suppliedKey]);
        const record = keyRes.rows[0];
        if (!record) { client.release(); return res.status(404).json({ success: false, valid: false, error: 'Activation key not found.' }); }
        const expired = record.expires_at && new Date(record.expires_at).getTime() <= Date.now();
        const typeMismatch = requestedType && record.type !== requestedType;
        if (expired || record.used_at || typeMismatch) {
          client.release();
          return res.status(409).json({ success: false, valid: false, error: expired ? 'Activation key has expired.' : record.used_at ? 'Activation key has already been used.' : 'Activation key is for a different bot type.' });
        }
        if (action === 'validate') {
          client.release();
          return res.status(200).json({ success: true, valid: true, key: record.key, botType: record.type, expiresAt: record.expires_at, issuedFor: record.issued_for });
        }
        const consumed = await client.query("UPDATE keys SET used_by = $1, used_at = CURRENT_TIMESTAMP WHERE key = $2 AND used_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) RETURNING key, type, used_number, used_by, used_at, expires_at", [telegramUser || 'telegram-bot', suppliedKey]);
        client.release();
        if (!consumed.rows[0]) return res.status(409).json({ success: false, valid: false, error: 'Activation key was already claimed.' });
        return res.status(200).json({ success: true, valid: true, consumed: true, key: consumed.rows[0] });
      }

      const phone = normalizeKenyanPhone(method === 'GET' ? query.phone : body.phone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'A valid Kenyan phone number is required.' }); }

      if (method === 'GET' || action === 'list') {
        const result = await client.query('SELECT key, type, issued_for, telegram_user, used_by, used_at, expires_at, created_at FROM keys WHERE used_number = $1 OR telegram_user = $1 ORDER BY created_at DESC LIMIT 30', [phone]);
        client.release();
        return res.status(200).json({ success: true, keys: result.rows });
      }

      if (action !== 'generate') { client.release(); return res.status(400).json({ error: 'Unsupported key action.' }); }
      const botType = normalizeKeyType(body.botType);
      const telegramUser = String(body.telegramUser || body.telegramUsername || body.telegramId || '').trim().slice(0, 120) || null;
      const durationDays = Math.min(365, Math.max(1, Number(body.durationDays || 30)));
      if (!botType) { client.release(); return res.status(400).json({ error: 'Choose a supported bot type.' }); }
      if (!Number.isFinite(durationDays)) { client.release(); return res.status(400).json({ error: 'Duration must be between 1 and 365 days.' }); }
      const userRes = await client.query('SELECT phone FROM users WHERE phone = $1 LIMIT 1', [phone]);
      if (!userRes.rows[0]) { client.release(); return res.status(404).json({ error: 'Create or load your account before generating a Telegram key.' }); }

      let created = null;
      for (let attempt = 0; attempt < 5 && !created; attempt += 1) {
        const generated = activationKey(botType);
        const result = await client.query("INSERT INTO keys (key, type, used_number, expires_at, issued_for, telegram_user) VALUES ($1, $2, $3, CURRENT_TIMESTAMP + ($4 * INTERVAL '1 day'), 'telegram', $5) ON CONFLICT (key) DO NOTHING RETURNING key, type, issued_for, telegram_user, expires_at, created_at", [generated, botType, phone, durationDays, telegramUser]);
        created = result.rows[0] || null;
      }
      if (!created) { client.release(); return res.status(500).json({ error: 'Could not generate a unique activation key. Try again.' }); }
      await client.query('INSERT INTO activity_logs (action, details) VALUES ($1, $2)', ['TELEGRAM_KEY_GENERATED', `${created.type} key generated for ${phone}.`]);
      client.release();
      return res.status(201).json({ success: true, key: created, message: 'Telegram activation key generated. Send it to the Telegram bot exactly as shown.' });
    }

    if (path === 'admin/sessions') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const adminSecret = headers['x-admin-secret'] || headers['X-Admin-Secret'] || query.adminSecret || '';
      const expectedAdminSecret = process.env.ADMIN_SECRET || 'blacklord254admin';
      if (!secretMatches(adminSecret, expectedAdminSecret)) {
        client.release();
        return res.status(401).json({ error: 'Unauthorized: Admin secret key required.' });
      }
      const sessionsRes = await client.query(`
        SELECT request_id, whatsapp_phone, bot_type, status, bot_session_id, linked_at, created_at, updated_at
        FROM pairing_requests
        WHERE status IN ('connected', 'active', 'completed', 'paired', 'waiting')
        ORDER BY updated_at DESC
        LIMIT 50
      `);
      const usersRes = await client.query('SELECT COUNT(*) as total_users FROM users');
      const pairingsCountRes = await client.query('SELECT COUNT(*) as total_pairings FROM pairing_requests');
      client.release();
      return res.status(200).json({
        success: true,
        uptimeSeconds: Math.floor(process.uptime()),
        totalUsers: Number(usersRes.rows[0]?.total_users || 0),
        totalPairings: Number(pairingsCountRes.rows[0]?.total_pairings || 0),
        sessions: sessionsRes.rows
      });
    }

    if (path === 'dashboard') {
      const phone = String(method === 'GET' ? query.phone : body.phone || '').trim();
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }
      const userRes = await client.query('SELECT phone, username, balance, created_at, reseller_tier, reseller_bonus_percent, total_topup_sd, registered_at FROM users WHERE phone = $1', [phone]);
      const keyRes = await client.query('SELECT key, type, created_at, expires_at FROM keys WHERE used_number = $1 OR used_by = $1 ORDER BY created_at DESC LIMIT 12', [phone]);
      const serverRes = await client.query('SELECT id, username, bot_type, subdomain, status, next_billing_date, created_at FROM servers WHERE phone = $1 ORDER BY created_at DESC LIMIT 12', [phone]);
      const depositRes = await client.query("SELECT reference, amount_sd, amount_ksh, status, created_at FROM deposits WHERE phone = $1 ORDER BY created_at DESC LIMIT 12", [phone]);
      const ticketRes = await client.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status = 'open')::int AS open_count FROM support_tickets WHERE phone = $1", [phone]);
      client.release();
      return res.status(200).json({
        success: true,
        user: userRes.rows[0] || { phone, username: null, balance: 0, created_at: null },
        keys: keyRes.rows,
        servers: serverRes.rows,
        deposits: depositRes.rows,
        support: ticketRes.rows[0] || { total: 0, open: 0 }
      });
    }

    if (path === 'support') {
      const phone = String(method === 'GET' ? query.phone : body.phone || '').trim();
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone required' }); }

      if (method === 'GET') {
        const ticketId = query.ticketId ? Number(query.ticketId) : null;
        if (ticketId) {
          const ticketRes = await client.query('SELECT * FROM support_tickets WHERE id = $1 AND phone = $2', [ticketId, phone]);
          if (ticketRes.rows.length === 0) { client.release(); return res.status(404).json({ error: 'Ticket not found' }); }
          const messageRes = await client.query('SELECT * FROM support_messages WHERE ticket_id = $1 ORDER BY created_at ASC', [ticketId]);
          client.release();
          return res.status(200).json({ success: true, ticket: ticketRes.rows[0], messages: messageRes.rows });
        }
        const result = await client.query('SELECT * FROM support_tickets WHERE phone = $1 ORDER BY updated_at DESC, created_at DESC', [phone]);
        client.release();
        return res.status(200).json({ success: true, tickets: result.rows });
      }

      if (method === 'POST') {
        const action = String(body.action || 'create');
        if (action === 'message') {
          const ticketId = Number(body.ticketId);
          const message = String(body.message || '').trim();
          if (!Number.isInteger(ticketId) || !message || message.length > 4000) { client.release(); return res.status(400).json({ error: 'Valid ticket and message required' }); }
          const ticketRes = await client.query('SELECT * FROM support_tickets WHERE id = $1 AND phone = $2', [ticketId, phone]);
          if (ticketRes.rows.length === 0) { client.release(); return res.status(404).json({ error: 'Ticket not found' }); }
          await client.query('INSERT INTO support_messages (ticket_id, sender_type, sender_name, body) VALUES ($1, $2, $3, $4)', [ticketId, 'user', body.username || phone, message]);
          await client.query("UPDATE support_tickets SET status = 'open', updated_at = CURRENT_TIMESTAMP WHERE id = $1", [ticketId]);
          client.release();
          return res.status(200).json({ success: true });
        }
        const subject = String(body.subject || '').trim();
        const message = String(body.message || '').trim();
        const category = String(body.category || 'General').trim().slice(0, 40);
        if (subject.length < 3 || subject.length > 120 || !message || message.length > 4000) { client.release(); return res.status(400).json({ error: 'Subject and message are required' }); }
        const ticketRes = await client.query('INSERT INTO support_tickets (phone, username, subject, category, priority, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [phone, body.username || null, subject, category, 'normal', 'open']);
        const ticket = ticketRes.rows[0];
        await client.query('INSERT INTO support_messages (ticket_id, sender_type, sender_name, body) VALUES ($1, $2, $3, $4)', [ticket.id, 'user', body.username || phone, message]);
        logActivity('SUPPORT_TICKET_CREATED', `Ticket #${ticket.id} created by ${body.username || phone}: ${subject}`);
        sendTelegramNotification(`🆘 New support ticket #${ticket.id}\nUser: ${body.username || phone}\nSubject: ${subject}`);
        client.release();
        return res.status(201).json({ success: true, ticket });
      }
      client.release();
      return res.status(405).json({ error: 'Method not allowed' });
    }

    if (path === 'status') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const result = await client.query("SELECT slug, name, category, status, uptime, region, last_ping_ms, last_ping_at, notes, updated_at FROM bot_status WHERE slug NOT IN ('mzazi', 'nxra') ORDER BY name ASC");
      client.release();
      return res.status(200).json({ success: true, bots: result.rows, checkedAt: new Date().toISOString() });
    }

    if (path === 'admin/vouchers') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const { adminKey, amount } = body;
      const expectedAdminKey = process.env.ADMIN_SECRET_KEY || 'blacklord254admin';
      if (!adminKey || adminKey !== expectedAdminKey) {
        client.release();
        return res.status(401).json({ error: 'Unauthorized: Invalid administrator key.' });
      }
      const voucherAmount = parseFloat(amount) || 10.00;
      const voucherCode = 'BLK-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
      await client.query('INSERT INTO vouchers (code, amount, is_used, created_by) VALUES ($1, $2, FALSE, $3)', [voucherCode, voucherAmount, 'admin']);
      logActivity('ADMIN_VOUCHER_GEN', `Admin generated voucher ${voucherCode} for ${voucherAmount} USD.`);
      sendTelegramNotification(`🎟️ *New Voucher Generated by Admin*\nCode: \`${voucherCode}\`\nAmount: *$${voucherAmount} USD*`);
      client.release();
      return res.status(201).json({ success: true, code: voucherCode, amount: voucherAmount });
    }

    // ADVANCED APIS: BAN & MEDIA
    if (path === 'advanced/ban') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const { targetPhone, reason, adminPhone } = body;
      if (!targetPhone) { client.release(); return res.status(400).json({ error: 'Target phone required' }); }
      await client.query('INSERT INTO global_bans (phone, reason, banned_by) VALUES ($1, $2, $3) ON CONFLICT (phone) DO UPDATE SET reason = $2, banned_by = $3', [targetPhone, reason || 'Violation of bot terms', adminPhone || 'system']);
      const mediaRes = await client.query("SELECT url, title FROM media_library WHERE media_type IN ('song', 'video', 'gif') ORDER BY RANDOM() LIMIT 1");
      client.release();
      return res.status(200).json({ success: true, message: `User ${targetPhone} has been globally banned.`, media: mediaRes.rows[0] || { url: 'https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3', title: 'Default Ban Anthem' } });
    }

    // ADVANCED APIS: SMART BOT AI AUTO-RESPONSE
    if (path === 'advanced/ai-response') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const { prompt, botTone } = body;
      const responseText = `Blacklord AI (${botTone || 'friendly'}): I have processed your query regarding "${prompt || 'hello'}". All systems are operational on Pterodactyl.`;
      client.release();
      return res.status(200).json({ success: true, response: responseText });
    }

    // ADVANCED APIS: REMOTE BOT POWER CONTROL
    if (path === 'advanced/bot-control') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const { serverId, action } = body; // action: start, stop, restart
      if (!serverId || !['start', 'stop', 'restart'].includes(action)) { client.release(); return res.status(400).json({ error: 'Valid serverId and action required' }); }
      const config = getPairingConfig();
      if (!config.panelUrl || !config.clientApiKey) { client.release(); return res.status(503).json({ error: 'Panel not configured' }); }
      try {
        await axios.post(`${config.panelUrl}/api/client/servers/${serverId}/power`, { signal: action }, {
          headers: { Authorization: `Bearer ${config.clientApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json', 'Content-Type': 'application/json' },
          timeout: 10000
        });
        client.release();
        return res.status(200).json({ success: true, message: `Server ${serverId} power action '${action}' sent successfully.` });
      } catch (err) {
        client.release();
        return res.status(502).json({ error: err.response?.data?.errors?.[0]?.detail || err.message });
      }
    }

    // (The routes continue below)


    if (path === 'bot-config') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const phone = normalizeKenyanPhone(query.phone || query.whatsappPhone);
      if (!phone) { client.release(); return res.status(400).json({ error: 'Phone number required' }); }

      const serverRes = await client.query('SELECT server_id, bot_type, status FROM servers WHERE phone = $1 AND status NOT IN (\'suspended\', \'deleted\') ORDER BY created_at DESC LIMIT 1', [phone]);
      if (serverRes.rows[0]) {
        client.release();
        return res.status(200).json({ success: true, botType: serverRes.rows[0].bot_type || 'blacklord', serverId: serverRes.rows[0].server_id });
      }

      const pairingRes = await client.query('SELECT bot_type, server_id FROM pairing_requests WHERE whatsapp_phone = $1 ORDER BY created_at DESC LIMIT 1', [phone]);
      client.release();
      if (pairingRes.rows[0]) {
        return res.status(200).json({ success: true, botType: pairingRes.rows[0].bot_type || 'blacklord', serverId: pairingRes.rows[0].server_id });
      }

      return res.status(200).json({ success: true, botType: 'blacklord' });
    }

    if (path === 'marketplace/plugins') {
      if (method === 'GET') {
        const pluginsRes = await client.query('SELECT id, name, description, price_sd, category, author FROM marketplace_plugins ORDER BY id ASC');
        client.release();
        return res.status(200).json({ success: true, plugins: pluginsRes.rows });
      }
      if (method === 'POST') {
        const user = await sessionUser(client, req);
        if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Log in required' }); }
        const pluginId = Number(body.pluginId);
        const pluginRes = await client.query('SELECT price_sd FROM marketplace_plugins WHERE id = $1', [pluginId]);
        if (!pluginRes.rows[0]) { client.release(); return res.status(404).json({ error: 'Plugin not found' }); }
        const price = Number(pluginRes.rows[0].price_sd);
        if (Number(user.balance) < price) { client.release(); return res.status(400).json({ error: 'Insufficient SD balance' }); }
        await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [price, user.phone]);
        await client.query('INSERT INTO user_plugins (phone, plugin_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [user.phone, pluginId]);
        client.release();
        return res.status(200).json({ success: true, message: 'Plugin purchased and installed successfully!' });
      }
    }

    if (path === 'analytics') {
      if (method !== 'GET') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Log in required' }); }
      const analyticsRes = await client.query('SELECT messages_count, commands_executed, uptime_percentage, recorded_at FROM bot_analytics WHERE phone = $1 ORDER BY recorded_at DESC LIMIT 30', [user.phone]);
      client.release();
      return res.status(200).json({ success: true, analytics: analyticsRes.rows });
    }

    if (path === 'reseller') {
      if (method === 'GET') {
        const user = await sessionUser(client, req);
        if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Log in required' }); }
        const resProfile = await client.query('SELECT brand_name, logo_url, custom_domain FROM reseller_profiles WHERE phone = $1', [user.phone]);
        client.release();
        return res.status(200).json({ success: true, profile: resProfile.rows[0] || null });
      }
      if (method === 'POST') {
        const user = await sessionUser(client, req);
        if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Log in required' }); }
        const { brandName, logoUrl, customDomain } = body;
        await client.query(`
          INSERT INTO reseller_profiles (phone, brand_name, logo_url, custom_domain)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (phone) DO UPDATE SET brand_name = $2, logo_url = $3, custom_domain = $4
        `, [user.phone, brandName, logoUrl, customDomain]);
        client.release();
        return res.status(200).json({ success: true, message: 'Reseller profile updated successfully!' });
      }
    }


    if (path === 'servers/provision') {
      if (method !== 'POST') { client.release(); return res.status(405).json({ error: 'Method not allowed' }); }
      const user = await sessionUser(client, req);
      if (!user?.registered_at) { client.release(); return res.status(401).json({ error: 'Authentication required. Please log in before purchasing a hosting panel.' }); }

      const { planId, planName, priceSD } = body;
      const cost = Number(priceSD || 10);

      // Check balance
      const userRes = await client.query('SELECT balance FROM users WHERE phone = $1', [user.phone]);
      const currentBalance = Number(userRes.rows[0]?.balance || 0);
      if (currentBalance < cost) {
        client.release();
        return res.status(400).json({ error: `Insufficient wallet balance (${currentBalance} SD). You need ${cost} SD for ${planName || 'this panel'}. Please top up your wallet.` });
      }

      const config = getPairingConfig();
      if (!config.panelUrl || !config.applicationApiKey) {
        client.release();
        return res.status(503).json({ error: 'Pterodactyl panel application API is not configured on this server.' });
      }

      try {
        // Deduct balance
        await client.query('UPDATE users SET balance = balance - $1 WHERE phone = $2', [cost, user.phone]);

        // Provision on Pterodactyl Application API
        // Find default node and egg
        const nodeRes = await axios.get(`${config.panelUrl}/api/application/nodes`, {
          headers: { Authorization: `Bearer ${config.applicationApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json' },
          timeout: 10000
        });
        const nodeId = config.nodeId || nodeRes.data.data?.[0]?.attributes?.id || 1;

        // Create or find user on Pterodactyl
        let pteroUserId;
        try {
          const userSearch = await axios.get(`${config.panelUrl}/api/application/users?filter[email]=${encodeURIComponent(user.phone + '@blacklord.tech')}`, {
            headers: { Authorization: `Bearer ${config.applicationApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json' },
            timeout: 10000
          });
          if (userSearch.data.data && userSearch.data.data.length > 0) {
            pteroUserId = userSearch.data.data[0].attributes.id;
          } else {
            const newUserRes = await axios.post(`${config.panelUrl}/api/application/users`, {
              email: `${user.phone}@blacklord.tech`,
              username: `user_${user.phone.slice(-6)}_${Date.now().toString().slice(-4)}`,
              first_name: 'Blacklord',
              last_name: 'User',
              password: crypto.randomBytes(10).toString('hex') + 'A1!'
            }, {
              headers: { Authorization: `Bearer ${config.applicationApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json', 'Content-Type': 'application/json' },
              timeout: 10000
            });
            pteroUserId = newUserRes.data.attributes.id;
          }
        } catch (uErr) {
          pteroUserId = 1; // fallback
        }

        // Server specs
        let memory = 1024, disk = 10240, cpu = 40;
        if (cost >= 100) { memory = 0; disk = 0; cpu = 0; } // unlimited
        else if (cost >= 60) { memory = 8192; disk = 80000; cpu = 400; }
        else if (cost >= 40) { memory = 4096; disk = 40000; cpu = 200; }
        else if (cost >= 20) { memory = 2048; disk = 20000; cpu = 100; }

        const serverRes = await axios.post(`${config.panelUrl}/api/application/servers`, {
          name: `${planName || 'Blacklord Server'} - ${user.phone.slice(-4)}`,
          user: pteroUserId,
          egg: Number(config.eggId || 1),
          docker_image: 'ghcr.io/parkervcp/yolks:nodejs_18',
          startup: 'npm start',
          environment: { INST: 'npm', USER_UPLOAD: '0', AUTO_UPDATE: '0', CPANEL: '0' },
          limits: { memory, swap: 0, disk, io: 500, cpu },
          feature_limits: { databases: 2, backups: 2, allocations: 1 },
          allocation: { default: Number(config.allocationId || 1) }
        }, {
          headers: { Authorization: `Bearer ${config.applicationApiKey}`, Accept: 'Application/vnd.pterodactyl.v1+json', 'Content-Type': 'application/json' },
          timeout: 15000
        });

        const serverData = serverRes.data.attributes;
        const serverId = serverData.id;
        const identifier = serverData.identifier;

        // Record in database
        await client.query(`
          INSERT INTO servers (phone, server_id, identifier, bot_type, status, name, memory, disk, cpu)
          VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8)
        `, [user.phone, serverId, identifier, 'blacklord', planName || 'Hosting Panel', memory, disk, cpu]);

        client.release();
        return res.status(200).json({
          success: true,
          message: `Successfully provisioned ${planName || 'Hosting Panel'}!`,
          server: { serverId, identifier, name: planName, status: 'active' }
        });
      } catch (provErr) {
        // Refund if failed
        await client.query('UPDATE users SET balance = balance + $1 WHERE phone = $2', [cost, user.phone]);
        client.release();
        return res.status(502).json({ error: provErr.response?.data?.errors?.[0]?.detail || provErr.message || 'Pterodactyl panel provisioning failed.' });
      }
    }

    client.release();
    return res.status(404).json({ error: 'User route not found' });
  } catch (error) {
    console.error(error);
    return res.status(error.statusCode || error.response?.status || 500).json({ error: error.response?.data?.message || error.message || 'Internal server error' });
  }
}
