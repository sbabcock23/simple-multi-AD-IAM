const { verifyToken } = require('./auth');
const cryptoHelper = require('./crypto');
const logger = require('./logger');

function requireAdminAuth(req, res, next) {
  const token = req.cookies.admin_token;
  const data = token && verifyToken(token);
  if (!data || data.role !== 'admin') {
    logger.debug('admin_auth_rejected', { requestId: req.id, path: req.path, reason: token ? 'invalid_or_expired_token' : 'no_token' });
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.admin = data;
  next();
}

function requireUserAuth(req, res, next) {
  const token = req.cookies.user_token;
  const data = token && verifyToken(token);
  if (!data || data.role !== 'user') {
    logger.debug('user_auth_rejected', { requestId: req.id, path: req.path, reason: token ? 'invalid_or_expired_token' : 'no_token' });
    return res.status(401).json({ error: 'Not authenticated' });
  }
  let password;
  try {
    password = cryptoHelper.decrypt(data.pwd);
  } catch (e) {
    // Most commonly caused by ENCRYPTION_KEY having changed since the
    // session cookie was issued (e.g. after redeploying with a new key).
    logger.warn('session_decrypt_failed', { requestId: req.id, username: data.username, ...logger.errInfo(e) });
    return res.status(401).json({ error: 'Session invalid, please sign in again' });
  }
  // The user's own AD credentials, cached only inside their signed, httpOnly
  // session cookie (encrypted at rest with ENCRYPTION_KEY) so every
  // directory operation can be performed as them rather than a stored
  // service account.
  req.user = { username: data.username, domainId: data.domainId, password };
  next();
}

module.exports = { requireAdminAuth, requireUserAuth };
