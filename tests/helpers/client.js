'use strict';

/** Minimal cookie-jar HTTP client over fetch (Node >= 18). */
class Client {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.jar = new Map();
  }

  cookieHeader() {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  _store(setCookie) {
    const [pair, ...attrs] = setCookie.split(';').map((s) => s.trim());
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx);
    const value = pair.slice(idx + 1);
    const lower = attrs.map((a) => a.toLowerCase());
    const expired = lower.some((a) => a === 'max-age=0' || (a.startsWith('expires=') && Date.parse(a.slice(8)) < Date.now()));
    if (!value || expired) this.jar.delete(name); else this.jar.set(name, value);
  }

  /** opts: { json, raw, headers, redirect, cookies, timeoutMs } */
  async request(method, urlPath, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    let body;
    const bodyless = method === 'GET' || method === 'HEAD';
    if (opts.json !== undefined && !bodyless) { headers['content-type'] = 'application/json'; body = JSON.stringify(opts.json); }
    if (opts.raw !== undefined && !bodyless) body = opts.raw;
    if (opts.cookies !== false && this.jar.size && !headers.cookie) headers.cookie = this.cookieHeader();
    const res = await fetch(this.baseUrl + urlPath, {
      method, headers, body, redirect: opts.redirect || 'manual',
      signal: AbortSignal.timeout(opts.timeoutMs || 15000), // a hung request must fail the test, not hang the suite
    });
    const setCookie = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    if (opts.cookies !== false) setCookie.forEach((c) => this._store(c));
    const text = await res.text();
    let parsed = text;
    try { parsed = JSON.parse(text); } catch (e) { /* not json */ }
    return { status: res.status, headers: res.headers, body: parsed, text, setCookie };
  }

  get(p, o) { return this.request('GET', p, o); }
  post(p, json, o) { return this.request('POST', p, { ...(o || {}), json }); }
  put(p, json, o) { return this.request('PUT', p, { ...(o || {}), json }); }
  del(p, o) { return this.request('DELETE', p, o); }

  /** Copy of this client carrying the same cookies (e.g. to model a second browser tab). */
  clone() { const c = new Client(this.baseUrl); c.jar = new Map(this.jar); return c; }
}

module.exports = { Client };
