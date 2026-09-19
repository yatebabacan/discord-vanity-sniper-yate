"use strict";
const http2 = require('http2');
const tls = require('tls');
const WebSocket = require('ws');
const fs = require('fs');
const token = "asdasds123";
const guildid = 'qwe';
const API_HOST = 'canary.discord.com';
const SESSION_COUNT = 8;
const TLS_COUNT = 8;
let mfaToken = null;
const vanityCache = new Map();

const identifyBuffer = JSON.stringify({op: 2,d: { token, intents: 1, properties: { os: 'linux', browser: 'chrome', device: 'chrome' }, guild_subscriptions: false, large_threshold: 0}});
const heartbeatBuffer = '{"op":1,"d":null}';
function readMfa() {const data = fs.readFileSync("mfa.txt", "utf8").trim();if (data && data !== mfaToken) {mfaToken = data;console.log("[MFA] Token guncellendi");}}
fs.watch("mfa.txt", (eventType) => {if (eventType === "change") readMfa();});
const h2Conns = new Array(SESSION_COUNT);
const tlsSocks = new Array(TLS_COUNT).fill({ write() {}, destroyed: true });
const tlsBackoff = new Array(TLS_COUNT).fill(500);
let tlsSession = undefined;

const createH2Session = (i) => {
    const session = http2.connect('https://canary.discord.com:443', {
        maxVersion: 'TLSv1.3',
        minVersion: 'TLSv1.3', ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384',
        ecdhCurve: 'X25519', ALPNProtocols: ['h2'], rejectUnauthorized: false,
        highWaterMark: 32 * 1024, peerMaxConcurrentStreams: 1000,
        paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
        maxConcurrentStreams: 200, enablePush: false, initialWindowSize: 4 * 1024 * 1024,
        maxFrameSize: 4 * 1024 * 1024, headerTableSize: 16384, maxHeaderListSize: 32768
    });
    session.ref();
    session.once('connect', () => {
        console.log(`[HTTP2] Session ${i} connected`);
        try {
            const req = session.request({
                ':method': 'GET',
                ':path': '/api/v9/gateway',
                ':scheme': 'https',
                ':authority': 'canary.discord.com',
            });
            req.on('error', () => {});
            req.end();
        } catch (e) {}
    });
    session.on('error', (err) => {console.error(`[HTTP2] Session ${i} error:`, err.message);setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100);});
    session.on('close', () => {console.warn(`[HTTP2] Session ${i} closed`);setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100);});
    return session;
};

function createTLS(i) {
    const s = tls.connect({
        host: "canary.discord.com", port: 443, servername: "canary.discord.com",
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
        ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
        ecdhCurve: "X25519:prime256v1:secp384r1",
        ALPNProtocols: ["http/1.1"],
        rejectUnauthorized: false,
        honorCipherOrder: true,
        session: tlsSession,
        highWaterMark: 1024 * 1024,
        handshakeTimeout: 4000,
        timeout: 0
    });
    s.setNoDelay(true);
    s.setKeepAlive(true, 15000);
    s.on("session", sess => { tlsSession = sess; });
    s.on("secureConnect", () => {
        tlsSocks[i] = s;
        tlsBackoff[i] = 500;
        s.write('\r\n');
        console.log(`tls[${i}] established`);
    });
    s.on("data", buf => {
        try {
            const json = JSON.parse(buf.toString("latin1").split("\r\n\r\n")[1] || "");
            if (json && json.code) console.log(`tls[${i}]:`, JSON.stringify(json));
        } catch {}
    });
    s.on("timeout", () => { s.destroy(); });
    s.on("error", err => console.log(`tls[${i}] error:`, err.message));
    s.on("close", () => {
        tlsSocks[i] = { write() {}, destroyed: true };
        setTimeout(createTLS, tlsBackoff[i], i);
        tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 5000);
    });
}
for (let i = 0; i < TLS_COUNT; i++) createTLS(i);
for (let i = 0; i < SESSION_COUNT; i++) h2Conns[i] = createH2Session(i);

function buildRequest(vanity) {
    const body = '{"code":"' + vanity + '"}';
    const bodyy = Buffer.from(body, "latin1");
    const len = bodyy.length;
    return () => {
        const tlsBuf = Buffer.from(
            `PATCH /api/v9/guilds/${guildid}/vanity-url HTTP/1.1\r\n` +
            `Host: canary.discord.com\r\n` +
            `Authorization: ${token}\r\n` +
            `Content-Type: application/json\r\n` +
            `Accept-Encoding: identity\r\n` +
            `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n` +
            `X-Super-Properties: "eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0="\r\n` +
            `X-Discord-Mfa-Authorization: ${mfaToken}\r\n` +
            `Content-Length: ${len}\r\n\r\n` + body,
            "latin1"
        );
        for (let i = h2Conns.length - 1; i >= 0; i--) {
            try {
                if (!h2Conns[i] || h2Conns[i].destroyed) continue;
                const req = h2Conns[i].request({
                    ':method': 'PATCH',
                    ':path': `/api/v9/guilds/${guildid}/vanity-url`,
                    ':authority': 'canary.discord.com',
                    'authorization': token,
                    'content-type': 'application/json',
                    "accept-encoding": 'identity',
                    'content-length': len,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'x-super-properties': 'eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=',
                    'x-discord-mfa-authorization': mfaToken,
                });
                let resp = '';
                req.on('data', chunk => { resp += chunk.toString('latin1'); });
                req.on('end', () => { if (resp.includes('code')) console.log(`h2[${i}]:`, resp); });
                req.on('error', () => {});
                req.end(bodyy);
            } catch (e) {
                // session destroyed mid-request
            }
        }
        for (let i = TLS_COUNT - 1; i >= 0; i--) {
            try {
                tlsSocks[i].write(tlsBuf);
            } catch (e) {}
        }
    };
}

function extractStr(data, key) {
    const i = data.indexOf(key);
    if (i === -1) return null;
    const start = i + key.length;
    const end = data.indexOf('"', start);
    if (end === -1) return null;
    return data.slice(start, end);
}

function handleGuildUpdate(data) {
    try {
        const gid = extractStr(data, '"id":"');
        if (!gid) return;
        const entry = vanityCache.get(gid);
        if (!entry) return;

        const vanityKey = '"vanity_url_code":"';
        const vIdx = data.indexOf(vanityKey);
        let newCode = null;
        if (vIdx !== -1) {
            const vStart = vIdx + vanityKey.length;
            const vEnd = data.indexOf('"', vStart);
            newCode = data.slice(vStart, vEnd);
        }
        if (!newCode || newCode === "null" || newCode !== entry[0]) {
            entry[1]();
        }
    } catch (e) {}
}

// YENI: GUILD_POWERUP_ENTITLEMENTS_DELETE handler
function handlePowerupDelete(data) {
    try {
        const gid = extractStr(data, '"guild_id":"');
        if (!gid) return;
        const entry = vanityCache.get(gid);
        if (!entry) return;
        // Powerup (boost) entitlement silindi -> hemen claim at
        entry[1]();
    } catch (e) {}
}

setInterval(() => {for (let i = h2Conns.length - 1; i >= 0; i--) {if (h2Conns[i] && !h2Conns[i].destroyed) h2Conns[i].ping(Buffer.alloc(8), (err) => {if (err);});}}, 30000);
setInterval(() => {for (let i = TLS_COUNT - 1; i >= 0; i--) {if (!tlsSocks[i].destroyed) {const endpoint = i % 2 === 0 ? '/api/v9/gateway' : '/';const req = `GET ${endpoint} HTTP/1.1\r\nhost: canary.discord.com\r\nconnection: keep-alive\r\n\r\n`;try { tlsSocks[i].write(req); } catch(e) {}}}}, 15000);

function connectGateway(url) {
    const sock = new WebSocket(url, {
        perMessageDeflate: false, skipUTF8Validation: true,
        followRedirects: false, rejectUnauthorized: false, maxRedirects: 0,
        handshakeTimeout: 30000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    });
    let hbTimer = null;
    let hbAcked = true;
    let pingTimer = null;
    sock.onopen = () => { if (sock.readyState === WebSocket.OPEN) sock.send(identifyBuffer); };
    sock.onmessage = (msg) => {
        try {
            let data = msg.data;
            if (Buffer.isBuffer(data)) data = data.toString('utf-8');

            // YENI: GUILD_POWERUP_ENTITLEMENTS_DELETE kontrolu
            if (data.indexOf('GUILD_POWERUP_ENTITLEMENTS_DELETE') !== -1) {
                handlePowerupDelete(data);
                return;
            }

            if (data.indexOf('GUILD_UPDATE') !== -1) {
                handleGuildUpdate(data);
                return;
            }
            if (data.indexOf('READY') !== -1) {
                const d = JSON.parse(data).d;
                const guilds = d.guilds;
                for (let i = 0; i < guilds.length; i++) {
                    const g = guilds[i];
                    if (g.vanity_url_code) vanityCache.set(g.id, [g.vanity_url_code, buildRequest(g.vanity_url_code)]);
                }
                readMfa();
                console.log('[READY]', vanityCache.size, 'vanity URLs cached');
                return;
            }
            if (data.indexOf('"op":0') !== -1) return;
            const p = JSON.parse(data);
            if (p.op === 11) { hbAcked = true; return; }
            if (p.op === 7 || p.op === 9) { sock.close(); return; }
            if (p.op === 10) {
                clearInterval(hbTimer);
                hbAcked = true;
                hbTimer = setInterval(() => {
                    if (sock.readyState !== WebSocket.OPEN) return;
                    if (!hbAcked) return sock.terminate();
                    try { hbAcked = false; sock.send(heartbeatBuffer); } catch(e) {}
                }, p.d.heartbeat_interval);
            }
        } catch (e) {
            // ignore malformed gateway messages
        }
    };
    sock.onerror = () => sock.close();
    sock.onclose = () => {
        clearInterval(hbTimer);
        clearInterval(pingTimer);
        setTimeout(() => connectGateway(url), 1000);
    };
    pingTimer = setInterval(() => {
        if (sock.readyState !== WebSocket.OPEN) return;
        try { sock.ping(); } catch {}
    }, 30000);
}
connectGateway("wss://gateway.discord.gg/?v=9&encoding=json");
connectGateway("wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json");
