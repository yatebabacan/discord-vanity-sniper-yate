"use strict";
const http2 = require('http2');
const tls = require('tls');
const https = require('https');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { HttpsProxyAgent } = require('https-proxy-agent');

// ==================== CONFIGURATION ====================
const configPath = path.resolve(__dirname, 'config.json');
let config = {};
try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (e) {
    console.error('[CONFIG ERROR] config.json dosyasi okunamadi:', e.message);
    process.exit(1);
}

const token = config.token || "";
const guildid = config.guildid || "";
const apiVersion = config.api_version || "v7";
const HOSTS = Array.isArray(config.hosts) && config.hosts.length > 0
    ? config.hosts
    : ['canary.discord.com', 'discord.com', 'ptb.discord.com'];

const proxies = Array.isArray(config.proxies) && config.proxies.length > 0
    ? config.proxies
    : (config.proxy ? [config.proxy] : []);

const SESSION_COUNT = config.session_count || 8;
const TLS_COUNT = config.tls_count || 8;

let mfaToken = null;
const vanityCache = new Map();

// ==================== ROTATION HELPERS ====================
let proxyIndex = 0;
function getNextProxy() {
    if (!proxies || proxies.length === 0) return null;
    const p = proxies[proxyIndex % proxies.length];
    proxyIndex = (proxyIndex + 1) % proxies.length;
    return p;
}

let hostIndex = 0;
function getNextHost() {
    const h = HOSTS[hostIndex % HOSTS.length];
    hostIndex = (hostIndex + 1) % HOSTS.length;
    return h;
}

// ==================== GATEWAY PAYLOADS & MFA ====================
const identifyBuffer = JSON.stringify({
    op: 2,
    d: {
        token,
        intents: 1,
        properties: { os: 'linux', browser: 'chrome', device: 'chrome' },
        guild_subscriptions: false,
        large_threshold: 0
    }
});
const heartbeatBuffer = '{"op":1,"d":null}';

function readMfa() {
    try {
        const mfaPath = path.resolve(__dirname, "mfa.txt");
        if (fs.existsSync(mfaPath)) {
            const data = fs.readFileSync(mfaPath, "utf8").trim();
            if (data && data !== mfaToken) {
                mfaToken = data;
                console.log("[MFA] Token guncellendi");
            }
        }
    } catch {}
}
readMfa();
try {
    fs.watch(path.resolve(__dirname, "mfa.txt"), (eventType) => {
        if (eventType === "change") readMfa();
    });
} catch {}

// ==================== HTTP/2 & TLS CONNECTION POOLS ====================
const h2Conns = new Array(SESSION_COUNT);
const tlsSocks = new Array(TLS_COUNT).fill({ write() {}, destroyed: true });
const tlsBackoff = new Array(TLS_COUNT).fill(500);
let tlsSession = undefined;

const createH2Session = (i) => {
    const host = HOSTS[i % HOSTS.length];
    const session = http2.connect(`https://${host}:443`, {
        maxVersion: 'TLSv1.3',
        minVersion: 'TLSv1.3',
        ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384',
        ecdhCurve: 'X25519',
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        highWaterMark: 32 * 1024,
        peerMaxConcurrentStreams: 1000,
        paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
        maxConcurrentStreams: 200,
        enablePush: false,
        initialWindowSize: 4 * 1024 * 1024,
        maxFrameSize: 4 * 1024 * 1024,
        headerTableSize: 16384,
        maxHeaderListSize: 32768
    });
    session.ref();
    session.host = host;

    session.once('connect', () => {
        console.log(`[HTTP2] Session ${i} connected (${host})`);
        try {
            const req = session.request({
                ':method': 'GET',
                ':path': `/api/${apiVersion}/gateway`,
                ':scheme': 'https',
                ':authority': host,
            });
            req.on('response', (headers) => {
                const status = Number(headers[':status']);
                if (status === 500) {
                    console.log(`[HTTP2 ${i}] Warmup 500 Internal Server Error - retry yapilmiyor.`);
                }
            });
            req.on('error', () => {});
            req.end();
        } catch (e) {}
    });

    session.on('error', (err) => {
        console.error(`[HTTP2] Session ${i} (${host}) error:`, err.message);
        setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100);
    });

    session.on('close', () => {
        console.warn(`[HTTP2] Session ${i} (${host}) closed`);
        setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100);
    });

    return session;
};

function createTLS(i) {
    const host = HOSTS[i % HOSTS.length];
    const s = tls.connect({
        host: host,
        port: 443,
        servername: host,
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
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
    s.host = host;
    s.setNoDelay(true);
    s.setKeepAlive(true, 15000);

    s.on("session", sess => { tlsSession = sess; });

    s.on("secureConnect", () => {
        tlsSocks[i] = s;
        tlsBackoff[i] = 500;
        s.write('\r\n');
        console.log(`tls[${i}] established (${host})`);
    });

    s.on("data", buf => {
        try {
            const raw = buf.toString("latin1");
            if (raw.includes(" 500 ") || raw.startsWith("HTTP/1.1 500") || raw.startsWith("HTTP/2 500")) {
                console.log(`[TLS ${i}] 500 Internal Server Error alindi, retry yapilmiyor.`);
                return;
            }
            const parts = raw.split("\r\n\r\n");
            const bodyStr = parts[1] || "";
            if (bodyStr) {
                const json = JSON.parse(bodyStr);
                if (json && json.code) console.log(`tls[${i}] (${host}):`, JSON.stringify(json));
            }
        } catch {}
    });

    s.on("timeout", () => { s.destroy(); });
    s.on("error", err => console.log(`tls[${i}] (${host}) error:`, err.message));
    s.on("close", () => {
        tlsSocks[i] = { write() {}, destroyed: true, host };
        setTimeout(() => createTLS(i), tlsBackoff[i]);
        tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 5000);
    });
}

for (let i = 0; i < TLS_COUNT; i++) createTLS(i);
for (let i = 0; i < SESSION_COUNT; i++) h2Conns[i] = createH2Session(i);

// ==================== PROXIED CLAIM REQUEST ====================
function sendClaimViaProxy(vanity, targetHost) {
    const proxyUrl = getNextProxy();
    const host = targetHost || getNextHost();
    const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;
    const body = JSON.stringify({ code: vanity });
    const bodyBuf = Buffer.from(body, 'utf8');

    const req = https.request({
        hostname: host,
        port: 443,
        path: `/api/${apiVersion}/guilds/${guildid}/vanity-url`,
        method: 'PATCH',
        agent: agent,
        headers: {
            'Host': host,
            'Authorization': token,
            'Content-Type': 'application/json',
            'Content-Length': bodyBuf.length,
            'Accept-Encoding': 'identity',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-Super-Properties': 'eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=',
            ...(mfaToken ? { 'X-Discord-Mfa-Authorization': mfaToken } : {})
        }
    }, (res) => {
        let respData = '';
        res.on('data', chunk => { respData += chunk; });
        res.on('end', () => {
            if (res.statusCode === 500) {
                console.log(`[PROXY CLAIM] [500] Host: ${host} - 500 Internal Server Error alindi, retry yapilmiyor.`);
                return;
            }
            console.log(`[PROXY CLAIM] [${res.statusCode}] Host: ${host} Response:`, respData);
        });
    });

    req.on('error', (err) => {
        console.error(`[PROXY CLAIM ERROR] Host: ${host}:`, err.message);
    });

    req.write(bodyBuf);
    req.end();
}

// ==================== BUILD REQUEST ====================
function buildRequest(vanity) {
    const body = '{"code":"' + vanity + '"}';
    const bodyy = Buffer.from(body, "latin1");
    const len = bodyy.length;

    // Pre-build TLS HTTP/1.1 buffers per rotated host
    const tlsBuffersByHost = {};
    for (const host of HOSTS) {
        tlsBuffersByHost[host] = Buffer.from(
            `PATCH /api/${apiVersion}/guilds/${guildid}/vanity-url HTTP/1.1\r\n` +
            `Host: ${host}\r\n` +
            `Authorization: ${token}\r\n` +
            `Content-Type: application/json\r\n` +
            `Accept-Encoding: identity\r\n` +
            `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n` +
            `X-Super-Properties: "eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0="\r\n` +
            (mfaToken ? `X-Discord-Mfa-Authorization: ${mfaToken}\r\n` : '') +
            `Content-Length: ${len}\r\n\r\n` + body,
            "latin1"
        );
    }

    return () => {
        // 1. Send via pre-warmed HTTP/2 sessions (rotated hosts)
        for (let i = h2Conns.length - 1; i >= 0; i--) {
            try {
                if (!h2Conns[i] || h2Conns[i].destroyed) continue;
                const host = h2Conns[i].host || HOSTS[i % HOSTS.length];
                const req = h2Conns[i].request({
                    ':method': 'PATCH',
                    ':path': `/api/${apiVersion}/guilds/${guildid}/vanity-url`,
                    ':authority': host,
                    'authorization': token,
                    'content-type': 'application/json',
                    'accept-encoding': 'identity',
                    'content-length': len,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'x-super-properties': 'eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=',
                    ...(mfaToken ? { 'x-discord-mfa-authorization': mfaToken } : {})
                });
                let resp = '';
                let statusCode = null;
                req.on('response', (headers) => {
                    statusCode = Number(headers[':status']);
                });
                req.on('data', chunk => { resp += chunk.toString('latin1'); });
                req.on('end', () => {
                    if (statusCode === 500) {
                        console.log(`[HTTP2 ${i}] [500] Host: ${host} - 500 Internal Server Error alindi, retry yapilmiyor.`);
                        return;
                    }
                    if (resp.includes('code') || statusCode === 200 || statusCode === 204) {
                        console.log(`h2[${i}] (${host}) [${statusCode}]:`, resp);
                    }
                });
                req.on('error', () => {});
                req.end(bodyy);
            } catch (e) {
                // session destroyed mid-request
            }
        }

        // 2. Send via pre-connected TLS sockets (rotated hosts)
        for (let i = TLS_COUNT - 1; i >= 0; i--) {
            try {
                const host = tlsSocks[i].host || HOSTS[i % HOSTS.length];
                const buf = tlsBuffersByHost[host] || tlsBuffersByHost[HOSTS[0]];
                tlsSocks[i].write(buf);
            } catch (e) {}
        }

        // 3. Send via rotating residential proxies across rotated hosts
        if (proxies.length > 0) {
            for (let h = 0; h < HOSTS.length; h++) {
                sendClaimViaProxy(vanity, HOSTS[h]);
            }
        }
    };
}

// ==================== FAST STRING EXTRACTION ====================
function extractStr(data, key) {
    const i = data.indexOf(key);
    if (i === -1) return null;
    const start = i + key.length;
    const end = data.indexOf('"', start);
    if (end === -1) return null;
    return data.slice(start, end);
}

// ==================== GUILD UPDATE EVENT HANDLER ====================
function handleGuildUpdate(data) {
    try {
        const gid = extractStr(data, '"id":"');
        if (!gid) return;
        const entry = vanityCache.get(gid);
        if (!entry) return;

        const boostKey = '"premium_subscription_count":';
        const bIdx = data.indexOf(boostKey);
        if (bIdx !== -1) {
            const bStart = bIdx + boostKey.length;
            const bEnd = data.indexOf(',', bStart);
            const count = parseInt(data.slice(bStart, bEnd));
            if (count < 14) {
                entry[1]();
                return;
            }
        }

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

// ==================== KEEPALIVE INTERVALS ====================
setInterval(() => {
    for (let i = h2Conns.length - 1; i >= 0; i--) {
        if (h2Conns[i] && !h2Conns[i].destroyed) {
            h2Conns[i].ping(Buffer.alloc(8), (err) => { if (err); });
        }
    }
}, 30000);

setInterval(() => {
    for (let i = TLS_COUNT - 1; i >= 0; i--) {
        if (!tlsSocks[i].destroyed) {
            const host = tlsSocks[i].host || HOSTS[i % HOSTS.length];
            const endpoint = i % 2 === 0 ? `/api/${apiVersion}/gateway` : '/';
            const req = `GET ${endpoint} HTTP/1.1\r\nhost: ${host}\r\nconnection: keep-alive\r\n\r\n`;
            try { tlsSocks[i].write(req); } catch(e) {}
        }
    }
}, 15000);

// ==================== GATEWAY WEBSOCKET ====================
function connectGateway(url) {
    const proxyUrl = getNextProxy();
    const wsOptions = {
        perMessageDeflate: false,
        skipUTF8Validation: true,
        followRedirects: false,
        rejectUnauthorized: false,
        maxRedirects: 0,
        handshakeTimeout: 30000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    };
    if (proxyUrl) {
        wsOptions.agent = new HttpsProxyAgent(proxyUrl);
    }

    const sock = new WebSocket(url, wsOptions);
    let hbTimer = null;
    let hbAcked = true;
    let pingTimer = null;

    sock.onopen = () => {
        if (sock.readyState === WebSocket.OPEN) {
            sock.send(identifyBuffer);
            console.log(`[GATEWAY] Connected to ${url}${proxyUrl ? ' (via proxy)' : ''}`);
        }
    };

    sock.onmessage = (msg) => {
        try {
            let data = msg.data;
            if (Buffer.isBuffer(data)) data = data.toString('utf-8');

            if (data.indexOf('GUILD_UPDATE') !== -1) {
                handleGuildUpdate(data);
                return;
            }

            if (data.indexOf('READY') !== -1) {
                const d = JSON.parse(data).d;
                const guilds = d.guilds;
                for (let i = 0; i < guilds.length; i++) {
                    const g = guilds[i];
                    if (g.vanity_url_code) {
                        vanityCache.set(g.id, [g.vanity_url_code, buildRequest(g.vanity_url_code)]);
                    }
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

const apiNum = apiVersion.replace(/^v/, '');
connectGateway(`wss://gateway.discord.gg/?v=${apiNum}&encoding=json`);
connectGateway(`wss://gateway-us-east1-b.discord.gg/?v=${apiNum}&encoding=json`);
