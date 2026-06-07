const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const OpenAI     = require('openai');
const express    = require('express');
const cors       = require('cors');
const puppeteer  = require('puppeteer');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const app    = express();
app.set('trust proxy', 1);

const ALLOWED_ORIGINS = [
    'https://developwithrax-dev-ed.my.site.com',
    process.env.FRONTEND_URL || ''
].filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        cb(new Error('Not allowed by CORS'));
    },
    methods:      ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'x-client-id', 'Authorization'],
    credentials:  true
}));

// Body size: 10mb handles base64 images but limits abuse headroom
app.use(express.json({ limit: '10mb' }));

// ─── Request ID + logger ─────────────────────────────────────────────────────
app.use((req, res, next) => {
    const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2,7)}`;
    res.setHeader('X-Request-ID', reqId);
    req.reqId = reqId;

    const start = Date.now();
    res.on('finish', () => {
        const ms  = Date.now() - start;
        const cid = (req.headers['x-client-id'] || 'none').slice(0, 40);
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${ms}ms cid=${cid} rid=${req.reqId}`);

        // Alert on suspicious patterns
        if (res.statusCode === 429) {
            console.warn(`[RATE-LIMIT] cid=${cid} ip=${req.ip} path=${req.path}`);
        }
    });
    next();
});

// Extend server response timeout to 120s — inspiration flow makes 2 OpenAI calls
app.use((req, res, next) => {
    res.setTimeout(120000, () => {
        res.status(503).json({ error: 'Request timed out. Please try again.' });
    });
    next();
});

app.use(
    helmet({
        crossOriginEmbedderPolicy: false,
        contentSecurityPolicy: false
    })
);

// ─── Version marker ───────────────────────────────────────────────────────────
const SERVER_VERSION = 'v9-auth-2026';
const BOOT_TIME      = Date.now();

// ─── Auth config ──────────────────────────────────────────────────────────────
const JWT_SECRET     = process.env.JWT_SECRET     || 'CHANGE_ME_32_CHAR_RANDOM_SECRET';
const JWT_EXPIRES    = '30d';
const FRONTEND_URL   = process.env.FRONTEND_URL   || 'https://developwithrax-dev-ed.my.site.com';
const APP_URL        = process.env.APP_URL         || 'https://salesforce-resume-pdf-server-production.up.railway.app';
const GOOGLE_ID      = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_SECRET  = process.env.GOOGLE_CLIENT_SECRET || '';
const LINKEDIN_ID    = process.env.LINKEDIN_CLIENT_ID   || '';
const LINKEDIN_SEC   = process.env.LINKEDIN_CLIENT_SECRET || '';

// ─── PostgreSQL pool ──────────────────────────────────────────────────────────
let db = null;
if (process.env.DATABASE_URL) {
    db = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000
    });
    db.query(`
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
        CREATE TABLE IF NOT EXISTS rn_users (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            email               VARCHAR(255) UNIQUE NOT NULL,
            name                VARCHAR(255),
            provider            VARCHAR(50)  NOT NULL,
            provider_user_id    VARCHAR(255),
            avatar_url          TEXT,
            plan                VARCHAR(50)  DEFAULT 'free',
            resume_count        INTEGER      DEFAULT 0,
            ats_reports_count   INTEGER      DEFAULT 0,
            anonymous_client_id VARCHAR(100),
            created_at          TIMESTAMPTZ  DEFAULT NOW(),
            last_login_at       TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_users_email    ON rn_users(email);
        CREATE INDEX IF NOT EXISTS idx_rn_users_prov     ON rn_users(provider, provider_user_id);
        CREATE TABLE IF NOT EXISTS rn_saved_resumes (
            id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id        UUID         NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            name           VARCHAR(255) DEFAULT 'My Resume',
            resume_data    JSONB        NOT NULL,
            ai_css         TEXT,
            template_style VARCHAR(100) DEFAULT 'sf-classic',
            created_at     TIMESTAMPTZ  DEFAULT NOW(),
            updated_at     TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_resumes_user ON rn_saved_resumes(user_id);
        CREATE TABLE IF NOT EXISTS rn_ats_reports (
            id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID         NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            resume_snapshot JSONB,
            job_description TEXT,
            analysis_result JSONB        NOT NULL,
            ats_score       INTEGER,
            jd_match_score  INTEGER,
            created_at      TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS rn_magic_tokens (
            id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            email      VARCHAR(255) NOT NULL,
            token      VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ  NOT NULL,
            used_at    TIMESTAMPTZ,
            client_id  VARCHAR(100),
            created_at TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_magic_token ON rn_magic_tokens(token);
    `)
    .then(() => console.log('[DB] Schema ready'))
    .catch(e => console.error('[DB] Schema init:', e.message));
} else {
    console.warn('[DB] DATABASE_URL not set — auth disabled');
}

// ─── Email transporter ────────────────────────────────────────────────────────
let mailer = null;
if (process.env.RESEND_API_KEY) {
    mailer = nodemailer.createTransport({
        host: 'smtp.resend.com', port: 465, secure: true,
        auth: { user: 'resend', pass: process.env.RESEND_API_KEY }
    });
} else if (process.env.SMTP_HOST) {
    mailer = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
}

// ─── IP-based rate limiters (first line of defence) ─────────────────────────
const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 20,                     // 20 AI calls per IP per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many AI requests. Please try again in 15 minutes.' }
});

const exportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 5,                      // 5 PDF exports per IP per hour
    message: { error: 'PDF export limit reached. Please try again later.' }
});

// ─── Per-clientId rate limiter (second line of defence) ──────────────────────
// Prevents abuse from users who rotate IPs but keep the same browser session.
// Uses an in-memory Map; resets on server restart.
const clientIdCalls = new Map();   // clientId → { count, windowStart }
const CLIENT_ID_LIMIT        = 15; // max AI calls per clientId per window
const CLIENT_ID_WINDOW_MS    = 15 * 60 * 1000; // 15 minutes

function perClientIdLimiter(req, res, next) {
    const clientId = req.headers['x-client-id'];
    if (!clientId) return next(); // validateClientSession handles missing id

    const now    = Date.now();
    const record = clientIdCalls.get(clientId);

    if (!record || (now - record.windowStart) > CLIENT_ID_WINDOW_MS) {
        // Fresh window
        clientIdCalls.set(clientId, { count: 1, windowStart: now });
        return next();
    }

    if (record.count >= CLIENT_ID_LIMIT) {
        console.warn(`[CLIENT-LIMIT] cid=${clientId.slice(0,40)} blocked (${record.count} calls in window)`);
        return res.status(429).json({
            error: 'You have made too many requests. Please wait 15 minutes before trying again.'
        });
    }

    record.count++;
    return next();
}

// Prune stale entries every 30 minutes to prevent memory leak
setInterval(() => {
    const cutoff = Date.now() - CLIENT_ID_WINDOW_MS;
    for (const [id, rec] of clientIdCalls.entries()) {
        if (rec.windowStart < cutoff) clientIdCalls.delete(id);
    }
}, 30 * 60 * 1000);

// IP-based rate limits
app.use('/generate-template',   aiLimiter);
app.use('/extract-resume',      aiLimiter);
app.use('/review-resume',       aiLimiter);
app.use('/improve-summary',     aiLimiter);
app.use('/generate-pdf',        exportLimiter);
app.use('/analyze-job-match',   aiLimiter);
app.use('/optimize-for-job',    aiLimiter);
app.use('/analyze-food',        aiLimiter);
app.use('/analyze-food',        validateClientSession);
app.use('/analyze-food',        perClientIdLimiter);

// Session validation (must come before per-clientId limiter)
app.use('/generate-template',   validateClientSession);
app.use('/extract-resume',      validateClientSession);
app.use('/review-resume',       validateClientSession);
app.use('/improve-summary',     validateClientSession);
app.use('/generate-pdf',        validateClientSession);
app.use('/analyze-job-match',   validateClientSession);
app.use('/optimize-for-job',    validateClientSession);

// Per-clientId limits (second layer — catches proxy rotators)
app.use('/generate-template',   perClientIdLimiter);
app.use('/extract-resume',      perClientIdLimiter);
app.use('/review-resume',       perClientIdLimiter);
app.use('/improve-summary',     perClientIdLimiter);
app.use('/generate-pdf',        perClientIdLimiter);
app.use('/analyze-job-match',   perClientIdLimiter);
app.use('/optimize-for-job',    perClientIdLimiter);

// ─── Health / version ─────────────────────────────────────────────────────────
app.get('/version', (req, res) => {
    res.json({
        version:  SERVER_VERSION,
        bootTime: new Date(BOOT_TIME).toISOString(),
        nowTime:  new Date().toISOString()
    });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Accepts: standard UUID (36 chars), or UUID-with-extras (up to 72 chars)
// Rejects: SQL injection strings, script tags, arbitrary text
const CLIENT_ID_PATTERN = /^[a-zA-Z0-9\-_]{8,72}$/;

function validateClientSession(req, res, next) {
    const clientId = req.headers['x-client-id'];
    if (!clientId) {
        return res.status(400).json({ error: 'Missing client session.' });
    }
    if (!CLIENT_ID_PATTERN.test(clientId)) {
        console.warn(`[INVALID-CID] Rejected clientId: "${clientId.slice(0,60)}"`);
        return res.status(400).json({ error: 'Invalid client session format.' });
    }
    next();
}

function truncateText(text, max = 12000) {
    if (!text) return '';
    return String(text).slice(0, max);
}

function sanitizeInput(value) {
    return String(value || '')
        .replace(/<script.*?>.*?<\/script>/gi, '')
        .trim();
}

// ─── PDF override CSS ─────────────────────────────────────────────────────────
const PDF_OVERRIDE_CSS = `
@page { size: A4; margin: 0; }

html, body {
    margin: 0 !important;
    padding: 0 !important;
    background: #ffffff !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}

* {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}

.rb-resume {
    transform: none !important;
    transform-origin: top left !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    max-width: none !important;
    width: 794px !important;
    min-height: 0 !important;
    margin: 0 auto !important;
    overflow: visible !important;
    background: #ffffff !important;
}

.rb-resume:hover { transform: none !important; }

.rb-resume__header,
.rb-exp-item,
.rb-edu-item,
.rb-resume__section {
    break-inside: avoid;
    page-break-inside: avoid;
}

.rp-preview__scale-wrap {
    transform: none !important;
    margin-bottom: 0 !important;
}

.rb-resume__photo-placeholder,
.rb-resume__top-deco,
.rb-cert {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}
`;

// ═════════════════════════════════════════════════════════════════════════════
// POST /generate-pdf
// ═════════════════════════════════════════════════════════════════════════════
// Strips dangerous HTML tags from PDF payload before Puppeteer renders it
function sanitizePdfHtml(html) {
    if (!html) return '';
    return html
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<iframe\b[^>]*>.*?<\/iframe>/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')       // strip inline handlers
        .replace(/javascript\s*:/gi, '')                      // strip js: hrefs
        .replace(/<link[^>]+rel\s*=\s*["']?import["']?[^>]*>/gi, '') // strip imports
        .slice(0, 500000);  // hard cap: 500kb of HTML max
}

app.post('/generate-pdf', async (req, res) => {

    console.log(`[${SERVER_VERSION}] /generate-pdf`, new Date().toISOString(), {
        htmlLen: req.body?.html?.length,
        cssLen:  req.body?.css?.length
    });

    try {
        const { html, css } = req.body;

        const browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--font-render-hinting=none'
            ]
        });

        const page = await browser.newPage();
        await page.setViewport({ width: 794, height: 1123, deviceScaleFactor: 2 });

        const fullHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="server-version" content="${SERVER_VERSION}">
    <style>
        /* Client CSS */
        ${css || ''}
        /* PDF Overrides */
        ${PDF_OVERRIDE_CSS}
    </style>
</head>
<body>
    ${html || ''}
</body>
</html>`;

        await page.setContent(fullHtml, { waitUntil: 'networkidle0' });
        await page.emulateMediaType('screen');
        await page.evaluateHandle('document.fonts.ready');

        const pdf = await page.pdf({
            format: 'A4',
            printBackground: true,
            preferCSSPageSize: true,
            margin: { top: '0', right: '0', bottom: '0', left: '0' }
        });

        await browser.close();

        res.set({
            'Content-Type':    'application/pdf',
            'Content-Length':   pdf.length,
            'X-Server-Version': SERVER_VERSION
        });
        res.send(pdf);

    } catch (e) {
        console.error('PDF generation error:', e);
        res.status(500).send('PDF generation failed');
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /extract-resume
// ═════════════════════════════════════════════════════════════════════════════
app.post('/extract-resume', async (req, res) => {

    try {
        let { text } = req.body;
        text = truncateText(text, 12000);
        if (!text) return res.status(400).json({ error: 'No text provided' });

        const prompt = `You are an expert resume parser. Extract structured data from the resume text below.

IMPORTANT — Two-column PDF note: The text may be extracted from a two-column PDF layout where sidebar content (skills, certifications, summary) is interleaved with main content (experience, education). Intelligently identify and separate these sections regardless of their order in the raw text.

Return ONLY valid JSON. No markdown, no code fences, no explanations.

Schema:
{
  "fullName": "string",
  "title": "string — job title/headline only, not a sentence",
  "email": "string",
  "phone": "string",
  "location": "string — city/country only",
  "linkedIn": "string — full URL or path",
  "summary": "string — 2-4 sentence professional summary, rewrite from About section if present",
  "skills": ["array of individual skill strings, max 20"],
  "experiences": [
    {
      "company": "string",
      "title": "string",
      "startDate": "string e.g. Jan 2021",
      "endDate": "string e.g. Present",
      "bullets": ["MAXIMUM 4 bullet points per role — pick the 4 most impactful, quantified achievements. Rewrite each to start with a strong action verb. Each bullet max 120 characters."]
    }
  ],
  "education": [
    {
      "degree": "string e.g. Bachelor of Technology",
      "field": "string e.g. Computer Science",
      "school": "string",
      "years": "string e.g. 2014 – 2018"
    }
  ],
  "certifications": ["array of certification name strings only, max 8"]
}

CRITICAL RULES:
1. MAX 4 bullets per experience role — choose the most impactful ones with numbers/results
2. MAX 20 skills — pick the most relevant technical skills
3. Ignore repeated or similar bullets — deduplicate
4. Skills, certifications, and summary often appear in a sidebar — extract them correctly even if interleaved with experience text
5. Do NOT include generic bullets like "Roles and responsibilities include..." or "Continue to bridge the gap..."

Resume text:
${text}`;

        const completion = await openai.chat.completions.create({
            model:           'gpt-4.1-mini',
            messages:        [
                { role: 'system', content: 'You are an expert resume parser. Extract clean structured data. Return ONLY valid JSON.' },
                { role: 'user',   content: prompt }
            ],
            temperature:     0.1,
            response_format: { type: 'json_object' }
        });

        const parsed = JSON.parse(completion.choices[0].message.content);

        // Server-side enforcement: cap bullets and skills
        if (parsed.experiences) {
            parsed.experiences = parsed.experiences.map(exp => ({
                ...exp,
                bullets: (exp.bullets || []).slice(0, 4)
            }));
        }
        if (parsed.skills)         parsed.skills         = parsed.skills.slice(0, 20);
        if (parsed.certifications) parsed.certifications = parsed.certifications.slice(0, 8);

        res.json(parsed);

    } catch (e) {
        console.error('Resume extraction error:', e);
        res.status(500).json({ error: 'AI extraction failed' });
    }
});

// ═════════════════════════════════════════════════════════════════════════════

// ─── AI CSS sanitizer ─────────────────────────────────────────────────────────
// Comprehensively strips any property that can break layout.
// Three-pass approach: strip dangerous values → fix column constraints → append hard overrides.
function sanitizeAiCss(css) {
    if (!css) return '';

    // ── Pass 1: Strip unconditionally dangerous values (anywhere in the CSS) ──

    // position: absolute / fixed → relative (causes overlap everywhere)
    css = css.replace(/position\s*:\s*(absolute|fixed)\s*(!important)?\s*;/gi,
        'position: relative;');

    // overflow: hidden / clip → visible (clips sidebar content from ANY element)
    css = css.replace(/overflow(-[xy])?\s*:\s*(hidden|clip)\s*(!important)?\s*;/gi,
        function(m, axis) { return 'overflow' + (axis||'') + ': visible;'; });

    // display: none (accidentally hides sections)
    css = css.replace(/display\s*:\s*none\s*(!important)?\s*;/gi, '');

    // float: left / right (breaks grid layout entirely)
    css = css.replace(/float\s*:\s*(left|right)\s*(!important)?\s*;/gi, '');

    // negative margins (causes sections to overlap)
    css = css.replace(/margin(-top|-bottom|-left|-right)?\s*:\s*-[\d.]+[a-z%]*\s*(!important)?\s*;/gi, '');

    // negative z-index (elements disappear behind others)
    css = css.replace(/z-index\s*:\s*-[\d]+\s*(!important)?\s*;/gi, 'z-index: 0;');

    // transform: translate with negative values (moves content off-screen)
    css = css.replace(/transform\s*:[^;]*translate[^;]*-[\d][^;]*;/gi, '');

    // ── Pass 2: Protect structural sizing constraints ──────────────────────

    // Strip grid-template-columns overrides on the body (preserve 2-col layout)
    css = css.replace(
        /(\.rb-resume--ai-generated[^{]*\.rb-resume__body[^{]*\{[^}]*)grid-template-columns\s*:[^;]+;/gi,
        '$1/* grid-template-columns locked to 210px 1fr */'
    );

    // Strip width overrides on sidebar/main (let grid control sizing)
    css = css.replace(
        /(\.rb-resume--ai-generated[^{]*(?:sidebar|main)[^{]*\{[^}]*)\bwidth\s*:\s*[\d.]+[a-z%]+\s*(!important)?\s*;/gi,
        '$1/* width locked by grid */'
    );

    // Strip fixed pixel heights on structural containers (content is clipped)
    css = css.replace(
        /(\.rb-resume--ai-generated[^{]*(?:sidebar|main|body|section|summary|header)[^{]*\{[^}]*)\bheight\s*:\s*[\d.]+[a-z%]+\s*(!important)?\s*;/gi,
        '$1min-height: 0;'
    );

    // Cap extreme padding (max 32px per side prevents blowout)
    css = css.replace(
        /\bpadding(-top|-bottom|-left|-right)?\s*:\s*([\d]+)px\s*(!important)?\s*;/gi,
        function(m, side, val, imp) {
            return parseInt(val, 10) > 32
                ? 'padding' + (side||'') + ': 32px;'
                : m;
        }
    );

    // Cap extreme font sizes to prevent blowout (max 24px body, 32px heading)
    css = css.replace(
        /\bfont-size\s*:\s*([\d]+)px\s*(!important)?\s*;/gi,
        function(m, val, imp) {
            return parseInt(val, 10) > 32 ? 'font-size: 14px;' : m;
        }
    );

    // ── Pass 3: Append hard layout safety overrides (highest specificity) ──
    css += `

/* ══ LAYOUT SAFETY OVERRIDES — injected by Renonym AI sanitizer ══
   These run LAST and use !important to guarantee the resume
   never breaks no matter what the AI generated above. */

/* Root — visible overflow so nothing clips */
.rb-resume--ai-generated {
    overflow: visible !important;
    box-sizing: border-box !important;
}

/* 2-col grid — locked. AI cannot change this. */
.rb-resume--ai-generated .rb-resume__body {
    display: grid !important;
    grid-template-columns: 210px 1fr !important;
    overflow: visible !important;
    position: relative !important;
    width: 100% !important;
}

/* Sidebar — flex column, never absolute, never floated */
.rb-resume--ai-generated .rb-resume__sidebar {
    display: flex !important;
    flex-direction: column !important;
    gap: 0 !important;
    position: relative !important;
    float: none !important;
    overflow: visible !important;
    height: auto !important;
    min-height: 0 !important;
    width: auto !important;
    box-sizing: border-box !important;
}

/* Main column — same guarantees */
.rb-resume--ai-generated .rb-resume__main {
    display: flex !important;
    flex-direction: column !important;
    position: relative !important;
    float: none !important;
    overflow: visible !important;
    height: auto !important;
    min-height: 0 !important;
    width: auto !important;
    box-sizing: border-box !important;
}

/* Every section stacks naturally — never overlaps */
.rb-resume--ai-generated .rb-resume__section {
    position: relative !important;
    float: none !important;
    display: block !important;
    overflow: visible !important;
    height: auto !important;
    min-height: 0 !important;
    flex-shrink: 0 !important;
    box-sizing: border-box !important;
    width: auto !important;
}

/* Section titles — always visible, always a block */
.rb-resume--ai-generated .rb-section-title {
    display: block !important;
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
    width: auto !important;
}

/* Summary — wraps, never clips */
.rb-resume--ai-generated .rb-summary,
.rb-resume--ai-generated .rb-summary p {
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
    word-break: break-word !important;
    overflow-wrap: break-word !important;
    white-space: normal !important;
    display: block !important;
}

/* Skills row — always wraps */
.rb-resume--ai-generated .rb-skills {
    display: flex !important;
    flex-wrap: wrap !important;
    height: auto !important;
    overflow: visible !important;
    position: relative !important;
}

/* Skill pills — inline flex, never absolute */
.rb-resume--ai-generated .rb-skill-pill {
    display: inline-flex !important;
    position: relative !important;
    height: auto !important;
    overflow: visible !important;
    white-space: nowrap !important;
    box-sizing: border-box !important;
}

/* Experience + education items — block, visible, auto height */
.rb-resume--ai-generated .rb-exp-item,
.rb-resume--ai-generated .rb-edu-item {
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
    display: block !important;
    float: none !important;
    box-sizing: border-box !important;
}

/* Bullet lists — visible, auto height */
.rb-resume--ai-generated .rb-exp-bullets,
.rb-resume--ai-generated .rb-exp-bullets li {
    overflow: visible !important;
    height: auto !important;
    position: relative !important;
    display: list-item !important;
}

/* Contact row — wraps on overflow */
.rb-resume--ai-generated .rb-resume__contact {
    overflow: visible !important;
    flex-wrap: wrap !important;
    height: auto !important;
}

/* Header — always visible */
.rb-resume--ai-generated .rb-resume__header {
    overflow: visible !important;
    position: relative !important;
    height: auto !important;
}
`;

    return css;
}


// POST /generate-template
// Generates AI CSS — now supports optional inspiration image via base64
// ═════════════════════════════════════════════════════════════════════════════
app.post('/generate-template', async (req, res) => {

    try {
        const {
            prompt,
            resumeData,
            metadata,
            inspirationBase64,
            inspirationMimeType
        } = req.body;

        const hasInspiration = !!(
            inspirationBase64 &&
            inspirationMimeType &&
            (inspirationMimeType.startsWith('image/') || inspirationMimeType === 'application/pdf') &&
            inspirationBase64.length < 4 * 1024 * 1024  // 4MB base64 limit
        );

        // ── Step 1: If inspiration image provided, vision-analyse it first ──
        let inspirationStyleSignals = '';

        if (hasInspiration) {
            try {
                console.log(`[${SERVER_VERSION}] Analysing inspiration image (${inspirationMimeType})`);

                const visionCompletion = await openai.chat.completions.create({
                    model: 'gpt-4o',
                    messages: [
                        {
                            role: 'system',
                            content: `You are a design analyst specialising in resume aesthetics and typography.
Analyse the uploaded resume image and extract ONLY style/design signals.
DO NOT extract or mention any personal data, names, companies, or content.
Focus exclusively on: layout structure, colour palette, typography choices, spacing density, section divider styles, header treatment, sidebar vs single-column, font character (serif/sans), visual hierarchy signals.
Return your analysis as a compact, structured paragraph of CSS-relevant design signals only.`
                        },
                        {
                            role: 'user',
                            content: [
                                {
                                    type: 'image_url',
                                    image_url: {
                                        url:    `data:${inspirationMimeType};base64,${inspirationBase64}`,
                                        detail: 'low'   // Low detail sufficient for style extraction
                                    }
                                },
                                {
                                    type: 'text',
                                    text: 'Analyse this resume image for design and style signals only. Extract: colour palette, typography style (serif/sans/mono), layout structure (columns, spacing), header style, section dividers, overall visual density. Return only design signals, no personal data.'
                                }
                            ]
                        }
                    ],
                    max_tokens: 300,
                    temperature: 0.3
                });

                inspirationStyleSignals = visionCompletion.choices[0].message.content.trim();
                console.log(`[${SERVER_VERSION}] Inspiration signals extracted:`, inspirationStyleSignals.slice(0, 100));

            } catch (visionErr) {
                // Non-fatal — proceed without inspiration signals
                console.warn(`[${SERVER_VERSION}] Vision analysis failed (non-fatal):`, visionErr.message);
            }
        }

        // ── Step 2: Generate CSS template ──
        const systemPrompt = `You are an elite AI resume designer. You ONLY generate CSS.

You design modern, premium, ATS-friendly resumes.

RULES:
- Output ONLY raw CSS. No markdown, no code fences, no explanations.
- ONLY use class .rb-resume--ai-generated and its descendants.
- All selectors MUST start with .rb-resume--ai-generated

HARD CONSTRAINTS — violating ANY of these will break the resume:
- FORBIDDEN: position: absolute or position: fixed (on ANY element)
- FORBIDDEN: overflow: hidden or overflow: clip (on ANY element)
- FORBIDDEN: display: none (on any element)
- FORBIDDEN: float: left or float: right (on any element)
- FORBIDDEN: negative margin values (any side)
- FORBIDDEN: negative z-index values
- FORBIDDEN: changing grid-template-columns on .rb-resume__body
- FORBIDDEN: setting width on .rb-resume__sidebar or .rb-resume__main
- FORBIDDEN: setting fixed pixel height on sidebar, main, body, or section
- FORBIDDEN: padding values above 32px on any side
- FORBIDDEN: font-size above 32px anywhere in the resume body

ALLOWED — style ONLY these visual/cosmetic properties:
- Colors: color, background-color, background (gradients OK)
- Typography: font-family, font-size (8–24px), font-weight, letter-spacing, line-height, text-transform
- Borders: border, border-radius, border-color, border-width, border-style
- Spacing: padding (max 32px), margin (positive values only), gap
- Decorative: box-shadow, opacity (never 0), text-decoration

- Preserve readable font sizes (minimum 8px body, 10px headings).
- Ensure high colour contrast for ATS scanning.
- Keep the two-column sidebar + main layout intact.
- Optimise for A4 single-page output.
- Use web-safe fonts only: system-ui, Georgia, 'Times New Roman', 'Courier New'.

CSS selectors available to style:
.rb-resume--ai-generated
.rb-resume--ai-generated .rb-resume__top-deco
.rb-resume--ai-generated .rb-resume__header
.rb-resume--ai-generated .rb-resume__photo-img
.rb-resume--ai-generated .rb-resume__photo-placeholder
.rb-resume--ai-generated .rb-resume__name
.rb-resume--ai-generated .rb-resume__title-line
.rb-resume--ai-generated .rb-resume__contact
.rb-resume--ai-generated .rb-resume__contact-item
.rb-resume--ai-generated .rb-resume__body
.rb-resume--ai-generated .rb-resume__sidebar
.rb-resume--ai-generated .rb-resume__main
.rb-resume--ai-generated .rb-resume__section
.rb-resume--ai-generated .rb-section-title
.rb-resume--ai-generated .rb-summary
.rb-resume--ai-generated .rb-skills
.rb-resume--ai-generated .rb-skill-pill
.rb-resume--ai-generated .rb-cert
.rb-resume--ai-generated .rb-exp-item
.rb-resume--ai-generated .rb-exp-head
.rb-resume--ai-generated .rb-exp-company
.rb-resume--ai-generated .rb-exp-date
.rb-resume--ai-generated .rb-exp-role
.rb-resume--ai-generated .rb-exp-bullets
.rb-resume--ai-generated .rb-exp-bullets li
.rb-resume--ai-generated .rb-edu-item
.rb-resume--ai-generated .rb-edu-head
.rb-resume--ai-generated .rb-edu-degree
.rb-resume--ai-generated .rb-edu-years
.rb-resume--ai-generated .rb-edu-school`;

        const densityWarning = (metadata?.totalBullets > 12 || metadata?.experienceCount > 3)
            ? `\nDENSITY WARNING: This resume has ${metadata?.totalBullets || 'many'} bullet points across ${metadata?.experienceCount || 'multiple'} roles.
You MUST use compact CSS to fit it on one page:
- .rb-resume--ai-generated font-size: 8.5px
- .rb-resume--ai-generated .rb-resume__body padding: 0
- .rb-resume--ai-generated .rb-resume__section margin-bottom: 10px
- .rb-resume--ai-generated .rb-exp-item margin-bottom: 8px
- .rb-resume--ai-generated .rb-exp-bullets li padding/margin: 1px
- .rb-resume--ai-generated .rb-resume__header padding: 16px 24px 12px`
            : '';

        const inspirationBlock = inspirationStyleSignals
            ? `\nSTYLE INSPIRATION SIGNALS (extracted from uploaded reference — translate these into equivalent CSS):
${inspirationStyleSignals}`
            : '';

        const userPrompt = `USER DESIGN REQUEST:
${sanitizeInput(prompt)}
${inspirationBlock}

RESUME CONTENT METADATA:
- Has photo: ${metadata?.hasPhoto || false}
- Experience entries: ${metadata?.experienceCount || 0}
- Skills: ${metadata?.skillCount || 0}
- Certifications: ${metadata?.certificationCount || 0}
- Education entries: ${metadata?.educationCount || 0}
- Summary length: ${metadata?.summaryLength || 0} characters
- Total bullet points across all roles: ${metadata?.totalBullets || 0}
- Content density: ${metadata?.totalBullets > 12 || metadata?.experienceCount > 3 ? 'HIGH — use compact spacing' : 'NORMAL'}
${densityWarning}

Generate CSS that:
1. Matches the design intent from the user request
${inspirationStyleSignals ? '2. Incorporates the style signals from the inspiration image — translate their visual language into equivalent CSS for the rb-resume structure' : '2. Creates a distinctive, premium design'}
3. Is specifically optimised for the content density above
4. Keeps everything on ONE A4 page — this is critical
5. Uses ONLY the .rb-resume--ai-generated namespace
6. Returns ONLY raw CSS — nothing else`;

        const completion = await openai.chat.completions.create({
            model:       'gpt-4.1-mini',
            messages:    [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userPrompt   }
            ],
            temperature: 0.85,
            max_tokens:  2000
        });

        let css = completion.choices[0].message.content;

        // Strip any accidental markdown fences
        css = css
            .replace(/^```(?:css)?\s*/i, '')
            .replace(/\s*```\s*$/,       '')
            .trim();

        // Sanitize AI CSS — strips dangerous layout properties that cause overlap
        css = sanitizeAiCss(css);

        res.json({ css });

    } catch (e) {
        console.error('Template generation error:', e);
        res.status(500).json({ error: 'Template generation failed' });
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /improve-summary
// ═════════════════════════════════════════════════════════════════════════════
app.post('/improve-summary', async (req, res) => {

    try {
        const { name, title, summary, skills = [], experience = [] } = req.body;

        const expContext = experience
            .filter(e => e.company || e.title)
            .slice(0, 3)
            .map(e => `${e.title || 'Role'} at ${e.company || 'Company'} (${e.dateRange || ''})`)
            .join(', ');

        const topSkills = (skills || []).slice(0, 8).join(', ');

        const prompt = `You are an expert resume writer specialising in ATS-optimised, compelling professional summaries.

Write a new professional summary for this person.

PERSON:
Name: ${sanitizeInput(name) || 'Unknown'}
Title: ${sanitizeInput(title) || 'Professional'}
Current summary: ${sanitizeInput(summary) || '(none provided)'}
Top skills: ${topSkills || '(not provided)'}
Recent experience: ${expContext || '(not provided)'}

REQUIREMENTS:
- 3–4 sentences maximum
- First sentence: years of experience + core expertise + industry context
- Second sentence: 1–2 quantified or notable achievements
- Third sentence: technical strengths or specialisation
- Fourth sentence (optional): value proposition or career goal
- Tone: confident, professional, concise — NOT clichéd
- NO phrases like "results-driven", "passionate", "dynamic", "team player", "go-getter"
- ATS-friendly: include relevant keywords naturally
- Return ONLY the summary text, no labels, no quotes, no explanation`;

        const completion = await openai.chat.completions.create({
            model:       'gpt-4.1-mini',
            messages:    [
                { role: 'system', content: 'You are a professional resume writer. Return only the requested text.' },
                { role: 'user',   content: prompt }
            ],
            temperature: 0.7,
            max_tokens:  200
        });

        const improvedSummary = completion.choices[0].message.content.trim();
        res.json({ summary: improvedSummary });

    } catch (e) {
        console.error('Summary improvement error:', e);
        res.status(500).json({ error: 'Summary improvement failed' });
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /review-resume
// ═════════════════════════════════════════════════════════════════════════════
app.post('/review-resume', async (req, res) => {

    try {
        const { formData } = req.body;

        const prompt = `You are a professional resume coach and ATS expert.

Review this resume and provide a structured critique.

RESUME DATA:
Name: ${formData?.fullName || 'N/A'}
Title: ${formData?.title || 'N/A'}
Summary length: ${formData?.summary?.length || 0} characters
Skills count: ${formData?.skills?.length || 0}
Experience entries: ${formData?.experiences?.length || 0}
Education entries: ${formData?.education?.length || 0}
Certifications: ${formData?.certifications?.length || 0}
Has LinkedIn: ${!!formData?.linkedIn}
Has phone: ${!!formData?.phone}
Has location: ${!!formData?.location}

Experience details:
${(formData?.experiences || [])
    .slice(0, 3)
    .map(e => `- ${e.title} at ${e.company} | ${e.bullets?.length || 0} bullet points`)
    .join('\n') || 'None'}

Skills: ${(formData?.skills || []).join(', ') || 'None listed'}

Summary: ${formData?.summary || 'Not provided'}

PROVIDE:
1. Overall score out of 10
2. Top 3 strengths (be specific)
3. Top 3 improvements needed (be specific and actionable)
4. ATS optimization tips (2–3 points)
5. One key recommendation to immediately increase interview chances

Keep response under 250 words. Be direct and specific — no generic advice.`;

        const completion = await openai.chat.completions.create({
            model:       'gpt-4.1-mini',
            messages:    [
                { role: 'system', content: 'You are a professional resume coach. Provide specific, actionable feedback.' },
                { role: 'user',   content: prompt }
            ],
            temperature: 0.5,
            max_tokens:  400
        });

        const feedback = completion.choices[0].message.content.trim();
        res.json({ feedback });

    } catch (e) {
        console.error('Resume review error:', e);
        res.status(500).json({ error: 'Resume review failed' });
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// Start
// ═════════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;

// ─── Helper: turn resumeData or resumeText into a readable string ─────────────
function buildResumeString(resumeData, resumeText) {
    // If we have structured data, use it (gives GPT cleaner, more structured input)
    // Append raw text only if structured data seems sparse (no experiences)
    const hasStructured = resumeData && (
        resumeData.fullName || resumeData.summary || resumeData.experiences?.length
    );

    if (hasStructured) {
        // Serialize the structured resumeData
        const structured = serializeResumeData(resumeData);
        // If we also have raw text and experiences are missing, append it for extra context
        if (resumeText && !resumeData.experiences?.length) {
            return (structured + '\n\n--- ADDITIONAL CONTEXT FROM UPLOADED FILE ---\n' + resumeText).slice(0, 8000);
        }
        return structured.slice(0, 8000);
    }

    // No structured data — use raw text directly (uploaded-only flow)
    if (resumeText && resumeText.trim().length > 50) {
        return resumeText.trim().slice(0, 8000);
    }

    // Otherwise serialize the structured formData from the builder
    if (!resumeData) return 'No resume data provided.';
    return serializeResumeData(resumeData);
}

function serializeResumeData(resumeData) {
    if (!resumeData) return 'No resume data provided.';
    const lines = [];
    if (resumeData.fullName)  lines.push(`Name: ${resumeData.fullName}`);
    if (resumeData.title)     lines.push(`Title: ${resumeData.title}`);
    if (resumeData.email)     lines.push(`Email: ${resumeData.email}`);
    if (resumeData.location)  lines.push(`Location: ${resumeData.location}`);
    if (resumeData.summary)   lines.push(`\nSummary:\n${resumeData.summary}`);
    if (resumeData.skills?.length)
        lines.push(`\nSkills: ${resumeData.skills.join(', ')}`);
    if (resumeData.certifications?.length)
        lines.push(`Certifications: ${resumeData.certifications.join(', ')}`);
    if (resumeData.experiences?.length) {
        lines.push('\nExperience:');
        resumeData.experiences.forEach(exp => {
            const dates = exp.dateRange || [exp.startDate, exp.endDate].filter(Boolean).join(' – ');
            lines.push(`  ${exp.title || ''} at ${exp.company || ''} (${dates})`);
            (exp.bullets || []).forEach(b => lines.push(`    • ${b}`));
        });
    }
    if (resumeData.education?.length) {
        lines.push('\nEducation:');
        resumeData.education.forEach(edu => {
            lines.push(`  ${edu.degree || ''}${edu.field ? ', ' + edu.field : ''} — ${edu.school || ''} (${edu.years || ''})`);
        });
    }
    return lines.join('\n').slice(0, 8000);
}

// ─── POST /analyze-job-match ──────────────────────────────────────────────────
// Accepts either { resumeData, jobDescription } or { resumeText, jobDescription }
// Returns structured gap analysis: scores + specific actionable suggestions
// ─────────────────────────────────────────────────────────────────────────────
app.post('/analyze-job-match', async (req, res) => {
    try {
        const { resumeData, resumeText, jobDescription } = req.body;

        if (!jobDescription || jobDescription.trim().length < 30) {
            return res.status(400).json({ error: 'Job description is too short (minimum 30 characters).' });
        }
        if (jobDescription.length > 6000) {
            return res.status(400).json({ error: 'Job description is too long. Please paste a maximum of 6000 characters.' });
        }
        if (resumeText && resumeText.length > 10000) {
            return res.status(400).json({ error: 'Resume text is too long. Maximum 10000 characters accepted.' });
        }

        const resumeString = buildResumeString(resumeData, resumeText);

        if (resumeString.length < 20) {
            return res.status(400).json({ error: 'Resume is empty. Please upload a resume or fill in the builder first.' });
        }

        const systemPrompt = `You are a senior technical recruiter and ATS specialist with 15 years of experience.
You analyse resumes against job descriptions and give precise, actionable feedback.
Your feedback must be SPECIFIC to this exact resume and JD — never generic.
You return ONLY valid JSON, no markdown, no explanation outside the JSON.`;

        const userPrompt = `Analyse this resume against the job description. Be precise and specific.

=== RESUME ===
${resumeString}

=== JOB DESCRIPTION ===
${jobDescription.trim().slice(0, 5000)}

=== SCORING RULES ===
- atsScore (0–100): How well the resume is structured for ATS parsing. Consider: section headings present, contact info visible, no tables/columns that break parsing, bullet points used, quantified achievements, appropriate length.
- jdMatch (0–100): How well the candidate's actual experience and skills match what the JD requires. Be realistic — a mismatch in seniority or core skills should give a low score.
- keywordCoverage (0–100): Percentage of important technical/domain keywords from the JD that appear anywhere in the resume.
- skillsCoverage (0–100): Percentage of explicitly listed required skills in the JD that appear in the resume skills section.

=== OUTPUT FORMAT ===
Return ONLY this JSON (no markdown fences):
{
  "atsScore": <integer 0–100>,
  "jdMatch": <integer 0–100>,
  "keywordCoverage": <integer 0–100>,
  "skillsCoverage": <integer 0–100>,
  "missingKeywords": [
    "<specific keyword from JD not in resume — be exact, e.g. 'Salesforce CPQ' not 'CRM tools'>",
    ... up to 8 items
  ],
  "missingSkills": [
    "<specific skill required by JD not in resume skills — be exact>",
    ... up to 6 items
  ],
  "strengths": [
    "<specific strength this resume has FOR THIS JD — reference actual content, e.g. '7 years of Apex development aligns with the Senior Developer requirement'>",
    ... 3–4 items
  ],
  "weaknesses": [
    "<specific, actionable gap — tell the candidate EXACTLY what to fix, e.g. 'Your summary does not mention Salesforce Lightning which appears 4 times in the JD — add it in the first sentence'>",
    ... 3–5 items
  ],
  "summarySuggestions": [
    "<concrete instruction for improving the summary for this specific JD — e.g. 'Add the phrase cloud-based CRM architecture to your summary opening line'>",
    ... 2–3 items
  ],
  "experienceSuggestions": [
    "<specific instruction for an experience bullet — e.g. 'Under your Infosys role, add a bullet quantifying how many Salesforce orgs you managed'>",
    ... 2–3 items
  ]
}`;

        const completion = await openai.chat.completions.create({
            model:           'gpt-4.1-mini',
            messages:        [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userPrompt   }
            ],
            temperature:     0.2,
            response_format: { type: 'json_object' }
        });

        let result;
        try {
            result = JSON.parse(completion.choices[0].message.content);
        } catch (parseErr) {
            console.error('JSON parse error:', parseErr);
            return res.status(500).json({ error: 'Failed to parse AI response.' });
        }

        // Clamp scores to 0–100
        ['atsScore','jdMatch','keywordCoverage','skillsCoverage'].forEach(k => {
            if (typeof result[k] === 'number') result[k] = Math.max(0, Math.min(100, Math.round(result[k])));
        });

        // Ensure all array fields exist
        ['missingKeywords','missingSkills','strengths','weaknesses',
         'summarySuggestions','experienceSuggestions'].forEach(k => {
            if (!Array.isArray(result[k])) result[k] = [];
        });

        console.log(`[${SERVER_VERSION}] /analyze-job-match — ATS:${result.atsScore} JD:${result.jdMatch}`);
        res.json(result);

    } catch (err) {
        console.error('/analyze-job-match error:', err);
        res.status(500).json({ error: 'Job match analysis failed. Please try again.' });
    }
});

// ─── POST /optimize-for-job ───────────────────────────────────────────────────
// Rewrites resume summary + experience bullets to target the JD
// NEVER invents facts — only rephrases existing content
// ─────────────────────────────────────────────────────────────────────────────
app.post('/optimize-for-job', async (req, res) => {
    try {
        const { resumeData, resumeText, jobDescription } = req.body;

        if (!jobDescription || jobDescription.trim().length < 30) {
            return res.status(400).json({ error: 'Job description is too short (minimum 30 characters).' });
        }
        if (jobDescription.length > 6000) {
            return res.status(400).json({ error: 'Job description is too long. Maximum 6000 characters accepted.' });
        }
        if (resumeText && resumeText.length > 10000) {
            return res.status(400).json({ error: 'Resume text is too long. Maximum 10000 characters accepted.' });
        }

        const resumeString = buildResumeString(resumeData, resumeText);

        const systemPrompt = `You are an expert resume writer specialising in ATS optimisation.
You rewrite resume content to better match a specific job description.

ABSOLUTE RULES — breaking any of these makes the output worthless:
1. NEVER invent companies, job titles, dates, degrees, or certifications
2. NEVER add skills or achievements the candidate has not demonstrated  
3. ONLY rephrase, reword, or restructure EXISTING content
4. Incorporate JD keywords NATURALLY — never stuff them awkwardly
5. Use strong action verbs: Led, Architected, Delivered, Reduced, Increased, Launched, Scaled
6. Keep bullets concise — maximum 130 characters each
7. Return ONLY valid JSON — no markdown, no explanation`;

        const userPrompt = `Optimise this resume for the job description below.

=== RESUME ===
${resumeString}

=== JOB DESCRIPTION ===
${jobDescription.trim().slice(0, 5000)}

=== INSTRUCTIONS ===
1. Rewrite the professional summary (3–4 sentences) to open with the candidate's most relevant strength for this specific role, then incorporate the top 3–4 keywords from the JD naturally.
2. For each experience role, rewrite or strengthen the bullet points to highlight achievements and responsibilities that align with the JD requirements. Do NOT add bullets that aren't based on existing content.
3. Reorder the skills array so the most JD-relevant skills appear first. You may add 1–2 skills that are clearly implied by their experience (e.g. if they built Salesforce integrations, adding "REST API Integration" is fair).
4. Keep ALL company names, titles, dates, and education exactly as-is.

Return ONLY this JSON:
{
  "summary": "<optimised summary>",
  "skills": ["<skill1>", "<skill2>", ...],
  "experiences": [
    {
      "company": "<EXACT same company name>",
      "title": "<EXACT same title>",
      "startDate": "<EXACT same>",
      "endDate": "<EXACT same>",
      "bullets": ["<optimised bullet>", ...]
    }
  ]
}`;

        const completion = await openai.chat.completions.create({
            model:           'gpt-4.1-mini',
            messages:        [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userPrompt   }
            ],
            temperature:     0.35,
            response_format: { type: 'json_object' }
        });

        let result;
        try {
            result = JSON.parse(completion.choices[0].message.content);
        } catch (parseErr) {
            return res.status(500).json({ error: 'Failed to parse AI response.' });
        }

        // If we have structured resumeData, merge the optimised content back in
        // so company/title/dates are always preserved from the original
        if (resumeData?.experiences?.length && result.experiences?.length) {
            result.experiences = result.experiences.map((optExp, i) => {
                const orig = resumeData.experiences[i] || {};
                return {
                    ...orig,
                    bullets:    optExp.bullets?.slice(0, 6) || orig.bullets || [],
                    bulletsRaw: (optExp.bullets || orig.bullets || []).join('\n')
                };
            });
        }

        console.log(`[${SERVER_VERSION}] /optimize-for-job completed`);
        res.json({ optimizedResume: result });

    } catch (err) {
        console.error('/optimize-for-job error:', err);
        res.status(500).json({ error: 'Resume optimisation failed. Please try again.' });
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH  —  Google OAuth · LinkedIn OAuth · Email Magic Link
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Helpers ──────────────────────────────────────────────────────────────────

function dbRequired(res) {
    if (!db) { res.status(503).json({ error: 'Auth not configured (no DATABASE_URL).' }); return false; }
    return true;
}

function signToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, name: user.name, plan: user.plan || 'free' },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
    );
}

function requireAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required.' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); }
    catch (_) { res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}

async function upsertUser({ email, name, provider, providerUserId, avatarUrl, anonClientId }) {
    const existing = await db.query(
        `SELECT * FROM rn_users WHERE (provider=$1 AND provider_user_id=$2) OR email=$3 LIMIT 1`,
        [provider, providerUserId || '', email]
    );
    if (existing.rows.length) {
        const u = existing.rows[0];
        await db.query(
            `UPDATE rn_users SET name=$1, avatar_url=$2, last_login_at=NOW(),
             anonymous_client_id=COALESCE(anonymous_client_id,$3) WHERE id=$4`,
            [name || u.name, avatarUrl || u.avatar_url, anonClientId || null, u.id]
        );
        return { ...u, name: name || u.name, avatar_url: avatarUrl || u.avatar_url };
    }
    const r = await db.query(
        `INSERT INTO rn_users(email,name,provider,provider_user_id,avatar_url,anonymous_client_id)
         VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
        [email, name, provider, providerUserId || null, avatarUrl || null, anonClientId || null]
    );
    return r.rows[0];
}

// Returns HTML page rendered inside the OAuth popup that posts the token back
// to the parent LWC window and self-closes.
function authSuccessPage(token, user) {
    const safe = JSON.stringify({
        id: user.id, email: user.email, name: user.name,
        avatarUrl: user.avatar_url, plan: user.plan || 'free'
    }).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
    return `<!DOCTYPE html><html><head><title>Signing in…</title>
<style>*{margin:0}body{font-family:system-ui,sans-serif;background:#0b0c1a;color:#fff;height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px}
.ring{width:40px;height:40px;border:3px solid #7c3aed;border-top-color:transparent;border-radius:50%;animation:s .8s linear infinite}@keyframes s{to{transform:rotate(360deg)}}</style></head>
<body><div class="ring"></div><p style="font-size:14px;color:rgba(255,255,255,0.5)">Signing you in…</p>
<script>
(function(){
  try{ window.opener && window.opener.postMessage({type:'RENONYM_AUTH_SUCCESS',token:'TOKEN',user:USER},'FRONTEND'); }catch(e){}
  setTimeout(function(){try{window.close();}catch(e){}},400);
})();
</script></body></html>`\
        .replace('TOKEN', token)\
        .replace('USER', safe)\
        .replace('FRONTEND', FRONTEND_URL);
}

function authErrorPage(msg) {
    const safe = msg.replace(/'/g, "\\'").replace(/</g, '&lt;');
    return `<!DOCTYPE html><html><head><title>Sign-in error</title>
<style>body{font-family:system-ui,sans-serif;background:#0b0c1a;color:#ef4444;height:100vh;display:flex;align-items:center;justify-content:center;font-size:14px;}</style>
</head><body><p>${safe}</p>
<script>
try{window.opener&&window.opener.postMessage({type:'RENONYM_AUTH_ERROR',error:'${safe}'},'FRONTEND');}catch(e){}
setTimeout(function(){try{window.close();}catch(e){}},3000);
</script></body></html>`.replace(/FRONTEND/g, FRONTEND_URL);
}

// ─── Google OAuth ──────────────────────────────────────────────────────────────

app.get('/auth/google', (req, res) => {
    if (!GOOGLE_ID) return res.send(authErrorPage('Google OAuth not configured on server.'));
    const state  = Buffer.from(JSON.stringify({ cid: req.query.cid || '', nonce: req.query.nonce || '', ts: Date.now() })).toString('base64url');
    const params = new URLSearchParams({
        client_id: GOOGLE_ID,
        redirect_uri: APP_URL + '/auth/google/callback',
        response_type: 'code', scope: 'openid email profile',
        state, access_type: 'offline', prompt: 'select_account'
    });
    res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params);
});

app.get('/auth/google/callback', async (req, res) => {
    if (!dbRequired(res)) return;
    const { code, state, error } = req.query;
    if (error || !code) return res.send(authErrorPage('Google sign-in was cancelled.'));
    let anonClientId = '', stateData = {};
    try { stateData = JSON.parse(Buffer.from(state||'','base64url').toString()); anonClientId = stateData.cid || ''; } catch(_){}
    try {
        const tokRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ code, client_id: GOOGLE_ID, client_secret: GOOGLE_SECRET,
                redirect_uri: APP_URL + '/auth/google/callback', grant_type: 'authorization_code' }).toString()
        });
        const tokData = await tokRes.json();
        if (!tokData.access_token) throw new Error('No access_token from Google');

        const profRes  = await fetch('https://www.googleapis.com/oauth2/v3/userinfo',
            { headers: { Authorization: 'Bearer ' + tokData.access_token } });
        const profile  = await profRes.json();
        if (!profile.email) throw new Error('No email returned from Google');

        const user  = await upsertUser({ email: profile.email,
            name: profile.name || profile.email.split('@')[0],
            provider: 'google', providerUserId: profile.sub,
            avatarUrl: profile.picture, anonClientId });
        const token = signToken(user);
        const safeUser = { id:user.id, email:user.email, name:user.name, avatarUrl:user.avatar_url, plan:user.plan||'free' };
        // Store in polling map so LWC can pick it up
        if (stateData && stateData.nonce && pendingAuthSessions.has(stateData.nonce)) {
            pendingAuthSessions.set(stateData.nonce, { token, user: safeUser, createdAt: Date.now() });
        }
        console.log('[AUTH] Google login:', user.email);
        res.send(authSuccessPage(token, safeUser));
    } catch (e) {
        console.error('[AUTH] Google callback error:', e.message);
        res.send(authErrorPage('Google sign-in failed. Please try again.'));
    }
});

// ─── LinkedIn OAuth ────────────────────────────────────────────────────────────

app.get('/auth/linkedin', (req, res) => {
    if (!LINKEDIN_ID) return res.send(authErrorPage('LinkedIn OAuth not configured on server.'));
    const state  = Buffer.from(JSON.stringify({ cid: req.query.cid || '', nonce: req.query.nonce || '', ts: Date.now() })).toString('base64url');
    const params = new URLSearchParams({
        response_type: 'code', client_id: LINKEDIN_ID,
        redirect_uri: APP_URL + '/auth/linkedin/callback',
        state, scope: 'openid profile email'
    });
    res.redirect('https://www.linkedin.com/oauth/v2/authorization?' + params);
});

app.get('/auth/linkedin/callback', async (req, res) => {
    if (!dbRequired(res)) return;
    const { code, state, error } = req.query;
    if (error || !code) return res.send(authErrorPage('LinkedIn sign-in was cancelled.'));
    let anonClientId = '', stateData = {};
    try { stateData = JSON.parse(Buffer.from(state||'','base64url').toString()); anonClientId = stateData.cid || ''; } catch(_){}
    try {
        const tokRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ grant_type: 'authorization_code', code,
                redirect_uri: APP_URL + '/auth/linkedin/callback',
                client_id: LINKEDIN_ID, client_secret: LINKEDIN_SEC }).toString()
        });
        const tokData = await tokRes.json();
        if (!tokData.access_token) throw new Error('No access_token from LinkedIn');

        const profRes  = await fetch('https://api.linkedin.com/v2/userinfo',
            { headers: { Authorization: 'Bearer ' + tokData.access_token } });
        const profile  = await profRes.json();

        const firstName = profile.given_name  || '';
        const lastName  = profile.family_name || '';
        const fullName  = (firstName + ' ' + lastName).trim() || profile.name || 'LinkedIn User';
        const email     = profile.email || profile.sub + '@linkedin.placeholder';

        const user  = await upsertUser({ email, name: fullName, provider: 'linkedin',
            providerUserId: profile.sub, avatarUrl: profile.picture || null, anonClientId });
        const token = signToken(user);
        console.log('[AUTH] LinkedIn login:', user.email);
        res.send(authSuccessPage(token, user));
    } catch (e) {
        console.error('[AUTH] LinkedIn callback error:', e.message);
        res.send(authErrorPage('LinkedIn sign-in failed. Please try again.'));
    }
});

// ─── Magic Link ────────────────────────────────────────────────────────────────

app.post('/auth/magic-link/request', async (req, res) => {
    if (!dbRequired(res)) return;
    const { email, clientId } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (!mailer)
        return res.status(503).json({ error: 'Email not configured on server. Use Google or LinkedIn.' });
    try {
        const rawToken  = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await db.query('DELETE FROM rn_magic_tokens WHERE email=$1 AND used_at IS NULL', [email]);
        await db.query(
            'INSERT INTO rn_magic_tokens(email,token,expires_at,client_id) VALUES($1,$2,$3,$4)',
            [email, rawToken, expiresAt, clientId || null]
        );
        const link = `${APP_URL}/auth/magic-link/verify?token=${rawToken}`;
        await mailer.sendMail({
            from: process.env.SMTP_FROM || 'noreply@renonym.ai',
            to: email,
            subject: 'Your Renonym AI sign-in link',
            html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
<div style="background:#0b0c1a;border-radius:16px;padding:32px;text-align:center;">
<div style="font-size:28px;font-weight:900;color:#f0f0f8;letter-spacing:-0.04em;margin-bottom:6px;">Renonym AI</div>
<p style="color:rgba(255,255,255,0.5);font-size:13px;margin:0 0 28px">AI-Powered Resume Builder</p>
<p style="color:#f0f0f8;font-size:15px;line-height:1.6;margin:0 0 24px">
  Click the button below to sign in.<br/>This link expires in <strong>15 minutes</strong>.
</p>
<a href="${link}" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#9333ea);color:#fff;text-decoration:none;padding:14px 36px;border-radius:10px;font-weight:700;font-size:15px;">
  Sign in to Renonym AI
</a>
<p style="margin-top:24px;font-size:11px;color:rgba(255,255,255,0.25);">
  If you didn't request this, you can safely ignore it.
</p></div></div>`
        });
        console.log('[AUTH] Magic link sent to:', email);
        res.json({ success: true });
    } catch (e) {
        console.error('[AUTH] Magic link error:', e.message);
        res.status(500).json({ error: 'Failed to send email. Please try again.' });
    }
});

app.get('/auth/magic-link/verify', async (req, res) => {
    if (!dbRequired(res)) return;
    const { token } = req.query;
    if (!token) return res.send(authErrorPage('Invalid magic link.'));
    try {
        const r = await db.query(
            'SELECT * FROM rn_magic_tokens WHERE token=$1 AND used_at IS NULL AND expires_at>NOW()',
            [token]
        );
        if (!r.rows.length) return res.send(authErrorPage('This link has expired or already been used. Please request a new one.'));
        const link = r.rows[0];
        await db.query('UPDATE rn_magic_tokens SET used_at=NOW() WHERE id=$1', [link.id]);
        const user  = await upsertUser({ email: link.email,
            name: link.email.split('@')[0], provider: 'email',
            providerUserId: null, avatarUrl: null, anonClientId: link.client_id });
        const jwtToken = signToken(user);
        const safeUser = { id:user.id, email:user.email, name:user.name, avatarUrl:user.avatar_url, plan:user.plan||'free' };
        if (link.client_id && pendingAuthSessions.has(link.client_id + '_ml')) {
            pendingAuthSessions.set(link.client_id + '_ml', { token: jwtToken, user: safeUser, createdAt: Date.now() });
        }
        console.log('[AUTH] Magic link login:', user.email);
        res.send(authSuccessPage(jwtToken, safeUser));
    } catch (e) {
        console.error('[AUTH] Magic link verify error:', e.message);
        res.send(authErrorPage('Sign-in failed. Please try again.'));
    }
});

// ─── Session endpoints ─────────────────────────────────────────────────────────

app.get('/auth/me', requireAuth, async (req, res) => {
    if (!dbRequired(res)) return;
    try {
        const r = await db.query('SELECT * FROM rn_users WHERE id=$1', [req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'User not found.' });
        const u = r.rows[0];
        res.json({ id:u.id, email:u.email, name:u.name, avatarUrl:u.avatar_url,
            plan:u.plan, resumeCount:u.resume_count, atsCount:u.ats_reports_count,
            createdAt:u.created_at, lastLoginAt:u.last_login_at });
    } catch (e) { res.status(500).json({ error: 'Failed to load profile.' }); }
});


// ─── Auth polling — LWC Locker Service safe alternative to postMessage ────────
// LWC cannot use window.addEventListener('message') due to Locker Service.
// Instead: LWC polls this endpoint every 1.5s after opening the OAuth popup.
// Flow: LWC calls /auth/init-poll → gets nonce → opens popup with nonce
//       → server stores JWT by nonce after OAuth → LWC polls /auth/poll?nonce
//       → returns JWT when ready → LWC stores token and updates state

const pendingAuthSessions = new Map(); // nonce → { token, user } or null

// Clean up stale nonces every 5 minutes
setInterval(() => {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [nonce, val] of pendingAuthSessions.entries()) {
        if (val && val.createdAt < cutoff) pendingAuthSessions.delete(nonce);
        else if (!val && typeof val !== 'object') pendingAuthSessions.delete(nonce);
    }
}, 5 * 60 * 1000);

app.post('/auth/init-poll', (req, res) => {
    const nonce = require('crypto').randomBytes(16).toString('hex');
    pendingAuthSessions.set(nonce, null); // null = pending
    // auto-expire after 5 min
    setTimeout(() => pendingAuthSessions.delete(nonce), 5 * 60 * 1000);
    res.json({ nonce });
});

app.get('/auth/poll', (req, res) => {
    const { nonce } = req.query;
    if (!nonce || !pendingAuthSessions.has(nonce)) {
        return res.status(404).json({ error: 'Invalid or expired nonce.' });
    }
    const session = pendingAuthSessions.get(nonce);
    if (!session) return res.json({ pending: true });   // still waiting
    pendingAuthSessions.delete(nonce);
    res.json({ pending: false, token: session.token, user: session.user });
});

app.post('/auth/logout', requireAuth, (req, res) => {
    console.log('[AUTH] Logout:', req.user.email);
    res.json({ success: true });
});

// ─── Save Resume (requires auth) ──────────────────────────────────────────────

app.post('/auth/save-resume', requireAuth, async (req, res) => {
    if (!dbRequired(res)) return;
    const { resumeData, aiCss, templateStyle, name, resumeId } = req.body;
    if (!resumeData) return res.status(400).json({ error: 'No resume data provided.' });
    try {
        let r;
        if (resumeId) {
            r = await db.query(
                `UPDATE rn_saved_resumes SET resume_data=$1,ai_css=$2,template_style=$3,name=$4,updated_at=NOW()
                 WHERE id=$5 AND user_id=$6 RETURNING *`,
                [resumeData, aiCss||null, templateStyle||'sf-classic', name||'My Resume', resumeId, req.user.id]
            );
        } else {
            r = await db.query(
                `INSERT INTO rn_saved_resumes(user_id,resume_data,ai_css,template_style,name)
                 VALUES($1,$2,$3,$4,$5) RETURNING *`,
                [req.user.id, resumeData, aiCss||null, templateStyle||'sf-classic', name||'My Resume']
            );
            await db.query('UPDATE rn_users SET resume_count=resume_count+1 WHERE id=$1', [req.user.id]);
        }
        res.json({ success:true, resume: r.rows[0] });
    } catch (e) {
        console.error('/auth/save-resume error:', e.message);
        res.status(500).json({ error: 'Failed to save resume.' });
    }
});

app.get('/auth/resumes', requireAuth, async (req, res) => {
    if (!dbRequired(res)) return;
    try {
        const r = await db.query(
            'SELECT id,name,template_style,created_at,updated_at FROM rn_saved_resumes WHERE user_id=$1 ORDER BY updated_at DESC',
            [req.user.id]
        );
        res.json({ resumes: r.rows });
    } catch (e) { res.status(500).json({ error: 'Failed to load resumes.' }); }
});

app.post('/auth/save-ats-report', requireAuth, async (req, res) => {
    if (!dbRequired(res)) return;
    const { resumeSnapshot, jobDescription, analysisResult } = req.body;
    if (!analysisResult) return res.status(400).json({ error: 'No analysis data.' });
    try {
        await db.query(
            `INSERT INTO rn_ats_reports(user_id,resume_snapshot,job_description,analysis_result,ats_score,jd_match_score)
             VALUES($1,$2,$3,$4,$5,$6)`,
            [req.user.id, resumeSnapshot||null, jobDescription||null, analysisResult,
             analysisResult.atsScore||null, analysisResult.jdMatch||null]
        );
        await db.query('UPDATE rn_users SET ats_reports_count=ats_reports_count+1 WHERE id=$1', [req.user.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed to save ATS report.' }); }
});

// ─── Calorie Calculator ────────────────────────────────────────────────────────

app.post('/analyze-food', async (req, res) => {
    try {
        const { imageBase64, mimeType } = req.body;
        if (!imageBase64 || imageBase64.length < 100)
            return res.status(400).json({ error: 'No image provided.' });
        if (imageBase64.length > 10_000_000)
            return res.status(400).json({ error: 'Image too large. Maximum 6 MB.' });
        const validMime = ['image/jpeg','image/jpg','image/png','image/webp','image/heic','image/gif'];
        const mime = (mimeType || 'image/jpeg').toLowerCase();
        if (!validMime.includes(mime))
            return res.status(400).json({ error: 'Unsupported image type.' });

        const completion = await openai.chat.completions.create({
            model: 'gpt-4o',
            max_tokens: 1000,
            messages: [{
                role: 'user',
                content: [
                    { type: 'image_url', image_url: { url: `data:${mime};base64,${imageBase64}`, detail: 'high' } },
                    { type: 'text', text: `You are a professional nutritionist. Analyse this food image.
Return ONLY valid JSON, no markdown:
{"items":[{"name":"<food name>","portion":"<e.g. 150g>","calories":<int>,"protein":<int>,"carbs":<int>,"fat":<int>}],
"totalCalories":<int>,"totalProtein":<int>,"totalCarbs":<int>,"totalFat":<int>,
"confidence":"high"|"medium"|"low","notes":"<under 80 words>"}
If no food visible: {"error":"No food detected."}` }
                ]
            }],
            response_format: { type: 'json_object' }
        });

        const result = JSON.parse(completion.choices[0].message.content);
        if (result.error) return res.status(400).json({ error: result.error });
        if (result.totalCalories > 5000) result.totalCalories = 5000;
        res.json(result);
    } catch (e) {
        console.error('/analyze-food error:', e.message);
        res.status(500).json({ error: 'Food analysis failed. Please try again.' });
    }
});


app.listen(PORT, () => {
    console.log(`[${SERVER_VERSION}] Server running on port ${PORT}`);
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong.' });
});