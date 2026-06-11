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

const openai   = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const Razorpay = require('razorpay');
const razorpay = new Razorpay({
    key_id:     process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});
const app    = express();
app.set('trust proxy', 1);

const ALLOWED_ORIGINS_EXTRA_LIST = (process.env.ALLOWED_ORIGINS_EXTRA || '').split(',').filter(Boolean);
const ALLOWED_ORIGINS = [
    'https://developwithrax-dev-ed.my.site.com',
    'https://renonym.com',
    'https://www.renonym.com',
    process.env.FRONTEND_URL || '',
    ...ALLOWED_ORIGINS_EXTRA_LIST
].filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        cb(new Error('Not allowed by CORS'));
    },
    methods:      ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],   // tracker uses PATCH — its absence broke every stage/star update
    allowedHeaders: ['Content-Type', 'x-client-id', 'Authorization', 'x-api-secret'],
    credentials:  true
}));

// Body size: 10mb handles base64 images but limits abuse headroom
app.use(express.json({ limit: '10mb' }));

// --- Request ID + logger ----------------------------------------------------
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

// Extend server response timeout to 120s - inspiration flow makes 2 OpenAI calls
app.use((req, res, next) => {
    res.setTimeout(120000, () => {
        if (!res.headersSent) res.status(503).json({ error: 'Request timed out. Please try again.' });
    });
    next();
});

app.use(
    helmet({
        crossOriginEmbedderPolicy: false,
        contentSecurityPolicy: false
    })
);

// --- Version marker ---------------------------------------------------------
const SERVER_VERSION = 'v14.3-credits-2026';
const BOOT_TIME      = Date.now();

// --- Auth config ------------------------------------------------------------
const JWT_SECRET     = process.env.JWT_SECRET     || 'CHANGE_ME_32_CHAR_RANDOM_SECRET';
const JWT_EXPIRES    = '30d';
const FRONTEND_URL   = process.env.FRONTEND_URL   || 'https://developwithrax-dev-ed.my.site.com';
const APP_URL        = process.env.APP_URL         || 'https://salesforce-resume-pdf-server-production.up.railway.app';
const GOOGLE_ID      = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_SECRET  = process.env.GOOGLE_CLIENT_SECRET || '';
const LINKEDIN_ID    = process.env.LINKEDIN_CLIENT_ID   || '';
const LINKEDIN_SEC   = process.env.LINKEDIN_CLIENT_SECRET || '';

// --- PostgreSQL pool --------------------------------------------------------
let db = null;
let schemaReady = Promise.resolve();   // app.listen waits for schema init
if (process.env.DATABASE_URL) {
    db = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000
    });
    schemaReady = db.query(`
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
        -- Shared per-user daily premium-action quota (free tier). Pro = unlimited.
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS daily_premium_count INTEGER DEFAULT 0;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS daily_premium_date  DATE;
        -- Entitlement grants (Pro + Coach) stamp updated_at; column was missing,
        -- which silently failed every plan grant after payment. Add it.
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
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

        -- ── Interview Coach ──────────────────────────────────────────────
        -- Coach entitlement is separate from the résumé 'plan' (free/pro):
        -- 'unlimited' subscription, or a count of one-time session passes.
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS coach_plan     VARCHAR(20) DEFAULT 'none';
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS coach_expires  TIMESTAMPTZ;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS session_passes INTEGER DEFAULT 0;
        CREATE TABLE IF NOT EXISTS rn_interview_sessions (
            id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID         NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            company         VARCHAR(255),
            job_title       VARCHAR(255),
            job_description  TEXT,
            interview_type  VARCHAR(50),
            difficulty      INTEGER      DEFAULT 60,
            mode            VARCHAR(20)  DEFAULT 'voice',
            resume_snapshot JSONB,
            questions       JSONB        DEFAULT '[]'::jsonb,
            answers         JSONB        DEFAULT '[]'::jsonb,
            report          JSONB,
            overall_score   INTEGER,
            status          VARCHAR(20)  DEFAULT 'in_progress',
            created_at      TIMESTAMPTZ  DEFAULT NOW(),
            updated_at      TIMESTAMPTZ  DEFAULT NOW(),
            completed_at    TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_rn_sessions_user ON rn_interview_sessions(user_id, created_at DESC);
        -- Replay protection: each Razorpay payment grants exactly once.
        CREATE TABLE IF NOT EXISTS rn_payments (
            payment_id VARCHAR(64)  PRIMARY KEY,
            order_id   VARCHAR(64),
            plan_id    VARCHAR(50),
            user_id    UUID,
            created_at TIMESTAMPTZ  DEFAULT NOW()
        );

        -- ── Application Tracker (job-search CRM) ─────────────────────────
        -- rn_jobs is the application record; rn_job_events is the uniform
        -- CRM timeline (notes, rounds, recruiter contacts, salary threads,
        -- follow-ups) — type + optional due_at/done covers all of them.
        CREATE TABLE IF NOT EXISTS rn_jobs (
            id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID         NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            company         VARCHAR(255) NOT NULL,
            title           VARCHAR(255) NOT NULL,
            location        VARCHAR(255),
            url             TEXT,
            source          VARCHAR(100),
            jd              TEXT,
            salary_min      INTEGER,
            salary_max      INTEGER,
            salary_currency VARCHAR(8)   DEFAULT 'INR',
            salary_notes    TEXT,
            stage           VARCHAR(20)  DEFAULT 'saved',
            excitement      INTEGER      DEFAULT 3,
            next_action     VARCHAR(255),
            next_action_due TIMESTAMPTZ,
            applied_at      TIMESTAMPTZ,
            archived        BOOLEAN      DEFAULT FALSE,
            created_at      TIMESTAMPTZ  DEFAULT NOW(),
            updated_at      TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_jobs_user ON rn_jobs(user_id, archived, stage);
        CREATE TABLE IF NOT EXISTS rn_job_events (
            id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id     UUID         NOT NULL REFERENCES rn_jobs(id) ON DELETE CASCADE,
            user_id    UUID         NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            type       VARCHAR(30)  NOT NULL,
            title      VARCHAR(255),
            body       TEXT,
            due_at     TIMESTAMPTZ,
            done       BOOLEAN      DEFAULT FALSE,
            meta       JSONB,
            created_at TIMESTAMPTZ  DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_job_events_job ON rn_job_events(job_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_rn_job_events_due ON rn_job_events(user_id, done, due_at);

        -- ── Monetization: prepaid credits + pass ladder (v14) ───────────
        -- Credits are a LEDGER (auditable grants/debits) + a cached balance.
        -- Passes (season / placement_pro) bypass credit checks while active.
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS credit_balance            INTEGER     DEFAULT 0;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS pass_type                 VARCHAR(20);
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS pass_expires_at           TIMESTAMPTZ;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS pass_interviews_remaining INTEGER     DEFAULT 0;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS interview_credits         INTEGER     DEFAULT 0;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS free_interview_used       BOOLEAN     DEFAULT FALSE;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS signup_credits_granted    BOOLEAN     DEFAULT FALSE;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS grandfathered             BOOLEAN     DEFAULT FALSE;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS referral_code             VARCHAR(16) UNIQUE;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS referred_by               UUID;
        ALTER TABLE rn_users ADD COLUMN IF NOT EXISTS idle_nudge_sent_at        TIMESTAMPTZ;
        CREATE TABLE IF NOT EXISTS rn_credit_ledger (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID        NOT NULL REFERENCES rn_users(id) ON DELETE CASCADE,
            delta           INTEGER     NOT NULL,
            reason          VARCHAR(50) NOT NULL,
            ref_id          VARCHAR(100),
            expires_at      TIMESTAMPTZ,            -- boost-pack grants expire (6 months)
            expired_handled BOOLEAN     DEFAULT FALSE,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rn_credit_ledger_user ON rn_credit_ledger(user_id, created_at DESC);
        -- one purchase grant per payment id — retries can never double-grant
        CREATE UNIQUE INDEX IF NOT EXISTS idx_rn_credit_ledger_purchase
            ON rn_credit_ledger(ref_id) WHERE reason LIKE 'purchase:%' AND ref_id IS NOT NULL;
        -- Free first interview produces a PARTIAL report until unlocked.
        ALTER TABLE rn_interview_sessions ADD COLUMN IF NOT EXISTS is_free_session BOOLEAN DEFAULT FALSE;
        ALTER TABLE rn_interview_sessions ADD COLUMN IF NOT EXISTS report_unlocked BOOLEAN DEFAULT TRUE;
        -- JD corpus for future programmatic SEO (fire-and-forget writes only).
        CREATE TABLE IF NOT EXISTS rn_jd_corpus (
            id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_hash  VARCHAR(64),
            raw_text   TEXT,
            tags       JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    `)
    .then(() => console.log('[DB] Schema ready'))
    .catch(e => console.error('[DB] Schema init:', e.message));
} else {
    console.warn('[DB] DATABASE_URL not set - auth disabled');
}

// --- Email transporter ------------------------------------------------------
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

// --- IP-based rate limiters (first line of defence) -------------------------
const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 20,                     // 20 AI calls per IP per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many AI requests. Please try again in 15 minutes.' }
});

const exportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 20,                     // per IP — generous for Pro users / shared NATs
    skipFailedRequests: true,    // a failed render must not burn an export slot
    message: { error: 'PDF export limit reached. Please try again later.' }
});

// Payment endpoints - strict limits to prevent API probing / forged-sig attacks
const paymentLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 10,                     // max 10 order creations per IP per hour
    standardHeaders: true,
    message: { error: 'Too many payment requests. Please try again later.' }
});

// Magic link - strict to prevent email spam abuse
const magicLinkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 5,                      // 5 magic link requests per IP per 15 min
    standardHeaders: true,
    message: { error: 'Too many email requests. Please wait 15 minutes.' }
});

// Auth polling - light limit to prevent nonce enumeration
const pollLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 250,                    // Google polls every 1.5s (~200/5min) + magic-link every 6s — both must fit
    message: { error: 'Too many poll requests.' }
});

// Coach audio (TTS questions + transcription) — cheap per call, but bounded.
// A 10-question interview with repeats ≈ 25-40 calls; 120 leaves headroom.
const coachMediaLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    message: { error: 'Too many audio requests. Please slow down a little.' }
});

// --- Per-clientId rate limiter (second line of defence) ---------------------
// Prevents abuse from users who rotate IPs but keep the same browser session.
// Uses an in-memory Map; resets on server restart.
const clientIdCalls = new Map();   // clientId -> { count, windowStart }
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

// -- API secret check - applied to all protected endpoints -------------------
// Rejects any request that doesn't include the correct x-api-secret header.
// This blocks direct API scraping even if someone finds the Railway URL.
app.use('/generate-template',   validateApiSecret);
app.use('/extract-resume',      validateApiSecret);
app.use('/review-resume',       validateApiSecret);
app.use('/improve-summary',     validateApiSecret);
app.use('/generate-pdf',        validateApiSecret);
app.use('/analyze-job-match',   validateApiSecret);
app.use('/optimize-for-job',    validateApiSecret);
app.use('/analyze-food',        validateApiSecret);
app.use('/create-order',        validateApiSecret);
app.use('/verify-payment',      validateApiSecret);

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

// Per-clientId limits (second layer - catches proxy rotators)
app.use('/generate-template',   perClientIdLimiter);
app.use('/extract-resume',      perClientIdLimiter);
app.use('/review-resume',       perClientIdLimiter);
app.use('/improve-summary',     perClientIdLimiter);
app.use('/generate-pdf',        perClientIdLimiter);
app.use('/analyze-job-match',   perClientIdLimiter);
app.use('/optimize-for-job',    perClientIdLimiter);

// ─── Premium gating: login required + shared daily quota (Pro = unlimited) ───
// Free tier: must be signed in; a single per-user daily allowance is shared
// across AI Style / Job Match / AI Review. Downloads are Pro-only. This is the
// server-side source of truth — the frontend gating is UX, this is enforcement.
const FREE_DAILY_QUOTA = parseInt(process.env.FREE_DAILY_QUOTA || '2', 10);

// Any premium action requires a valid signed-in user (free or pro).
function requirePremiumAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Please sign in to use this feature.', code: 'AUTH_REQUIRED' });
    try { req.user = jwt.verify(token, JWT_SECRET); return next(); }
    catch (_) { return res.status(401).json({ error: 'Session expired. Please sign in again.', code: 'AUTH_REQUIRED' }); }
}

// Shared per-user daily quota across premium AI actions. Pro = unlimited.
// Checks before the handler (no wasted AI spend); counts only successful
// responses (a failed/validation-error request does not consume an allowance).
async function enforceDailyQuota(req, res, next) {
    if (!db) return next(); // no DB configured (dev) — cannot enforce
    try {
        const r = await db.query(
            `SELECT plan, coach_plan, coach_expires,
                    CASE WHEN daily_premium_date = CURRENT_DATE THEN daily_premium_count ELSE 0 END AS used
             FROM rn_users WHERE id = $1`,
            [req.user.id]
        );
        if (!r.rows.length) return res.status(401).json({ error: 'Account not found.', code: 'AUTH_REQUIRED' });
        const plan  = r.rows[0].plan;
        const used  = r.rows[0].used;
        // Coach Unlimited is the paid tier actually sold — it carries the paid benefits
        const isPro = plan === 'pro' || coachAccess(r.rows[0]).unlimited;

        if (!isPro && used >= FREE_DAILY_QUOTA) {
            return res.status(402).json({
                error: `You've used your ${FREE_DAILY_QUOTA} free actions for today. Upgrade to Pro for unlimited access.`,
                code: 'QUOTA_EXCEEDED', plan, used, limit: FREE_DAILY_QUOTA
            });
        }

        res.setHeader('X-Quota-Plan',  plan);
        res.setHeader('X-Quota-Limit', String(FREE_DAILY_QUOTA));
        res.setHeader('X-Quota-Used',  String(isPro ? used : used + 1));

        if (!isPro) {
            res.on('finish', () => {
                if (res.statusCode >= 200 && res.statusCode < 300 && !res.locals.aiFallback) {
                    db.query(
                        `UPDATE rn_users SET
                            daily_premium_count = CASE WHEN daily_premium_date = CURRENT_DATE THEN daily_premium_count + 1 ELSE 1 END,
                            daily_premium_date  = CURRENT_DATE
                         WHERE id = $1`,
                        [req.user.id]
                    ).catch(e => console.error('[QUOTA] increment failed:', e.message));
                }
            });
        }
        return next();
    } catch (e) {
        console.error('[QUOTA] check failed (fail-open):', e.message);
        return next(); // don't block during a DB hiccup
    }
}

// ── v14 credits: charge per output-improving AI action ──────────────────────
// Pass (season/placement) or legacy paid (pro / unexpired Coach Unlimited)
// bypasses entirely. Debit happens ONLY after a successful AI response —
// failures and default-token fallbacks never charge.
function requireCredits(n) {
    return async function (req, res, next) {
        if (!db) return next();
        try {
            await expireStaleCredits(req.user.id);
            const r = await db.query(
                `SELECT credit_balance, plan, coach_plan, coach_expires, pass_type, pass_expires_at
                 FROM rn_users WHERE id = $1`, [req.user.id]);
            if (!r.rows.length) return res.status(401).json({ error: 'Account not found.', code: 'AUTH_REQUIRED' });
            const u = r.rows[0];
            if (hasActivePass(u) || u.plan === 'pro' || coachAccess(u).unlimited) return next();
            if ((u.credit_balance || 0) < n) {
                const t = await db.query(
                    `SELECT COUNT(*)::int AS n FROM rn_credit_ledger WHERE user_id=$1 AND delta < 0 AND reason LIKE 'spend:%'`,
                    [req.user.id]).catch(() => ({ rows: [{ n: 0 }] }));
                return res.status(402).json({
                    error: `You're out of credits — this needs ${n}.`,
                    code: 'CREDITS_REQUIRED',
                    balance: u.credit_balance || 0, needed: n, actionsUsed: t.rows[0].n,
                });
            }
            const reason = ('spend:' + (req.baseUrl || req.path)).slice(0, 50);   // baseUrl is reset by finish-time
            res.on('finish', async () => {
                if (res.statusCode >= 200 && res.statusCode < 300 && !res.locals.aiFallback) {
                    try {
                        // conditional debit FIRST — ledger row only when it landed,
                        // so parallel requests can't drive ledger and balance apart
                        const d = await db.query(
                            `UPDATE rn_users SET credit_balance = credit_balance - $2, updated_at = NOW()
                             WHERE id = $1 AND credit_balance >= $2`, [req.user.id, n]);
                        if (d.rowCount) {
                            await db.query(
                                `INSERT INTO rn_credit_ledger(user_id, delta, reason) VALUES($1, $2, $3)`,
                                [req.user.id, -n, reason]);
                        } else {
                            console.warn(`[credits] raced to zero — action delivered uncharged for ${req.user.id}`);
                        }
                    } catch (e) { console.error('[credits] debit failed:', e.message); }
                }
            });
            return next();
        } catch (e) { console.error('[credits] check failed (fail-open):', e.message); return next(); }
    };
}

// ── v14 PDF export: gated by TEMPLATE, not plan. Free templates (and AI
// styles, which already cost a credit to generate) export clean for any
// signed-in user; the 7 premium templates need an active pass / legacy paid.
const FREE_TEMPLATES = ['sf-classic', 'sf-minimal', 'nordic-clean'];
async function requireTemplateEntitlement(req, res, next) {
    if (!db) return next();
    try {
        const html = String((req.body && req.body.html) || '');
        // AI-styled exports are always allowed — generating the style already
        // cost a credit. (Check the marker class explicitly: the base template
        // class appears FIRST in the class list, so a capture-group sniff alone
        // would wrongly bill AI styles applied over premium bases.)
        if (/rb-resume--ai-(tokens|generated)/i.test(html)) return next();
        const m = html.match(/rb-resume--([a-z0-9-]+)/i);
        const effective = (m ? m[1].toLowerCase() : '') || String((req.body && req.body.templateStyle) || '').toLowerCase();
        if (!effective || FREE_TEMPLATES.includes(effective)) return next();
        const r = await db.query(
            'SELECT plan, coach_plan, coach_expires, pass_type, pass_expires_at FROM rn_users WHERE id = $1',
            [req.user.id]);
        const u = r.rows[0] || {};
        if (hasActivePass(u) || u.plan === 'pro' || coachAccess(u).unlimited) return next();
        return res.status(402).json({
            error: 'This premium template needs a Season Pass — free templates export clean, forever.',
            code: 'PASS_REQUIRED', template: effective,
        });
    } catch (e) { console.error('[pdf-gate] failed (fail-open):', e.message); return next(); }
}

// Pro-only — used for downloads. Free users get a watermarked+blurred preview
// on the client and are blocked here from producing a real file.
async function requirePro(req, res, next) {
    if (!db) return next();
    try {
        const r = await db.query('SELECT plan, coach_plan, coach_expires FROM rn_users WHERE id = $1', [req.user.id]);
        const plan = (r.rows[0] && r.rows[0].plan) || 'free';
        const paid = plan === 'pro' || (r.rows[0] && coachAccess(r.rows[0]).unlimited);
        if (!paid) {
            return res.status(402).json({
                error: 'Downloading is a Pro feature. Upgrade to download your resume without a watermark.',
                code: 'PRO_REQUIRED', plan
            });
        }
        return next();
    } catch (e) {
        console.error('[PRO] check failed (fail-open):', e.message);
        return next();
    }
}

// v14 ladder: 1 credit per output-improving action; JD match stays free for
// signed-in users (anonymous teaser arrives in Phase 5); PDF export is gated
// by template, not plan. The old shared daily quota is retired.
app.use('/generate-template',   requirePremiumAuth, requireCredits(1));
app.use('/review-resume',       requirePremiumAuth, requireCredits(1));
app.use('/improve-summary',     requirePremiumAuth, requireCredits(1));   // was reachable anonymously — closed
app.use('/optimize-for-job',    requirePremiumAuth, requireCredits(1));   // was reachable anonymously — closed
app.use('/analyze-job-match',   optionalAuth);   // anonymous gets a teaser; signed-in gets the full report
app.use('/generate-pdf',        requirePremiumAuth, requireTemplateEntitlement);

// Payment endpoints - rate limited + session validated
app.use('/create-order',        paymentLimiter);
app.use('/create-order',        validateClientSession);
app.use('/verify-payment',      paymentLimiter);
app.use('/verify-payment',      validateClientSession);

// Magic link - rate limited to prevent email spam
app.use('/auth/magic-link/request', magicLinkLimiter);

// Auth polling - light rate limit
app.use('/auth/poll',           pollLimiter);
app.use('/auth/init-poll',      pollLimiter);

// --- Health / version -------------------------------------------------------
app.get('/version', (req, res) => {
    res.json({
        version:  SERVER_VERSION,
        bootTime: new Date(BOOT_TIME).toISOString(),
        nowTime:  new Date().toISOString()
    });
});

// --- Helpers ----------------------------------------------------------------

// Accepts: standard UUID (36 chars), or UUID-with-extras (up to 72 chars)
// Rejects: SQL injection strings, script tags, arbitrary text
const CLIENT_ID_PATTERN = /^[a-zA-Z0-9\-_]{8,72}$/;

// --- Shared API secret - first line of defence against external scraping -----
// Set RENONYM_API_SECRET in Railway env vars (any long random string, 32+ chars)
// Frontend sends it as x-api-secret header (via VITE_API_SECRET env var)
const API_SECRET = process.env.RENONYM_API_SECRET || null;

function validateApiSecret(req, res, next) {
    // If no secret configured on server, skip check (dev mode / not yet set up)
    if (!API_SECRET) return next();

    const provided = req.headers['x-api-secret'];
    if (!provided || provided !== API_SECRET) {
        console.warn(`[API-SECRET] Rejected request - invalid secret. IP=${req.ip} path=${req.path}`);
        return res.status(401).json({ error: 'Unauthorised.' });
    }
    next();
}

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

// --- PDF override CSS - BULLETPROOF VERSION ---------------------------------
// Rules are ordered: base -> structural -> content -> color-print
// Every rule uses !important to win over any app/token CSS.
const PDF_OVERRIDE_CSS = `

/* -- 1. Page & body reset ------------------------------------------------ */
html, body {
    margin: 0 !important; padding: 0 !important;
    background: #ffffff !important;
    overflow: visible !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}
* {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    box-sizing: border-box !important;
}

/* -- 2. Remove all browser/app chrome that interferes with PDF ----------- */
.rp-preview__scale-wrap,
.rp-preview,
.rp-builder,
.rp-topbar {
    transform: none !important;
    margin: 0 !important; padding: 0 !important;
}

/* -- 3. Resume root ------------------------------------------------------ */
.rb-resume {
    position: relative !important;
    display: block !important;
    transform: none !important;
    transform-origin: top left !important;
    width: 794px !important;
    min-height: 0 !important;
    height: auto !important;
    max-width: 794px !important;
    margin: 0 !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    overflow: visible !important;
    background: #ffffff !important;
    float: none !important;
}
.rb-resume:hover { transform: none !important; }

/* -- 3b. The app shell is dark, but the PDF page is always white paper ---- */
html, body {
    background: #ffffff !important;
    color-scheme: light !important;
}

/* -- 4. Header: full-width strip, auto height ---------------------------- */
.rb-resume__header {
    position: relative !important;
    display: flex !important;
    width: 100% !important;
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    float: none !important;
    flex-shrink: 0 !important;
}

/* -- 5. Body grid: LOCKED to 2 columns, auto height --------------------- */
/* This is the critical fix - prevents body from collapsing to 0 height    */
.rb-resume__body {
    display: grid !important;
    grid-template-columns: 210px 1fr !important;
    grid-template-rows: auto !important;
    width: 100% !important;
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    position: relative !important;
    float: none !important;
}

/* -- 6. Sidebar: left column, full stretch ------------------------------ */
.rb-resume__sidebar {
    grid-column: 1 / 2 !important;
    grid-row: 1 !important;
    display: flex !important;
    flex-direction: column !important;
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    position: relative !important;
    align-self: stretch !important;
    float: none !important;
}

/* -- 7. Main content: right column, full stretch ------------------------ */
.rb-resume__main {
    grid-column: 2 / 3 !important;
    grid-row: 1 !important;
    display: flex !important;
    flex-direction: column !important;
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    position: relative !important;
    align-self: stretch !important;
    float: none !important;
}

/* -- 8. Non-two-col layouts: undo the section-5 grid lock ---------------- */
/* Each AI layout keeps its own structure in the PDF — single/banner are
   block flows, asymmetric keeps its 35%/65% split.                         */
.rb-resume--layout-single .rb-resume__body,
.rb-resume--layout-single-ai .rb-resume__body,
.rb-resume--layout-banner .rb-resume__body {
    display: block !important;
    grid-template-columns: unset !important;
}
.rb-resume--layout-asymmetric .rb-resume__body {
    grid-template-columns: 35% 65% !important;
}
.rb-resume--layout-single .rb-resume__sidebar,
.rb-resume--layout-single-ai .rb-resume__sidebar,
.rb-resume--layout-banner .rb-resume__sidebar {
    grid-column: unset !important;
    width: 100% !important;
}
.rb-resume--layout-single .rb-resume__main,
.rb-resume--layout-single-ai .rb-resume__main,
.rb-resume--layout-banner .rb-resume__main {
    grid-column: unset !important;
    width: 100% !important;
}

/* -- 9. Sections and content: all visible, auto height ------------------ */
/* NOTE: .rb-skills is deliberately NOT in this group - forcing display:block
   on it kills the flex context and the pills wrap mid-word. It gets its own
   flex rule below (9b). */
.rb-resume__section,
.rb-resume .rb-exp-item,
.rb-resume .rb-edu-item,
.rb-resume .rb-cert,
.rb-resume .rb-summary {
    overflow: visible !important;
    height: auto !important;
    min-height: 0 !important;
    position: relative !important;
    display: block !important;
    float: none !important;
}

/* -- 9b. Skills: keep the pill row as a wrapping flex row, pills intact -- */
.rb-resume .rb-skills {
    display: flex !important;
    flex-wrap: wrap !important;
    gap: 4px !important;
    align-content: flex-start !important;
    overflow: visible !important;
    height: auto !important;
    min-height: 0 !important;
    position: relative !important;
    float: none !important;
}
.rb-resume .rb-skill-pill {
    display: inline-flex !important;
    align-items: center !important;
    white-space: normal !important;   /* a 40+ char skill wraps inside the pill, never crosses the page edge */
    overflow: visible !important;
    height: auto !important;
    flex: 0 1 auto !important;
    max-width: 100% !important;
}

/* -- 10. Bullet lists: keep the client's middot markers, just wrap text -- */
/* (forcing disc here used to double up with the client's li::before middot) */
.rb-resume .rb-exp-bullets {
    display: block !important;
    overflow: visible !important;
    height: auto !important;
}
.rb-resume .rb-exp-bullets li {
    display: block !important;        /* no native marker — the client's ::before middot is the only bullet */
    overflow: visible !important;
    height: auto !important;
    word-break: normal !important;
    overflow-wrap: break-word !important;
}

/* -- 10b. No unbroken string may escape the 794px page ------------------- */
.rb-resume p, .rb-resume span, .rb-resume div, .rb-resume li,
.rb-resume h1, .rb-resume h2, .rb-resume h3 {
    overflow-wrap: anywhere !important;
    word-break: break-word !important;
}

/* -- 11. Prevent page breaks INSIDE key elements ------------------------ */
.rb-resume__header,
.rb-exp-item,
.rb-edu-item {
    break-inside: avoid !important;
    page-break-inside: avoid !important;
}

/* -- 12. Color accuracy ------------------------------------------------- */
.rb-resume__photo-placeholder,
.rb-resume__top-deco,
.rb-resume .rb-cert,
.rb-resume .rb-skill-pill {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}
`;

// ----------------------------------------------------------------------------
// POST /generate-pdf
// ----------------------------------------------------------------------------
// Strips dangerous HTML tags from PDF payload before Puppeteer renders it.
// Cap is generous (6MB) because résumés can carry a base64 photo data-URL.
function sanitizePdfHtml(html) {
    if (!html) return '';
    let out = String(html)
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<iframe\b[^>]*>.*?<\/iframe>/gi, '')
        .replace(/<link[^>]+rel\s*=\s*["']?import["']?[^>]*>/gi, '');
    // Strip inline handlers / js: URLs ONLY inside tags — a résumé summary that
    // literally says "JavaScript: built SPAs" must come through untouched.
    let prev;
    do { prev = out; out = out.replace(/<([a-zA-Z][^>]*?)\son\w+\s*=\s*("[^"]*"|'[^']*')/g, '<$1'); } while (out !== prev);
    out = out.replace(/\b(href|src)\s*=\s*(["'])\s*javascript\s*:[^"']*\2/gi, '$1=$2#$2');
    return out.slice(0, 6_000_000);
}

// Chromium concurrency gate — each render launches a full browser (~300MB).
// 2 run at once; up to 6 wait their turn; beyond that we say "busy" instead
// of OOM-killing the Railway instance.
let pdfActive = 0;
const pdfWaiters = [];
function acquirePdfSlot() {
    if (pdfActive < 2) { pdfActive++; return Promise.resolve(true); }
    if (pdfWaiters.length >= 6) return Promise.resolve(false);
    return new Promise(resolve => pdfWaiters.push(resolve));
}
function releasePdfSlot() {
    const next = pdfWaiters.shift();
    if (next) next(true); else pdfActive = Math.max(0, pdfActive - 1);
}

app.post('/generate-pdf', async (req, res) => {

    console.log(`[${SERVER_VERSION}] /generate-pdf`, new Date().toISOString(), {
        htmlLen: req.body?.html?.length,
        cssLen:  req.body?.css?.length
    });

    const rawHtml = req.body && req.body.html;
    if (!rawHtml || String(rawHtml).trim().length < 50) {
        return res.status(400).json({ error: 'Nothing to export — the resume preview was empty.' });
    }
    const html = sanitizePdfHtml(String(rawHtml));
    const css  = String((req.body && req.body.css) || '').slice(0, 1_500_000);

    const slot = await acquirePdfSlot();
    if (!slot) return res.status(503).json({ error: 'Export queue is full — please try again in a few seconds.' });

    let browser = null;   // closed in finally — error paths must not leak Chromium
    try {
        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--font-render-hinting=none',
                '--force-device-scale-factor=1'
            ]
        });

        const page = await browser.newPage();
        // No deviceScaleFactor - causes coordinate issues with getBoundingClientRect
        // Use a tall enough viewport so nothing is virtualized off-screen
        await page.setViewport({ width: 794, height: 2000, deviceScaleFactor: 1 });

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

        // domcontentloaded + a BOUNDED font wait: a slow/hung Google Fonts CDN
        // degrades to fallback fonts instead of timing out the whole export
        // (networkidle0 made third-party font availability a hard dependency).
        await page.setContent(fullHtml, { waitUntil: 'domcontentloaded', timeout: 20000 });
        await page.emulateMediaType('screen');
        await Promise.race([
            page.evaluateHandle('document.fonts.ready').catch(() => {}),
            new Promise(r => setTimeout(r, 8000)),
        ]);

        // Settle: fonts + any deferred layout reflows
        await new Promise(r => setTimeout(r, 600));

        // -- ROBUST HEIGHT MEASUREMENT -------------------------------------
        // Problem: CSS grid containers often report height:0 in scrollHeight
        // because grid children with `align-self: stretch` don't expand the container.
        // Fix: force-unlock every structural element, then take the MAX of
        // four independent measurement strategies.
        const bodyH = await page.evaluate(() => {
            // 1. Unlock all overflow constraints
            document.body.style.setProperty('overflow', 'visible', 'important');
            document.documentElement.style.setProperty('overflow', 'visible', 'important');

            const el = document.querySelector('.rb-resume');
            if (!el) return document.documentElement.scrollHeight;

            // 2. Force the resume root and its grid/flex children to auto-height
            const forceAuto = (node) => {
                node.style.setProperty('height',     'auto',    'important');
                node.style.setProperty('min-height', '0',       'important');
                node.style.setProperty('overflow',   'visible', 'important');
            };
            forceAuto(el);
            const structurals = [
                '.rb-resume__body',
                '.rb-resume__sidebar',
                '.rb-resume__main',
            ];
            structurals.forEach(sel => {
                const node = el.querySelector(sel);
                if (node) forceAuto(node);
            });

            // 3. Measure the RESUME ELEMENT's true content height, relative to
            // its own top. We deliberately do NOT use
            // document.documentElement.scrollHeight: it is floored at the
            // viewport height (set to 2000 above), so any resume shorter than
            // that gets padded out to ~2000px, leaving a long blank tail.
            const top = el.getBoundingClientRect().top;

            // Strategy B: lowest point of any descendant, relative to the resume
            // top. Robust for grid/flex where the container's own height reads 0
            // (child boxes still report correct bottoms, even past the fold).
            let mB = 0;
            el.querySelectorAll('*').forEach(child => {
                const r = child.getBoundingClientRect();
                const bottom = r.bottom - top;
                if (bottom > mB) mB = bottom;
            });

            // Strategy D: the resume element's own box height after forcing auto.
            const mD = Math.max(el.scrollHeight, el.getBoundingClientRect().height);

            // +8px guards against sub-pixel clipping of the final line.
            const measured = Math.ceil(Math.max(mB, mD, 400)) + 8;
            console.log('[PDF-HEIGHT] B=' + Math.ceil(mB) + ' D=' + Math.ceil(mD) + ' -> ' + measured);
            return measured;
        });

        // Raise cap to 5000px - supports dense 4-page resumes without clipping
        const pdfH = Math.min(Math.max(bodyH, 800), 5000);
        console.log(`[${SERVER_VERSION}] /generate-pdf bodyH=${bodyH} pdfH=${pdfH}`);

        const pdf = await page.pdf({
            width: '794px',
            height: pdfH + 'px',
            printBackground: true,
            margin: { top: '0', right: '0', bottom: '0', left: '0' }
        });

        res.set({
            'Content-Type':    'application/pdf',
            'Content-Length':   pdf.length,
            'X-Server-Version': SERVER_VERSION
        });
        res.send(pdf);

    } catch (e) {
        console.error('PDF generation error:', e);
        if (!res.headersSent) res.status(500).send('PDF generation failed');
    } finally {
        releasePdfSlot();
        if (browser) await browser.close().catch(() => {});
    }
});

// ----------------------------------------------------------------------------
// POST /extract-resume
// ----------------------------------------------------------------------------
app.post('/extract-resume', async (req, res) => {

    try {
        let { text } = req.body;
        text = truncateText(text, 12000);
        if (!text) return res.status(400).json({ error: 'No text provided' });

        const prompt = `You are an expert resume parser. Extract structured data from the resume text below.

IMPORTANT - Two-column PDF note: The text may be extracted from a two-column PDF layout where sidebar content (skills, certifications, summary) is interleaved with main content (experience, education). Intelligently identify and separate these sections regardless of their order in the raw text.

Return ONLY valid JSON. No markdown, no code fences, no explanations.

Schema:
{
  "fullName": "string",
  "title": "string - job title/headline only, not a sentence",
  "email": "string",
  "phone": "string",
  "location": "string - city/country only",
  "linkedIn": "string - full URL or path",
  "summary": "string - 2-4 sentence professional summary, rewrite from About section if present",
  "skills": ["array of individual skill strings, max 20"],
  "experiences": [
    {
      "company": "string",
      "title": "string",
      "startDate": "string e.g. Jan 2021",
      "endDate": "string e.g. Present",
      "bullets": ["MAXIMUM 4 bullet points per role - pick the 4 most impactful, quantified achievements. Rewrite each to start with a strong action verb. Each bullet max 120 characters."]
    }
  ],
  "education": [
    {
      "degree": "string e.g. Bachelor of Technology",
      "field": "string e.g. Computer Science",
      "school": "string",
      "years": "string e.g. 2014 - 2018"
    }
  ],
  "certifications": ["array of certification name strings only, max 8"]
}

CRITICAL RULES:
1. MAX 4 bullets per experience role - choose the most impactful ones with numbers/results
2. MAX 20 skills - pick the most relevant technical skills
3. Ignore repeated or similar bullets - deduplicate
4. Skills, certifications, and summary often appear in a sidebar - extract them correctly even if interleaved with experience text
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

// ----------------------------------------------------------------------------
// AI THEME TOKENS - the bulletproof theming system
// ----------------------------------------------------------------------------
// The AI returns ONLY a set of colour + font values (design tokens). The
// frontend applies them as CSS custom properties (--rn-*) on a 100%-hardcoded
// layout. The AI never authors CSS, so it can NEVER touch grid/position/size:
// layout is structurally unbreakable no matter what the user prompts.
//
// This server's job is to guarantee the token set is ALWAYS complete, valid,
// and accessible: every colour is a real hex value, every font is whitelisted,
// and text/background pairs meet WCAG AA contrast. Anything the model gets
// wrong is repaired here before it ever reaches the client.

// Fonts the frontend supports (app.css [data-font] selectors). Anything the
// model returns that is not in this list is coerced to 'Inter'.
const ALLOWED_FONTS = ['Inter', 'Helvetica', 'Georgia', 'Times New Roman', 'Poppins', 'Roboto', 'system-ui'];

// Safe fallback palette (Salesforce-classic look) used for any missing/invalid
// token, and as the entire response if the AI call fails.
const DEFAULT_TOKENS = {
    headerBg:     '#032d60',
    headerText:   '#ffffff',
    headerSub:    '#cfe0f3',
    sidebarBg:    '#f5f7fa',
    sidebarText:  '#374151',
    sidebarTitle: '#032d60',
    accent:       '#0b5cab',
    mainBg:       '#ffffff',
    mainText:     '#1f2937',
    mainTitle:    '#032d60',
    mainRole:     '#0b5cab',
    skillBg:      '#e8eef7',
    skillText:    '#032d60',
    certBg:       '#00000000',  // transparent by default
    certText:     '#374151',
    fontBody:     'Inter',
    fontHeading:  'Inter'
};

// Colour token keys (everything except the two font keys)
const COLOR_TOKEN_KEYS = Object.keys(DEFAULT_TOKENS).filter(k => !k.startsWith('font'));

// Accept only real CSS hex colours: #rgb, #rgba, #rrggbb, #rrggbbaa
const HEX_PATTERN = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

function isHex(v) { return typeof v === 'string' && HEX_PATTERN.test(v.trim()); }

// Reduce any hex (incl. alpha / shorthand) to an opaque 6-digit hex for the
// luminance helpers, which expect 3- or 6-digit input.
function toOpaqueHex6(hex) {
    let h = String(hex || '').replace(/^#/, '');
    if (h.length === 4) h = h.slice(0, 3);        // #rgba -> #rgb
    else if (h.length === 8) h = h.slice(0, 6);   // #rrggbbaa -> #rrggbb
    return '#' + h;
}

// Returns true when a hex value is fully transparent (alpha 00)
function isTransparent(hex) {
    const h = String(hex || '').replace(/^#/, '');
    if (h.length === 8) return h.slice(6).toLowerCase() === '00';
    if (h.length === 4) return h.slice(3).toLowerCase() === '0';
    return false;
}

function clampFont(v) {
    if (typeof v !== 'string') return 'Inter';
    const match = ALLOWED_FONTS.find(f => f.toLowerCase() === v.trim().toLowerCase());
    return match || 'Inter';
}

// --- WCAG contrast helpers (reused for token validation) --------------------
function hexToRgb(hex) {
    hex = hex.replace(/^#/, '');
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    const n = parseInt(hex, 16);
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}
function relativeLuminance({ r, g, b }) {
    return [r, g, b].reduce((sum, v, i) => {
        v /= 255;
        v = v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        return sum + v * [0.2126, 0.7152, 0.0722][i];
    }, 0);
}
function contrastRatio(hex1, hex2) {
    try {
        const l1 = relativeLuminance(hexToRgb(toOpaqueHex6(hex1)));
        const l2 = relativeLuminance(hexToRgb(toOpaqueHex6(hex2)));
        const [hi, lo] = [Math.max(l1, l2), Math.min(l1, l2)];
        return (hi + 0.05) / (lo + 0.05);
    } catch (e) { return 4.5; }
}
function ensureReadableText(bgHex) {
    const rw = contrastRatio(bgHex, '#FFFFFF');
    const rb = contrastRatio(bgHex, '#000000');
    if (rw >= 4.5) return '#FFFFFF';
    if (rb >= 4.5) return '#000000';
    return rw > rb ? '#FFFFFF' : '#111111';
}

// Take whatever the model produced and return a guaranteed-valid token set:
//  1. every colour is a real hex (else falls back to DEFAULT_TOKENS)
//  2. fonts are whitelisted
//  3. text/background pairs are forced to >= 4.5:1 WCAG AA contrast
function sanitizeTokens(raw) {
    const t = {};
    const src = (raw && typeof raw === 'object') ? raw : {};

    // 1. Colours: keep valid hex, else fall back to the safe default
    COLOR_TOKEN_KEYS.forEach(key => {
        t[key] = isHex(src[key]) ? src[key].trim() : DEFAULT_TOKENS[key];
    });

    // 2. Fonts: whitelist only
    t.fontBody    = clampFont(src.fontBody);
    t.fontHeading = clampFont(src.fontHeading);

    // 3. Contrast: fix the TEXT colour wherever it can't be read on its bg.
    // Cert background is often transparent, so test cert text against the
    // sidebar background it actually sits on.
    const pairs = [
        ['headerText',   'headerBg'],
        ['headerSub',    'headerBg'],
        ['sidebarText',  'sidebarBg'],
        ['sidebarTitle', 'sidebarBg'],
        ['mainText',     'mainBg'],
        ['mainTitle',    'mainBg'],
        ['skillText',    'skillBg'],
        ['certText',     isTransparent(t.certBg) ? 'sidebarBg' : 'certBg']
    ];
    const fixed = [];
    pairs.forEach(([textKey, bgKey]) => {
        const bg = t[bgKey];
        if (contrastRatio(bg, t[textKey]) < 4.5) {
            t[textKey] = ensureReadableText(bg);
            fixed.push(textKey);
        }
    });
    if (fixed.length) console.log('[token-contrast] fixed:', fixed.join(', '));

    return t;
}

// ----------------------------------------------------------------------------
// POST /generate-template
// ----------------------------------------------------------------------------
// Returns { tokens, layout }. The AI picks colours/fonts (tokens) and a layout
// from a fixed set; the frontend renders a hardcoded structure styled by those
// tokens. No CSS is ever generated or trusted.
app.post('/generate-template', async (req, res) => {

    try {
        const {
            prompt,
            metadata,
            inspirationBase64,
            inspirationMimeType
        } = req.body;

        const hasInspiration = !!(
            inspirationBase64 &&
            inspirationMimeType &&
            (inspirationMimeType.startsWith('image/') || inspirationMimeType === 'application/pdf') &&
            inspirationBase64.length < 7_200_000  // ~5MB raw → ~6.7M base64; matches the client's 5MB cap
        );

        // -- Step 1: If inspiration image provided, vision-analyse it first --
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
Focus exclusively on: colour palette (give hex values where you can), typography character (serif/sans), spacing density, header treatment, sidebar vs single-column, visual hierarchy.
Return a compact, structured paragraph of design signals only.`
                        },
                        {
                            role: 'user',
                            content: [
                                {
                                    type: 'image_url',
                                    image_url: {
                                        url:    `data:${inspirationMimeType};base64,${inspirationBase64}`,
                                        detail: 'low'
                                    }
                                },
                                {
                                    type: 'text',
                                    text: 'Analyse this resume image for design and style signals only. Extract colour palette (hex if possible), typography style, layout structure, header style, visual density. Return only design signals, no personal data.'
                                }
                            ]
                        }
                    ],
                    max_tokens: 300,
                    temperature: 0.3
                });
                inspirationStyleSignals = visionCompletion.choices[0].message.content.trim();
                console.log(`[${SERVER_VERSION}] Inspiration signals:`, inspirationStyleSignals.slice(0, 100));
            } catch (visionErr) {
                console.warn(`[${SERVER_VERSION}] Vision analysis failed (non-fatal):`, visionErr.message);
            }
        }

        // -- Step 2: Classify layout (one of the four hardcoded layouts) -----
        let detectedLayout = 'two-col';
        if (inspirationStyleSignals || prompt) {
            try {
                const layoutCompletion = await openai.chat.completions.create({
                    model: 'gpt-4.1-mini',
                    messages: [{
                        role: 'user',
                        content: `You are a resume layout classifier.

Given this design brief and style signals:
PROMPT: ${sanitizeInput(prompt)}
SIGNALS: ${inspirationStyleSignals || 'none'}

Classify the layout as ONE of:
- two-col: narrow left sidebar (skills/about) + wider right column (experience/education)
- single: single full-width column, all sections stacked
- top-banner: full-width coloured header across the top, content below
- asymmetric: identity/contact/skills in left accent column (35%), experience/education in wider right (65%)

Reply with ONLY ONE word: two-col, single, top-banner, or asymmetric`
                    }],
                    max_tokens: 10,
                    temperature: 0
                });
                const raw = layoutCompletion.choices[0].message.content.trim().toLowerCase();
                if (['two-col','single','top-banner','asymmetric'].includes(raw)) {
                    detectedLayout = raw;
                }
            } catch (e) {
                // non-fatal - use default
            }
        }

        // -- Step 3: Generate design TOKENS (colours + fonts only) -----------
        const tokenSystemPrompt = `You are an elite resume colour & typography designer.
You DO NOT write CSS. You return ONLY a JSON object of design tokens.

Return EXACTLY these keys, every value a CSS hex colour (e.g. "#1a2b3c") except
fontBody and fontHeading which must be one of:
Inter, Helvetica, Georgia, Times New Roman, Poppins, Roboto, system-ui.

{
  "headerBg":     "hex - header/banner background",
  "headerText":   "hex - main name text on the header",
  "headerSub":    "hex - title line + contact text on the header",
  "sidebarBg":    "hex - sidebar background",
  "sidebarText":  "hex - sidebar body text",
  "sidebarTitle": "hex - sidebar section titles",
  "accent":       "hex - primary accent (rules, role titles, highlights)",
  "mainBg":       "hex - main content background (usually white or near-white)",
  "mainText":     "hex - main content body text",
  "mainTitle":    "hex - main section titles",
  "mainRole":     "hex - job role / position titles",
  "skillBg":      "hex - skill pill background",
  "skillText":    "hex - skill pill text",
  "certBg":       "hex - certification chip background (use #00000000 for transparent)",
  "certText":     "hex - certification text",
  "fontBody":     "one allowed font name",
  "fontHeading":  "one allowed font name"
}

RULES:
- Output ONLY the JSON object. No markdown, no commentary.
- Ensure strong, readable contrast between every text colour and its background (aim for WCAG AA, 4.5:1+).
- Match the requested mood/brand/aesthetic precisely with real hex values.
- Keep it professional and ATS-friendly (clean, not garish).`;

        const densityNote = (metadata?.totalBullets > 12 || metadata?.experienceCount > 3)
            ? 'This is a dense resume - prefer a calm, high-contrast palette that stays readable at small sizes.'
            : '';

        const inspirationNote = inspirationStyleSignals
            ? `\nSTYLE SIGNALS from an uploaded reference (translate the palette/typography into tokens):\n${inspirationStyleSignals}`
            : '';

        const tokenUserPrompt = `DESIGN REQUEST:
${sanitizeInput(prompt) || 'A clean, modern, professional resume.'}
${inspirationNote}
${densityNote}

Return the design tokens as JSON only.`;

        let tokens;
        try {
            const completion = await openai.chat.completions.create({
                model:           'gpt-4.1-mini',
                messages:        [
                    { role: 'system', content: tokenSystemPrompt },
                    { role: 'user',   content: tokenUserPrompt   }
                ],
                temperature:     0.5,
                max_tokens:      500,
                response_format: { type: 'json_object' }
            });
            const rawTokens = JSON.parse(completion.choices[0].message.content);
            tokens = sanitizeTokens(rawTokens);
        } catch (aiErr) {
            // Graceful degradation - never fail the theming path on an AI hiccup
            console.warn(`[${SERVER_VERSION}] Token generation failed (using defaults):`, aiErr.message);
            tokens = { ...DEFAULT_TOKENS };
            res.locals.aiFallback = true;   // don't charge quota for a default theme
        }

        console.log(`[${SERVER_VERSION}] /generate-template -> layout=${detectedLayout} accent=${tokens.accent}${res.locals.aiFallback ? ' (FALLBACK)' : ''}`);
        // fallback:true lets the client say "applied a safe default" instead of
        // claiming a custom theme was generated.
        res.json({ tokens, layout: detectedLayout, fallback: !!res.locals.aiFallback });

    } catch (e) {
        console.error('Template generation error:', e);
        // Even on an unexpected error, hand back a usable theme rather than 500
        res.locals.aiFallback = true;
        res.json({ tokens: { ...DEFAULT_TOKENS }, layout: 'two-col', fallback: true });
    }
});

// ----------------------------------------------------------------------------
// POST /improve-summary
// ----------------------------------------------------------------------------
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
- 3-4 sentences maximum
- First sentence: years of experience + core expertise + industry context
- Second sentence: 1-2 quantified or notable achievements
- Third sentence: technical strengths or specialisation
- Fourth sentence (optional): value proposition or career goal
- Tone: confident, professional, concise - NOT cliched
- NO phrases like "results-driven", "passionate", "dynamic", "team player", "go-getter"
- ATS-friendly: include relevant keywords naturally
- Return ONLY the summary text, no labels, no quotes, no explanation`;

        const completion = await openai.chat.completions.create({
            model:       'gpt-4.1',
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

// ----------------------------------------------------------------------------
// POST /review-resume
// ----------------------------------------------------------------------------
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
4. ATS optimization tips (2-3 points)
5. One key recommendation to immediately increase interview chances

Keep response under 250 words. Be direct and specific - no generic advice.`;

        const completion = await openai.chat.completions.create({
            model:       'gpt-4.1',
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

// ----------------------------------------------------------------------------
// Start
// ----------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

// --- Helper: turn resumeData or resumeText into a readable string -----------
function buildResumeString(resumeData, resumeText) {
    // If we have structured data, use it (gives GPT cleaner, more structured input)
    // Append raw text only if structured data seems sparse (no experiences)
    const hasStructured = resumeData && (
        resumeData.fullName || resumeData.summary || resumeData.experiences?.length
    );

    if (hasStructured) {
        const structured = serializeResumeData(resumeData);
        if (resumeText && !resumeData.experiences?.length) {
            return (structured + '\n\n--- ADDITIONAL CONTEXT FROM UPLOADED FILE ---\n' + resumeText).slice(0, 8000);
        }
        return structured.slice(0, 8000);
    }

    if (resumeText && resumeText.trim().length > 50) {
        return resumeText.trim().slice(0, 8000);
    }

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
            const dates = exp.dateRange || [exp.startDate, exp.endDate].filter(Boolean).join(' - ');
            lines.push(`  ${exp.title || ''} at ${exp.company || ''} (${dates})`);
            (exp.bullets || []).forEach(b => lines.push(`    - ${b}`));
        });
    }
    if (resumeData.education?.length) {
        lines.push('\nEducation:');
        resumeData.education.forEach(edu => {
            lines.push(`  ${edu.degree || ''}${edu.field ? ', ' + edu.field : ''} - ${edu.school || ''} (${edu.years || ''})`);
        });
    }
    return lines.join('\n').slice(0, 8000);
}

// --- POST /analyze-job-match ------------------------------------------------
// Accepts either { resumeData, jobDescription } or { resumeText, jobDescription }
// Returns structured gap analysis: scores + specific actionable suggestions
// ----------------------------------------------------------------------------
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
Your feedback must be SPECIFIC to this exact resume and JD - never generic.
You return ONLY valid JSON, no markdown, no explanation outside the JSON.`;

        const userPrompt = `Analyse this resume against the job description. Be precise and specific.

=== RESUME ===
${resumeString}

=== JOB DESCRIPTION ===
${jobDescription.trim().slice(0, 5000)}

=== SCORING RULES ===
- atsScore (0-100): How well the resume is structured for ATS parsing. Consider: section headings present, contact info visible, no tables/columns that break parsing, bullet points used, quantified achievements, appropriate length.
- jdMatch (0-100): How well the candidate's actual experience and skills match what the JD requires. Be realistic - a mismatch in seniority or core skills should give a low score.
- keywordCoverage (0-100): Percentage of important technical/domain keywords from the JD that appear anywhere in the resume.
- skillsCoverage (0-100): Percentage of explicitly listed required skills in the JD that appear in the resume skills section.

=== OUTPUT FORMAT ===
Return ONLY this JSON (no markdown fences):
{
  "atsScore": <integer 0-100>,
  "jdMatch": <integer 0-100>,
  "keywordCoverage": <integer 0-100>,
  "skillsCoverage": <integer 0-100>,
  "missingKeywords": [
    "<specific keyword from JD not in resume - be exact, e.g. 'Salesforce CPQ' not 'CRM tools'>",
    ... up to 8 items
  ],
  "missingSkills": [
    "<specific skill required by JD not in resume skills - be exact>",
    ... up to 6 items
  ],
  "strengths": [
    "<specific strength this resume has FOR THIS JD - reference actual content, e.g. '7 years of Apex development aligns with the Senior Developer requirement'>",
    ... 3-4 items
  ],
  "weaknesses": [
    "<specific, actionable gap - tell the candidate EXACTLY what to fix, e.g. 'Your summary does not mention Salesforce Lightning which appears 4 times in the JD - add it in the first sentence'>",
    ... 3-5 items
  ],
  "summarySuggestions": [
    "<concrete instruction for improving the summary for this specific JD - e.g. 'Add the phrase cloud-based CRM architecture to your summary opening line'>",
    ... 2-3 items
  ],
  "experienceSuggestions": [
    "<specific instruction for an experience bullet - e.g. 'Under your Infosys role, add a bullet quantifying how many Salesforce orgs you managed'>",
    ... 2-3 items
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

        // Clamp scores to 0-100
        ['atsScore','jdMatch','keywordCoverage','skillsCoverage'].forEach(k => {
            if (typeof result[k] === 'number') result[k] = Math.max(0, Math.min(100, Math.round(result[k])));
        });

        // Ensure all array fields exist
        ['missingKeywords','missingSkills','strengths','weaknesses',
         'summarySuggestions','experienceSuggestions'].forEach(k => {
            if (!Array.isArray(result[k])) result[k] = [];
        });

        console.log(`[${SERVER_VERSION}] /analyze-job-match - ATS:${result.atsScore} JD:${result.jdMatch}${req.user ? '' : ' (anon teaser)'}`);
        if (!req.user) {
            // anonymous teaser: scores + top-3 gaps — the full report is the
            // signup hook (free account + 2 starter credits)
            return res.json({
                atsScore: result.atsScore, jdMatch: result.jdMatch,
                missingKeywords: (result.missingKeywords || []).slice(0, 3),
                locked: true,
            });
        }
        res.json(result);

    } catch (err) {
        console.error('/analyze-job-match error:', err);
        res.status(500).json({ error: 'Job match analysis failed. Please try again.' });
    }
});

// --- POST /optimize-for-job -------------------------------------------------
// Rewrites resume summary + experience bullets to target the JD
// NEVER invents facts - only rephrases existing content
// ----------------------------------------------------------------------------
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

ABSOLUTE RULES - breaking any of these makes the output worthless:
1. NEVER invent companies, job titles, dates, degrees, or certifications
2. NEVER add skills or achievements the candidate has not demonstrated
3. ONLY rephrase, reword, or restructure EXISTING content
4. Incorporate JD keywords NATURALLY - never stuff them awkwardly
5. Use strong action verbs: Led, Architected, Delivered, Reduced, Increased, Launched, Scaled
6. Keep bullets concise - maximum 130 characters each
7. Return ONLY valid JSON - no markdown, no explanation`;

        const userPrompt = `Optimise this resume for the job description below.

=== RESUME ===
${resumeString}

=== JOB DESCRIPTION ===
${jobDescription.trim().slice(0, 5000)}

=== INSTRUCTIONS ===
1. Rewrite the professional summary (3-4 sentences) to open with the candidate's most relevant strength for this specific role, then incorporate the top 3-4 keywords from the JD naturally.
2. For each experience role, rewrite or strengthen the bullet points to highlight achievements and responsibilities that align with the JD requirements. Do NOT add bullets that aren't based on existing content.
3. Reorder the skills array so the most JD-relevant skills appear first. You may add 1-2 skills that are clearly implied by their experience (e.g. if they built Salesforce integrations, adding "REST API Integration" is fair).
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


// ============================================================================
//  AUTH  -  Google OAuth . LinkedIn OAuth . Email Magic Link
// ============================================================================

// --- Helpers ----------------------------------------------------------------

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

// Attaches req.user when a valid Bearer token is present; never rejects.
// Used by routes that serve a TEASER to anonymous callers (JD match).
function optionalAuth(req, res, next) {
    try {
        const header = req.headers['authorization'] || '';
        const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (token) req.user = jwt.verify(token, JWT_SECRET);
    } catch (_) { /* anonymous */ }
    next();
}

function requireAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); }
    catch (_) { res.status(401).json({ error: 'Session expired. Please log in again.', code: 'AUTH_REQUIRED' }); }
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
        `INSERT INTO rn_users(email,name,provider,provider_user_id,avatar_url,anonymous_client_id,referral_code)
         VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [email, name, provider, providerUserId || null, avatarUrl || null, anonClientId || null, makeReferralCode()]
    );
    return { ...r.rows[0], created: true };   // brand-new account — Phase 5 signup grant keys off this
}

// Returns HTML page rendered inside the OAuth popup that posts the token back
// to the parent LWC window and self-closes.
function authSuccessPage(token, user) {
    const safe = JSON.stringify({
        id: user.id, email: user.email, name: user.name,
        avatarUrl: user.avatar_url, plan: user.plan || 'free'
    }).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
    return `<!DOCTYPE html><html><head><title>Signing in...</title>
<style>*{margin:0}body{font-family:system-ui,sans-serif;background:#0b0c1a;color:#fff;height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px}
.ring{width:40px;height:40px;border:3px solid #7c3aed;border-top-color:transparent;border-radius:50%;animation:s .8s linear infinite}@keyframes s{to{transform:rotate(360deg)}}</style></head>
<body><div class="ring"></div><p style="font-size:14px;color:rgba(255,255,255,0.5)">Signing you in...</p>
<script>
(function(){
  try{ window.opener && window.opener.postMessage({type:'RENONYM_AUTH_SUCCESS',token:'TOKEN',user:USER},'FRONTEND'); }catch(e){}
  setTimeout(function(){try{window.close();}catch(e){}},400);
})();
</script></body></html>`
        .replace('TOKEN', token)
        .replace('USER', safe)
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

// --- Google OAuth -----------------------------------------------------------

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
        if (user.created) await grantSignupCredits(user.id);
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

// --- LinkedIn OAuth ---------------------------------------------------------

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
        if (user.created) await grantSignupCredits(user.id);
        const token = signToken(user);
        console.log('[AUTH] LinkedIn login:', user.email);
        res.send(authSuccessPage(token, user));
    } catch (e) {
        console.error('[AUTH] LinkedIn callback error:', e.message);
        res.send(authErrorPage('LinkedIn sign-in failed. Please try again.'));
    }
});

// --- Magic Link -------------------------------------------------------------

app.post('/auth/magic-link/request', async (req, res) => {
    if (!dbRequired(res)) return;
    const { email, clientId } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (!mailer)
        return res.status(503).json({ error: 'Email not configured on server. Use Google sign-in instead.' });
    try {
        const rawToken  = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await db.query('DELETE FROM rn_magic_tokens WHERE email=$1 AND used_at IS NULL', [email]);
        await db.query(
            'INSERT INTO rn_magic_tokens(email,token,expires_at,client_id) VALUES($1,$2,$3,$4)',
            [email, rawToken, expiresAt, clientId || null]
        );
        // Register the polling slot so the SPA can pick up the session after the
        // user clicks the email link (popup/opener can't be relied on from mail apps).
        if (clientId) {
            pendingAuthSessions.set(clientId + '_ml', null);
            setTimeout(() => {
                const v = pendingAuthSessions.get(clientId + '_ml');
                if (v === null) pendingAuthSessions.delete(clientId + '_ml');
            }, 15 * 60 * 1000);
        }
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
        if (user.created) await grantSignupCredits(user.id);
        const jwtToken = signToken(user);
        const safeUser = { id:user.id, email:user.email, name:user.name, avatarUrl:user.avatar_url, plan:user.plan||'free' };
        // Set unconditionally (not just if pre-registered) so a server restart
        // between request and click doesn't strand the sign-in.
        if (link.client_id) {
            pendingAuthSessions.set(link.client_id + '_ml', { token: jwtToken, user: safeUser, createdAt: Date.now() });
        }
        console.log('[AUTH] Magic link login:', user.email);
        res.send(authSuccessPage(jwtToken, safeUser));
    } catch (e) {
        console.error('[AUTH] Magic link verify error:', e.message);
        res.send(authErrorPage('Sign-in failed. Please try again.'));
    }
});

// --- Session endpoints ------------------------------------------------------

app.get('/auth/me', requireAuth, async (req, res) => {
    if (!dbRequired(res)) return;
    try {
        const r = await db.query('SELECT * FROM rn_users WHERE id=$1', [req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'User not found.' });
        const u = r.rows[0];
        await expireStaleCredits(u.id);
        const fresh = await db.query('SELECT credit_balance FROM rn_users WHERE id=$1', [u.id]).catch(() => null);
        res.json({ id:u.id, email:u.email, name:u.name, avatarUrl:u.avatar_url,
            plan:u.plan, resumeCount:u.resume_count, atsCount:u.ats_reports_count,
            createdAt:u.created_at, lastLoginAt:u.last_login_at,
            coach: coachAccess(u),
            // v14 ladder — one call refreshes the whole entitlement surface
            credits: fresh && fresh.rows.length ? fresh.rows[0].credit_balance : (u.credit_balance || 0),
            passType: hasActivePass(u) ? u.pass_type : null,
            passExpiresAt: hasActivePass(u) ? u.pass_expires_at : null,
            passInterviewsRemaining: hasActivePass(u) ? (u.pass_interviews_remaining || 0) : 0,
            interviewCredits: u.interview_credits || 0,
            freeInterviewUsed: !!u.free_interview_used,
            referralCode: u.referral_code || null,
            grandfathered: !!u.grandfathered });
    } catch (e) { res.status(500).json({ error: 'Failed to load profile.' }); }
});


// --- Auth polling - LWC Locker Service safe alternative to postMessage -------
// LWC cannot use window.addEventListener('message') due to Locker Service.
// Instead: LWC polls this endpoint every 1.5s after opening the OAuth popup.
// Flow: LWC calls /auth/init-poll -> gets nonce -> opens popup with nonce
//       -> server stores JWT by nonce after OAuth -> LWC polls /auth/poll?nonce
//       -> returns JWT when ready -> LWC stores token and updates state

const pendingAuthSessions = new Map(); // nonce -> { token, user } or null

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

// --- Save Resume (requires auth) --------------------------------------------

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

// --- Calorie Calculator -----------------------------------------------------

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



// ============================================================================
// RAZORPAY - PAYMENT INTEGRATION
// ============================================================================

const PLANS = {
    // ── v14 credit + pass ladder (one-time orders; amounts live HERE only) ──
    boost_299:         { amount: 29900,  label: 'Boost Pack — 10 credits',      currency: 'INR', grant: 'boost' },
    single_499:        { amount: 49900,  label: 'Single Interview',             currency: 'INR', grant: 'single' },
    season_1499:       { amount: 149900, label: 'Season Pass — 90 days',        currency: 'INR', grant: 'season' },
    pro_2999:          { amount: 299900, label: 'Placement Pro — 90 days',      currency: 'INR', grant: 'placement' },
    report_unlock_299: { amount: 29900,  label: 'Full Report Unlock',           currency: 'INR', grant: 'report_unlock' },
    // ── retired SKUs: no longer purchasable; kept so historical verify-payment
    //    replays and refund lookups stay safe ──
    pro_monthly:  { amount: 59900,  label: 'Pro Monthly',  currency: 'INR', retired: true },
    pro_yearly:   { amount: 598800, label: 'Pro Yearly',   currency: 'INR', retired: true },
    team_monthly: { amount: 179900, label: 'Team Monthly', currency: 'INR', retired: true },
    team_yearly:  { amount: 1798800,label: 'Team Yearly',  currency: 'INR', retired: true },
    coach_unlimited:        { amount: 159900,  label: 'Coach Unlimited',      currency: 'INR', coach: 'unlimited', retired: true },
    coach_unlimited_yearly: { amount: 1318800, label: 'Coach Unlimited (yr)', currency: 'INR', coach: 'unlimited', retired: true },
    session_pass:           { amount: 59900,   label: 'Coach Session Pass',   currency: 'INR', coach: 'pass', retired: true }
};

// POST /create-order
// Creates a Razorpay order server-side - key_secret never leaves the server
app.post('/create-order', async (req, res) => {
    try {
        const { planId, userId } = req.body;

        const plan = PLANS[planId];
        if (!plan) {
            return res.status(400).json({ error: 'Invalid plan ID' });
        }
        // Bridge: old SKUs stay purchasable until the Phase-3 ladder UI is live.
        // Flip LADDER_LIVE=true on Railway when the new checkout deploys.
        if (plan.retired && process.env.LADDER_LIVE === 'true') {
            return res.status(400).json({ error: 'This plan is no longer available — see the new plans.' });
        }
        // report unlocks are bound to ONE owned, still-locked free session —
        // reject up front so ₹299 can never be captured with nothing to grant
        if (planId === 'report_unlock_299') {
            let uid = null;
            try {
                const ah = req.headers['authorization'] || '';
                const tk = ah.startsWith('Bearer ') ? ah.slice(7) : null;
                if (tk) uid = jwt.verify(tk, JWT_SECRET).id;
            } catch (e) {}
            const sid = String(req.body.sessionId || '');
            if (!uid) return res.status(401).json({ error: 'Sign in to unlock your report.', code: 'AUTH_REQUIRED' });
            if (!UUID_RE.test(sid)) return res.status(400).json({ error: 'Missing interview session for this unlock.' });
            if (db) {
                const chk = await db.query(
                    `SELECT id FROM rn_interview_sessions
                     WHERE id=$1 AND user_id=$2 AND is_free_session=TRUE AND report_unlocked=FALSE`, [sid, uid]);
                if (!chk.rows.length) return res.status(400).json({ error: 'That report is already unlocked (or the session was not found).' });
            }
        }
        if (plan.amount < 100) {
            return res.status(400).json({ error: 'Amount must be at least 100 paise' });
        }

        const receipt = `rcpt_${planId}_${Date.now()}`;

        const order = await razorpay.orders.create({
            amount:   plan.amount,
            currency: plan.currency,
            receipt:  receipt,
            notes: {
                plan:      planId,
                userId:    userId || 'guest',
                // report unlocks are bound to one interview session
                sessionId: (planId === 'report_unlock_299' && req.body.sessionId && UUID_RE.test(String(req.body.sessionId))) ? String(req.body.sessionId) : ''
            }
        });

        console.log(`[${SERVER_VERSION}] Razorpay order created: ${order.id} plan=${planId}`);

        res.json({
            order_id: order.id,
            amount:   order.amount,
            currency: order.currency,
            key_id:   process.env.RAZORPAY_KEY_ID   // safe: public key only
        });

    } catch (err) {
        console.error(`[${SERVER_VERSION}] create-order error:`, err.message);
        if (err.statusCode === 401) {
            return res.status(401).json({ error: 'Razorpay auth failed - check credentials' });
        }
        res.status(500).json({ error: 'Failed to create order', details: err.message });
    }
});

// POST /verify-payment
// Verifies Razorpay signature using HMAC-SHA256 - never trust client-side success alone
app.post('/verify-payment', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature, planId, userId } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ error: 'Missing payment fields' });
        }

        // HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
        const body      = razorpay_order_id + '|' + razorpay_payment_id;
        const expected  = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body)
            .digest('hex');

        if (expected !== razorpay_signature) {
            console.warn(`[${SERVER_VERSION}] Signature mismatch for order ${razorpay_order_id}`);
            return res.status(400).json({ error: 'Invalid payment signature' });
        }

        // The plan is derived from the ORDER (created server-side with the real
        // amount), never from the client body — a ₹599 payment can't claim
        // coach_unlimited by sending a different planId.
        let effectivePlanId = planId;
        try {
            const order = await razorpay.orders.fetch(razorpay_order_id);
            if (order && order.notes && order.notes.plan && PLANS[order.notes.plan]) {
                effectivePlanId = order.notes.plan;
                if (planId && planId !== effectivePlanId) {
                    console.warn(`[${SERVER_VERSION}] planId mismatch: body=${planId} order=${effectivePlanId} — using order`);
                }
            }
        } catch (e) { console.error(`[${SERVER_VERSION}] order fetch failed (using body planId):`, e.message); }
        const plan = PLANS[effectivePlanId];
        if (!plan) return res.status(400).json({ error: 'Unknown plan for this payment.' });
        console.log(`[${SERVER_VERSION}] Payment verified: order=${razorpay_order_id} payment=${razorpay_payment_id} plan=${effectivePlanId}`);

        // Resolve the user to grant to. Prefer the signed-in JWT (always sent by
        // the client) over the body userId, which can be missing/stale — that was
        // causing Coach entitlement to silently not save after payment.
        let grantUserId = null;
        try {
            const ah = req.headers['authorization'] || '';
            const tk = ah.startsWith('Bearer ') ? ah.slice(7) : null;
            if (tk) grantUserId = jwt.verify(tk, JWT_SECRET).id;
        } catch (e) { /* ignore bad/expired token */ }
        if (!grantUserId) grantUserId = userId;
        const coach = plan.coach; // 'unlimited' | 'pass' | undefined
        console.log(`[${SERVER_VERSION}] grant → user=${grantUserId} plan=${effectivePlanId} coach=${coach || 'none'}`);

        // Replay protection: a payment id grants exactly once. ON CONFLICT no-op
        // → if it was already redeemed, acknowledge success without re-granting.
        let redeemed = false;
        if (db) {
            try {
                const ins = await db.query(
                    `INSERT INTO rn_payments(payment_id, order_id, plan_id, user_id)
                     VALUES($1,$2,$3,$4) ON CONFLICT (payment_id) DO NOTHING`,
                    [razorpay_payment_id, razorpay_order_id, effectivePlanId, grantUserId || null]
                );
                redeemed = ins.rowCount > 0;
                if (!redeemed) {
                    console.warn(`[${SERVER_VERSION}] Replay blocked: payment ${razorpay_payment_id} already redeemed`);
                    return res.json({ success: true, payment_id: razorpay_payment_id, order_id: razorpay_order_id, plan: effectivePlanId, replay: true });
                }
            } catch (e) { console.error(`[${SERVER_VERSION}] replay-check failed (continuing):`, e.message); }
        }

        // Grant outcome is echoed in the response (debug) so the client can show
        // exactly what happened if entitlement doesn't appear to save.
        const grantInfo = { user: grantUserId || null, coach: coach || 'none', rows: null, error: null };
        if (grantUserId && db) {
            try {
                const expiresAt = effectivePlanId.includes('yearly')
                    ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
                    : new Date(Date.now() + 30  * 24 * 60 * 60 * 1000);

                let rc = 0;
                const v14 = plan.grant;   // v14 ladder grants take priority
                // marker-first idempotency: every v14 grant writes one ledger row
                // keyed by payment id (delta 0 for non-credit grants). If the row
                // already exists, this is a retry of an ALREADY-applied grant —
                // skip the side effect instead of doubling it.
                let v14Fresh = true;
                if (v14) {
                    const mk = await db.query(
                        `INSERT INTO rn_credit_ledger(user_id, delta, reason, ref_id, expires_at)
                         VALUES($1, $2, $3, $4, $5)
                         ON CONFLICT (ref_id) WHERE reason LIKE 'purchase:%' DO NOTHING`,
                        [grantUserId,
                         v14 === 'boost' ? 10 : 0,
                         'purchase:' + v14,
                         razorpay_payment_id,
                         v14 === 'boost' ? new Date(Date.now() + 182 * 24 * 60 * 60 * 1000) : null]);
                    v14Fresh = mk.rowCount > 0;
                    if (!v14Fresh) console.warn(`[${SERVER_VERSION}] v14 grant retry detected for ${razorpay_payment_id} — side effects skipped`);
                }
                if (v14 === 'boost') {
                    if (v14Fresh) {
                        await db.query(`UPDATE rn_users SET credit_balance = credit_balance + 10, updated_at=NOW() WHERE id=$1`, [grantUserId]);
                    }
                    rc = 1;
                    console.log(`[${SERVER_VERSION}] Boost Pack granted: +10 credits (fresh=${v14Fresh})`);
                } else if (v14 === 'single') {
                    if (v14Fresh) {
                        const r = await db.query(`UPDATE rn_users SET interview_credits = interview_credits + 1, updated_at=NOW() WHERE id=$1`, [grantUserId]);
                        rc = r.rowCount;
                    } else rc = 1;
                    // buying ANY interview product unlocks a previously locked free report
                    await db.query(`UPDATE rn_interview_sessions SET report_unlocked=TRUE WHERE user_id=$1 AND is_free_session=TRUE`, [grantUserId]).catch(() => {});
                    console.log(`[${SERVER_VERSION}] Single Interview granted (fresh=${v14Fresh})`);
                } else if (v14 === 'season' || v14 === 'placement') {
                    const passExp = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
                    const interviews = v14 === 'season' ? 6 : 25;
                    const passType = v14 === 'season' ? 'season' : 'placement_pro';
                    if (v14Fresh) {
                        const r = await db.query(
                            `UPDATE rn_users SET pass_type=$2, pass_expires_at=$3,
                                    pass_interviews_remaining =
                                        (CASE WHEN pass_expires_at IS NOT NULL AND pass_expires_at > NOW()
                                              THEN GREATEST(pass_interviews_remaining, 0) ELSE 0 END) + $4,
                                    updated_at=NOW() WHERE id=$1`,
                            [grantUserId, passType, passExp, interviews]);
                        rc = r.rowCount;
                    } else rc = 1;
                    // a pass unlocks the locked free report too
                    await db.query(`UPDATE rn_interview_sessions SET report_unlocked=TRUE WHERE user_id=$1 AND is_free_session=TRUE`, [grantUserId]).catch(() => {});
                    console.log(`[${SERVER_VERSION}] ${passType} granted until ${passExp.toISOString().slice(0,10)} (+${interviews} interviews, fresh=${v14Fresh})`);
                } else if (v14 === 'report_unlock') {
                    let sessionId = '';
                    try { const ord = await razorpay.orders.fetch(razorpay_order_id); sessionId = (ord.notes && ord.notes.sessionId) || ''; } catch (e) {}
                    if (sessionId && UUID_RE.test(sessionId)) {
                        const r = await db.query(`UPDATE rn_interview_sessions SET report_unlocked=TRUE, updated_at=NOW() WHERE id=$1 AND user_id=$2`, [sessionId, grantUserId]);
                        rc = r.rowCount;
                        console.log(`[${SERVER_VERSION}] Report unlocked for session ${sessionId} (rows=${rc})`);
                    } else {
                        console.error(`[${SERVER_VERSION}] report_unlock without valid sessionId in order notes`);
                    }
                } else if (coach === 'unlimited') {
                    const r = await db.query(`UPDATE rn_users SET coach_plan='unlimited', coach_expires=$2, updated_at=NOW() WHERE id=$1`, [grantUserId, expiresAt]);
                    rc = r.rowCount;
                    console.log(`[${SERVER_VERSION}] Coach Unlimited granted (rows=${rc}) until ${expiresAt}`);
                } else if (coach === 'pass') {
                    const r = await db.query(`UPDATE rn_users SET session_passes = COALESCE(session_passes,0) + 1, updated_at=NOW() WHERE id=$1`, [grantUserId]);
                    rc = r.rowCount;
                    console.log(`[${SERVER_VERSION}] Session Pass granted (rows=${rc})`);
                } else {
                    const r = await db.query(`UPDATE rn_users SET plan = 'pro', updated_at = NOW() WHERE id = $1`, [grantUserId]);
                    rc = r.rowCount;
                    console.log(`[${SERVER_VERSION}] Pro granted (rows=${rc})`);
                }
                grantInfo.rows = rc;
                if (rc === 0) console.error(`[${SERVER_VERSION}] GRANT MATCHED 0 ROWS — user id not found: ${grantUserId}`);
            } catch (dbErr) {
                grantInfo.error = dbErr.message;
                console.error(`[${SERVER_VERSION}] DB grant failed:`, dbErr.message);
            }
        } else {
            grantInfo.error = 'no-grant-user-or-db';
            console.error(`[${SERVER_VERSION}] NO grantUserId — entitlement NOT saved (body userId=${userId})`);
        }

        // If the grant didn't land, release the redemption so a retry of
        // verify-payment can grant — otherwise the payment is stranded forever.
        if (redeemed && db && (grantInfo.error || grantInfo.rows === 0)) {
            await db.query('DELETE FROM rn_payments WHERE payment_id=$1', [razorpay_payment_id]).catch(() => {});
            console.warn(`[${SERVER_VERSION}] redemption released for ${razorpay_payment_id} (grant did not land)`);
        }

        res.json({
            success:    true,
            payment_id: razorpay_payment_id,
            order_id:   razorpay_order_id,
            plan:       effectivePlanId,
            grant:      grantInfo
        });

    } catch (err) {
        console.error(`[${SERVER_VERSION}] verify-payment error:`, err.message);
        res.status(500).json({ error: 'Payment verification failed' });
    }
});


// ============================================================================
// INTERVIEW COACH — sessions, AI interview engine, scoring
// ============================================================================
// All Coach endpoints require a signed-in user (requireAuth) + the shared API
// secret. Starting a session also requires Coach entitlement (Unlimited sub or
// a Session Pass) — consumed on start. Sessions are owned per-user.

const COACH_TYPES = ['Behavioral', 'Technical', 'Mixed', 'System design', 'Case'];

// ── Credits + passes (v14 monetization) ─────────────────────────────────────
// One grant/debit = one ledger row + the cached balance updated in the same
// statement. Debits happen in requireCredits (Phase 2); grants here.
async function creditGrant(userId, delta, reason, refId = null, expiresAt = null) {
    await db.query(
        `WITH ins AS (
            INSERT INTO rn_credit_ledger(user_id, delta, reason, ref_id, expires_at)
            VALUES($1,$2,$3,$4,$5)
        )
        UPDATE rn_users SET credit_balance = GREATEST(0, credit_balance + $2), updated_at = NOW()
        WHERE id = $1`,
        [userId, delta, reason, refId, expiresAt]
    );
}

// Lazy expiry for boost-pack grants: debits made AFTER a grant are assumed to
// consume that grant first (user-favourable, fully auditable via the ledger);
// whatever remains of an expired grant is forfeited with a compensating entry.
async function expireStaleCredits(userId) {
    try {
        const g = await db.query(
            `SELECT id, delta, created_at FROM rn_credit_ledger
             WHERE user_id=$1 AND delta > 0 AND expires_at IS NOT NULL
               AND expires_at < NOW() AND expired_handled = FALSE`, [userId]);
        for (const grant of g.rows) {
            const used = await db.query(
                `SELECT COALESCE(SUM(-delta), 0)::int AS used FROM rn_credit_ledger
                 WHERE user_id=$1 AND delta < 0 AND created_at > $2`, [userId, grant.created_at]);
            const forfeit = Math.max(0, grant.delta - used.rows[0].used);
            const claim = await db.query(
                'UPDATE rn_credit_ledger SET expired_handled = TRUE WHERE id=$1 AND expired_handled = FALSE', [grant.id]);
            if (!claim.rowCount) continue;   // a concurrent request already handled it
            if (forfeit > 0) {
                await creditGrant(userId, -forfeit, 'expiry', grant.id);
                console.log(`[credits] expired ${forfeit} for user ${userId} (grant ${grant.id})`);
            }
        }
    } catch (e) { console.error('[credits] expiry sweep failed:', e.message); }
}

// Active pass = unlimited AI actions (credit checks bypassed entirely).
function hasActivePass(u) {
    return !!(u && u.pass_type && u.pass_expires_at && new Date(u.pass_expires_at) > new Date());
}

// +2 credits on account creation — exactly once (flag-guarded, so safe even
// if an auth flow retries). Pulled forward from Phase 5 so the credit economy
// works from day one.
async function grantSignupCredits(userId) {
    try {
        const r = await db.query(
            `UPDATE rn_users SET signup_credits_granted = TRUE
             WHERE id=$1 AND signup_credits_granted = FALSE`, [userId]);
        if (r.rowCount) await creditGrant(userId, 2, 'signup');
    } catch (e) { console.error('[credits] signup grant failed:', e.message); }
}

function makeReferralCode() {
    return crypto.randomBytes(5).toString('base64url').replace(/[^a-zA-Z0-9]/g, 'x').slice(0, 8).toUpperCase();
}

// Free first interview ships a PARTIAL report until unlocked (₹299 or a pass):
// overall + verdict + ONE strength + ONE weakness. Enforced server-side —
// the full report stays stored; only the response is trimmed.
function partialReport(r) {
    if (!r) return r;
    return {
        overall: r.overall, verdict: r.verdict, percentile: r.percentile,
        strengths: (r.strengths || []).slice(0, 1),
        weaknesses: (r.weaknesses || []).slice(0, 1),
        dimensions: [], fixes: [], recommendations: [],
        locked: true,
    };
}
function reportIsLocked(row) {
    return !!(row && row.is_free_session && !row.report_unlocked);
}

function coachAccess(u) {
    const unlimited = u && u.coach_plan === 'unlimited' &&
        (!u.coach_expires || new Date(u.coach_expires) > new Date());
    const passes = (u && u.session_passes) || 0;
    return { unlimited, passes, has: unlimited || passes > 0 };
}

// Generate interview questions tailored to the résumé + JD + config.
async function coachGenerateQuestions({ resumeString, company, jobTitle, jobDescription, interviewType, difficulty, count, avoid = [] }) {
    // Per-session variation: same résumé + JD must still produce a fresh set.
    const LENSES = [
        'delivery under deadline pressure', 'stakeholder conflict and influence',
        'technical depth and trade-offs', 'failure, debugging and lessons learned',
        'scale, performance and reliability', 'ownership and cross-team leadership',
        'ambiguity and prioritisation', 'metrics and business impact'
    ];
    const lenses = LENSES.slice().sort(() => Math.random() - 0.5).slice(0, 3);
    const seed = Math.random().toString(36).slice(2, 8);
    const sys = `You are an elite interviewer running a realistic ${interviewType} interview for the role below.
Generate exactly ${count} questions, ordered from warm-up to hardest.
Difficulty ${difficulty}/100 (higher = sharper, more probing, more quantitative).

BALANCE REQUIREMENT — this is what makes the interview feel real:
- At least HALF the questions must directly probe specific requirements, responsibilities, technologies, or qualifications stated in the JOB DESCRIPTION (name them explicitly in the question, the way the hiring manager who wrote the JD would).
- The remaining questions connect the candidate's actual résumé experience to THIS role — gaps between their background and the JD's demands are prime material.
- If the job description names concrete skills/tools/duties, they MUST appear across the question set. Never produce a question that could have been written without reading the JD.
EVERY SESSION MUST FEEL FRESH: given the same résumé and job description, a re-run must produce a substantially different set — vary the requirements you probe, the angle of attack, and the scenarios. Never default to the most obvious first-pass questions if alternatives exist.
Return ONLY JSON: {"questions":[{"text":"...","focus":"2-4 word tag","hint":"the single key phrase in the question to emphasise"}]}`;
    const avoidBlock = avoid.length
        ? `\n\n=== DO NOT REPEAT ===\nThe candidate has interviewed for this role before. Do NOT reuse or closely paraphrase any of these previously asked questions:\n${avoid.slice(0, 18).map(q => '- ' + q).join('\n')}`
        : '';
    const user = `=== ROLE ===\n${sanitizeInput(jobTitle)} at ${sanitizeInput(company)}\n\n=== JOB DESCRIPTION ===\n${truncateText(jobDescription, 4000)}\n\n=== CANDIDATE RÉSUMÉ ===\n${truncateText(resumeString, 6000)}\n\n=== SESSION VARIATION (seed ${seed}) ===\nLean this session's questions toward: ${lenses.join('; ')}.${avoidBlock}\n\nReturn ${count} questions as JSON.`;
    const c = await openai.chat.completions.create({
        model: 'gpt-4.1-mini', temperature: 0.85, max_tokens: 1200,
        response_format: { type: 'json_object' },
        messages: [{ role: 'system', content: sys }, { role: 'user', content: user }],
    });
    const parsed = JSON.parse(c.choices[0].message.content);
    const qs = Array.isArray(parsed.questions) ? parsed.questions.slice(0, count) : [];
    return qs.map((q, i) => ({ id: 'q' + (i + 1), text: String(q.text || '').slice(0, 400), focus: q.focus || '', hint: q.hint || '' }));
}

// Score the completed interview → the structured report the UI renders.
async function coachScore({ resumeString, jobTitle, company, jobDescription, qa }) {
    const sys = `You are a brutally specific interview coach. Score this completed ${qa.length}-question interview.
Be concrete and tied to what the candidate ACTUALLY said. No vague praise.
Return ONLY JSON with this exact shape:
{
 "overall": <int 0-100>,
 "verdict": {"headline":"<6-8 words>","summary":"<2-3 sentence verdict>"},
 "percentile": "<e.g. Top 25%>",
 "dimensions": [
   {"key":"Communication","score":<0-100>,"note":"<<=12 words>"},
   {"key":"Confidence","score":<0-100>,"note":"<<=12 words>"},
   {"key":"Structure","score":<0-100>,"note":"<<=12 words>"},
   {"key":"Technical relevance","score":<0-100>,"note":"<<=12 words>"}
 ],
 "strengths": [{"title":"<short>","detail":"<1 sentence tied to an answer>"}],
 "weaknesses": [{"title":"<short>","detail":"<1 sentence, actionable>"}],
 "fixes": [{"questionId":"qN","tag":"<Qn · topic>","score":<0-100>,"quote":"<paraphrase of what they said>","rewrite":"<stronger version; wrap the key upgrade in {curly braces}>"}],
 "recommendations": ["<imperative next step>"]
}
Give 3 strengths, 3 weaknesses, the 2 weakest answers as fixes, and 3 recommendations.`;
    const transcript = qa.map((x, i) => `Q${i + 1} (${x.focus || 'general'}): ${x.text}\nANSWER: ${x.answer || '(skipped)'}`).join('\n\n');
    const user = `=== ROLE ===\n${sanitizeInput(jobTitle)} at ${sanitizeInput(company)}\n\n=== RÉSUMÉ ===\n${truncateText(resumeString, 4000)}\n\n=== TRANSCRIPT ===\n${truncateText(transcript, 8000)}\n\nScore it. Return JSON only.`;
    const c = await openai.chat.completions.create({
        model: 'gpt-4.1-mini', temperature: 0.3, max_tokens: 1800,
        response_format: { type: 'json_object' },
        messages: [{ role: 'system', content: sys }, { role: 'user', content: user }],
    });
    const r = JSON.parse(c.choices[0].message.content);
    r.overall = Math.max(0, Math.min(100, Math.round(r.overall || 0)));
    (r.dimensions || []).forEach(d => { d.score = Math.max(0, Math.min(100, Math.round(d.score || 0))); });
    return r;
}

// All /coach endpoints share the API secret + require a signed-in user.
// Only create + score hit OpenAI — aiLimiter goes on those two routes alone.
// A blanket limiter here would 429 paying users mid-interview (10+ answer
// saves per session are plain DB writes).
app.use('/coach', validateApiSecret);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Coach entitlement status (frontend uses this to gate UI / route to checkout).
app.get('/coach/me', requireAuth, async (req, res) => {
    if (!db) return res.json({ unlimited: false, passes: 0, has: false });
    try {
        const r = await db.query(
            `SELECT coach_plan, coach_expires, session_passes, pass_type, pass_expires_at,
                    pass_interviews_remaining, interview_credits, free_interview_used
             FROM rn_users WHERE id=$1`, [req.user.id]);
        const u = r.rows[0] || {};
        const acc = coachAccess(u);
        const passOk = hasActivePass(u) && (u.pass_interviews_remaining || 0) > 0;
        return res.json({
            unlimited: acc.unlimited,
            passes: acc.passes,
            passType: hasActivePass(u) ? u.pass_type : null,
            passInterviewsRemaining: passOk ? u.pass_interviews_remaining : 0,
            interviewCredits: u.interview_credits || 0,
            freeInterviewAvailable: !u.free_interview_used,
            // has = can start a PAID-grade interview right now (free path is separate)
            has: acc.unlimited || acc.passes > 0 || passOk || (u.interview_credits || 0) > 0,
        });
    } catch (e) { return res.status(500).json({ error: 'Failed to load Coach status.' }); }
});

// Create a session (consumes entitlement) and generate the questions.
app.post('/coach/sessions', requireAuth, aiLimiter, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    try {
        const { resumeData, company, jobTitle, jobDescription, interviewType, difficulty, mode, length } = req.body;
        if (!jobDescription || jobDescription.trim().length < 30) return res.status(400).json({ error: 'Add a job description (min 30 chars).' });
        if (jobDescription.length > 12000) return res.status(400).json({ error: 'Job description is too long — paste the relevant part (under 12,000 characters).' });

        // v14 entitlement ladder (consumed AFTER question generation succeeds, so
        // an AI failure never burns anything; refunded if the insert fails):
        //   legacy Unlimited (no consumption) → active pass interviews →
        //   single-interview credits → legacy session passes → ONE free text interview.
        const ur = await db.query(
            `SELECT plan, coach_plan, coach_expires, session_passes, pass_type, pass_expires_at,
                    pass_interviews_remaining, interview_credits, free_interview_used
             FROM rn_users WHERE id=$1`, [req.user.id]);
        const u = ur.rows[0] || {};
        const wantAudio = mode !== 'text';
        let source = null;
        if (coachAccess(u).unlimited) source = 'legacy_unlimited';
        else if (hasActivePass(u) && (u.pass_interviews_remaining || 0) > 0) source = 'pass';
        else if ((u.interview_credits || 0) > 0) source = 'interview_credit';
        else if ((u.session_passes || 0) > 0) source = 'legacy_pass';
        // a paying pass-holder who used up their interviews gets the top-up
        // upsell — never a silently degraded 'free' session
        else if (!u.free_interview_used && !wantAudio && !hasActivePass(u)) source = 'free';
        if (!source) {
            const passExhausted = hasActivePass(u) && (u.pass_interviews_remaining || 0) <= 0;
            return res.status(402).json({
                error: passExhausted
                    ? "You've used all the interviews in your pass — add a Single Interview (₹499) to keep going."
                    : wantAudio && !u.free_interview_used
                        ? 'Audio interviews need a Single Interview (₹499) or a Season Pass — your first TEXT interview is free.'
                        : "You've used your free interview. Get a Single Interview (₹499), or 6 complete interviews with the Season Pass (₹1,499).",
                code: 'INTERVIEW_REQUIRED',
                freeAvailable: !u.free_interview_used && !hasActivePass(u),
            });
        }
        const isFreeSession = source === 'free';

        const type  = COACH_TYPES.includes(interviewType) ? interviewType : 'Behavioral';
        const count = isFreeSession ? 5 : ([5, 6, 10].includes(length) ? length : 6);
        const diffN = parseInt(difficulty, 10);
        const diff  = Math.max(0, Math.min(100, Number.isFinite(diffN) ? diffN : 60));
        const resumeString = serializeResumeData(resumeData);

        // Previously asked questions for this user+role → the generator must avoid them
        let avoid = [];
        try {
            const prev = await db.query(
                `SELECT questions FROM rn_interview_sessions
                 WHERE user_id=$1 AND (job_title=$2 OR company=$3)
                 ORDER BY created_at DESC LIMIT 3`,
                [req.user.id, String(jobTitle || '').slice(0, 255), String(company || '').slice(0, 255)]
            );
            avoid = prev.rows.flatMap(r => (Array.isArray(r.questions) ? r.questions : []).map(q => String(q.text || '').slice(0, 200))).filter(Boolean);
        } catch (e) { /* variety aid only — never block creation */ }

        let questions = [];
        try {
            questions = await coachGenerateQuestions({ resumeString, company, jobTitle, jobDescription, interviewType: type, difficulty: diff, count, avoid });
        } catch (aiErr) {
            console.error('[coach] question gen failed:', aiErr.message);
            return res.status(502).json({ error: 'Could not generate questions. Please try again.' });
        }
        if (!questions.length) return res.status(502).json({ error: 'Could not generate questions. Please try again.' });

        // consume the entitlement (atomic; race-lost → honest 402)
        const CONSUME = {
            pass:             "UPDATE rn_users SET pass_interviews_remaining = pass_interviews_remaining - 1, updated_at=NOW() WHERE id=$1 AND pass_interviews_remaining > 0",
            interview_credit: "UPDATE rn_users SET interview_credits = interview_credits - 1, updated_at=NOW() WHERE id=$1 AND interview_credits > 0",
            legacy_pass:      "UPDATE rn_users SET session_passes = session_passes - 1, updated_at=NOW() WHERE id=$1 AND session_passes > 0",
            free:             "UPDATE rn_users SET free_interview_used = TRUE, updated_at=NOW() WHERE id=$1 AND free_interview_used = FALSE",
        };
        if (CONSUME[source]) {
            const dec = await db.query(CONSUME[source], [req.user.id]);
            if (!dec.rowCount) return res.status(402).json({ error: 'That entitlement was just used up — refresh and try again.', code: 'INTERVIEW_REQUIRED' });
        }

        let ins;
        try {
            ins = await db.query(
                `INSERT INTO rn_interview_sessions(user_id,company,job_title,job_description,interview_type,difficulty,mode,resume_snapshot,questions,status,is_free_session,report_unlocked)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'in_progress',$10,$11) RETURNING id, questions`,
                [req.user.id, String(company || '').slice(0, 255), String(jobTitle || '').slice(0, 255), jobDescription, type, diff, mode === 'text' ? 'text' : 'voice', resumeData || null, JSON.stringify(questions),
                 isFreeSession, !isFreeSession]
            );
        } catch (insErr) {
            // refund whatever we just consumed — the user got nothing
            const REFUND = {
                pass:             "UPDATE rn_users SET pass_interviews_remaining = pass_interviews_remaining + 1 WHERE id=$1",
                interview_credit: "UPDATE rn_users SET interview_credits = interview_credits + 1 WHERE id=$1",
                legacy_pass:      "UPDATE rn_users SET session_passes = session_passes + 1 WHERE id=$1",
                free:             "UPDATE rn_users SET free_interview_used = FALSE WHERE id=$1",
            };
            if (REFUND[source]) await db.query(REFUND[source], [req.user.id]).catch(() => {});
            throw insErr;
        }
        console.log(`[${SERVER_VERSION}] [coach] session ${ins.rows[0].id} created (${type}, ${count}Q, ${mode})`);
        res.json({ id: ins.rows[0].id, questions });
    } catch (e) {
        console.error('[coach] create error:', e.message);
        res.status(500).json({ error: 'Failed to start interview.' });
    }
});

// List the user's sessions (history).
app.get('/coach/sessions', requireAuth, async (req, res) => {
    if (!db) return res.json({ sessions: [] });
    try {
        const r = await db.query(
            `SELECT id, company, job_title, interview_type, mode, overall_score, status, created_at
             FROM rn_interview_sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.user.id]);
        res.json({ sessions: r.rows });
    } catch (e) { res.status(500).json({ error: 'Failed to load history.' }); }
});

// Fetch a single owned session.
app.get('/coach/sessions/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Session not found.' });
    try {
        const r = await db.query('SELECT * FROM rn_interview_sessions WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Session not found.' });
        const row = r.rows[0];
        if (reportIsLocked(row) && row.report) {
            return res.json({ ...row, report: partialReport(row.report), report_locked: true });
        }
        res.json(row);
    } catch (e) { res.status(500).json({ error: 'Failed to load session.' }); }
});

// Submit an answer. Atomic jsonb append — no read-modify-write race; only
// in-progress sessions accept answers, capped so the row can't grow unbounded.
app.post('/coach/sessions/:id/answers', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Session not found.' });
    try {
        const { questionId, text } = req.body;
        if (!/^q\d{1,2}$/.test(String(questionId || ''))) return res.status(400).json({ error: 'Invalid question id.' });
        const entry = JSON.stringify([{ questionId: String(questionId), text: truncateText(text, 6000), at: new Date().toISOString() }]);
        const r = await db.query(
            `UPDATE rn_interview_sessions
             SET answers = COALESCE(answers,'[]'::jsonb) || $1::jsonb, updated_at = NOW()
             WHERE id=$2 AND user_id=$3 AND status='in_progress'
               AND jsonb_array_length(COALESCE(answers,'[]'::jsonb)) < 60
             RETURNING jsonb_array_length(answers) AS n`,
            [entry, req.params.id, req.user.id]
        );
        if (!r.rowCount) return res.status(409).json({ error: 'Could not save — this interview may already be scored.' });
        res.json({ ok: true, answered: r.rows[0].n });
    } catch (e) { res.status(500).json({ error: 'Failed to save answer.' }); }
});

// Generate the scored report.
app.post('/coach/sessions/:id/score', requireAuth, aiLimiter, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Session not found.' });
    try {
        const r = await db.query('SELECT * FROM rn_interview_sessions WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Session not found.' });
        const s = r.rows[0];
        if (s.report) return res.json({ report: reportIsLocked(s) ? partialReport(s.report) : s.report, overall: s.overall_score, locked: reportIsLocked(s) }); // idempotent

        const questions = Array.isArray(s.questions) ? s.questions : [];
        const answers   = Array.isArray(s.answers) ? s.answers : [];
        // Latest answer wins per question; legacy voice placeholders don't count.
        const lastByQ = {};
        for (const a of answers) if (a && a.questionId) lastByQ[a.questionId] = a;
        const isRealAnswer = t => t && String(t).trim() && !String(t).startsWith('[Spoken answer');
        const qa = questions.map(q => ({
            focus: q.focus, text: q.text,
            answer: (lastByQ[q.id] && isRealAnswer(lastByQ[q.id].text)) ? lastByQ[q.id].text : ''
        }));
        if (!qa.some(x => x.answer)) {
            return res.status(400).json({ error: 'No answers were recorded for this interview. Resume it and answer at least one question, then generate the report.' });
        }
        const resumeString = serializeResumeData(s.resume_snapshot);
        let report;
        try {
            report = await coachScore({ resumeString, jobTitle: s.job_title, company: s.company, jobDescription: s.job_description, qa });
        } catch (aiErr) {
            console.error('[coach] scoring failed:', aiErr.message);
            return res.status(502).json({ error: 'Could not score the interview. Please try again.' });
        }
        // First scorer wins — a concurrent score call returns the stored report.
        const upd = await db.query(
            `UPDATE rn_interview_sessions SET report=$1, overall_score=$2, status='scored', completed_at=NOW(), updated_at=NOW() WHERE id=$3 AND report IS NULL`,
            [JSON.stringify(report), report.overall, s.id]
        );
        if (!upd.rowCount) {
            const re = await db.query('SELECT report, overall_score FROM rn_interview_sessions WHERE id=$1', [s.id]);
            return res.json({ report: reportIsLocked(s) ? partialReport(re.rows[0].report) : re.rows[0].report, overall: re.rows[0].overall_score, locked: reportIsLocked(s) });
        }
        console.log(`[${SERVER_VERSION}] [coach] session ${s.id} scored → ${report.overall}`);
        res.json({ report: reportIsLocked(s) ? partialReport(report) : report, overall: report.overall, locked: reportIsLocked(s) });
    } catch (e) {
        console.error('[coach] score error:', e.message);
        res.status(500).json({ error: 'Failed to generate report.' });
    }
});

// ── Coach audio — the interviewer's voice + spoken-answer transcription ─────
// The frontend falls back to browser speechSynthesis / SpeechRecognition if
// either endpoint fails, so neither is a single point of failure.

// Speak a question aloud (AI interviewer voice). Returns MP3.
app.post('/coach/sessions/:id/question-audio', requireAuth, coachMediaLimiter, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Session not found.' });
    try {
        const { questionId } = req.body || {};
        const r = await db.query('SELECT questions FROM rn_interview_sessions WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Session not found.' });
        const questions = Array.isArray(r.rows[0].questions) ? r.rows[0].questions : [];
        const q = questions.find(x => x.id === String(questionId || ''));
        if (!q) return res.status(404).json({ error: 'Question not found.' });

        const text = String(q.text).slice(0, 600);
        let speech;
        try {
            speech = await openai.audio.speech.create({
                model: 'gpt-4o-mini-tts', voice: 'onyx', input: text, response_format: 'mp3',
                instructions: 'You are a calm, professional job interviewer. Speak clearly at a natural, unhurried pace.',
            });
        } catch (e) {
            speech = await openai.audio.speech.create({ model: 'tts-1', voice: 'onyx', input: text, response_format: 'mp3' });
        }
        const buf = Buffer.from(await speech.arrayBuffer());
        res.set({ 'Content-Type': 'audio/mpeg', 'Content-Length': buf.length, 'Cache-Control': 'private, max-age=3600' });
        res.send(buf);
    } catch (e) {
        console.error('[coach] tts error:', e.message);
        res.status(502).json({ error: 'Could not generate question audio.' });
    }
});

// Transcribe a spoken answer (raw audio body, ≤16MB). Returns { text }.
app.post('/coach/sessions/:id/transcribe', requireAuth, coachMediaLimiter,
    express.raw({ type: ['audio/*', 'video/webm', 'application/octet-stream'], limit: '16mb' }),
    async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Coach not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Session not found.' });
    try {
        if (!Buffer.isBuffer(req.body) || req.body.length < 200) return res.status(400).json({ error: 'No audio received.' });
        const own = await db.query('SELECT id FROM rn_interview_sessions WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!own.rows.length) return res.status(404).json({ error: 'Session not found.' });

        const ct  = String(req.headers['content-type'] || 'audio/webm').toLowerCase();
        const ext = ct.includes('mp4') || ct.includes('m4a') ? 'mp4'
                  : ct.includes('ogg') ? 'ogg'
                  : ct.includes('mpeg') || ct.includes('mp3') ? 'mp3'
                  : ct.includes('wav') ? 'wav' : 'webm';
        const mime = ct.split(';')[0];

        let tr;
        try {
            const file = await OpenAI.toFile(req.body, `answer.${ext}`, { type: mime });
            tr = await openai.audio.transcriptions.create({ file, model: 'gpt-4o-mini-transcribe' });
        } catch (e) {
            const file2 = await OpenAI.toFile(req.body, `answer.${ext}`, { type: mime });
            tr = await openai.audio.transcriptions.create({ file: file2, model: 'whisper-1' });
        }
        const text = String((tr && tr.text) || '').trim().slice(0, 6000);
        console.log(`[${SERVER_VERSION}] [coach] transcribed ${Math.round(req.body.length / 1024)}KB → ${text.length} chars`);
        res.json({ text });
    } catch (e) {
        console.error('[coach] transcribe error:', e.message);
        res.status(502).json({ error: 'Could not transcribe your answer.' });
    }
});


// ============================================================================
// APPLICATION TRACKER — job-search CRM (jobs + uniform event timeline)
// ============================================================================
// Same gates as /coach: shared API secret + signed-in user. No AI calls.
const trackerWriteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,                    // generous for humans, blocks scripted bloat
    message: { error: 'Too many changes at once — slow down a little.' }
});
app.use('/tracker', validateApiSecret);
app.use('/tracker', (req, res, next) => req.method === 'GET' ? next() : trackerWriteLimiter(req, res, next));

const JOB_STAGES  = ['saved', 'applied', 'interviewing', 'offer', 'rejected'];
const EVENT_TYPES = ['note', 'stage', 'round', 'contact', 'salary', 'followup', 'task', 'offer', 'rejection'];

const jobStr = (v, max) => (v === undefined || v === null) ? null : String(v).slice(0, max);
const jobInt = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.max(-2147483648, Math.min(2147483647, n)) : null; };
const jobDate = (v) => { if (!v) return null; const d = new Date(v); return isNaN(d) ? null : d; };

// List jobs (board). q searches company/title; archived hidden by default.
app.get('/tracker/jobs', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    try {
        const params = [req.user.id];
        let where = 'user_id=$1';
        if (req.query.archived === 'true') { where += ' AND archived=TRUE'; }
        else { where += ' AND archived=FALSE'; }
        if (req.query.stage && JOB_STAGES.includes(req.query.stage)) { params.push(req.query.stage); where += ` AND stage=$${params.length}`; }
        if (req.query.q) { params.push('%' + String(req.query.q).slice(0, 100) + '%'); where += ` AND (company ILIKE $${params.length} OR title ILIKE $${params.length})`; }
        const r = await db.query(
            `SELECT id, company, title, location, url, source, stage, excitement,
                    salary_min, salary_max, salary_currency,
                    next_action, next_action_due, applied_at, created_at, updated_at
             FROM rn_jobs WHERE ${where} ORDER BY updated_at DESC LIMIT 500`, params);
        res.json({ jobs: r.rows });
    } catch (e) { console.error('[tracker] list error:', e.message); res.status(500).json({ error: 'Failed to load jobs.' }); }
});

// Create a job. Logs the initial stage event.
app.post('/tracker/jobs', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    try {
        const b = req.body || {};
        const company = jobStr(b.company, 255), title = jobStr(b.title, 255);
        if (!company || !company.trim() || !title || !title.trim()) {
            return res.status(400).json({ error: 'Company and job title are required.' });
        }
        const stage = JOB_STAGES.includes(b.stage) ? b.stage : 'saved';
        const exc = Math.max(1, Math.min(5, jobInt(b.excitement) || 3));
        const r = await db.query(
            `INSERT INTO rn_jobs(user_id, company, title, location, url, source, jd,
                                 salary_min, salary_max, salary_currency, salary_notes,
                                 stage, excitement, next_action, next_action_due, applied_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
            [req.user.id, company.trim(), title.trim(), jobStr(b.location, 255), jobStr(b.url, 2000),
             jobStr(b.source, 100), jobStr(b.jd, 12000), jobInt(b.salaryMin), jobInt(b.salaryMax),
             jobStr(b.salaryCurrency, 8) || 'INR', jobStr(b.salaryNotes, 2000),
             stage, exc, jobStr(b.nextAction, 255), jobDate(b.nextActionDue),
             ['applied', 'interviewing', 'offer'].includes(stage) ? new Date() : null]);
        const job = r.rows[0];
        await db.query(`INSERT INTO rn_job_events(job_id, user_id, type, title) VALUES($1,$2,'stage',$3)`,
            [job.id, req.user.id, `Added to pipeline as "${stage}"`]).catch(() => {});
        console.log(`[${SERVER_VERSION}] [tracker] job created ${job.id} (${stage})`);
        res.json(job);
    } catch (e) { console.error('[tracker] create error:', e.message); res.status(500).json({ error: 'Failed to save the job.' }); }
});

// Job + its timeline.
app.get('/tracker/jobs/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Job not found.' });
    try {
        const r = await db.query('SELECT * FROM rn_jobs WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rows.length) return res.status(404).json({ error: 'Job not found.' });
        const ev = await db.query(
            'SELECT * FROM rn_job_events WHERE job_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 200',
            [req.params.id, req.user.id]);
        res.json({ job: r.rows[0], events: ev.rows });
    } catch (e) { console.error('[tracker] get error:', e.message); res.status(500).json({ error: 'Failed to load the job.' }); }
});

// Update job fields; stage moves are logged and stamp applied_at.
app.patch('/tracker/jobs/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Job not found.' });
    try {
        const cur = await db.query('SELECT * FROM rn_jobs WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!cur.rows.length) return res.status(404).json({ error: 'Job not found.' });
        const j = cur.rows[0];
        const b = req.body || {};
        const stageProvided = b.stage !== undefined && JOB_STAGES.includes(b.stage) && b.stage !== j.stage;
        const stage = stageProvided ? b.stage : j.stage;
        const pick = (key, val, max) => b[key] !== undefined ? jobStr(val, max) : undefined;
        const nonEmpty = (v) => { const t = v === undefined ? undefined : jobStr(v, 255); return (t && t.trim()) ? t.trim() : undefined; };
        const fields = {
            company: nonEmpty(b.company), title: nonEmpty(b.title),
            location: pick('location', b.location, 255), url: pick('url', b.url, 2000),
            source: pick('source', b.source, 100), jd: pick('jd', b.jd, 12000),
            salary_min: b.salaryMin !== undefined ? jobInt(b.salaryMin) : undefined,
            salary_max: b.salaryMax !== undefined ? jobInt(b.salaryMax) : undefined,
            salary_currency: pick('salaryCurrency', b.salaryCurrency, 8),
            salary_notes: pick('salaryNotes', b.salaryNotes, 2000),
            excitement: b.excitement !== undefined ? Math.max(1, Math.min(5, jobInt(b.excitement) || 3)) : undefined,
            next_action: pick('nextAction', b.nextAction, 255),
            next_action_due: b.nextActionDue !== undefined ? jobDate(b.nextActionDue) : undefined,
            archived: b.archived !== undefined ? !!b.archived : undefined,
            stage: stageProvided ? stage : undefined,
        };
        const sets = [], vals = [];
        for (const [k, v] of Object.entries(fields)) {
            if (v === undefined) continue;
            vals.push(v); sets.push(`${k}=$${vals.length}`);
        }
        if (stageProvided && ['applied', 'interviewing', 'offer'].includes(stage) && !j.applied_at) { vals.push(new Date()); sets.push(`applied_at=$${vals.length}`); }
        sets.push('updated_at=NOW()');
        vals.push(req.params.id, req.user.id);
        const r = await db.query(
            `UPDATE rn_jobs SET ${sets.join(', ')} WHERE id=$${vals.length - 1} AND user_id=$${vals.length} RETURNING *`, vals);
        if (stageProvided) {
            await db.query(`INSERT INTO rn_job_events(job_id, user_id, type, title) VALUES($1,$2,'stage',$3)`,
                [req.params.id, req.user.id, `Moved to "${stage}"`]).catch(() => {});
        }
        res.json(r.rows[0]);
    } catch (e) { console.error('[tracker] patch error:', e.message); res.status(500).json({ error: 'Failed to update the job.' }); }
});

// Archive (soft delete).
app.delete('/tracker/jobs/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Job not found.' });
    try {
        const r = await db.query('UPDATE rn_jobs SET archived=TRUE, updated_at=NOW() WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rowCount) return res.status(404).json({ error: 'Job not found.' });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed to archive the job.' }); }
});

// Add a timeline event (note / round / contact / salary / followup / ...).
app.post('/tracker/jobs/:id/events', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Job not found.' });
    try {
        const own = await db.query('SELECT id FROM rn_jobs WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!own.rows.length) return res.status(404).json({ error: 'Job not found.' });
        const b = req.body || {};
        const type = EVENT_TYPES.includes(b.type) ? b.type : 'note';
        const title = jobStr(b.title, 255), body = jobStr(b.body, 6000);
        if ((!title || !title.trim()) && (!body || !body.trim())) {
            return res.status(400).json({ error: 'Write something first.' });
        }
        const r = await db.query(
            `INSERT INTO rn_job_events(job_id, user_id, type, title, body, due_at, meta)
             VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [req.params.id, req.user.id, type, title, body, jobDate(b.dueAt),
             (() => { if (!b.meta || typeof b.meta !== 'object') return null; const m = JSON.stringify(b.meta); return m.length <= 4000 ? m : null; })()]);
        await db.query('UPDATE rn_jobs SET updated_at=NOW() WHERE id=$1', [req.params.id]).catch(() => {});
        res.json(r.rows[0]);
    } catch (e) { console.error('[tracker] event error:', e.message); res.status(500).json({ error: 'Failed to save.' }); }
});

// Edit / complete an event.
app.patch('/tracker/events/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Not found.' });
    try {
        const b = req.body || {};
        const sets = [], vals = [];
        if (b.done !== undefined) { vals.push(!!b.done); sets.push(`done=$${vals.length}`); }
        if (b.title !== undefined) { vals.push(jobStr(b.title, 255)); sets.push(`title=$${vals.length}`); }
        if (b.body !== undefined) { vals.push(jobStr(b.body, 6000)); sets.push(`body=$${vals.length}`); }
        if (b.dueAt !== undefined) { vals.push(jobDate(b.dueAt)); sets.push(`due_at=$${vals.length}`); }
        if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
        vals.push(req.params.id, req.user.id);
        const r = await db.query(
            `UPDATE rn_job_events SET ${sets.join(', ')} WHERE id=$${vals.length - 1} AND user_id=$${vals.length} RETURNING *`, vals);
        if (!r.rows.length) return res.status(404).json({ error: 'Not found.' });
        await db.query('UPDATE rn_jobs SET updated_at=NOW() WHERE id=$1 AND user_id=$2', [r.rows[0].job_id, req.user.id]).catch(() => {});
        res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: 'Failed to update.' }); }
});

app.delete('/tracker/events/:id', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Not found.' });
    try {
        const r = await db.query('DELETE FROM rn_job_events WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (!r.rowCount) return res.status(404).json({ error: 'Not found.' });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed to delete.' }); }
});

// The daily loop: overdue / today / upcoming dated items + computed
// follow-up suggestions (applied jobs silent for 7+ days, nothing pending).
app.get('/tracker/agenda', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    try {
        const due = await db.query(
            `SELECT e.id, e.job_id, e.type, e.title, e.due_at, j.company, j.title AS job_title
             FROM rn_job_events e JOIN rn_jobs j ON j.id = e.job_id
             WHERE e.user_id=$1 AND e.done=FALSE AND e.due_at IS NOT NULL
               AND e.due_at < NOW() + (CASE WHEN e.type='round' THEN INTERVAL '30 days' ELSE INTERVAL '7 days' END)
               AND j.archived=FALSE
             ORDER BY e.due_at ASC LIMIT 50`, [req.user.id]);
        const nextActions = await db.query(
            `SELECT id AS job_id, company, title AS job_title, next_action AS title, next_action_due AS due_at
             FROM rn_jobs
             WHERE user_id=$1 AND archived=FALSE AND next_action IS NOT NULL AND next_action_due IS NOT NULL
               AND next_action_due < NOW() + INTERVAL '7 days'
             ORDER BY next_action_due ASC LIMIT 50`, [req.user.id]);
        const suggested = await db.query(
            `SELECT j.id AS job_id, j.company, j.title AS job_title, j.stage, j.updated_at
             FROM rn_jobs j
             WHERE j.user_id=$1 AND j.archived=FALSE
               AND ((j.stage='applied'      AND j.updated_at < NOW() - INTERVAL '7 days')
                 OR (j.stage='interviewing' AND j.updated_at < NOW() - INTERVAL '14 days'))
               AND NOT EXISTS (SELECT 1 FROM rn_job_events e WHERE e.job_id=j.id AND e.done=FALSE AND e.type='followup')
             ORDER BY j.updated_at ASC LIMIT 10`, [req.user.id]);
        const items = [
            ...due.rows.map(r => ({ ...r, kind: 'event' })),
            ...nextActions.rows.map(r => ({ ...r, kind: 'next_action', type: 'task' })),
        ];
        const now = Date.now(), endOfToday = new Date(); endOfToday.setHours(23, 59, 59, 999);
        res.json({
            overdue:   items.filter(i => new Date(i.due_at).getTime() < now && new Date(i.due_at).toDateString() !== new Date().toDateString()),
            today:     items.filter(i => new Date(i.due_at).toDateString() === new Date().toDateString()),
            upcoming:  items.filter(i => new Date(i.due_at).getTime() > endOfToday.getTime()),
            suggested: suggested.rows,
        });
    } catch (e) { console.error('[tracker] agenda error:', e.message); res.status(500).json({ error: 'Failed to load your agenda.' }); }
});

// Momentum metrics for the insights strip.
app.get('/tracker/insights', requireAuth, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Tracker not configured.' });
    try {
        const stages = await db.query(
            `SELECT stage, COUNT(*)::int AS n FROM rn_jobs WHERE user_id=$1 AND archived=FALSE GROUP BY stage`, [req.user.id]);
        const week = await db.query(
            `SELECT
               COUNT(*) FILTER (WHERE applied_at >= NOW() - INTERVAL '7 days')::int  AS applied_this_week,
               COUNT(*) FILTER (WHERE applied_at >= NOW() - INTERVAL '14 days'
                                AND applied_at <  NOW() - INTERVAL '7 days')::int    AS applied_last_week,
               COUNT(*) FILTER (WHERE stage IN ('interviewing','offer') AND applied_at IS NOT NULL)::int AS progressed,
               COUNT(*) FILTER (WHERE applied_at IS NOT NULL)::int                    AS applied_total,
               COUNT(*) FILTER (WHERE stage='offer')::int                             AS offers
             FROM rn_jobs WHERE user_id=$1 AND archived=FALSE`, [req.user.id]);
        const w = week.rows[0];
        const byStage = {}; stages.rows.forEach(r => { byStage[r.stage] = r.n; });
        res.json({
            stages: byStage,
            appliedThisWeek: w.applied_this_week,
            appliedLastWeek: w.applied_last_week,
            responseRate: w.applied_total ? Math.round((w.progressed / w.applied_total) * 100) : null,
            offers: w.offers,
            active: (byStage.saved || 0) + (byStage.applied || 0) + (byStage.interviewing || 0) + (byStage.offer || 0),
        });
    } catch (e) { console.error('[tracker] insights error:', e.message); res.status(500).json({ error: 'Failed to load insights.' }); }
});


app.use((err, req, res, next) => {
    console.error(err);
    if (res.headersSent) return;
    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'That upload is too large. Try a smaller file or shorter content.' });
    }
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Malformed request.' });
    }
    res.status(500).json({ error: 'Something went wrong.' });
});

// Don't serve requests before tables exist on a cold start; schema failures
// still boot (the .catch above resolves) so a migration hiccup isn't an outage.
schemaReady.then(() => {
    app.listen(PORT, () => {
        console.log(`[${SERVER_VERSION}] Server running on port ${PORT}`);
    });
});
