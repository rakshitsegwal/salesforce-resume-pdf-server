const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const OpenAI    = require('openai');
const express   = require('express');
const cors      = require('cors');
const puppeteer = require('puppeteer');

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const app    = express();
app.set('trust proxy', 1);

app.use(cors({
    origin: [
        'https://developwithrax-dev-ed.my.site.com'
    ],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'x-client-id']
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
const SERVER_VERSION = 'v8-css-fix-2026';
const BOOT_TIME      = Date.now();

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
// Strips properties that break the sidebar layout. Called on every AI-generated
// CSS string before it is returned to the client.
function sanitizeAiCss(css) {
    if (!css) return '';

    // 1. Remove absolute/fixed positioning — causes section overlap
    css = css.replace(/position\s*:\s*(absolute|fixed)\s*(!important)?\s*;/gi, 'position: relative;');

    // 2. Remove negative margins — causes sections to overlap each other
    css = css.replace(/margin(-top|-bottom|-left|-right)?\s*:\s*-[\d.]+[a-z%]*\s*(!important)?\s*;/gi, '');

    // 3. Remove overflow:hidden on structural containers — clips content
    css = css.replace(
        /(\.rb-resume--ai-generated(?:\s+\.rb-resume__(?:sidebar|main|body|section|header))?\s*\{[^}]*?)overflow\s*:\s*hidden\s*(!important)?\s*;/gi,
        '$1overflow: visible;'
    );

    // 4. Remove height on sidebar/sections — fixed heights clip content
    css = css.replace(
        /(\.rb-resume--ai-generated(?:\s+\.rb-resume__(?:sidebar|section))?\s*\{[^}]*)\bheight\s*:\s*[\d.]+[a-z%]+\s*(!important)?\s*;/gi,
        '$1min-height: 0;'
    );

    // 5. Remove float — breaks grid layout
    css = css.replace(/float\s*:\s*(left|right)\s*(!important)?\s*;/gi, '');

    // 6. Remove display:none — hides content accidentally
    css = css.replace(/display\s*:\s*none\s*(!important)?\s*;/gi, '');

    // 7. Remove grid/flex on sidebar that could change column count
    css = css.replace(
        /(\.rb-resume--ai-generated\s+\.rb-resume__body\s*\{[^}]*)grid-template-columns\s*:[^;]+;/gi,
        '$1grid-template-columns: 210px 1fr;'
    );

    // 8. Append a safety block that enforces critical layout rules
    css += `

/* ── Safety overrides — prevent layout breakage ── */
.rb-resume--ai-generated .rb-resume__body {
    display: grid !important;
    grid-template-columns: 210px 1fr !important;
    overflow: visible !important;
}

.rb-resume--ai-generated .rb-resume__sidebar {
    display: flex !important;
    flex-direction: column !important;
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
}

.rb-resume--ai-generated .rb-resume__main {
    display: flex !important;
    flex-direction: column !important;
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
}

.rb-resume--ai-generated .rb-resume__section {
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
    float: none !important;
    display: block !important;
}

.rb-resume--ai-generated .rb-summary {
    position: relative !important;
    overflow: visible !important;
    height: auto !important;
    word-break: break-word !important;
    overflow-wrap: break-word !important;
}

.rb-resume--ai-generated .rb-skills {
    display: flex !important;
    flex-wrap: wrap !important;
    position: relative !important;
    height: auto !important;
    overflow: visible !important;
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
- No absolute or fixed positioning.
- No animations or transitions.
- No overflow: hidden on the resume root.
- Preserve readable font sizes (minimum 8px for body, 10px for headings).
- Ensure high colour contrast for ATS scanning.
- Keep the two-column sidebar + main layout unless explicitly asked to change it.
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


app.listen(PORT, () => {
    console.log(`[${SERVER_VERSION}] Server running on port ${PORT}`);
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong.' });
});