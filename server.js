import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
const OpenAI = require('openai');
const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const app = express();
app.set('trust proxy', 1);

app.use(cors({
    origin: [
        'https://developwithrax-dev-ed.my.site.com'
    ],
    methods: [
        'GET',
        'POST'
    ],
    allowedHeaders: [
        'Content-Type',
        'x-client-id'
    ]
}));
app.use(express.json({ limit: '1mb' }));
app.use(
    helmet({
        crossOriginEmbedderPolicy: false,
        contentSecurityPolicy: false
    })
);

// ─── Version marker ───────────────────────────────────────────────────────────
const SERVER_VERSION = 'v4-redesign-2026-05-27';
const BOOT_TIME = Date.now();

const aiLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,

    max: 20,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
        error:
            'Too many AI requests. Please try again later.'
    }
});

const exportLimiter = rateLimit({

    windowMs: 60 * 60 * 1000,

    max: 5,

    message: {
        error:
            'PDF export limit reached. Please try later.'
    }
});
app.use('/generate-template', aiLimiter);
app.use('/extract-resume', aiLimiter);
app.use('/review-resume', aiLimiter);
app.use('/improve-summary', aiLimiter);
app.use('/generate-pdf', exportLimiter);
app.use('/generate-template', validateClientSession);
app.use('/extract-resume', validateClientSession);
app.use('/review-resume', validateClientSession);
app.use('/improve-summary', validateClientSession);
app.use('/generate-pdf', validateClientSession);
app.get('/version', (req, res) => {
    res.json({
        version: SERVER_VERSION,
        bootTime: new Date(BOOT_TIME).toISOString(),
        nowTime:  new Date().toISOString()
    });
});

function validateClientSession(req, res, next) {

    const clientId =
        req.headers['x-client-id'];

    if (!clientId) {
        return res.status(400).json({
            error:
                'Missing client session.'
        });
    }

    if (clientId.length > 100) {
        return res.status(400).json({
            error:
                'Invalid client session.'
        });
    }

    next();
}

function truncateText(text, max = 12000) {

    if (!text) {
        return '';
    }

    return String(text)
        .slice(0, max);
}

// ─── PDF override CSS (applied last so Puppeteer renders cleanly) ─────────────
const PDF_OVERRIDE_CSS = `
@page { size: A4; margin: 0; }

html, body {
    margin: 0 !important;
    padding: 0 !important;
    background: #ffffff !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
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

/* Remove preview scaling — Puppeteer renders at full size */
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
            'Content-Type':     'application/pdf',
            'Content-Length':    pdf.length,
            'X-Server-Version':  SERVER_VERSION
        });
        res.send(pdf);

    } catch (e) {
        console.error('PDF generation error:', e);
        res.status(500).send('PDF generation failed');
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /extract-resume
// Parses raw resume text into structured JSON
// Handles two-column PDFs, dense content, and bullet trimming for single-page
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
            model:       'gpt-4.1-mini',
            messages:    [
                {
                    role:    'system',
                    content: 'You are an expert resume parser. Extract clean structured data. Return ONLY valid JSON.'
                },
                { role: 'user', content: prompt }
            ],
            temperature: 0.1,
            response_format: { type: 'json_object' }
        });

        const parsed = JSON.parse(completion.choices[0].message.content);

        // Server-side enforcement: cap bullets and skills even if AI ignored the limit
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
// POST /generate-template
// Generates AI CSS for the resume based on a user prompt
// ═════════════════════════════════════════════════════════════════════════════
app.post('/generate-template', async (req, res) => {

    try {
        const { prompt, resumeData, metadata } = req.body;

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

const userPrompt = `USER DESIGN REQUEST:
${prompt}

RESUME CONTENT METADATA:
- Has photo: ${metadata?.hasPhoto || false}
- Experience entries: ${metadata?.experienceCount || 0}
- Skills: ${metadata?.skillCount || 0}
- Certifications: ${metadata?.certificationCount || 0}
- Education entries: ${metadata?.educationCount || 0}
- Summary length: ${metadata?.summaryLength || 0} characters
- Total bullet points across all roles: ${metadata?.totalBullets || 0}
- Content density: ${metadata?.totalBullets > 12 || metadata?.experienceCount > 3 ? 'HIGH — use compact spacing' : 'NORMAL'}

${metadata?.totalBullets > 12 || metadata?.experienceCount > 3 ? `
DENSITY WARNING: This resume has ${metadata?.totalBullets || 'many'} bullet points across ${metadata?.experienceCount || 'multiple'} roles.
You MUST use compact CSS to fit it on one page:
- .rb-resume font-size: 8.5px (not 10px)
- .rb-resume__body padding: 0
- .rb-resume__section margin-bottom: 10px (not 18px)
- .rb-exp-item margin-bottom: 8px (not 13px)
- .rb-exp-bullets li padding/margin: 1px
- .rb-resume__header padding: 16px 24px 12px
` : ''}

Generate CSS that:
1. Matches the design intent from the user request
2. Is specifically optimised for the content density above
3. Keeps everything on ONE A4 page — this is critical
4. Uses ONLY the .rb-resume--ai-generated namespace
5. Returns ONLY raw CSS — nothing else`;

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

        res.json({ css });

    } catch (e) {
        console.error('Template generation error:', e);
        res.status(500).json({ error: 'Template generation failed' });
    }
});

function sanitizeInput(value) {

    return String(value || '')
        .replace(/<script.*?>.*?<\/script>/gi, '')
        .trim();
}

// ═════════════════════════════════════════════════════════════════════════════
// POST /improve-summary
// Rewrites the user's professional summary using their full resume context
// ═════════════════════════════════════════════════════════════════════════════
app.post('/improve-summary', async (req, res) => {

    try {
        const { name, title, summary, skills = [], experience = [] } = req.body;

        // Build context from experience
        const expContext = experience
            .filter(e => e.company || e.title)
            .slice(0, 3)
            .map(e => `${e.title || 'Role'} at ${e.company || 'Company'} (${e.dateRange || ''})`)
            .join(', ');

        const topSkills = (skills || []).slice(0, 8).join(', ');

        const prompt = `You are an expert resume writer specialising in ATS-optimised, compelling professional summaries.

Write a new professional summary for this person.

PERSON:
Name: ${name || 'Unknown'}
Title: ${title || 'Professional'}
Current summary: ${summary || '(none provided)'}
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
// Returns actionable feedback on the complete resume
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

app.listen(PORT, () => {
    console.log(`[${SERVER_VERSION}] Server running on port ${PORT}`);
});

app.use((err, req, res, next) => {

    console.error(err);

    res.status(500).json({
        error:
            'Something went wrong.'
    });
});