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

app.use(express.json({ limit: '20mb' }));   // Increased for base64 inspiration images

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
const SERVER_VERSION = 'v6-job-match-2026';
const BOOT_TIME      = Date.now();

// ─── Rate limiters ────────────────────────────────────────────────────────────
const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many AI requests. Please try again later.' }
});

const exportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'PDF export limit reached. Please try later.' }
});

app.use('/generate-template',       aiLimiter);
app.use('/extract-resume',          aiLimiter);
app.use('/review-resume',           aiLimiter);
app.use('/improve-summary',         aiLimiter);
app.use('/generate-pdf',            exportLimiter);
app.use('/analyze-job-match',        aiLimiter);
app.use('/optimize-for-job',         aiLimiter);

app.use('/generate-template',       validateClientSession);
app.use('/extract-resume',          validateClientSession);
app.use('/review-resume',           validateClientSession);
app.use('/improve-summary',         validateClientSession);
app.use('/generate-pdf',            validateClientSession);
app.use('/analyze-job-match',        validateClientSession);
app.use('/optimize-for-job',         validateClientSession);

// ─── Health / version ─────────────────────────────────────────────────────────
app.get('/version', (req, res) => {
    res.json({
        version:  SERVER_VERSION,
        bootTime: new Date(BOOT_TIME).toISOString(),
        nowTime:  new Date().toISOString()
    });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function validateClientSession(req, res, next) {
    const clientId = req.headers['x-client-id'];
    if (!clientId)           return res.status(400).json({ error: 'Missing client session.' });
    if (clientId.length > 100) return res.status(400).json({ error: 'Invalid client session.' });
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
// POST /analyze-job-match
// Analyses resume against a job description — returns scores + gap analysis
// ═════════════════════════════════════════════════════════════════════════════
app.post('/analyze-job-match', async (req, res) => {
    try {
        const { resumeData, jobDescription } = req.body;

        if (!jobDescription || jobDescription.trim().length < 30) {
            return res.status(400).json({ error: 'Job description is too short.' });
        }

        const resumeText = buildResumeText(resumeData);
        const jdText     = truncateText(sanitizeInput(jobDescription), 6000);

        const systemPrompt = `You are an expert ATS analyst and senior technical recruiter.
You deeply understand how applicant tracking systems score resumes and what hiring managers look for.
Analyse the resume against the job description and return ONLY valid JSON — no markdown, no explanation.`;

        const userPrompt = `RESUME:
${resumeText}

JOB DESCRIPTION:
${jdText}

SCORING INSTRUCTIONS:
- atsScore (0-100): Consider keyword density, section completeness (has summary/skills/experience/education), measurable achievements, clear formatting signals, contact info completeness.
- jdMatch (0-100): Consider skill overlap, keyword overlap, responsibility alignment, seniority match between resume and JD.
- keywordCoverage (0-100): % of important technical/domain keywords from the JD that appear anywhere in the resume.
- skillsCoverage (0-100): % of explicitly required skills/tools from the JD found in the resume skills list.

Be realistic and calibrated — a resume with no JD overlap should score 30-50 on jdMatch, not 70+.

Return ONLY this JSON structure:
{
  "atsScore": <integer 0-100>,
  "jdMatch": <integer 0-100>,
  "keywordCoverage": <integer 0-100>,
  "skillsCoverage": <integer 0-100>,
  "missingKeywords": [<up to 8 important JD keywords/tools not found anywhere in resume>],
  "missingSkills": [<up to 6 required skills from JD not in resume skills list>],
  "strengths": [<3-4 specific strengths of this resume FOR this particular JD — be specific, not generic>],
  "weaknesses": [<3-4 specific gaps or weak spots for this JD — be specific and actionable>],
  "summarySuggestions": [<2-3 concrete suggestions to improve the summary to better match this JD>],
  "experienceSuggestions": [<2-3 concrete suggestions to strengthen experience bullets for this JD>]
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

        const result = JSON.parse(completion.choices[0].message.content);

        // Clamp scores to valid range
        ['atsScore','jdMatch','keywordCoverage','skillsCoverage'].forEach(k => {
            if (typeof result[k] === 'number') {
                result[k] = Math.max(0, Math.min(100, Math.round(result[k])));
            }
        });

        // Ensure arrays
        ['missingKeywords','missingSkills','strengths','weaknesses',
         'summarySuggestions','experienceSuggestions'].forEach(k => {
            if (!Array.isArray(result[k])) result[k] = [];
        });

        res.json(result);

    } catch (e) {
        console.error('Job match analysis error:', e);
        res.status(500).json({ error: 'Job match analysis failed' });
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// POST /optimize-for-job
// Rewrites resume content (summary + bullets) to target a specific JD
// NEVER invents experience — only rephrases existing content
// ═════════════════════════════════════════════════════════════════════════════
app.post('/optimize-for-job', async (req, res) => {
    try {
        const { resumeData, jobDescription } = req.body;

        if (!jobDescription || jobDescription.trim().length < 30) {
            return res.status(400).json({ error: 'Job description is too short.' });
        }

        const resumeText = buildResumeText(resumeData);
        const jdText     = truncateText(sanitizeInput(jobDescription), 6000);

        const systemPrompt = `You are an expert resume writer specialising in ATS optimisation.
Your task is to rephrase and strengthen existing resume content to better match a job description.

ABSOLUTE RULES — violating these makes the output useless:
1. NEVER invent companies, job titles, dates, degrees, certifications, or projects
2. NEVER add skills or certifications the candidate has not demonstrated
3. ONLY rephrase, reword, or restructure existing content
4. Incorporate JD keywords NATURALLY into existing bullets — do not stuff
5. Use strong action verbs (Led, Architected, Delivered, Optimised, Reduced, Increased, etc.)
6. Add quantification where the original implies scale but lacks numbers (use phrases like "significantly" or "across enterprise-scale systems" if no numbers exist)
7. Keep bullets concise — max 120 characters each
8. Return ONLY valid JSON — no markdown, no explanation`;

        const userPrompt = `Optimise this resume for the job description below.

CURRENT RESUME:
${resumeText}

JOB DESCRIPTION:
${jdText}

Return ONLY this JSON (preserve all original companies/titles/dates exactly):
{
  "summary": "<optimised professional summary — 3-4 sentences, incorporating JD keywords naturally>",
  "skills": [<optimised skills array — keep all existing skills, reorder by JD relevance, may add 1-3 clearly implied skills based on their experience>],
  "experiences": [
    {
      "company": "<EXACT same company name>",
      "title": "<EXACT same job title>",
      "startDate": "<EXACT same>",
      "endDate": "<EXACT same>",
      "bullets": ["<optimised bullet 1>", "<optimised bullet 2>", "<optimised bullet 3>"]
    }
  ]
}`;

        const completion = await openai.chat.completions.create({
            model:           'gpt-4.1-mini',
            messages:        [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userPrompt   }
            ],
            temperature:     0.4,
            response_format: { type: 'json_object' }
        });

        const result = JSON.parse(completion.choices[0].message.content);

        // Validate structure — ensure experiences match input
        if (result.experiences && resumeData?.experiences) {
            result.experiences = result.experiences.map((optExp, i) => {
                const original = resumeData.experiences[i] || {};
                return {
                    ...original,               // preserve all original fields (key, dateRange, etc.)
                    summary:   optExp.summary,
                    bullets:   (optExp.bullets || []).slice(0, 5),
                    bulletsRaw: (optExp.bullets || []).join('\n')
                };
            });
        }

        res.json({ optimizedResume: result });

    } catch (e) {
        console.error('Job optimize error:', e);
        res.status(500).json({ error: 'Resume optimisation failed' });
    }
});

// ─── Resume text builder helper ───────────────────────────────────────────────
function buildResumeText(resumeData) {
    if (!resumeData) return 'No resume data provided.';
    const lines = [];
    if (resumeData.fullName)  lines.push(`Name: ${resumeData.fullName}`);
    if (resumeData.title)     lines.push(`Title: ${resumeData.title}`);
    if (resumeData.summary)   lines.push(`\nSummary:\n${resumeData.summary}`);
    if (resumeData.skills?.length) {
        lines.push(`\nSkills: ${resumeData.skills.join(', ')}`);
    }
    if (resumeData.certifications?.length) {
        lines.push(`\nCertifications: ${resumeData.certifications.join(', ')}`);
    }
    if (resumeData.experiences?.length) {
        lines.push('\nExperience:');
        resumeData.experiences.forEach(exp => {
            lines.push(`  ${exp.title || ''} at ${exp.company || ''} (${exp.dateRange || [exp.startDate, exp.endDate].filter(Boolean).join(' – ')})`);
            (exp.bullets || []).forEach(b => lines.push(`    • ${b}`));
        });
    }
    if (resumeData.education?.length) {
        lines.push('\nEducation:');
        resumeData.education.forEach(edu => {
            lines.push(`  ${edu.degree || ''} ${edu.field ? ', ' + edu.field : ''} — ${edu.school || ''} (${edu.years || ''})`);
        });
    }
    return lines.join('\n');
}

// ═════════════════════════════════════════════════════════════════════════════
// Start
// ═════════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`[${SERVER_VERSION}] Server running on port ${PORT}`);
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong.' });
});