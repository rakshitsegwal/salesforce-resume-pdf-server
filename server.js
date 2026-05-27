const OpenAI = require('openai');

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});
const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');

const app = express();

app.use(cors());

app.use(express.json({
    limit: '20mb'
}));

// =============================================================================
// VERSION MARKER — used to verify which build is actually live on Railway.
// =============================================================================
const SERVER_VERSION = 'v3-with-overrides-2026-05-25';
const BOOT_TIME = Date.now();

app.get('/version', (req, res) => {
    res.json({
        version: SERVER_VERSION,
        bootTime: new Date(BOOT_TIME).toISOString(),
        nowTime: new Date().toISOString()
    });
});

// =============================================================================
// PDF OVERRIDE CSS
// =============================================================================
const PDF_OVERRIDE_CSS = `

/* ---- Page setup ---- */
@page {
    size: A4;
    margin: 0;
}

html, body {
    margin: 0 !important;
    padding: 0 !important;
    background: #ffffff !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    font-family:
        'Salesforce Sans',
        -apple-system,
        BlinkMacSystemFont,
        'Segoe UI',
        Roboto,
        'Helvetica Neue',
        Arial,
        sans-serif;
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
    margin: 0 auto !important;
    overflow: visible !important;
    background: #ffffff !important;
}

.rb-resume:hover {
    transform: none !important;
}

.rb-resume__header,
.rb-resume__exp,
.rb-resume__edu,
.rb-resume__cert,
.rb-resume__skill {
    break-inside: avoid;
    page-break-inside: avoid;
}

.rb-resume__photo-placeholder,
.rb-resume__top-deco,
.rb-resume__cert {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}
`;

app.post('/generate-pdf', async (req, res) => {

    // Diagnostic log — visible in Railway → Deployments → Logs
    console.log('[' + SERVER_VERSION + '] /generate-pdf hit at', new Date().toISOString(), {
        htmlLength: req.body?.html?.length,
        cssLength: req.body?.css?.length,
        cssFirst80: req.body?.css?.slice(0, 80)
    });

    try {

        const {
            html,
            css
        } = req.body;

        const browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--font-render-hinting=none'
            ]
        });

        const page = await browser.newPage();

        await page.setViewport({
            width: 794,
            height: 1123,
            deviceScaleFactor: 2
        });

        const fullHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="server-version" content="${SERVER_VERSION}">

    <style>
        /* ===== Client CSS (from the live LWC) ===== */
        ${css || ''}

        /* ===== PDF Overrides (must come last) ===== */
        ${PDF_OVERRIDE_CSS}
    </style>
</head>

<body>
    ${html || ''}
</body>
</html>
`;

        await page.setContent(
            fullHtml,
            {
                waitUntil: 'networkidle0'
            }
        );

        await page.emulateMediaType('screen');

        await page.evaluateHandle('document.fonts.ready');

        const pdf = await page.pdf({
            format: 'A4',
            printBackground: true,
            preferCSSPageSize: true,
            margin: {
                top: '0',
                right: '0',
                bottom: '0',
                left: '0'
            }
        });

        await browser.close();

        res.set({
            'Content-Type': 'application/pdf',
            'Content-Length': pdf.length,
            'X-Server-Version': SERVER_VERSION
        });

        res.send(pdf);

    } catch (e) {

        console.error(
            'PDF generation error:',
            e
        );

        res.status(500).send(
            'PDF generation failed'
        );
    }
});

app.post('/extract-resume', async (req, res) => {

    try {

        const { text } = req.body;

        if (!text) {
            return res.status(400).json({
                error: 'No text provided'
            });
        }

        const prompt = `
Extract the following resume into structured JSON.

Return ONLY valid JSON.
Do not return markdown.
Do not return explanations.

Schema:
{
  "fullName": "",
  "title": "",
  "email": "",
  "phone": "",
  "location": "",
  "linkedIn": "",
  "summary": "",
  "skills": [],
  "experiences": [
    {
      "company": "",
      "title": "",
      "startDate": "",
      "endDate": "",
      "bullets": []
    }
  ],
  "education": [
    {
      "degree": "",
      "school": "",
      "years": ""
    }
  ],
  "certifications": []
}

Resume:
${text}
`;

        const completion = await openai.chat.completions.create({
            model: 'gpt-4.1-mini',
            messages: [
                {
                    role: 'system',
                    content: 'You are a resume parsing engine that extracts structured resume information.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            temperature: 0.2
        });

        const aiText = completion.choices[0].message.content;

        console.log('AI RESPONSE:', aiText);

        const parsed = JSON.parse(aiText);

        res.json(parsed);

    } catch (e) {
        console.error('AI EXTRACTION ERROR:', e);
        res.status(500).json({
            error: 'AI extraction failed'
        });
    }
});

app.post(
    '/generate-template',
    async (req, res) => {

        try {

            const {
    prompt,
    resumeData,
    metadata
} = req.body;

            const completion =
                await openai.chat.completions.create({

                    model: 'gpt-4.1-mini',

                    messages: [

                        {
                            role: 'system',

                            content: `
YYou are an elite AI resume designer.

You ONLY generate CSS.

You are designing modern premium resumes.

Requirements:
- ATS friendly
- One-page optimized
- Minimal modern aesthetic
- Elegant typography
- Compact spacing when content is dense
- Spacious layout when content is small
- SaaS-level visual quality
- Professional hierarchy
- Beautiful PDF rendering
- Never overflow
- Never clip
- No absolute positioning
- No fixed positioning
- No animations
- Use ONLY:
  .rb-resume--ai-generated

Output ONLY raw CSS.
No markdown.
No explanations.
`
                        },

                        {
    role: 'user',

    content: `

USER DESIGN REQUEST:
${prompt}

RESUME DATA:
${JSON.stringify(resumeData)}

RESUME METADATA:
${JSON.stringify(metadata)}

Generate CSS optimized specifically for THIS resume.

Requirements:
- Single page layout
- ATS friendly
- Compact if resume has large content
- Elegant spacing if content is small
- Modern SaaS quality design
- Professional typography
- Prevent overflow
- Prevent clipping
- No absolute positioning
- No fixed positioning
- Only generate CSS
`
}
                    ],

                    temperature: 0.9
                });

            const css =
                completion
                    .choices[0]
                    .message
                    .content;

            res.json({
                css
            });

        } catch (e) {

            console.error(e);

            res.status(500).json({
                error:
                    'Template generation failed'
            });
        }
    }
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`PDF server ${SERVER_VERSION} running on ${PORT}`);
});