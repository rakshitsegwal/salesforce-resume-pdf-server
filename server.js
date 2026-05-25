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
// PDF OVERRIDE CSS
// -----------------------------------------------------------------------------
// Appended AFTER the client CSS so it wins on specificity.
// Neutralizes preview-only styling (scale transform, card shadow, etc.) and
// enforces A4-correct dimensions so the resume renders at full size.
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

/* ---- Force backgrounds / gradients to render in print ---- */
* {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}

/* ---- Kill preview-only transforms / shadows / rounding on .rb-resume ---- */
.rb-resume {
    transform: none !important;
    transform-origin: top left !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    max-width: none !important;
    width: 794px !important;       /* A4 width at 96dpi */
    margin: 0 auto !important;
    overflow: visible !important;
    background: #ffffff !important;
}

.rb-resume:hover {
    transform: none !important;
}

/* ---- Avoid awkward page breaks inside content blocks ---- */
.rb-resume__header,
.rb-resume__exp,
.rb-resume__edu,
.rb-resume__cert,
.rb-resume__skill {
    break-inside: avoid;
    page-break-inside: avoid;
}

/* ---- The photo placeholder gradient needs explicit print color flag ---- */
.rb-resume__photo-placeholder,
.rb-resume__top-deco,
.rb-resume__cert {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
}
`;

app.post('/generate-pdf', async (req, res) => {

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

        // A4 at 96dpi = 794 x 1123 px.
        // deviceScaleFactor=2 gives crisp text without changing the layout box.
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

    <style>
        /* ===== Client CSS (from the live LWC) ===== */
        ${css}

        /* ===== PDF Overrides (must come last) ===== */
        ${PDF_OVERRIDE_CSS}
    </style>
</head>

<body>
    ${html}
</body>
</html>
`;

        await page.setContent(
            fullHtml,
            {
                waitUntil: 'networkidle0'
            }
        );

        // Use screen media so the resume keeps its on-screen look,
        // but printBackground + the color-adjust CSS rules above
        // ensure gradients and tinted backgrounds still render.
        await page.emulateMediaType('screen');

        // Give fonts and any inline base64 images a beat to settle.
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
            'Content-Length': pdf.length
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
                    content:
                        'You are a resume parsing engine that extracts structured resume information.'
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

        console.error(
            'AI EXTRACTION ERROR:',
            e
        );

        res.status(500).json({
            error: 'AI extraction failed'
        });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`PDF server running on ${PORT}`);
});
