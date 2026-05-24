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

app.post('/generate-pdf', async (req, res) => {

    try {

        const {
            html,
            css
        } = req.body;

       const browser =
    await puppeteer.launch({

        headless: true,

        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu'
        ]
    });
        const page =
            await browser.newPage();

        const finalHtml = `
            <html>
                <head>
                    <style>
                        ${css}
                    </style>
                </head>

                <body>
                    ${html}
                </body>
            </html>
        `;

        await page.setContent(
            finalHtml,
            {
                waitUntil: 'networkidle0'
            }
        );

        const pdf =
            await page.pdf({
                format: 'A4',
                printBackground: true,
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

    res.status(500).send({
        error: e.message
    });
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

        const completion =
            await openai.chat.completions.create({

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

        const aiText =
            completion.choices[0]
                .message.content;

        console.log(
            'AI RESPONSE:',
            aiText
        );

        const parsed =
            JSON.parse(aiText);

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

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log(
    `PDF server running on ${PORT}`
);
});