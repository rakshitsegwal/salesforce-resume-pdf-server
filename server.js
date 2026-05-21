const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');

const app = express();

app.use(cors({
    origin: '*',
    methods: [
        'GET',
        'POST',
        'OPTIONS'
    ],
    allowedHeaders: [
        'Content-Type'
    ]
}));

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

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log(
    `PDF server running on ${PORT}`
);
});