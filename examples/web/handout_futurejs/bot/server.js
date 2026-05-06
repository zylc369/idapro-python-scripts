const express = require('express')
const puppeteer = require('puppeteer')
const path = require('node:path')

const FLAG = process.env.FLAG || 'SK-CERT{fake_flag}'
const CHALLENGE_URL = process.env.CHALLENGE_URL || 'http://proxy:4000'
const BOT_PORT = Number(process.env.BOT_PORT || 3000)
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT || 10)

let activeVisits = 0

const app = express()
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

app.get('/health', (req, res) => {
  res.sendStatus(200)
})

app.post('/visit', async (req, res) => {
  const { url } = req.body || {}

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'missing url' })
  }

  let parsedUrl
  try {
    parsedUrl = new URL(url)
  } catch {
    return res.status(400).json({ error: 'invalid url' })
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'url must be http or https' })
  }

  if (activeVisits >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'too many concurrent visits' })
  }

  activeVisits++

  let browser
  try {
    browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
      ],
    })

    const page = await browser.newPage()

    await page.setCookie({
      name: 'flag',
      value: FLAG,
      url: CHALLENGE_URL,
      path: '/',
      httpOnly: false,
    })

    await page.goto(url, { timeout: 10000, waitUntil: 'networkidle2' })
    await new Promise((resolve) => setTimeout(resolve, 3000))

    return res.json({ status: 'visited' })
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error'
    console.error('visit error:', message)
    return res.status(500).json({ error: 'visit failed' })
  } finally {
    if (browser) {
      try {
        await browser.close()
      } catch {
        // ignore close errors
      }
    }

    activeVisits--
  }
})

app.listen(BOT_PORT, () => {
  console.log(`bot listening on port ${BOT_PORT}`)
})
