const puppeteer = require('puppeteer');
const ms = require('ms');
const consola = require('consola');
const { exit } = require('process');

// Check environment variables
const URLs = (process.env.URLs || 'https://www.google.com,https://www.cloudflare.com').split(',');
const TIME_LIMIT = process.env.TIME_LIMIT || '30s';
const VERBOSE = process.env.VERBOSE === 'true';
const OUTPUT_FILE = process.env.OUTPUT_FILE || 'output.json';


// Enable debug-level logging if VERBOSE is enabled
if (VERBOSE) {
  consola.level = 4;
}

consola.info(`Script started with configuration: 
URLs: ${URLs}
TIME_LIMIT: ${TIME_LIMIT}
VERBOSE: ${VERBOSE}
OUTPUT_FILE: ${OUTPUT_FILE}`);

// Core logic
(async () => {
  const browser = await puppeteer.launch({
    headless: true,
    defaultViewport: null,
    timeout: 0,
    args: [
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-setuid-sandbox',
      '--no-first-run',
      '--no-sandbox',
      '--no-zygote',
      '--deterministic-fetch',
      '--disable-features=IsolateOrigins',
      '--disable-site-isolation-trials',
  ]
  });
  const stats = {};

  for (let url of URLs) {
    let page = await browser.newPage();

    // Initialize stats for URL
    stats[url] = {
      reloadsCount: 0,
      requestsCount: 0,
      errorsCount: 0,
      duration: {
        total: 0,
        avg: 0
      }
    };

    page.on('request', (request) => {
      consola.debug(`Starting request: ${request.url()}`);
    });

    page.on('requestfinished', (request) => {
      let duration = NaN;
      if (request.response().timing() != null) {
        duration =
          request.response().timing().receiveHeadersEnd -
          request.response().timing().sendStart;
          stats[url].requestsCount += 1;
      stats[url].duration.total += duration;
      stats[url].duration.avg = stats[url].duration.total / stats[url].requestsCount;
      consola.debug(`Finished request: ${request.url()} - Duration: ${duration}ms`);
      }
    });

    page.on('requestfailed', (request) => {
      consola.warn(`Request failed: ${request.url()} - Error: ${request.failure().errorText}`);
      stats[url].errorsCount += 1;
    });

    // Periodically reload the page with a random delay
    const reloadPage = async () => {
      await page.goto(url);
      stats[url].reloadsCount += 1;
      consola.info(`Reloaded tab for: ${url}`);
      setTimeout(reloadPage, Math.floor(Math.random() * (300000 - 5000) + 5000));
    };

    reloadPage();
  }

  // Save statistics after the specified time
  setTimeout(async () => {
    await browser.close();
    require('fs').writeFileSync(OUTPUT_FILE, JSON.stringify({
      configuration: {
        URLs, TIME_LIMIT, VERBOSE, OUTPUT_FILE
      },
      statistics: stats
    }, null, 2));
    consola.info(`Script finished. Output written to: ${OUTPUT_FILE}`);
    exit(0)
  }, ms(TIME_LIMIT));

})();
