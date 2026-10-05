const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');
const puppeteer = require(path.join(__dirname, '../ui/node_modules/puppeteer'));

const PORT = 50080;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const DOCS_IMAGES = path.join(__dirname, '../docs/images');
const FRAMES_DIR = path.join(__dirname, '../temp_frames');

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  if (!fs.existsSync(DOCS_IMAGES)) {
    fs.mkdirSync(DOCS_IMAGES, { recursive: true });
  }
  if (!fs.existsSync(FRAMES_DIR)) {
    fs.mkdirSync(FRAMES_DIR, { recursive: true });
  }

  // 1. Launch server
  console.log('⚡ Launching DNSWatch server...');
  const binaryPath = path.join(__dirname, '../bin/dnswatch.exe');
  const serverProc = spawn(binaryPath, ['serve', `--port=${PORT}`], {
    stdio: 'ignore'
  });

  serverProc.on('error', (err) => {
    console.error('Failed to start server:', err);
  });

  await sleep(2500);

  // 2. Launch Puppeteer using system Chrome
  console.log('🚀 Launching headless browser with system Chrome...');
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1280,820']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 820, deviceScaleFactor: 2 });

  try {
    console.log(`🌐 Navigating to ${BASE_URL}...`);
    await page.goto(BASE_URL, { waitUntil: 'networkidle0', timeout: 30000 });

    // Wait for initial query to complete
    await sleep(4500);

    // Frame counter for demo GIF
    let frameIdx = 0;
    const saveFrame = async () => {
      const framePath = path.join(FRAMES_DIR, `frame_${String(frameIdx).padStart(3, '0')}.png`);
      await page.screenshot({ path: framePath });
      frameIdx++;
    };

    // Helper to click tabs
    const clickTab = async (text) => {
      await page.evaluate((tabText) => {
        const buttons = Array.from(document.querySelectorAll('button'));
        const btn = buttons.find(b => b.textContent && b.textContent.includes(tabText));
        if (btn) btn.click();
      }, text);
      await sleep(1200);
    };

    // 1. Capture Trace View
    console.log('📸 Capturing Recursive Trace View...');
    await clickTab('Recursive Trace');
    const tracePng = path.join(DOCS_IMAGES, 'screenshot_trace.png');
    await page.screenshot({ path: tracePng });
    for (let i = 0; i < 4; i++) await saveFrame();

    // 2. Capture Propagation View with World Map
    console.log('📸 Capturing Global Edge Propagation Map...');
    await clickTab('Edge Propagation');
    const propPng = path.join(DOCS_IMAGES, 'screenshot_propagation.png');
    await page.screenshot({ path: propPng });
    for (let i = 0; i < 5; i++) await saveFrame();

    // 3. Capture DNSSEC Chain View
    console.log('📸 Capturing DNSSEC Chain View...');
    await clickTab('DNSSEC Chain');
    const dnssecPng = path.join(DOCS_IMAGES, 'screenshot_dnssec.png');
    await page.screenshot({ path: dnssecPng });
    for (let i = 0; i < 4; i++) await saveFrame();

    // 4. Capture Domain Health & Audit
    console.log('📸 Capturing Domain Health & Audit View...');
    await clickTab('Domain Health & Audit');
    const auditPng = path.join(DOCS_IMAGES, 'screenshot_audit.png');
    await page.screenshot({ path: auditPng });
    for (let i = 0; i < 5; i++) await saveFrame();

    // 5. Build high-quality animated GIF with ffmpeg
    console.log('🎞️ Compiling animated demo GIF with ffmpeg...');
    const gifOutput = path.join(DOCS_IMAGES, 'dnswatch_demo.gif');
    try {
      execSync(
        `ffmpeg -y -framerate 2 -i "${FRAMES_DIR}/frame_%03d.png" -vf "fps=4,scale=1000:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer" "${gifOutput}"`,
        { stdio: 'inherit' }
      );
      console.log(`✓ Successfully generated ${gifOutput}`);
    } catch (ffmpegErr) {
      console.warn('ffmpeg compilation warning:', ffmpegErr.message);
    }

    console.log('✓ All authentic screenshots and demo GIF captured successfully!');
  } finally {
    await browser.close();
    serverProc.kill();
    // Clean up temporary frames
    if (fs.existsSync(FRAMES_DIR)) {
      fs.rmSync(FRAMES_DIR, { recursive: true, force: true });
    }
  }
}

main().catch(err => {
  console.error('Fatal error during capture:', err);
  process.exit(1);
});
