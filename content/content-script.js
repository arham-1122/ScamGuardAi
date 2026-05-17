const BRANDS = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'netflix', 'coinbase', 'binance', 'chase', 'bankofamerica'];
const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.cc', '.buzz', '.info'];

const URGENCY_REGEX = /offer expires in|only \d+ left|flash sale|deal ends tonight|hurry/i;
const FEAR_REGEX = /your account has been|suspicious activity detected|immediately|verify now or lose access|action required/i;
const SCARCITY_REGEX = /limited stock|only \d+ remaining|\d+ people viewing now/i;
const AUTHORITY_REGEX = /IRS|FBI|Microsoft Support|Apple Security Team|Support Agent/i;
const LOTTERY_REGEX = /you have been selected|congratulations winner|claim your prize/i;
const CRYPTO_REGEX = /guaranteed returns|10x your investment|passive income|bitcoin giveaway|Elon Musk|double your crypto/i;
const JOB_REGEX = /work from home earn \$|no experience needed make \$\d+\/day|be your own boss unlimited income/i;
const ROMANCE_REGEX = /I need your help urgently|wire transfer|gift cards/i;

function levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    let matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
        }
    }
    return matrix[b.length][a.length];
}

function extractDomainInfo() {
    const url = window.location.href;
    const hostname = window.location.hostname;
    const parts = hostname.split('.');
    const tld = parts.length > 1 ? `.${parts[parts.length - 1]}` : '';
    const domain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

    // Lookalike 
    let lookalikeBrand = null;
    let coreName = parts.length > 1 ? parts[parts.length - 2] : parts[0];
    for (let brand of BRANDS) {
        if (coreName !== brand && levenshtein(coreName, brand) <= 2) {
            lookalikeBrand = brand;
            break;
        }
    }

    return { url, hostname, tld, domain, lookalikeBrand, isHTTPS: window.location.protocol === 'https:' };
}

function analyzeFormFields() {
    const forms = Array.from(document.forms);
    let formsStats = { count: forms.length, hasPassword: false, hasCreditCard: false, hasSSN: false };
    let hiddenCount = 0;

    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        if (input.type === 'password') formsStats.hasPassword = true;
        if (input.type === 'hidden') hiddenCount++;
        const nameStr = (input.name || input.id || input.placeholder).toLowerCase();
        if (/card|cc\b|cvv|cvc/.test(nameStr)) formsStats.hasCreditCard = true;
        if (/ssn|social security/.test(nameStr)) formsStats.hasSSN = true;
    });

    formsStats.hiddenCount = hiddenCount;
    return formsStats;
}

function extractSignals() {
    const domainInfo = extractDomainInfo();

    const textContent = document.body ? document.body.innerText : "";
    const pageText = textContent.slice(0, 6000);

    const title = document.title;

    const links = Array.from(document.links);
    let externalCount = 0;
    let suspiciousTLDCount = 0;

    links.forEach(l => {
        if (l.hostname && l.hostname !== domainInfo.hostname) {
            externalCount++;
            if (SUSPICIOUS_TLDS.some(dt => l.hostname.endsWith(dt))) suspiciousTLDCount++;
        }
    });

    const iframes = Array.from(document.querySelectorAll('iframe'));
    let crossOriginIframes = 0;
    iframes.forEach(iframe => {
        try {
            if (new URL(iframe.src).hostname !== domainInfo.hostname) crossOriginIframes++;
        } catch (e) { }
    });

    let urgencyPatterns = [], cryptoPatterns = [], jobScamPatterns = [], fearPatterns = [];
    if (URGENCY_REGEX.test(pageText)) urgencyPatterns.push("Urgency Indicator");
    if (SCARCITY_REGEX.test(pageText)) urgencyPatterns.push("Scarcity Metric");
    if (FEAR_REGEX.test(pageText)) fearPatterns.push("Fear/Access Warning");
    if (AUTHORITY_REGEX.test(pageText)) fearPatterns.push("Authority Impersonation");
    if (LOTTERY_REGEX.test(pageText)) urgencyPatterns.push("Lottery/Prize");
    if (CRYPTO_REGEX.test(pageText)) cryptoPatterns.push("Crypto Gain Promise");
    if (JOB_REGEX.test(pageText)) jobScamPatterns.push("Easy Money/Job Scam");

    let structuralFlags = [];
    if (!pageText.toLowerCase().includes('privacy policy')) structuralFlags.push('no-privacy');
    if (!pageText.toLowerCase().match(/contact us|support@/)) structuralFlags.push('no-contact');
    if (window.performance && performance.getEntriesByType) {
        const navs = performance.getEntriesByType("navigation");
        if (navs.length > 0 && navs[0].redirectCount > 3) structuralFlags.push('deep-redirect');
    }

    return {
        url: domainInfo.url,
        domain: domainInfo.hostname,
        tld: domainInfo.tld,
        isHTTPS: domainInfo.isHTTPS,
        domainAgeFlags: { isRecent: false }, // Needs external API for true WHOIS
        lookalikeBrand: domainInfo.lookalikeBrand,
        pageText: pageText,
        title: title,
        formFields: analyzeFormFields(),
        links: { externalCount, suspiciousTLDCount },
        iframes: { total: iframes.length, crossOrigin: crossOriginIframes },
        urgencyPatterns,
        cryptoPatterns,
        jobScamPatterns,
        fearPatterns,
        structuralFlags,
        timestamp: Date.now()
    };
}

let debounceTimer = null;
let lastUrl = window.location.href;
let mutationCount = 0;

function sendSignals() {
    const signalBundle = extractSignals();
    chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", payload: signalBundle }).catch(() => { });
}

function handleDOMMutations() {
    if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        mutationCount = 0;
        chrome.runtime.sendMessage({ type: "SCAN_PENDING" }).catch(() => { });
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(sendSignals, 2000);
        return;
    }

    mutationCount++;
    if (mutationCount > 200) {
        chrome.runtime.sendMessage({ type: "SCAN_PENDING" }).catch(() => { });
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            mutationCount = 0;
            sendSignals();
        }, 2000);
    }
}

// Initial Run
setTimeout(sendSignals, 1000);

// Observer for SPA
if (document.body) {
    const observer = new MutationObserver(handleDOMMutations);
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
}

// Verdict Receiver to display banner
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "VERDICT" && message.payload.risk_score >= 75) {
        const payload = message.payload;
        // Inject Warning Banner
        if (document.getElementById('scamguard-banner-host')) return;

        const host = document.createElement('div');
        host.id = 'scamguard-banner-host';
        host.style.position = 'fixed';
        host.style.top = '0';
        host.style.left = '0';
        host.style.width = '100%';
        host.style.zIndex = '2147483647';
        host.style.pointerEvents = 'none'; // allow click through except banner child
        document.body.appendChild(host);

        const shadow = host.attachShadow({ mode: 'closed' });

        // Link CSS
        const styleLink = document.createElement('link');
        styleLink.rel = 'stylesheet';
        styleLink.href = chrome.runtime.getURL('content/content-style.css');
        shadow.appendChild(styleLink);

        const banner = document.createElement('div');
        banner.className = `scamguard-banner ${payload.risk_score >= 90 ? 'critical' : 'high'}`;
        banner.style.pointerEvents = 'auto'; // allow clicking banner controls

        banner.innerHTML = `
            <div class="scamguard-banner-content">
                <span class="scamguard-icon">⚠</span>
                <span class="scamguard-text"><strong>ScamGuard Alert:</strong> ${payload.user_warning || "High risk site detected!"}</span>
            </div>
            <div class="scamguard-actions">
                <button class="scamguard-details-btn">Details</button>
                <button class="scamguard-dismiss-btn">Dismiss</button>
            </div>
        `;

        shadow.appendChild(banner);

        const dismissBtn = banner.querySelector('.scamguard-dismiss-btn');
        dismissBtn.addEventListener('click', () => {
            host.remove();
        });

        const detailsBtn = banner.querySelector('.scamguard-details-btn');
        detailsBtn.addEventListener('click', () => {
            // Future extension could inject popup or just dismiss
            alert("Open the ScamGuard extension popup for detailed risk information.");
        });
    }
});
