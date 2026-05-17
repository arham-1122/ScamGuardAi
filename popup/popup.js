document.addEventListener('DOMContentLoaded', async () => {
    // Buttons
    document.getElementById('btn-options').addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });

    document.getElementById('btn-dismiss').addEventListener('click', () => {
        window.close();
    });

    document.getElementById('btn-report').addEventListener('click', () => {
        chrome.tabs.create({ url: "https://github.com/scamguard/issues/new" });
    });

    document.getElementById('btn-block').addEventListener('click', () => {
        alert("This domain has been flagged. DeclarativeNetRequest blocking will be implemented here.");
    });

    // Fetch tab info
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        if (!tabs || tabs.length === 0) return;
        const tab = tabs[0];

        try {
            const url = new URL(tab.url);
            document.getElementById('current-domain').textContent = url.hostname;
        } catch (e) {
            document.getElementById('current-domain').textContent = "Unknown";
            return;
        }

        // Get verdict from session storage
        const result = await chrome.storage.session.get(`verdict_${tab.id}`);
        const verdict = result[`verdict_${tab.id}`];

        if (verdict) {
            updateUI(verdict);
        } else {
            // Waiting for background or whitelist
            chrome.action.getBadgeText({ tabId: tab.id }, (badge) => {
                if (badge === '✓') {
                    updateUI({
                        risk_score: 0,
                        risk_level: "safe",
                        primary_threat: "none",
                        user_warning: "This site has been verified or whitelisted.",
                        technical_summary: "Whitelisted or completely safe.",
                        red_flags: [],
                        safe_signals: ["Verified safe site"]
                    });
                }
            });
        }
    });
});

function updateUI(verdict) {
    const scoreText = document.getElementById('score-text');
    const gaugeFill = document.getElementById('gauge-fill');
    const riskBadge = document.getElementById('risk-badge');
    const userWarning = document.getElementById('user-warning');

    // Set score
    const score = verdict.risk_score || 0;
    scoreText.textContent = score;

    // Animate Gauge (Circumference 283)
    const offset = 283 - (score / 100) * 283;
    // We want reversed: score 100 means full gauge.
    setTimeout(() => {
        gaugeFill.style.strokeDashoffset = offset;
    }, 50);

    // Color logic
    let color = '#1E8E3E'; // Green
    if (score >= 75) color = '#D93025'; // Red
    else if (score >= 45) color = '#F29900'; // Amber

    gaugeFill.style.stroke = color;
    riskBadge.style.background = color;
    riskBadge.style.color = 'white';

    riskBadge.textContent = verdict.risk_level.toUpperCase();
    userWarning.textContent = verdict.user_warning || (score < 45 ? "This site looks safe securely surf." : "Proceed with extreme caution.");

    // Populate Details
    const redFlagsList = document.getElementById('red-flags-list');
    redFlagsList.innerHTML = '';
    if (verdict.red_flags && verdict.red_flags.length > 0) {
        verdict.red_flags.forEach(flag => {
            const li = document.createElement('li');
            li.textContent = flag;
            redFlagsList.appendChild(li);
        });
    } else {
        redFlagsList.innerHTML = '<li>None detected</li>';
    }

    const safeSignalsList = document.getElementById('safe-signals-list');
    safeSignalsList.innerHTML = '';
    if (verdict.safe_signals && verdict.safe_signals.length > 0) {
        verdict.safe_signals.forEach(sig => {
            const li = document.createElement('li');
            li.textContent = sig;
            safeSignalsList.appendChild(li);
        });
    } else {
        safeSignalsList.innerHTML = '<li>None</li>';
    }

    document.getElementById('tech-summary').textContent = verdict.technical_summary || "AI Analysis " + (verdict.ai_skipped ? "skipped" : "complete");
}
