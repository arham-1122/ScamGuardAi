import { RulesEngine } from './rules.js';
import { CacheEngine } from './cache.js';
import { RateLimiter } from './rate-limiter.js';

export const Analyzer = {
    async analyze(signalBundle) {
        const domainAndPath = `${signalBundle.domain}${signalBundle.url}`;

        // Check Cache
        const cachedVerdict = await CacheEngine.get(domainAndPath);
        if (cachedVerdict) {
            console.log('Cache hit for', domainAndPath);
            return cachedVerdict;
        }

        // Step 1: Static Rules
        const staticScore = RulesEngine.calculateStaticScore(signalBundle);
        console.log('Static score computed:', staticScore);

        if (staticScore < 20) {
            // Safe, fast path
            const verdict = this._generateFallbackSafeVerdict(staticScore);
            return verdict; // don't cache inherently safe plain sites just to save space, or maybe we do? Let's not cache obvious safe to save IDB space.
        }

        // Step 3: Rate Limiter Check (done before calling Claude)
        const canUseAi = await RateLimiter.consume();
        if (!canUseAi || staticScore >= 60) {
            // If static score >= 60 AND cache has no Claude result -> skip Claude, return immediately
            // Wait, spec says "If static score >= 60 AND cache has no Claude result -> skip Claude..."
            console.log('Skipping AI. Static Score:', staticScore, 'Rate Limited:', !canUseAi);
            const verdict = this._generateStaticVerdict(staticScore, !canUseAi);
            return verdict;
        }

        // Call AI
        const prefs = await chrome.storage.sync.get(['apiKey']);
        if (!prefs.apiKey) {
            console.warn("API key not configured.");
            return this._generateStaticVerdict(staticScore, true, "API key not configured");
        }

        try {
            const aiVerdict = await this._callClaudeAPI(signalBundle, prefs.apiKey);

            // Merge scores
            const finalScore = Math.round((staticScore * 0.3) + (aiVerdict.risk_score * 0.7));
            aiVerdict.risk_score = finalScore;

            // Update risk level based on final calculated score
            if (finalScore >= 90) aiVerdict.risk_level = "critical";
            else if (finalScore >= 75) aiVerdict.risk_level = "high";
            else if (finalScore >= 45) aiVerdict.risk_level = "medium";
            else if (finalScore >= 20) aiVerdict.risk_level = "low";
            else aiVerdict.risk_level = "safe";

            // Cache the result
            await CacheEngine.set(domainAndPath, aiVerdict);

            return aiVerdict;
        } catch (error) {
            console.error('Claude API Error:', error);
            // Retry logic or fallback
            let retryData = null;
            try {
                await new Promise(res => setTimeout(res, 1000));
                retryData = await this._callClaudeAPI(signalBundle, prefs.apiKey);
            } catch (retryError) {
                console.error('Retry failed:', retryError);
            }

            if (retryData) {
                // Compute and cache retry
                const finalScore = Math.round((staticScore * 0.3) + (retryData.risk_score * 0.7));
                retryData.risk_score = finalScore;
                await CacheEngine.set(domainAndPath, retryData);
                return retryData;
            }

            // Final fallback
            chrome.storage.local.set({ last_error: error.message });
            return this._generateStaticVerdict(staticScore, true, "API Error");
        }
    },

    async _callClaudeAPI(signalBundle, apiKey) {
        const promptData = `
You are ScamGuard, an expert security analyst embedded in a browser extension. 
Your job is to analyze webpage signal data and return a structured risk assessment.

You detect:
1. Phishing pages (credential harvesting, brand impersonation)
2. Fake ecommerce stores (non-delivery, payment fraud)
3. Scam job postings (advance fee, fake employers, data harvesting)
4. Crypto scams (fake giveaways, rug pulls, pump-and-dump promotion)
5. Fake urgency manipulation (countdown timers, false scarcity, FOMO)
6. Suspicious domains (lookalikes, typosquatting, IDN homoglyphs)
7. Social engineering (authority impersonation, fear/urgency tactics)
8. Manipulative language (dark patterns, pressure selling, gaslighting)
9. Fake reviews (generic superlatives, no specifics, bulk testimonials)
10. Dangerous redirects (cloaking, affiliate fraud, malware delivery)

You receive a JSON object of signals extracted from the page. Analyze ALL signals 
holistically — do not react to individual keywords in isolation. A legitimate site 
can mention "limited time" — look for CLUSTERS of signals across multiple categories.

Always respond with ONLY this JSON object, no prose, no markdown:
{
  "risk_score": <integer 0-100>,
  "risk_level": <"safe" | "low" | "medium" | "high" | "critical">,
  "primary_threat": <string — single most likely threat type or "none">,
  "threat_categories": [<array of detected threat types from the list above>],
  "confidence": <"low" | "medium" | "high">,
  "user_warning": <string — plain English warning for user, max 2 sentences, "" if safe>,
  "technical_summary": <string — technical detail for advanced users, max 3 sentences>,
  "red_flags": [<array of specific signals that raised risk — concrete, specific>],
  "safe_signals": [<array of signals suggesting legitimacy — be fair>],
  "recommendation": <"proceed" | "caution" | "avoid" | "block">,
  "false_positive_risk": <"low" | "medium" | "high" — how likely this is a FP>
}

Risk score guidelines:
0–20: Safe. Established domain, no manipulation, no suspicious patterns.
21–44: Low risk. Minor flags, likely legitimate but review.
45–74: Medium risk. Meaningful red flags. User should proceed with caution.
75–89: High risk. Strong indicators of scam/phishing. Recommend avoiding.
90–100: Critical. Near-certain malicious page. Block recommended.

Be fair: do not penalize legitimate urgency (real sales), known brands, or 
common marketing language when other signals are clean. Context matters.
`;

        // Removing user emails and PII from pageText just in case before sending.
        const safeSignalBundle = { ...signalBundle };
        if (safeSignalBundle.pageText) {
            safeSignalBundle.pageText = safeSignalBundle.pageText
                .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL-REDACTED]')
                .replace(/(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?/gi, '[PHONE-REDACTED]');
        }

        const abortController = new AbortController();
        const timeout = setTimeout(() => abortController.abort(), 8000); // 8s timeout

        const res = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
                "x-api-key": apiKey,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "prompt-caching-2024-07-31",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "claude-3-5-sonnet-20241022",
                max_tokens: 800,
                system: [
                    {
                        type: "text",
                        text: promptData,
                        cache_control: { type: "ephemeral" }
                    }
                ],
                messages: [{ role: "user", content: JSON.stringify(safeSignalBundle, null, 2) }]
            }),
            signal: abortController.signal
        });

        clearTimeout(timeout);

        if (!res.ok) {
            throw new Error(`Anthropic API error: ${res.status}`);
        }

        const data = await res.json();
        let messageText = data.content[0].text;

        // Parse the JSON safely
        const startIndex = messageText.indexOf('{');
        const endIndex = messageText.lastIndexOf('}');
        if (startIndex !== -1 && endIndex !== -1) {
            messageText = messageText.substring(startIndex, endIndex + 1);
        }

        return JSON.parse(messageText);
    },

    _generateStaticVerdict(score, aiSkipped = false, reason = "") {
        return {
            risk_score: score,
            risk_level: score >= 90 ? "critical" : (score >= 75 ? "high" : (score >= 45 ? "medium" : "low")),
            primary_threat: score >= 60 ? "Multiple heuristic flags" : "none",
            threat_categories: [],
            confidence: "low",
            user_warning: score >= 75 ? "Warning: High risk flags detected based on statistical heuristics." : "",
            technical_summary: `Static analysis scored ${score}/100. AI skipped: ${aiSkipped} (${reason})`,
            red_flags: ["Flagged via offline static heuristics"],
            safe_signals: [],
            recommendation: score >= 75 ? "avoid" : (score >= 45 ? "caution" : "proceed"),
            false_positive_risk: "high",
            ai_skipped: aiSkipped
        };
    },

    _generateFallbackSafeVerdict(score) {
        return {
            risk_score: score,
            risk_level: "safe",
            primary_threat: "none",
            threat_categories: [],
            confidence: "high",
            user_warning: "",
            technical_summary: "No immediate threats flagged by static heuristics. AI skipped.",
            red_flags: [],
            safe_signals: ["Static heuristic clean"],
            recommendation: "proceed",
            false_positive_risk: "low"
        };
    }
};
