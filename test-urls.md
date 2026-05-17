# ScamGuard Test URLs

Use these scenarios to test the ScamGuard extension's analysis engine. Because actual scam sites are volatile and frequently taken down, these represent patterns you can simulate or commonly find. You can simulate these locally using an HTML page with matched patterns.

### Known Safe Sites (Score < 20)
*These established domains have no suspicious manipulation patterns and are structurally sound.*
1. `https://www.github.com` - Clean structure, well known, no urgent language.
2. `https://www.wikipedia.org` - High-authority information domain.
3. `https://www.apple.com` - No form fields except search, high authority, no scam terminology.
4. `https://developer.mozilla.org` - Standard documentation site, safe.
5. `https://www.amazon.com` - E-commerce without manipulative urgency on main page, established brand.

### Medium-Risk Scenarios (Score 45–74)
*Aggressive marketing, lots of iframes, or mild urgency tactics on lesser-known domains.*
1. `https://www.wish.com` - Often uses countdown timers ("Flash Sale") and scarcity patterns.
2. `https://buy-cheap-electronics-today.myshopify.xyz` (Simulated) - Suspicious TLD (.xyz) combined with a sales countdown.
3. `http://local-plumber-no-ssl.com` (Simulated) - HTTP only, has a contact form asking for personal details, lacks privacy policy.
4. `https://new-crypto-token-presale.io` (Simulated) - Clean domain but uses "10x your investment" marketing language.
5. `https://urgent-news-update.info` (Simulated) - High redirect depth, lots of cross-origin iframes (ad-heavy).

### High-Risk Patterns (Score 75–89)
*Strong indicators of phishing or advance-fee fraud.*
1. `https://paypa1-security-update.tk` (Simulated) - Lookalike brand (paypa1), suspicious TLD (.tk), asks for password.
2. `https://amazon-rewards-winner.ga` (Simulated) - Brand abuse, lottery language ("You have been selected"), no privacy policy.
3. `http://192.168.1.100/login` (Simulated external IP) - IP address as host, HTTP only, contains a password field.
4. `https://work-from-home-earn-500.cf` (Simulated) - Job scam language ("no experience needed make $500/day").
5. `https://elon-musk-eth-giveaway.cc` (Simulated) - Crypto scam language ("guaranteed returns", "double your crypto").

### Critical / Known Scam Patterns (Score 90+)
*Near-certain malicious pages containing clusters of manipulation and technical red flags.*
1. `http://xn--microsft-5wa.com/support/verify` (Simulated Punycode) - IDN homoglyph spoofing Microsoft, HTTP, asks for password.
2. `http://apple-security-alert-id4812.tk` (Simulated) - Fear triggers ("suspicious activity detected", "verify now or lose access"), non-HTTPS login, looks like Apple.
3. `https://irs-tax-refund-claim.xyz` (Simulated) - Authority impersonation ("IRS", "action required" "immediately"), form asks for SSN.
4. `https://metamask-wallet-validation.ml` (Simulated) - Phishing crypto wallet, form containing "seed phrase" inputs, recently registered domain.
5. `http://10.2.4.5/secure-banking-login` (Simulated external IP) - IP address host, password field, HTTP, bank lookalike terminology.
