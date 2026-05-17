export const RulesEngine = {
  calculateStaticScore(signals) {
    let score = 0;
    
    // Non-HTTPS with password field
    if (!signals.isHTTPS && signals.formFields.hasPassword) {
      score += 40;
    }
    
    // Lookalike domain match
    if (signals.lookalikeBrand) {
      score += 35;
    }
    
    // IDN/Punycode domain
    if (signals.domain && signals.domain.includes('xn--')) {
      score += 30;
    }
    
    // IP address as host
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(signals.domain)) {
      score += 30;
    }
    
    // Domain age < 30 days
    if (signals.domainAgeFlags && signals.domainAgeFlags.isRecent) {
      score += 25;
    }
    
    // Urgency patterns (Fake countdown, deals, etc.)
    if (signals.urgencyPatterns && signals.urgencyPatterns.length > 3) {
      score += 20;
    }
    
    // Fear patterns (Account suspended, IRS, etc.)
    if (signals.fearPatterns && signals.fearPatterns.length > 2) {
      score += 20;
    }
    
    // Crypto guarantee language
    if (signals.cryptoPatterns && signals.cryptoPatterns.length > 0) {
      score += 30;
    }
    
    // Job scam patterns
    if (signals.jobScamPatterns && signals.jobScamPatterns.length > 0) {
      score += 25;
    }
    
    // No privacy policy + no contact
    if (signals.structuralFlags && signals.structuralFlags.includes('no-privacy') && signals.structuralFlags.includes('no-contact')) {
      score += 15;
    }
    
    // Excessive iframes (>3 cross-origin)
    if (signals.iframes && signals.iframes.crossOrigin > 3) {
      score += 20;
    }
    
    // Suspicious TLD (.xyz .tk .ml .ga .cf)
    const suspiciousTlds = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
    if (signals.tld && suspiciousTlds.includes(signals.tld.toLowerCase())) {
      score += 15;
    }
    
    // Redirect depth > 3
    if (signals.structuralFlags && signals.structuralFlags.includes('deep-redirect')) {
      score += 20;
    }
    
    return Math.min(score, 100);
  }
};
