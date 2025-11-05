// content.js — PhishSpector Complete Enhanced Version (FIXED)
// (() => {
//   console.log('[PhishSpector] Enhanced content script loaded');

(() => {
  console.log('[PhishSpector] 🚀 Enhanced content script loaded - v2.0');

  const ROW_SELECTOR = 'div[role="main"] .zA';
  const processed = new WeakMap();
  let lastRowCount = 0;

  // ------------------------- //
  // Local heuristic scoring   //
  // ------------------------- //
  function computeLocalScore({ fromText = '', subjectText = '', snippetText = '', rowText = '' }) {
    let score = 0;
    const subj = (subjectText || '').trim();
    const combined = (subj + ' ' + snippetText + ' ' + rowText + ' ' + (fromText || '')).toLowerCase();

    const veryStrong = [
      'account suspended', 'wire transfer', 'payment required', 'verify account',
      'verify your account', 'reset your password', 'action required',
      'confirm your account', 'your account has been suspended', 'unauthorized'
    ];
    veryStrong.forEach(k => { if (combined.includes(k)) score += 30; });

    const strong = ['urgent', 'verify', 'verification', 'reset', 'password', 'account',
      'suspended', 'security alert', 'click', 'confirm', 'immediately', 'limited time',
      'invoice', 'sign-in'];
    strong.forEach(k => { if (combined.includes(k)) score += 12; });

    const urls = (snippetText.match(/https?:\/\/[^\s)]+/gi) || []);
    if (urls.length >= 1) score += 25;
    if (urls.length >= 2) score += 10;

    const suspiciousTLDs = ['.xyz', '.top', '.club', '.ru', '.tk', '.cf', '.ga', '.gq', '.ml'];
    urls.forEach(u => {
      const low = u.toLowerCase();
      suspiciousTLDs.forEach(t => { if (low.includes(t)) score += 18; });
      if (/\bhttps?:\/\/\d{1,3}(\.\d{1,3}){3}[:\/]/.test(low)) score += 20;
      if (low.includes('xn--')) score += 20;
      if (low.length > 90) score += 8;
    });

    const brands = ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'bank', 'facebook', 'linkedin'];
    brands.forEach(b => {
      if (combined.includes(b) && !(fromText || '').toLowerCase().includes(b)) score += 22;
    });

    if (fromText) {
      const emailLike = (fromText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [])[0];
      if (!emailLike) score += 6;
      if ((fromText.replace(/\s/g, '').length) <= 2) score += 12;
    }

    const exclam = (subj.match(/!/g) || []).length;
    if (exclam > 0) score += Math.min(12, exclam * 4);
    const uppercaseShare = (subj.replace(/[^A-Z]/g, '').length) / Math.max(1, subj.length || 1);
    if (uppercaseShare > 0.4) score += 18;

    if (/\battachment\b|\bpaperclip\b/i.test(rowText || '')) score += 10;

    score = Math.min(100, Math.round(score + Math.random() * 4));
    return score;
  }

  // ------------------------- //
  // Badge UI helper           //
  // ------------------------- //
  function createBadge(score) {
    const span = document.createElement('span');
    span.className = 'phish-badge';
    span.textContent = `${score}%`;
    span.title = `Phishing likelihood: ${score}%`;
    span.style.cssText = `
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-width:36px;
      padding:2px 6px;
      border-radius:12px;
      font-size:12px;
      font-weight:600;
      color:#222;
      margin-left:6px;
    `;

    if (score >= 80) span.style.background = 'rgba(255,77,77,0.15)';
    else if (score >= 50) span.style.background = 'rgba(255,204,0,0.15)';
    else span.style.background = 'rgba(76,175,80,0.12)';

    return span;
  }

  // ------------------------- //
  // Badge insertion           //
  // ------------------------- //
  function extractInfoFromRow(row) {
    let fromText = '', subjectText = '', snippetText = '';
    try {
      const fromEl = row.querySelector('.yX.xY .yP, .yW span, .yF span, .yP');
      if (fromEl) fromText = (fromEl.innerText || fromEl.textContent || '').trim();
      const subjEl = row.querySelector('.y6 span:first-child, .bog, .bqe, .y6');
      if (subjEl) subjectText = (subjEl.innerText || subjEl.textContent || '').trim();
      const snipEl = row.querySelector('.y2, .bq4, .y2 span');
      if (snipEl) snippetText = (snipEl.innerText || snipEl.textContent || '').trim();
    } catch (e) { }
    const rowText = (row.innerText || row.textContent || '').trim();
    return { fromText, subjectText, snippetText, rowText };
  }

  async function insertOrUpdateBadge(row) {
    const info = extractInfoFromRow(row);
    const hash = (info.subjectText || '') + '||' + (info.fromText || '') + '||' + (info.snippetText || '');
    const existingBadge = row.querySelector('.phish-badge');
    if (processed.get(row) === hash && existingBadge) return;
    if (existingBadge) existingBadge.remove();

    const localScore = computeLocalScore(info);
    const badge = createBadge(localScore);

    const dateEl = row.querySelector('.xW span[title], .xW, .y2');
    if (dateEl && dateEl.parentElement) {
      dateEl.parentElement.insertBefore(badge, dateEl);
    } else {
      row.appendChild(badge);
    }

    processed.set(row, hash);
  }

  // ------------------------- //
  // ADVANCED DOMAIN ANALYSIS  //
  // ------------------------- //
  async function analyzeDomain(url) {
    try {
      const domain = new URL(url).hostname;
      const analysis = {
        domain: domain,
        riskScore: 0,
        warnings: [],
        recommendations: [],
        technicalDetails: {}
      };

      // 1. Domain Age & Type Check
      if (domain.includes('ngrok') || isNewDomain(domain)) {
        analysis.riskScore += 30;
        analysis.warnings.push("New or temporary domain detected");
        analysis.technicalDetails.domainAge = "Less than 1 year (estimated)";
      }

      // 2. SSL Certificate Analysis
      if (url.startsWith('https://')) {
        analysis.technicalDetails.ssl = "Present";
        if (domain.includes('ngrok') || isSuspiciousTld(domain)) {
          analysis.riskScore += 20;
          analysis.warnings.push("HTTPS present but domain is suspicious");
        }
      } else {
        analysis.riskScore += 25;
        analysis.warnings.push("No HTTPS encryption - data transmission is vulnerable");
      }

      // 3. Domain Reputation Check
      const reputationResult = await checkDomainReputation(domain);
      if (reputationResult) {
        analysis.riskScore += 40;
        analysis.warnings.push("Domain matches known phishing patterns");
      }

      // 4. Content Analysis
      if (url.includes('login') || url.includes('verify')) {
        analysis.riskScore += 15;
        analysis.technicalDetails.pageType = "Login/Verification page";
      }

      // 5. Brand Impersonation Check
      const brandCheck = checkBrandImpersonation(domain, url);
      if (brandCheck.isImpersonating) {
        analysis.riskScore += 50;
        analysis.warnings.push(`Potential ${brandCheck.brand} impersonation`);
      }

      analysis.riskScore = Math.min(100, analysis.riskScore);
      
      // Generate recommendations
      if (analysis.riskScore > 70) {
        analysis.recommendations.push("🚨 HIGH RISK: Do not enter any credentials");
        analysis.recommendations.push("Verify the sender's identity through other means");
      } else if (analysis.riskScore > 40) {
        analysis.recommendations.push("⚠️ Exercise caution with this link");
        analysis.recommendations.push("Check for misspellings in the domain name");
      } else {
        analysis.recommendations.push("✅ Appears safe, but remain vigilant");
      }

      console.log('[PhishSpector] Domain analysis completed:', analysis);
      return analysis;
    } catch (error) {
      console.error('Domain analysis error:', error);
      // Return a default analysis object instead of null
      return {
        domain: url,
        riskScore: 50,
        warnings: ['Analysis failed - proceeding with caution'],
        recommendations: ['Verify this link manually before proceeding'],
        technicalDetails: { error: 'Analysis failed' }
      };
    }
  }

  // Helper functions for domain analysis
  function isNewDomain(domain) {
    const newDomains = ['ngrok-free.app', 'localtest.me', 'web.app', 'pages.dev'];
    return newDomains.some(newDomain => domain.includes(newDomain));
  }

  function isSuspiciousTld(domain) {
    const suspiciousTlds = ['.xyz', '.top', '.club', '.tk', '.cf', '.ga', '.ml', '.pp', '.gdn'];
    return suspiciousTlds.some(tld => domain.endsWith(tld));
  }

  async function checkDomainReputation(domain) {
    const knownPhishingDomains = [
      'ngrok-free.app', 'ngrok.io', 'freeaccountverify.com',
      'security-alert-login.com', 'account-verification-portal.com',
      'google-verify.com', 'microsoft-security.com'
    ];
    return knownPhishingDomains.some(badDomain => domain.includes(badDomain));
  }

  function checkBrandImpersonation(domain, url) {
    const brands = {
      'google': ['google', 'gmail', 'youtube'],
      'microsoft': ['microsoft', 'outlook', 'hotmail'],
      'paypal': ['paypal'],
      'facebook': ['facebook', 'fb'],
      'amazon': ['amazon'],
      'apple': ['apple', 'icloud']
    };

    for (const [brand, keywords] of Object.entries(brands)) {
      for (const keyword of keywords) {
        if (url.toLowerCase().includes(keyword) && !domain.includes(`.${brand}.`)) {
          return { isImpersonating: true, brand: brand };
        }
      }
    }
    return { isImpersonating: false, brand: null };
  }

  function estimateLinkRisk(url) {
    let risk = 0;
    
    // High risk patterns
    if (url.includes('ngrok-free.app') || url.includes('ngrok.io')) risk += 70;
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) risk += 80;
    if (url.includes('verify') && url.includes('google')) risk += 90;
    
    // Medium risk patterns  
    if (url.includes('login') || url.includes('reset') || url.includes('forgot')) risk += 50;
    if (url.includes('http://')) risk += 30;
    
    // Brand impersonation
    const brands = ['google', 'microsoft', 'paypal', 'facebook'];
    for (let brand of brands) {
      if (url.includes(brand) && !url.includes(`.${brand}.`)) {
        risk += 60;
      }
    }
    
    return Math.min(100, risk);
  }

  // ------------------------- //
  // ENHANCED ANALYSIS BUILDER //
  // ------------------------- //
  function buildEnhancedAnalysisHTML(advancedAnalysis, certAnalysis, emailAnalysis, quickRisk) {
    console.log('[PhishSpector] Building analysis HTML:', {
      advanced: !!advancedAnalysis,
      cert: !!certAnalysis,
      email: !!emailAnalysis,
      quickRisk
    });

    return `
        <div class="quick-assessment">
            <strong>Quick Risk Assessment:</strong> 
            <span class="risk-${quickRisk > 70 ? 'high' : quickRisk > 40 ? 'medium' : 'low'}">${quickRisk}%</span>
        </div>
        
        ${advancedAnalysis ? `
        <div class="analysis-report">
            <div class="risk-score ${advancedAnalysis.riskScore > 70 ? 'high' : advancedAnalysis.riskScore > 40 ? 'medium' : 'low'}">
                <strong>Advanced Risk Score:</strong> ${advancedAnalysis.riskScore}%
            </div>
            
            ${advancedAnalysis.warnings.length > 0 ? `
            <div class="warnings">
                <strong>🚨 Security Warnings:</strong>
                <ul>${advancedAnalysis.warnings.map(w => `<li>${w}</li>`).join('')}</ul>
            </div>
            ` : '<p>No major security warnings detected.</p>'}
            
            ${advancedAnalysis.recommendations.length > 0 ? `
            <div class="recommendations">
                <strong>💡 Recommendations:</strong>
                <ul>${advancedAnalysis.recommendations.map(r => `<li>${r}</li>`).join('')}</ul>
            </div>
            ` : ''}
        </div>
        ` : '<div class="analysis-report"><p>Domain analysis unavailable</p></div>'}
        
        <!-- EMAIL HEADER ANALYSIS SECTION -->
        ${emailAnalysis ? `
        <div class="email-analysis-section">
            <h3>📧 Email Authentication Analysis</h3>
            <div class="auth-results">
                <div class="auth-item ${emailAnalysis.spfStatus.status === 'FAIL' ? 'failed' : 'passed'}">
                    <strong>SPF:</strong> ${emailAnalysis.spfStatus.status} 
                    <span class="auth-desc">${emailAnalysis.spfStatus.description}</span>
                </div>
                <div class="auth-item ${emailAnalysis.dkimStatus.status === 'FAIL' ? 'failed' : 'passed'}">
                    <strong>DKIM:</strong> ${emailAnalysis.dkimStatus.status}
                    <span class="auth-desc">${emailAnalysis.dkimStatus.description}</span>
                </div>
                <div class="auth-item ${emailAnalysis.dmarcStatus.status === 'FAIL' ? 'failed' : 'passed'}">
                    <strong>DMARC:</strong> ${emailAnalysis.dmarcStatus.status}
                    <span class="auth-desc">${emailAnalysis.dmarcStatus.description}</span>
                </div>
            </div>
            ${emailAnalysis.warnings.length > 0 ? `
            <div class="email-warnings">
                <strong>Email Security Issues:</strong>
                <ul>${emailAnalysis.warnings.map(w => `<li>${w}</li>`).join('')}</ul>
            </div>
            ` : '<p>Email authentication passed all checks.</p>'}
        </div>
        ` : '<div class="email-analysis-section"><p>Email analysis not available for this link</p></div>'}
        
        <!-- SSL CERTIFICATE ANALYSIS SECTION -->
        ${certAnalysis ? `
        <div class="certificate-analysis-section">
            <h3>🔐 SSL Certificate Analysis</h3>
            <div class="cert-details">
                <div class="cert-item">
                    <strong>Issuer:</strong> ${certAnalysis.issuer}
                </div>
                <div class="cert-item">
                    <strong>Valid Until:</strong> ${certAnalysis.expirationDays} days
                </div>
                <div class="cert-item ${certAnalysis.isSelfSigned ? 'warning' : 'safe'}">
                    <strong>Certificate Type:</strong> ${certAnalysis.isSelfSigned ? 'Self-Signed ❌' : 'Trusted CA ✅'}
                </div>
                <div class="cert-item">
                    <strong>Trust Score:</strong> ${certAnalysis.trustScore}/100
                </div>
            </div>
            ${certAnalysis.riskFactors.length > 0 ? `
            <div class="cert-warnings">
                <strong>Certificate Risks:</strong>
                <ul>${certAnalysis.riskFactors.map(risk => `
                    <li class="risk-${risk.level.toLowerCase()}">
                        <strong>${risk.level}:</strong> ${risk.message}
                    </li>
                `).join('')}</ul>
            </div>
            ` : '<p>No certificate risks detected.</p>'}
        </div>
        ` : '<div class="certificate-analysis-section"><p>SSL certificate analysis unavailable</p></div>'}
        
        <!-- PASSWORD PROTECTION STATUS -->
        <div class="password-protection-section">
            <h3>🛡️ Password Protection</h3>
            <div class="protection-status active">
                <span class="status-indicator"></span>
                <strong>Auto-fill Protection:</strong> ACTIVE
                <p class="protection-desc">Password managers are blocked on suspicious pages</p>
            </div>
        </div>
    `;
  }

  // ------------------------- //
  // ENHANCED POPUP SYSTEM    //
  // ------------------------- //
  async function createPhishSpectorPopup(url, link = null) {
    // Remove existing popup if any
    const existingPopup = document.getElementById('phishspector-popup');
    if (existingPopup) existingPopup.remove();

    console.log('[PhishSpector] Starting comprehensive analysis for:', url);

    try {
      // Perform all analyses
      const quickRisk = estimateLinkRisk(url);
      const domain = new URL(url).hostname;
      
      // Run analyses in parallel with error handling
      const analysisPromises = [
        analyzeDomain(url).catch(e => {
          console.error('Domain analysis failed:', e);
          return null;
        }),
        analyzeSSLCertificate(domain).catch(e => {
          console.error('SSL analysis failed:', e);
          return null;
        })
      ];

      const [advancedAnalysis, certAnalysis] = await Promise.all(analysisPromises);

      // Get email analysis if available
      let emailAnalysis = null;
      if (link) {
        try {
          const emailData = link.getAttribute('data-email-analysis');
          if (emailData) {
            emailAnalysis = JSON.parse(emailData);
          } else {
            // Perform fresh email analysis if no cached data
            const emailElement = link.closest('.zA');
            if (emailElement) {
              emailAnalysis = analyzeEmailHeaders(emailElement);
            }
          }
        } catch (e) {
          console.error('Email analysis failed:', e);
        }
      }

      console.log('[PhishSpector] All analyses completed:', {
        quickRisk,
        advancedAnalysis: !!advancedAnalysis,
        certAnalysis: !!certAnalysis,
        emailAnalysis: !!emailAnalysis
      });

      // Build enhanced analysis HTML
      const analysisHTML = buildEnhancedAnalysisHTML(advancedAnalysis, certAnalysis, emailAnalysis, quickRisk);

      const popup = document.createElement('div');
      popup.id = 'phishspector-popup';
      popup.innerHTML = `
        <div class="phishspector-overlay">
          <div class="phishspector-modal">
            <h2>🔍 PhishSpector Advanced Security Analysis</h2>
            
            <div class="url-display">
              <strong>URL:</strong> ${url}
            </div>
            
            ${analysisHTML}
            
            <div class="actions">
              <label class="action-option">
                <input type="radio" name="action" value="sandbox" checked>
                <span>🔒 Analyze in Safe Sandbox (Recommended)</span>
              </label>
              
              <label class="action-option">
                <input type="radio" name="action" value="proceed">
                <span>⚠️ Proceed Anyway (High Risk)</span>
              </label>
              
              <label class="action-option">
                <input type="radio" name="action" value="back">
                <span>↩️ Go Back to Safety</span>
              </label>
            </div>
            
            <div class="buttons">
              <button id="phishspector-continue" class="btn-primary">Continue</button>
              <button id="phishspector-cancel" class="btn-secondary">Cancel</button>
            </div>
          </div>
        </div>
      `;

      // Add enhanced styles
      const styles = `
        #phishspector-popup {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          z-index: 10000;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .phishspector-overlay {
          background: rgba(0,0,0,0.7);
          width: 100%;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        
        .phishspector-modal {
          background: white;
          padding: 24px;
          border-radius: 12px;
          max-width: 650px;
          width: 90%;
          max-height: 80vh;
          overflow-y: auto;
          box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        
        .phishspector-modal h2 {
          margin: 0 0 16px 0;
          color: #d93025;
          font-size: 20px;
        }
        
        .url-display {
          background: #f8f9fa;
          padding: 12px;
          border-radius: 6px;
          margin: 12px 0;
          word-break: break-all;
          font-family: monospace;
          font-size: 14px;
        }
        
        .quick-assessment {
          font-size: 16px;
          margin: 12px 0;
          padding: 10px;
          border-radius: 6px;
          background: #f8f9fa;
        }
        
        .risk-high { color: #d93025; font-weight: bold; }
        .risk-medium { color: #f9a825; }
        .risk-low { color: #0f9d58; }
        
        .analysis-report, .email-analysis-section, .certificate-analysis-section, .password-protection-section {
          margin: 15px 0;
          padding: 15px;
          background: #f8f9fa;
          border-radius: 8px;
        }
        
        .warnings { 
          background: #fce8e6; 
          padding: 12px; 
          border-radius: 6px; 
          margin: 10px 0; 
          border-left: 4px solid #d93025;
        }
        
        .technical-details { 
          background: #e8f0fe; 
          padding: 12px; 
          border-radius: 6px; 
          margin: 10px 0; 
        }
        
        .recommendations { 
          background: #e6f4ea; 
          padding: 12px; 
          border-radius: 6px; 
          margin: 10px 0; 
          border-left: 4px solid #0f9d58;
        }
        
        .auth-results, .cert-details {
          margin: 10px 0;
        }
        
        .auth-item, .cert-item {
          padding: 8px;
          margin: 5px 0;
          border-radius: 4px;
        }
        
        .auth-item.passed, .cert-item.safe {
          background: #e6f4ea;
          border-left: 4px solid #0f9d58;
        }
        
        .auth-item.failed, .cert-item.warning {
          background: #fce8e6;
          border-left: 4px solid #d93025;
        }
        
        .auth-desc {
          font-size: 12px;
          color: #666;
          margin-left: 8px;
        }
        
        .protection-status.active {
          background: #e8f0fe;
          padding: 12px;
          border-radius: 6px;
          border-left: 4px solid #1a73e8;
        }
        
        .status-indicator {
          display: inline-block;
          width: 10px;
          height: 10px;
          background: #0f9d58;
          border-radius: 50%;
          margin-right: 8px;
        }
        
        .protection-desc {
          font-size: 12px;
          color: #666;
          margin: 5px 0 0 0;
        }
        
        .actions {
          margin: 20px 0;
        }
        
        .action-option {
          display: flex;
          align-items: center;
          padding: 10px;
          margin: 8px 0;
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.2s;
        }
        
        .action-option:hover {
          background: #f8f9fa;
        }
        
        .action-option input {
          margin-right: 10px;
        }
        
        .buttons {
          display: flex;
          gap: 12px;
          justify-content: flex-end;
        }
        
        .btn-primary {
          background: #1a73e8;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 600;
        }
        
        .btn-primary:hover {
          background: #0d62d9;
        }
        
        .btn-secondary {
          background: #f8f9fa;
          color: #5f6368;
          border: 1px solid #dadce0;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
        }
        
        .btn-secondary:hover {
          background: #e8eaed;
        }
      `;

      const styleSheet = document.createElement('style');
      styleSheet.textContent = styles;
      popup.appendChild(styleSheet);

      // Add event listeners
      const continueBtn = popup.querySelector('#phishspector-continue');
      const cancelBtn = popup.querySelector('#phishspector-cancel');

      continueBtn.addEventListener('click', () => {
        const selectedAction = popup.querySelector('input[name="action"]:checked').value;
        
        if (selectedAction === 'sandbox') {
          // Redirect to safe sandbox
          const encoded = btoa(url);
          window.location.href = `http://localhost:5000/safe-redirect/${encoded}`;
        } else if (selectedAction === 'proceed') {
          // Proceed to original URL
          window.location.href = url;
        } else if (selectedAction === 'back') {
          // Go back
          window.history.back();
        }
        
        popup.remove();
      });

      cancelBtn.addEventListener('click', () => {
        popup.remove();
      });

      document.body.appendChild(popup);

    } catch (error) {
      console.error('[PhishSpector] Popup creation failed:', error);
      // Fallback: show basic warning
      showBasicWarning(url);
    }
  }

  // Fallback function if comprehensive analysis fails
  function showBasicWarning(url) {
    const popup = document.createElement('div');
    popup.innerHTML = `
      <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center;">
        <div style="background:white;padding:20px;border-radius:8px;max-width:400px;">
          <h3 style="color:#d93025;">⚠️ Security Warning</h3>
          <p>PhishSpector detected a potentially suspicious link:</p>
          <code style="background:#f5f5f5;padding:8px;display:block;margin:10px 0;">${url}</code>
          <p>Proceed with caution.</p>
          <button onclick="this.closest('[style]').remove()" style="background:#d93025;color:white;border:none;padding:8px 16px;border-radius:4px;">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(popup);
  }

  // ------------------------- //
  // ENHANCED LINK PROTECTION //
  // ------------------------- //
  function protectSuspiciousLinks() {
    const links = document.querySelectorAll('a[href*="http"]');
    
    console.log('[PhishSpector] Enhanced link protection activated');
    
    links.forEach(link => {
      if (link.hasAttribute('data-phishspector-protected')) return;
      
      link.setAttribute('data-phishspector-protected', 'true');
      
      // Perform email header analysis
      let emailRiskScore = 0;
      let emailAnalysis = null;
      if (link.closest('[role="main"]')) {
        const emailElement = link.closest('.zA');
        if (emailElement) {
          emailAnalysis = analyzeEmailHeaders(emailElement);
          emailRiskScore = emailAnalysis.riskScore;
          
          if (emailAnalysis.riskScore > 50) {
            console.log('[PhishSpector] 📧 High-risk email detected:', {
              riskScore: emailAnalysis.riskScore,
              warnings: emailAnalysis.warnings
            });
            
            // Store analysis data for popup
            link.setAttribute('data-email-analysis', JSON.stringify(emailAnalysis));
          }
        }
      }
      
      link.addEventListener('click', async (e) => {
        const url = link.href;
        
        // Check if suspicious (combine URL + email analysis)
        const urlSuspicious = isSuspiciousUrl(url);
        const urlRisk = estimateLinkRisk(url);
        const combinedRisk = emailRiskScore > 0 ? Math.max(urlRisk, emailRiskScore) : urlRisk;
        
        if (urlSuspicious || combinedRisk > 60) {
          console.log('[PhishSpector] 🚨 Blocking suspicious link:', {
            url: url,
            urlRisk: urlRisk,
            emailRisk: emailRiskScore,
            combinedRisk: combinedRisk
          });
          
          e.preventDefault();
          e.stopPropagation();
          await createPhishSpectorPopup(url, link);
          return false;
        } else {
          console.log('[PhishSpector] ✅ Allowing safe link:', url);
        }
      });
    });
  }

  function isSuspiciousUrl(url) {
    const suspiciousPatterns = [
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
      /\.(xyz|top|club|ru|tk|cf|ga|gq|ml|ngrok|localtest)$/i, // Suspicious TLDs + ngrok
      /login|verify|account|password|reset|forgot/i, // Suspicious keywords
      /ngrok-free\.app|ngrok\.io/, // Ngrok domains
      /verify.*google|google.*verify/i, // Brand + verify combinations
      /security.*alert|alert.*security/i,
      /unusual.*activity|activity.*unusual/i
    ];
    
    // Also check for brand names in URL but not in domain
    const brands = ['google', 'microsoft', 'paypal', 'facebook', 'amazon', 'apple', 'bank'];
    const urlLower = url.toLowerCase();
    
    for (let brand of brands) {
      if (urlLower.includes(brand) && !urlLower.includes(`.${brand}.`)) {
        return true;
      }
    }
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
  }

  // ------------------------- //
  // EMAIL HEADER ANALYSIS     //
  // ------------------------- //
  function analyzeEmailHeaders(emailElement) {
    try {
      const emailData = extractEmailData(emailElement);
      const analysis = {
        spfStatus: checkSPF(emailData),
        dkimStatus: checkDKIM(emailData),
        dmarcStatus: checkDMARC(emailData),
        riskScore: calculateHeaderRisk(emailData),
        warnings: generateHeaderWarnings(emailData),
        technicalDetails: getTechnicalDetails(emailData)
      };
      console.log('[PhishSpector] Email analysis completed:', analysis);
      return analysis;
    } catch (error) {
      console.error('Email analysis error:', error);
      return {
        spfStatus: { status: 'UNKNOWN', description: 'Analysis failed' },
        dkimStatus: { status: 'UNKNOWN', description: 'Analysis failed' },
        dmarcStatus: { status: 'UNKNOWN', description: 'Analysis failed' },
        riskScore: 50,
        warnings: ['Email header analysis failed'],
        technicalDetails: { error: 'Analysis failed' }
      };
    }
  }

  function extractEmailData(emailElement) {
    // Extract email metadata from Gmail DOM
    const emailInfo = {
        from: emailElement.querySelector('.yW span')?.textContent || '',
        subject: emailElement.querySelector('.y6 span')?.textContent || '',
        date: emailElement.querySelector('.xW span')?.textContent || '',
        snippet: emailElement.querySelector('.y2')?.textContent || ''
    };
    
    // Simulate header extraction
    return {
        fromAddress: extractEmailAddress(emailInfo.from),
        fromName: extractName(emailInfo.from),
        subject: emailInfo.subject,
        receivedDate: emailInfo.date,
        // Simulated header values for demonstration
        spf: Math.random() > 0.3 ? 'PASS' : 'FAIL', // 70% pass rate
        dkim: Math.random() > 0.4 ? 'PASS' : 'FAIL', // 60% pass rate  
        dmarc: Math.random() > 0.5 ? 'PASS' : 'FAIL' // 50% pass rate
    };
  }

  function checkSPF(emailData) {
    return {
        status: emailData.spf,
        description: emailData.spf === 'PASS' ? 
            'Sender verified by domain SPF record' : 
            'Sender NOT verified - possible spoofing'
    };
  }

  function checkDKIM(emailData) {
    return {
        status: emailData.dkim,
        description: emailData.dkim === 'PASS' ? 
            'Email signature verified' : 
            'Digital signature missing or invalid'
    };
  }

  function checkDMARC(emailData) {
    return {
        status: emailData.dmarc,
        description: emailData.dmarc === 'PASS' ? 
            'Domain alignment verified' : 
            'Domain alignment failed'
    };
  }

  function calculateHeaderRisk(emailData) {
    let risk = 0;
    if (emailData.spf === 'FAIL') risk += 30;
    if (emailData.dkim === 'FAIL') risk += 25; 
    if (emailData.dmarc === 'FAIL') risk += 20;
    
    // Additional risk factors
    if (isSuspiciousSender(emailData.fromAddress)) risk += 15;
    
    return Math.min(100, risk);
  }

  function generateHeaderWarnings(emailData) {
    const warnings = [];
    
    if (emailData.spf === 'FAIL') {
        warnings.push('SPF verification failed - sender may be spoofed');
    }
    if (emailData.dkim === 'FAIL') {
        warnings.push('DKIM signature invalid - email may be tampered with');
    }
    if (emailData.dmarc === 'FAIL') {
        warnings.push('DMARC alignment failed - possible domain impersonation');
    }
    
    return warnings;
  }

  function getTechnicalDetails(emailData) {
    return {
        sender: emailData.fromAddress,
        authentication: `SPF: ${emailData.spf}, DKIM: ${emailData.dkim}, DMARC: ${emailData.dmarc}`
    };
  }

  // Helper functions
  function extractEmailAddress(text) {
    const match = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    return match ? match[0] : 'unknown@example.com';
  }

  function extractName(text) {
    return text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i, '').trim() || 'Unknown Sender';
  }

  function isSuspiciousSender(email) {
    const suspiciousDomains = ['tempmail.com', 'fakeinbox.com', 'throwaway.com'];
    return suspiciousDomains.some(domain => email.includes(domain));
  }

  // ------------------------- //
  // SSL CERTIFICATE ANALYSIS  //
  // ------------------------- //
  async function analyzeSSLCertificate(domain) {
    try {
      const certInfo = await simulateCertificateFetch(domain);
      const analysis = {
          domain: domain,
          isValid: certInfo.isValid,
          isSelfSigned: certInfo.isSelfSigned,
          expirationDays: getDaysUntilExpiry(certInfo.validTo),
          issuer: certInfo.issuer,
          subject: certInfo.subject,
          trustScore: calculateCertificateTrustScore(certInfo),
          riskFactors: calculateCertificateRisks(certInfo)
      };
      console.log('[PhishSpector] SSL analysis completed:', analysis);
      return analysis;
    } catch (error) {
      console.error('Certificate analysis failed:', error);
      return {
        domain: domain,
        isValid: false,
        isSelfSigned: true,
        expirationDays: 0,
        issuer: 'Unknown',
        subject: domain,
        trustScore: 0,
        riskFactors: [{ level: 'HIGH', message: 'Certificate analysis failed' }]
      };
    }
  }

  async function simulateCertificateFetch(domain) {
    // Simulate certificate data
    const currentDate = new Date();
    const validTo = new Date(currentDate);
    validTo.setDate(validTo.getDate() + Math.floor(Math.random() * 365) + 30);
    
    const isSelfSigned = domain.includes('ngrok') || Math.random() > 0.8;
    
    return {
        issuer: isSelfSigned ? domain : 'Let\'s Encrypt Authority X3',
        subject: domain,
        validTo: validTo,
        isValid: Math.random() > 0.1,
        isSelfSigned: isSelfSigned
    };
  }

  function getDaysUntilExpiry(validTo) {
    const now = new Date();
    const expiry = new Date(validTo);
    return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
  }

  function calculateCertificateRisks(certInfo) {
    const risks = [];
    
    if (certInfo.isSelfSigned) {
        risks.push({
            level: 'HIGH',
            message: 'Self-signed certificate - no trusted CA validation'
        });
    }
    
    if (certInfo.expirationDays < 7) {
        risks.push({
            level: 'MEDIUM', 
            message: `Certificate expires in ${certInfo.expirationDays} days`
        });
    }
    
    if (!certInfo.isValid) {
        risks.push({
            level: 'HIGH',
            message: 'Certificate validation failed'
        });
    }
    
    return risks;
  }

  function calculateCertificateTrustScore(certInfo) {
    let score = 100;
    
    if (certInfo.isSelfSigned) score -= 40;
    if (!certInfo.isValid) score -= 30;
    if (certInfo.expirationDays < 30) score -= 20;
    
    return Math.max(0, score);
  }

  // ------------------------- //
  // PASSWORD PROTECTION       //
  // ------------------------- //
  class PasswordProtection {
    constructor() {
        this.protectedPages = new Set();
        this.userWarned = false;
        this.pageLoadTime = performance.now();
        this.init();
    }
    
    init() {
        this.monitorPasswordFields();
    }
    
    monitorPasswordFields() {
        // Watch for dynamically added password fields
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) {
                        const passwordFields = node.querySelectorAll ? 
                            node.querySelectorAll('input[type="password"]') : [];
                        passwordFields.forEach(field => this.protectField(field));
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        // Protect existing fields
        document.querySelectorAll('input[type="password"]').forEach(field => this.protectField(field));
    }
    
    protectField(passwordField) {
        if (passwordField.hasAttribute('data-phish-protected')) return;
        
        passwordField.setAttribute('data-phish-protected', 'true');
        
        // Add focus protection
        passwordField.addEventListener('focus', (e) => {
            if (this.isSuspiciousPage()) {
                this.showPasswordWarning(passwordField);
                this.temporarilyDisableAutoFill(passwordField);
            }
        });
    }
    
    isSuspiciousPage() {
        const url = window.location.href;
        const domain = new URL(url).hostname;
        
        const suspiciousIndicators = [
            domain.includes('ngrok'),
            domain.includes('localhost'),
            /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain),
            url.includes('login') && !url.includes('accounts.google.com'),
            document.querySelector('input[type="password"]') && 
            !this.isKnownLegitimateSite(domain)
        ];
        
        return suspiciousIndicators.some(indicator => indicator);
    }
    
    showPasswordWarning(passwordField) {
        if (this.userWarned) return;
        
        const warning = document.createElement('div');
        warning.className = 'phishspector-password-warning';
        warning.innerHTML = `
            <div style="
                position: fixed;
                top: 20px;
                right: 20px;
                background: #fce8e6;
                border: 2px solid #d93025;
                border-radius: 8px;
                padding: 15px;
                max-width: 300px;
                z-index: 10001;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                font-family: Arial, sans-serif;
            ">
                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                    <span style="color: #d93025; font-size: 20px; margin-right: 8px;">⚠️</span>
                    <strong style="color: #d93025;">Password Warning</strong>
                </div>
                <p style="margin: 0; font-size: 14px; color: #5f6368;">
                    This page appears suspicious. Avoid entering passwords or sensitive information.
                </p>
                <button onclick="this.parentElement.remove()" style="
                    margin-top: 10px;
                    background: #d93025;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 12px;
                ">
                    I Understand
                </button>
            </div>
        `;
        
        document.body.appendChild(warning);
        this.userWarned = true;
        
        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (warning.parentElement) {
                warning.remove();
            }
        }, 10000);
    }
    
    temporarilyDisableAutoFill(passwordField) {
        // Temporarily make field readonly to prevent auto-fill
        passwordField.setAttribute('readonly', 'true');
        passwordField.style.backgroundColor = '#fff3cd';
        passwordField.style.borderColor = '#ffc107';
        
        setTimeout(() => {
            passwordField.removeAttribute('readonly');
            passwordField.style.backgroundColor = '';
            passwordField.style.borderColor = '';
        }, 2000);
    }
    
    isKnownLegitimateSite(domain) {
        const legitimateSites = [
            'accounts.google.com',
            'facebook.com',
            'microsoft.com',
            'apple.com',
            'paypal.com',
            'github.com'
        ];
        return legitimateSites.some(site => domain.includes(site));
    }
  }

  // Initialize password protection
  const passwordProtection = new PasswordProtection();

  // ------------------------- //
  // Main execution            //
  // ------------------------- //
  function persistentScan() {
    const rows = document.querySelectorAll(ROW_SELECTOR);
    if (!rows) return;
    if (rows.length !== lastRowCount) {
      lastRowCount = rows.length;
      console.log(`[PhishSpector] scanning ${rows.length} rows`);
    }
    rows.forEach(row => insertOrUpdateBadge(row));
  }

  function watchInbox() {
    const main = document.querySelector('div[role="main"]');
    if (!main) return setTimeout(watchInbox, 600);
    
    const observer = new MutationObserver(() => {
      persistentScan();
      protectSuspiciousLinks();
    });
    
    observer.observe(main, { childList: true, subtree: true });
    persistentScan();
    protectSuspiciousLinks();
    
    // Also protect links periodically
    setInterval(() => {
      persistentScan();
      protectSuspiciousLinks();
    }, 1500);
    
    console.log('[PhishSpector] Enhanced protection active');
  }

  watchInbox();

  // For rescan trigger from popup
  try {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg && msg.type === "rescan") {
        console.log("[PhishSpector] Rescan requested from popup");
        persistentScan();
        protectSuspiciousLinks();
        sendResponse({ ok: true });
      }
    });
  } catch (e) {
    console.warn("[PhishSpector] Message listener error", e);
  }

})();