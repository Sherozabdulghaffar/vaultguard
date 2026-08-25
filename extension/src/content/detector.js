// ============================================
// VaultGuard Content Script - Field Detector
// Detects login forms and 2FA input fields
// ============================================

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__vaultguard_detector_loaded) return;
  window.__vaultguard_detector_loaded = true;

  // ============================================
  // Field Detection Patterns
  // ============================================

  const USERNAME_PATTERNS = [
    /user/i, /email/i, /login/i, /account/i, /name/i, /id/i,
    /phone/i, /mobile/i, /username/i, /usr/i, /signin/i,
  ];

  const PASSWORD_PATTERNS = [
    /pass/i, /pwd/i, /secret/i, /credential/i,
  ];

  const TOTP_PATTERNS = [
    /otp/i, /2fa/i, /two.?factor/i, /auth/i, /code/i,
    /token/i, /verif/i, /security.?code/i, /login.?code/i,
    /verification.?code/i, /one.?time/i, /totp/i,
    /mfa/i, /authenticator/i, /passcode/i, /pin/i,
  ];

  const EMAIL_PATTERNS = [/email/i, /mail/i, /e-mail/i];

  // ============================================
  // Field Analysis
  // ============================================

  function analyzeInputField(input) {
    const field = {
      type: 'text',
      selector: '',
      value: input.value || '',
      placeholder: input.placeholder || '',
      autocomplete: input.autocomplete || '',
      name: input.name || '',
      id: input.id || '',
      ariaLabel: input.getAttribute('aria-label') || '',
      labelText: '',
      isVisible: isVisible(input),
    };

    // Generate unique selector
    field.selector = generateSelector(input);

    // Get label text
    const label = findLabel(input);
    if (label) {
      field.labelText = label.textContent.trim();
    }

    // Determine field type based on multiple signals
    const signals = [
      field.name.toLowerCase(),
      field.id.toLowerCase(),
      field.placeholder.toLowerCase(),
      field.autocomplete.toLowerCase(),
      field.ariaLabel.toLowerCase(),
      field.labelText.toLowerCase(),
      input.type,
    ].join(' ');

    // Check for TOTP first (most specific)
    if (TOTP_PATTERNS.some(p => p.test(signals))) {
      field.type = 'totp';
    } else if (PASSWORD_PATTERNS.some(p => p.test(signals)) || input.type === 'password') {
      field.type = 'password';
    } else if (EMAIL_PATTERNS.some(p => p.test(signals)) || input.type === 'email') {
      field.type = 'email';
    } else if (USERNAME_PATTERNS.some(p => p.test(signals))) {
      field.type = 'username';
    } else if (input.type === 'text' || input.type === 'tel') {
      // Could be username or TOTP - use heuristics
      if (input.maxLength === 6 || input.maxLength === 8) {
        field.type = 'totp';
      } else {
        field.type = 'text';
      }
    }

    return field;
  }

  function findLabel(input) {
    // Check for explicit label
    if (input.id) {
      const label = document.querySelector(`label[for="${input.id}"]`);
      if (label) return label;
    }

    // Check for wrapping label
    let parent = input.parentElement;
    while (parent && parent !== document.body) {
      if (parent.tagName === 'LABEL') return parent;
      const label = parent.querySelector('label');
      if (label) return label;
      parent = parent.parentElement;
    }

    // Check for aria-labelledby
    const labelledBy = input.getAttribute('aria-labelledby');
    if (labelledBy) {
      const labelEl = document.getElementById(labelledBy);
      if (labelEl) return labelEl;
    }

    return null;
  }

  function generateSelector(input) {
    if (input.id) {
      return `#${CSS.escape(input.id)}`;
    }

    if (input.name) {
      const escaped = CSS.escape(input.name);
      return `input[name="${escaped}"]`;
    }

    // Generate path-based selector
    const path = [];
    let current = input;
    while (current && current !== document.body) {
      let selector = current.tagName.toLowerCase();
      if (current.id) {
        selector = `#${CSS.escape(current.id)}`;
        path.unshift(selector);
        break;
      }
      if (current.className && typeof current.className === 'string') {
        const classes = current.className.trim().split(/\s+/).slice(0, 2);
        if (classes.length) {
          selector += '.' + classes.map(c => CSS.escape(c)).join('.');
        }
      }
      path.unshift(selector);
      current = current.parentElement;
    }

    return path.join(' > ');
  }

  function isVisible(element) {
    const style = window.getComputedStyle(element);
    return (
      style.display !== 'none' &&
      style.visibility !== 'hidden' &&
      style.opacity !== '0' &&
      element.offsetWidth > 0 &&
      element.offsetHeight > 0
    );
  }

  // ============================================
  // Page Scanning
  // ============================================

  function scanPage() {
    const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
    const fields = [];

    inputs.forEach(input => {
      if (isVisible(input)) {
        fields.push(analyzeInputField(input));
      }
    });

    const hasLoginForm = fields.some(f => f.type === 'username' || f.type === 'email') &&
                        fields.some(f => f.type === 'password');

    const hasTotpField = fields.some(f => f.type === 'totp');

    return {
      url: window.location.href,
      title: document.title,
      fields,
      hasLoginForm,
      hasTotpField,
    };
  }

  // ============================================
  // Detect otpauth:// links and QR codes
  // ============================================

  function detectOtpauthLinks() {
    const results = [];

    // Check anchor elements
    const links = document.querySelectorAll('a[href^="otpauth://"], a[href*="otpauth://"]');
    links.forEach(link => {
      try {
        results.push({ href: link.href, text: link.textContent.trim() });
      } catch {}
    });

    // Check for otpauth URIs in visible text
    const allText = document.body?.innerText || '';
    const matches = allText.match(/otpauth:\/\/[^\s"']+/gi) || [];
    matches.forEach(m => {
      if (!results.find(r => r.href === m)) {
        results.push({ href: m, text: '' });
      }
    });

    return results;
  }

  function detectQRCodes() {
    // Look for QR code images on the page
    const qrSelectors = [
      'img[src*="qr"]',
      'img[src*="QR"]',
      'img[alt*="QR"]',
      'img[alt*="qr code"]',
      'img[alt*="QR code"]',
      'img[title*="QR"]',
      'img[data-qr]',
      'canvas[data-qr]',
      'img[src*="data:image"]',
      '[class*="qr"]',
      '[id*="qr"]',
    ];

    const qrElements = [];
    qrSelectors.forEach(selector => {
      try {
        document.querySelectorAll(selector).forEach(el => {
          if (isVisible(el) && !qrElements.includes(el)) {
            qrElements.push(el);
          }
        });
      } catch {}
    });

    return qrElements;
  }

  // ============================================
  // Message Handling
  // ============================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_PAGE') {
      const result = scanPage();
      const otpauthLinks = detectOtpauthLinks();
      const qrCodes = detectQRCodes();
      result.otpauthLinks = otpauthLinks;
      result.hasOtpauthLink = otpauthLinks.length > 0;
      result.hasQRCode = qrCodes.length > 0;
      result.qrCodeCount = qrCodes.length;
      sendResponse(result);
    }
    return true;
  });

  // ============================================
  // Auto-detect and notify background
  // ============================================

  function notifyBackground() {
    const scanResult = scanPage();
    const otpauthLinks = detectOtpauthLinks();
    const qrCodes = detectQRCodes();

    scanResult.otpauthLinks = otpauthLinks;
    scanResult.hasOtpauthLink = otpauthLinks.length > 0;
    scanResult.hasQRCode = qrCodes.length > 0;
    scanResult.qrCodeCount = qrCodes.length;

    if (scanResult.hasLoginForm || scanResult.hasTotpField || scanResult.hasOtpauthLink || scanResult.hasQRCode) {
      chrome.runtime.sendMessage({
        type: 'PAGE_DETECTED',
        data: scanResult,
      }).catch(() => {});
    }
  }

  // Run detection on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(notifyBackground, 500);
    });
  } else {
    setTimeout(notifyBackground, 500);
  }

  // Watch for dynamic form injection (SPAs)
  const observer = new MutationObserver((mutations) => {
    let shouldRescan = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        shouldRescan = true;
        break;
      }
    }
    if (shouldRescan) {
      setTimeout(notifyBackground, 300);
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  console.log('VaultGuard field detector loaded');
})();
