// ============================================
// VaultGuard Content Script - Auto-fill Engine
// Fills password and TOTP fields automatically
// ============================================

(function () {
  'use strict';

  if (window.__vaultguard_autofill_loaded) return;
  window.__vaultguard_autofill_loaded = true;

  // Helper: escape HTML
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ============================================
  // Auto-fill Functions
  // ============================================

  function setInputValue(input, value) {
    // Focus the input
    input.focus();
    input.click();

    // Clear existing value
    input.value = '';

    // Use native input setter to bypass framework wrappers
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      'value'
    ).set;

    nativeInputValueSetter.call(input, value);

    // Dispatch events to trigger framework state updates (React, Vue, Angular)
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));

    // Add visual feedback
    highlightField(input);
  }

  function highlightField(input) {
    const originalBorder = input.style.border;
    const originalBoxShadow = input.style.boxShadow;
    const originalTransition = input.style.transition;

    input.style.transition = 'all 0.3s ease';
    input.style.border = '2px solid #7c5cff';
    input.style.boxShadow = '0 0 0 3px rgba(124, 92, 255, 0.2)';

    setTimeout(() => {
      input.style.border = originalBorder;
      input.style.boxShadow = originalBoxShadow;
      setTimeout(() => {
        input.style.transition = originalTransition;
      }, 300);
    }, 1500);
  }

  function findFieldByType(type) {
    const patterns = {
      username: [
        'input[type="text"][name*="user"]',
        'input[type="text"][name*="email"]',
        'input[type="text"][name*="login"]',
        'input[type="text"][name*="account"]',
        'input[type="email"]',
        'input[type="tel"]',
        'input[name="username"]',
        'input[name="email"]',
        'input[id*="user"]',
        'input[id*="email"]',
        'input[id*="login"]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
      ],
      password: [
        'input[type="password"]',
        'input[name="password"]',
        'input[name="pass"]',
        'input[id*="pass"]',
        'input[autocomplete="current-password"]',
      ],
      totp: [
        'input[name*="otp"]',
        'input[name*="2fa"]',
        'input[name*="code"]',
        'input[name*="token"]',
        'input[id*="otp"]',
        'input[id*="2fa"]',
        'input[id*="code"]',
        'input[autocomplete="one-time-code"]',
        'input[inputmode="numeric"]',
        'input[maxlength="6"]',
        'input[maxlength="8"]',
        'input[name*="mfa"]',
        'input[name*="auth"]',
        'input[name*="verif"]',
        'input[id*="mfa"]',
        'input[id*="auth"]',
        'input[id*="verif"]',
        'input[name*="pin"]',
        'input[id*="pin"]',
        'input[autocomplete="one-time-password"]',
      ],
    };

    const selectors = patterns[type] || [];
    for (const selector of selectors) {
      try {
        const field = document.querySelector(selector);
        if (field && field.offsetParent !== null) {
          return field;
        }
      } catch (e) {
        // Invalid selector, skip
      }
    }

    return null;
  }

  // ============================================
  // Auto-fill Credentials
  // ============================================

  function autoFillCredentials(data) {
    const { username, password } = data;

    if (username) {
      const usernameField = findFieldByType('username');
      if (usernameField) {
        setInputValue(usernameField, username);
      }
    }

    // Small delay for password field (some forms have animations)
    setTimeout(() => {
      if (password) {
        const passwordField = findFieldByType('password');
        if (passwordField) {
          setInputValue(passwordField, password);
        }
      }
    }, 100);
  }

  // ============================================
  // Auto-fill TOTP Code
  // ============================================

  function autoFillTotp(code) {
    // Try single field first
    const totpField = findFieldByType('totp');
    if (totpField) {
      setInputValue(totpField, code);
      highlightField(totpField);
      return;
    }

    // Handle split fields (e.g., 6 separate input boxes for each digit)
    const splitFields = document.querySelectorAll(
      'input[maxlength="1"][inputmode="numeric"], ' +
      'input[maxlength="1"][type="text"], ' +
      'input[data-digit], input[class*="digit"], input[id*="digit"]'
    );
    if (splitFields.length >= 4) {
      const digits = code.split('');
      splitFields.forEach((field, index) => {
        if (digits[index]) {
          setInputValue(field, digits[index]);
          highlightField(field);
        }
      });
      return;
    }

    // Handle common 2FA grid patterns
    const gridFields = document.querySelectorAll(
      'input[maxlength="2"], input[maxlength="3"]'
    );
    if (gridFields.length >= 2) {
      // Distribute code across grid fields
      const chunkSize = Math.ceil(code.length / gridFields.length);
      let codeIndex = 0;
      gridFields.forEach(field => {
        const chunk = code.slice(codeIndex, codeIndex + chunkSize);
        if (chunk) {
          setInputValue(field, chunk);
          highlightField(field);
          codeIndex += chunkSize;
        }
      });
    }
  }

  // ============================================
  // Floating Action Button
  // ============================================

  function createFloatingButton() {
    if (document.getElementById('vaultguard-fab')) return;

    const fab = document.createElement('div');
    fab.id = 'vaultguard-fab';
    fab.innerHTML = `
      <div id="vaultguard-fab-button" title="VaultGuard - Click to fill">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <div id="vaultguard-fab-menu" class="vaultguard-hidden">
        <div class="vaultguard-menu-item" data-action="fill-username">Fill Username</div>
        <div class="vaultguard-menu-item" data-action="fill-password">Fill Password</div>
        <div class="vaultguard-menu-item" data-action="fill-2fa">Fill 2FA Code</div>
        <div class="vaultguard-menu-separator"></div>
        <div class="vaultguard-menu-item vaultguard-menu-item-secondary" data-action="open-vault">Open VaultGuard</div>
      </div>
    `;

    document.body.appendChild(fab);

    // Add styles
    const style = document.createElement('style');
    style.textContent = `
      #vaultguard-fab {
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }

      #vaultguard-fab-button {
        width: 48px;
        height: 48px;
        border-radius: 50%;
        background: linear-gradient(135deg, #7c5cff 0%, #5f28e3 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        box-shadow: 0 4px 20px rgba(124, 92, 255, 0.4);
        transition: all 0.2s ease;
      }

      #vaultguard-fab-button:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 28px rgba(124, 92, 255, 0.5);
      }

      #vaultguard-fab-menu {
        position: absolute;
        bottom: 60px;
        right: 0;
        background: #1a1b2e;
        border: 1px solid rgba(124, 92, 255, 0.2);
        border-radius: 12px;
        padding: 8px;
        min-width: 180px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      }

      #vaultguard-fab-menu.vaultguard-hidden {
        display: none;
      }

      .vaultguard-menu-item {
        padding: 10px 14px;
        color: #e5e7eb;
        font-size: 13px;
        cursor: pointer;
        border-radius: 8px;
        transition: all 0.15s ease;
      }

      .vaultguard-menu-item:hover {
        background: rgba(124, 92, 255, 0.15);
        color: #b2abff;
      }

      .vaultguard-menu-item-secondary {
        color: #9ca3af;
        font-size: 12px;
      }

      .vaultguard-menu-separator {
        height: 1px;
        background: rgba(124, 92, 255, 0.1);
        margin: 4px 8px;
      }
    `;
    document.head.appendChild(style);

    // Event handlers
    const button = document.getElementById('vaultguard-fab-button');
    const menu = document.getElementById('vaultguard-fab-menu');

    button.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.toggle('vaultguard-hidden');
    });

    document.addEventListener('click', () => {
      menu.classList.add('vaultguard-hidden');
    });

    menu.querySelectorAll('.vaultguard-menu-item').forEach((item) => {
      item.addEventListener('click', async (e) => {
        e.stopPropagation();
        const action = item.dataset.action;

        if (action === 'open-vault') {
          chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
        } else {
          // Request entries from background
          const response = await chrome.runtime.sendMessage({
            type: 'GET_ENTRIES_FOR_URL',
            url: window.location.href,
          });

          if (response?.passwords?.length > 0) {
            const entry = response.passwords[0];
            if (action === 'fill-username') {
              setInputValue(findFieldByType('username'), entry.username);
            } else if (action === 'fill-password') {
              setInputValue(findFieldByType('password'), entry.password);
            }
          }

          if (action === 'fill-2fa' && response?.totpEntries?.length > 0) {
            const totpResponse = await chrome.runtime.sendMessage({
              type: 'GENERATE_TOTP',
              secret: response.totpEntries[0].secret,
              options: {
                algorithm: response.totpEntries[0].algorithm,
                digits: response.totpEntries[0].digits,
                period: response.totpEntries[0].period,
              },
            });

            if (totpResponse?.code) {
              autoFillTotp(totpResponse.code);
            }
          }
        }

        menu.classList.add('vaultguard-hidden');
      });
    });
  }

  // ============================================
  // 2FA Auto-fill Notification Banner
  // ============================================

  function show2FANotification(issuer, code, period) {
    // Remove existing notification
    const existing = document.getElementById('vaultguard-2fa-notification');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'vaultguard-2fa-notification';
    banner.innerHTML = `
      <div class="vg-2fa-inner">
        <div class="vg-2fa-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10" stroke="white" stroke-width="2"/>
          </svg>
        </div>
        <div class="vg-2fa-text">
          <span class="vg-2fa-issuer">${escapeHtml(issuer)}</span>
          <span class="vg-2fa-code">${code}</span>
        </div>
        <div class="vg-2fa-timer">
          <svg class="vg-2fa-countdown" width="24" height="24" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10" fill="none" stroke="rgba(255,255,255,0.2)" stroke-width="2"/>
            <circle cx="12" cy="12" r="10" fill="none" stroke="#7c5cff" stroke-width="2" stroke-dasharray="62.83" stroke-dashoffset="0" stroke-linecap="round" transform="rotate(-90 12 12)" class="vg-2fa-progress"/>
          </svg>
          <span class="vg-2fa-seconds">${period || 30}</span>
        </div>
        <button class="vg-2fa-close" title="Dismiss">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
    `;

    const style = document.createElement('style');
    style.textContent = `
      #vaultguard-2fa-notification {
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: vg-slide-in 0.3s ease-out;
      }

      @keyframes vg-slide-in {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }

      .vg-2fa-inner {
        display: flex;
        align-items: center;
        gap: 10px;
        background: linear-gradient(135deg, #1a1b2e 0%, #252642 100%);
        border: 1px solid rgba(124, 92, 255, 0.3);
        border-radius: 12px;
        padding: 10px 14px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(124, 92, 255, 0.1);
        min-width: 260px;
      }

      .vg-2fa-icon {
        width: 32px;
        height: 32px;
        border-radius: 8px;
        background: linear-gradient(135deg, #7c5cff 0%, #5f28e3 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }

      .vg-2fa-text {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
      }

      .vg-2fa-issuer {
        font-size: 11px;
        color: #9ca3af;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .vg-2fa-code {
        font-size: 20px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: 3px;
        font-variant-numeric: tabular-nums;
      }

      .vg-2fa-timer {
        position: relative;
        width: 36px;
        height: 36px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }

      .vg-2fa-countdown {
        position: absolute;
      }

      .vg-2fa-seconds {
        font-size: 10px;
        color: #e5e7eb;
        font-weight: 600;
        z-index: 1;
      }

      .vg-2fa-progress {
        transition: stroke-dashoffset 1s linear;
      }

      .vg-2fa-close {
        background: none;
        border: none;
        color: #6b7280;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.15s ease;
        flex-shrink: 0;
      }

      .vg-2fa-close:hover {
        background: rgba(255, 255, 255, 0.1);
        color: #e5e7eb;
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(banner);

    // Close button
    banner.querySelector('.vg-2fa-close').addEventListener('click', () => {
      banner.style.animation = 'vg-slide-out 0.3s ease-in forwards';
      setTimeout(() => banner.remove(), 300);
    });

    // Auto-dismiss after 1.5x the TOTP period
    const totalSeconds = period || 30;
    const dismissTime = totalSeconds * 1500;
    setTimeout(() => {
      if (banner.parentElement) {
        banner.style.animation = 'vg-slide-out 0.3s ease-in forwards';
        setTimeout(() => banner.remove(), 300);
      }
    }, dismissTime);

    // Countdown timer
    let remaining = totalSeconds;
    const progressCircle = banner.querySelector('.vg-2fa-progress');
    const secondsText = banner.querySelector('.vg-2fa-seconds');
    const circumference = 2 * Math.PI * 10; // r=10

    const timer = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(timer);
        return;
      }
      secondsText.textContent = remaining;
      const offset = circumference * (1 - remaining / totalSeconds);
      progressCircle.style.strokeDashoffset = offset;
    }, 1000);
  }

  // ============================================
  // Message Handling
  // ============================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
      case 'DO_AUTO_FILL':
        autoFillCredentials(message.data);
        sendResponse({ success: true });
        break;

      case 'DO_AUTO_FILL_TOTP':
        autoFillTotp(message.code);
        sendResponse({ success: true });
        break;

      case 'SHOW_2FA_NOTIFICATION':
        show2FANotification(message.issuer, message.code, message.period);
        sendResponse({ success: true });
        break;

      case 'SHOW_FLOATING_BUTTON':
        createFloatingButton();
        sendResponse({ success: true });
        break;
    }
    return true;
  });

  // ============================================
  // Initialize
  // ============================================

  // Show floating button if on a login page
  function checkAndShowButton() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      createFloatingButton();
    }
  }

  // Initial check
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(checkAndShowButton, 1000));
  } else {
    setTimeout(checkAndShowButton, 1000);
  }

  // Watch for dynamic password fields
  const observer = new MutationObserver(() => {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0 && !document.getElementById('vaultguard-fab')) {
      createFloatingButton();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  console.log('VaultGuard auto-fill engine loaded');
})();
