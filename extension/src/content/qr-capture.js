// ============================================
// VaultGuard - QR Code Screen Capture Content Script
// Matches Authenticator Extension pattern: gray overlay + selection box + QR decode
// ============================================

(function () {
  'use strict';

  if (window.__vaultguard_qr_capture_loaded) return;
  window.__vaultguard_qr_capture_loaded = true;

  let captureBox = null;
  let grayLayout = null;
  let qrCanvas = null;
  let startPos = { x: 0, y: 0 };

  // Pre-load jsQR library
  function ensureJsQR() {
    return new Promise((resolve) => {
      if (typeof jsQR !== 'undefined') {
        resolve(true);
        return;
      }
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('lib/jsqr.min.js');
      script.onload = () => resolve(true);
      script.onerror = () => resolve(false);
      (document.head || document.documentElement).appendChild(script);
      // Timeout after 3 seconds
      setTimeout(() => resolve(typeof jsQR !== 'undefined'), 3000);
    });
  }

  // Listen for messages from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
      case 'capture':
        sendResponse('beginCapture');
        showGrayLayout();
        break;
      case 'sendCaptureUrl':
        ensureJsQR().then((ready) => {
          if (ready) {
            qrDecode(
              message.info.url,
              message.info.captureBoxLeft,
              message.info.captureBoxTop,
              message.info.captureBoxWidth,
              message.info.captureBoxHeight
            );
          } else {
            showNotification('QR library failed to load. Try again.', 'error');
          }
        });
        break;
      case 'errorqr':
        hideGrayLayout();
        showNotification('Could not read QR code', 'error');
        break;
      case 'errorsecret':
        hideGrayLayout();
        showNotification('Invalid secret: ' + message.secret, 'error');
        break;
      case 'errorenc':
        hideGrayLayout();
        showNotification('Incorrect passphrase', 'error');
        break;
      case 'added':
        hideGrayLayout();
        showNotification(message.account + ' added!', 'success');
        break;
      case 'text':
        hideGrayLayout();
        showNotification(message.text, 'info');
        break;
      case 'stopCapture':
        hideGrayLayout();
        break;
      default:
        break;
    }
    return true;
  });

  function showGrayLayout() {
    if (!grayLayout) {
      // Create canvas for QR decoding
      qrCanvas = document.createElement('canvas');
      qrCanvas.id = '__vg_qrCanvas__';
      qrCanvas.style.display = 'none';
      document.body.appendChild(qrCanvas);

      // Create gray overlay
      grayLayout = document.createElement('div');
      grayLayout.id = '__vg_grayLayout__';
      grayLayout.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        z-index: 2147483647;
        cursor: crosshair;
      `;
      document.body.appendChild(grayLayout);

      // Create scan animation
      const scan = document.createElement('div');
      scan.id = '__vg_scan__';
      scan.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 200px;
        height: 200px;
        border: 2px solid #7c5cff;
        border-radius: 12px;
        pointer-events: none;
        animation: vg-pulse 2s ease-in-out infinite;
      `;

      // Add scan line animation
      const scanLine = document.createElement('div');
      scanLine.style.cssText = `
        position: absolute;
        left: 10px;
        right: 10px;
        height: 2px;
        background: linear-gradient(90deg, transparent, #7c5cff, transparent);
        animation: vg-scanline 2s linear infinite;
      `;
      scan.appendChild(scanLine);

      // Add instructions text
      const instructions = document.createElement('div');
      instructions.style.cssText = `
        position: fixed;
        top: calc(50% + 120px);
        left: 50%;
        transform: translateX(-50%);
        color: white;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        text-align: center;
        pointer-events: none;
        text-shadow: 0 1px 3px rgba(0,0,0,0.5);
      `;
      instructions.textContent = 'Draw a box around the QR code';

      // Add escape hint
      const hint = document.createElement('div');
      hint.style.cssText = `
        position: fixed;
        bottom: 20px;
        left: 50%;
        transform: translateX(-50%);
        color: rgba(255,255,255,0.7);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 12px;
        pointer-events: none;
      `;
      hint.textContent = 'Press Escape to cancel';

      // Add styles
      const style = document.createElement('style');
      style.textContent = `
        @keyframes vg-pulse {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 1; }
        }
        @keyframes vg-scanline {
          0% { top: 10px; }
          50% { top: calc(100% - 12px); }
          100% { top: 10px; }
        }
      `;
      document.head.appendChild(style);

      // Create capture box
      captureBox = document.createElement('div');
      captureBox.id = '__vg_captureBox__';
      captureBox.style.cssText = `
        position: fixed;
        display: none;
        border: 2px solid #7c5cff;
        background: rgba(124, 92, 255, 0.1);
        z-index: 2147483648;
        pointer-events: none;
      `;

      grayLayout.appendChild(scan);
      grayLayout.appendChild(instructions);
      grayLayout.appendChild(hint);
      grayLayout.appendChild(captureBox);

      // Mouse events
      grayLayout.addEventListener('mousedown', onGrayLayoutDown);
      grayLayout.addEventListener('mousemove', onGrayLayoutMove);
      grayLayout.addEventListener('mouseup', onGrayLayoutUp);
      grayLayout.addEventListener('contextmenu', (e) => e.preventDefault());
    }

    grayLayout.style.display = 'block';
  }

  function hideGrayLayout() {
    if (grayLayout) {
      grayLayout.style.display = 'none';
    }
    if (captureBox) {
      captureBox.style.display = 'none';
    }
  }

  function onGrayLayoutDown(event) {
    if (event.button !== 0) return;

    startPos = { x: event.clientX, y: event.clientY };
    captureBox.style.left = event.clientX + 'px';
    captureBox.style.top = event.clientY + 'px';
    captureBox.style.width = '1px';
    captureBox.style.height = '1px';
    captureBox.style.display = 'block';

    // Hide scan animation
    const scan = document.getElementById('__vg_scan__');
    if (scan) scan.style.display = 'none';
  }

  function onGrayLayoutMove(event) {
    if (event.buttons !== 1) return;

    const left = Math.min(startPos.x, event.clientX);
    const top = Math.min(startPos.y, event.clientY);
    const width = Math.abs(startPos.x - event.clientX);
    const height = Math.abs(startPos.y - event.clientY);

    captureBox.style.left = left + 'px';
    captureBox.style.top = top + 'px';
    captureBox.style.width = width + 'px';
    captureBox.style.height = height + 'px';
  }

  function onGrayLayoutUp(event) {
    if (event.button !== 0) return;

    const boxLeft = Math.min(startPos.x, event.clientX) + 1;
    const boxTop = Math.min(startPos.y, event.clientY) + 1;
    const boxWidth = Math.abs(startPos.x - event.clientX) - 1;
    const boxHeight = Math.abs(startPos.y - event.clientY) - 1;

    // Minimum box size
    if (boxWidth < 10 || boxHeight < 10) {
      hideGrayLayout();
      return;
    }

    // Hide overlay
    setTimeout(() => {
      grayLayout.style.display = 'none';
      captureBox.style.display = 'none';
    }, 100);

    // Request screen capture from background
    setTimeout(() => {
      chrome.runtime.sendMessage({
        action: 'getCapture',
        info: {
          captureBoxLeft: boxLeft,
          captureBoxTop: boxTop,
          captureBoxWidth: boxWidth,
          captureBoxHeight: boxHeight,
        },
      });
    }, 200);
  }

  async function qrDecode(url, left, top, width, height) {
    if (!qrCanvas) {
      qrCanvas = document.createElement('canvas');
    }

    const qr = new Image();
    qr.onload = () => {
      const devicePixelRatio = qr.width / window.innerWidth;
      qrCanvas.width = qr.width;
      qrCanvas.height = qr.height;
      const ctx = qrCanvas.getContext('2d');
      ctx.drawImage(qr, 0, 0);

      const imageData = ctx.getImageData(
        left * devicePixelRatio,
        top * devicePixelRatio,
        width * devicePixelRatio,
        height * devicePixelRatio
      );

      if (imageData) {
        qrCanvas.width = imageData.width;
        qrCanvas.height = imageData.height;
        ctx.putImageData(imageData, 0, 0);

        // Try jsQR first
        if (typeof jsQR !== 'undefined') {
          const jsQrCode = jsQR(imageData.data, imageData.width, imageData.height);
          if (jsQrCode) {
            chrome.runtime.sendMessage({
              action: 'getTotp',
              info: jsQrCode.data,
            });
            return;
          }
        }

        // Fallback: try decoding from the full captured area
        const fullImageData = ctx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
        if (typeof jsQR !== 'undefined') {
          const jsQrCode = jsQR(fullImageData.data, fullImageData.width, fullImageData.height);
          if (jsQrCode) {
            chrome.runtime.sendMessage({
              action: 'getTotp',
              info: jsQrCode.data,
            });
            return;
          }
        }

        showNotification('Could not read QR code. Try again.', 'error');
      }
    };
    qr.src = url;
  }

  function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      z-index: 2147483647;
      animation: vg-notif-in 0.3s ease-out;
      color: white;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;

    const colors = {
      success: '#22c55e',
      error: '#ef4444',
      info: '#7c5cff',
    };
    notification.style.background = colors[type] || colors.info;
    notification.textContent = message;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes vg-notif-in {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);

    document.body.appendChild(notification);
    setTimeout(() => {
      notification.style.animation = 'vg-notif-in 0.3s ease-in reverse';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }

  // Escape key to cancel
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      hideGrayLayout();
    }
  });

  console.log('VaultGuard QR capture loaded');
})();
