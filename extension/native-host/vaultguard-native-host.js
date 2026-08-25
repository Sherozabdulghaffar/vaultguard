// VaultGuard Native Messaging Host
// Bridges Chrome/Edge native messaging to the VaultGuard desktop app via IPC

const net = require('net');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Pipe for Chrome native messaging (32-bit length prefix + JSON)
const STDIN = process.stdin;
const STDOUT = process.stdout;

// Try to connect to the VaultGuard desktop app's IPC server
const IPC_PIPE_NAME = '\\\\.\\pipe\\vaultguard-ipc';
let desktopConnection = null;
let pendingMessages = [];

function logToStderr(msg) {
  // Native messaging uses stdout for data, stderr for logging
  process.stderr.write(`[VaultGuard Host] ${msg}\n`);
}

// Handle process termination gracefully
process.on('SIGTERM', () => {
  logToStderr('Received SIGTERM, shutting down...');
  if (desktopConnection) desktopConnection.destroy();
  process.exit(0);
});

process.on('SIGINT', () => {
  logToStderr('Received SIGINT, shutting down...');
  if (desktopConnection) desktopConnection.destroy();
  process.exit(0);
});

// Read message from Chrome (32-bit length prefix + JSON)
function readMessage(callback) {
  const header = Buffer.alloc(4);
  let headerBytesRead = 0;

  function readHeader() {
    STDIN.read(header.length - headerBytesRead, (err, data) => {
      if (err) {
        logToStderr(`Read error: ${err.message}`);
        process.exit(1);
      }
      if (data === null) {
        // EOF - Chrome closed the pipe
        process.exit(0);
      }
      data.copy(header, headerBytesRead);
      headerBytesRead += data.length;
      if (headerBytesRead < 4) {
        readHeader();
      } else {
        const messageLength = header.readUInt32LE(0);
        readBody(messageLength, callback);
      }
    });
  }

  function readBody(length, callback) {
    const body = Buffer.alloc(length);
    let bodyBytesRead = 0;

    function readChunk() {
      STDIN.read(length - bodyBytesRead, (err, data) => {
        if (err) {
          logToStderr(`Body read error: ${err.message}`);
          process.exit(1);
        }
        if (data === null) {
          process.exit(0);
        }
        data.copy(body, bodyBytesRead);
        bodyBytesRead += data.length;
        if (bodyBytesRead < length) {
          readChunk();
        } else {
          try {
            const message = JSON.parse(body.toString('utf-8'));
            callback(message);
          } catch (e) {
            logToStderr(`JSON parse error: ${e.message}`);
            callback({ type: 'ERROR', error: 'Invalid JSON' });
          }
        }
      });
    }

    readChunk();
  }

  readHeader();
}

// Send message to Chrome (32-bit length prefix + JSON)
function sendMessage(message) {
  const json = JSON.stringify(message);
  const buffer = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(buffer.length, 0);

  try {
    STDOUT.write(header);
    STDOUT.write(buffer);
  } catch (e) {
    logToStderr(`Write error: ${e.message}`);
  }
}

// Connect to VaultGuard desktop app via named pipe IPC
function connectToDesktop() {
  return new Promise((resolve, reject) => {
    desktopConnection = net.createConnection(IPC_PIPE_NAME, () => {
      logToStderr('Connected to VaultGuard desktop app');
      resolve(desktopConnection);
    });

    desktopConnection.on('error', (err) => {
      logToStderr(`Desktop connection error: ${err.message}`);
      desktopConnection = null;
      reject(err);
    });

    desktopConnection.on('close', () => {
      logToStderr('Desktop connection closed');
      desktopConnection = null;
    });

    // Handle responses from desktop app
    let responseBuffer = '';
    desktopConnection.on('data', (data) => {
      responseBuffer += data.toString('utf-8');

      // Try to parse complete JSON messages (newline-delimited)
      const lines = responseBuffer.split('\n');
      responseBuffer = lines.pop(); // Keep incomplete line in buffer

      for (const line of lines) {
        if (line.trim()) {
          try {
            const response = JSON.parse(line);
            handleDesktopResponse(response);
          } catch (e) {
            logToStderr(`Desktop response parse error: ${e.message}`);
          }
        }
      }
    });
  });
}

// Forward message to desktop app
function sendToDesktop(message) {
  return new Promise((resolve, reject) => {
    if (!desktopConnection) {
      reject(new Error('Not connected to desktop app'));
      return;
    }

    const requestId = message.requestId || `host_${Date.now()}`;
    message.requestId = requestId;

    // Store pending request
    pendingMessages.push({ requestId, resolve, reject, timestamp: Date.now() });

    // Send to desktop (newline-delimited JSON)
    const json = JSON.stringify(message) + '\n';
    desktopConnection.write(json);

    // Timeout after 30 seconds
    setTimeout(() => {
      const idx = pendingMessages.findIndex(m => m.requestId === requestId);
      if (idx !== -1) {
        pendingMessages.splice(idx, 1);
        reject(new Error('Request timeout'));
      }
    }, 30000);
  });
}

// Handle response from desktop app
function handleDesktopResponse(response) {
  const requestId = response.requestId;
  if (!requestId) return;

  const pending = pendingMessages.find(m => m.requestId === requestId);
  if (pending) {
    pending.resolve(response);
    pendingMessages = pendingMessages.filter(m => m.requestId !== requestId);
  }
}

// Main message loop
async function main() {
  // Try to connect to desktop app
  try {
    await connectToDesktop();
  } catch (err) {
    logToStderr('Failed to connect to desktop app. Extension will work in limited mode.');
    // Continue anyway - we can still report errors to Chrome
  }

  // Read messages from Chrome
  function processNextMessage() {
    readMessage(async (message) => {
      try {
        let response;

        if (desktopConnection) {
          // Forward to desktop app
          const result = await sendToDesktop(message);
          response = { requestId: message.requestId, payload: result };
        } else {
          // Desktop not connected
          response = {
            requestId: message.requestId,
            type: 'ERROR',
            error: 'VaultGuard desktop app is not running',
          };
        }

        sendMessage(response);
      } catch (err) {
        sendMessage({
          requestId: message.requestId,
          type: 'ERROR',
          error: err.message,
        });
      }

      // Process next message
      processNextMessage();
    });
  }

  processNextMessage();
}

main();
