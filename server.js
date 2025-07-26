const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

const BASE_URL = process.env.PDF_BASE_URL || 'https://example.com/files/';
const BLOCKED_REG = process.env.BLOCKED_REG
  ? process.env.BLOCKED_REG.split(',').map(x => x.trim())
  : [];
// console.log(BLOCKED_REG);
const LOGIN_PASSWORD = process.env.AUTH_PASSWORD; // set this securely

// Approved device fingerprints (SHA-256 hashes)
const APPROVED_DEVICES = [
  // Paste approved fingerprints here
  '90076ff5db599e0eacaa9de79078f43700610e98f04ee6ea3a3eab29ddf41',
 '5099ed33efc3116f60a9f69b70799dfa9a2065e6e2b57012f2fca87dd0b71631', 'd94c9043d50f836ae67104ee7ca26ce387aee0a3c9224ff145d61a797ecccd98', 'dbd2a3233618d40255da395c6269f7b2500f2ea5ca1c7b73c3a7d4bea01aaae4',
 '31c1d872e2ef3230fa35026d8d437f7b75b5e93f9b41b6cbf78ed5061b16165f'
];

function createFingerprint(deviceInfo, headers) {
  const fingerprintSource = [
    deviceInfo.userAgent,
    deviceInfo.platform,
    deviceInfo.language,
    deviceInfo.screenWidth,
    deviceInfo.screenHeight,
    deviceInfo.hardwareConcurrency,
    headers['accept-language'],
    headers['accept-encoding'],
    headers['accept']
  ].join('|');

  return crypto.createHash('sha256').update(fingerprintSource).digest('hex');
}

// Auth route with fingerprint logging
app.post('/api/auth', (req, res) => {
 // console.log('📥 /api/auth body:', JSON.stringify(req.body));

  const { password, deviceInfo } = req.body;

  if (!deviceInfo) {
   console.log(`❌ Auth attempt missing deviceInfo at ${new Date().toISOString()}`);
    return res.status(400).json({ success: false, message: 'Missing device info' });
    
  }

  const fingerprint = createFingerprint(deviceInfo, req.headers);
  // console.log(deviceInfo);
 // console.log(`🔐 Auth attempt fingerprint: ${fingerprint} at ${new Date().toISOString()}`);
  
  // ✳️ TEMPORARY: Enable this block to add fingerprints dynamically
   if (!APPROVED_DEVICES.includes(fingerprint)) {
    APPROVED_DEVICES.push(fingerprint);
  } 

  if (!APPROVED_DEVICES.includes(fingerprint))  {
    console.log(`❌ Unauthorized fingerprint at login: ${fingerprint}`)
    
    
    return res.status(403).json({ success: false, message: 'Device not authorized' });
  }

  if (password === LOGIN_PASSWORD) {
    return res.json({ success: true });
  } else {
    return res.json({ success: false, message: 'Incorrect password' });
  }
});

// PDF access route
app.get('/view', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/08913.html'));
});

// Back route that redirects user to homepage or form
app.get('/back', (req, res) => {
  res.redirect('/view');
});

app.post('/api/get-pdf', (req, res) => {
  // console.log('📥 /api/get-pdf body:', JSON.stringify(req.body));

  const { reg} = req.body;
  
  if (!reg) {
    return res.status(400).json({ error: true, message: 'No reg number provided' });
  }
if (reg.length > 9) {
    return res.status(403).send("reg too long. Max 10 characters allowed.");
}
  if (BLOCKED_REG.includes(reg)) {
    return res.status(403).json({ error: true, message: 'Access denied for this reg number.' });
  }

  const fileURL = `${BASE_URL}${reg}`;
  const viewer = `https://docs.google.com/gview?embedded=true&chrome=false&url=${encodeURIComponent(fileURL)}`;


  res.json({ error: false, viewer });
});

// Serve index page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
