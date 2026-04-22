const https = require('https');
const crypto = require('crypto');

const INTEGRATION_KEY = 'fa2466a9-cb58-4909-8db8-4be8b67abd1f';
const OAUTH_BASE      = 'account-d.docusign.com';
const API_BASE        = 'demo.docusign.net';
const ACCOUNT_ID      = '22e8c703-228d-4b5c-bc80-98311e1d264b';

exports.handler = async (event) => {
  if(event.httpMethod === 'OPTIONS'){
    return { statusCode: 200, headers: corsHeaders(), body: '' };
  }
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, headers: corsHeaders(), body: 'Method Not Allowed' };
  }

  const USER_ID         = process.env.DOCUSIGN_USER_ID;
  const PRIVATE_KEY_RAW = process.env.DOCUSIGN_PRIVATE_KEY;

  if(!USER_ID || !PRIVATE_KEY_RAW){
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: 'Missing env vars' }),
    };
  }

  try{
    // Get JWT access token
    const token = await getJWTToken(USER_ID, PRIVATE_KEY_RAW);
    if(!token){
      return {
        statusCode: 401,
        headers: corsHeaders(),
        body: JSON.stringify({ error: 'Could not get access token' }),
      };
    }

    const body = JSON.parse(event.body || '{}');
    const action = body.action || 'token';

    // Just return the token if that's all that's needed
    if(action === 'token'){
      return {
        statusCode: 200,
        headers: corsHeaders(),
        body: JSON.stringify({ access_token: token, expires_in: 3600 }),
      };
    }

    // Create envelope
    if(action === 'createEnvelope'){
      const envResp = await apiRequest(
        'POST',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes`,
        token,
        body.envelope
      );
      return {
        statusCode: envResp.status,
        headers: corsHeaders(),
        body: JSON.stringify(envResp.data),
      };
    }

    // Get recipient view (embedded signing URL)
    if(action === 'recipientView'){
      const viewResp = await apiRequest(
        'POST',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes/${body.envelopeId}/views/recipient`,
        token,
        body.viewRequest
      );
      return {
        statusCode: viewResp.status,
        headers: corsHeaders(),
        body: JSON.stringify(viewResp.data),
      };
    }

    return {
      statusCode: 400,
      headers: corsHeaders(),
      body: JSON.stringify({ error: 'Unknown action' }),
    };

  } catch(err){
    console.error('Error:', err.message);
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: err.message }),
    };
  }
};

async function getJWTToken(userId, privateKeyRaw){
  // Clean up key
  let cleanKey = privateKeyRaw
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim();

  if(!cleanKey.includes('\n')){
    const begin = '-----BEGIN RSA PRIVATE KEY-----';
    const end   = '-----END RSA PRIVATE KEY-----';
    const b64   = cleanKey.replace(begin,'').replace(end,'').trim();
    const chunks = b64.match(/.{1,64}/g) || [];
    cleanKey = `${begin}\n${chunks.join('\n')}\n${end}`;
  }

  const now     = Math.floor(Date.now() / 1000);
  const header  = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({
    iss: INTEGRATION_KEY, sub: userId, aud: OAUTH_BASE,
    iat: now, exp: now + 3600, scope: 'signature',
  }));
  const sigInput = `${header}.${payload}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(sigInput);
  sign.end();
  const signature = sign.sign({ key: cleanKey, format: 'pem' }, 'base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

  const jwt = `${sigInput}.${signature}`;
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;

  const resp = await postReq(OAUTH_BASE, '/oauth/token', body);

  if(resp.data.error === 'consent_required'){
    console.log('Consent required');
    return null;
  }

  return resp.data.access_token || null;
}

function apiRequest(method, path, token, body){
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const req = https.request({
      hostname: API_BASE, path, method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try{ resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e){ resolve({ status: res.statusCode, data: { raw: data } }); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

function postReq(host, path, body){
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host, path, method: 'POST',
      headers: {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try{ resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e){ resolve({ status: res.statusCode, data: { raw: data } }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function b64url(str){
  return Buffer.from(str).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function corsHeaders(){
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };
}
