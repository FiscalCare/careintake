const https = require('https');
const crypto = require('crypto');

exports.handler = async (event) => {
  if(event.httpMethod === 'OPTIONS'){
    return { statusCode: 200, headers: corsHeaders(), body: '' };
  }
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, headers: corsHeaders(), body: 'Method Not Allowed' };
  }

  const INTEGRATION_KEY = 'fa2466a9-cb58-4909-8db8-4be8b67abd1f';
  const USER_ID         = process.env.DOCUSIGN_USER_ID;
  const PRIVATE_KEY_RAW = process.env.DOCUSIGN_PRIVATE_KEY;
  const OAUTH_BASE      = 'account-d.docusign.com';

  if(!USER_ID || !PRIVATE_KEY_RAW){
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: 'Missing DOCUSIGN_USER_ID or DOCUSIGN_PRIVATE_KEY' }),
    };
  }

  try{
    // Clean up the private key - handle all possible newline formats
    let cleanKey = PRIVATE_KEY_RAW
      .replace(/\\n/g, '\n')   // escaped newlines
      .replace(/\r\n/g, '\n')  // windows newlines
      .replace(/\r/g, '\n')    // old mac newlines
      .trim();

    // If the key doesn't have proper newlines, reconstruct it
    if(!cleanKey.includes('\n')){
      // Key is all on one line - split it properly
      cleanKey = cleanKey
        .replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----\n')
        .replace('-----END RSA PRIVATE KEY-----', '\n-----END RSA PRIVATE KEY-----')
        // Split the base64 content into 64-char lines
        .split('\n')
        .map((line, i) => {
          if(line.startsWith('-----')) return line;
          // Split long base64 into 64-char chunks
          const chunks = [];
          for(let j = 0; j < line.length; j += 64){
            chunks.push(line.slice(j, j + 64));
          }
          return chunks.join('\n');
        })
        .join('\n');
    }

    console.log('Key starts with:', cleanKey.substring(0, 40));
    console.log('Key has newlines:', cleanKey.includes('\n'));

    // Build JWT
    const now     = Math.floor(Date.now() / 1000);
    const header  = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({
      iss: INTEGRATION_KEY, sub: USER_ID, aud: OAUTH_BASE,
      iat: now, exp: now + 3600, scope: 'signature',
    }));
    const sigInput = `${header}.${payload}`;

    // Try signing with the key
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(sigInput);
    sign.end();
    const signature = sign.sign({
      key: cleanKey,
      format: 'pem',
    }, 'base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const jwt = `${sigInput}.${signature}`;

    // Exchange JWT for access token
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const tokenResp = await postReq(OAUTH_BASE, '/oauth/token', body);

    console.log('Token response status:', tokenResp.status);
    console.log('Token response:', JSON.stringify(tokenResp.data).substring(0, 100));

    if(tokenResp.data && tokenResp.data.error === 'consent_required'){
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: JSON.stringify({
          error: 'consent_required',
          consent_url: `https://account-d.docusign.com/oauth/auth?response_type=code&scope=signature%20impersonation&client_id=${INTEGRATION_KEY}&redirect_uri=https://singular-shortbread-980c33.netlify.app/`
        }),
      };
    }

    return {
      statusCode: tokenResp.status,
      headers: corsHeaders(),
      body: JSON.stringify(tokenResp.data),
    };

  } catch(err){
    console.error('JWT error:', err.message);
    console.error('JWT error stack:', err.stack);
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: err.message, stack: err.stack }),
    };
  }
};

function b64url(str){
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function corsHeaders(){
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };
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
