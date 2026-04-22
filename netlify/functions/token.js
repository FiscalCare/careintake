const https = require('https');
const crypto = require('crypto');

exports.handler = async (event) => {
  // Handle CORS preflight
  if(event.httpMethod === 'OPTIONS'){
    return { statusCode: 200, headers: corsHeaders(), body: '' };
  }
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, headers: corsHeaders(), body: 'Method Not Allowed' };
  }

  const INTEGRATION_KEY = 'fa2466a9-cb58-4909-8db8-4be8b67abd1f';
  const USER_ID         = process.env.DOCUSIGN_USER_ID;
  const PRIVATE_KEY     = process.env.DOCUSIGN_PRIVATE_KEY;
  const OAUTH_BASE      = 'account-d.docusign.com';

  if(!USER_ID || !PRIVATE_KEY){
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: 'Missing DOCUSIGN_USER_ID or DOCUSIGN_PRIVATE_KEY env vars' }),
    };
  }

  try{
    const now    = Math.floor(Date.now() / 1000);
    const header  = b64url(JSON.stringify({ alg:'RS256', typ:'JWT' }));
    const payload = b64url(JSON.stringify({
      iss: INTEGRATION_KEY, sub: USER_ID, aud: OAUTH_BASE,
      iat: now, exp: now + 3600, scope: 'signature',
    }));
    const sigInput = `${header}.${payload}`;

    const cleanKey = PRIVATE_KEY.replace(/\\n/g,'\n').replace(/\r/g,'').trim();
    const sign = crypto.createSign('SHA256');
    sign.update(sigInput);
    const signature = sign.sign(cleanKey,'base64')
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

    const jwt = `${sigInput}.${signature}`;

    const tokenResp = await postReq(OAUTH_BASE, '/oauth/token',
      `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
    );

    // If consent_required error, return helpful message
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
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: JSON.stringify({ error: err.message }),
    };
  }
};

function b64url(str){
  return Buffer.from(str).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
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
        'Content-Type': 'application/x-www-form-urlencoded',
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
