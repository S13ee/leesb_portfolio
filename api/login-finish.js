const supabase = require('./_db');
const { verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { v4: uuidv4 } = require('uuid');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { userId, credential } = req.body;
  if (!userId || !credential) return res.status(400).json({ error: '필수값 누락' });

  // 챌린지 조회
  const { data: challengeRow } = await supabase
    .from('passkey_challenges')
    .select('*')
    .eq('user_id', userId)
    .eq('used', false)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (!challengeRow) return res.status(400).json({ error: '챌린지 없음' });

  // 챌린지 만료 확인
  if (new Date(challengeRow.expires_at) < new Date()) {
    return res.status(400).json({ error: '챌린지 만료' });
  }

  // 챌린지 재사용 확인
  const challengeAge = new Date() - new Date(challengeRow.created_at);
  if (challengeRow.used) {
    return res.status(400).json({ error: '이미 사용된 챌린지' });
  }

  // 패스키 조회
  const credentialId = credential.id;
  const { data: storedCredential } = await supabase
    .from('passkey_credentials')
    .select('*')
    .eq('id', credentialId)
    .eq('user_id', userId)
    .single();

  if (!storedCredential) return res.status(400).json({ error: '패스키 없음' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: `https://${req.headers.host.split(':')[0]}`,
      expectedRPID: req.headers.host.split(':')[0],
      credential: {
        id: storedCredential.id,
        publicKey: Buffer.from(storedCredential.public_key, 'base64url'),
        counter: storedCredential.counter,
      },
      requireUserVerification: false,
    });
  } catch (e) {
    return res.status(400).json({ error: '검증 실패', detail: e.message });
  }

  if (!verification.verified) {
    return res.status(400).json({ error: '서명 검증 실패' });
  }

  // 챌린지 사용 처리
  await supabase
    .from('passkey_challenges')
    .update({ used: true })
    .eq('id', challengeRow.id);

  // counter 업데이트 (v14: authenticationInfo.newCounter)
  await supabase
    .from('passkey_credentials')
    .update({ counter: verification.authenticationInfo.newCounter })
    .eq('id', credentialId);

  // 세션 토큰 발급
  const token = uuidv4();
  await supabase.from('passkey_sessions').insert({
    user_id: userId,
    token,
  });

  return res.status(200).json({ success: true, token });
};
