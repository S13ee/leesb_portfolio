const supabase = require('./_db');
const { verifyRegistrationResponse } = require('@simplewebauthn/server');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { userId, credential, deviceName } = req.body;
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

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: `https://${req.headers.host.split(':')[0]}`,
      expectedRPID: req.headers.host.split(':')[0],
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

  // 공개키 저장
  const { registrationInfo } = verification;
  const { credential: regCredential } = registrationInfo;

  const credentialID = regCredential.id;
  const credentialPublicKey = Buffer.from(regCredential.publicKey).toString('base64url');
  const counter = regCredential.counter;

  const { error } = await supabase.from('passkey_credentials').insert({
    id: credentialID,
    user_id: userId,
    public_key: credentialPublicKey,
    counter: counter,
    device_name: deviceName || '기기',
  });

  if (error) return res.status(500).json({ error: '패스키 저장 실패', detail: error.message });

  return res.status(200).json({ success: true });
};
