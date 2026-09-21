const supabase = require('./_db');
const { generateAuthenticationOptions } = require('@simplewebauthn/server');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username 필요' });

  // 유저 조회
  const { data: user } = await supabase
    .from('passkey_users')
    .select('*')
    .eq('username', username)
    .single();

  if (!user) return res.status(404).json({ error: '유저 없음' });

  // 등록된 패스키 조회
  const { data: credentials } = await supabase
    .from('passkey_credentials')
    .select('*')
    .eq('user_id', user.id);

  if (!credentials || credentials.length === 0) {
    return res.status(400).json({ error: '등록된 패스키 없음' });
  }

  const options = await generateAuthenticationOptions({
    rpID: req.headers.host.split(':')[0],
    allowCredentials: credentials.map(c => ({
      id: c.id,
      type: 'public-key',
    })),
    userVerification: 'discouraged',
  });

  // 챌린지 저장
  await supabase.from('passkey_challenges').insert({
    challenge: options.challenge,
    user_id: user.id,
  });

  return res.status(200).json({ options, userId: user.id });
};
