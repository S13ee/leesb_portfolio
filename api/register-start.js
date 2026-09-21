const supabase = require('./_db');
const { generateRegistrationOptions } = require('@simplewebauthn/server');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username 필요' });

  // 기존 유저 조회 또는 생성
  let { data: user, error: fetchError } = await supabase
    .from('passkey_users')
    .select('*')
    .eq('username', username)
    .maybeSingle();

  if (fetchError) return res.status(500).json({ error: '유저 조회 실패', detail: fetchError.message });

  if (!user) {
    const { data: newUser, error: insertError } = await supabase
      .from('passkey_users')
      .insert({ username })
      .select()
      .maybeSingle();
    if (insertError) return res.status(500).json({ error: '유저 생성 실패', detail: insertError.message });
    user = newUser;
  }

  // 기존 패스키 목록 조회 (중복 등록 방지용)
  const { data: existingCredentials } = await supabase
    .from('passkey_credentials')
    .select('id')
    .eq('user_id', user.id);

  const options = await generateRegistrationOptions({
    rpName: 'leesb portfolio',
    rpID: req.headers.host.split(':')[0],
    userID: new TextEncoder().encode(user.id),
    userName: username,
    excludeCredentials: (existingCredentials || []).map(c => ({
      id: c.id,
      type: 'public-key',
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  // 챌린지 저장
  await supabase.from('passkey_challenges').insert({
    challenge: options.challenge,
    user_id: user.id,
  });

  return res.status(200).json({ options, userId: user.id });
};