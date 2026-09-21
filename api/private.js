const supabase = require('./_db');

// 토큰으로 유저 확인하는 함수
async function getUserFromToken(token) {
  if (!token) return null;
  const { data: session } = await supabase
    .from('passkey_sessions')
    .select('*, passkey_users(*)')
    .eq('token', token)
    .gt('expires_at', new Date().toISOString())
    .single();
  return session?.passkey_users || null;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: '인증 필요' });

  // 내 비공개 콘텐츠만 조회
  const { data: contents } = await supabase
    .from('passkey_contents')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: true });

  return res.status(200).json({
    username: user.username,
    contents: contents || [],
  });
};
