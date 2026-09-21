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
  res.setHeader('Access-Control-Allow-Methods', 'GET, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: '인증 필요' });

  // 패스키 목록 조회
  if (req.method === 'GET') {
    const { data: credentials } = await supabase
      .from('passkey_credentials')
      .select('id, device_name, created_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: true });

    return res.status(200).json({ credentials: credentials || [] });
  }

  // 패스키 삭제
  if (req.method === 'DELETE') {
    const { credentialId } = req.body;
    if (!credentialId) return res.status(400).json({ error: 'credentialId 필요' });

    // 마지막 패스키 삭제 방지
    const { data: remaining } = await supabase
      .from('passkey_credentials')
      .select('id')
      .eq('user_id', user.id);

    if (remaining.length <= 1) {
      return res.status(400).json({ error: '마지막 패스키는 삭제할 수 없습니다' });
    }

    const { error } = await supabase
      .from('passkey_credentials')
      .delete()
      .eq('id', credentialId)
      .eq('user_id', user.id);

    if (error) return res.status(500).json({ error: '삭제 실패' });

    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
