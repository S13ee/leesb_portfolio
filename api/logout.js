const supabase = require('./_db');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '토큰 없음' });

  const { data, error } = await supabase
    .from('passkey_sessions')
    .delete()
    .eq('token', token)
    .select();

  if (error) return res.status(500).json({ error: '로그아웃 실패', detail: error.message });
  if (!data || data.length === 0) return res.status(404).json({ error: '세션 없음' });

  return res.status(200).json({ success: true });
};
