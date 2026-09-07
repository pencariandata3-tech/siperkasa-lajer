
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '12h';
const DB_SSL = String(process.env.DB_SSL || 'false').toLowerCase() === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: DB_SSL ? { rejectUnauthorized: false } : false
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15*60*1000, max: 500 }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false });

async function q(text, params=[]) { return pool.query(text, params); }
function asyncRoute(fn){ return (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next); }

async function audit(req, action, entity, entityId=null, detail={}) {
  try {
    await q(`INSERT INTO audit_logs(user_id,username,action,entity,entity_id,detail,ip)
             VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [req.user?.id || null, req.user?.username || null, action, entity, entityId ? String(entityId) : null, JSON.stringify(detail), req.ip]);
  } catch(e) { console.error('Audit error:', e.message); }
}

function auth(req,res,next){
  const token = req.cookies.siperkasa_token || (req.headers.authorization||'').replace(/^Bearer\s+/,'');
  if(!token) return res.status(401).json({error:'Silakan login.'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({error:'Sesi tidak valid atau telah berakhir.'}); }
}
function allow(...roles){
  return (req,res,next)=> roles.includes(req.user.role) ? next() : res.status(403).json({error:'Akses tidak diizinkan.'});
}

async function initDb(){
  const schema = fs.readFileSync(path.join(__dirname,'sql','schema.sql'),'utf8');
  await q(schema);
  const cap = Number(process.env.DEFAULT_CAPACITY || 390);
  const occ = Number(process.env.DEFAULT_OCCUPANTS || 939);
  await q('UPDATE settings SET capacity=$1, occupants=$2 WHERE id=1', [cap,occ]);

  const username = process.env.ADMIN_USERNAME || 'admin';
  const existing = await q('SELECT id FROM users WHERE username=$1',[username]);
  if(existing.rowCount===0){
    const password = process.env.ADMIN_PASSWORD || 'GantiPasswordKuat123!';
    const hash = await bcrypt.hash(password, 12);
    await q(`INSERT INTO users(name,username,password_hash,role)
             VALUES($1,$2,$3,'admin')`,
      [process.env.ADMIN_NAME || 'Administrator SIPERKASA', username, hash]);
    console.log(`Bootstrap admin created: ${username}`);
  }
}

app.get('/api/health', asyncRoute(async(req,res)=>{
  await q('SELECT 1');
  res.json({ok:true, app:process.env.APP_NAME || 'SIPERKASA LAJER'});
}));

app.post('/api/auth/login', loginLimiter, asyncRoute(async(req,res)=>{
  const {username,password} = req.body || {};
  if(!username || !password) return res.status(400).json({error:'Username dan password wajib diisi.'});
  const r = await q('SELECT * FROM users WHERE username=$1 AND is_active=TRUE',[String(username).trim()]);
  if(r.rowCount===0) return res.status(401).json({error:'Username atau password salah.'});
  const user = r.rows[0];
  const ok = await bcrypt.compare(String(password), user.password_hash);
  if(!ok) return res.status(401).json({error:'Username atau password salah.'});
  const payload = {id:user.id,name:user.name,username:user.username,role:user.role};
  const token = jwt.sign(payload, JWT_SECRET, {expiresIn:JWT_EXPIRES_IN});
  res.cookie('siperkasa_token', token, {
    httpOnly:true, sameSite:'lax',
    secure:process.env.NODE_ENV==='production',
    maxAge:12*60*60*1000
  });
  req.user=payload;
  await audit(req,'LOGIN','auth',user.id);
  res.json({user:payload});
}));

app.post('/api/auth/logout', auth, asyncRoute(async(req,res)=>{
  await audit(req,'LOGOUT','auth',req.user.id);
  res.clearCookie('siperkasa_token');
  res.json({ok:true});
}));
app.get('/api/auth/me', auth, (req,res)=>res.json({user:req.user}));

app.get('/api/dashboard', auth, asyncRoute(async(req,res)=>{
  const settings=(await q('SELECT * FROM settings WHERE id=1')).rows[0];
  const blockCount=(await q('SELECT COUNT(*)::int c FROM blocks')).rows[0].c;
  const highWbp=(await q(`SELECT COUNT(*)::int c FROM wbp_risks WHERE (violation+conflict+escape+contraband)>=13`)).rows[0].c;
  const patrol7=(await q(`SELECT COUNT(*)::int c FROM patrols WHERE occurred_at >= NOW()-INTERVAL '7 days'`)).rows[0].c;
  const incident30=(await q(`SELECT COUNT(*)::int c FROM incidents WHERE occurred_at >= NOW()-INTERVAL '30 days'`)).rows[0].c;
  const blocks=(await q(`SELECT *,
    CASE WHEN capacity>0 THEN ROUND((occupants::numeric/capacity)*100,1) ELSE 0 END occupancy_rate,
    ROUND((
      (CASE WHEN capacity=0 THEN 1 WHEN occupants::numeric/capacity>=2 THEN 5 WHEN occupants::numeric/capacity>=1.5 THEN 4 WHEN occupants::numeric/capacity>=1.2 THEN 3 WHEN occupants::numeric/capacity>=1 THEN 2 ELSE 1 END)*0.6
      + threat*0.4
    )::numeric,1) risk_score
    FROM blocks ORDER BY risk_score DESC LIMIT 10`)).rows;
  res.json({settings,blockCount,highWbp,patrol7,incident30,blocks});
}));

app.get('/api/settings', auth, asyncRoute(async(req,res)=>res.json((await q('SELECT * FROM settings WHERE id=1')).rows[0])));
app.put('/api/settings', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  const {capacity,occupants}=req.body;
  const r=await q(`UPDATE settings SET capacity=$1,occupants=$2,updated_at=NOW() WHERE id=1 RETURNING *`,[Number(capacity),Number(occupants)]);
  await audit(req,'UPDATE','settings',1,{capacity,occupants});
  res.json(r.rows[0]);
}));

app.get('/api/blocks', auth, asyncRoute(async(req,res)=>{
  const r=await q(`SELECT *,
    CASE WHEN capacity>0 THEN ROUND((occupants::numeric/capacity)*100,1) ELSE 0 END occupancy_rate,
    ROUND((
      (CASE WHEN capacity=0 THEN 1 WHEN occupants::numeric/capacity>=2 THEN 5 WHEN occupants::numeric/capacity>=1.5 THEN 4 WHEN occupants::numeric/capacity>=1.2 THEN 3 WHEN occupants::numeric/capacity>=1 THEN 2 ELSE 1 END)*0.6
      + threat*0.4
    )::numeric,1) risk_score
    FROM blocks ORDER BY name`);
  res.json(r.rows);
}));
app.post('/api/blocks', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const {name,capacity,occupants,threat,notes=''}=req.body;
  const r=await q(`INSERT INTO blocks(name,capacity,occupants,threat,notes,created_by,updated_by)
    VALUES($1,$2,$3,$4,$5,$6,$6) RETURNING *`,
    [name,Number(capacity),Number(occupants),Number(threat),notes,req.user.id]);
  await audit(req,'CREATE','blocks',r.rows[0].id,{name});
  res.json(r.rows[0]);
}));
app.put('/api/blocks/:id', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const {name,capacity,occupants,threat,notes=''}=req.body;
  const r=await q(`UPDATE blocks SET name=$1,capacity=$2,occupants=$3,threat=$4,notes=$5,updated_by=$6,updated_at=NOW()
    WHERE id=$7 RETURNING *`,[name,Number(capacity),Number(occupants),Number(threat),notes,req.user.id,req.params.id]);
  if(!r.rowCount) return res.status(404).json({error:'Data tidak ditemukan.'});
  await audit(req,'UPDATE','blocks',req.params.id,{name});
  res.json(r.rows[0]);
}));
app.delete('/api/blocks/:id', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  await q('DELETE FROM blocks WHERE id=$1',[req.params.id]);
  await audit(req,'DELETE','blocks',req.params.id);
  res.json({ok:true});
}));

app.get('/api/wbp', auth, asyncRoute(async(req,res)=>{
  const r=await q(`SELECT w.*, b.name block_name,
    (w.violation+w.conflict+w.escape+w.contraband) risk_score
    FROM wbp_risks w LEFT JOIN blocks b ON b.id=w.block_id
    ORDER BY risk_score DESC,w.id DESC`);
  res.json(r.rows);
}));
app.post('/api/wbp', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const d=req.body;
  const r=await q(`INSERT INTO wbp_risks(identity_label,registration_no,block_id,violation,conflict,escape,contraband,notes,created_by,updated_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *`,
    [d.identity_label,d.registration_no||'',d.block_id||null,+d.violation||0,+d.conflict||0,+d.escape||0,+d.contraband||0,d.notes||'',req.user.id]);
  await audit(req,'CREATE','wbp_risks',r.rows[0].id,{identity_label:d.identity_label});
  res.json(r.rows[0]);
}));
app.put('/api/wbp/:id', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const d=req.body;
  const r=await q(`UPDATE wbp_risks SET identity_label=$1,registration_no=$2,block_id=$3,violation=$4,conflict=$5,escape=$6,contraband=$7,notes=$8,updated_by=$9,updated_at=NOW()
    WHERE id=$10 RETURNING *`,
    [d.identity_label,d.registration_no||'',d.block_id||null,+d.violation||0,+d.conflict||0,+d.escape||0,+d.contraband||0,d.notes||'',req.user.id,req.params.id]);
  if(!r.rowCount) return res.status(404).json({error:'Data tidak ditemukan.'});
  await audit(req,'UPDATE','wbp_risks',req.params.id,{identity_label:d.identity_label});
  res.json(r.rows[0]);
}));
app.delete('/api/wbp/:id', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  await q('DELETE FROM wbp_risks WHERE id=$1',[req.params.id]);
  await audit(req,'DELETE','wbp_risks',req.params.id);
  res.json({ok:true});
}));

app.get('/api/patrols', auth, asyncRoute(async(req,res)=>{
  res.json((await q(`SELECT p.*,b.name block_name,u.name created_by_name FROM patrols p
    LEFT JOIN blocks b ON b.id=p.block_id LEFT JOIN users u ON u.id=p.created_by
    ORDER BY p.occurred_at DESC LIMIT 500`)).rows);
}));
app.post('/api/patrols', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const d=req.body;
  const r=await q(`INSERT INTO patrols(occurred_at,block_id,officer,level,finding,action,created_by)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [d.occurred_at,d.block_id||null,d.officer,d.level,d.finding,d.action,req.user.id]);
  await audit(req,'CREATE','patrols',r.rows[0].id,{level:d.level});
  res.json(r.rows[0]);
}));
app.delete('/api/patrols/:id', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  await q('DELETE FROM patrols WHERE id=$1',[req.params.id]);
  await audit(req,'DELETE','patrols',req.params.id);
  res.json({ok:true});
}));

app.get('/api/incidents', auth, asyncRoute(async(req,res)=>{
  res.json((await q(`SELECT i.*,b.name block_name,u.name created_by_name FROM incidents i
    LEFT JOIN blocks b ON b.id=i.block_id LEFT JOIN users u ON u.id=i.created_by
    ORDER BY i.occurred_at DESC LIMIT 500`)).rows);
}));
app.post('/api/incidents', auth, allow('admin','kepala_kplp','operator'), asyncRoute(async(req,res)=>{
  const d=req.body;
  const r=await q(`INSERT INTO incidents(occurred_at,block_id,incident_type,severity,description,action,created_by)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [d.occurred_at,d.block_id||null,d.incident_type,d.severity,d.description,d.action,req.user.id]);
  await audit(req,'CREATE','incidents',r.rows[0].id,{severity:d.severity,type:d.incident_type});
  res.json(r.rows[0]);
}));
app.delete('/api/incidents/:id', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  await q('DELETE FROM incidents WHERE id=$1',[req.params.id]);
  await audit(req,'DELETE','incidents',req.params.id);
  res.json({ok:true});
}));

app.get('/api/users', auth, allow('admin'), asyncRoute(async(req,res)=>{
  res.json((await q(`SELECT id,name,username,role,is_active,created_at FROM users ORDER BY id`)).rows);
}));
app.post('/api/users', auth, allow('admin'), asyncRoute(async(req,res)=>{
  const {name,username,password,role}=req.body;
  if(!name||!username||!password||!['admin','kepala_kplp','operator'].includes(role))
    return res.status(400).json({error:'Data user tidak lengkap/valid.'});
  if(String(password).length<8) return res.status(400).json({error:'Password minimal 8 karakter.'});
  const hash=await bcrypt.hash(String(password),12);
  const r=await q(`INSERT INTO users(name,username,password_hash,role) VALUES($1,$2,$3,$4)
                   RETURNING id,name,username,role,is_active,created_at`,[name,username,hash,role]);
  await audit(req,'CREATE','users',r.rows[0].id,{username,role});
  res.json(r.rows[0]);
}));
app.put('/api/users/:id', auth, allow('admin'), asyncRoute(async(req,res)=>{
  const {name,role,is_active,password}=req.body;
  if(!['admin','kepala_kplp','operator'].includes(role)) return res.status(400).json({error:'Role tidak valid.'});
  if(password){
    const hash=await bcrypt.hash(String(password),12);
    await q(`UPDATE users SET name=$1,role=$2,is_active=$3,password_hash=$4,updated_at=NOW() WHERE id=$5`,[name,role,!!is_active,hash,req.params.id]);
  } else {
    await q(`UPDATE users SET name=$1,role=$2,is_active=$3,updated_at=NOW() WHERE id=$4`,[name,role,!!is_active,req.params.id]);
  }
  await audit(req,'UPDATE','users',req.params.id,{role,is_active});
  res.json({ok:true});
}));

app.get('/api/audit', auth, allow('admin','kepala_kplp'), asyncRoute(async(req,res)=>{
  res.json((await q('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 300')).rows);
}));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.use((err,req,res,next)=>{
  console.error(err);
  if(err.code==='23505') return res.status(409).json({error:'Data duplikat. Nama/username mungkin sudah digunakan.'});
  if(err.code==='23514') return res.status(400).json({error:'Nilai data tidak valid.'});
  res.status(500).json({error:'Terjadi kesalahan server.'});
});

initDb().then(()=>{
  app.listen(PORT,()=>console.log(`SIPERKASA LAJER running on :${PORT}`));
}).catch(err=>{
  console.error('Gagal inisialisasi database:',err);
  process.exit(1);
});
