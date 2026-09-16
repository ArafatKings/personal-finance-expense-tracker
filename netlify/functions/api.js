const express = require('express');
const serverless = require('serverless-http');
const crypto = require('crypto');
const { createClient } = require('@tursodatabase/serverless/compat');

const app = express();
app.use(express.json({ limit: '1mb' }));

const JWT_SECRET = process.env.PFTRACKER_JWT_SECRET;
const DEMO_EMAIL = 'demo@pftracker.local';
const DEMO_PASSWORD = 'Demo@12345';

if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN || !JWT_SECRET) {
  console.warn('PFTracker: TURSO_DATABASE_URL, TURSO_AUTH_TOKEN and PFTRACKER_JWT_SECRET must be configured in Netlify.');
}

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'libsql://missing.invalid',
  authToken: process.env.TURSO_AUTH_TOKEN || 'missing'
});

let initPromise;
async function initDb() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    await db.execute('PRAGMA foreign_keys=ON');
    await db.execute(`CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS categories(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('income','expense','both')),
      created_at TEXT NOT NULL,
      UNIQUE(user_id,name,type),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    await db.execute(`CREATE TABLE IF NOT EXISTS transactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('income','expense')),
      amount REAL NOT NULL CHECK(amount>0),
      category_id INTEGER,
      transaction_date TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )`);
  })();
  return initPromise;
}

const now=()=>new Date().toISOString();
async function q(sql,args=[]){ const r=await db.execute({sql,args}); return r.rows.map(row=>{const o={}; for(const k of Object.keys(row)) o[k]=row[k]; return o;}); }
async function run(sql,args=[]){ return db.execute({sql,args}); }
async function scalar(sql,args=[]){ const r=await q(sql,args); return r.length ? Object.values(r[0])[0] : null; }
function b64(s){return Buffer.from(s).toString('base64url');}
function sign(input){return crypto.createHmac('sha256',JWT_SECRET||'').update(input).digest('base64url');}
function makeToken(userId){const head=b64(JSON.stringify({alg:'HS256',typ:'JWT'}));const payload=b64(JSON.stringify({sub:Number(userId),exp:Date.now()+1000*60*60*8}));return `${head}.${payload}.${sign(`${head}.${payload}`)}`;}
function verifyToken(token){try{if(!token)return null;const [h,p,s]=token.split('.');if(!h||!p||!s||s!==sign(`${h}.${p}`))return null;const data=JSON.parse(Buffer.from(p,'base64url').toString());if(!data.sub||data.exp<Date.now())return null;return Number(data.sub);}catch{return null;}}
function cookies(req){const out={};for(const part of String(req.headers.cookie||'').split(';')){const i=part.indexOf('=');if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());}return out;}
function setAuthCookie(res,userId){res.setHeader('Set-Cookie',`pftracker_token=${encodeURIComponent(makeToken(userId))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`);}
function clearAuthCookie(res){res.setHeader('Set-Cookie','pftracker_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');}
async function currentUserId(req){return verifyToken(cookies(req).pftracker_token);}
async function auth(req,res,next){await initDb();const uid=await currentUserId(req);if(!uid)return res.status(401).json({error:'Authentication required'});req.userId=uid;next();}

function hashPassword(password){return crypto.createHash('sha256').update(password+'::PFTrackerDemoSalt').digest('hex');}
// Passwords are stored using the same bcryptjs-compatible local format only in the local server.
// Online accounts use a PBKDF2 hash so the Netlify Function needs no native password module.
function hashOnline(password,salt=crypto.randomBytes(16).toString('hex')){return `${salt}:${crypto.pbkdf2Sync(password,salt,120000,32,'sha256').toString('hex')}`;}
function checkOnline(password,stored){const [salt,hash]=String(stored||'').split(':');if(!salt||!hash)return false;const got=crypto.pbkdf2Sync(password,salt,120000,32,'sha256').toString('hex');return crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(got,'hex'));}

app.get('/api/health',async(req,res)=>{try{await initDb();res.json({ok:true,online:true})}catch(e){res.status(500).json({ok:false,error:'Database is not configured.'})}});

app.post('/api/auth/register',async(req,res)=>{await initDb();const {name,email,password}=req.body||{};if(!name||!email||!password||password.length<6)return res.status(400).json({error:'Name, email and a password of at least 6 characters are required.'});const cleanEmail=String(email).trim().toLowerCase();try{await run('INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)',[String(name).trim(),cleanEmail,hashOnline(password),now()]);const id=await scalar('SELECT id FROM users WHERE email=?',[cleanEmail]);setAuthCookie(res,id);res.json({user:{id,name:String(name).trim(),email:cleanEmail}})}catch(e){res.status(409).json({error:'An account with that email already exists.'})}});
app.post('/api/auth/login',async(req,res)=>{await initDb();const {email,password}=req.body||{};const cleanEmail=String(email||'').trim().toLowerCase();const r=await q('SELECT id,name,email,password_hash FROM users WHERE email=?',[cleanEmail]);if(!r.length||!checkOnline(password||'',r[0].password_hash))return res.status(401).json({error:'Invalid email or password.'});setAuthCookie(res,r[0].id);res.json({user:{id:r[0].id,name:r[0].name,email:r[0].email}})});
app.post('/api/auth/logout',async(req,res)=>{clearAuthCookie(res);res.json({ok:true})});
app.get('/api/auth/me',auth,async(req,res)=>{const r=await q('SELECT id,name,email,created_at FROM users WHERE id=?',[req.userId]);if(!r.length)return res.status(401).json({error:'Not logged in'});res.json({user:r[0]})});

app.get('/api/categories',auth,async(req,res)=>res.json(await q('SELECT * FROM categories WHERE user_id=? ORDER BY type,name',[req.userId])));
app.post('/api/categories',auth,async(req,res)=>{const {name,type='expense'}=req.body||{};if(!name||!['income','expense','both'].includes(type))return res.status(400).json({error:'Valid category name and type are required.'});try{await run('INSERT INTO categories(user_id,name,type,created_at) VALUES(?,?,?,?)',[req.userId,String(name).trim(),type,now()]);res.json({ok:true})}catch(e){res.status(409).json({error:'That category already exists.'})}});
app.put('/api/categories/:id',auth,async(req,res)=>{const {name,type}=req.body||{};if(!name||!['income','expense','both'].includes(type))return res.status(400).json({error:'Valid category name and type are required.'});const n=await scalar('SELECT COUNT(*) FROM categories WHERE id=? AND user_id=?',[req.params.id,req.userId]);if(!n)return res.status(404).json({error:'Category not found.'});await run('UPDATE categories SET name=?,type=? WHERE id=? AND user_id=?',[String(name).trim(),type,req.params.id,req.userId]);res.json({ok:true})});
app.delete('/api/categories/:id',auth,async(req,res)=>{await run('DELETE FROM categories WHERE id=? AND user_id=?',[req.params.id,req.userId]);res.json({ok:true})});

const txSelect=()=>`SELECT t.id,t.type,t.amount,t.category_id,t.transaction_date,t.description,c.name category_name FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=?`;
app.get('/api/transactions',auth,async(req,res)=>{let sql=txSelect(),p=[req.userId];const {type,category,start,end,search}=req.query;if(type&&['income','expense'].includes(type)){sql+=' AND t.type=?';p.push(type)}if(category){sql+=' AND t.category_id=?';p.push(category)}if(start){sql+=' AND t.transaction_date>=?';p.push(start)}if(end){sql+=' AND t.transaction_date<=?';p.push(end)}if(search){sql+=` AND (LOWER(t.description) LIKE LOWER(?) OR LOWER(COALESCE(c.name,'')) LIKE LOWER(?))`;p.push('%'+search+'%','%'+search+'%')}sql+=' ORDER BY t.transaction_date DESC,t.id DESC';res.json(await q(sql,p))});
app.post('/api/transactions',auth,async(req,res)=>{const {type,amount,category_id,transaction_date,description=''}=req.body||{};if(!['income','expense'].includes(type)||!Number(amount)||Number(amount)<=0||!transaction_date)return res.status(400).json({error:'Type, positive amount and date are required.'});await run('INSERT INTO transactions(user_id,type,amount,category_id,transaction_date,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',[req.userId,type,Number(amount),category_id||null,transaction_date,description,now(),now()]);res.json({ok:true})});
app.put('/api/transactions/:id',auth,async(req,res)=>{const {type,amount,category_id,transaction_date,description=''}=req.body||{};if(!['income','expense'].includes(type)||!Number(amount)||Number(amount)<=0||!transaction_date)return res.status(400).json({error:'Type, positive amount and date are required.'});const n=await scalar('SELECT COUNT(*) FROM transactions WHERE id=? AND user_id=?',[req.params.id,req.userId]);if(!n)return res.status(404).json({error:'Transaction not found.'});await run('UPDATE transactions SET type=?,amount=?,category_id=?,transaction_date=?,description=?,updated_at=? WHERE id=? AND user_id=?',[type,Number(amount),category_id||null,transaction_date,description,now(),req.params.id,req.userId]);res.json({ok:true})});
app.delete('/api/transactions/:id',auth,async(req,res)=>{await run('DELETE FROM transactions WHERE id=? AND user_id=?',[req.params.id,req.userId]);res.json({ok:true})});

app.get('/api/dashboard',auth,async(req,res)=>{const uid=req.userId;const totals=(await q(`SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense FROM transactions WHERE user_id=?`,[uid]))[0];const recent=await q(`${txSelect()} ORDER BY t.transaction_date DESC,t.id DESC LIMIT 8`,[uid]);const category=await q(`SELECT c.name,SUM(t.amount) value FROM transactions t JOIN categories c ON c.id=t.category_id WHERE t.user_id=? AND t.type='expense' GROUP BY c.id,c.name ORDER BY value DESC`,[uid]);const monthly=await q(`SELECT substr(transaction_date,1,7) month,COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense FROM transactions WHERE user_id=? GROUP BY month ORDER BY month DESC LIMIT 12`,[uid]);monthly.reverse();const count=await scalar('SELECT COUNT(*) FROM transactions WHERE user_id=?',[uid]);const income=Number(totals.income||0),expense=Number(totals.expense||0);res.json({totals:{income,expense,balance:income-expense,savingsRate:income?((income-expense)/income)*100:0},recent,category,monthly,count:Number(count||0)})});
app.get('/api/reports',auth,async(req,res)=>{const uid=req.userId;const byType=await q(`SELECT type,COUNT(*) count,SUM(amount) total FROM transactions WHERE user_id=? GROUP BY type`,[uid]);const byCategory=await q(`SELECT c.name,t.type,SUM(t.amount) total FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=? GROUP BY c.name,t.type ORDER BY total DESC`,[uid]);const monthly=await q(`SELECT substr(transaction_date,1,7) month, SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income,SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense FROM transactions WHERE user_id=? GROUP BY month ORDER BY month`,[uid]);res.json({byType,byCategory,monthly})});
app.post('/api/demo',auth,async(req,res)=>{const uid=req.userId;const existing=await scalar('SELECT COUNT(*) FROM transactions WHERE user_id=?',[uid]);if(Number(existing)>0)return res.status(400).json({error:'Your account already has transactions. Demo data was not added to avoid mixing records.'});const cats={};for(const x of await q('SELECT id,name FROM categories WHERE user_id=?',[uid]))cats[x.name]=x.id;for(const [n,t] of [['Salary','income'],['Freelance','income'],['Scholarship','income'],['Rent','expense'],['Food','expense'],['Education','expense'],['Utilities','expense'],['Transport','expense'],['Shopping','expense'],['Entertainment','expense'],['Health','expense']]){if(!cats[n]){try{await run('INSERT INTO categories(user_id,name,type,created_at) VALUES(?,?,?,?)',[uid,n,t,now()]);cats[n]=await scalar('SELECT id FROM categories WHERE user_id=? AND name=? AND type=?',[uid,n,t])}catch{}}}const data=[['income',50000,'Salary','2026-09-01','Monthly salary'],['income',15000,'Freelance','2026-09-04','Video editing client'],['income',5000,'Scholarship','2026-09-06','University scholarship'],['expense',12000,'Rent','2026-09-02','Monthly accommodation'],['expense',5200,'Food','2026-09-03','Groceries and dining'],['expense',3500,'Education','2026-09-05','Books and project materials'],['expense',2200,'Utilities','2026-09-07','Internet and electricity'],['expense',1800,'Transport','2026-09-09','Bus and ride sharing'],['expense',2500,'Shopping','2026-09-11','Clothing and supplies'],['expense',1200,'Entertainment','2026-09-12','Movies and outings'],['expense',900,'Health','2026-09-13','Pharmacy']];for(const [t,a,c,d,desc] of data)await run('INSERT INTO transactions(user_id,type,amount,category_id,transaction_date,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',[uid,t,a,cats[c],d,desc,now(),now()]);res.json({ok:true})});

// The frontend is hosted by Netlify. Express only handles /api/* through this function.
module.exports.handler = serverless(app);
