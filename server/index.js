const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const PORT = process.env.PORT || 3000;
const DB_DIR = path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DB_DIR, 'finance.sqlite');
fs.mkdirSync(DB_DIR, { recursive: true });

let db;
const app = express();
app.use(express.json());
app.use(session({ secret: 'pftracker-local-session-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000*60*60*8 } }));

function q(sql, params=[]) { const stmt=db.prepare(sql); if(params.length) stmt.bind(params); const rows=[]; while(stmt.step()) rows.push(stmt.getAsObject()); stmt.free(); return rows; }
function run(sql, params=[]) { db.run(sql, params); saveDb(); }
function scalar(sql, params=[]) { const r=q(sql,params); return r.length ? Object.values(r[0])[0] : null; }
function saveDb(){ const data=db.export(); fs.writeFileSync(DB_FILE, Buffer.from(data)); }
function now(){ return new Date().toISOString(); }

async function init(){
  const SQL = await initSqlJs({ locateFile: f => path.join(path.dirname(require.resolve('sql.js')), f) });
  db = fs.existsSync(DB_FILE) ? new SQL.Database(new Uint8Array(fs.readFileSync(DB_FILE))) : new SQL.Database();
  db.run(`PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN ('income','expense','both')),created_at TEXT NOT NULL,UNIQUE(user_id,name,type),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,type TEXT NOT NULL CHECK(type IN ('income','expense')),amount REAL NOT NULL CHECK(amount>0),category_id INTEGER,transaction_date TEXT NOT NULL,description TEXT DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL);
  `);
  seedDemoUser(); saveDb();
  app.listen(PORT,()=>console.log(`PFTracker API running at http://localhost:${PORT}`));
}

function seedDemoUser(){
  const email='demo@pftracker.local';
  if(scalar('SELECT id FROM users WHERE email=?',[email])) return;
  const hash=bcrypt.hashSync('Demo@12345',10); run('INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)',['Demo User',email,hash,now()]);
  const uid=scalar('SELECT id FROM users WHERE email=?',[email]);
  const cats={};
  [['Salary','income'],['Freelance','income'],['Scholarship','income'],['Rent','expense'],['Food','expense'],['Education','expense'],['Utilities','expense'],['Transport','expense'],['Shopping','expense'],['Entertainment','expense'],['Health','expense']].forEach(([n,t])=>{run('INSERT INTO categories(user_id,name,type,created_at) VALUES(?,?,?,?)',[uid,n,t,now()]); cats[n]=scalar('SELECT id FROM categories WHERE user_id=? AND name=? AND type=?',[uid,n,t]);});
  const tx=[
    ['income',50000,'Salary','2026-09-01','Monthly salary'],['income',15000,'Freelance','2026-09-04','Video editing client'],['income',5000,'Scholarship','2026-09-06','University scholarship'],
    ['expense',12000,'Rent','2026-09-02','Monthly accommodation'],['expense',5200,'Food','2026-09-03','Groceries and dining'],['expense',3500,'Education','2026-09-05','Books and project materials'],['expense',2200,'Utilities','2026-09-07','Internet and electricity'],['expense',1800,'Transport','2026-09-09','Bus and ride sharing'],['expense',2500,'Shopping','2026-09-11','Clothing and supplies'],['expense',1200,'Entertainment','2026-09-12','Movies and outings'],['expense',900,'Health','2026-09-13','Pharmacy']
  ];
  tx.forEach(([t,a,c,d,desc])=>run('INSERT INTO transactions(user_id,type,amount,category_id,transaction_date,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',[uid,t,a,cats[c],d,desc,now(),now()]));
}

function auth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:'Authentication required'}); next(); }
function user(req){ return scalar('SELECT id FROM users WHERE id=?',[req.session.userId]); }

app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/auth/register',(req,res)=>{ const {name,email,password}=req.body||{}; if(!name||!email||!password||password.length<6) return res.status(400).json({error:'Name, email and a password of at least 6 characters are required.'}); try{run('INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)',[name.trim(),email.trim().toLowerCase(),bcrypt.hashSync(password,10),now()]); const id=scalar('SELECT id FROM users WHERE email=?',[email.trim().toLowerCase()]); req.session.userId=id; res.json({user:{id,name:name.trim(),email:email.trim().toLowerCase()}});}catch(e){res.status(409).json({error:'An account with that email already exists.'})} });
app.post('/api/auth/login',(req,res)=>{ const {email,password}=req.body||{}; const r=q('SELECT id,name,email,password_hash FROM users WHERE email=?',[String(email||'').trim().toLowerCase()]); if(!r.length||!bcrypt.compareSync(password||'',r[0].password_hash)) return res.status(401).json({error:'Invalid email or password.'}); req.session.userId=r[0].id; res.json({user:{id:r[0].id,name:r[0].name,email:r[0].email}}); });
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/auth/me',(req,res)=>{ if(!req.session.userId) return res.status(401).json({error:'Not logged in'}); const r=q('SELECT id,name,email,created_at FROM users WHERE id=?',[req.session.userId]); if(!r.length)return res.status(401).json({error:'Not logged in'}); res.json({user:r[0]}); });

app.get('/api/categories',auth,(req,res)=>res.json(q('SELECT * FROM categories WHERE user_id=? ORDER BY type,name',[user(req)])));
app.post('/api/categories',auth,(req,res)=>{const {name,type='expense'}=req.body||{}; if(!name||!['income','expense','both'].includes(type))return res.status(400).json({error:'Valid category name and type are required.'}); try{run('INSERT INTO categories(user_id,name,type,created_at) VALUES(?,?,?,?)',[user(req),name.trim(),type,now()]);res.json({ok:true});}catch(e){res.status(409).json({error:'That category already exists.'})}});
app.put('/api/categories/:id',auth,(req,res)=>{const {name,type}=req.body||{}; if(!name||!['income','expense','both'].includes(type))return res.status(400).json({error:'Valid category name and type are required.'}); const n=scalar('SELECT COUNT(*) FROM categories WHERE id=? AND user_id=?',[req.params.id,user(req)]);if(!n)return res.status(404).json({error:'Category not found.'});run('UPDATE categories SET name=?,type=? WHERE id=? AND user_id=?',[name.trim(),type,req.params.id,user(req)]);res.json({ok:true})});
app.delete('/api/categories/:id',auth,(req,res)=>{run('DELETE FROM categories WHERE id=? AND user_id=?',[req.params.id,user(req)]);res.json({ok:true})});

function transactionSelect(){return `SELECT t.id,t.type,t.amount,t.category_id,t.transaction_date,t.description,c.name category_name FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=?`}
app.get('/api/transactions',auth,(req,res)=>{let sql=transactionSelect();const p=[user(req)];const {type,category,start,end,search}=req.query;if(type&&['income','expense'].includes(type)){sql+=' AND t.type=?';p.push(type)}if(category){sql+=' AND t.category_id=?';p.push(category)}if(start){sql+=' AND t.transaction_date>=?';p.push(start)}if(end){sql+=' AND t.transaction_date<=?';p.push(end)}if(search){sql+=' AND (LOWER(t.description) LIKE LOWER(?) OR LOWER(COALESCE(c.name,\'\')) LIKE LOWER(?))';p.push('%'+search+'%','%'+search+'%')}sql+=' ORDER BY t.transaction_date DESC,t.id DESC';res.json(q(sql,p))});
app.post('/api/transactions',auth,(req,res)=>{const {type,amount,category_id,transaction_date,description=''}=req.body||{};if(!['income','expense'].includes(type)||!Number(amount)||Number(amount)<=0||!transaction_date)return res.status(400).json({error:'Type, positive amount and date are required.'});run('INSERT INTO transactions(user_id,type,amount,category_id,transaction_date,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',[user(req),type,Number(amount),category_id||null,transaction_date,description,now(),now()]);res.json({ok:true})});
app.put('/api/transactions/:id',auth,(req,res)=>{const {type,amount,category_id,transaction_date,description=''}=req.body||{};if(!['income','expense'].includes(type)||!Number(amount)||Number(amount)<=0||!transaction_date)return res.status(400).json({error:'Type, positive amount and date are required.'});const n=scalar('SELECT COUNT(*) FROM transactions WHERE id=? AND user_id=?',[req.params.id,user(req)]);if(!n)return res.status(404).json({error:'Transaction not found.'});run('UPDATE transactions SET type=?,amount=?,category_id=?,transaction_date=?,description=?,updated_at=? WHERE id=? AND user_id=?',[type,Number(amount),category_id||null,transaction_date,description,now(),req.params.id,user(req)]);res.json({ok:true})});
app.delete('/api/transactions/:id',auth,(req,res)=>{run('DELETE FROM transactions WHERE id=? AND user_id=?',[req.params.id,user(req)]);res.json({ok:true})});

app.get('/api/dashboard',auth,(req,res)=>{const uid=user(req);const totals=q(`SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense FROM transactions WHERE user_id=?`,[uid])[0];const recent=q(`${transactionSelect()} ORDER BY t.transaction_date DESC,t.id DESC LIMIT 8`,[uid]);const category=q(`SELECT c.name,SUM(t.amount) value FROM transactions t JOIN categories c ON c.id=t.category_id WHERE t.user_id=? AND t.type='expense' GROUP BY c.id,c.name ORDER BY value DESC`,[uid]);const monthly=q(`SELECT substr(transaction_date,1,7) month,COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense FROM transactions WHERE user_id=? GROUP BY month ORDER BY month DESC LIMIT 12`,[uid]).reverse();const count=scalar('SELECT COUNT(*) FROM transactions WHERE user_id=?',[uid]);res.json({totals:{income:Number(totals.income),expense:Number(totals.expense),balance:Number(totals.income)-Number(totals.expense),savingsRate:totals.income?((Number(totals.income)-Number(totals.expense))/Number(totals.income))*100:0},recent,category,monthly,count:Number(count)});});
app.get('/api/reports',auth,(req,res)=>{const uid=user(req);const byType=q(`SELECT type,COUNT(*) count,SUM(amount) total FROM transactions WHERE user_id=? GROUP BY type`,[uid]);const byCategory=q(`SELECT c.name,t.type,SUM(t.amount) total FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=? GROUP BY c.name,t.type ORDER BY total DESC`,[uid]);const monthly=q(`SELECT substr(transaction_date,1,7) month, SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income,SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense FROM transactions WHERE user_id=? GROUP BY month ORDER BY month`,[uid]);res.json({byType,byCategory,monthly});});
app.post('/api/demo',auth,(req,res)=>{const uid=user(req);const existing=scalar('SELECT COUNT(*) FROM transactions WHERE user_id=?',[uid]);if(existing>0)return res.status(400).json({error:'Your account already has transactions. Demo data was not added to avoid mixing records.'});const cats={};q('SELECT id,name FROM categories WHERE user_id=?',[uid]).forEach(x=>cats[x.name]=x.id);[['Salary','income'],['Freelance','income'],['Scholarship','income'],['Rent','expense'],['Food','expense'],['Education','expense'],['Utilities','expense'],['Transport','expense'],['Shopping','expense'],['Entertainment','expense'],['Health','expense']].forEach(([n,t])=>{if(!cats[n]){try{run('INSERT INTO categories(user_id,name,type,created_at) VALUES(?,?,?,?)',[uid,n,t,now()]);cats[n]=scalar('SELECT id FROM categories WHERE user_id=? AND name=?',[uid,n]);}catch(e){}}});const data=[['income',50000,'Salary','2026-09-01','Monthly salary'],['income',15000,'Freelance','2026-09-04','Video editing client'],['income',5000,'Scholarship','2026-09-06','University scholarship'],['expense',12000,'Rent','2026-09-02','Monthly accommodation'],['expense',5200,'Food','2026-09-03','Groceries and dining'],['expense',3500,'Education','2026-09-05','Books and project materials'],['expense',2200,'Utilities','2026-09-07','Internet and electricity'],['expense',1800,'Transport','2026-09-09','Bus and ride sharing'],['expense',2500,'Shopping','2026-09-11','Clothing and supplies'],['expense',1200,'Entertainment','2026-09-12','Movies and outings'],['expense',900,'Health','2026-09-13','Pharmacy']];data.forEach(([t,a,c,d,desc])=>run('INSERT INTO transactions(user_id,type,amount,category_id,transaction_date,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',[uid,t,a,cats[c],d,desc,now(),now()]));res.json({ok:true});});

app.use(express.static(path.join(__dirname,'..','dist')));
app.get('/*splat',(req,res,next)=>{if(req.path.startsWith('/api/'))return next();res.sendFile(path.join(__dirname,'..','dist','index.html'));});

init().catch(e=>{console.error(e);process.exit(1)});
