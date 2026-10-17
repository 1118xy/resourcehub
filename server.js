#!/usr/bin/env node
/**
 * 资源上传平台 - 后端服务器（零依赖 Node.js）
 *
 * 功能：
 *  - 用户注册（手机号 + 密码 + 确认密码）/ 登录（手机号、QQ邮箱）
 *  - 微信 / QQ 第三方登录接口（预留 OAuth 回调，OpenID 入库）
 *  - 作者编号 001/002... 顺序分配，防止假账号冒充
 *  - 文件上传：大小限制 + 扩展名白名单 + SHA256 黑名单比对 + 启发式病毒扫描
 *  - 危险文件自动拉黑名单（禁止下载、禁止再次上传）
 *  - 每个用户每天最多上传 5 个文件
 *  - 资源广场：列表 / 按类型筛选 / 搜索 / 分页
 *  - 下载鉴权（需登录） + 下载次数统计
 *
 * 运行：node server.js  （监听 0.0.0.0:3000，可用环境变量 PORT 修改）
 * 部署：见 README.md
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ===================== 配置 =====================
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = process.env.SECRET || 'resource-hub-secret-2026';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_SIZE = 200 * 1024 * 1024;      // 单文件 200MB
const DAILY_UPLOAD_LIMIT = 5;                  // 普通用户每人每天上传上限
const VIP_DAILY_UPLOAD_LIMIT = 20;             // 会员每人每天上传上限
const VIP_DAY_MS = 24 * 3600 * 1000;           // 会员券 = 1 天会员使用权
const VIP_MONTH_MS = 30 * 24 * 3600 * 1000;    // 会员充值 5 元 = 30 天会员使用权
const QUOTA_FREE = 1 * 1024 * 1024 * 1024;     // 免费云盘 1GB
const QUOTA_VIP = 100 * 1024 * 1024 * 1024;    // 会员云盘 100GB（兼容旧会员）
const TOKEN_TTL = 90 * 24 * 3600 * 1000;        // token 有效期 90 天（登录后 3 个月内不用重复登录）
const BACKUP_DIR = path.join(__dirname, 'backups');   // 自动备份目录
const BACKUP_KEEP_DAYS = 30;                           // 备份保留 30 天

// ===================== 小善专属VIP 会员计划 =====================
// basic: 5 元/30 天 → 5GB；pro: 10 元/30 天 → 100GB
const VIP_PLANS = {
  basic: { id: 'basic', name: '小善专属VIP·基础', price: 5,  festivalDiscount: 3, storageGB: 5,   days: 30 },
  pro:   { id: 'pro',   name: '小善专属VIP·高级', price: 10, festivalDiscount: 5, storageGB: 100, days: 30 },
};
// 国家法定节假日（按日历自动生效，节日当天 ±1 天享优惠价）
const FESTIVALS = [
  { name: '元旦',   dates: ['2026-01-01', '2027-01-01', '2028-01-01'] },
  { name: '春节',   dates: ['2026-02-17', '2027-02-06', '2028-01-26'] },
  { name: '清明节', dates: ['2026-04-05', '2027-04-05', '2028-04-04'] },
  { name: '劳动节', dates: ['2026-05-01', '2027-05-01', '2028-05-01'] },
  { name: '端午节', dates: ['2026-06-19', '2027-06-09', '2028-05-31'] },
  { name: '中秋节', dates: ['2026-09-25', '2027-09-15', '2028-10-03'] },
  { name: '国庆节', dates: ['2026-10-01', '2027-10-01', '2028-10-01'] },
];

// 在线人数统计：uid → 最后活跃时间（有请求就算活跃）
const activeUsers = new Map();

// 允许上传的文件类型（扩展名白名单）
const ALLOWED_EXT = new Set([
  'apk', 'exe', 'txt', 'html', 'htm', 'zip', 'rar', '7z', 'pdf',
  'mp4', 'mp3', 'jpg', 'jpeg', 'png', 'gif', 'js', 'bat', 'sh',
  'csv', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'json', 'md',
  // 视频 / 音频 / 录音
  'm4v', 'avi', 'mkv', 'mov', 'wmv', 'webm', '3gp', 'flv', 'ts',
  'm4a', 'wav', 'aac', 'amr', 'ogg', 'flac', 'opus', 'mid', 'midi',
]);

// 危险权限特征（APK 启发式）
const DANGER_PERMS = [
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.ACCESSIBILITY_SERVICE',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.DEVICE_ADMIN',
  'android.permission.RECEIVE_BOOT_COMPLETED',
  'android.permission.CALL_PHONE',
];

// EXE 危险 API 特征
const DANGER_API = [
  'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
  'SetWindowsHookEx', 'WinExec', 'URLDownloadToFile', 'ShellExecute',
  'powershell', 'cmd.exe /c', 'certutil', 'bitsadmin', 'mshta',
  'regsvr32', 'wscript', 'cscript', '-enc', 'base64 -d',
];

// 网页脚本危险特征
const DANGER_HTML = [
  'eval(', 'atob(', 'document.cookie', 'webhook', 'telegram',
  'crypto miner', 'coinhive', 'keylog', 'document.write',
];

// ===================== 数据持久化 =====================
function loadJson(file, def) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { console.error('[数据文件损坏，已重置]', file, e.message); }
  return def;
}
function saveJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const usersFile = path.join(DATA_DIR, 'users.json');
const resFile = path.join(DATA_DIR, 'resources.json');
const blackFile = path.join(DATA_DIR, 'blacklist.json');
const uploadsFile = path.join(DATA_DIR, 'uploads.json');
const messagesFile = path.join(DATA_DIR, 'messages.json');
const rechargesFile = path.join(DATA_DIR, 'recharges.json');
const scansFile = path.join(DATA_DIR, 'scan_sessions.json');
const cardsFile = path.join(DATA_DIR, 'cards.json');       // 会员卡密库 { "XS-XXXX-...": { plan, used, usedBy, usedAt } }

let users = loadJson(usersFile, []);
let resources = loadJson(resFile, []);
let blacklist = loadJson(blackFile, []);
let uploadsLog = loadJson(uploadsFile, {});   // { "2026-10-15": { "userId": 3 } }
let messages = loadJson(messagesFile, []);    // [{ id, from, fromName, to, content, time, read }]
let recharges = loadJson(rechargesFile, []);  // 会员充值核验申请
let scanSessions = loadJson(scansFile, {});   // { code: { uid, vcode, exp } }
let cards = loadJson(cardsFile, {});          // 会员卡密库

function persistAll() {
  saveJson(usersFile, users);
  saveJson(resFile, resources);
  saveJson(blackFile, blacklist);
  saveJson(uploadsFile, uploadsLog);
  saveJson(messagesFile, messages);
  saveJson(rechargesFile, recharges);
  saveJson(scansFile, scanSessions);
  saveJson(cardsFile, cards);
}

/** 自动备份：把全部数据打包成一份 data.json，每天一个备份目录，保留最近 30 天 */
function backupNow() {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const day = localDateStr();
    const dir = path.join(BACKUP_DIR, 'backup-' + day);
    fs.mkdirSync(dir, { recursive: true });
    const bundle = {
      createdAt: new Date().toISOString(),
      users, resources, blacklist, uploadsLog, messages, recharges, scanSessions, cards,
    };
    fs.writeFileSync(path.join(dir, 'data.json'), JSON.stringify(bundle, null, 2));
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({
      createdAt: new Date().toISOString(), users: users.length, resources: resources.length,
    }, null, 2));
    // 清理超过保留天数的旧备份
    const cutoff = Date.now() - BACKUP_KEEP_DAYS * 86400000;
    for (const name of fs.readdirSync(BACKUP_DIR)) {
      const m = /^backup-(\d{4}-\d{2}-\d{2})$/.exec(name);
      if (m) {
        const t = new Date(m[1] + 'T00:00:00Z').getTime();
        if (t < cutoff) fs.rmSync(path.join(BACKUP_DIR, name), { recursive: true, force: true });
      }
    }
    console.log('[自动备份] ' + day + ' 完成（用户 ' + users.length + ' / 资源 ' + resources.length + '）');
    return true;
  } catch (e) {
    console.error('[自动备份失败]', e.message);
    return false;
  }
}

// ===================== 工具函数 =====================
function uid(len = 12) {
  return crypto.randomBytes(len).toString('hex');
}
function hashPwd(pwd, salt) {
  return crypto.scryptSync(pwd, salt, 64).toString('hex');
}
function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + TOKEN_TTL })).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}
function verifyToken(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    const expect = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (sig !== expect) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    if (Date.now() > data.exp) return null;
    return data.uid;
  } catch (e) { return null; }
}
function nextAuthorNo() {
  return String(users.length + 1).padStart(3, '0');
}
function today() {
  return new Date().toISOString().slice(0, 10);
}
function todayCount(userId) {
  return (uploadsLog[today()] && uploadsLog[today()][userId]) || 0;
}
function addUploadCount(userId) {
  uploadsLog[today()] = uploadsLog[today()] || {};
  uploadsLog[today()][userId] = (uploadsLog[today()][userId] || 0) + 1;
}
// -------- 会员 / 签到 --------
function isVip(u) {
  return !!(u.vipUntil && new Date(u.vipUntil).getTime() > Date.now());
}
function vipExpireAt(u) {
  return isVip(u) ? u.vipUntil : '';
}
function dailyLimitFor(u) {
  return isVip(u) ? VIP_DAILY_UPLOAD_LIMIT : DAILY_UPLOAD_LIMIT;
}
function unusedCoupons(u) {
  return (u.vipCoupons || []).filter((c) => !c.used);
}
function ensureVipFields(u) {
  if (u.vipUntil === undefined) u.vipUntil = '';
  if (!Array.isArray(u.vipCoupons)) u.vipCoupons = [];
  if (!u.lastSignin) u.lastSignin = '';
  if (u.vipPlan === undefined) u.vipPlan = '';   // 旧会员无档位 → 默认按高级(pro) 100GB，不降级
  return u;
}
/** 用户云盘已用字节数（其名下资源总大小） */
function storageUsed(userId) {
  return resources.filter((r) => r.authorId === userId).reduce((a, r) => a + (r.size || 0), 0);
}
/** 云盘配额：免费 1GB；小善专属VIP·基础 5GB；VIP·高级 100GB（旧会员兼容 100GB） */
function quotaFor(u) {
  if (!isVip(u)) return QUOTA_FREE;
  const plan = VIP_PLANS[u.vipPlan] || VIP_PLANS.pro;
  return plan.storageGB * 1024 * 1024 * 1024;
}
/** 本地日期（中国时区 YYYY-MM-DD），节日按本地日历判断 */
function localDateStr() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
/** 当前是否处于国家法定节假日优惠窗口（节日当天 ±1 天） */
function festivalToday() {
  const d = localDateStr();
  const t = new Date(d + 'T00:00:00Z').getTime();
  for (const f of FESTIVALS) {
    for (const ds of f.dates) {
      const c = new Date(ds + 'T00:00:00Z').getTime();
      if (Math.abs(t - c) <= 86400000) return { active: true, name: f.name, date: d };
    }
  }
  return { active: false, name: '', date: d };
}
/** 生成会员卡密：XS-XXXXXX-XXXXXX-XXXXXX */
function genCardCode() {
  const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return 'XS-' + seg() + '-' + seg() + '-' + seg();
}
/** 自动命名：001=作者，002=助理，其他=作者+编号 */
function defaultNickname(authorNo) {
  if (authorNo === '001') return '作者';
  if (authorNo === '002') return '助理';
  return '作者' + authorNo;
}
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function fmtSize(n) {
  if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GB';
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}
function getExt(name) {
  const m = /\.([A-Za-z0-9]+)$/.exec(name || '');
  return m ? m[1].toLowerCase() : '';
}
function publicUser(u) {
  return {
    id: u.id, nickname: u.nickname, authorNo: u.authorNo,
    phone: u.phone ? u.phone.replace(/^(\d{3})\d{4}(\d{4})$/, '$1****$2') : '',
    email: u.email || '', avatar: u.avatar || '',
  };
}
function publicRes(r) {
  return {
    id: r.id, title: r.title, fileName: r.fileName, fileType: r.fileType,
    size: r.size, sha256: r.sha256.slice(0, 16) + '…',
    authorId: r.authorId, authorNo: r.authorNo, authorName: r.authorName,
    status: r.status, scanReport: r.scanReport, downloads: r.downloads,
    createdAt: r.createdAt,
    key: r.key || '',
    // 密钥只展示编号（前 4 位 + ****），完整密钥不可查看
    displayKey: (r.key || '??????').slice(0, 4) + '****',
  };
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ===================== 病毒扫描引擎 =====================
function scanFile(fileName, size, buffer) {
  const ext = getExt(fileName);
  const report = [];
  let danger = false;
  let susp = false;

  // 1. 大小限制
  if (size > MAX_FILE_SIZE) {
    return { status: 'dangerous', reason: '文件超过 200MB 大小限制', report: ['超过大小限制'] };
  }
  // 2. 扩展名白名单
  if (!ALLOWED_EXT.has(ext)) {
    return { status: 'dangerous', reason: `不允许上传 .${ext || '未知'} 类型文件`, report: ['扩展名不在白名单'] };
  }
  // 3. EICAR 标准病毒测试样本（国际防病毒标准特征串，命中即视为病毒）
  const latin = buffer.toString('latin1');
  if (latin.includes('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')) {
    return { status: 'dangerous', reason: '检测到 EICAR 标准病毒测试特征（视为病毒），已拉入黑名单', report: ['命中 EICAR 病毒特征'] };
  }
  // 4. SHA256 黑名单比对
  const hash = sha256(buffer);
  const hit = blacklist.find((b) => b.sha256 === hash);
  if (hit) {
    return { status: 'dangerous', reason: `命中已知危险文件黑名单（${hit.reason}）`, report: ['命中黑名单哈希'] };
  }
  // 4. 文件头（magic bytes）与扩展名一致性
  const magic = buffer.slice(0, 8).toString('hex');
  const isZip = magic.startsWith('504b0304') || magic.startsWith('504b0506');
  const isMZ = magic.startsWith('4d5a');
  const isELF = magic.startsWith('7f454c46');
  const isText = !isZip && !isMZ && !isELF;

  if (ext === 'apk') {
    if (!isZip) { danger = true; report.push('危险：不是有效的 APK/ZIP 文件（文件头不符）'); }
    const text = buffer.toString('latin1');
    let permHits = 0;
    const hits = [];
    for (const p of DANGER_PERMS) {
      if (text.includes(p)) { permHits++; hits.push(p.split('.').pop()); }
    }
    if (permHits >= 5) { susp = true; report.push(`存疑：申请敏感权限过多（${hits.join('、')}）`); }
    if (text.includes('Runtime.getRuntime().exec') && permHits >= 3) {
      susp = true; report.push('存疑：含动态执行代码且申请多项敏感权限');
    }
    if (!danger && permHits === 0 && !text.includes('AndroidManifest')) {
      susp = true; report.push('存疑：APK 结构异常（未识别到清单信息）');
    }
  } else if (ext === 'exe' || ext === 'bat' || ext === 'sh') {
    if (ext === 'exe' && !isMZ) { danger = true; report.push('危险：不是有效的 EXE(PE) 文件（缺少 MZ 文件头）'); }
    const text = buffer.toString('latin1');
    if (ext === 'exe' && text.includes('UPX0')) { susp = true; report.push('存疑：检测到 UPX 加壳压缩'); }
    let apiHits = [];
    for (const a of DANGER_API) {
      if (text.includes(a)) apiHits.push(a);
    }
    if (apiHits.length >= 2) { danger = true; report.push(`危险：包含恶意行为 API（${apiHits.join('、')}）`); }
    else if (apiHits.length === 1) { susp = true; report.push(`存疑：包含敏感操作特征（${apiHits[0]}）`); }
    if (ext === 'bat' || ext === 'sh') {
      if (/powershell|curl.*-o|wget.*-O|bitsadmin|certutil/.test(text)) {
        danger = true; report.push('危险：脚本包含下载并执行外部程序的行为');
      }
    }
  } else if (ext === 'html' || ext === 'htm' || ext === 'js') {
    const text = buffer.toString('utf8');
    if (!/<\/?html/i.test(text) && !/^[\s\S]*<\//.test(text) && text.includes('<script')) {
      susp = true; report.push('存疑：HTML 结构异常但包含脚本');
    }
    let hits = [];
    for (const h of DANGER_HTML) if (text.toLowerCase().includes(h)) hits.push(h);
    if (text.toLowerCase().includes('coinhive') || /miner|mining\.start/.test(text)) {
      danger = true; report.push('危险：检测到网页挖矿脚本');
    }
    if (hits.length >= 2 && (text.toLowerCase().includes('webhook') || text.toLowerCase().includes('document.cookie'))) {
      danger = true; report.push(`危险：疑似盗取账号/信息的恶意脚本（${hits.join('、')}）`);
    } else if (hits.length >= 1) {
      susp = true; report.push(`存疑：包含混淆/敏感脚本特征（${hits.join('、')}）`);
    }
  } else if (ext === 'txt') {
    if (isZip || isMZ || isELF) { susp = true; report.push('存疑：文本文件内嵌可执行文件内容'); }
    const lines = buffer.toString('utf8').split('\n');
    const longest = Math.max(...lines.map((l) => l.length));
    if (longest > 8000) { susp = true; report.push('存疑：包含超长单行内容（疑似混淆数据）'); }
  } else if (ext === 'zip' || ext === 'rar' || ext === '7z') {
    const text = buffer.toString('latin1');
    if (ext === 'zip' && !isZip) { danger = true; report.push('危险：不是有效的 ZIP 压缩包'); }
    if (text.includes('../') || text.includes('..\\')) { susp = true; report.push('存疑：压缩包内含路径穿越条目'); }
    if (/(\.exe|\.scr|\.vbs|\.bat|\.cmd)(\x00|\x01)/.test(text)) { susp = true; report.push('存疑：压缩包内含可执行文件条目'); }
  } else if (isZip && ext !== 'zip') {
    susp = true; report.push('存疑：文件实际为 ZIP 压缩格式，与扩展名不符');
  }

  if (danger) return { status: 'dangerous', reason: report[0] || '检测到危险内容', report };
  if (susp) return { status: 'suspicious', reason: report[0] || '存在可疑特征', report };
  return { status: 'safe', reason: '扫描通过', report: ['未发现病毒或危险特征，安全'] };
}

// ===================== HTTP 服务器 =====================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  const method = req.method;

  const send = (code, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Token,X-File-Name,X-File-Size,Authorization',
    });
    res.end(body);
  };
  if (method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // 请求体（JSON 或 原始文件流）
  const getAuth = () => {
    const t = req.headers['x-token'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const userId = verifyToken(t);
    const user = userId ? users.find((u) => u.id === userId) : null;
    if (user) activeUsers.set(user.id, Date.now());
    return user;
  };

  try {
    // ---------- 健康检查 ----------
    if (method === 'GET' && p === '/api/health') {
      return send(200, { ok: true, time: new Date().toISOString(), version: '1.0.0', dailyLimit: DAILY_UPLOAD_LIMIT });
    }

    // ---------- 服务器统计（在线人数 / 注册 / 资源 / 下载） ----------
    if (method === 'GET' && p === '/api/stats') {
      const now = Date.now();
      let active15 = 0, active60 = 0;
      for (const ts of activeUsers.values()) {
        if (now - ts < 15 * 60 * 1000) active15++;
        if (now - ts < 60 * 60 * 1000) active60++;
      }
      const todayUploads = Object.values(uploadsLog[today()] || {}).reduce((a, b) => a + b, 0);
      return send(200, {
        totalUsers: users.length,
        totalResources: resources.length,
        totalDownloads: resources.reduce((a, r) => a + (r.downloads || 0), 0),
        todayUploads,
        active15min: active15,
        active60min: active60,
        serverTime: new Date().toISOString(),
        uptimeSec: Math.floor(process.uptime()),
      });
    }

    // ---------- 注册 ----------
    if (method === 'POST' && p === '/api/register') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const { phone, password, confirmPassword, email } = body;
      if (!/^1[3-9]\d{9}$/.test(phone || '')) return send(400, { error: '请输入正确的 11 位手机号' });
      if (!password || password.length < 6) return send(400, { error: '密码至少需要 6 位' });
      if (password !== confirmPassword) return send(400, { error: '两次输入的密码不一致' });
      if (email && !/^[\w.+-]+@[\w-]+(\.[\w-]+)+$/.test(email)) return send(400, { error: '邮箱格式不正确' });
      if (users.some((u) => u.phone === phone)) return send(400, { error: '该手机号已注册，请直接登录' });
      if (email && users.some((u) => u.email === email)) return send(400, { error: '该邮箱已被使用' });

      const salt = crypto.randomBytes(16).toString('hex');
      const an = nextAuthorNo();
      const user = ensureVipFields({
        id: uid(), phone, email: email || '',
        salt, passwordHash: hashPwd(password, salt),
        nickname: defaultNickname(an), authorNo: an,
        avatar: '', wechatOpenid: '', qqOpenid: '', createdAt: new Date().toISOString(),
      });
      users.push(user);
      persistAll();
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 登录（手机号 / QQ邮箱） ----------
    if (method === 'POST' && p === '/api/login') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const { account, password, mode } = body;
      if (!account || !password) return send(400, { error: '请输入账号和密码' });
      const user = mode === 'email'
        ? users.find((u) => u.email === account.toLowerCase())
        : users.find((u) => u.phone === account);
      if (!user) return send(404, { error: '账号不存在，请先注册' });
      if (!user.passwordHash) return send(403, { error: '该账号是微信/QQ快速登录账号，请使用「快速登录」进入' });
      if (user.passwordHash !== hashPwd(password, user.salt)) return send(401, { error: '密码错误' });
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 快速登录（微信 / QQ 模拟授权快速通道，点即登：无需填任何资料） ----------
    // 点击微信/QQ → 自动创建/登录账号（编号自动分配：001=作者，002=助理…），手机号/邮箱/名称都不用填
    if (method === 'POST' && p === '/api/login/quick') {
      const body = JSON.parse((await readBody(req, 4 << 20)).toString('utf8') || '{}');
      const { channel, phone, email, nickname, avatar } = body;
      if (!['wechat', 'qq', 'guest'].includes(channel)) return send(400, { error: '快速通道类型错误' });
      if (phone && !/^1[3-9]\d{9}$/.test(phone)) return send(400, { error: '请输入正确的 11 位手机号' });
      if (email && !/^[\w.+-]+@[\w-]+(\.[\w-]+)+$/.test(email)) return send(400, { error: '邮箱格式不正确' });
      if (nickname && (nickname.length < 1 || nickname.length > 16)) return send(400, { error: '名称需 1-16 个字' });
      if (avatar && avatar.length > 500 * 1024) return send(400, { error: '头像图片过大' });

      // 设备唯一标识：同一台手机同一通道再次快速登录 → 回到原账号（不再每次新建）
      // openid 约定：quick-<channel>-<deviceId>
      const deviceId = String(body.deviceId || '').trim();
      const openidKey = deviceId ? `quick-${channel}-${deviceId}` : '';

      let user = null;
      if (phone) {
        // 有手机号：按手机号查找或创建
        user = users.find((u) => u.phone === phone);
      } else if (openidKey) {
        // 有设备标识：按 通道+设备 查找该设备的原账号
        user = users.find((u) =>
          (channel === 'wechat' ? u.wechatOpenid : channel === 'qq' ? u.qqOpenid : u.qqOpenid) === openidKey ||
          (channel === 'guest' && (u.qqOpenid === openidKey || u.wechatOpenid === openidKey))
        );
      } else {
        // 无手机号也无设备标识：创建独立账号（旧逻辑兜底）
        const legacyOpenid = 'quick-' + channel + '-auto-' + uid(6);
        user = users.find((u) => (channel === 'wechat' ? u.wechatOpenid : u.qqOpenid) === legacyOpenid);
      }

      if (!user) {
        const authorNo = nextAuthorNo();
        const autoOpenid = phone ? 'quick-' + phone : openidKey || ('quick-' + channel + '-auto-' + uid(6));
        user = ensureVipFields({
          id: uid(), phone: phone || '', email: email || '', salt: '', passwordHash: '',
          nickname: nickname || (phone ? (channel === 'wechat' ? '微信用户' : 'QQ用户') : defaultNickname(authorNo)),
          authorNo, avatar: avatar || '',
          wechatOpenid: channel === 'wechat' ? autoOpenid : '',
          qqOpenid: channel === 'qq' || channel === 'guest' ? autoOpenid : '',
          createdAt: new Date().toISOString(),
        });
        users.push(user);
      } else {
        // 已存在：更新可填资料
        if (email) user.email = email;
        if (nickname) user.nickname = nickname;
        if (avatar) user.avatar = avatar;
        if (channel === 'wechat' && !user.wechatOpenid) user.wechatOpenid = phone ? 'quick-' + phone : (openidKey || 'quick-wechat-auto');
        if (channel === 'qq' && !user.qqOpenid) user.qqOpenid = phone ? 'quick-' + phone : (openidKey || 'quick-qq-auto');
        if (channel === 'guest' && !user.qqOpenid && !user.wechatOpenid) user.qqOpenid = openidKey;
        if (!user.passwordHash) user.salt = '';
      }
      persistAll();
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 第三方登录（微信 / QQ，OAuth 成功后回传 OpenID） ----------
    if (method === 'POST' && p === '/api/login/third') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const { platform, openid, nickname, avatar } = body;
      if (!['wechat', 'qq'].includes(platform) || !openid) return send(400, { error: '缺少第三方登录参数' });
      const field = platform === 'wechat' ? 'wechatOpenid' : 'qqOpenid';
      let user = users.find((u) => u[field] === openid);
      if (!user) {
        user = ensureVipFields({
          id: uid(), phone: '', email: '', salt: '', passwordHash: '',
          nickname: nickname || (platform === 'wechat' ? '微信用户' : 'QQ用户'),
          authorNo: nextAuthorNo(), avatar: avatar || '',
          wechatOpenid: platform === 'wechat' ? openid : '',
          qqOpenid: platform === 'qq' ? openid : '',
          createdAt: new Date().toISOString(),
        });
        users.push(user);
        persistAll();
      }
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 当前用户（含会员 / 签到状态） ----------
    if (method === 'GET' && p === '/api/me') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      ensureVipFields(user);
      const limit = dailyLimitFor(user);
      const left = limit - todayCount(user.id);
      return send(200, {
        user: publicUser(user),
        todayUploaded: todayCount(user.id), uploadLeft: Math.max(0, left), dailyLimit: limit,
        isVip: isVip(user), vipUntil: vipExpireAt(user), vipPlan: isVip(user) ? (user.vipPlan || 'pro') : '',
        todaySigned: user.lastSignin === today(),
        couponCount: unusedCoupons(user).length,
        coupons: unusedCoupons(user).map((c) => ({ id: c.id, createdAt: c.createdAt })),
        storageUsed: storageUsed(user.id), storageQuota: quotaFor(user),
      });
    }

    // ---------- VIP 会员方案与节日优惠价（App 会员中心展示） ----------
    if (method === 'GET' && p === '/api/vip/plans') {
      const f = festivalToday();
      const plans = Object.values(VIP_PLANS).map((pl) => {
        const discount = f.active ? pl.festivalDiscount : 0;
        return {
          id: pl.id, name: pl.name, price: pl.price, days: pl.days, storageGB: pl.storageGB,
          discount, finalPrice: Math.max(0, pl.price - discount), onSale: f.active,
        };
      });
      return send(200, { plans, festival: f });
    }

    // ---------- 管理员生成会员卡密（仅作者 001） ----------
    if (method === 'POST' && p === '/api/vip/gencards') {
      const admin = getAuth();
      if (!admin) return send(401, { error: '未登录或登录已过期' });
      if (admin.authorNo !== '001') return send(403, { error: '仅管理员(作者001)可生成卡密' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const plan = VIP_PLANS[body.plan];
      if (!plan) return send(400, { error: '卡密档位必须为 basic 或 pro' });
      const count = Math.min(Math.max(parseInt(body.count, 10) || 1, 1), 100);
      const out = [];
      for (let i = 0; i < count; i++) {
        const code = genCardCode();
        cards[code] = { plan: plan.id, used: false, usedBy: '', usedAt: '', createdAt: new Date().toISOString() };
        out.push(code);
      }
      persistAll();
      return send(200, { message: `已生成 ${count} 张「${plan.name}」卡密`, cards: out, plan: plan.id });
    }

    // ---------- 卡密兑换（输入卡密 → 开通 VIP） ----------
    if (method === 'POST' && p === '/api/vip/redeem') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const code = String(body.card || '').trim().toUpperCase();
      const card = cards[code];
      if (!card) return send(404, { error: '卡密不存在，请检查是否输错' });
      if (card.used) return send(400, { error: '该卡密已被使用，无法重复兑换' });
      const plan = VIP_PLANS[card.plan];
      if (!plan) return send(400, { error: '卡密档位无效' });
      ensureVipFields(user);
      const base = isVip(user) ? new Date(user.vipUntil).getTime() : Date.now();
      user.vipUntil = new Date(base + plan.days * 86400000).toISOString();
      user.vipPlan = plan.id;
      card.used = true;
      card.usedBy = user.authorNo || user.id;
      card.usedAt = new Date().toISOString();
      persistAll();
      return send(200, { message: `兑换成功！「${plan.name}」已开通 ${plan.days} 天`, vipUntil: user.vipUntil, vipPlan: plan.id, isVip: true });
    }

    // ---------- 每日签到（领 1 张会员券） ----------
    if (method === 'POST' && p === '/api/signin') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      ensureVipFields(user);
      if (user.lastSignin === today()) return send(400, { error: '今天已经签过到了，明天再来吧' });
      user.lastSignin = today();
      user.vipCoupons.push({ id: uid(), createdAt: new Date().toISOString(), used: false });
      persistAll();
      return send(200, { message: '签到成功，获得 1 张会员券', todaySigned: true, couponCount: unusedCoupons(user).length });
    }

    // ---------- 使用会员券（获得 1 天会员使用权） ----------
    if (method === 'POST' && p === '/api/coupon/use') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      ensureVipFields(user);
      const coupon = (user.vipCoupons || []).find((c) => !c.used);
      if (!coupon) return send(400, { error: '没有可用的会员券，先去签到领取吧' });
      coupon.used = true;
      coupon.usedAt = new Date().toISOString();
      const base = isVip(user) ? new Date(user.vipUntil).getTime() : Date.now();
      user.vipUntil = new Date(base + VIP_DAY_MS).toISOString();
      persistAll();
      return send(200, { message: '会员券已使用，获得 1 天会员使用权', vipUntil: user.vipUntil, couponCount: unusedCoupons(user).length });
    }

    // ---------- 会员充值核验申请（扫码付 5 元 → 上传转账截图 → 管理员核验） ----------
    if (method === 'POST' && p === '/api/vip/recharge') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const body = JSON.parse((await readBody(req, 4 << 20)).toString('utf8') || '{}');
      const name = String(body.name || '').trim();
      const amount = parseFloat(body.amount);
      const evidence = String(body.evidence || '');
      if (!name || name.length > 32) return send(400, { error: '请填写收款名称' });
      if (!(amount > 0)) return send(400, { error: '请填写充值金额' });
      if (!evidence || evidence.length < 100 || !evidence.startsWith('data:image')) return send(400, { error: '请上传转账成功的截图（相册图片）' });
      if (evidence.length > 4 * 1024 * 1024) return send(400, { error: '截图过大' });
      const rec = { id: uid(), userId: user.id, authorNo: user.authorNo, name, amount, evidence,
        status: 'pending', createdAt: new Date().toISOString() };
      recharges.push(rec);
      persistAll();
      return send(200, { message: '充值核验申请已提交，等待管理员确认（客服 QQ：1218742069）', id: rec.id });
    }

    // ---------- 管理员查看充值申请列表 ----------
    if (method === 'GET' && p === '/api/vip/recharges') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      if (user.authorNo !== '001') return send(403, { error: '仅管理员可查看' });
      const list = recharges.slice(-50).reverse().map((r) => ({
        id: r.id, authorNo: r.authorNo, name: r.name, amount: r.amount,
        status: r.status, createdAt: r.createdAt,
      }));
      return send(200, { total: recharges.length, items: list });
    }

    // ---------- 管理员核验充值（通过 → 会员 30 天） ----------
    if (method === 'POST' && p === '/api/vip/verify') {
      const admin = getAuth();
      if (!admin) return send(401, { error: '未登录或登录已过期' });
      if (admin.authorNo !== '001') return send(403, { error: '仅管理员可核验' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const rec = recharges.find((r) => r.id === body.id);
      if (!rec) return send(404, { error: '申请不存在' });
      if (rec.status !== 'pending') return send(400, { error: '该申请已处理' });
      if (body.pass === false) {
        rec.status = 'rejected';
        rec.reviewedAt = new Date().toISOString();
        persistAll();
        return send(200, { message: '已拒绝该充值申请' });
      }
      const u = users.find((x) => x.id === rec.userId);
      if (!u) return send(404, { error: '申请用户不存在' });
      ensureVipFields(u);
      const base = isVip(u) ? new Date(u.vipUntil).getTime() : Date.now();
      u.vipUntil = new Date(base + VIP_MONTH_MS).toISOString();
      rec.status = 'approved';
      rec.reviewedAt = new Date().toISOString();
      persistAll();
      return send(200, { message: '已核验通过，会员已开通 30 天', vipUntil: u.vipUntil });
    }

    // ---------- 扫码登录（匿名）：登录页「展开」生成登录二维码 ----------
    // 新设备(未登录)请求：生成 sid+随机验证码，等待已登录账号扫码确认
    if (method === 'POST' && p === '/api/scan/anonymous') {
      const sid = uid(6).toUpperCase();
      const vcode = String(crypto.randomInt(100000, 999999));
      scanSessions[sid] = { uid: null, vcode, exp: Date.now() + 5 * 60 * 1000 };
      persistAll();
      return send(200, { sid, vcode, expireSec: 300, url: `resourcehub://scanlogin?sid=${sid}` });
    }

    // ---------- 扫码登录（确认）：已登录账号扫新设备的二维码 + 输入验证码 → 绑定 ----------
    if (method === 'POST' && p === '/api/scan/confirm') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const sid = String(body.sid || '').trim().toUpperCase();
      const vcode = String(body.vcode || '').trim();
      const s = scanSessions[sid];
      if (!s) return send(400, { error: '登录码不存在或已过期' });
      if (Date.now() > s.exp) return send(400, { error: '登录码已过期，请重新生成' });
      if (s.vcode !== vcode) return send(401, { error: '验证码不正确' });
      if (s.uid) return send(400, { error: '该二维码已被确认，请重新生成' });
      s.uid = user.id;
      persistAll();
      return send(200, { ok: true, message: '已确认，对方设备将自动登录' });
    }

    // ---------- 扫码登录（轮询）：新设备等待确认结果，成功后自动登录 ----------
    if (method === 'GET' && p === '/api/scan/poll') {
      const qs = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams;
      const sid = String(qs.get('sid') || '').trim().toUpperCase();
      const s = scanSessions[sid];
      if (!s || Date.now() > s.exp) return send(400, { error: '登录码不存在或已过期' });
      if (!s.uid) return send(200, { status: 'waiting' });
      const user = users.find((u) => u.id === s.uid);
      if (!user) return send(404, { error: '账号不存在' });
      delete scanSessions[sid];
      persistAll();
      return send(200, { status: 'ok', token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 扫码登录：已登录设备生成登录码 ----------
    if (method === 'POST' && p === '/api/scan/gen') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const code = uid(4).toUpperCase();
      const vcode = String(crypto.randomInt(100000, 999999));
      scanSessions[code] = { uid: user.id, vcode, exp: Date.now() + 5 * 60 * 1000 };
      persistAll();
      return send(200, { code, vcode, expireSec: 300, url: `resourcehub://scan?code=${code}` });
    }

    // ---------- 扫码登录：另一设备输入 登录码+验证码 登录 ----------
    if (method === 'POST' && p === '/api/scan/login') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const code = String(body.code || '').trim().toUpperCase();
      const vcode = String(body.vcode || '').trim();
      const s = scanSessions[code];
      if (!s) return send(400, { error: '登录码不存在或已过期' });
      if (Date.now() > s.exp) return send(400, { error: '登录码已过期，请重新生成' });
      if (s.vcode !== vcode) return send(401, { error: '验证码不正确' });
      const user = users.find((u) => u.id === s.uid);
      if (!user) return send(404, { error: '账号不存在' });
      delete scanSessions[code];
      persistAll();
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- 收款码图片（网站/App 通用显示） ----------
    if (method === 'GET' && p === '/qr') {
      const file = path.join(__dirname, 'assets', 'wechat_qr.png');
      if (!fs.existsSync(file)) return send(404, { error: '收款码不存在' });
      const buf = fs.readFileSync(file);
      res.writeHead(200, { 'Content-Type': 'image/webp', 'Content-Length': buf.length });
      res.end(buf);
      return;
    }

    // ---------- 修改昵称 ----------
    if (method === 'POST' && p === '/api/profile/update') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const body = JSON.parse((await readBody(req, 4 << 20)).toString('utf8') || '{}');
      const nickname = String(body.nickname || '').trim();
      if (nickname.length < 1 || nickname.length > 16) return send(400, { error: '昵称需为 1-16 个字符' });
      const email = String(body.email || '').trim();
      if (email && !/^[\w.+-]+@[\w-]+(\.[\w-]+)+$/.test(email)) return send(400, { error: '邮箱格式不正确' });
      if (email && users.some((u) => u.email === email && u.id !== user.id)) return send(400, { error: '该邮箱已被使用' });
      const avatar = String(body.avatar || '');
      if (avatar && (avatar.length > 500 * 1024 || !avatar.startsWith('data:image'))) return send(400, { error: '头像图片过大或格式错误' });
      user.nickname = nickname;
      if (email) user.email = email;
      if (avatar) user.avatar = avatar;
      persistAll();
      return send(200, { message: '资料已保存', user: publicUser(user) });
    }

    // ---------- 修改密码（旧密码验证 + 新密码） ----------
    if (method === 'POST' && p === '/api/password/change') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      if (!user.phone) return send(400, { error: '第三方登录账号没有密码，暂不支持修改' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const { oldPassword, newPassword } = body;
      if (!oldPassword || !newPassword) return send(400, { error: '请输入旧密码和新密码' });
      if (user.passwordHash !== hashPwd(oldPassword, user.salt)) return send(401, { error: '旧密码错误' });
      if (String(newPassword).length < 6) return send(400, { error: '新密码至少 6 位' });
      user.salt = crypto.randomBytes(16).toString('hex');
      user.passwordHash = hashPwd(newPassword, user.salt);
      persistAll();
      return send(200, { message: '密码已修改，下次请用新密码登录' });
    }

    // ---------- 资源列表 ----------
    if (method === 'GET' && p === '/api/resources') {
      const type = url.searchParams.get('type') || '';
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
      const pageSize = Math.min(50, Math.max(1, parseInt(url.searchParams.get('pageSize') || '20', 10)));
      let list = resources.filter((r) => r.status !== 'blacklisted');
      if (type) list = list.filter((r) => r.fileType === type);
      if (q) list = list.filter((r) => (r.title + r.fileName + r.authorName + r.authorNo).toLowerCase().includes(q));
      list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const total = list.length;
      const slice = list.slice((page - 1) * pageSize, page * pageSize);
      return send(200, { total, page, pageSize, items: slice.map(publicRes) });
    }

    // ---------- 黑名单公示 ----------
    if (method === 'GET' && p === '/api/blacklist') {
      const list = blacklist.slice(-30).reverse().map((b) => ({
        sha256: b.sha256.slice(0, 16) + '…', fileName: b.fileName, reason: b.reason, addedAt: b.addedAt,
      }));
      return send(200, { total: blacklist.length, items: list });
    }

    // ---------- 我的上传 ----------
    if (method === 'GET' && p === '/api/my/resources') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期' });
      const list = resources.filter((r) => r.authorId === user.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return send(200, { items: list.map(publicRes) });
    }

    // ---------- 上传文件 ----------
    if (method === 'POST' && p === '/api/upload') {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期，请先登录' });
      ensureVipFields(user);
      if (todayCount(user.id) >= dailyLimitFor(user)) {
        return send(429, { error: `今天已达上传上限（${dailyLimitFor(user)} 个），会员每天可上传 ${VIP_DAILY_UPLOAD_LIMIT} 个，签到可领会员券提升额度` });
      }
      const rawName = Buffer.from(req.headers['x-file-name'] || '', 'base64').toString('utf8');
      const fileName = path.basename(rawName || 'unnamed');
      const declaredSize = parseInt(req.headers['x-file-size'] || '0', 10);
      if (declaredSize > MAX_FILE_SIZE) return send(413, { error: '文件超过 200MB 上传限制' });
      if (declaredSize > 0 && storageUsed(user.id) + declaredSize > quotaFor(user)) {
        return send(429, { error: `云盘空间不足：已用 ${fmtSize(storageUsed(user.id))} / ${fmtSize(quotaFor(user))}。免费云盘 1GB，开通「小善专属VIP」可扩容：基础 5 元/30 天=5GB，高级 10 元/30 天=100GB，节假日享优惠价` });
      }
      const buffer = await readBody(req, MAX_FILE_SIZE + (1 << 20));

      if (!fileName) return send(400, { error: '缺少文件名' });
      const ext = getExt(fileName);
      if (!ALLOWED_EXT.has(ext)) return send(400, { error: `不允许上传 .${ext || '未知'} 类型的文件` });

      const scan = scanFile(fileName, buffer.length, buffer);

      if (scan.status === 'dangerous') {
        blacklist.push({ sha256: sha256(buffer), fileName, reason: scan.reason, addedAt: new Date().toISOString() });
        addUploadCount(user.id);
        persistAll();
        return send(200, { status: 'dangerous', reason: scan.reason, report: scan.report, message: '检测到病毒/危险特征，文件已拉入黑名单，禁止下载' });
      }

      // 保存文件
      const id = uid();
      const key = crypto.randomBytes(3).toString('hex').toUpperCase(); // 6位密钥编号
      const storeName = id + '_' + fileName;
      const storePath = path.join(UPLOAD_DIR, storeName);
      fs.writeFileSync(storePath, buffer);

      const resource = {
        id, key, title: fileName.replace(/\.[^.]+$/, ''), fileName, fileType: ext,
        size: buffer.length, sha256: sha256(buffer),
        authorId: user.id, authorNo: user.authorNo, authorName: user.nickname,
        status: scan.status, scanReport: scan.report, downloads: 0,
        createdAt: new Date().toISOString(), storeName,
      };
      resources.push(resource);
      addUploadCount(user.id);
      persistAll();

      const msg = scan.status === 'safe' ? '扫描通过，已发布到资源广场' : '扫描发现可疑特征，已标记为「存疑」，建议人工复核';
      return send(200, { status: scan.status, reason: scan.reason, report: scan.report, message: msg, resource: publicRes(resource) });
    }

    // ---------- 下载 ----------
    if (method === 'GET' && p.startsWith('/api/resource/')) {
      const user = getAuth();
      if (!user) return send(401, { error: '未登录或登录已过期，请先登录' });
      const rid = p.split('/').pop();
      const item = resources.find((r) => r.id === rid);
      if (!item) return send(404, { error: '资源不存在或已下架' });
      if (item.status === 'blacklisted') return send(403, { error: '该资源已被安全卫士拉入黑名单，禁止下载' });
      const filePath = path.join(UPLOAD_DIR, item.storeName);
      if (!fs.existsSync(filePath)) return send(404, { error: '文件丢失，请联系管理员' });

      item.downloads = (item.downloads || 0) + 1;
      persistAll();
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(item.fileName)}`,
        'Content-Length': fs.statSync(filePath).size,
        'X-Resource-Status': item.status,
      });
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    // ---------- 站内消息（跟别人发消息，需登录） ----------
    // 发送：{ "to": "作者编号 如 001", "content": "你好" }
    if (method === 'POST' && p === '/api/message/send') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const target = String(body.to || '').trim();
      const content = String(body.content || '').trim();
      if (!/^\d{3}$/.test(target)) return send(400, { error: '收件人作者编号格式错误（如 001）' });
      if (!content || content.length > 500) return send(400, { error: '消息内容需 1-500 字' });
      const toUser = users.find((u) => u.authorNo === target);
      if (!toUser) return send(404, { error: '作者编号不存在' });
      if (toUser.id === me.id) return send(400, { error: '不能给自己发消息' });
      const msg = {
        id: uid(8),
        from: me.id,
        fromName: me.nickname || '#' + me.authorNo,
        fromAuthorNo: me.authorNo,
        to: toUser.id,
        content,
        time: new Date().toISOString(),
        read: false,
      };
      messages.push(msg);
      saveJson(messagesFile, messages);
      return send(200, { ok: true, message: '消息已发送', id: msg.id });
    }
    // 我的收件箱（发给我的，按时间倒序）
    if (method === 'GET' && p === '/api/messages') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const mine = messages
        .filter((m) => m.to === me.id)
        .sort((a, b) => (a.time < b.time ? 1 : -1))
        .slice(0, 200);
      return send(200, { ok: true, messages: mine, unread: mine.filter((m) => !m.read).length });
    }
    // 标记已读
    if (method === 'POST' && p === '/api/message/read') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const msg = messages.find((m) => m.id === String(body.id || '') && m.to === me.id);
      if (!msg) return send(404, { error: '消息不存在' });
      msg.read = true;
      saveJson(messagesFile, messages);
      return send(200, { ok: true });
    }

    // ---------- 公开链接下载页（英文字母链接，浏览器直接打开，真实有效） ----------
    if (method === 'GET' && p.startsWith('/d/') && !p.endsWith('/file')) {
      const rid = p.split('/')[2];
      const item = resources.find((r) => r.id === rid);
      if (!item) return send(404, { error: '资源不存在或已下架' });
      const blocked = item.status === 'blacklisted';
      const base = `https://${req.headers.host || 'localhost'}`;
      const fileUrl = `${base}/d/${rid}/file`;

      const esc = (s) => String(s || '').replace(/[&<>"']/g, (c) =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      const typeIcon = (item.fileType || 'file').toUpperCase().slice(0, 4);
      const statusTag = blocked
        ? '<span class="tag danger">BLOCKED</span>'
        : item.status === 'suspicious'
          ? '<span class="tag warn">SUSPICIOUS</span>'
          : '<span class="tag safe">SAFE</span>';
      const fmt = (n) => {
        if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GB';
        if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
        if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
        return n + ' B';
      };

      const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(item.title)} - 下载</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
         background:linear-gradient(160deg,#0A0E1A 0%,#0E1730 55%,#132A52 100%);
         min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
  .card { background:#FFFFFF; border-radius:18px; max-width:440px; width:100%;
          padding:30px 26px; box-shadow:0 20px 60px rgba(0,0,0,.45); }
  .icon { width:64px; height:64px; border-radius:16px; background:linear-gradient(135deg,#33E6FF,#1677FF);
          display:flex; align-items:center; justify-content:center; color:#fff; font-weight:800;
          font-size:16px; margin-bottom:16px; }
  h1 { font-size:20px; color:#1F2329; word-break:break-all; line-height:1.4; }
  .meta { margin-top:12px; font-size:13px; color:#646A73; line-height:1.9; }
  .meta b { color:#1F2329; font-weight:600; }
  .tag { display:inline-block; padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700; margin-left:6px; }
  .safe { background:#E8F7F0; color:#00B578; }
  .warn { background:#FFF4E6; color:#FF8F1F; }
  .danger { background:#FDECEC; color:#F53F3F; }
  .btn { display:block; text-align:center; padding:14px 0; border-radius:12px; font-size:15px;
         font-weight:700; text-decoration:none; margin-top:18px; }
  .btn-main { background:linear-gradient(90deg,#22A6FF,#00E5C8); color:#fff; }
  .btn-ghost { border:1.5px solid #1677FF; color:#1677FF; margin-top:10px; }
  .tip { margin-top:14px; font-size:11px; color:#9AA0A8; text-align:center; }
  .vip { margin-top:20px; border-top:1px dashed #E4E7EC; padding-top:16px; text-align:center; }
  .vip-title { font-size:14px; color:#1F2329; font-weight:700; }
  .vip-text { margin-top:6px; font-size:12px; color:#646A73; line-height:1.7; }
  .qr-img { margin-top:12px; width:200px; height:auto; border-radius:10px;
            border:1px solid #E4E7EC; box-shadow:0 6px 18px rgba(0,0,0,.08); }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">${esc(typeIcon)}</div>
    <h1>${esc(item.title)}</h1>
    <div class="meta">
      文件名：<b>${esc(item.fileName)}</b><br>
      类型：<b>${esc(item.fileType)}</b> · 大小：<b>${fmt(item.size)}</b><br>
      作者：<b>#${esc(item.authorNo)} ${esc(item.authorName)}</b> · 下载 ${item.downloads || 0} 次<br>
      密钥编号：<b>${esc((item.key || '??????').slice(0, 4))}****</b> · 扫描状态：${statusTag}
    </div>
    ${blocked
      ? '<div style="margin-top:18px;padding:12px;border-radius:10px;background:#FDECEC;color:#F53F3F;font-size:13px;text-align:center;">该文件已被安全卫士拉入黑名单，禁止下载</div>'
      : `<a class="btn btn-main" href="${esc(fileUrl)}">立即下载</a>
         <a class="btn btn-ghost" href="resourcehub://resource?id=${esc(item.id)}">在 App 中打开查看</a>`}
    <div class="tip">链接真实有效 · 由资源上传平台生成</div>
    <div class="vip">
      <div class="vip-title">❤ 支持平台 · 开通小善专属VIP</div>
      <div class="vip-text">基础 VIP：5 元/30 天 = 5GB 云盘<br>高级 VIP：10 元/30 天 = 100GB 云盘<br>国家法定节假日享优惠价（5 元档实付 2 元 / 10 元档实付 5 元）<br>微信扫码付款后，找作者领取卡密，在 App「会员中心」输入卡密即可开通</div>
      <img src="/qr" alt="收款码" class="qr-img">
    </div>
  </div>
</body>
</html>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // ---------- 公开下载（浏览器直接下载，真实文件流） ----------
    if (method === 'GET' && p.startsWith('/d/') && p.endsWith('/file')) {
      const rid = p.split('/')[2];
      const item = resources.find((r) => r.id === rid);
      if (!item) return send(404, { error: '资源不存在或已下架' });
      if (item.status === 'blacklisted') return send(403, { error: '该资源已被安全卫士拉入黑名单，禁止下载' });
      const filePath = path.join(UPLOAD_DIR, item.storeName);
      if (!fs.existsSync(filePath)) return send(404, { error: '文件丢失，请联系管理员' });

      item.downloads = (item.downloads || 0) + 1;
      persistAll();
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(item.fileName)}`,
        'Content-Length': fs.statSync(filePath).size,
      });
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    // ---------- 数据备份（仅作者 001）：列出备份 ----------
    if (method === 'GET' && p === '/api/backup/list') {
      const admin = getAuth();
      if (!admin) return send(401, { error: '未登录或登录已过期' });
      if (admin.authorNo !== '001') return send(403, { error: '仅管理员可查看备份' });
      const items = [];
      for (const name of fs.readdirSync(BACKUP_DIR)) {
        const metaFile = path.join(BACKUP_DIR, name, 'meta.json');
        if (fs.existsSync(metaFile)) {
          try { items.push({ date: name.replace('backup-', ''), ...JSON.parse(fs.readFileSync(metaFile, 'utf8')) }); } catch (e) { /* 忽略损坏的 meta */ }
        }
      }
      items.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      return send(200, { items });
    }

    // ---------- 下载最新备份（仅作者 001，用于防数据丢失） ----------
    if (method === 'GET' && p === '/api/backup/download') {
      const admin = getAuth();
      if (!admin) return send(401, { error: '未登录或登录已过期' });
      if (admin.authorNo !== '001') return send(403, { error: '仅管理员可下载备份' });
      const dirs = fs.readdirSync(BACKUP_DIR).filter((n) => /^backup-\d{4}-\d{2}-\d{2}$/.test(n)).sort().reverse();
      const latest = dirs[0];
      if (!latest) return send(404, { error: '还没有备份，稍后再试' });
      const file = path.join(BACKUP_DIR, latest, 'data.json');
      if (!fs.existsSync(file)) return send(404, { error: '备份文件不存在' });
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${latest}-data.json"`,
      });
      fs.createReadStream(file).pipe(res);
      return;
    }

    send(404, { error: '接口不存在' });
  } catch (e) {
    if (e.message === 'TOO_LARGE') return send(413, { error: '文件太大，超过上传限制' });
    console.error('[错误]', e);
    send(500, { error: '服务器内部错误：' + e.message });
  }
});

// 定时持久化 + 清理超 30 天黑名单展示（保留记录）
setInterval(persistAll, 60 * 1000);
// 自动备份：启动后 5 秒执行一次，之后每 24 小时一次（数据永不丢）
setTimeout(backupNow, 5000);
setInterval(backupNow, 24 * 3600 * 1000);
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });
server.listen(PORT, HOST, () => {
  console.log('==============================================');
  console.log('  资源上传平台 - 后端服务器已启动');
  console.log(`  地址: http://${HOST}:${PORT}`);
  // 打印本机局域网地址（手机 App「修改服务器地址」用）
  try {
    const ifs = require('os').networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const info of ifs[name]) {
        if (info.family === 'IPv4' && !info.internal) {
          console.log(`  手机可填地址: http://${info.address}:${PORT}（手机连同一 WIFI）`);
        }
      }
    }
  } catch (e) { /* 忽略 */ }
  console.log(`  每日上传上限: ${DAILY_UPLOAD_LIMIT} 个/人（会员 ${VIP_DAILY_UPLOAD_LIMIT} 个/人）`);
  console.log(`  已注册用户: ${users.length}  已发布资源: ${resources.length}  黑名单: ${blacklist.length}`);
  console.log('==============================================');
});
