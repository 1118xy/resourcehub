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
const tls = require('tls');

// ===================== 配置 =====================
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = process.env.SECRET || 'resource-hub-secret-2026';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;   // 单文件 2GB（免费用户；作者不受此限）
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
  'm4v', 'avi', 'mkv', 'mov', 'wmv', 'webm', '3gp', 'flv', 'ts', 'mpg', 'mpeg', 'vob', 'rm', 'rmvb', 'swf',
  'm4a', 'wav', 'aac', 'amr', 'ogg', 'flac', 'opus', 'mid', 'midi', 'wma', 'ra',
  // 图片 / 设计 / 文档 / 其他常用文件（什么文件都可以传）
  'webp', 'svg', 'bmp', 'ico', 'tif', 'tiff', 'heic', 'heif', 'psd', 'ai', 'cdr', 'dwg',
  'ttf', 'otf', 'woff', 'woff2', 'eot', 'lrc', 'srt', 'ass', 'sub',
  'bak', 'dat', 'db', 'sql', 'log', 'ini', 'cfg', 'conf', 'yaml', 'yml', 'toml',
  'torrent', 'iso', 'img', 'dmg', 'vhd', 'epub', 'mobi', 'azw3', 'chm', 'djvu', 'caj',
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
const groupFile = path.join(DATA_DIR, 'group_messages.json'); // 群聊消息（公共群）
const groupsFile = path.join(DATA_DIR, 'groups.json'); // 用户自建群（多群：创建/按编号加入/加朋友）
let groups = loadJson(groupsFile, []);
const backupsFile = path.join(DATA_DIR, 'backups.json'); // 用户自动备份 { userId: { lastAt, phone, authorNo, nickname, vipTag, favCount, upCount } }
let backups = loadJson(backupsFile, {});
const updateFile = path.join(DATA_DIR, 'update.json');  // 远程更新配置 { version, log, link, notice } 作者可随时改
let updateCfg = loadJson(updateFile, {});

let users = loadJson(usersFile, []);
let resources = loadJson(resFile, []);
let blacklist = loadJson(blackFile, []);
let uploadsLog = loadJson(uploadsFile, {});   // { "2026-10-15": { "userId": 3 } }
let messages = loadJson(messagesFile, []);    // [{ id, from, fromName, to, content, time, read }]
let recharges = loadJson(rechargesFile, []);  // 会员充值核验申请
let scanSessions = loadJson(scansFile, {});   // { code: { uid, vcode, exp } }
let cards = loadJson(cardsFile, {});          // 会员卡密库
let groupMsgs = loadJson(groupFile, []);      // 群聊 [{ id, authorId, authorNo, authorName, content, createdAt }]

function persistAll() {
  saveJson(usersFile, users);
  saveJson(resFile, resources);
  saveJson(blackFile, blacklist);
  saveJson(uploadsFile, uploadsLog);
  saveJson(messagesFile, messages);
  saveJson(rechargesFile, recharges);
  saveJson(scansFile, scanSessions);
  saveJson(cardsFile, cards);
  saveJson(groupFile, groupMsgs);
  saveJson(backupsFile, backups);
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

/** 用户级自动备份：每次登录/操作后把账号关键信息存到 backups.json，供用户查看 */
function autoBackup(u) {
  if (!u || !u.id) return;
  try {
    backups[u.id] = {
      lastAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
      phone: maskPhone(u.phone || ''),
      authorNo: u.authorNo || '',
      nickname: u.nickname || '',
      vipTag: u.vipTag || (u.vipPlan ? '会员' : '普通用户'),
      favCount: (u.favs || []).length,
      upCount: (u.uploadCount || 0),
    };
    saveJson(backupsFile, backups);
  } catch (e) { console.error('[用户备份失败]', e.message); }
}
function maskPhone(p) {
  return p && p.length === 11 ? p.slice(0, 3) + '****' + p.slice(7) : p;
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
/** 是否平台作者（001=作者，免费无限上传，云盘不限） */
function isAuthor(u) {
  return u && u.authorNo === '001';
}
const QUOTA_AUTHOR = 100 * 1024 * 1024 * 1024 * 1024; // 作者云盘 100TB（视为不限）
function dailyLimitFor(u) {
  if (isAuthor(u)) return 99999;             // 作者免费：每天可传 99999 个（视为不限）
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
/** 云盘配额：作者 100TB（不限）；免费 1GB；小善专属VIP·基础 5GB；VIP·高级 100GB（旧会员兼容 100GB） */
function quotaFor(u) {
  if (isAuthor(u)) return QUOTA_AUTHOR;
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
  if (n >= 1125899906842624) return (n / 1125899906842624).toFixed(2) + ' PB';
  if (n >= 1099511627776) return (n / 1099511627776).toFixed(2) + ' TB';
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

// ===================== QQ 邮箱验证码登录（SMTP 发信） =====================
// 使用前需配置发信邮箱 + SMTP 授权码（QQ邮箱网页版 → 设置 → 账户 → 开启SMTP服务 → 生成授权码）
// 可通过环境变量 QMAIL_USER / QMAIL_PASS 注入，未配置时接口返回明确提示
const EMAIL_SMTP = {
  host: 'smtp.qq.com',
  port: 465,
  user: process.env.QMAIL_USER || '',
  pass: process.env.QMAIL_PASS || '',
};
// 邮箱验证码：email → { code, exp }，5 分钟有效（内存存储）
const emailCodes = new Map();

// 手写 SMTP 客户端（QQ 邮箱 465 隐式 TLS），不依赖第三方库
const smtpSend = (to, subject, html) =>
  new Promise((resolve, reject) => {
    const { user, pass, host, port } = EMAIL_SMTP;
    if (!user || !pass) return reject(new Error('QQ邮箱SMTP未配置：请提供发信邮箱和授权码'));
    const sock = tls.connect({ host, port, servername: host }, () => {
      const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
      const cmds = [
        ['EHLO resourcehub\r\n', 250],
        ['AUTH LOGIN\r\n', 334],
        [b64(user) + '\r\n', 334],
        [b64(pass) + '\r\n', 235],
        ['MAIL FROM:<' + user + '>\r\n', 250],
        ['RCPT TO:<' + to + '>\r\n', 250],
        ['DATA\r\n', 354],
        ['From: 资源上传平台 <' + user + '>\r\nTo: <' + to + '>\r\nSubject: =?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=\r\nContent-Type: text/html; charset=UTF-8\r\nMIME-Version: 1.0\r\n\r\n' + html + '\r\n.\r\n', 250],
        ['QUIT\r\n', 221],
      ];
      let i = 0, buf = '';
      const next = () => {
        if (i >= cmds.length) { sock.end(); resolve(); return; }
        sock.write(cmds[i][0]);
        const expect = cmds[i][1];
        const onData = (d) => {
          buf += d.toString();
          const m = buf.match(/^(\d{3})[ -]/m);
          if (!m) return;
          const code = parseInt(m[1], 10);
          if (code === expect) {
            buf = '';
            i++;
            sock.removeListener('data', onData);
            if (i < cmds.length) next();
            else { sock.end(); resolve(); }
          } else {
            sock.removeListener('data', onData);
            sock.destroy();
            reject(new Error('SMTP 错误：期望 ' + expect + ' 收到 ' + code + '：' + buf.slice(0, 200)));
          }
        };
        sock.on('data', onData);
      };
      const first = (d) => {
        buf += d.toString();
        if (buf.match(/^220/)) { sock.removeListener('data', first); next(); }
      };
      sock.on('data', first);
      sock.setTimeout(20000, () => { sock.destroy(); reject(new Error('SMTP 超时')); });
    });
    sock.on('error', (e) => reject(e));
  });

// ===================== 网页版首页（登录后：资源广场 + 站内消息，其余功能跳转 App） =====================
const WEB_HOME = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>资源上传平台 · 网页版</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
         background:#0A0E1A; color:#E6EAF2; min-height:100vh; }
  header { padding:26px 18px 14px; text-align:center;
           background:linear-gradient(160deg,#0E1730 0%,#132A52 100%); }
  header h1 { font-size:21px; letter-spacing:1px; }
  header .sub { margin-top:5px; font-size:12px; color:#8FA3C8; }
  .login-wrap { max-width:440px; margin:0 auto; padding:18px 14px 90px; }
  .lg-card { background:#101A33; border:1px solid #1C2B4D; border-radius:14px; padding:16px; margin-bottom:12px; }
  .lg-card h3 { font-size:15px; margin-bottom:12px; color:#33E6FF; }
  .lg-card input { width:100%; padding:11px 12px; border-radius:10px; border:1px solid #1C2B4D;
    background:#0E1730; color:#E6EAF2; font-size:14px; outline:none; margin-bottom:10px; }
  .row2 { display:flex; gap:8px; }
  .row2 input { flex:1; }
  .btn { border:none; border-radius:10px; padding:12px; font-size:15px; font-weight:700; cursor:pointer;
         color:#fff; background:linear-gradient(90deg,#22A6FF,#00E5C8); width:100%; }
  .btn.small { padding:10px 0; font-size:13px; width:auto; flex:0 0 auto; margin-bottom:10px; }
  .btn.ghost { background:transparent; border:1px solid #33E6FF; color:#33E6FF; }
  .hint { font-size:11px; color:#8FA3C8; text-align:center; margin-top:8px; line-height:1.7; }
  .scancode { background:#132A52; border:1px dashed #33E6FF; border-radius:10px; padding:12px;
              text-align:center; font-size:13px; line-height:1.8; margin-bottom:10px; }
  .scancode b { color:#33E6FF; font-size:16px; letter-spacing:2px; }
  nav { display:flex; background:#0E1730; border-bottom:1px solid #1C2B4D; }
  nav button { flex:1; padding:13px 0; background:transparent; border:none; color:#8FA3C8;
               font-size:15px; cursor:pointer; border-bottom:2px solid transparent; }
  nav button.on { color:#33E6FF; border-bottom-color:#33E6FF; font-weight:700; }
  .topbar { display:flex; align-items:center; justify-content:space-between; max-width:760px;
            margin:0 auto; padding:12px 14px 0; }
  .topbar .who { font-size:14px; color:#8FA3C8; }
  .topbar .who b { color:#33E6FF; }
  .topbar button { background:transparent; border:1px solid #1C2B4D; color:#8FA3C8; border-radius:8px;
                   padding:6px 12px; font-size:12px; cursor:pointer; }
  main { max-width:760px; margin:0 auto; padding:14px 14px 90px; }
  .toolbar { display:flex; gap:8px; margin-bottom:12px; }
  .toolbar input, .toolbar select { flex:1; padding:10px 12px; border-radius:10px; border:1px solid #1C2B4D;
    background:#0E1730; color:#E6EAF2; font-size:14px; outline:none; }
  .toolbar select { flex:0 0 auto; }
  .card { background:#101A33; border:1px solid #1C2B4D; border-radius:14px; padding:13px;
          margin-bottom:10px; display:flex; gap:12px; align-items:center; }
  .ficon { width:44px; height:44px; border-radius:12px; flex:0 0 auto;
           background:linear-gradient(135deg,#33E6FF,#1677FF); display:flex; align-items:center;
           justify-content:center; font-weight:800; color:#fff; font-size:11px; }
  .info { flex:1; min-width:0; }
  .info .t { font-size:15px; font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .info .m { margin-top:4px; font-size:11px; color:#8FA3C8; line-height:1.6;
             white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .btn.act { width:auto; padding:9px 13px; font-size:12px; flex:0 0 auto; }
  .empty { text-align:center; color:#5A6B8F; padding:40px 0; font-size:14px; }
  .box { background:#101A33; border:1px solid #1C2B4D; border-radius:14px; padding:15px; margin-bottom:12px; }
  .box h3 { font-size:15px; margin-bottom:11px; color:#33E6FF; }
  .box input, .box textarea { width:100%; padding:11px 12px; border-radius:10px; border:1px solid #1C2B4D;
    background:#0E1730; color:#E6EAF2; font-size:14px; outline:none; margin-bottom:10px; }
  .box textarea { min-height:64px; resize:vertical; }
  .msg { padding:10px; border-radius:10px; background:#0E1730; margin-bottom:8px; font-size:13px; line-height:1.6; }
  .msg .from { color:#33E6FF; font-weight:700; }
  .msg .time { float:right; color:#5A6B8F; font-size:11px; }
  .msg.unread { border-left:3px solid #FF8F1F; }
  .mi { display:flex; align-items:center; justify-content:space-between; padding:13px 4px;
        border-bottom:1px solid #16224A; font-size:14px; }
  .mi:last-child { border-bottom:none; }
  .mi .lbl { color:#C7D3EA; }
  .mi .val { color:#5A6B8F; font-size:12px; }
  .mi .go { color:#33E6FF; font-size:12px; }
  .dl-tip { background:#132A52; border:1px solid #1C2B4D; border-radius:10px; padding:10px;
            font-size:12px; color:#8FA3C8; line-height:1.7; margin-bottom:12px; }
  footer { position:fixed; bottom:0; left:0; right:0; background:#0A0E1A; text-align:center;
           padding:10px; font-size:11px; color:#5A6B8F; border-top:1px solid #1C2B4D; }
  .err { color:#FF7A7A; font-size:12px; margin-bottom:10px; text-align:center; min-height:14px; }
</style>
</head>
<body>
<header>
  <h1>📦 资源上传平台</h1>
  <p class="sub">公开 · 永久免费 · 登录后可看资源 / 聊天，下载需打开 App</p>
</header>

<!-- 登录页 -->
<div id="page-login" class="login-wrap">
  <div class="lg-card">
    <h3>📱 手机号密码登录</h3>
    <input id="lg-acc" placeholder="手机号">
    <input id="lg-pwd" type="password" placeholder="密码">
    <div class="err" id="err-phone"></div>
    <button class="btn" id="lg-btn">登 录</button>
  </div>
  <div class="lg-card">
    <h3>✉️ QQ 邮箱验证码登录</h3>
    <input id="qmail" placeholder="QQ 邮箱（如 123456@qq.com）">
    <div class="row2">
      <input id="qcode" placeholder="6 位验证码">
      <button class="btn small" id="qsend">获取验证码</button>
    </div>
    <div class="err" id="err-qmail"></div>
    <button class="btn" id="qmail-btn">验证码登录</button>
  </div>
  <div class="lg-card">
    <h3>📲 App 扫码登录</h3>
    <div class="scancode" id="scan-box">生成中…</div>
    <button class="btn" id="scan-btn">打开 App 确认登录</button>
    <button class="btn ghost" style="margin-top:8px" onclick="location.href='/app.apk'">未装 App？点此下载安装</button>
    <p class="hint" style="margin-top:10px">点「打开 App 确认登录」会跳转 App；未安装则先点下方按钮下载 App</p>
  </div>
  <p class="hint">没有账号？请先下载「资源上传平台」App 注册登录<br>
  加入 QQ 群 1123 · 客服 QQ：1218742069</p>
</div>

<!-- 登录后主界面 -->
<div id="page-main" hidden>
  <div class="topbar">
    <span class="who">你好，<b id="me-name"></b><span id="me-no"></span></span>
    <button id="logout-btn">退出登录</button>
  </div>
  <nav>
    <button id="nav-res" class="on">资源广场</button>
    <button id="nav-msg">我的消息</button>
    <button id="nav-me">我的</button>
  </nav>
  <main>
    <section id="tab-res">
      <div class="toolbar">
        <input id="q" placeholder="搜索资源 / 作者">
        <select id="type">
          <option value="">全部</option>
          <option>apk</option><option>exe</option><option>zip</option><option>rar</option>
          <option>pdf</option><option>doc</option><option>xls</option><option>ppt</option>
          <option>txt</option><option>mp4</option><option>mp3</option><option>jpg</option>
          <option>png</option><option>html</option><option>other</option>
        </select>
      </div>
      <div class="dl-tip">🔒 网页版可看资源信息；<b>下载文件需在 App 内查看</b>。会员、云盘、上传等请在 App 操作。<br>📲 <a href="/app.apk" style="color:#33E6FF">未安装 App？点此下载安装包</a>（永久链接）</div>
      <div id="res-list">加载中…</div>
    </section>
    <section id="tab-msg" hidden>
      <div class="box">
        <h3>📥 收件箱</h3>
        <div id="inbox">加载中…</div>
      </div>
      <div class="box">
        <h3>✉️ 发消息（收件人填作者编号，如 001）</h3>
        <input id="to-no" placeholder="作者编号（001 / 002 …）">
        <textarea id="msg-content" placeholder="消息内容（1-500 字）"></textarea>
        <button class="btn" id="send-btn">发送</button>
      </div>
    </section>
    <section id="tab-me" hidden>
      <div class="box">
        <h3>👤 我的资料</h3>
        <div class="mi"><span class="lbl">昵称</span><span class="val" id="me-nick"></span></div>
        <div class="mi"><span class="lbl">作者编号</span><span class="val" id="me-author"></span></div>
        <div class="mi"><span class="lbl">账号</span><span class="val" id="me-acc"></span></div>
      </div>
      <div class="box">
        <h3>⚙️ 更多功能（需在 App 内操作）</h3>
        <div class="mi"><span class="lbl">小善专属VIP · 会员</span><span class="go" onclick="openApp('member')">在 App 查看 →</span></div>
        <div class="mi"><span class="lbl">云盘空间 / 上传文件</span><span class="go" onclick="openApp('cloud')">在 App 操作 →</span></div>
        <div class="mi"><span class="lbl">下载记录 / 我的上传</span><span class="go" onclick="openApp('mine')">在 App 查看 →</span></div>
        <div class="mi"><span class="lbl">签到 / 会员券 / 卡密</span><span class="go" onclick="openApp('vip')">在 App 操作 →</span></div>
        <div class="mi"><span class="lbl">设置 / 主题 / 反馈</span><span class="go" onclick="openApp('settings')">在 App 打开 →</span></div>
      </div>
    </section>
  </main>
</div>

<footer>资源上传平台 · 服务器 http://131292rj7lw33.vicp.fun · v1.2.14 · 客服QQ 1218742069</footer>
<script>
(function(){
  var $ = function(id){ return document.getElementById(id); };
  var token = localStorage.getItem('hsk_token') || '';
  var fmt = function(n){
    if(n>=1073741824) return (n/1073741824).toFixed(2)+' GB';
    if(n>=1048576) return (n/1048576).toFixed(1)+' MB';
    if(n>=1024) return (n/1024).toFixed(1)+' KB';
    return n+' B';
  };
  var esc = function(s){ return String(s||'').replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };
  var api = function(path, opt){
    opt = opt || {};
    var headers = opt.headers || {};
    if(token) headers['X-Token'] = token;
    if(opt.body) headers['Content-Type'] = 'application/json';
    return fetch(path, { method: opt.method || 'GET', headers: headers,
      body: opt.body ? JSON.stringify(opt.body) : undefined });
  };
  var openApp = function(page){
    try { location.href = 'resourcehub://' + (page || ''); } catch(e){}
    setTimeout(function(){
      if(confirm('如果手机已安装「资源上传平台」App 会自动打开；\n未安装则点击「确定」跳转下载安装包（或点「取消」继续浏览网页版）。')){
        location.href = '/app.apk';
      }
    }, 600);
  };
  // ---------- 登录态 ----------
  function afterLogin(d){
    token = d.token;
    localStorage.setItem('hsk_token', token);
    localStorage.setItem('hsk_me', JSON.stringify(d.user || {}));
    showMain(d.user);
  }
  function showMain(u){
    $('page-login').hidden = true;
    $('page-main').hidden = false;
    $('me-name').textContent = esc(u.nickname || '用户');
    $('me-no').textContent = ' #' + esc(u.authorNo || '');
    $('me-nick').textContent = esc(u.nickname || '');
    $('me-author').textContent = '#' + esc(u.authorNo || '');
    $('me-acc').textContent = esc(u.phone || u.email || '第三方账号');
    loadRes();
  }
  // ---------- ① 手机号密码登录 ----------
  $('lg-btn').addEventListener('click', function(){
    var acc = $('lg-acc').value.trim(), pwd = $('lg-pwd').value;
    if(!acc || !pwd){ $('err-phone').textContent = '请输入账号和密码'; return; }
    $('err-phone').textContent = '';
    $('lg-btn').disabled = true; $('lg-btn').textContent = '登录中…';
    api('/api/login', { method:'POST', body:{ account: acc, password: pwd,
      mode: acc.indexOf('@')>=0 ? 'email' : 'phone' } })
      .then(function(r){ return r.json(); })
      .then(function(d){
        $('lg-btn').disabled = false; $('lg-btn').textContent = '登 录';
        if(!d.token){ $('err-phone').textContent = d.error || '登录失败'; return; }
        afterLogin(d);
      }).catch(function(){ $('lg-btn').disabled=false; $('lg-btn').textContent='登 录';
        $('err-phone').textContent = '网络错误，请重试'; });
  });
  // ---------- ② QQ 邮箱验证码登录 ----------
  $('qsend').addEventListener('click', function(){
    var email = $('qmail').value.trim();
    if(!/^[\w.+-]+@(qq|foxmail)\.com$/.test(email)){ $('err-qmail').textContent = '请输入 QQ 邮箱'; return; }
    $('err-qmail').textContent = '';
    $('qsend').disabled = true; $('qsend').textContent = '发送中…';
    api('/api/qmail/code', { method:'POST', body:{ email: email } })
      .then(function(r){ return r.json(); })
      .then(function(d){
        $('qsend').disabled = false; $('qsend').textContent = '获取验证码';
        if(d.ok){ $('err-qmail').textContent = '验证码已发送到 ' + email + '（5 分钟内有效）'; }
        else $('err-qmail').textContent = d.error || '发送失败';
      }).catch(function(){ $('qsend').disabled=false; $('qsend').textContent='获取验证码';
        $('err-qmail').textContent = '网络错误，请重试'; });
  });
  $('qmail-btn').addEventListener('click', function(){
    var email = $('qmail').value.trim(), code = $('qcode').value.trim();
    if(!email || !code){ $('err-qmail').textContent = '请填写邮箱和验证码'; return; }
    $('err-qmail').textContent = '';
    $('qmail-btn').disabled = true; $('qmail-btn').textContent = '登录中…';
    api('/api/qmail/login', { method:'POST', body:{ email: email, code: code } })
      .then(function(r){ return r.json(); })
      .then(function(d){
        $('qmail-btn').disabled = false; $('qmail-btn').textContent = '验证码登录';
        if(!d.token){ $('err-qmail').textContent = d.error || '登录失败'; return; }
        afterLogin(d);
      }).catch(function(){ $('qmail-btn').disabled=false; $('qmail-btn').textContent='验证码登录';
        $('err-qmail').textContent = '网络错误，请重试'; });
  });
  // ---------- ③ App 扫码登录 ----------
  var scanSid = '', scanVcode = '', scanTimer = null;
  function startScan(){
    api('/api/scan/anonymous', { method:'POST', body:{} })
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(!d.sid){ $('scan-box').textContent = '生成失败，请刷新'; return; }
        scanSid = d.sid; scanVcode = d.vcode;
        $('scan-box').innerHTML = '登录码：<b>' + esc(d.sid) + '</b><br>验证码：<b>' + esc(d.vcode) + '</b><br><span style="font-size:11px;color:#5A6B8F">' + esc(d.url) + '</span>';
        clearInterval(scanTimer);
        scanTimer = setInterval(function(){
          api('/api/scan/poll?sid=' + scanSid)
            .then(function(r){ return r.json(); })
            .then(function(d){
              if(d.status === 'ok'){
                clearInterval(scanTimer);
                afterLogin(d);
              }
            }).catch(function(){});
        }, 2500);
      }).catch(function(){ $('scan-box').textContent = '生成失败，请刷新'; });
  }
  $('scan-btn').addEventListener('click', function(){
    if(!scanSid){ startScan(); }
    location.href = 'resourcehub://scanlogin?sid=' + scanSid;
  });
  startScan();
  // ---------- 资源广场 ----------
  function loadRes(){
    var q = encodeURIComponent($('q').value.trim());
    var t = $('type').value;
    api('/api/resources?page=1&pageSize=50&q=' + q + (t ? '&type=' + t : ''))
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(!d.items || !d.items.length){ $('res-list').innerHTML = '<div class="empty">暂无资源</div>'; return; }
        $('res-list').innerHTML = d.items.map(function(r){
          var icon = (r.fileType||'file').toUpperCase().slice(0,4);
          return '<div class="card">' +
            '<div class="ficon">' + esc(icon) + '</div>' +
            '<div class="info"><div class="t">' + esc(r.title) + '</div>' +
            '<div class="m">' + esc(r.fileName) + ' · ' + fmt(r.size) + ' · 作者 #' + esc(r.authorNo) + ' ' + esc(r.authorName) +
            ' · 下载 ' + (r.downloads||0) + ' 次 · ' + esc((r.createdAt||'').slice(0,10)) + '</div></div>' +
            '<button class="btn act" onclick="openApp(\'resource?id=' + esc(r.id) + '\')">在 App 打开</button>' +
            '</div>';
        }).join('');
      }).catch(function(){ $('res-list').innerHTML = '<div class="empty">加载失败，请刷新重试</div>'; });
  }
  $('q').addEventListener('input', function(){ clearTimeout(window._t); window._t = setTimeout(loadRes, 300); });
  $('type').addEventListener('change', loadRes);
  // ---------- 消息 ----------
  function loadMsg(){
    api('/api/messages')
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(!d.ok){ $('inbox').innerHTML = '<div class="empty">请先登录</div>'; return; }
        if(!d.messages.length){ $('inbox').innerHTML = '<div class="empty">暂无消息</div>'; return; }
        $('inbox').innerHTML = d.messages.map(function(m){
          return '<div class="msg' + (m.read ? '' : ' unread') + '"><span class="time">' + esc((m.time||'').slice(0,16).replace('T',' ')) + '</span>' +
            '<span class="from">' + esc(m.fromName || '#') + '（#' + esc(m.fromAuthorNo||'') + '）</span>：' + esc(m.content) + '</div>';
        }).join('');
      }).catch(function(){ $('inbox').innerHTML = '<div class="empty">加载失败</div>'; });
  }
  $('send-btn').addEventListener('click', function(){
    var to = $('to-no').value.trim(), content = $('msg-content').value.trim();
    if(!/^\\d{3}$/.test(to)){ alert('作者编号格式错误（如 001）'); return; }
    if(!content){ alert('请输入消息内容'); return; }
    $('send-btn').disabled = true;
    api('/api/message/send', { method:'POST', body:{ to: to, content: content } })
      .then(function(r){ return r.json(); })
      .then(function(d){
        $('send-btn').disabled = false;
        if(d.ok){ alert('消息已发送'); $('msg-content').value=''; loadMsg(); }
        else alert(d.error || '发送失败');
      }).catch(function(){ $('send-btn').disabled=false; alert('网络错误，请重试'); });
  });
  // ---------- Tab 切换 / 退出 ----------
  $('nav-res').addEventListener('click', function(){ tab('res'); });
  $('nav-msg').addEventListener('click', function(){ tab('msg'); loadMsg(); });
  $('nav-me').addEventListener('click', function(){ tab('me'); });
  function tab(name){
    $('nav-res').className = name==='res' ? 'on' : '';
    $('nav-msg').className = name==='msg' ? 'on' : '';
    $('nav-me').className = name==='me' ? 'on' : '';
    $('tab-res').hidden = name!=='res';
    $('tab-msg').hidden = name!=='msg';
    $('tab-me').hidden = name!=='me';
  }
  $('logout-btn').addEventListener('click', function(){
    token = '';
    localStorage.removeItem('hsk_token');
    localStorage.removeItem('hsk_me');
    location.reload();
  });
  // ---------- 启动 ----------
  if(token){
    api('/api/me')
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d.user){ showMain(d.user); }
        else { token=''; localStorage.removeItem('hsk_token'); location.reload(); }
      }).catch(function(){});
  }
})();
</script>
</body>
</html>`;

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
    // ---------- APK 安装包下载（网页版跳转下载链接用，永久有效） ----------
    if (method === 'GET' && (p === '/app.apk' || p === '/download')) {
      const apkPath = path.join(__dirname, 'app.apk');
      if (!fs.existsSync(apkPath)) return send(404, { error: '安装包不存在' });
      const stat = fs.statSync(apkPath);
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Length': stat.size,
        'Content-Disposition': 'attachment; filename="resourcehub_v1.2.14.apk"',
      });
      fs.createReadStream(apkPath).pipe(res);
      return;
    }

    // ---------- 网页版首页（资源广场 + 站内消息，下载跳转 App） ----------
    if (method === 'GET' && (p === '/' || p === '/web/')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(WEB_HOME);
      return;
    }

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

    // ---------- 自动备份：查看备份信息 ----------
    if (method === 'GET' && p === '/api/backup/info') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const bk = backups[me.id];
      return send(200, {
        ok: true,
        count: bk ? 1 : 0,
        info: bk ? ('最近备份：' + bk.lastAt + '\n备份项：手机号、编号、昵称、会员、收藏、上传记录') : '暂无备份数据，登录后自动备份',
      });
    }

    // ---------- 自动备份：查看备份内容 ----------
    if (method === 'GET' && p === '/api/backup/content') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const bk = backups[me.id];
      if (!bk) return send(200, { content: '暂无备份内容。账号信息会在每次登录时自动备份到云端。' });
      return send(200, {
        content: '备份时间：' + bk.lastAt + '\n\n手机号：' + bk.phone + '\n编号：' + bk.authorNo + '\n昵称：' + bk.nickname + '\n会员：' + bk.vipTag + '\n收藏：' + bk.favCount + ' 项\n上传文件：' + bk.upCount + ' 个\n主题设置：已备份',
      });
    }

    // ---------- 检查更新（远程管理：作者配置 data/update.json） ----------
    if (method === 'GET' && p === '/api/checkUpdate') {
      const upd = updateCfg || {};
      const hasUpdate = !!upd.version && upd.version !== '1.2.17' && upd.version !== '1.2.18';
      return send(200, { ok: true, hasUpdate, version: upd.version || '', log: upd.log || '', link: upd.link || '', notice: upd.notice || '' });
    }

    // ---------- 绑定账号：我的绑定码（用作者编号作绑定码） ----------
    if (method === 'GET' && p === '/api/bind/mycode') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      return send(200, { ok: true, bindCode: me.authorNo, qr: 'resourcehub://bind?code=' + me.authorNo });
    }

    // ---------- 绑定账号：扫码绑定（互相绑定） ----------
    if (method === 'POST' && p === '/api/bind/scan') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      let code = String(body.code || '').trim();
      if (code.includes('bind?code=')) code = code.substring(code.indexOf('bind?code=') + 10);
      code = code.split(/[^0-9A-Za-z]/)[0];
      if (!code) return send(400, { error: '未识别到有效的绑定码' });
      if (code === me.authorNo) return send(400, { error: '不能绑定自己' });
      const friend = users.find((u) => u.authorNo === code);
      if (!friend) return send(404, { error: '未找到该编号对应的账号' });
      me.binds = me.binds || [];
      friend.binds = friend.binds || [];
      if (!me.binds.includes(friend.id)) me.binds.push(friend.id);
      if (!friend.binds.includes(me.id)) friend.binds.push(me.id);
      persistAll();
      return send(200, { ok: true, message: '已与「' + (friend.nickname || friend.authorNo) + '」互相绑定账号', friend: { authorNo: friend.authorNo, nickname: friend.nickname } });
    }

    // ---------- 绑定账号：我的绑定列表 ----------
    if (method === 'GET' && p === '/api/bind/list') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const ids = me.binds || [];
      const list = users.filter((u) => ids.includes(u.id)).map((u) => ({ authorNo: u.authorNo, nickname: u.nickname || ('用户' + u.authorNo) }));
      return send(200, { ok: true, list });
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
      autoBackup(user); // 登录成功 → 自动备份账号数据
      return send(200, { token: signToken(user.id), user: publicUser(user), authorNo: user.authorNo });
    }

    // ---------- QQ 邮箱验证码登录：发送验证码到 QQ 邮箱 ----------
    if (method === 'POST' && p === '/api/qmail/code') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const email = String(body.email || '').trim().toLowerCase();
      if (!/^[\w.+-]+@(qq|foxmail)\.com$/.test(email)) return send(400, { error: '请输入 QQ 邮箱（如 123456@qq.com）' });
      const code = String(crypto.randomInt(100000, 999999));
      emailCodes.set(email, { code, exp: Date.now() + 5 * 60 * 1000 });
      try {
        await smtpSend(email, '资源上传平台 - 登录验证码',
          '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;background:#f7f8fa;border-radius:12px">' +
          '<h2 style="color:#1677ff;margin:0 0 12px">资源上传平台 · 登录验证码</h2>' +
          '<p style="color:#333;line-height:1.7">你的登录验证码是：</p>' +
          '<p style="font-size:34px;font-weight:800;letter-spacing:8px;color:#1677ff;margin:14px 0">' + code + '</p>' +
          '<p style="color:#888;font-size:12px;line-height:1.6">验证码 5 分钟内有效，请勿泄露给他人。<br>如非本人操作，请忽略本邮件。</p></div>');
        return send(200, { ok: true, message: '验证码已发送到 ' + email, expireSec: 300 });
      } catch (e) {
        emailCodes.delete(email);
        return send(500, { error: e.message });
      }
    }
    // ---------- QQ 邮箱验证码登录：校验验证码并登录（不存在则自动注册） ----------
    if (method === 'POST' && p === '/api/qmail/login') {
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const email = String(body.email || '').trim().toLowerCase();
      const code = String(body.code || '').trim();
      const s = emailCodes.get(email);
      if (!s || Date.now() > s.exp) return send(400, { error: '验证码不存在或已过期，请重新获取' });
      if (s.code !== code) return send(401, { error: '验证码不正确' });
      emailCodes.delete(email);
      let user = users.find((u) => u.email === email);
      if (!user) {
        user = ensureVipFields({
          id: uid(), phone: '', email, salt: '', passwordHash: '',
          nickname: email.split('@')[0] + '用户', authorNo: nextAuthorNo(), avatar: '',
          qqOpenid: 'qmail-' + email, createdAt: new Date().toISOString(),
        });
        users.push(user);
      }
      persistAll();
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
        vipTag: user.vipTag || (isVip(user) ? (user.vipPlan === 'pro' ? '高级VIP' : '基础VIP') : ''),
        todaySigned: user.lastSignin === today(),
        couponCount: unusedCoupons(user).length,
        coupons: unusedCoupons(user).map((c) => ({ id: c.id, createdAt: c.createdAt })),
        storageUsed: storageUsed(user.id), storageQuota: quotaFor(user),
        quotaText: isAuthor(user) ? '不限' : fmtSize(quotaFor(user)),
        dailyText: isAuthor(user) ? '不限' : String(dailyLimitFor(user)),
        groupUnread: (() => {
          const lastTs = groupMsgs.length ? groupMsgs[groupMsgs.length - 1].createdAt : '';
          const readAt = user.groupReadAt || '';
          if (!lastTs) return 0;
          if (!readAt) return Math.min(groupMsgs.length, 99);
          return lastTs > readAt ? Math.min(groupMsgs.filter((m) => m.createdAt > readAt).length, 99) : 0;
        })(),
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
      if (declaredSize > MAX_FILE_SIZE) return send(413, { error: '文件超过 2GB 上传上限，如需更大请先开通会员' });
      if (declaredSize > 0 && storageUsed(user.id) + declaredSize > quotaFor(user)) {
        if (isAuthor(user)) return send(429, { error: '云盘空间不足' });
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

    // ---------- 公共群聊（全部注册用户都在「资源上传平台 · 官方群」） ----------
    // 发群消息：{ "content": "大家好" }
    if (method === 'POST' && p === '/api/group/send') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const content = String(body.content || '').trim();
      if (!content || content.length > 500) return send(400, { error: '群消息内容需 1-500 字' });
      // 基础内容安全过滤（违法/攻击性内容直接拦截）
      const BAD_WORDS = ['卖身','裸聊','一夜情','赌博网','博彩','六合彩','毒品','冰毒','海洛因','枪支','炸药','杀人','绑架','炸弹','恐怖袭击','黑客攻击','钓鱼网站'];
      const hit = BAD_WORDS.find((w) => content.includes(w));
      if (hit) return send(400, { error: '群消息包含违规内容（' + hit + '），已拦截' });
      const gm = {
        id: uid(8),
        authorId: me.id,
        authorNo: me.authorNo,
        authorName: me.nickname || ('#' + me.authorNo),
        content,
        createdAt: new Date().toISOString(),
      };
      groupMsgs.push(gm);
      if (groupMsgs.length > 500) groupMsgs = groupMsgs.slice(-500); // 最多保留 500 条
      saveJson(groupFile, groupMsgs);
      return send(200, { ok: true, message: '已发送到群', id: gm.id });
    }
    // 拉取群消息（after=上次最后一条时间，增量拉取，最多 100 条）
    if (method === 'GET' && p === '/api/group/messages') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const qs = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams;
      const after = qs.get('after') || '';
      let list = groupMsgs;
      if (after) list = list.filter((m) => m.createdAt > after);
      list = list.slice(-100);
      // 计算群未读：最后一条群消息时间晚于本用户已读时间戳的消息数
      const lastTs = groupMsgs.length ? groupMsgs[groupMsgs.length - 1].createdAt : '';
      const readAt = me.groupReadAt || '';
      const unread = readAt && lastTs > readAt ? groupMsgs.filter((m) => m.createdAt > readAt).length : (readAt ? 0 : groupMsgs.length);
      return send(200, { ok: true, messages: list, unread: Math.min(unread, 99), groupName: '资源上传平台 · 官方群' });
    }
    // 群已读（进入群聊页时调用）
    if (method === 'POST' && p === '/api/group/read') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      me.groupReadAt = new Date().toISOString();
      saveJson(usersFile, users);
      return send(200, { ok: true });
    }

    // ---------- 多群系统：创建群 / 我的群 / 按编号加入 / 群主按编号加朋友 ----------
    // 创建群：{ "name":"我的群", "groupNo":"8888" }
    if (method === 'POST' && p === '/api/groups/create') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const name = String(body.name || '').trim();
      const groupNo = String(body.groupNo || '').trim();
      if (!name || !groupNo) return send(400, { error: '群名和群编号不能为空' });
      if (name.length > 20 || groupNo.length > 20) return send(400, { error: '群名/编号最多 20 字' });
      if (groups.some((g) => g.groupNo === groupNo)) return send(400, { error: '该群编号已被使用' });
      const g = { id: uid(8), name, groupNo, owner: me.authorNo, members: [me.authorNo], createdAt: new Date().toISOString() };
      groups.push(g);
      saveJson(groupsFile, groups);
      return send(200, { ok: true, group: g, message: '群创建成功' });
    }
    // 我的群（我创建或加入的群）
    if (method === 'GET' && p === '/api/groups/mine') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const mine = groups.filter((g) => (g.members || []).includes(me.authorNo) || g.owner === me.authorNo);
      return send(200, { ok: true, groups: mine });
    }
    // 按群编号加入群：{ "groupNo":"8888" }
    if (method === 'POST' && p === '/api/groups/join') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const groupNo = String(body.groupNo || '').trim();
      const g = groups.find((x) => x.groupNo === groupNo);
      if (!g) return send(404, { error: '群编号不存在' });
      if (!(g.members || []).includes(me.authorNo)) { g.members.push(me.authorNo); saveJson(groupsFile, groups); }
      return send(200, { ok: true, group: g, message: '已加入群' });
    }
    // 群主按朋友编号加进群：{ "groupId":"...", "authorNo":"123" }
    if (method === 'POST' && p === '/api/groups/addmember') {
      const me = getAuth();
      if (!me) return send(401, { error: '请先登录' });
      const body = JSON.parse((await readBody(req, 1 << 20)).toString('utf8') || '{}');
      const gid = String(body.groupId || '').trim();
      const memberNo = String(body.authorNo || '').trim();
      const g = groups.find((x) => x.id === gid);
      if (!g) return send(404, { error: '群不存在' });
      if (g.owner !== me.authorNo) return send(403, { error: '只有群主可以添加成员' });
      if (!memberNo) return send(400, { error: '请输入成员编号' });
      if (!(g.members || []).includes(memberNo)) { g.members.push(memberNo); saveJson(groupsFile, groups); }
      return send(200, { ok: true, members: g.members, message: '已添加成员 #' + memberNo });
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
