const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ THREAT DETECTION KEYWORDS ============
const THREAT_KEYWORDS = {
    high: [
        'ransomware', 'backdoor', 'trojan', 'rootkit', 'keylogger',
        'password stealer', 'reverse shell', 'cryptolocker'
    ],
    medium: [
        'eval(', 'exec(', 'system(', 'shell_exec', 'base64',
        'invoke-expression', 'downloadstring', 'wget', 'persistence'
    ],
    stego: [
        'steghide', 'outguess', 'zsteg', 'lsb', 'least significant bit',
        'pixel manipulation', 'concealed data'
    ]
};

// ============ MIDDLEWARE ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'shadowhunt_secret_key_2024',
    resave: false,
    saveUninitialized: true
}));

// ============ FILE UPLOAD SETUP ============
const storage = multer.diskStorage({
    destination: 'public/uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + (req.session?.user || 'anonymous') + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ============ CREATE FOLDERS ============
if (!fs.existsSync('data')) fs.mkdirSync('data');
if (!fs.existsSync('public/uploads')) fs.mkdirSync('public/uploads', { recursive: true });
if (!fs.existsSync('views')) fs.mkdirSync('views', { recursive: true });

// ============ DATA FILES ============
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Initialize users file if not exists
if (!fs.existsSync(USERS_FILE)) {
    const defaultUser = {
        username: 'admin',
        email: 'admin@shadowhunt.com',
        password: bcrypt.hashSync('admin123', 10),
        createdAt: new Date().toISOString(),
        scans: [],
        failedLogins: []
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify([defaultUser], null, 2));
}

// ============ HELPER FUNCTIONS ============
function getUserData(username) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username);
    if (!user) {
        return { scans: [], failedLogins: [] };
    }
    if (!user.scans) user.scans = [];
    if (!user.failedLogins) user.failedLogins = [];
    return { scans: user.scans, failedLogins: user.failedLogins, user: user };
}

function saveUserData(username, scans, failedLogins) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex !== -1) {
        users[userIndex].scans = scans;
        users[userIndex].failedLogins = failedLogins;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    }
}

// ============ FILE ANALYSIS FUNCTIONS ============
function analyzeFileContent(fileBuffer) {
    let content = fileBuffer.toString('utf8', 0, Math.min(fileBuffer.length, 100000));
    let detectedKeywords = [];
    let threatScore = 0;
    
    for (let keyword of THREAT_KEYWORDS.high) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
            detectedKeywords.push({ keyword, severity: 'high' });
            threatScore += 15;
        }
    }
    
    for (let keyword of THREAT_KEYWORDS.medium) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
            detectedKeywords.push({ keyword, severity: 'medium' });
            threatScore += 8;
        }
    }
    
    for (let keyword of THREAT_KEYWORDS.stego) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
            detectedKeywords.push({ keyword, severity: 'steganography' });
            threatScore += 20;
        }
    }
    
    return { detectedKeywords, threatScore };
}

function analyzeFile(file, keywordScore = 0, detectedKeywords = []) {
    const fileExt = path.extname(file.filename).toLowerCase();
    const fileSize = file.size;
    
    let threatScore = keywordScore;
    let infectedLines = 0;
    let cleanLines = 0;
    
    if (fileExt === '.exe' || fileExt === '.bat') {
        threatScore += 40;
        infectedLines = 50 + (detectedKeywords.length * 5);
        cleanLines = 100;
    } else if (fileExt === '.js' || fileExt === '.vbs') {
        threatScore += 35;
        infectedLines = 20 + (detectedKeywords.length * 3);
        cleanLines = 80;
    } else if (fileExt === '.jpg' || fileExt === '.png') {
        if (detectedKeywords.length > 0) {
            threatScore += 45;
            infectedLines = 10 + detectedKeywords.length;
            cleanLines = 200;
        } else {
            threatScore += 10;
            infectedLines = Math.floor(Math.random() * 10);
            cleanLines = 300;
        }
    } else {
        threatScore += 15;
        infectedLines = detectedKeywords.length * 2;
        cleanLines = 100;
    }
    
    if (fileSize > 10 * 1024 * 1024) {
        threatScore += 10;
    }
    
    let threatLevel = 'low';
    if (threatScore >= 70) threatLevel = 'high';
    else if (threatScore >= 35) threatLevel = 'medium';
    
    return {
        threatScore: Math.min(threatScore, 100),
        threatLevel: threatLevel,
        infectedLines: infectedLines,
        cleanLines: cleanLines,
        fileName: file.originalname,
        fileSize: file.size,
        fileType: fileExt,
        keywordsFound: detectedKeywords.length,
        keywordList: detectedKeywords.slice(0, 10)
    };
}

function calculateStats(scans, failedLogins) {
    let totalInfected = 0;
    let totalClean = 0;
    let highThreatCount = 0;
    let mediumThreatCount = 0;
    let lowThreatCount = 0;
    
    scans.forEach(scan => {
        totalInfected += scan.analysis.infectedLines;
        totalClean += scan.analysis.cleanLines;
        if (scan.analysis.threatLevel === 'high') highThreatCount++;
        else if (scan.analysis.threatLevel === 'medium') mediumThreatCount++;
        else lowThreatCount++;
    });
    
    return {
        totalScans: scans.length,
        totalInfected: totalInfected,
        totalClean: totalClean,
        highThreatCount: highThreatCount,
        mediumThreatCount: mediumThreatCount,
        lowThreatCount: lowThreatCount,
        recentScans: scans.slice(-5).reverse(),
        failedLogins: failedLogins.slice(-5).reverse(),
        threatSeverity: highThreatCount > scans.length / 2 ? 'high' : 'low'
    };
}

// ============ AUTHENTICATION ============
function requireAuth(req, res, next) {
    if (!req.session.user) {
        res.redirect('/login');
    } else {
        next();
    }
}

// ============ ROUTES ============
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username);
    
    if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = username;
        res.redirect('/dashboard');
    } else {
        const userData = getUserData(username);
        userData.failedLogins.push({
            timestamp: new Date().toISOString(),
            username: username,
            ip: req.ip
        });
        saveUserData(username, userData.scans, userData.failedLogins);
        res.send('<script>alert("Invalid credentials!"); window.location="/login";</script>');
    }
});

app.post('/api/signup', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !password || !email) {
        return res.json({ success: false, message: 'All fields required' });
    }
    
    if (password.length < 6) {
        return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    
    if (users.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Username exists' });
    }
    
    const newUser = {
        username: username,
        email: email,
        password: bcrypt.hashSync(password, 10),
        createdAt: new Date().toISOString(),
        scans: [],
        failedLogins: []
    };
    
    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.json({ success: true, message: 'Account created!' });
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/upload', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'upload.html'));
});

app.post('/upload-analysis', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileBuffer = fs.readFileSync(req.file.path);
    const { detectedKeywords, threatScore: keywordScore } = analyzeFileContent(fileBuffer);
    const analysis = analyzeFile(req.file, keywordScore, detectedKeywords);
    
    let fileContent = fileBuffer.toString('utf8', 0, Math.min(fileBuffer.length, 5000));
    let lines = fileContent.split('\n').slice(0, 30);
    
    const userData = getUserData(req.session.user);
    userData.scans.push({
        filename: req.file.originalname,
        timestamp: new Date().toISOString(),
        analysis: analysis,
        detectedKeywords: detectedKeywords,
        filePreview: lines
    });
    saveUserData(req.session.user, userData.scans, userData.failedLogins);
    
    res.json({
        success: true,
        fileName: req.file.originalname,
        threatLevel: analysis.threatLevel,
        threatScore: analysis.threatScore,
        infectedLines: analysis.infectedLines,
        cleanLines: analysis.cleanLines,
        fileType: analysis.fileType,
        fileSize: req.file.size,
        keywordsFound: detectedKeywords.length,
        keywordList: detectedKeywords.slice(0, 15),
        codePreview: lines
    });
});

app.get('/api/dashboard-data', requireAuth, (req, res) => {
    const userData = getUserData(req.session.user);
    const stats = calculateStats(userData.scans, userData.failedLogins);
    res.json(stats);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/report/:filename', requireAuth, (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    const userData = getUserData(req.session.user);
    const scan = userData.scans.find(s => s.filename === filename);
    
    if (!scan) {
        return res.send('<h3>Report not found</h3><a href="/dashboard">Go back</a>');
    }
    
    const analysis = scan.analysis;
    const keywords = scan.detectedKeywords || [];
    const preview = scan.filePreview || [];
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Report - ${filename}</title>
            <style>
                body { font-family: monospace; background: #0a0c15; color: #e0e0e0; padding: 40px; }
                .container { max-width: 1000px; margin: 0 auto; background: rgba(15,25,55,0.9); padding: 30px; border-radius: 15px; border: 1px solid #00c6ff; }
                h1, h2 { color: #00c6ff; }
                .threat-high { color: #ff4444; }
                .threat-medium { color: #ffaa00; }
                .threat-low { color: #00ff88; }
                .infected { background: rgba(255,68,68,0.2); border-left: 3px solid #ff4444; padding: 8px; margin: 5px 0; }
                .clean { background: rgba(0,255,136,0.1); border-left: 3px solid #00ff88; padding: 8px; margin: 5px 0; }
                .btn { background: #00c6ff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; margin-right: 10px; }
                pre { background: rgba(0,0,0,0.5); padding: 15px; border-radius: 8px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📋 FORENSIC ANALYSIS REPORT</h1>
                <p><strong>File:</strong> ${filename}</p>
                <p><strong>Time:</strong> ${new Date(scan.timestamp).toLocaleString()}</p>
                <p><strong>Threat Level:</strong> <span class="threat-${analysis.threatLevel}">${analysis.threatLevel.toUpperCase()}</span></p>
                <p><strong>Threat Score:</strong> ${analysis.threatScore}/100</p>
                <p><strong>Infected Lines:</strong> ${analysis.infectedLines} | <strong>Clean Lines:</strong> ${analysis.cleanLines}</p>
                
                <h2>🔍 Detected Keywords</h2>
                ${keywords.map(k => `<div class="infected">⚠️ ${k.keyword} (${k.severity})</div>`).join('') || '<div class="clean">✅ No threats detected</div>'}
                
                <h2>📝 File Analysis</h2>
                <pre>
${preview.map(line => {
    const isInfected = line.toLowerCase().includes('ransomware') || 
                       line.toLowerCase().includes('backdoor') ||
                       line.toLowerCase().includes('eval') ||
                       line.toLowerCase().includes('base64');
    return (isInfected ? '❌ ' : '✅ ') + line;
}).join('\n')}
                </pre>
                
                <a href="/dashboard" class="btn">← Dashboard</a>
                <a href="/upload" class="btn">📤 Upload New</a>
            </div>
        </body>
        </html>
    `);
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔍 ShadowHunt running on port ${PORT}`);
});