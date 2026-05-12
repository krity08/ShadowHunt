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
    high: ['ransomware', 'backdoor', 'trojan', 'rootkit', 'keylogger', 'password stealer', 'reverse shell', 'cryptolocker', 'mimikatz'],
    medium: ['eval(', 'exec(', 'system(', 'shell_exec', 'base64', 'invoke-expression', 'downloadstring', 'wget', 'persistence', 'schtasks']
};

// ============ MIDDLEWARE ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'shadowhunt_secret_2024',
    resave: false,
    saveUninitialized: true
}));

// ============ FILE UPLOAD ============
const storage = multer.diskStorage({
    destination: 'public/uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// ============ CREATE FOLDERS ============
if (!fs.existsSync('data')) fs.mkdirSync('data');
if (!fs.existsSync('public/uploads')) fs.mkdirSync('public/uploads', { recursive: true });

// ============ USERS FILE ============
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([{
        username: 'admin',
        email: 'admin@shadowhunt.com',
        password: bcrypt.hashSync('admin123', 10),
        createdAt: new Date().toISOString(),
        scans: [],
        failedLogins: []
    }], null, 2));
}

// ============ HELPER FUNCTIONS ============
function getUserData(username) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username);
    if (!user) return { scans: [], failedLogins: [] };
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

// ============ ANALYSIS FUNCTIONS ============
function analyzeFile(file) {
    const fileExt = path.extname(file.filename).toLowerCase();
    const fileSize = file.size;
    let isImage = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'].includes(fileExt);
    
    let threatScore = 0;
    let detectedKeywords = [];
    
    // For images - simulated steganography detection
    if (isImage) {
        const randomScore = Math.random() * 100;
        if (randomScore > 75) {
            threatScore = 75;
            detectedKeywords.push({ keyword: 'Suspicious pixel pattern detected', severity: 'high' });
        } else if (randomScore > 40) {
            threatScore = 45;
            detectedKeywords.push({ keyword: 'Minor pixel anomalies', severity: 'medium' });
        } else {
            threatScore = 10;
        }
    } else {
        // For text files - random threat simulation
        const randomScore = Math.random() * 100;
        threatScore = randomScore;
        if (randomScore > 70) {
            detectedKeywords.push({ keyword: 'Suspicious code pattern', severity: 'high' });
        } else if (randomScore > 35) {
            detectedKeywords.push({ keyword: 'Unusual string pattern', severity: 'medium' });
        }
    }
    
    let threatLevel = 'low';
    if (threatScore >= 70) threatLevel = 'high';
    else if (threatScore >= 35) threatLevel = 'medium';
    
    return {
        threatScore: Math.floor(threatScore),
        threatLevel: threatLevel,
        infectedLines: threatLevel === 'high' ? 45 : (threatLevel === 'medium' ? 15 : 2),
        cleanLines: 100,
        keywordsFound: detectedKeywords.length,
        keywordList: detectedKeywords,
        isImage: isImage,
        fileType: fileExt
    };
}

function calculateStats(scans) {
    let totalInfected = 0, totalClean = 0;
    let highThreatCount = 0, mediumThreatCount = 0, lowThreatCount = 0;
    
    scans.forEach(scan => {
        totalInfected += scan.analysis.infectedLines;
        totalClean += scan.analysis.cleanLines;
        if (scan.analysis.threatLevel === 'high') highThreatCount++;
        else if (scan.analysis.threatLevel === 'medium') mediumThreatCount++;
        else lowThreatCount++;
    });
    
    return {
        totalScans: scans.length,
        totalInfected, totalClean,
        highThreatCount, mediumThreatCount, lowThreatCount,
        recentScans: scans.slice(-5).reverse(),
        threatSeverity: highThreatCount > scans.length / 2 ? 'high' : 'low'
    };
}

// ============ AUTHENTICATION ============
function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
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
        userData.failedLogins.push({ timestamp: new Date().toISOString(), username, ip: req.ip });
        saveUserData(username, userData.scans, userData.failedLogins);
        res.send('<script>alert("Invalid credentials!"); window.location="/login";</script>');
    }
});

app.post('/api/signup', (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) return res.json({ success: false, message: 'All fields required' });
    if (password.length < 6) return res.json({ success: false, message: 'Password must be at least 6 characters' });
    
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (users.find(u => u.username === username)) return res.json({ success: false, message: 'Username exists' });
    
    users.push({
        username, email,
        password: bcrypt.hashSync(password, 10),
        createdAt: new Date().toISOString(),
        scans: [],
        failedLogins: []
    });
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
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const analysis = analyzeFile(req.file);
    
    const userData = getUserData(req.session.user);
    userData.scans.unshift({
        filename: req.file.originalname,
        timestamp: new Date().toISOString(),
        analysis: analysis,
        fileSize: req.file.size
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
        keywordsFound: analysis.keywordsFound,
        keywordList: analysis.keywordList,
        isImage: analysis.isImage
    });
});

app.get('/api/dashboard-data', requireAuth, (req, res) => {
    const userData = getUserData(req.session.user);
    const stats = calculateStats(userData.scans);
    res.json(stats);
});

app.get('/api/scan-details/:filename', requireAuth, (req, res) => {
    const filename = decodeURIComponent(req.params.filename);
    const userData = getUserData(req.session.user);
    const scan = userData.scans.find(s => s.filename === filename);
    res.json(scan || null);
});

app.get('/report/:filename', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'report.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔍 ShadowHunt running on port ${PORT}`);
    console.log(`🔐 Login: admin / admin123`);
});