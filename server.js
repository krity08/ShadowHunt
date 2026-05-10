const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// ============ THREAT DETECTION KEYWORDS ============
const THREAT_KEYWORDS = {
    high: [
        'ransomware', 'backdoor', 'trojan', 'rootkit', 'keylogger',
        'password stealer', 'reverse shell', 'cryptolocker',
        'createremotethread', 'virtualallocex', 'mimikatz'
    ],
    medium: [
        'eval(', 'exec(', 'system(', 'shell_exec', 'base64',
        'invoke-expression', 'downloadstring', 'wget',
        'persistence', 'schtasks', 'registry run'
    ],
    stego: [
        'steghide', 'outguess', 'zsteg', 'lsb', 'least significant bit',
        'pixel manipulation', 'concealed data', 'embedded message'
    ],
    suspicious: [
        'obfuscated', 'encrypted payload', 'packed', 'crypted',
        'anti-debug', 'vm detection', 'sandbox escape'
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
        cb(null, Date.now() + '-' + req.session.user + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ============ CREATE FOLDERS IF NOT EXIST ============
if (!fs.existsSync('data')) fs.mkdirSync('data');
if (!fs.existsSync('public/uploads')) fs.mkdirSync('public/uploads', { recursive: true });
if (!fs.existsSync('public/css')) fs.mkdirSync('public/css', { recursive: true });
if (!fs.existsSync('public/js')) fs.mkdirSync('public/js', { recursive: true });
if (!fs.existsSync('views')) fs.mkdirSync('views', { recursive: true });

// ============ DATA FILES ============
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Create default admin user if not exists
if (!fs.existsSync(USERS_FILE)) {
    const defaultUser = {
        username: 'admin',
        email: 'admin@shadowhunt.com',
        password: bcrypt.hashSync('admin123', 10),
        createdAt: new Date().toISOString(),
        scans: [],      // Each user has their own scans array
        failedLogins: [] // Each user has their own failed logins
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify([defaultUser], null, 2));
}

// Helper function to get user data
function getUserData(username) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username);
    if (!user) {
        return { scans: [], failedLogins: [] };
    }
    // Ensure user has scans and failedLogins arrays (for backward compatibility)
    if (!user.scans) user.scans = [];
    if (!user.failedLogins) user.failedLogins = [];
    return { scans: user.scans, failedLogins: user.failedLogins, user: user };
}

// Helper function to save user data
function saveUserData(username, scans, failedLogins) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex !== -1) {
        users[userIndex].scans = scans;
        users[userIndex].failedLogins = failedLogins;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    }
}

// ============ FILE CONTENT ANALYSIS FUNCTION ============
function analyzeFileContent(fileBuffer, fileExt) {
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
    
    for (let keyword of THREAT_KEYWORDS.suspicious) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
            detectedKeywords.push({ keyword, severity: 'suspicious' });
            threatScore += 10;
        }
    }
    
    return { detectedKeywords, threatScore };
}

// ============ FILE ANALYSIS FUNCTION ============
function analyzeFile(file, keywordScore = 0, detectedKeywords = []) {
    const fileExt = path.extname(file.filename).toLowerCase();
    const fileSize = file.size;
    
    let threatScore = keywordScore;
    let infectedLines = 0;
    let cleanLines = 0;
    
    if (fileExt === '.exe' || fileExt === '.bat' || fileExt === '.sh') {
        threatScore += 40;
        infectedLines = Math.floor(Math.random() * 100) + 50 + (detectedKeywords.length * 5);
        cleanLines = Math.floor(Math.random() * 200) + 100;
    } else if (fileExt === '.js' || fileExt === '.vbs' || fileExt === '.ps1') {
        threatScore += 35;
        infectedLines = Math.floor(Math.random() * 50) + 20 + (detectedKeywords.length * 3);
        cleanLines = Math.floor(Math.random() * 150) + 80;
    } else if (fileExt === '.jpg' || fileExt === '.png') {
        const steganographyRisk = Math.random() * 100;
        if (steganographyRisk > 60 || detectedKeywords.length > 0) {
            threatScore += 45;
            infectedLines = Math.floor(Math.random() * 40) + 10 + detectedKeywords.length;
            cleanLines = Math.floor(Math.random() * 300) + 200;
        } else {
            threatScore += 10;
            infectedLines = Math.floor(Math.random() * 10);
            cleanLines = Math.floor(Math.random() * 100) + 300;
        }
    } else if (fileExt === '.pdf' || fileExt === '.docm' || fileExt === '.xlsm') {
        threatScore += 30;
        infectedLines = Math.floor(Math.random() * 30) + 10 + (detectedKeywords.length * 2);
        cleanLines = Math.floor(Math.random() * 200) + 150;
    } else if (fileExt === '.txt' || fileExt === '.log') {
        threatScore += keywordScore;
        infectedLines = detectedKeywords.length * 2;
        cleanLines = Math.max(50, Math.floor(Math.random() * 100) + 50);
    } else {
        threatScore += 15;
        infectedLines = Math.floor(Math.random() * 20) + 5 + Math.floor(detectedKeywords.length / 2);
        cleanLines = Math.floor(Math.random() * 150) + 100;
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

// ============ STATISTICS FUNCTION (PER USER) ============
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
        else if (scan.analysis.threatLevel === 'low') lowThreatCount++;
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

// ============ AUTHENTICATION MIDDLEWARE ============
function requireAuth(req, res, next) {
    if (!req.session.user) {
        res.redirect('/login');
    } else {
        next();
    }
}

// ============ ROUTES ============

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Sign Up page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

// Login POST
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username);
    
    if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = username;
        res.redirect('/dashboard');
    } else {
        // Log failed login for this specific user
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

// Sign Up API
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !password || !email) {
        return res.json({ success: false, message: 'All fields are required' });
    }
    
    if (password.length < 6) {
        return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    let users = [];
    if (fs.existsSync(USERS_FILE)) {
        users = JSON.parse(fs.readFileSync(USERS_FILE));
    }
    
    if (users.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Username already exists' });
    }
    
    if (users.find(u => u.email === email)) {
        return res.json({ success: false, message: 'Email already registered' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
        username: username,
        email: email,
        password: hashedPassword,
        createdAt: new Date().toISOString(),
        scans: [],      // Empty scans for new user
        failedLogins: [] // Empty failed logins for new user
    };
    
    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    
    res.json({ success: true, message: 'Account created successfully' });
});

// Dashboard page
app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// Upload page
app.get('/upload', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'upload.html'));
});

// Upload POST
app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.send('<script>alert("No file uploaded!"); window.location="/upload";</script>');
    }
    
    const fileBuffer = fs.readFileSync(req.file.path);
    const { detectedKeywords, threatScore: keywordScore } = analyzeFileContent(fileBuffer, path.extname(req.file.originalname));
    const analysis = analyzeFile(req.file, keywordScore, detectedKeywords);
    
    // Get current user's data
    const userData = getUserData(req.session.user);
    
    // Add scan to user's personal scans
    userData.scans.push({
        filename: req.file.originalname,
        timestamp: new Date().toISOString(),
        analysis: analysis,
        detectedKeywords: detectedKeywords
    });
    
    // Save back to user's data
    saveUserData(req.session.user, userData.scans, userData.failedLogins);
    
    res.send(`
        <script>
            sessionStorage.setItem('lastScan', JSON.stringify(${JSON.stringify(analysis)}));
            alert("🔍 File analyzed!\\nThreat Level: ${analysis.threatLevel.toUpperCase()}\\nKeywords Found: ${detectedKeywords.length}");
            window.location="/dashboard";
        </script>
    `);
});

// API endpoint for dashboard data (PER USER)
app.get('/api/dashboard-data', requireAuth, (req, res) => {
    const userData = getUserData(req.session.user);
    const stats = calculateStats(userData.scans, userData.failedLogins);
    res.json(stats);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ============ START SERVER ============
app.listen(PORT, () => {
    console.log(`🔍 ShadowHunt running at http://localhost:${PORT}`);
    console.log(`🔐 Login: admin / admin123`);
    console.log(`📝 Anyone can sign up at /signup`);
    console.log(`✅ Each user has PRIVATE scan history`);
});