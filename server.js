// ============ NEW: Upload with JSON Response (for animation) ============
app.post('/upload-analysis', requireAuth, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileBuffer = fs.readFileSync(req.file.path);
    const { detectedKeywords, threatScore: keywordScore } = analyzeFileContent(fileBuffer, path.extname(req.file.originalname));
    const analysis = analyzeFile(req.file, keywordScore, detectedKeywords);
    
    // Get file content for preview (first 20 lines)
    let fileContent = fileBuffer.toString('utf8', 0, Math.min(fileBuffer.length, 5000));
    let lines = fileContent.split('\n').slice(0, 30);
    
    // Get user's data
    const userData = getUserData(req.session.user);
    userData.scans.push({
        filename: req.file.originalname,
        timestamp: new Date().toISOString(),
        analysis: analysis,
        detectedKeywords: detectedKeywords,
        filePreview: lines
    });
    saveUserData(req.session.user, userData.scans, userData.failedLogins);
    
    // Return JSON response for the frontend
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

// ============ NEW: View Report for specific file ============
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
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: monospace; background: #0a0c15; color: #e0e0e0; padding: 40px; }
                .container { max-width: 1000px; margin: 0 auto; background: rgba(15,25,55,0.9); padding: 30px; border-radius: 15px; border: 1px solid #00c6ff; }
                h1, h2 { color: #00c6ff; margin-bottom: 20px; }
                .threat-high { color: #ff4444; font-size: 24px; }
                .threat-medium { color: #ffaa00; font-size: 24px; }
                .threat-low { color: #00ff88; font-size: 24px; }
                .infected { background: rgba(255,68,68,0.2); border-left: 3px solid #ff4444; padding: 8px; margin: 5px 0; }
                .clean { background: rgba(0,255,136,0.1); border-left: 3px solid #00ff88; padding: 8px; margin: 5px 0; }
                .keyword-badge { display: inline-block; background: #ff4444; padding: 5px 10px; border-radius: 5px; margin: 5px; font-size: 12px; }
                .btn { background: #00c6ff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
                pre { background: rgba(0,0,0,0.5); padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📋 FORENSIC ANALYSIS REPORT</h1>
                <p><strong>File:</strong> ${filename}</p>
                <p><strong>Analysis Time:</strong> ${new Date(scan.timestamp).toLocaleString()}</p>
                <p><strong>Threat Level:</strong> <span class="threat-${analysis.threatLevel}">${analysis.threatLevel.toUpperCase()}</span></p>
                <p><strong>Threat Score:</strong> ${analysis.threatScore}/100</p>
                <p><strong>Infected Lines:</strong> ${analysis.infectedLines} | <strong>Clean Lines:</strong> ${analysis.cleanLines}</p>
                
                <h2>🔍 Detected Threat Keywords</h2>
                <div>
                    ${keywords.map(k => `<span class="keyword-badge">⚠️ ${k.keyword} (${k.severity})</span>`).join('') || '<p>No threats detected</p>'}
                </div>
                
                <h2>📝 File Content Analysis</h2>
                <pre>
${preview.map(line => {
    const isInfected = line.toLowerCase().includes('ransomware') || 
                       line.toLowerCase().includes('backdoor') ||
                       line.toLowerCase().includes('eval') ||
                       line.toLowerCase().includes('base64');
    return (isInfected ? '❌ ' : '✅ ') + line;
}).join('\n')}
                </pre>
                
                <a href="/dashboard" class="btn">← Back to Dashboard</a>
                <a href="/upload" class="btn" style="margin-left: 10px;">📤 Upload New File</a>
            </div>
        </body>
        </html>
    `);
});
