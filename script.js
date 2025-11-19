
    // PAGE NAV
    const welcomePage = document.getElementById('welcomePage');
    const introColumns = document.getElementById('introColumns');
    const goToDetector = document.getElementById('goToDetector');
    const detectorPage = document.getElementById('detectorPage');
    const backBtn = document.getElementById('backBtn');

    goToDetector.addEventListener('click', () => {
      // hide welcome sections, show detector
      welcomePage.style.display = 'none';
      introColumns.style.display = 'none';
      goToDetector.style.display = 'none';
      detectorPage.style.display = 'block';
      detectorPage.setAttribute('aria-hidden', 'false');
      document.getElementById('msgInput').focus();
      // scroll to top of file (for small screens)
      window.scrollTo(0,0);
    });

    backBtn.addEventListener('click', () => {
      welcomePage.style.display = '';
      introColumns.style.display = '';
      goToDetector.style.display = '';
      detectorPage.style.display = 'none';
      detectorPage.setAttribute('aria-hidden', 'true');
      window.scrollTo(0,0);
    });

    // DETECTION LOGIC
    const suspiciousWords = [
      "otp","one time password","password","pin","verify","verify now","account",
      "bank","login","click","link","bit.ly","tinyurl","shorturl","free","win",
      "winner","lottery","congratulations","prize","limited","urgent","immediately",
      "transfer","refund","offer","reward","scan","qr","scan qr","security alert",
      "blocked","debit","credit","update now","suspicious"
    ];

    function findTriggeredWords(text) {
      const triggered = new Set();
      const lowered = text.toLowerCase();
      suspiciousWords.forEach(w => {
        if (lowered.includes(w)) triggered.add(w);
      });

      // detect simple URL patterns
      const urlRegex = /(https?:\/\/[^\s]+)|([a-z0-9-]+\.(com|in|net|xyz|online|org|co)\/[^\s]*)|(\bbit\.ly\b|\btinyurl\b|\bgoo\.gl\b)/i;
      if (urlRegex.test(text)) triggered.add('contains link/URL');

      // detect numeric sequences that look like OTP or account numbers (4-8 digits)
      const numSeq = text.match(/\b\d{4,8}\b/g);
      if (numSeq) triggered.add('numeric sequence (possible OTP/account)');

      return Array.from(triggered);
    }

    function analyzeText(text) {
      const trimmed = text.trim();
      if (!trimmed) return {label:'empty', confidence:0, triggered:[]};

      const triggered = findTriggeredWords(trimmed);
      // simple scoring: more triggers → more likely unsafe
      let score = triggered.length;

      // boost score if contains urgent words
      const urgentPhrases = ['urgent','immediately','verify now','security alert','blocked'];
      urgentPhrases.forEach(u => { if (trimmed.toLowerCase().includes(u)) score += 1; });

      // final decision thresholds (tuneable)
      let label = 'Safe', confidence = 80;
      if (score >= 3) { label = 'Unsafe'; confidence = Math.min(95, 55 + score*12); }
      else if (score === 2) { label = 'Suspicious'; confidence = 60; }
      else { label = 'Safe'; confidence = Math.max(50, 85 - score*8); }

      return {label, confidence, triggered};
    }

    // UI Hookups
    const checkBtn = document.getElementById('checkBtn');
    const msgInput = document.getElementById('msgInput');
    const outputArea = document.getElementById('outputArea');
    const resultBox = document.getElementById('resultBox');
    const explainArea = document.getElementById('explainArea');

    function showResult(res) {
      outputArea.style.display = 'block';
      explainArea.innerHTML = '';

      if (res.label === 'empty') {
        resultBox.className = 'result';
        resultBox.textContent = '⚠️ Please paste a message to check.';
        explainArea.textContent = '';
        return;
      }

      if (res.label === 'Unsafe') {
        resultBox.className = 'result unsafe';
        resultBox.innerHTML = `🚨 <span>UNSAFE</span> <span style="font-weight:600">${res.confidence}%</span>`;
      } else if (res.label === 'Suspicious') {
        resultBox.className = 'result unsafe';
        resultBox.innerHTML = `⚠️ <span>SUSPICIOUS</span> <span style="font-weight:600">${res.confidence}%</span>`;
      } else {
        resultBox.className = 'result safe';
        resultBox.innerHTML = `✅ <span>SAFE</span> <span style="font-weight:600">${res.confidence}%</span>`;
      }

      // show triggered words/tips
      if (res.triggered && res.triggered.length > 0) {
        explainArea.innerHTML = '<div style="font-weight:600; margin-bottom:8px;">Detected indicators:</div>';
        res.triggered.forEach(t => {
          const span = document.createElement('span');
          span.className = 'tag';
          span.textContent = t;
          explainArea.appendChild(span);
        });

        const advise = document.createElement('div');
        advise.style.marginTop = '12px';
        advise.style.color = 'var(--muted)';
        advise.style.fontSize = '14px';
        advise.textContent = 'Advice: Do not click links or share OTP/passwords. Verify using official channels.';
        explainArea.appendChild(advise);
      } else {
        explainArea.innerHTML = '<div style="color:var(--muted)">No obvious scam indicators found. Still be cautious — verify sender if unsure.</div>';
      }
    }

    checkBtn.addEventListener('click', () => {
      const text = msgInput.value;
      const res = analyzeText(text);
      showResult(res);
    });

    // allow Ctrl+Enter to check
    msgInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        checkBtn.click();
      }
    });
  