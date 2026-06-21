// Templates for testing
const TEMPLATES = {
  docker: {
    name: 'Dockerfile',
    vulnerable: `# Vulnerable Dockerfile
FROM ubuntu:18.04

RUN apt-get update && apt-get install -y openssh-server

COPY app.js .
EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]`,
    hardened: `# Hardened Dockerfile
FROM alpine:3.18

RUN apk add --no-cache nodejs npm

COPY app.js .
RUN adduser -D nonroot
USER nonroot

EXPOSE 8080
CMD ["node", "app.js"]`
  },
  compose: {
    name: 'docker-compose.yml',
    vulnerable: `# Vulnerable Docker Compose
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock`,
    hardened: `# Hardened Docker Compose
version: '3.8'
services:
  web:
    image: nginx:1.25-alpine
    ports:
      - "127.0.0.1:8080:80"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run`
  },
  nginx: {
    name: 'nginx.conf',
    vulnerable: `# Vulnerable Nginx Configuration
server {
    listen 80;
    server_name example.com;

    location / {
        root /usr/share/nginx/html;
        index index.html;
        autoindex on;
    }
}`,
    hardened: `# Hardened Nginx Configuration
server {
    listen 80;
    server_name example.com;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Security-Policy "default-src 'self';";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    location / {
        root /usr/share/nginx/html;
        index index.html;
        autoindex off;
    }
}`
  },
  k8s: {
    name: 'deployment.yaml',
    vulnerable: `# Vulnerable K8s Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          privileged: true`,
    hardened: `# Hardened K8s Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 10001`
  }
};

let currentFile = {
  name: '',
  content: '',
  hardenedContent: ''
};

// UI Elements
const scoreCircle = document.querySelector('.progress-ring__circle');
const scoreNumber = document.getElementById('scoreNumber');
const scoreLabel = document.getElementById('scoreLabel');
const countCritical = document.getElementById('countCritical');
const countHigh = document.getElementById('countHigh');
const countMedium = document.getElementById('countMedium');
const countLow = document.getElementById('countLow');
const findingsCount = document.getElementById('findingsCount');
const findingsList = document.getElementById('findingsList');
const diffContainer = document.getElementById('diffContainer');
const codeVulnerable = document.getElementById('codeVulnerable');
const codeHardened = document.getElementById('codeHardened');
const downloadBtn = document.getElementById('downloadBtn');
const dropZone = document.getElementById('dropZone');

// Initialize Ring Length
const radius = scoreCircle.r.baseVal.value;
const circumference = radius * 2 * Math.PI;
scoreCircle.style.strokeDasharray = `${circumference} ${circumference}`;

function setScore(score) {
  const offset = circumference - (score / 100) * circumference;
  scoreCircle.style.strokeDashoffset = offset;
  scoreNumber.innerText = score;
  
  if (score >= 90) {
    scoreLabel.innerText = 'EXCELLENT';
    scoreLabel.style.color = '#10b981';
  } else if (score >= 70) {
    scoreLabel.innerText = 'SECURE';
    scoreLabel.style.color = '#06b6d4';
  } else if (score >= 40) {
    scoreLabel.innerText = 'WARNING';
    scoreLabel.style.color = '#f97316';
  } else {
    scoreLabel.innerText = 'VULNERABLE';
    scoreLabel.style.color = '#ef4444';
  }
}

// Load Template
function loadTemplate(key) {
  const tpl = TEMPLATES[key];
  if (!tpl) return;
  
  currentFile.name = tpl.name;
  currentFile.content = tpl.vulnerable;
  currentFile.hardenedContent = tpl.hardened;
  
  runAudit();
}

// Simple Static Audit Rules Parser
function runAudit() {
  const content = currentFile.content;
  const name = currentFile.name.toLowerCase();
  
  let findings = [];
  let score = 100;
  
  let criticals = 0;
  let highs = 0;
  let mediums = 0;
  let lows = 0;

  if (name.includes('dockerfile')) {
    // 1. Root check
    if (!content.includes('USER ') || content.includes('USER root')) {
      findings.push({
        title: 'Running as Root User',
        severity: 'high',
        threat: 'Container running without explicit non-root user. If compromised, attacker has full root access on container and potentially host.',
        remediation: 'Create a non-root user using "RUN adduser -D nonroot" and activate it with "USER nonroot" instruction.'
      });
      highs++;
      score -= 20;
    }
    // 2. Unpinned base image tag
    if (content.match(/FROM\s+[a-zA-Z0-9_\-\/]+:(latest)/i) || (content.includes('FROM ') && !content.includes(':'))) {
      findings.push({
        title: 'Unpinned Base Image / Latest Tag',
        severity: 'high',
        threat: 'Using unpinned or "latest" tags can cause unexpected breaking changes or introduction of vulnerabilities when base images are updated.',
        remediation: 'Pin base image versions to specific tags (e.g., alpine:3.18 instead of alpine:latest).'
      });
      highs++;
      score -= 15;
    }
    // 3. Insecure ports
    if (content.includes('EXPOSE 22')) {
      findings.push({
        title: 'Insecure Port exposed (SSH Port 22)',
        severity: 'critical',
        threat: 'Exposing port 22 inside containers invites SSH brute force attacks and is usually unnecessary for containerized workflows.',
        remediation: 'Remove EXPOSE 22. Secure communication should go through application ports (e.g. 8080/80).'
      });
      criticals++;
      score -= 25;
    }
  } else if (name.includes('docker-compose') || name.includes('compose.yml')) {
    // 1. Docker Sock
    if (content.includes('/var/run/docker.sock')) {
      findings.push({
        title: 'Docker Socket Mounted',
        severity: 'critical',
        threat: 'Mounting docker.sock inside a container allows the container to control the host Docker daemon, resulting in complete host takeover.',
        remediation: 'Avoid mounting docker.sock. If API access is required, restrict it using a secure reverse proxy.'
      });
      criticals++;
      score -= 30;
    }
    // 2. Privileged container
    if (content.includes('privileged: true')) {
      findings.push({
        title: 'Privileged Mode Enabled',
        severity: 'critical',
        threat: 'Privileged container bypasses all security isolation checks of kernel namespaces, exposing host capabilities to attackers.',
        remediation: 'Remove "privileged: true". Instead, explicitly grant required capabilities using cap_add.'
      });
      criticals++;
      score -= 30;
    }
    // 3. Ports exposed to all
    if (content.match(/-\s+["']?\d+:\d+["']?/)) {
      findings.push({
        title: 'Port Binded to wildcard 0.0.0.0',
        severity: 'medium',
        threat: 'Port bindings without host IP expose the container to external network threats directly.',
        remediation: 'Bind ports to localhost loopback: "127.0.0.1:8080:80".'
      });
      mediums++;
      score -= 10;
    }
  } else if (name.includes('nginx.conf') || name.includes('nginx')) {
    // 1. Missing Security Headers
    if (!content.includes('X-Frame-Options')) {
      findings.push({
        title: 'Missing X-Frame-Options Header',
        severity: 'medium',
        threat: 'Protection against Clickjacking is missing. Attackers can embed your site in an iframe to trick users.',
        remediation: 'Add header: add_header X-Frame-Options "SAMEORIGIN";'
      });
      mediums++;
      score -= 10;
    }
    if (!content.includes('Content-Security-Policy')) {
      findings.push({
        title: 'Missing Content-Security-Policy Header',
        severity: 'high',
        threat: 'Allows execution of unauthorized scripts, exposing users to Cross-Site Scripting (XSS) attacks.',
        remediation: 'Configure a strong Content-Security-Policy (CSP) header.'
      });
      highs++;
      score -= 15;
    }
    // 2. Autoindex enabled
    if (content.includes('autoindex on')) {
      findings.push({
        title: 'Directory Listing Enabled',
        severity: 'medium',
        threat: 'Autoindex allows anyone to browse the directory structure, leaking sensitive source file info.',
        remediation: 'Change "autoindex on;" to "autoindex off;".'
      });
      mediums++;
      score -= 10;
    }
  } else if (name.includes('deployment') || name.includes('k8s') || name.includes('.yaml') || name.includes('.yml')) {
    // K8s check
    if (content.includes('privileged: true')) {
      findings.push({
        title: 'K8s Container running Privileged',
        severity: 'critical',
        threat: 'Allows container process to access host devices, breaking security isolation.',
        remediation: 'Disable privilege escalation in SecurityContext.'
      });
      criticals++;
      score -= 30;
    }
    if (!content.includes('limits:')) {
      findings.push({
        title: 'Missing Container Resource Limits',
        severity: 'medium',
        threat: 'Without CPU/Memory resource limits, a compromised or buggy container can cause denial-of-service on the node.',
        remediation: 'Add resources limits block specifying CPU and memory boundaries.'
      });
      mediums++;
      score -= 15;
    }
  } else {
    // General / Unknown file types
    findings.push({
      title: 'Scanned file type has limited built-in checks',
      severity: 'low',
      threat: 'File extension does not match primary rulesets.',
      remediation: 'Ensure the uploaded config is Dockerfile, docker-compose, nginx.conf or deployment.yaml.'
    });
    lows++;
  }

  score = Math.max(0, score);
  
  // Render results
  setScore(score);
  
  countCritical.innerText = criticals;
  countHigh.innerText = highs;
  countMedium.innerText = mediums;
  countLow.innerText = lows;
  
  findingsCount.innerText = `${findings.length} Issue${findings.length > 1 ? 's' : ''} Found`;
  
  findingsList.innerHTML = '';
  findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'finding-item';
    item.innerHTML = `
      <div class="finding-info">
        <span class="finding-title">${f.title}</span>
        <span class="finding-meta">${f.threat}</span>
        <span class="finding-meta" style="color: var(--cyan-neon); margin-top: 0.25rem;">🔧 Fix: ${f.remediation}</span>
      </div>
      <span class="finding-tag ${f.severity}">${f.severity}</span>
    `;
    findingsList.appendChild(item);
  });
  
  // Display code panel
  codeVulnerable.innerText = currentFile.content;
  codeHardened.innerText = currentFile.hardenedContent;
  
  diffContainer.style.display = 'grid';
  downloadBtn.style.display = 'block';
}

// File Drag & Drop Handlers
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  
  const files = e.dataTransfer.files;
  if (files.length > 0) {
    handleFile(files[0]);
  }
});

document.getElementById('fileInput').addEventListener('change', (e) => {
  const files = e.target.files;
  if (files.length > 0) {
    handleFile(files[0]);
  }
});

function handleFile(file) {
  const reader = new FileReader();
  reader.onload = function(e) {
    currentFile.name = file.name;
    currentFile.content = e.target.result;
    
    // Auto-generate hardened content for display
    let fileType = 'docker';
    if (file.name.includes('compose')) fileType = 'compose';
    else if (file.name.includes('nginx')) fileType = 'nginx';
    else if (file.name.includes('deployment') || file.name.includes('k8s')) fileType = 'k8s';
    
    currentFile.hardenedContent = TEMPLATES[fileType].hardened;
    runAudit();
  };
  reader.readAsText(file);
}

// Download Trigger
function downloadRemediation() {
  const zipName = `${currentFile.name.split('.')[0]}_hardened_patch`;
  
  // Trigger single file download
  const blob = new Blob([currentFile.hardenedContent], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `secure_${currentFile.name}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
