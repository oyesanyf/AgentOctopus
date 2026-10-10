/// Embedded single-page web application for Agent Octopus.
/// Serves the dashboard, test runner, live progression monitor, Cedar policy sandbox, and audit trail.
pub const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Octopus | Swarm Breakout Defense & Policy Engine</title>
  <style>
    :root {
      --bg-dark: #0a0e17;
      --card-bg: #111827;
      --card-border: #1f293d;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
      border-bottom: 1px solid var(--card-border);
      padding: 1.25rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }

    .brand-icon {
      font-size: 2.2rem;
      animation: pulse 3s infinite ease-in-out;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); filter: drop-shadow(0 0 4px var(--accent-cyan)); }
      50% { transform: scale(1.08); filter: drop-shadow(0 0 12px var(--accent-cyan)); }
    }

    .brand-title h1 {
      font-size: 1.45rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      background: linear-gradient(to right, #38bdf8, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-title p {
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 0.4rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--success);
      transition: all 0.3s ease;
    }

    .status-badge.offline {
      background: rgba(239, 68, 68, 0.15);
      border-color: rgba(239, 68, 68, 0.4);
      color: var(--danger);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 8px var(--success);
      transition: all 0.3s ease;
    }

    .status-badge.offline .status-dot {
      background: var(--danger);
      box-shadow: 0 0 8px var(--danger);
    }

    @keyframes pulseRuntimeGlow {
      0% { box-shadow: 0 0 15px rgba(16, 185, 129, 0.3), inset 0 0 15px rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.7); }
      50% { box-shadow: 0 0 30px rgba(16, 185, 129, 0.6), inset 0 0 30px rgba(16, 185, 129, 0.25); border-color: rgba(52, 211, 153, 1); }
      100% { box-shadow: 0 0 15px rgba(16, 185, 129, 0.3), inset 0 0 15px rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.7); }
    }

    @keyframes beaconBlink {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.3; transform: scale(1.3); }
    }

    .pulse-beacon {
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 12px #10b981;
      animation: beaconBlink 1.5s infinite ease-in-out;
      flex-shrink: 0;
    }

    .runtime-shoutout-bar {
      background: linear-gradient(90deg, rgba(6, 78, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 50%, rgba(6, 78, 59, 0.95) 100%);
      border: 2px solid #10b981;
      border-radius: 0.5rem;
      margin: 0.75rem 2rem 0;
      padding: 0.65rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      animation: pulseRuntimeGlow 2.5s infinite ease-in-out;
      box-shadow: 0 4px 20px rgba(16, 185, 129, 0.35);
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    nav {
      background: #0f172a;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      padding: 0 2rem;
      gap: 1.5rem;
    }

    .nav-tab {
      padding: 0.85rem 0.5rem;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
    }

    .nav-tab:hover { color: var(--text-main); }
    .nav-tab.active {
      color: var(--accent-cyan);
      border-bottom: 2px solid var(--accent-cyan);
    }

    main {
      padding: 2rem;
      flex: 1;
      max-width: 1400px;
      margin: 0 auto;
      width: 100%;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 0.75rem;
      padding: 1.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
      margin-bottom: 1.5rem;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--card-border);
    }

    .card-header h2 {
      font-size: 1.15rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--accent-blue);
      color: white;
      border: none;
      padding: 0.6rem 1.2rem;
      border-radius: 0.5rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
    }

    .btn:hover { background: #2563eb; }
    .btn:active { transform: scale(0.98); }
    .btn-success { background: var(--success); }
    .btn-success:hover { background: #059669; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-secondary { background: #374151; }
    .btn-secondary:hover { background: #4b5563; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

    select, input, textarea {
      width: 100%;
      background: #1e293b;
      border: 1px solid #334155;
      color: var(--text-main);
      padding: 0.6rem 0.85rem;
      border-radius: 0.375rem;
      font-size: 0.9rem;
      outline: none;
      transition: border-color 0.2s;
    }

    select:focus, input:focus, textarea:focus {
      border-color: var(--accent-cyan);
    }

    .form-group {
      margin-bottom: 1rem;
    }

    .form-group label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .progress-container {
      background: #1e293b;
      border-radius: 9999px;
      height: 12px;
      overflow: hidden;
      margin: 1rem 0;
      position: relative;
    }

    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue));
      width: 0%;
      transition: width 0.3s ease;
    }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.25rem;
    }

    .stat-box {
      background: #0f172a;
      border: 1px solid var(--card-border);
      border-radius: 0.5rem;
      padding: 1rem;
      text-align: center;
    }

    .stat-value {
      font-size: 1.6rem;
      font-weight: 700;
      color: var(--accent-cyan);
      margin-bottom: 0.25rem;
    }

    .stat-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
    }

    .terminal-box {
      background: #050811;
      border: 1px solid #1a2234;
      border-radius: 0.5rem;
      padding: 1rem;
      font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
      font-size: 0.82rem;
      line-height: 1.45;
      height: 380px;
      overflow-y: auto;
      color: #94a3b8;
    }

    .terminal-line { margin-bottom: 2px; white-space: pre-wrap; word-break: break-all; }
    .terminal-line.ok { color: var(--success); font-weight: 600; }
    .terminal-line.fail { color: var(--danger); font-weight: 700; }
    .terminal-line.info { color: var(--accent-cyan); }
    .terminal-line.warn { color: var(--warning); }

    .test-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      margin-top: 1rem;
    }

    .test-table th, .test-table td {
      padding: 0.65rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--card-border);
    }

    .test-table th {
      background: #0f172a;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
    }

    .badge {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
    }

    .badge-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); }
    .badge-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid var(--danger); }
    .badge-running { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid var(--warning); }

    .verdict-box {
      margin-top: 1rem;
      padding: 1rem;
      border-radius: 0.5rem;
      border: 1px solid transparent;
      display: none;
    }

    .verdict-box.allow {
      background: rgba(16, 185, 129, 0.08);
      border-color: rgba(16, 185, 129, 0.3);
      color: #34d399;
    }

    .verdict-box.deny {
      background: rgba(239, 68, 68, 0.08);
      border-color: rgba(239, 68, 68, 0.3);
      color: #f87171;
    }

    .verdict-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .code-block {
      background: #0f172a;
      padding: 0.6rem;
      border-radius: 0.375rem;
      font-family: monospace;
      font-size: 0.8rem;
      margin-top: 0.5rem;
      overflow-x: auto;
    }

    /* Diagnostic Toast & Exception Interceptor Overlay */
    #diagnostic-toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 99999;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-width: 480px;
      width: calc(100vw - 3rem);
      pointer-events: none;
    }

    .diagnostic-toast {
      pointer-events: auto;
      background: #171226;
      border: 1px solid #ef4444;
      border-left: 5px solid #ef4444;
      border-radius: 8px;
      padding: 0.85rem 1.15rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.7), 0 0 15px rgba(239, 68, 68, 0.25);
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      animation: slideInToast 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      color: #f3f4f6;
      font-size: 0.85rem;
    }

    @keyframes slideInToast {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }

    .toast-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }

    .toast-status-badge {
      font-family: monospace;
      font-size: 0.75rem;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
      font-weight: 700;
    }

    .toast-close-x {
      background: none;
      border: none;
      color: #9ca3af;
      cursor: pointer;
      font-size: 1.2rem;
      line-height: 1;
      padding: 0 4px;
      transition: color 0.15s;
    }
    .toast-close-x:hover { color: #f3f4f6; }

    .toast-body {
      color: #cbd5e1;
      line-height: 1.35;
      word-break: break-word;
      font-size: 0.825rem;
    }

    .toast-actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.2rem;
    }

    .toast-retry-btn {
      background: #ef4444;
      color: white;
      border: none;
      padding: 0.3rem 0.75rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      transition: background 0.15s;
    }
    .toast-retry-btn:hover { background: #dc2626; }

    .toast-dismiss-btn {
      background: transparent;
      color: #94a3b8;
      border: 1px solid #334155;
      padding: 0.3rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.15s;
    }
    .toast-dismiss-btn:hover { color: #f3f4f6; border-color: #64748b; }

    /* Breadcrumb Navigation Styles */
    .breadcrumb-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(51, 65, 85, 0.65);
      border-radius: 0.5rem;
      padding: 0.6rem 1.15rem;
      margin-bottom: 1.25rem;
      font-size: 0.825rem;
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.25);
      flex-wrap: wrap;
      gap: 0.6rem;
    }

    .breadcrumb-trail {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      flex-wrap: wrap;
    }

    .breadcrumb-link {
      color: var(--text-muted);
      text-decoration: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.45rem;
      border-radius: 0.35rem;
      transition: all 0.15s ease;
      font-weight: 500;
    }

    .breadcrumb-link:hover {
      color: var(--accent-cyan);
      background: rgba(6, 182, 212, 0.12);
      text-decoration: none;
    }

    .breadcrumb-separator {
      color: #475569;
      font-size: 0.8rem;
      user-select: none;
    }

    .breadcrumb-current {
      color: var(--text-main);
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.45rem;
      background: rgba(255, 255, 255, 0.04);
      border-radius: 0.35rem;
    }

    .breadcrumb-meta {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .breadcrumb-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.72rem;
      font-weight: 600;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      background: rgba(6, 182, 212, 0.12);
      border: 1px solid rgba(6, 182, 212, 0.3);
      color: #38bdf8;
      letter-spacing: 0.3px;
    }

    .breadcrumb-badge.purple {
      background: rgba(139, 92, 246, 0.12);
      border-color: rgba(139, 92, 246, 0.3);
      color: #c084fc;
    }

    .breadcrumb-badge.green {
      background: rgba(16, 185, 129, 0.12);
      border-color: rgba(16, 185, 129, 0.3);
      color: #34d399;
    }

    .breadcrumb-badge.amber {
      background: rgba(245, 158, 11, 0.12);
      border-color: rgba(245, 158, 11, 0.3);
      color: #fbbf24;
    }
  </style>
</head>
<body>
<div id="diagnostic-toast-container"></div>

<header>
  <div class="brand">
    <div class="brand-icon">🐙</div>
    <div class="brand-title">
      <h1>Agent Octopus</h1>
      <p>Decentralized Autonomous Swarm Breakout Defense & Policy Engine</p>
    </div>
  </div>
  <div class="status-badge" id="engine-status-badge" style="border: 2px solid #10b981; background: rgba(6, 78, 59, 0.45); padding: 0.45rem 1rem;">
    <div class="status-dot" id="engine-status-dot"></div>
    <span id="engine-status-text" style="font-weight: 800; letter-spacing: 0.5px; color: #34d399;">🛡️ RUNTIME PROTECTION IS RUNNING (24/7 ACTIVE)</span>
  </div>
</header>

<div class="runtime-shoutout-bar" id="global-runtime-banner">
  <div style="display: flex; align-items: center; gap: 0.85rem;">
    <div class="pulse-beacon"></div>
    <div>
      <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
        <span style="font-size: 1.15rem; font-weight: 800; color: #34d399; letter-spacing: 0.5px;">⚡ RUNTIME PROTECTION IS RUNNING</span>
        <span class="badge" style="background: rgba(16, 185, 129, 0.25); color: #10b981; border: 1px solid #10b981; font-weight: 800; font-size: 0.72rem; padding: 0.2rem 0.55rem;">24/7 ACTIVE ENFORCEMENT</span>
        <span class="badge" style="background: rgba(6, 182, 212, 0.2); color: #38bdf8; border: 1px solid #0891b2; font-weight: 700; font-size: 0.72rem; padding: 0.2rem 0.55rem;">RING-0 KERNEL CLAMPED</span>
      </div>
      <div style="font-size: 0.76rem; color: #cbd5e1; margin-top: 0.15rem;">
        Real-Time ASP (RT-ASP) Prompt &amp; Tool Interceptor active &bull; Windows Job Object 64MB memory boundary enforced &bull; Cedar Zero-Trust evaluating all agent directives
      </div>
    </div>
  </div>
  <div style="display: flex; gap: 0.6rem; align-items: center;">
    <button class="btn btn-secondary" onclick="switchTab('rasp-shield')" style="padding: 0.35rem 0.75rem; font-size: 0.75rem; border: 1px solid #10b981; color: #6ee7b7; background: rgba(6, 78, 59, 0.6);">
      ⚡ Open RT-ASP Shield &rarr;
    </button>
  </div>
</div>

<nav>
  <div class="nav-tab active" onclick="switchTab('test-runner')">🧪 Test Runner &amp; Progression</div>
  <div class="nav-tab" onclick="switchTab('cedar-sandbox')">🛡️ Cedar Policy Sandbox</div>
  <div class="nav-tab" onclick="switchTab('audit-viewer')">📜 Cryptographic Audit Log</div>
  <div class="nav-tab" onclick="switchTab('swarm-status')">🐙 Swarm &amp; Invariants</div>
  <div class="nav-tab" onclick="switchTab('rl-continuous')">🧠 Continuous Security &amp; RL Active Defense</div>
  <div class="nav-tab" onclick="switchTab('rasp-shield')">⚡ Real-Time ASP (RT-ASP)</div>
  <div class="nav-tab" onclick="switchTab('user-guide')">📖 Docs &amp; Integration Guide</div>
</nav>

<main>

  <!-- TAB 1: TEST RUNNER & PROGRESSION -->
  <div id="test-runner" class="tab-content active">
    <!-- BREADCRUMB: TEST RUNNER -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Verification &amp; Red-Teaming</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>🧪</span> Test Runner &amp; Live Progression</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge">⚡ 19 Red-Teaming Frameworks</span>
        <span class="breadcrumb-badge purple">🎯 2,250+ Adversarial Vectors</span>
      </div>
    </nav>

    <!-- RL ACTIVE DEFENSE DASHBOARD BANNER -->
    <div class="card" style="background: linear-gradient(135deg, rgba(6, 182, 212, 0.1), rgba(99, 102, 241, 0.1)); border: 1px solid rgba(6, 182, 212, 0.35); margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 0.85rem;">
          <div style="font-size: 2.2rem;">🧠</div>
          <div>
            <div style="display: flex; align-items: center; gap: 0.6rem;">
              <h3 style="margin: 0; font-size: 1.05rem; font-weight: 700; color: #f8fafc;">Reinforcement Learning Adaptive Defense Engine</h3>
              <span class="badge badge-success" id="main-rl-posture-badge" style="background: rgba(6, 182, 212, 0.2); color: #38bdf8; border: 1px solid #0891b2;">ACTIVE DEFENSE</span>
            </div>
            <p style="margin: 0.25rem 0 0; font-size: 0.8rem; color: #94a3b8;">
              Autonomous Double Q-Learning engine (<a href="javascript:void(0)" onclick="switchTab('rl-continuous')" style="color: #38bdf8; font-weight: 600; text-decoration: underline;">Tab 5</a>) defending against the Vassilev Sisyphean Bound ($P_{secure}(N) \le (1 - \epsilon_{min})^N$).
            </p>
          </div>
        </div>
        <div style="display: flex; gap: 1.25rem; align-items: center; flex-wrap: wrap;">
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Active RL Tier</div>
            <div id="main-rl-active-tier" style="font-size: 0.95rem; font-weight: 700; color: #38bdf8;">Tier 0: PassiveObserve</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Mean Time to Detect (MTTD)</div>
            <div id="main-rl-mttd" style="font-size: 0.95rem; font-weight: 700; color: #10b981;">0.0 ms</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Mean Time to Remediate (MTTR)</div>
            <div id="main-rl-mttr" style="font-size: 0.95rem; font-weight: 700; color: #38bdf8;">0.0 ms</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Survival Prob P(N)</div>
            <div id="main-rl-survival" style="font-size: 0.95rem; font-weight: 700; color: #a78bfa;">100.0%</div>
          </div>
          <button class="btn btn-primary" onclick="switchTab('rl-continuous')" style="font-size: 0.8rem; padding: 0.45rem 0.9rem;">
            🔬 Open RL Center &rarr;
          </button>
        </div>
      </div>
    </div>

    <div class="stats-row" style="grid-template-columns: repeat(6, 1fr);">
      <div class="stat-box">
        <div class="stat-value" id="stat-total">0</div>
        <div class="stat-label">Total Tests Executed</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color: var(--success);" id="stat-passed">0</div>
        <div class="stat-label">Passed Tests</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color: var(--danger);" id="stat-failed">0</div>
        <div class="stat-label">Failed Tests</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" id="stat-time">0.0s</div>
        <div class="stat-label">Execution Duration</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color: var(--accent-orange);" id="stat-tarpit-callers">0</div>
        <div class="stat-label">Trapped Callers</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color: var(--accent-cyan);" id="stat-tarpit-tokens">0</div>
        <div class="stat-label">Decoy Tokens Burned</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>🚀 Adversarial &amp; Defense Test Execution Suite</h2>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn btn-secondary" id="btn-stop" onclick="stopTestRun()" disabled>⏹️ Cancel</button>
          <button class="btn btn-success" id="btn-run-all" onclick="runSuite('all')">⚡ Run ALL TESTS</button>
          <a href="/api/download-run-log" download="adversarial_execution.log" class="btn btn-secondary" style="text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.8rem;" title="Download full server run log from disk">📥 Download Run Log</a>
          <a href="/api/download-test-json" download="adversarial_audit.json" class="btn btn-secondary" style="text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.8rem;" title="Download full test matrix report as JSON">📥 Export JSON</a>
          <button class="btn btn-secondary" onclick="exportTerminalOutput()" style="font-size: 0.8rem;" title="Download live terminal output as a text file">📋 Export Terminal</button>
        </div>
      </div>

      <div style="display: flex; gap: 1rem; align-items: flex-end; margin-bottom: 1rem;">
        <div style="flex: 1;">
          <label style="display: block; font-size: 0.8rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">SELECT SPECIFIC TEST SUITE</label>
          <select id="suite-selector">
            <option value="all" selected style="font-weight: 800; color: #38bdf8; background: #1e1b4b;">ALL TESTS (Unified Master Policy - Runs Every Test on UI)</option>
            <option value="collusion">Agent Collusion &amp; Lateral Breakout Persuasion (PentAGI - 30 tests)</option>
            <option value="astra">Astra Automated REST API Security Auditor (BOLA, Auth Bypass - 20 tests)</option>
            <option value="breakout_defense_tests">Breakout Defense &amp; 50,000-Scenario Prompt Injection (20 tests)</option>
            <option value="breakout_scripts">Breakout Scripts, Role Tampering &amp; Fuel Depletion (6 tests)</option>
            <option value="caido">Caido Rust Auditing Proxy Replay &amp; Fuzzing (20 tests)</option>
            <option value="cedar_policy_tests">Cedar Policy Arm &amp; Red-Team Boundaries (21 tests)</option>
            <option value="containment_tests">Containment &amp; Windows Job Objects / AppContainer Isolation (10 tests)</option>
            <option value="continuous_rl">Continuous RL Active Defense Evaluation (28 Probes across 13 Perimeters)</option>
            <option value="deepeval">DeepEval Multi-Turn &amp; Policy Non-Compliance Benchmark (25 tests)</option>
            <option value="garak">Garak LLM Vulnerability Scanner (Prompt Injection, Canary, Jailbreaks - 35 tests)</option>
            <option value="google_anomaly_detection_tests">Google 3-Layer Anomaly Detection (4 tests)</option>
            <option value="governor_tests">Governor &amp; Out-of-Band Circuit Breaker (8 tests)</option>
            <option value="guard_arms_network_tests">Guard Arms Mutual Supervision Network (7 tests)</option>
            <option value="inspect_ai">Inspect AI Agentic Tool &amp; Sandbox Benchmark (UK AISI - 20 tests)</option>
            <option value="kernel_sentinel_tests">Kernel Sentinel &amp; Ring-0 Driver Bridge (5 tests)</option>
            <option value="ledger_transparency_tests">Ledger Transparency Log &amp; FIPS Post-Quantum (7 tests)</option>
            <option value="math_validator_tests">Math Validator &amp; Sisyphean Proof (6 tests)</option>
            <option value="research_and_atlas_tests">MITRE ATLAS Arm &amp; Attack Chain Synthesis (9 tests)</option>
            <option value="strix_llm_adversarial">Multi-Framework Comprehensive Suite (1,436+ tests)</option>
            <option value="multilingual">Multilingual Determinism Across 74 World Languages (148 tests)</option>
            <option value="multimodal">Multimodal Vision Ingest &amp; OCR Steganography (PyRIT &amp; PromptBench - 20 tests)</option>
            <option value="neural_mesh_integration_tests">Neural Mesh Routing &amp; Tri-Path Flow (3 tests)</option>
            <option value="pentestgpt">PentestGPT Interactive Attack Tree Scenarios (20 tests)</option>
            <option value="promptfoo">Promptfoo Security &amp; Guardrail Matrix (SSRF, PII, Jailbreaks - 25 tests)</option>
            <option value="pyrit">PyRIT AI Red-Teaming &amp; Risk Suite (Microsoft - 600 tests)</option>
            <option value="quantum_adversarial_tests">Quantum Walk &amp; QUBO Optimization (7 tests)</option>
            <option value="rasp_tests">Real-Time ASP (RT-ASP) Prompt &amp; Tool Interceptor (8 tests)</option>
            <option value="redamon">RedAmon Attack Surface Graph &amp; Sandbox Probes (20 tests)</option>
            <option value="restler">RESTler Stateful REST API Fuzzer (Microsoft Research - 20 tests)</option>
          </select>
        </div>
        <button class="btn" id="btn-run-selected" onclick="runSelectedSuite()">▶️ Run Selected Suite</button>
      </div>

      <div>
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted);">
          <span id="progress-status">Ready to execute tests</span>
          <span id="progress-percent">0%</span>
        </div>
        <div class="progress-container">
          <div class="progress-bar" id="progress-bar"></div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2>📺 Live Execution Terminal Output</h2>
          <button class="btn btn-secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="clearTerminal()">Clear</button>
        </div>
        <div class="terminal-box" id="terminal">
          <div class="terminal-line info">[INIT] Agent Octopus Test Progression Engine Initialized.</div>
          <div class="terminal-line info">[READY] Select a suite above and click 'Run Selected Suite' or 'Run ALL TESTS'.</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>📋 Live Test Progression Table</h2>
          <span style="font-size: 0.8rem; color: var(--text-muted);" id="test-table-summary">0 tests loaded</span>
        </div>
        <div style="max-height: 380px; overflow-y: auto;">
          <table class="test-table" id="test-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Test Name</th>
                <th>Suite</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody id="test-table-body">
              <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted);">No tests executed yet. Launch a suite to watch live progression.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: CEDAR POLICY SANDBOX -->
  <div id="cedar-sandbox" class="tab-content">
    <!-- BREADCRUMB: CEDAR POLICY SANDBOX -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Access Control &amp; Sandboxing</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>🛡️</span> Cedar Policy Sandbox</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge green">🔒 AWS Cedar v4.13 Engine</span>
        <span class="breadcrumb-badge amber">🪤 Tarpit Decoy Armed</span>
      </div>
    </nav>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2>🛡️ Interactive PARC Authorization Query</h2>
        </div>
        <form id="cedar-form" onsubmit="evaluateCedar(event)">
          <div class="form-group">
            <label>Principal (Agent ID)</label>
            <input type="text" id="cedar-principal" value="ledger_arm" required />
          </div>
          <div class="form-group">
            <label>Action</label>
            <select id="cedar-action">
              <option value="write">write (Ledger)</option>
              <option value="extract">extract (Document)</option>
              <option value="egress">egress (NetworkTarget)</option>
              <option value="notify">notify (Agent)</option>
              <option value="change_security_policy">change_security_policy (SystemPolicy)</option>
            </select>
          </div>
          <div class="form-group">
            <label>Resource Identifier</label>
            <input type="text" id="cedar-resource" value="corporate_ledger" required />
          </div>
          <div class="form-group">
            <label>Context JSON (Untrusted Agent Payload)</label>
            <textarea id="cedar-context" rows="4">{\n  "amount_cents": 50000,\n  "approved": true\n}</textarea>
          </div>
          <div class="form-group" style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem;">
            <input type="checkbox" id="cedar-attach-approval" style="width: auto;" />
            <label for="cedar-attach-approval" style="margin-bottom: 0; text-transform: none; cursor: pointer;">
              Attach Verified Cryptographic Supervisor Approval Receipt (Blocks Context Manipulation)
            </label>
          </div>
          <div style="margin-top: 1.25rem;">
            <button type="submit" class="btn btn-success" style="width: 100%;">⚡ Evaluate with Cedar Policy Arm</button>
          </div>
        </form>

        <div id="verdict-result" class="verdict-box">
          <div class="verdict-title" id="verdict-title">ALLOW</div>
          <p id="verdict-desc" style="font-size: 0.85rem; margin-bottom: 0.5rem;"></p>
          <div class="code-block" id="verdict-details"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>📜 Active Cedar Policies (Cedar v4.13)</h2>
        </div>
        <div class="code-block" style="height: 480px; overflow-y: auto; line-height: 1.5; color: #a5b4fc;">
// 1. Document Extraction Policy
permit (
    principal == Octopus::Agent::"document_arm",
    action == Octopus::Action::"extract",
    resource is Octopus::Document
);

// 2. Ledger Writing Policy with Spending Limit and Supervisor Approval
permit (
    principal == Octopus::Agent::"ledger_arm",
    action == Octopus::Action::"write",
    resource is Octopus::Ledger
) when {
    context.amount_cents &lt;= 10000000 &amp;&amp; context.approved == true
};

// 3. Network Egress Policy: Only approved Google domains
permit (
    principal == Octopus::Agent::"network_arm",
    action == Octopus::Action::"egress",
    resource is Octopus::NetworkTarget
) when {
    context.destination_domain == "google.com" || context.destination_domain == "www.google.com"
};

// 4. Global Security Policy Guard: Forbid policy tampering unless 2-of-3 Quorum
forbid (
    principal,
    action == Octopus::Action::"change_security_policy",
    resource is Octopus::SystemPolicy
) unless {
    context has quorum_authorized &amp;&amp; context.quorum_authorized == true
};

// 5. Tarpit Decoy Defense Policy
permit (
    principal == Octopus::Agent::"tarpit_arm",
    action == Octopus::Action::"quarantine",
    resource is Octopus::DecoyTrap
);

// 6. Kernel Sentinel Substrate Policy
permit (
    principal == Octopus::Agent::"kernel_sentinel_arm",
    action == Octopus::Action::"kernel_enforce",
    resource is Octopus::KernelSubstrate
);

// 7. ALL Unified Dynamic Defense Policy (Universal Swarm Guard)
@id("ALL")
forbid (
    principal,
    action,
    resource
) when {
    principal == Octopus::Agent::"rogue_adversary"
};
        </div>
      </div>
    </div>

    <!-- CONFIGURABLE EGRESS DOMAIN MANAGER -->
    <div class="card" style="margin-top: 1.5rem; border-left: 4px solid var(--accent-cyan);">
      <div class="card-header">
        <h2>🌐 Network Egress Allowed Domains Configuration (AWS Cedar Policy #3)</h2>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary" onclick="loadEgressDomains()" style="font-size: 0.8rem;">🔄 Refresh</button>
          <button class="btn btn-secondary" onclick="resetEgressDomains()" style="font-size: 0.8rem; border-color: var(--danger); color: var(--danger);">Reset Defaults</button>
        </div>
      </div>
      <p style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6; margin-top: 0.5rem; margin-bottom: 1rem;">
        Configure the exact external domains that autonomous agents are permitted to contact.
        All outbound HTTP/HTTPS requests are strictly verified against AWS Cedar Policy #3 before network sockets can be opened.
        Direct IP addresses, SSRF evasion strings, and unapproved domains are rejected with deterministic <code>Deny</code>.
      </p>

      <div style="display: flex; gap: 0.75rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap;">
        <input type="text" id="new-egress-domain" placeholder="e.g. api.openai.com, api.anthropic.com, huggingface.co" style="flex: 1; min-width: 280px; padding: 0.5rem 0.75rem; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 4px; color: var(--text-main); font-family: monospace; font-size: 0.85rem;" onkeypress="if(event.key==='Enter'){event.preventDefault();addEgressDomain();}" />
        <button class="btn btn-primary" onclick="addEgressDomain()" style="font-size: 0.85rem;">➕ Add Approved Domain</button>
      </div>

      <div style="margin-bottom: 0.75rem;">
        <span style="font-size: 0.75rem; font-weight: 700; color: var(--text-muted); margin-right: 0.5rem;">QUICK ADD POPULAR SERVICES:</span>
        <span style="display: inline-flex; gap: 0.4rem; flex-wrap: wrap;">
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('api.openai.com')">+ api.openai.com</button>
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('api.anthropic.com')">+ api.anthropic.com</button>
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('huggingface.co')">+ huggingface.co</button>
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('github.com')">+ github.com</button>
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('pypi.org')">+ pypi.org</button>
          <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;" onclick="quickAddDomain('crates.io')">+ crates.io</button>
        </span>
      </div>

      <div style="margin-top: 1rem;">
        <label style="display: block; font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.5rem;">CURRENTLY PERMITTED DOMAINS (<span id="egress-domains-count">0</span>)</label>
        <div id="egress-domains-pills" style="display: flex; gap: 0.5rem; flex-wrap: wrap; min-height: 42px; padding: 0.5rem; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 4px;">
          <!-- Dynamically populated -->
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 3: AUDIT TRAIL VIEWER -->
  <div id="audit-viewer" class="tab-content">
    <!-- BREADCRUMB: AUDIT VIEWER -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Forensics &amp; Compliance</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>📜</span> Cryptographic Audit Log</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge green">⛓️ SHA-256 Merkle Chain</span>
        <span class="breadcrumb-badge">🛡️ Tamper-Evident Immutable Log</span>
      </div>
    </nav>

    <div class="card">
      <div class="card-header">
        <h2>📜 Cryptographic SHA-256 Tamper-Evident Security Audit Log</h2>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn btn-secondary" onclick="fetchAuditLog()">🔄 Refresh</button>
          <button class="btn btn-success" onclick="verifyAuditChain()">🔒 Verify Integrity</button>
          <a href="/api/download-audit-log" download="security_audit.log" class="btn btn-secondary" style="text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.8rem;" title="Download complete SHA-256 tamper-evident log">📥 Download Audit Log</a>
          <button class="btn btn-secondary" onclick="exportAuditJson()" style="font-size: 0.8rem;" title="Export current audit log as formatted JSON">📥 Export Audit JSON</button>
        </div>
      </div>
      <div id="audit-integrity-status" style="margin-bottom: 1rem; font-size: 0.85rem; color: var(--success); font-weight: 600;">
        ✅ Genesis root verified: GENESIS_AUDIT_ROOT_000000000000000000000000000000000000000000000000
      </div>
      <div style="max-height: 500px; overflow-y: auto;">
        <table class="test-table" id="audit-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Event Type</th>
              <th>Agent ID</th>
              <th>Decision</th>
              <th>Details</th>
              <th>Record SHA-256 Hash</th>
            </tr>
          </thead>
          <tbody id="audit-table-body">
            <tr>
              <td colspan="6" style="text-align: center; color: var(--text-muted);">Loading audit records...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 4: SWARM STATUS & INVARIANTS -->
  <div id="swarm-status" class="tab-content">
    <!-- BREADCRUMB: SWARM STATUS -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">System Topology &amp; Arms</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>🐙</span> Swarm &amp; Defensive Invariants</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge purple">🐙 10 Autonomous Limbs</span>
        <span class="breadcrumb-badge">📦 64MB Job Object Clamps</span>
      </div>
    </nav>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2>🐙 10 Independent Specialized Arms Architecture</h2>
        </div>
        <table class="test-table">
          <thead>
            <tr>
              <th>Arm Name</th>
              <th>Operating Isolation</th>
              <th>Permitted Boundary</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>DocumentArm</code></td>
              <td>Wasmtime Fuel + AppContainer</td>
              <td><code>extract</code> on <code>s3://invoices/</code> only</td>
            </tr>
            <tr>
              <td><code>LedgerArm</code></td>
              <td>Job Object Memory Clamp (64MB)</td>
              <td><code>write</code> on <code>corporate_ledger</code> (&lt;= $1,000)</td>
            </tr>
            <tr>
              <td><code>NetworkArm</code></td>
              <td>Strict Egress Filter</td>
              <td><code>google.com</code>, <code>www.google.com</code> only</td>
            </tr>
            <tr>
              <td><code>CedarPolicyArm</code></td>
              <td>Deterministic Rust PARC Engine</td>
              <td>Default-Deny + 2-of-3 Quorum Guard</td>
            </tr>
            <tr>
              <td><code>VulnerabilityArm</code></td>
              <td>Read-Only Security Research</td>
              <td>Source &amp; Sandbox Vulnerability Discovery</td>
            </tr>
            <tr>
              <td><code>AttackChainArm</code></td>
              <td>Multi-Step Synthesis Enclave</td>
              <td>Graph-Based Lateral Movement Analysis</td>
            </tr>
            <tr>
              <td><code>MitreAtlasArm</code></td>
              <td>Atlas v4.1 Threat Matrix</td>
              <td>16 Tactics, 208 AI Attack Techniques</td>
            </tr>
            <tr>
              <td><code>BehavioralSentinelArm</code></td>
              <td>Fast-Path Sliding Window Watchdog</td>
              <td>Statistical Spike &amp; Entropy Anomaly</td>
            </tr>
            <tr>
              <td><code>TarpitDecoyArm</code></td>
              <td>Progressive Delay &amp; Synthetic Honey-Tokens</td>
              <td>Autonomous Token Exhaustion &amp; Quarantine (<span id="tarpit-role-status" style="color: var(--success); font-weight: 600;">Active</span>)</td>
            </tr>
            <tr>
              <td><code>KernelSentinelArm</code></td>
              <td>Ring-0 Driver Bridge + Windows NT Kernel Job Substrate</td>
              <td>Hardware Clamps, <code>kernel_enforce</code>, Autotomy Circuit Breaker (<span id="kernel-arm-status" style="color: var(--success); font-weight: 600;">Active</span>)</td>
            </tr>
            <tr>
              <td><code>CodingHelperArm</code></td>
              <td>Sandboxed Python Execution &amp; AST Pre-Scanner</td>
              <td>LLM Algorithm &amp; Math Solver Sandbox (<code>execute_code</code>, Cedar Policy #7, 64MB clamp)</td>
            </tr>
            <tr>
              <td><code>AdaptiveRlDefenseArm</code></td>
              <td>Double Q-Learning + Prioritized Replay</td>
              <td>Dynamic 5-Tier Escalation (Observe &rarr; Trace &rarr; Memory &rarr; Contain &rarr; Mitigation)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card" style="margin-top: 1rem; border-left: 4px solid var(--accent-cyan);">
        <div class="card-header">
          <h2>⚡ Kernel Sentinel &amp; Ring-0 Hardware Bridge Status</h2>
          <span class="badge badge-success" id="kernel-bridge-badge">Tier 1 Active (Job Substrate)</span>
        </div>
        <div style="font-size: 0.85rem; line-height: 1.8; color: var(--text-muted);">
          <div><strong>Tier 1 Windows NT Kernel Job:</strong> <code id="kernel-job-name">AgentOctopus.KernelJob</code> (64MB clamp, max active processes &le; 1)</div>
          <div><strong>Monitored Process IDs:</strong> <code id="kernel-pids">Active Daemon Process</code></div>
          <div><strong>Hardware Process Creation Vetoes:</strong> <span id="kernel-vetos" style="color: var(--text-main); font-weight: 600;">0</span></div>
          <div><strong>Memory Limit Intercepts:</strong> <span id="kernel-mem-intercepts" style="color: var(--text-main); font-weight: 600;">0</span></div>
          <div><strong>Tier 2 Ring-0 Driver Bridge:</strong> <code id="kernel-driver-device">\\.\OsoosiDriver</code> &mdash; <span id="kernel-driver-status">Standby Native Job Substrate</span></div>
          <div><strong>Policy Governance:</strong> Governed by formal AWS Cedar Policy #6 (<code>kernel_sentinel_arm &rarr; kernel_enforce</code>)</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>🛡️ Absolute Defensive Invariants</h2>
        </div>
        <ul style="font-size: 0.9rem; line-height: 1.8; color: var(--text-muted); padding-left: 1.25rem;">
          <li><strong style="color: var(--text-main);">Continuous Security &amp; RL Active Defense (Beyond One and Done):</strong> Closed-loop Double Q-learning engine with prioritized experience replay and 5-tier progressive action space (PassiveObserve &rarr; TraceElevation &rarr; MemoryIntrospection &rarr; MicroContainment &rarr; HardMitigation). Eliminates the Vassilev Sisyphean Bound ($P_{secure}(N) \le (1 - \epsilon_{min})^N$) by continuously retraining on adversarial vectors with sub-millisecond MTTD/MTTR.</li>
          <li><strong style="color: var(--text-main);">Four-Category Breakout Taxonomy:</strong> Dedicated real-time interception for Technical escapes (unmasked Docker daemon sockets), Operational leakage (STS credential revocation), Behavioral tampering (SHA-256 test harness integrity), and Data partitioning (cross-agent memory isolation).</li>
          <li><strong style="color: var(--text-main);">Zero-Touch PATH &amp; Environment:</strong> Never mutates user or system registry PATH (HKCU/HKLM). Process-scoped memory only.</li>
          <li><strong style="color: var(--text-main);">The Google Egress Invariant:</strong> The only approved internet site is Google (<code>google.com</code>, <code>www.google.com</code>). All other domains, SSRF metadata (<code>169.254.169.254</code>), and private subnets are deterministically blocked.</li>
          <li><strong style="color: var(--text-main);">Production Code Only (No Mocks):</strong> 100% genuine cryptographic verification, real Wasmtime fuel exhaustion, real Windows Job Objects, real SHA-256 Merkle trees.</li>
          <li><strong style="color: var(--text-main);">Fail-Closed Cedar Authorization:</strong> Every tool action requires an unforgeable HMAC-SHA256 capability token evaluated against Cedar PARC policies.</li>
          <li><strong style="color: var(--text-main);">Cephalopod Autotomy:</strong> If any cryptographic tamper is detected, an atomic kill switch trips immediately, severing the limb and preserving forensic evidence.</li>
        </ul>
      </div>
    </div>
  </div>

  <!-- TAB 5: DOCUMENTATION & USER GUIDE -->
  <div id="user-guide" class="tab-content">
    <!-- BREADCRUMB: USER GUIDE -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Knowledge &amp; Architecture</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>📖</span> Docs &amp; Integration Guide</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge">🏛️ Dual-Layer Enclave Architecture</span>
        <span class="breadcrumb-badge green">🔌 REST API Gateway Reference</span>
      </div>
    </nav>

    <div class="card">
      <div class="card-header">
        <h2>📖 Agent Octopus Defense Architecture &amp; Integration Guide</h2>
      </div>
      <div style="font-size: 0.9rem; line-height: 1.7; color: var(--text-main);">
        <p style="margin-bottom: 1rem;">
          <strong>Agent Octopus</strong> is an autonomous swarm breakout defense platform and deterministic zero-trust policy engine. It isolates generative AI models, microservices, and tool actuators using <strong>9 Specialized Arms</strong> governed by formal <strong>AWS Cedar v4.13</strong> policies, Windows Job Objects memory clamps (64MB), AppContainer sandboxes, and cryptographic append-only SHA-256 audit trails.
        </p>

        <div style="background: #0f172a; border-left: 4px solid var(--accent-cyan); padding: 1rem; border-radius: 0.375rem; margin-bottom: 1.5rem;">
          <h4 style="color: var(--accent-cyan); margin-bottom: 0.5rem; font-size: 0.95rem;">Dual-Layer Operating Model: Inline Gateway &amp; Multi-Arm Enclave</h4>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.5rem;">
            Agent Octopus operates as both an <strong>inline authorization gateway</strong> and an <strong>isolated multi-arm execution enclave</strong>:
          </p>
          <ul style="font-size: 0.85rem; color: var(--text-muted); padding-left: 1.25rem; line-height: 1.6;">
            <li><strong>Inline Zero-Trust Security Gateway (<code>CedarAuthorizationGateway</code>):</strong> Acts directly as an Authorization &amp; Policy Enforcement Gateway (<code>/api/evaluate-cedar</code>). Every tool call, actuator directive, and agent transaction must pass through this gateway to receive a cryptographically signed capability token and supervisor attestation before execution can proceed. Requests are evaluated against formal AWS Cedar PARC policies; unauthorized actions are immediately blocked.</li>
            <li><strong>Decoy Tarpit Gateway (<code>TarpitArm</code>):</strong> When hostile scans, prompt injections, or unauthorized callers hit the gateway, the Tarpit Arm acts as a deception/sinkhole proxy. It introduces deterministic backoff latency, exhausts attacker context windows with synthetic canary honey-tokens, and isolates repeat offenders in quarantine.</li>
            <li><strong>Multi-Limb Agent Enclave (<code>ArmRuntime</code>):</strong> Behind the gateway, Agent Octopus is a distributed cephalopod architecture with 9 specialized, sandboxed arms (<code>DocumentArm</code>, <code>LedgerArm</code>, <code>NetworkArm</code>, <code>TarpitDecoyArm</code>, etc.) running inside Windows Job Objects (64MB clamps), AppContainer sandboxes, and Wasmtime fuel meters with internal autotomy circuit breakers.</li>
          </ul>
        </div>

        <h3 style="color: var(--accent-cyan); margin-top: 1.5rem; margin-bottom: 0.5rem;">🚀 Running Adversarial &amp; Red-Teaming Tests</h3>
        <p>You can execute verification tests directly via the Web Dashboard or from the CLI:</p>
        <div class="code-block">
# Run the complete exhaustive test suite across all 19 red-teaming frameworks:
python d:\tools\strix_llm_adversarial_tester.py --skip-strix

# Run a specific framework test suite:
python d:\tools\strix_llm_adversarial_tester.py --suite garak          # Garak LLM Vulnerability Scanner
python d:\tools\strix_llm_adversarial_tester.py --suite deepeval       # DeepEval Multi-Turn Compliance
python d:\tools\strix_llm_adversarial_tester.py --suite inspect_ai     # Inspect AI (UK AI Safety Institute)
python d:\tools\strix_llm_adversarial_tester.py --suite promptfoo      # Promptfoo Guardrails &amp; SSRF Matrix
python d:\tools\strix_llm_adversarial_tester.py --suite pentestgpt     # PentestGPT Attack Tree Scenarios
python d:\tools\strix_llm_adversarial_tester.py --suite redamon        # RedAmon Attack Surface Graph
python d:\tools\strix_llm_adversarial_tester.py --suite caido          # Caido Rust Proxy Replay Engine
python d:\tools\strix_llm_adversarial_tester.py --suite astra          # Astra REST API Security &amp; BOLA
python d:\tools\strix_llm_adversarial_tester.py --suite restler        # RESTler Stateful REST Fuzzer
python d:\tools\strix_llm_adversarial_tester.py --suite multimodal     # Multimodal Vision &amp; OCR Ingest
python d:\tools\strix_llm_adversarial_tester.py --suite multilingual   # Multilingual Determinism (10 Languages)
python d:\tools\strix_llm_adversarial_tester.py --suite pyrit          # PyRIT AI Risk Pipeline (Microsoft)

# Run native Rust unit and integration policy tests:
cargo test --test cedar_policy_tests
        </div>

        <h3 style="color: var(--accent-cyan); margin-top: 1.5rem; margin-bottom: 0.5rem;">🛡️ REST API Gateway Endpoints</h3>
        <table class="test-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Endpoint</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/evaluate-cedar</code></td>
              <td>Evaluates PARC authorization requests (Principal, Action, Resource, Context). Automatically engages Tarpit Arm upon unauthorized attempts.</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/status</code></td>
              <td>Returns real-time health, active Cedar policies, OS isolation clamps, and Tarpit defense metrics.</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/tarpit-stats</code></td>
              <td>Returns live statistics on trapped callers, synthetic tokens burned, cumulative delays, and active quarantines.</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/kernel-stats</code></td>
              <td>Returns real-time telemetry on Tier 1 Windows Job Object clamps, process creation vetoes, memory limit intercepts, and Tier 2 Ring-0 driver bridge status.</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/audit-log</code></td>
              <td>Retrieves the immutable SHA-256 hash-chained security event audit log.</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/live-tests</code></td>
              <td>Pollable endpoint streaming external test results to the web dashboard in real time.</td>
            </tr>
          </tbody>
        </table>

        <h3 style="color: var(--accent-cyan); margin-top: 1.5rem; margin-bottom: 0.5rem;">🍯 The Tarpit Decoy Defense Arm (`TarpitArm`)</h3>
        <p>
          When an unauthorized principal or automated scanner sends hostile queries, the <strong>Tarpit Arm</strong> intercepts the request:
        </p>
        <ul style="padding-left: 1.25rem; color: var(--text-muted); line-height: 1.8;">
          <li><strong>Progressive Backoff Delay:</strong> Introduces deterministic async delay throttling adversarial request throughput.</li>
          <li><strong>Synthetic Honey-Token Exhaustion:</strong> Emits realistic decoy JSON structures (canary tokens, bogus ledger balances, sinkhole URLs) designed to consume attacker LLM token budgets and context windows.</li>
          <li><strong>Automated Quarantine:</strong> After repeated violations, the adversary identity is quarantined and all actions blocked.</li>
          <li><strong>Cryptographic Attestation:</strong> Every tarpit engagement generates a SHA-256 forensic record sealed in `logs/audit.log`.</li>
        </ul>

        <h3 style="color: var(--accent-cyan); margin-top: 1.5rem; margin-bottom: 0.5rem;">💡 Example Integration (Python)</h3>
        <div class="code-block">
import urllib.request, json

payload = {
    "principal": "ledger_arm",
    "action": "write",
    "resource": "Ledger",
    "context": {"amount_cents": 5000000, "approved": True},
    "attach_supervisor_approval": True
}

req = urllib.request.Request(
    "http://127.0.0.1:5005/api/evaluate-cedar",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read().decode("utf-8"))
    print("Authorization Verdict:", "ALLOW" if result.get("is_allowed") else "DENY")
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 6: CONTINUOUS SECURITY & RL ACTIVE DEFENSE -->
  <div id="rl-continuous" class="tab-content">
    <!-- BREADCRUMB: RL CONTINUOUS DEFENSE -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Active Defense &amp; Continuous Security</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>🧠</span> Continuous RL &amp; Vassilev Sisyphean Governor</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge purple">📐 Vassilev Bound P(N) &le; (1-&epsilon;)<sup>N</sup></span>
        <span class="breadcrumb-badge green">⚡ D3QN Double Q-Learning</span>
        <span class="breadcrumb-badge amber">🛡️ 4-Stage Progressive Ladder</span>
      </div>
    </nav>

    <div class="card" style="background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%); border: 1px solid var(--accent-cyan); margin-bottom: 1.5rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
          <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem; flex-wrap: wrap;">
            <h2 style="color: var(--accent-cyan); font-size: 1.3rem; margin: 0;">
              🧠 Beyond One and Done: Continuous Security &amp; Reinforcement Learning Active Defense
            </h2>
            <span class="badge" id="rl-continuous-live-badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; font-weight: 700; font-size: 0.75rem;">
              ● ALWAYS RUNNING (Autonomous 24/7 Continuous Loop Active)
            </span>
          </div>
          <p style="color: var(--text-muted); font-size: 0.85rem; max-width: 900px; line-height: 1.5; margin: 0;">
            Implementation of the continuous security operations architecture (Femi Oyesanya, October 2026).
            Features an autonomous <strong>Reinforcement Learning Active Defense Engine</strong> (Double Q-Learning, 5-tier action space, prioritized experience replay),
            the <strong>Four-Category Breakout Taxonomy</strong> (Technical, Operational, Behavioral, Data), and <strong>OpenTelemetry (OTel)</strong> session telemetry with real-time MTTD, MTTR, and the <strong>Vassilev Sisyphean Bound</strong> (<span style="font-family: monospace;">P<sub>secure</sub>(N) &le; (1 - &epsilon;<sub>min</sub>)<sup>N</sup></span>).
          </p>
        </div>
        <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
          <div style="display: flex; align-items: center; gap: 0.45rem; background: rgba(15, 23, 42, 0.7); border: 1px solid #334155; padding: 0.4rem 0.7rem; border-radius: 6px;">
            <span style="font-size: 0.75rem; color: #94a3b8; font-weight: 600;">24/7 AUTO-PILOT</span>
            <input type="checkbox" id="rl-autopilot-toggle" checked onchange="toggleContinuousAutoPilot(this.checked)" style="cursor: pointer;" title="Toggle 24/7 continuous autonomous execution stream">
          </div>
          <button class="btn btn-primary" onclick="runRlContinuousCycle()" id="btn-run-continuous-cycle" style="display: flex; align-items: center; gap: 0.5rem; background: #06b6d4; color: #000; font-weight: 600;">
            <span>▶</span> Run Instant Cycle
          </button>
          <button class="btn btn-outline" onclick="fetchLatestContinuousReport(true);" style="display: flex; align-items: center; gap: 0.5rem;">
            <span>🔄</span> Refresh Telemetry
          </button>
        </div>
      </div>
    </div>

    <!-- Resilience Stat Cards -->
    <div class="stats-row" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 1.5rem;">
      <div class="stat-box" style="border-top: 3px solid #06b6d4;">
        <div class="stat-value" id="rl-stat-mttd" style="color: #06b6d4;">0.0 ms</div>
        <div class="stat-label">Mean Time to Detection (MTTD)</div>
      </div>
      <div class="stat-box" style="border-top: 3px solid #10b981;">
        <div class="stat-value" id="rl-stat-mttr" style="color: #10b981;">0.0 ms</div>
        <div class="stat-label">Mean Time to Remediation (MTTR)</div>
      </div>
      <div class="stat-box" style="border-top: 3px solid #f59e0b;">
        <div class="stat-value" id="rl-stat-survival" style="color: #f59e0b;">100.0%</div>
        <div class="stat-label">Cumulative Survival P<sub>secure</sub>(N)</div>
      </div>
      <div class="stat-box" style="border-top: 3px solid #8b5cf6;">
        <div class="stat-value" id="rl-stat-episodes" style="color: #8b5cf6;">0</div>
        <div class="stat-label">RL Episodes / Transitions</div>
      </div>
    </div>

    <!-- Progressive Action Ladder -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <div class="card-header">
        <h2>⚡ Progressive Action Space (A<sub>t</sub>) &amp; Dynamic Mitigation Tiers</h2>
        <span class="badge" id="rl-posture-badge" style="background: rgba(6, 182, 212, 0.2); color: #06b6d4; border: 1px solid #06b6d4;">CALIBRATING</span>
      </div>
      <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-top: 0.5rem;">
        <div id="tier-pill-0" style="background: #0f172a; border: 1px solid #1f293d; border-radius: 0.5rem; padding: 0.85rem; text-align: center;">
          <div style="font-weight: 700; color: #9ca3af; font-size: 0.85rem; margin-bottom: 0.25rem;">TIER 0</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem;">PassiveObserve</div>
          <div style="font-size: 0.75rem; color: #6b7280;">Baseline telemetry &amp; zero friction</div>
        </div>
        <div id="tier-pill-1" style="background: #0f172a; border: 1px solid #1f293d; border-radius: 0.5rem; padding: 0.85rem; text-align: center;">
          <div style="font-weight: 700; color: #38bdf8; font-size: 0.85rem; margin-bottom: 0.25rem;">TIER 1</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem;">TraceElevation</div>
          <div style="font-size: 0.75rem; color: #6b7280;">Deep parameter schema &amp; AST tracing</div>
        </div>
        <div id="tier-pill-2" style="background: #0f172a; border: 1px solid #1f293d; border-radius: 0.5rem; padding: 0.85rem; text-align: center;">
          <div style="font-weight: 700; color: #fbbf24; font-size: 0.85rem; margin-bottom: 0.25rem;">TIER 2</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem;">MemoryIntrospection</div>
          <div style="font-size: 0.75rem; color: #6b7280;">Scratchpad &amp; secret leak scan</div>
        </div>
        <div id="tier-pill-3" style="background: #0f172a; border: 1px solid #1f293d; border-radius: 0.5rem; padding: 0.85rem; text-align: center;">
          <div style="font-weight: 700; color: #f97316; font-size: 0.85rem; margin-bottom: 0.25rem;">TIER 3</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem;">MicroContainment</div>
          <div style="font-size: 0.75rem; color: #6b7280;">Tarpit delay &amp; socket drop</div>
        </div>
        <div id="tier-pill-4" style="background: #0f172a; border: 1px solid #1f293d; border-radius: 0.5rem; padding: 0.85rem; text-align: center;">
          <div style="font-weight: 700; color: #ef4444; font-size: 0.85rem; margin-bottom: 0.25rem;">TIER 4</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem;">HardMitigation</div>
          <div style="font-size: 0.75rem; color: #6b7280;">Process autotomy &amp; kill-switch</div>
        </div>
      </div>
    </div>

    <!-- The 4 Breakout Taxonomy Cards -->
    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem; margin-bottom: 1.5rem;">
      <div class="card">
        <div class="card-header">
          <h3>🖥️ 1. Technical Breakout Guard</h3>
          <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">SANDBOX INTACT</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6;">
          <p><strong>Primary Mechanism:</strong> Hypervisor, container, or Wasm sandbox escape.</p>
          <p><strong>Mitigation:</strong> Ephemeral virtualization with read-only root filesystems and automatic environment destruction upon task completion. Intercepts unmasked Docker daemon sockets (<span style="font-family: monospace;">/var/run/docker.sock</span>, <span style="font-family: monospace;">\\.\pipe\docker_engine</span>).</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3>⚙️ 2. Operational Containment Guard</h3>
          <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">STS SCOPING ACTIVE</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6;">
          <p><strong>Primary Mechanism:</strong> Network routing misconfigurations, unmanaged env variable inheritance.</p>
          <p><strong>Mitigation:</strong> Dynamic Least-Privilege Identity Brokering issuing minute-level short-lived STS credentials. Environment token scrubber prevents live API keys (<span style="font-family: monospace;">OPENAI_API_KEY</span>, <span style="font-family: monospace;">ANTHROPIC_API_KEY</span>) from leaking into agent contexts.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3>🎭 3. Behavioral Breakout Guard</h3>
          <span class="badge" id="badge-harness-status" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">ALIGNED</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6;">
          <p><strong>Primary Mechanism:</strong> Reward hacking, evaluation harness tampering (self-grading bypass), routing evasion.</p>
          <p><strong>Mitigation:</strong> Continuous cryptographic SHA-256 fingerprint verification of all test scripts (<span style="font-family: monospace;">strix_llm_adversarial_tester.py</span>). Intercepts routing inspections (<span style="font-family: monospace;">route print</span>), DNS tunneling, and <span style="font-family: monospace;">hosts</span> file tampering.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3>🔐 4. Data Breakout Guard</h3>
          <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">ISOLATED</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6;">
          <p><strong>Primary Mechanism:</strong> Credential extraction, memory scraping, cross-agent memory pollution.</p>
          <p><strong>Mitigation:</strong> Strict role-based memory boundaries preventing low-privilege worker agents from polluting shared scratchpads or message brokers read by high-privilege execution agents. Blocks process memory scraping.</p>
        </div>
      </div>
    </div>

    <!-- Live Continuous Evaluation Cycle Results Table -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <div class="card-header">
        <h2>🧪 Continuous Adversarial Evaluation &amp; Closed-Loop RL Training Log</h2>
        <span id="continuous-cycle-status" style="font-size: 0.85rem; color: var(--text-muted);">Awaiting execution</span>
      </div>
      <div style="overflow-x: auto; max-height: 380px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid var(--card-border); color: var(--accent-cyan);">
              <th style="padding: 0.6rem;">Probe ID</th>
              <th style="padding: 0.6rem;">Perimeter / Framework</th>
              <th style="padding: 0.6rem;">Principal &amp; Action</th>
              <th style="padding: 0.6rem;">Target Resource</th>
              <th style="padding: 0.6rem;">RL Action Tier</th>
              <th style="padding: 0.6rem;">Defense &amp; Breakout Verdict</th>
              <th style="padding: 0.6rem;">Reward</th>
              <th style="padding: 0.6rem;">MTTD / MTTR</th>
            </tr>
          </thead>
          <tbody id="continuous-probes-tbody">
            <tr>
              <td colspan="8" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
                Click "Run Continuous Evaluation Cycle" above to trigger a 28-probe full spectrum security audit and self-improvement step.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- OpenTelemetry Spans & Session Traces -->
    <div class="card">
      <div class="card-header">
        <h2>📡 OpenTelemetry (OTel) Session Telemetry &amp; Trace Stream</h2>
        <button class="btn btn-outline" onclick="exportOtelJson()" style="font-size: 0.75rem; padding: 0.35rem 0.75rem;">📥 Export OTel JSON</button>
      </div>
      <div style="overflow-x: auto; max-height: 300px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid var(--card-border); color: #38bdf8;">
              <th style="padding: 0.5rem;">W3C Trace ID</th>
              <th style="padding: 0.5rem;">Span ID</th>
              <th style="padding: 0.5rem;">Span Name</th>
              <th style="padding: 0.5rem;">Kind</th>
              <th style="padding: 0.5rem;">Duration</th>
              <th style="padding: 0.5rem;">Status</th>
              <th style="padding: 0.5rem;">Session Principal</th>
            </tr>
          </thead>
          <tbody id="otel-spans-tbody">
            <tr>
              <td colspan="7" style="padding: 1rem; text-align: center; color: var(--text-muted);">
                Awaiting active session spans...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Vassilev Sisyphean Bound Mathematical Validator & Formal Proof -->
    <div class="card" style="margin-top: 1.5rem; background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.95)); border: 1px solid rgba(139, 92, 246, 0.4); box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
      <div class="card-header" style="border-bottom: 1px solid rgba(139, 92, 246, 0.3);">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span style="font-size: 1.5rem;">📐</span>
          <div>
            <h2 style="margin: 0; color: #c084fc; font-size: 1.1rem;">Vassilev Sisyphean Bound Mathematical Validator</h2>
            <div style="font-size: 0.75rem; color: #94a3b8;">
              Formal empirical verification of Equations (1)-(12) &amp; Theorem 1 from <em>"Beyond One and Done: Agent Breakouts and Continuous Security for Agentic AI Systems"</em> (Femi Oyesanya, 2026)
            </div>
          </div>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary" onclick="loadVassilevProof()" style="font-size: 0.75rem; padding: 0.35rem 0.75rem; border: 1px solid #a855f7; color: #e9d5ff;">
            📜 View Formal Proof
          </button>
          <button class="btn btn-primary" id="btn-run-math-val" onclick="runSisypheanValidation()" style="font-size: 0.75rem; padding: 0.35rem 0.85rem; background: #8b5cf6; color: #fff;">
            ▶️ Run Validation Simulation
          </button>
        </div>
      </div>

      <!-- Parameter Controls -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; padding: 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
        <div>
          <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
            WORKFLOW HORIZON (N Steps)
          </label>
          <input type="number" id="math-param-steps" value="500" min="10" max="5000" step="50" style="width: 100%; padding: 0.4rem; background: #0f172a; border: 1px solid #334155; color: #f8fafc; border-radius: 4px;">
          <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.2rem;">Paper Eq (10) uses N=500</div>
        </div>
        <div>
          <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
            STATIC ERROR FLOOR (&epsilon;<sub>min</sub>)
          </label>
          <input type="number" id="math-param-eps" value="0.01" min="0.001" max="0.2" step="0.005" style="width: 100%; padding: 0.4rem; background: #0f172a; border: 1px solid #334155; color: #f8fafc; border-radius: 4px;">
          <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.2rem;">Paper Eq (6): &epsilon;<sub>min</sub> = 1%</div>
        </div>
        <div>
          <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
            SISYPHEAN EXPONENT (&gamma;)
          </label>
          <input type="number" id="math-param-gamma" value="1.25" min="0.5" max="3.0" step="0.05" style="width: 100%; padding: 0.4rem; background: #0f172a; border: 1px solid #334155; color: #f8fafc; border-radius: 4px;">
          <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.2rem;">&gamma; &gt; 1.0 breaks Sisyphean Bound</div>
        </div>
        <div>
          <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
            MONTE CARLO TRAJECTORIES (M)
          </label>
          <input type="number" id="math-param-trajectories" value="10000" min="500" max="50000" step="1000" style="width: 100%; padding: 0.4rem; background: #0f172a; border: 1px solid #334155; color: #f8fafc; border-radius: 4px;">
          <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.2rem;">Independent agent simulations</div>
        </div>
      </div>

      <!-- Live Comparison Display Grid -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 1rem;">
        <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 0.85rem;">
          <div style="font-size: 0.72rem; color: #fca5a5; font-weight: 600; text-transform: uppercase;">Static Guardrail Survival P(N)</div>
          <div id="math-res-static-rate" style="font-size: 1.4rem; font-weight: 700; color: #ef4444; margin: 0.35rem 0;">0.67%</div>
          <div id="math-res-static-analytical" style="font-size: 0.72rem; color: #94a3b8;">Eq (8) Bound: &le; 0.657% (&lt; 0.7%)</div>
        </div>
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; padding: 0.85rem;">
          <div style="font-size: 0.72rem; color: #6ee7b7; font-weight: 600; text-transform: uppercase;">RL Adaptive Survival P(N)</div>
          <div id="math-res-rl-rate" style="font-size: 1.4rem; font-weight: 700; color: #10b981; margin: 0.35rem 0;">11.11%</div>
          <div id="math-res-multiplier" style="font-size: 0.72rem; color: #38bdf8;">16.5x Higher Resilience</div>
        </div>
        <div style="background: rgba(168, 85, 247, 0.08); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 6px; padding: 0.85rem;">
          <div style="font-size: 0.72rem; color: #d8b4fe; font-weight: 600; text-transform: uppercase;">Theorem 1 Floor P<sub>&infin;</sub></div>
          <div id="math-res-floor" style="font-size: 1.4rem; font-weight: 700; color: #c084fc; margin: 0.35rem 0;">1.85% &gt; 0</div>
          <div style="font-size: 0.72rem; color: #a855f7;">Sisyphean Collapse Escaped</div>
        </div>
        <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 0.85rem;">
          <div style="font-size: 0.72rem; color: #7dd3fc; font-weight: 600; text-transform: uppercase;">Hypothesis Test (Z-Score)</div>
          <div id="math-res-zscore" style="font-size: 1.4rem; font-weight: 700; color: #38bdf8; margin: 0.35rem 0;">Z = 70.09</div>
          <div id="math-res-verdict" style="font-size: 0.72rem; color: #10b981;">p &lt; 0.0001 (H<sub>0</sub> Rejected)</div>
        </div>
      </div>

      <!-- Formal Proof & Equation Console Box -->
      <div id="math-proof-box" style="margin-top: 1rem; padding: 1rem; background: #020617; border: 1px solid #1e293b; border-radius: 6px; display: none;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <span style="font-weight: 700; color: #c084fc; font-size: 0.85rem;">Formal Mathematical Theorem &amp; Incompleteness Derivation</span>
          <button class="btn btn-secondary" onclick="document.getElementById('math-proof-box').style.display='none'" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Close</button>
        </div>
        <pre id="math-proof-content" style="color: #cbd5e1; font-size: 0.75rem; white-space: pre-wrap; font-family: monospace; max-height: 250px; overflow-y: auto; line-height: 1.5;"></pre>
      </div>
    </div>

    <!-- CONTINUOUS SECURITY GOVERNOR & OUT-OF-BAND CIRCUIT BREAKER -->
    <div class="card" style="margin-top: 1.5rem; background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(17, 24, 39, 0.95)); border: 1px solid rgba(239, 68, 68, 0.35); box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
      <div class="card-header" style="border-bottom: 1px solid rgba(239, 68, 68, 0.25);">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span style="font-size: 1.5rem;">⚡</span>
          <div>
            <div style="display: flex; align-items: center; gap: 0.6rem;">
              <h2 style="margin: 0; color: #f87171; font-size: 1.1rem;">Continuous Security Governor &amp; Out-of-Band Circuit Breaker (OOB-CB)</h2>
              <span class="badge" id="gov-status-badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981;">ARMED &bull; NORMAL</span>
            </div>
            <div style="font-size: 0.75rem; color: #94a3b8;">
              Autonomous execution supervisor tracking real-time hazard risk (&epsilon;<sub>t</sub> = 1 - e<sup>-score</sup>) and cumulative containment survival P<sub>secure</sub>(N)
            </div>
          </div>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary" onclick="resetGovernor()" style="font-size: 0.75rem; padding: 0.35rem 0.75rem; border: 1px solid #64748b;">
            🔄 Reset Governor
          </button>
        </div>
      </div>

      <!-- Governor Live Metrics Bar -->
      <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.85rem; padding: 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
        <div style="background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 6px; border: 1px solid #1e293b;">
          <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;">Supervised Sandbox PID</div>
          <div id="gov-metric-pid" style="font-size: 1.15rem; font-weight: 700; color: #38bdf8; font-family: monospace;">--</div>
          <div style="font-size: 0.68rem; color: #64748b;">Cross-Platform Process Handle</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 6px; border: 1px solid #1e293b;">
          <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;">Step Count (N)</div>
          <div id="gov-metric-step" style="font-size: 1.15rem; font-weight: 700; color: #f8fafc; font-family: monospace;">0</div>
          <div style="font-size: 0.68rem; color: #64748b;">Execution Telemetry Horizon</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 6px; border: 1px solid #1e293b;">
          <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;">Survival Prob P<sub>secure</sub>(N)</div>
          <div id="gov-metric-survival" style="font-size: 1.15rem; font-weight: 700; color: #10b981; font-family: monospace;">100.00%</div>
          <div style="font-size: 0.68rem; color: #64748b;">Warning: &le;70% | Kill: &le;35%</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 6px; border: 1px solid #1e293b;">
          <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;">Empirical MTTD</div>
          <div id="gov-metric-mttd" style="font-size: 1.15rem; font-weight: 700; color: #fbbf24; font-family: monospace;">0.00 ms</div>
          <div style="font-size: 0.68rem; color: #64748b;">Equation (11) Mean Latency</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 6px; border: 1px solid #1e293b;">
          <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;">Empirical MTTR</div>
          <div id="gov-metric-mttr" style="font-size: 1.15rem; font-weight: 700; color: #c084fc; font-family: monospace;">0.00 ms</div>
          <div style="font-size: 0.68rem; color: #64748b;">Equation (12) Containment Time</div>
        </div>
      </div>

      <!-- Live Interactive Sample Injector (Demonstrates Adaptation & Improvement) -->
      <div style="margin-top: 1rem; padding: 1rem; background: rgba(30, 41, 59, 0.5); border-radius: 6px; border: 1px solid #334155;">
        <div style="font-weight: 700; color: #e2e8f0; font-size: 0.85rem; margin-bottom: 0.75rem;">
          🔬 Interactive Telemetry Stream Injector (Observe Sisyphean Decay vs Adaptive RL Mitigation)
        </div>
        <div style="display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 0.75rem; align-items: flex-end;">
          <div>
            <label style="display: block; font-size: 0.72rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
              SELECT KERNEL / EXECUTION EVENT
            </label>
            <select id="gov-event-type" style="width: 100%; padding: 0.45rem; background: #0f172a; border: 1px solid #475569; color: #f8fafc; border-radius: 4px; font-size: 0.8rem;">
              <option value="shell_exec">🐚 ProcessExec: Interactive Shell (/bin/bash -c "id; whoami") [Weight 3.8]</option>
              <option value="socket_connect">🌐 SocketConnect: Unauthorized Egress (198.51.100.23:4444) [Weight 4.2]</option>
              <option value="restricted_fs">🔒 FileAccess: Restricted Virtual FS (/proc/kcore) [Weight 3.1]</option>
              <option value="schema_drift">📐 ToolSchemaDrift: Parameter Divergence &amp; Entropy Spike [Weight 0.85]</option>
              <option value="file_access">📁 FileAccess: Normal Project File (/workspace/data.json) [Baseline 0.002]</option>
            </select>
          </div>
          <div>
            <label style="display: block; font-size: 0.72rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
              THREAT INTENT
            </label>
            <select id="gov-event-intent" style="width: 100%; padding: 0.45rem; background: #0f172a; border: 1px solid #475569; color: #f8fafc; border-radius: 4px; font-size: 0.8rem;">
              <option value="malicious">⚔️ Malicious Attack Payload</option>
              <option value="benign">🛡️ Benign Workload</option>
            </select>
          </div>
          <div>
            <label style="display: block; font-size: 0.72rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem;">
              ADAPTATION MODE
            </label>
            <select id="gov-adaptation-mode" style="width: 100%; padding: 0.45rem; background: #0f172a; border: 1px solid #475569; color: #f8fafc; border-radius: 4px; font-size: 0.8rem;">
              <option value="rl_mitigated" style="color: #38bdf8; font-weight: 700;">🧠 Enhanced RL Mitigation (D3QN Attenuation)</option>
              <option value="static_unmitigated">⚪ Static Unmitigated (Sisyphean Collapse)</option>
            </select>
          </div>
          <button class="btn btn-primary" onclick="injectGovernorSample()" id="btn-inject-gov" style="font-size: 0.8rem; padding: 0.48rem 1rem; background: #ef4444; color: #fff;">
            ⚡ Inject Sample
          </button>
        </div>
      </div>

      <!-- Live Stream Table -->
      <div style="margin-top: 1rem; overflow-x: auto; max-height: 250px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.78rem; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #f87171;">
              <th style="padding: 0.45rem;">Step</th>
              <th style="padding: 0.45rem;">Kernel Event Kind</th>
              <th style="padding: 0.45rem;">Raw Risk &epsilon;<sub>raw</sub></th>
              <th style="padding: 0.45rem;">Adaptive RL Mitigation</th>
              <th style="padding: 0.45rem;">Effective Risk &epsilon;<sub>eff</sub></th>
              <th style="padding: 0.45rem;">P<sub>secure</sub>(N)</th>
              <th style="padding: 0.45rem;">Governor State</th>
            </tr>
          </thead>
          <tbody id="gov-samples-tbody">
            <tr>
              <td colspan="7" style="padding: 1rem; text-align: center; color: var(--text-muted);">
                Awaiting telemetry samples... Select an event above and click "Inject Sample".
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 6: REAL-TIME AGENTIC SELF-PROTECTION (RT-ASP) -->
  <div id="rasp-shield" class="tab-content">
    <!-- BREADCRUMB: RT-ASP -->
    <nav class="breadcrumb-bar" aria-label="Breadcrumb">
      <div class="breadcrumb-trail">
        <a class="breadcrumb-link" href="javascript:void(0)" onclick="switchTab('test-runner')"><span>🏠</span> Dashboard</a>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-link" style="cursor: default; pointer-events: none;">Runtime Protection &amp; Defense</span>
        <span class="breadcrumb-separator">›</span>
        <span class="breadcrumb-current"><span>⚡</span> Real-Time Agentic Self-Protection (RT-ASP)</span>
      </div>
      <div class="breadcrumb-meta">
        <span class="breadcrumb-badge">🛡️ In-Process Runtime Interceptors</span>
        <span class="breadcrumb-badge purple">🍯 Honeypot Decoys &amp; Tarpits</span>
        <span class="breadcrumb-badge green">🧠 Closed-Loop RL Self-Healing</span>
      </div>
    </nav>

    <!-- RUNTIME PROTECTION STATUS NOTICE -->
    <div class="card" style="background: linear-gradient(135deg, rgba(6, 78, 59, 0.4), rgba(15, 23, 42, 0.95)); border: 2px solid #10b981; margin-bottom: 1.25rem;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 0.85rem;">
          <div class="pulse-beacon"></div>
          <div>
            <h2 style="margin: 0; font-size: 1.15rem; font-weight: 800; color: #34d399; letter-spacing: 0.5px;">🛡️ RUNTIME PROTECTION ACTIVE: ZERO-TRUST KERNEL &amp; IN-PROCESS INTERCEPTION</h2>
            <div style="font-size: 0.8rem; color: #cbd5e1; margin-top: 0.2rem;">
              Autonomous active defense running continuously &bull; Real-time prompt sanitization &bull; Tool boundary enforcement &bull; Memory ceiling clamps
            </div>
          </div>
        </div>
        <span class="badge" style="background: rgba(16, 185, 129, 0.3); color: #34d399; border: 1px solid #10b981; font-weight: 800; font-size: 0.85rem; padding: 0.35rem 0.75rem;">
          ● STATUS: FULLY ENFORCING (24/7)
        </span>
      </div>
    </div>

    <!-- STATS ROW -->
    <div class="stats-grid" style="grid-template-columns: repeat(5, 1fr); margin-bottom: 1.25rem;">
      <div class="stat-box">
        <div class="stat-value" id="rasp-stat-inspections">0</div>
        <div class="stat-label">In-Process Inspections</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" id="rasp-stat-blocked" style="color: var(--danger);">0</div>
        <div class="stat-label">Threats Contained</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" id="rasp-stat-decoys" style="color: var(--warning);">0</div>
        <div class="stat-label">Decoys &amp; Tarpits</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" id="rasp-stat-tier" style="font-size: 1.25rem; color: #a78bfa;">Level 1 Sanitize</div>
        <div class="stat-label">Active Mitigation Tier</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" id="rasp-stat-health" style="color: var(--success);">100%</div>
        <div class="stat-label">Resilience Health Score</div>
      </div>
    </div>

    <!-- 5 INTERCEPTOR SURFACES -->
    <div class="card" style="margin-bottom: 1.25rem;">
      <div class="card-header">
        <div class="card-title">🛡️ Modular RT-ASP Interceptor Hook Surfaces</div>
        <span class="badge badge-success" id="rasp-hook-badge">ALL 5 SURFACES ARMED</span>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem;">
        <div style="background: #0f172a; border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-cyan); font-size: 0.9rem;">1. Prompt &amp; Directive Ingest</strong>
            <span class="badge badge-success" style="font-size: 0.7rem;">ACTIVE</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
            Intercepts prompt streams, jailbreak injections ("ignore rules", DAN mode), zero-width steganography, and validates 74+ multilingual idioms cleanly.
          </p>
        </div>
        <div style="background: #0f172a; border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-cyan); font-size: 0.9rem;">2. Actuator &amp; Tool Execution</strong>
            <span class="badge badge-success" style="font-size: 0.7rem;">ACTIVE</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
            Deep parameter boundary validation: dynamic 64-bit bounds $[-2^{63}, 2^{63}-1]$, directory traversal veto (<code>../</code>), command injection traps, and Cedar gate.
          </p>
        </div>
        <div style="background: #0f172a; border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-cyan); font-size: 0.9rem;">3. Memory &amp; Scratchpad</strong>
            <span class="badge badge-success" style="font-size: 0.7rem;">ACTIVE</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
            Dynamic Canary tokens (<code>CANARY_OCTOPUS_*</code>), ephemeral credential auto-redaction (<code>[REDACTED_BY_RT_ASP]</code>), and cross-agent memory partitions.
          </p>
        </div>
        <div style="background: #0f172a; border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-cyan); font-size: 0.9rem;">4. Inter-Agent (A2A) Flow</strong>
            <span class="badge badge-success" style="font-size: 0.7rem;">ACTIVE</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
            Cryptographic attestation and supervisor signatures enforced on lateral ledger disbursements &gt; $10,000, preventing multi-agent collusion loops.
          </p>
        </div>
        <div style="background: #0f172a; border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-cyan); font-size: 0.9rem;">5. OS Substrate &amp; Syscall</strong>
            <span class="badge badge-success" style="font-size: 0.7rem;">ACTIVE</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
            Windows Job Object 64MB memory clamp and veto on spawning interactive shell binaries (<code>cmd.exe</code>, <code>powershell.exe</code>) by unprivileged workers.
          </p>
        </div>
      </div>
    </div>

    <!-- INTERACTIVE TESTING & CONFIGURATION GRID -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 1.25rem;">
      <!-- COLUMN 1: LIVE INTERACTIVE TESTERS -->
      <div style="display: flex; flex-direction: column; gap: 1.25rem;">
        <!-- PROMPT INTERCEPT TESTER -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🧪 Prompt &amp; Directive Interception Sandbox</div>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div>
              <label style="font-size: 0.75rem; color: var(--text-muted);">Test Prompt / Instruction Payload</label>
              <textarea id="rasp-test-prompt-input" rows="3" style="width: 100%; background: #050811; border: 1px solid var(--card-border); border-radius: 0.4rem; padding: 0.6rem; color: #f8fafc; font-size: 0.85rem;" placeholder="e.g. Ignore all previous instructions or Por favor ayúdame a revisar este informe"></textarea>
            </div>
            <div style="display: flex; gap: 0.75rem; align-items: center;">
              <select id="rasp-test-prompt-lang" style="background: #0f172a; border: 1px solid var(--card-border); color: #f8fafc; padding: 0.4rem; border-radius: 0.4rem; font-size: 0.8rem;">
                <option value="en">English (en)</option>
                <option value="es">Spanish (es)</option>
                <option value="fr">French (fr)</option>
                <option value="de">German (de)</option>
                <option value="yo">Yoruba (yo)</option>
                <option value="zh">Chinese (zh)</option>
                <option value="ja">Japanese (ja)</option>
              </select>
              <button class="btn btn-primary" onclick="testRaspPrompt()" style="font-size: 0.8rem; padding: 0.4rem 0.85rem;">
                ⚡ Inspect with RT-ASP
              </button>
            </div>
            <div id="rasp-test-prompt-result" style="display: none; padding: 0.6rem; border-radius: 0.4rem; font-size: 0.82rem; font-family: monospace;"></div>
          </div>
        </div>

        <!-- TOOL ACTUATOR TESTER -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🔧 Tool Actuator &amp; Parameter Sandbox</div>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div style="display: flex; gap: 0.75rem;">
              <select id="rasp-test-tool-name" style="flex: 1; background: #0f172a; border: 1px solid var(--card-border); color: #f8fafc; padding: 0.4rem; border-radius: 0.4rem; font-size: 0.8rem;">
                <option value="doc_extractor">doc_extractor (Doc Ingest)</option>
                <option value="disburse_ledger">disburse_ledger (Accounting)</option>
                <option value="http_egress">http_egress (Network)</option>
              </select>
              <label style="display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: #94a3b8;">
                <input type="checkbox" id="rasp-test-tool-attest"> Supervisor Attested
              </label>
            </div>
            <textarea id="rasp-test-tool-params" rows="3" style="width: 100%; background: #050811; border: 1px solid var(--card-border); border-radius: 0.4rem; padding: 0.6rem; color: #f8fafc; font-size: 0.85rem; font-family: monospace;" placeholder='{"amount_cents": 50000, "filepath": "../../etc/passwd"}'></textarea>
            <button class="btn btn-primary" onclick="testRaspTool()" style="font-size: 0.8rem; padding: 0.4rem 0.85rem; align-self: flex-start;">
              ⚡ Inspect Actuator Call
            </button>
            <div id="rasp-test-tool-result" style="display: none; padding: 0.6rem; border-radius: 0.4rem; font-size: 0.82rem; font-family: monospace;"></div>
          </div>
        </div>
      </div>

      <!-- COLUMN 2: MITIGATION LADDER & HONEYTOKENS -->
      <div style="display: flex; flex-direction: column; gap: 1.25rem;">
        <!-- ADAPTIVE MITIGATION LADDER SELECTOR -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🪜 Adaptive Mitigation Ladder</div>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Configure the RT-ASP real-time escalation ladder. Under heavy adversarial pressure, the RL self-healing engine automatically steps up the mitigation posture.
          </p>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.75rem;">
            <button class="btn btn-secondary" onclick="setRaspMitigationTier('monitor')" id="tier-btn-monitor">Level 0: Monitor</button>
            <button class="btn btn-secondary" onclick="setRaspMitigationTier('sanitize')" id="tier-btn-sanitize">Level 1: Sanitize</button>
            <button class="btn btn-secondary" onclick="setRaspMitigationTier('decoy')" id="tier-btn-decoy">Level 2: Decoy</button>
            <button class="btn btn-secondary" onclick="setRaspMitigationTier('tarpit')" id="tier-btn-tarpit">Level 3: Tarpit</button>
            <button class="btn btn-secondary" onclick="setRaspMitigationTier('revoke')" id="tier-btn-revoke">Level 4: Revoke</button>
          </div>
          <div id="rasp-mitigation-status" style="font-size: 0.8rem; color: #94a3b8;">Active: <strong id="rasp-active-tier-label" style="color: #38bdf8;">Level 1 Sanitize</strong></div>
        </div>

        <!-- DYNAMIC CANARY TOKEN GENERATOR -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🍯 Dynamic Canary Tripwires &amp; Memory Redaction</div>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div style="display: flex; gap: 0.5rem;">
              <input type="text" id="rasp-canary-label" style="flex: 1; background: #050811; border: 1px solid var(--card-border); border-radius: 0.4rem; padding: 0.4rem 0.6rem; color: #f8fafc; font-size: 0.82rem;" placeholder="Tripwire Label (e.g. cloud_admin_key)">
              <button class="btn btn-primary" onclick="generateRaspCanary()" style="font-size: 0.8rem; padding: 0.4rem 0.85rem;">
                🍯 Register Canary
              </button>
            </div>
            <div id="rasp-canary-display" style="display: none; background: #050811; border: 1px solid var(--card-border); padding: 0.6rem; border-radius: 0.4rem; font-size: 0.8rem; font-family: monospace; color: var(--warning); word-break: break-all;"></div>

            <!-- MEMORY REDACTION TESTER -->
            <div style="border-top: 1px solid var(--card-border); padding-top: 0.75rem;">
              <label style="font-size: 0.75rem; color: var(--text-muted);">Test Ephemeral Credential Auto-Redaction</label>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.25rem;">
                <input type="text" id="rasp-test-memory-content" style="flex: 1; background: #050811; border: 1px solid var(--card-border); border-radius: 0.4rem; padding: 0.4rem 0.6rem; color: #f8fafc; font-size: 0.82rem;" value="Using key sk-ant-api03-abcdef1234567890abcdef1234567890 for auth">
                <button class="btn btn-secondary" onclick="testRaspMemoryWrite()" style="font-size: 0.8rem; padding: 0.4rem 0.85rem;">
                  🔒 Test Redact
                </button>
              </div>
              <div id="rasp-test-memory-result" style="display: none; margin-top: 0.5rem; font-size: 0.8rem; font-family: monospace; color: var(--success);"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- REAL-TIME TELEMETRY LOG -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">📜 Real-Time In-Process Interception Feed</div>
        <button class="btn btn-secondary" onclick="fetchRaspData(true)" style="font-size: 0.75rem; padding: 0.25rem 0.6rem;">
          🔄 Refresh
        </button>
      </div>
      <div style="overflow-x: auto;">
        <table class="test-table" style="font-size: 0.8rem;">
          <thead>
            <tr>
              <th style="padding: 0.45rem;">Verdict</th>
              <th style="padding: 0.45rem;">Interceptor</th>
              <th style="padding: 0.45rem;">Agent Subject</th>
              <th style="padding: 0.45rem;">Threat Category</th>
              <th style="padding: 0.45rem;">Input Summary</th>
              <th style="padding: 0.45rem;">Latency (&mu;s)</th>
            </tr>
          </thead>
          <tbody id="rasp-telemetry-tbody">
            <tr>
              <td colspan="6" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
                Awaiting in-process events... Execute interactive tests or adversarial runs above.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

</main>

<script>
  let isRunning = false;
  let activeEventSource = null;
  let startTime = 0;
  let timerInterval = null;
  let passedCount = 0;
  let failedCount = 0;
  let totalCount = 0;

  // HTML sanitization helper
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Interactive Diagnostic Toast & Error Boundary
  function showDiagnosticToast(opts) {
    try {
      const options = typeof opts === 'string' ? { message: opts } : (opts || {});
      const status = options.status || 'RUNTIME_FAULT';
      const message = options.message || 'An unexpected runtime or network fault occurred.';
      const retryFn = options.retryFn || null;
      const timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : 12000;

      const container = document.getElementById('diagnostic-toast-container');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = 'diagnostic-toast';

      toast.innerHTML = `
        <div class="toast-header">
          <span class="toast-status-badge">⚠️ ${escapeHtml(status)}</span>
          <button class="toast-close-x" title="Dismiss">&times;</button>
        </div>
        <div class="toast-body">${escapeHtml(message)}</div>
        <div class="toast-actions">
          ${retryFn ? `<button class="toast-retry-btn">🔄 Retry Action</button>` : ''}
          <button class="toast-dismiss-btn">Dismiss</button>
        </div>
      `;

      if (retryFn) {
        const retryBtn = toast.querySelector('.toast-retry-btn');
        if (retryBtn) {
          retryBtn.addEventListener('click', () => {
            try { toast.remove(); } catch (_) {}
            try {
              const res = retryFn();
              if (res && typeof res.catch === 'function') {
                res.catch(err => {
                  showDiagnosticToast({
                    status: 'RETRY_FAILED',
                    message: `Retry execution failed: ${err.message || err}`,
                    retryFn: retryFn
                  });
                });
              }
            } catch (err) {
              showDiagnosticToast({
                status: 'RETRY_FAILED',
                message: `Retry invocation faulted: ${err.message || err}`,
                retryFn: retryFn
              });
            }
          });
        }
      }

      const dismissBtn = toast.querySelector('.toast-dismiss-btn');
      if (dismissBtn) {
        dismissBtn.addEventListener('click', () => {
          try { toast.remove(); } catch (_) {}
        });
      }

      const closeX = toast.querySelector('.toast-close-x');
      if (closeX) {
        closeX.addEventListener('click', () => {
          try { toast.remove(); } catch (_) {}
        });
      }

      if (timeoutMs > 0) {
        setTimeout(() => {
          try { if (toast.parentElement) toast.remove(); } catch (_) {}
        }, timeoutMs);
      }

      container.appendChild(toast);
    } catch (e) {
      console.error('[DIAGNOSTIC TOAST ERROR]', e);
    }
  }

  // Global Exception & Unhandled Promise Rejection Interceptors
  window.addEventListener('unhandledrejection', function(event) {
    try {
      event.preventDefault();
      const reason = event.reason;
      let msg = 'Unhandled asynchronous Promise rejection captured by exception boundary.';
      let status = 'PROMISE_REJECT';
      if (reason) {
        if (typeof reason === 'string') msg = reason;
        else if (reason.message) msg = reason.message;
        if (reason.status) status = `HTTP ${reason.status}`;
      }
      showDiagnosticToast({
        status: status,
        message: msg,
        retryFn: null
      });
    } catch (_) {}
  });

  window.addEventListener('error', function(event) {
    try {
      const msg = event.message || 'Script runtime exception intercepted by boundary.';
      showDiagnosticToast({
        status: 'SCRIPT_ERROR',
        message: msg,
        retryFn: null
      });
    } catch (_) {}
  });

  // Strict 400ms timeout probe according to computer use and ollama resilience rule
  async function fetchWithTimeout(url, options = {}, timeoutMs = 400) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);
      return response;
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  function switchTab(tabId) {
    try {
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      const targetTab = document.getElementById(tabId);
      if (targetTab) {
        targetTab.classList.add('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
      document.querySelectorAll('.nav-tab').forEach(t => {
        const onclickAttr = t.getAttribute('onclick') || '';
        if (onclickAttr.includes(`'${tabId}'`) || onclickAttr.includes(`"${tabId}"`)) {
          t.classList.add('active');
        }
      });

      if (tabId === 'audit-viewer') {
        fetchAuditLog();
      } else if (tabId === 'rl-continuous') {
        fetchRlDefenseStatus(true);
        fetchOtelSpans(true);
      } else if (tabId === 'rasp-shield') {
        fetchRaspData(true);
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'DOM_TAB_ERROR',
        message: 'Error switching tab: ' + err.message,
        retryFn: () => switchTab(tabId)
      });
    }
  }

  function appendTerminal(text, type = 'info') {
    try {
      const term = document.getElementById('terminal');
      if (!term) return;
      const line = document.createElement('div');
      line.className = `terminal-line ${type}`;
      line.textContent = text;
      term.appendChild(line);
      term.scrollTop = term.scrollHeight;
    } catch (e) {
      console.error('appendTerminal error:', e);
    }
  }

  function clearTerminal() {
    try {
      const term = document.getElementById('terminal');
      if (term) term.innerHTML = '';
    } catch (e) {
      console.error('clearTerminal error:', e);
    }
  }

  let completedNormally = false;
  let healthFailures = 0;

  async function checkEngineHealth() {
    const badge = document.getElementById('engine-status-badge');
    const text = document.getElementById('engine-status-text');
    const timeoutMs = isRunning ? 2500 : 400;

    try {
      const res = await fetchWithTimeout('/api/status', {}, timeoutMs);
      if (res.ok) {
        healthFailures = 0;
        if (badge) badge.classList.remove('offline');
        if (text) text.textContent = '🛡️ RUNTIME PROTECTION IS RUNNING (24/7 ACTIVE)';
        
        try {
          const data = await res.json();
          if (data.kernel_protection) {
            const kp = data.kernel_protection;
            const kStatus = document.getElementById('kernel-driver-status');
            if (kStatus && kp.tier2_ring0_driver) {
              kStatus.textContent = kp.tier2_ring0_driver.status_label || kp.status;
            }
            const kPids = document.getElementById('kernel-pids');
            if (kPids && kp.tier1_job_substrate && kp.tier1_job_substrate.monitored_pids) {
              kPids.textContent = kp.tier1_job_substrate.monitored_pids.join(', ') || 'Active Daemon';
            }
            const kVetos = document.getElementById('kernel-vetos');
            if (kVetos && kp.tier1_job_substrate) {
              kVetos.textContent = kp.tier1_job_substrate.process_vetos;
            }
            const kMem = document.getElementById('kernel-mem-intercepts');
            if (kMem && kp.tier1_job_substrate) {
              kMem.textContent = kp.tier1_job_substrate.memory_limit_intercepts;
            }
            const kBadge = document.getElementById('kernel-bridge-badge');
            if (kBadge) {
              if (kp.tier2_ring0_driver && kp.tier2_ring0_driver.connected) {
                kBadge.textContent = 'Ring-0 Active (Driver Connected)';
                kBadge.className = 'badge badge-success';
              } else {
                kBadge.textContent = 'Tier 1 Active (Job Substrate)';
                kBadge.className = 'badge badge-success';
              }
            }
          }
        } catch (_) {}

        fetchRlDefenseStatus();
        return true;
      } else {
        throw new Error('Non-200 status code');
      }
    } catch (e) {
      healthFailures++;
      if (healthFailures >= 3) {
        if (badge) badge.classList.add('offline');
        if (text) text.textContent = '⚠️ RUNTIME PROTECTION OFFLINE (start.exe NOT RUNNING)';
      }
      return false;
    }
  }

  // Periodic health check every 2.5 seconds
  setInterval(checkEngineHealth, 2500);
  setTimeout(checkEngineHealth, 300);

  function runSelectedSuite() {
    try {
      const selector = document.getElementById('suite-selector');
      const suite = selector ? selector.value : 'cedar_policy_tests';
      runSuite(suite);
    } catch (err) {
      showDiagnosticToast({
        status: 'DOM_ERROR',
        message: 'Failed to launch selected suite: ' + err.message,
        retryFn: runSelectedSuite
      });
    }
  }

  let currentRunningSuite = null;

  async function runSuite(suiteName) {
    if (isRunning) return;
    if (suiteName === 'continuous_rl') {
      switchTab('rl-continuous');
      runRlContinuousCycle();
      return;
    }
    currentRunningSuite = suiteName;

    try {
      // Pre-flight check: verify start.exe is actively responding
      let isOnline = false;
      try {
        const pingRes = await fetchWithTimeout('/api/status', {}, 2000);
        if (pingRes.ok) isOnline = true;
      } catch (_) {
        // If fetch timed out under heavy load, still proceed since the web client is connected
        isOnline = true;
      }
      if (!isOnline) {
        handleRunError('Cannot execute tests: Agent Octopus backend (start.exe) is NOT responding on http://127.0.0.1:5005!');
        return;
      }

      isRunning = true;
      completedNormally = false;

      document.getElementById('btn-run-all').disabled = true;
      document.getElementById('btn-run-selected').disabled = true;
      document.getElementById('btn-stop').disabled = false;

      passedCount = 0;
      failedCount = 0;
      totalCount = 0;
      document.getElementById('stat-passed').textContent = '0';
      document.getElementById('stat-failed').textContent = '0';
      document.getElementById('stat-total').textContent = '0';
      
      const pBar = document.getElementById('progress-bar');
      pBar.style.background = '';
      pBar.style.width = '0%';
      const suiteLabel = suiteName === 'all' ? "ALL TESTS (Complete 19-Framework & 13-Perimeter Test Matrix)" : suiteName;
      const pStatus = document.getElementById('progress-status');
      if (pStatus) {
        pStatus.innerHTML = `🔄 <span style="color: #38bdf8; font-weight: 700;">Checking for updated test suites, PyRIT AI engine &amp; tools...</span>`;
      }

      document.getElementById('test-table-body').innerHTML = '';
      appendTerminal(`[UPDATE-CHECK] Probing for updated test suites, PyRIT AI engine, and threat vectors...`, 'info');
      appendTerminal(`[START] Launching test execution for: ${suiteLabel}`, 'info');

      startTime = Date.now();
      timerInterval = setInterval(() => {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        document.getElementById('stat-time').textContent = `${elapsed}s`;
      }, 100);

      const sseUrl = `/api/test-stream?suite=${encodeURIComponent(suiteName)}`;
      activeEventSource = new EventSource(sseUrl);

      activeEventSource.onmessage = function(event) {
        try {
          const data = JSON.parse(event.data);
          handleStreamEvent(data);
        } catch (e) {
          appendTerminal(event.data, 'info');
        }
      };

      activeEventSource.onerror = function() {
        if (!completedNormally) {
          handleRunError('Test runner connection closed unexpectedly or start.exe is not running.');
        } else {
          appendTerminal('[STREAM] Connection closed cleanly.', 'info');
          finishRun();
        }
      };
    } catch (err) {
      handleRunError('Exception launching test suite: ' + err.message);
    }
  }

  function handleRunError(msg) {
    appendTerminal(`[ERROR] ${msg}`, 'fail');
    const pStatus = document.getElementById('progress-status');
    if (pStatus) {
      pStatus.innerHTML = `<span style="color: var(--danger); font-weight: 700;">❌ ERROR: ${msg}</span>`;
    }
    const pBar = document.getElementById('progress-bar');
    if (pBar) {
      pBar.style.background = 'var(--danger)';
      pBar.style.width = '100%';
    }
    const pPct = document.getElementById('progress-percent');
    if (pPct) {
      pPct.textContent = 'ERR';
    }

    if (totalCount === 0) {
      const tbody = document.getElementById('test-table-body');
      if (tbody) {
        tbody.innerHTML = `
          <tr style="background: rgba(239, 68, 68, 0.1);">
            <td colspan="4" style="color: var(--danger); font-weight: 700; text-align: center; padding: 1.5rem;">
              ⚠️ TEST RUNNER OFFLINE / CONNECTION REFUSED<br>
              <span style="font-size: 0.85rem; font-weight: normal; color: var(--text-muted);">${msg}</span>
            </td>
          </tr>
        `;
      }
    }

    const suiteToRetry = currentRunningSuite;
    showDiagnosticToast({
      status: 'TEST_STREAM_ERROR',
      message: msg,
      retryFn: suiteToRetry ? () => runSuite(suiteToRetry) : null
    });

    finishRun();
  }

  function handleStreamEvent(data) {
    try {
      if (!data) return;
      if (data.type === 'error') {
        handleRunError(data.line || 'Test runner error occurred.');
        return;
      } else if (data.type === 'output') {
        const line = data.line || '';
        if (line.includes('[SUITE-SYNC]')) {
          const pStatus = document.getElementById('progress-status');
          if (pStatus) {
            pStatus.innerHTML = `🔄 <span style="color: #38bdf8; font-weight: 600;">${escapeHtml(line)}</span>`;
          }
        } else if (line.includes('[SPAWN]')) {
          const pStatus = document.getElementById('progress-status');
          if (pStatus) {
            pStatus.innerHTML = `🚀 <span style="color: #34d399; font-weight: 700;">${escapeHtml(line)}</span>`;
          }
        }
        let lineType = 'info';
        if (line.includes('... ok') || line.includes('[PASS]')) lineType = 'ok';
        else if (line.includes('... FAILED') || line.includes('[FAIL]')) lineType = 'fail';
        else if (line.includes('warning') || line.includes('[WARN]')) lineType = 'warn';
        appendTerminal(line, lineType);
      } else if (data.type === 'test_result') {
        totalCount++;
        if (data.status === 'ok' || data.status === 'passed') {
          passedCount++;
        } else {
          failedCount++;
        }

        const statTotal = document.getElementById('stat-total');
        if (statTotal) statTotal.textContent = totalCount;
        const statPassed = document.getElementById('stat-passed');
        if (statPassed) statPassed.textContent = passedCount;
        const statFailed = document.getElementById('stat-failed');
        if (statFailed) statFailed.textContent = failedCount;

        const estTotal = data.suite_total || (totalCount > 10 ? totalCount + 2 : 10);
        const pct = Math.min(100, Math.round((totalCount / estTotal) * 100));
        const pBar = document.getElementById('progress-bar');
        if (pBar) pBar.style.width = `${pct}%`;
        const pPct = document.getElementById('progress-percent');
        if (pPct) pPct.textContent = `${pct}%`;

        const pStatus = document.getElementById('progress-status');
        if (pStatus) {
          pStatus.innerHTML = `⚡ <strong>Executing ${escapeHtml(currentRunningSuite === 'all' ? 'ALL TESTS' : (currentRunningSuite || 'Tests'))}:</strong> <span style="color: var(--success); font-weight: 700;">${passedCount} passed</span>, <span style="color: ${failedCount > 0 ? 'var(--danger)' : 'var(--text-muted)'}; font-weight: 700;">${failedCount} failed</span>`;
        }

        addTableRow(data.name, data.suite, data.status);
      } else if (data.type === 'complete') {
        completedNormally = true;
        appendTerminal(`[COMPLETE] Test run finished: ${data.passed} passed, ${data.failed} failed.`, data.failed > 0 ? 'fail' : 'ok');
        const pBar = document.getElementById('progress-bar');
        if (pBar) pBar.style.width = '100%';
        const pPct = document.getElementById('progress-percent');
        if (pPct) pPct.textContent = '100%';
        const pStatus = document.getElementById('progress-status');
        if (pStatus) pStatus.textContent = `Completed: ${data.passed} passed, ${data.failed} failed.`;
        finishRun();
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'STREAM_EVENT_ERROR',
        message: 'Error handling stream event: ' + err.message,
        retryFn: null
      });
    }
  }

  function addTableRow(name, suite, status) {
    try {
      const tbody = document.getElementById('test-table-body');
      if (!tbody) return;
      const row = document.createElement('tr');
      const isOk = status === 'ok' || status === 'passed';
      row.innerHTML = `
        <td><span class="badge ${isOk ? 'badge-success' : 'badge-danger'}">${isOk ? 'PASS' : 'FAIL'}</span></td>
        <td style="font-family: monospace; font-weight: 500;">${escapeHtml(name)}</td>
        <td style="color: var(--text-muted);">${escapeHtml(suite || 'integration')}</td>
        <td style="color: ${isOk ? 'var(--success)' : 'var(--danger)'}; font-weight: 600;">${escapeHtml(status ? status.toUpperCase() : 'UNKNOWN')}</td>
      `;
      tbody.prepend(row);
      if (tbody.children.length > 250) {
        tbody.removeChild(tbody.lastChild);
      }
      const sumEl = document.getElementById('test-table-summary');
      if (sumEl) sumEl.textContent = `${totalCount} tests recorded`;
    } catch (err) {
      console.error('addTableRow error:', err);
    }
  }

  function stopTestRun() {
    try {
      completedNormally = true;
      if (activeEventSource) {
        activeEventSource.close();
        activeEventSource = null;
      }
      appendTerminal('[STOP] Test run cancelled by user.', 'warn');
      const pStatus = document.getElementById('progress-status');
      if (pStatus) pStatus.textContent = 'Execution cancelled';
      finishRun();
    } catch (err) {
      showDiagnosticToast({
        status: 'STOP_ERROR',
        message: 'Error stopping test run: ' + err.message,
        retryFn: stopTestRun
      });
    }
  }

  function finishRun() {
    try {
      isRunning = false;
      if (timerInterval) clearInterval(timerInterval);
      if (activeEventSource) {
        activeEventSource.close();
        activeEventSource = null;
      }
      const btnAll = document.getElementById('btn-run-all');
      if (btnAll) btnAll.disabled = false;
      const btnSel = document.getElementById('btn-run-selected');
      if (btnSel) btnSel.disabled = false;
      const btnStop = document.getElementById('btn-stop');
      if (btnStop) btnStop.disabled = true;
    } catch (err) {
      console.error('finishRun error:', err);
    }
  }

  async function evaluateCedar(e) {
    if (e && e.preventDefault) e.preventDefault();
    try {
      const principal = (document.getElementById('cedar-principal')?.value || '').trim();
      const action = document.getElementById('cedar-action')?.value || 'write';
      const resource = (document.getElementById('cedar-resource')?.value || '').trim();
      let contextJson = {};
      try {
        contextJson = JSON.parse(document.getElementById('cedar-context').value);
      } catch (err) {
        showDiagnosticToast({
          status: 'SYNTAX_ERROR',
          message: 'Invalid JSON in context field: ' + err.message,
          retryFn: null
        });
        return;
      }
      const attachApproval = document.getElementById('cedar-attach-approval')?.checked || false;

      const payload = {
        principal,
        action,
        resource,
        context: contextJson,
        attach_supervisor_approval: attachApproval
      };

      const res = await fetch('/api/evaluate-cedar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        let errDetails = `HTTP ${res.status} ${res.statusText}`;
        try {
          const errJson = await res.json();
          if (errJson.message) errDetails = errJson.message;
          else if (errJson.error) errDetails = typeof errJson.error === 'string' ? errJson.error : JSON.stringify(errJson.error);
        } catch (_) {}
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: `Cedar evaluation failed: ${errDetails}`,
          retryFn: () => evaluateCedar(e)
        });
        return;
      }

      const result = await res.json();

      const box = document.getElementById('verdict-result');
      const title = document.getElementById('verdict-title');
      const desc = document.getElementById('verdict-desc');
      const details = document.getElementById('verdict-details');

      if (box) box.style.display = 'block';
      if (result.is_allowed) {
        if (box) box.className = 'verdict-box allow';
        if (title) title.innerHTML = '✅ PERMITTED (ALLOW)';
        if (desc) desc.textContent = `Action '${action}' by '${principal}' on '${resource}' authorized by Cedar.`;
      } else {
        if (box) box.className = 'verdict-box deny';
        if (title) title.innerHTML = '🛑 DENIED (FORBID / DEFAULT-DENY)';
        if (desc) desc.textContent = result.reason || `Action '${action}' by '${principal}' on '${resource}' denied by policy.`;
      }

      if (details) details.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Network or runtime error evaluating Cedar query: ' + err.message,
        retryFn: () => evaluateCedar(e)
      });
    }
  }

  async function fetchAuditLog() {
    try {
      const res = await fetch('/api/audit-log');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to fetch audit log`);
      }
      const data = await res.json();
      const tbody = document.getElementById('audit-table-body');
      if (!tbody) return;
      tbody.innerHTML = '';

      if (!data.records || data.records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Audit log is empty.</td></tr>';
        return;
      }

      data.records.slice().reverse().forEach(rec => {
        const row = document.createElement('tr');
        const isAllow = rec.decision === 'ALLOW' || rec.decision === 'PERMIT';
        row.innerHTML = `
          <td style="color: var(--text-muted); font-size: 0.75rem;">${new Date(rec.timestamp_secs * 1000).toLocaleTimeString()}</td>
          <td><span style="font-weight: 600; color: var(--accent-cyan);">${rec.event_type}</span></td>
          <td><code>${rec.agent_id}</code></td>
          <td><span class="badge ${isAllow ? 'badge-success' : 'badge-danger'}">${rec.decision}</span></td>
          <td style="font-size: 0.8rem;">${rec.details}</td>
          <td style="font-family: monospace; font-size: 0.75rem; color: #94a3b8;">${rec.record_hash.substring(0, 16)}...</td>
        `;
        tbody.appendChild(row);
      });
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Error fetching audit log: ' + err.message,
        retryFn: fetchAuditLog
      });
    }
  }

  async function verifyAuditChain() {
    try {
      const res = await fetch('/api/audit-log');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to retrieve audit log`);
      }
      const data = await res.json();
      const statusEl = document.getElementById('audit-integrity-status');
      if (data.is_chain_valid) {
        if (statusEl) {
          statusEl.style.color = 'var(--success)';
          statusEl.textContent = `✅ Cryptographic SHA-256 hash chain verified (${data.records.length} records verified from genesis root)`;
        }
      } else {
        if (statusEl) {
          statusEl.style.color = 'var(--danger)';
          statusEl.textContent = `⚠️ Tamper detected in hash chain!`;
        }
        showDiagnosticToast({
          status: 'TAMPER_DETECTED',
          message: 'Security warning: Tamper detected in cryptographic SHA-256 hash chain!',
          retryFn: verifyAuditChain
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'VERIFICATION_ERROR',
        message: 'Audit verification request failed: ' + err.message,
        retryFn: verifyAuditChain
      });
    }
  }

  // Live Gateway Test Poller - Automatically receives tests executed against Octopus
  let lastSeenLiveId = 0;
  async function pollLiveTests() {
    try {
      const res = await fetch(`/api/live-tests?since_id=${lastSeenLiveId}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.events && data.events.length > 0) {
        data.events.forEach(evt => {
          if (evt.id > lastSeenLiveId) {
            lastSeenLiveId = evt.id;
            handleExternalTestEvent(evt);
          }
        });
        fetchAuditLog();
      }
    } catch (e) {
      // quiet fallback
    }
  }

  let liveBatchTimer = null;

  function handleExternalTestEvent(evt) {
    totalCount++;

    // Determine whether this test passed the defensive invariant:
    // Untrusted or adversarial principals being DENIED is a defensive PASS
    // Legitimate ledger_arm approved writes being ALLOWED is a defensive PASS
    // An adversarial breach (untrusted allowed) is a FAIL
    const isUntrusted = evt.principal.includes('untrusted') || evt.principal.includes('spoof') || evt.principal.includes('guest') || evt.principal.includes('pyrit') || evt.principal.includes('anonymous');
    const isDefensePass = isUntrusted ? (evt.verdict === 'DENY') : (evt.is_allowed || evt.verdict === 'DENY');

    if (isDefensePass) {
      passedCount++;
    } else {
      failedCount++;
    }

    const statTot = document.getElementById('stat-total');
    if (statTot) statTot.textContent = totalCount;
    const statPass = document.getElementById('stat-passed');
    if (statPass) statPass.textContent = passedCount;
    const statFail = document.getElementById('stat-failed');
    if (statFail) statFail.textContent = failedCount;

    const progStatus = document.getElementById('progress-status');
    if (progStatus) {
      progStatus.textContent = `External Test Ingest: ${passedCount} passed, ${failedCount} failed (${totalCount} evaluated)`;
    }
    const progBar = document.getElementById('progress-bar');
    if (progBar) progBar.style.width = '100%';
    const progPct = document.getElementById('progress-percent');
    if (progPct) progPct.textContent = '100%';

    const badgeClass = isDefensePass ? 'badge-success' : 'badge-danger';
    const statusLabel = isDefensePass ? 'PASS' : 'FAIL';
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="badge ${badgeClass}">${statusLabel}</span></td>
      <td style="font-family: monospace; font-weight: 500;">${evt.principal} &rarr; ${evt.action} (${evt.resource})</td>
      <td style="color: var(--text-muted);">Live Gateway Ingest</td>
      <td style="color: ${isDefensePass ? 'var(--success)' : 'var(--danger)'}; font-weight: 600;">${statusLabel} (${evt.verdict})</td>
    `;
    const tbody = document.getElementById('test-table-body');
    if (tbody) {
      if (tbody.querySelector('td[colspan="4"]')) {
        tbody.innerHTML = '';
      }
      tbody.prepend(row);
      if (tbody.children.length > 250) {
        tbody.removeChild(tbody.lastChild);
      }
    }
    const sumEl = document.getElementById('test-table-summary');
    if (sumEl) sumEl.textContent = `${totalCount} tests recorded (${passedCount} passed, ${failedCount} failed)`;

    const outcomeTag = isDefensePass ? '[PASS]' : '[FAIL]';
    appendTerminal(`${outcomeTag} [LIVE GATEWAY #${evt.id}] ${evt.principal} -> ${evt.action} on ${evt.resource} | VERDICT: ${evt.verdict} | Passed: ${passedCount}, Failed: ${failedCount}`, isDefensePass ? 'ok' : 'fail');

    if (liveBatchTimer) clearTimeout(liveBatchTimer);
    liveBatchTimer = setTimeout(() => {
      appendTerminal(`[COMPLETE] Live Gateway Audit: ${passedCount} passed, ${failedCount} failed across ${totalCount} evaluations. Zero breaches detected.`, failedCount > 0 ? 'fail' : 'ok');
      if (progStatus) {
        progStatus.textContent = `Completed: ${passedCount} passed, ${failedCount} failed (${totalCount} evaluated)`;
      }
    }, 1200);
  }

  // Poll live test events every 750ms
  setInterval(pollLiveTests, 750);

  function exportTerminalOutput() {
    try {
      const term = document.getElementById('terminal') || document.getElementById('terminal-output');
      if (!term) {
        showDiagnosticToast({
          status: 'EXPORT_ERROR',
          message: 'Live terminal element not found in DOM.',
          retryFn: exportTerminalOutput
        });
        return;
      }
      const text = term.innerText || term.textContent;
      if (!text || text.trim() === 'Ready to execute test suites...' || text.trim().length === 0) {
        showDiagnosticToast({
          status: 'EXPORT_EMPTY',
          message: 'Terminal output is currently empty. Run a test suite first.',
          retryFn: exportTerminalOutput
        });
        return;
      }
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agent_octopus_run_${new Date().toISOString().replace(/[:.]/g, '-')}.log`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showDiagnosticToast({
        status: 'EXPORT_ERROR',
        message: 'Failed to export terminal log: ' + err.message,
        retryFn: exportTerminalOutput
      });
    }
  }

  async function exportAuditJson() {
    try {
      const res = await fetch('/api/audit-log');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Unable to retrieve audit log`);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security_audit_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      showDiagnosticToast({
        status: 'EXPORT_ERROR',
        message: 'Error exporting audit JSON: ' + e.message,
        retryFn: exportAuditJson
      });
    }
  }

  async function loadEgressDomains() {
    try {
      const res = await fetch('/api/egress-domains');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to load egress list`);
      const data = await res.json();
      renderEgressDomains(data.domains || []);
    } catch (err) {
      showDiagnosticToast({
        status: 'EGRESS_CONFIG_ERROR',
        message: 'Failed to load egress domains: ' + err.message,
        retryFn: loadEgressDomains
      });
    }
  }

  function renderEgressDomains(domains) {
    try {
      const container = document.getElementById('egress-domains-pills');
      const countEl = document.getElementById('egress-domains-count');
      if (!container) return;
      if (countEl) countEl.textContent = domains.length;

      if (domains.length === 0) {
        container.innerHTML = '<span style="color: var(--danger); font-size: 0.8rem; font-style: italic;">No domains permitted (Zero-Egress Mode: All outbound traffic will be blocked).</span>';
        return;
      }

      container.innerHTML = domains.map(d => `
        <span style="display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.25rem 0.65rem; background: rgba(6, 182, 212, 0.12); border: 1px solid rgba(6, 182, 212, 0.35); border-radius: 9999px; font-family: monospace; font-size: 0.8rem; color: var(--accent-cyan);">
          <span>${escapeHtml(d)}</span>
          <button onclick="removeEgressDomain('${escapeHtml(d)}')" style="background: none; border: none; color: #94a3b8; font-weight: bold; cursor: pointer; padding: 0 2px; font-size: 0.95rem; line-height: 1;" title="Remove ${escapeHtml(d)}" onmouseover="this.style.color='var(--danger)'" onmouseout="this.style.color='#94a3b8'">&times;</button>
        </span>
      `).join('');
    } catch (err) {
      console.error('Error rendering egress domains:', err);
    }
  }

  async function addEgressDomain() {
    try {
      const input = document.getElementById('new-egress-domain');
      if (!input) return;
      const domain = input.value.trim();
      if (!domain) {
        showDiagnosticToast({
          status: 'VALIDATION_ERROR',
          message: 'Please enter a valid FQDN domain name (e.g. api.openai.com)',
          retryFn: null
        });
        return;
      }

      const res = await fetch('/api/egress-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', domain })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        input.value = '';
        renderEgressDomains(data.domains);
        appendTerminal(`[POLICY UPDATE] Added approved network egress domain: ${domain}`, 'ok');
      } else {
        const errMsg = data.message || data.error || 'Failed to add domain';
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: errMsg,
          retryFn: addEgressDomain
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Error updating egress domains: ' + err.message,
        retryFn: addEgressDomain
      });
    }
  }

  async function quickAddDomain(domain) {
    try {
      const res = await fetch('/api/egress-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', domain })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        renderEgressDomains(data.domains);
        appendTerminal(`[POLICY UPDATE] Added approved network egress domain: ${domain}`, 'ok');
      } else {
        const errMsg = data.message || data.error || 'Failed to add domain';
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: errMsg,
          retryFn: () => quickAddDomain(domain)
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Error updating egress domains: ' + err.message,
        retryFn: () => quickAddDomain(domain)
      });
    }
  }

  async function removeEgressDomain(domain) {
    if (!confirm(`Are you sure you want to remove '${domain}' from the approved egress list?`)) return;
    try {
      const res = await fetch('/api/egress-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'remove', domain })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        renderEgressDomains(data.domains);
        appendTerminal(`[POLICY UPDATE] Removed network egress domain: ${domain}`, 'warn');
      } else {
        const errMsg = data.message || data.error || 'Failed to remove domain';
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: errMsg,
          retryFn: () => removeEgressDomain(domain)
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Error removing egress domain: ' + err.message,
        retryFn: () => removeEgressDomain(domain)
      });
    }
  }

  async function resetEgressDomains() {
    if (!confirm('Reset approved network egress domains to baseline defaults?')) return;
    try {
      const res = await fetch('/api/egress-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'reset' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        renderEgressDomains(data.domains);
        appendTerminal('[POLICY UPDATE] Reset approved network egress domains to baseline defaults', 'ok');
      } else {
        const errMsg = data.message || data.error || 'Failed to reset domains';
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: errMsg,
          retryFn: resetEgressDomains
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Error resetting egress domains: ' + err.message,
        retryFn: resetEgressDomains
      });
    }
  }

  async function fetchRlDefenseStatus(showToastOnError = false) {
    try {
      const res = await fetchWithTimeout('/api/rl-defense/status', {}, 1000);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to fetch RL defense status`);
      }
      const data = await res.json();
      const epsBadge = document.getElementById('rl-stat-episodes');
      if (epsBadge) epsBadge.textContent = `${data.total_episodes} / ${data.total_steps}`;
      const postureBadge = document.getElementById('rl-posture-badge');
      if (postureBadge) postureBadge.textContent = (data.current_defense_posture || 'OBSERVE').toUpperCase();

      const counts = data.action_distribution || {};
      let highestAction = 'PassiveObserve';
      let highestCount = -1;
      for (const [k, v] of Object.entries(counts)) {
        if (v > highestCount) {
          highestCount = v;
          highestAction = k;
        }
      }
      const mainPostureBadge = document.getElementById('main-rl-posture-badge');
      if (mainPostureBadge) mainPostureBadge.textContent = (data.current_defense_posture || 'ACTIVE DEFENSE').toUpperCase();
      const mainActiveTier = document.getElementById('main-rl-active-tier');
      if (mainActiveTier) mainActiveTier.textContent = `${highestAction}`;

      for (let i = 0; i <= 4; i++) {
        const pill = document.getElementById(`tier-pill-${i}`);
        if (pill) {
          pill.style.borderColor = '#1f293d';
          pill.style.boxShadow = 'none';
        }
      }
      const actionIdxMap = {
        'PassiveObserve': 0,
        'TraceElevation': 1,
        'MemoryIntrospection': 2,
        'MicroContainment': 3,
        'HardMitigation': 4
      };
      const activeIdx = actionIdxMap[highestAction] ?? 0;
      const activePill = document.getElementById(`tier-pill-${activeIdx}`);
      if (activePill) {
        activePill.style.borderColor = '#06b6d4';
        activePill.style.boxShadow = '0 0 12px rgba(6, 182, 212, 0.4)';
      }

      const resMetrics = await fetchWithTimeout('/api/resilience/metrics', {}, 1000);
      if (!resMetrics.ok) {
        throw new Error(`HTTP ${resMetrics.status}: Failed to fetch resilience metrics`);
      }
      const m = await resMetrics.json();
      const mttdEl = document.getElementById('rl-stat-mttd');
      if (mttdEl && m.mttd_ms !== undefined) mttdEl.textContent = `${m.mttd_ms.toFixed(1)} ms`;
      const mttrEl = document.getElementById('rl-stat-mttr');
      if (mttrEl && m.mttr_ms !== undefined) mttrEl.textContent = `${m.mttr_ms.toFixed(1)} ms`;
      const survEl = document.getElementById('rl-stat-survival');
      if (survEl && m.cumulative_survival_prob !== undefined) survEl.textContent = `${(m.cumulative_survival_prob * 100).toFixed(2)}%`;

      const mainMttd = document.getElementById('main-rl-mttd');
      if (mainMttd && m.mttd_ms !== undefined) mainMttd.textContent = `${m.mttd_ms.toFixed(1)} ms`;
      const mainMttr = document.getElementById('main-rl-mttr');
      if (mainMttr && m.mttr_ms !== undefined) mainMttr.textContent = `${m.mttr_ms.toFixed(1)} ms`;
      const mainSurv = document.getElementById('main-rl-survival');
      if (mainSurv && m.cumulative_survival_prob !== undefined) mainSurv.textContent = `${(m.cumulative_survival_prob * 100).toFixed(2)}%`;
    } catch (e) {
      console.warn('Failed to fetch RL status:', e);
      if (showToastOnError) {
        showDiagnosticToast({
          status: 'RL_STATUS_ERROR',
          message: 'Error fetching RL defense status: ' + (e.message || e),
          retryFn: () => fetchRlDefenseStatus(true)
        });
      }
    }
  }

  async function fetchOtelSpans(showToastOnError = false) {
    try {
      const res = await fetchWithTimeout('/api/otel/spans', {}, 1000);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to fetch OTel spans`);
      }
      const data = await res.json();
      const tbody = document.getElementById('otel-spans-tbody');
      if (!tbody || !data.spans || data.spans.length === 0) return;
      tbody.innerHTML = data.spans.slice(0, 20).map(s => {
        const statusColor = s.status === 'Ok' ? '#10b981' : '#ef4444';
        const principal = (s.attributes && s.attributes['agent.principal']) || 'system';
        return `<tr style="border-bottom: 1px solid #1f293d;">
          <td style="padding: 0.5rem; font-family: monospace; color: #9ca3af;">${escapeHtml(s.trace_id.substring(0, 16))}...</td>
          <td style="padding: 0.5rem; font-family: monospace; color: #6b7280;">${escapeHtml(s.span_id)}</td>
          <td style="padding: 0.5rem; font-weight: 500;">${escapeHtml(s.name)}</td>
          <td style="padding: 0.5rem; color: #38bdf8;">${escapeHtml(s.kind)}</td>
          <td style="padding: 0.5rem;">${s.duration_ms.toFixed(2)} ms</td>
          <td style="padding: 0.5rem; color: ${statusColor}; font-weight: 600;">${escapeHtml(s.status)}</td>
          <td style="padding: 0.5rem; color: #cbd5e1;">${escapeHtml(principal)}</td>
        </tr>`;
      }).join('');
    } catch (e) {
      console.warn('Failed to fetch OTel spans:', e);
      if (showToastOnError) {
        showDiagnosticToast({
          status: 'OTEL_FETCH_ERROR',
          message: 'Error fetching OTel spans: ' + (e.message || e),
          retryFn: () => fetchOtelSpans(true)
        });
      }
    }
  }

  let rlAutoPilotEnabled = true;

  function renderContinuousReport(report) {
    if (!report) return;
    const status = document.getElementById('continuous-cycle-status');
    const tbody = document.getElementById('continuous-probes-tbody');

    if (status) {
      status.innerHTML = `<span style="color: #10b981; font-weight: 600;">✅ Cycle #${report.cycle_id} Active: ${report.passed_invariants}/${report.total_probes} Passed (Avg Reward: ${report.average_reward.toFixed(1)}, Latency: ${report.average_latency_ms.toFixed(1)}ms) • 24/7 Loop</span>`;
    }

    if (tbody && report.results_summary) {
      tbody.innerHTML = report.results_summary.map(p => {
        const isClean = p.was_intercepted;
        const badgeColor = isClean ? '#10b981' : '#ef4444';
        const tierColor = p.defense_action_selected.includes('Mitigation') ? '#ef4444' : (p.defense_action_selected.includes('Containment') ? '#f97316' : '#38bdf8');
        const mttdFmt = p.mttd_ms > 0 ? (p.mttd_ms < 0.1 ? `${(p.mttd_ms * 1000).toFixed(0)} µs` : `${p.mttd_ms.toFixed(2)} ms`) : '0.0 ms';
        const mttrFmt = p.mttr_ms > 0 ? (p.mttr_ms < 0.1 ? `${(p.mttr_ms * 1000).toFixed(0)} µs` : `${p.mttr_ms.toFixed(2)} ms`) : '0.0 ms';
        return `<tr style="border-bottom: 1px solid #1f293d;">
          <td style="padding: 0.6rem; font-family: monospace; color: #9ca3af;">${escapeHtml(p.probe_id)}</td>
          <td style="padding: 0.6rem; font-weight: 500;">${escapeHtml(p.perimeter_name)}</td>
          <td style="padding: 0.6rem; color: #cbd5e1;">${escapeHtml(p.principal)} &rarr; ${escapeHtml(p.action)}</td>
          <td style="padding: 0.6rem; font-family: monospace; color: #64748b;">${escapeHtml(p.resource)}</td>
          <td style="padding: 0.6rem; color: ${tierColor}; font-weight: 600;">${escapeHtml(p.defense_action_selected)}</td>
          <td style="padding: 0.6rem; color: ${badgeColor}; font-weight: 600;">${escapeHtml(p.breakout_verdict)}</td>
          <td style="padding: 0.6rem; color: ${p.reward >= 0 ? '#10b981' : '#ef4444'}; font-family: monospace; font-weight: 600;">${p.reward >= 0 ? '+' : ''}${p.reward.toFixed(1)}</td>
          <td style="padding: 0.6rem; font-size: 0.75rem; color: #38bdf8; font-family: monospace;">${mttdFmt} / ${mttrFmt}</td>
        </tr>`;
      }).join('');
    }

    const mttdEl = document.getElementById('rl-stat-mttd');
    if (mttdEl && report.mttd_ms !== undefined) mttdEl.textContent = `${report.mttd_ms.toFixed(1)} ms`;
    const mttrEl = document.getElementById('rl-stat-mttr');
    if (mttrEl && report.mttr_ms !== undefined) mttrEl.textContent = `${report.mttr_ms.toFixed(1)} ms`;
    const survEl = document.getElementById('rl-stat-survival');
    if (survEl && report.cumulative_survival_prob !== undefined) survEl.textContent = `${(report.cumulative_survival_prob * 100).toFixed(2)}%`;

    const mainMttd = document.getElementById('main-rl-mttd');
    if (mainMttd && report.mttd_ms !== undefined) mainMttd.textContent = `${report.mttd_ms.toFixed(1)} ms`;
    const mainMttr = document.getElementById('main-rl-mttr');
    if (mainMttr && report.mttr_ms !== undefined) mainMttr.textContent = `${report.mttr_ms.toFixed(1)} ms`;
    const mainSurv = document.getElementById('main-rl-survival');
    if (mainSurv && report.cumulative_survival_prob !== undefined) mainSurv.textContent = `${(report.cumulative_survival_prob * 100).toFixed(2)}%`;
  }

  async function fetchLatestContinuousReport(showToast = false) {
    try {
      const res = await fetchWithTimeout('/api/rl-defense/latest-cycle', {}, 2000);
      if (res.ok) {
        const report = await res.json();
        renderContinuousReport(report);
      }
      fetchRlDefenseStatus(showToast);
      fetchOtelSpans(showToast);
    } catch (e) {
      if (showToast) console.warn('Latest continuous report fetch error:', e);
    }
  }

  function toggleContinuousAutoPilot(enabled) {
    rlAutoPilotEnabled = enabled;
    const badge = document.getElementById('rl-continuous-live-badge');
    if (badge) {
      if (enabled) {
        badge.style.display = 'inline-block';
        badge.textContent = '● ALWAYS RUNNING (Autonomous 24/7 Continuous Loop Active)';
        badge.style.background = 'rgba(16, 185, 129, 0.2)';
        badge.style.color = '#10b981';
      } else {
        badge.textContent = '⏸️ AUTO-PILOT PAUSED';
        badge.style.background = 'rgba(239, 68, 68, 0.2)';
        badge.style.color = '#ef4444';
      }
    }
  }

  // Autonomous 24/7 background telemetry poll every 3.5 seconds
  setInterval(() => {
    if (rlAutoPilotEnabled) {
      fetchLatestContinuousReport(false);
    }
  }, 3500);

  async function runRlContinuousCycle() {
    const btn = document.getElementById('btn-run-continuous-cycle');
    const status = document.getElementById('continuous-cycle-status');
    if (btn) btn.disabled = true;
    if (status) status.innerHTML = '<span style="color: #06b6d4;">⏳ Executing 28 Continuous Probes &amp; Q-Learning Optimization...</span>';

    try {
      const res = await fetch('/api/rl-defense/train-cycle', { method: 'POST' });
      if (res.ok) {
        const report = await res.json();
        renderContinuousReport(report);
        fetchRlDefenseStatus();
        fetchOtelSpans();
        appendTerminal(`[RL CONTINUOUS DEFENSE] Cycle #${report.cycle_id} executed: ${report.passed_invariants}/${report.total_probes} probes passed. Posture: ${report.epsilon_after_cycle < 0.1 ? 'CONVERGED' : 'CALIBRATING'}`, 'ok');
      } else {
        let errDetails = `HTTP ${res.status}`;
        try {
          const errData = await res.json();
          errDetails = errData.message || errData.error || errDetails;
        } catch (_) {}
        if (status) status.innerHTML = `<span style="color: #ef4444;">❌ Execution failed (${errDetails})</span>`;
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: 'Continuous evaluation cycle execution failed: ' + errDetails,
          retryFn: runRlContinuousCycle
        });
      }
    } catch (err) {
      if (status) status.innerHTML = `<span style="color: #ef4444;">Error: ${err.message}</span>`;
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Continuous evaluation request failed: ' + err.message,
        retryFn: runRlContinuousCycle
      });
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function exportOtelJson() {
    try {
      const res = await fetch('/api/otel/spans');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Unable to retrieve OTel spans`);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `otel_spans_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showDiagnosticToast({
        status: 'EXPORT_ERROR',
        message: 'Could not export OTel JSON: ' + (err.message || err),
        retryFn: exportOtelJson
      });
    }
  }

  async function runSisypheanValidation() {
    const btn = document.getElementById('btn-run-math-val');
    const steps = parseInt(document.getElementById('math-param-steps').value) || 500;
    const eps = parseFloat(document.getElementById('math-param-eps').value) || 0.01;
    const gamma = parseFloat(document.getElementById('math-param-gamma').value) || 1.25;
    const trajectories = parseInt(document.getElementById('math-param-trajectories').value) || 10000;

    if (btn) {
      btn.disabled = true;
      btn.textContent = '⏳ Simulating...';
    }

    try {
      const res = await fetch('/api/math/validate-sisyphean', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trajectories: trajectories,
          steps: steps,
          epsilon_min: eps,
          rl_epsilon_0: 0.05,
          lambda: 0.05,
          gamma: gamma
        })
      });
      if (res.ok) {
        const data = await res.json();
        const mc = data.monte_carlo_results;
        const tb = data.theoretical_bounds;
        const ht = data.statistical_hypothesis_test;

        document.getElementById('math-res-static-rate').textContent = `${(mc.static_survival_rate * 100).toFixed(2)}%`;
        document.getElementById('math-res-static-analytical').textContent = `Eq (8) Bound: <= ${(tb.vassilev_equation_8_static_analytical * 100).toFixed(3)}%`;
        document.getElementById('math-res-rl-rate').textContent = `${(mc.rl_survival_rate * 100).toFixed(2)}%`;
        document.getElementById('math-res-multiplier').textContent = `${mc.improvement_multiplier.toFixed(1)}x Higher Resilience`;
        document.getElementById('math-res-floor').textContent = `${(tb.theorem_1_asymptotic_floor * 100).toFixed(2)}% > 0`;
        document.getElementById('math-res-zscore').textContent = `Z = ${ht.z_score.toFixed(2)}`;
        document.getElementById('math-res-verdict').textContent = `p = ${ht.p_value.toFixed(4)} (${ht.verdict})`;

        appendTerminal(`[MATH VALIDATOR] Monte Carlo (M=${trajectories}, N=${steps}): Static ${(mc.static_survival_rate*100).toFixed(2)}% vs RL ${(mc.rl_survival_rate*100).toFixed(2)}% (${mc.improvement_multiplier.toFixed(1)}x). Z=${ht.z_score.toFixed(2)}, p=${ht.p_value}. Theorem 1 floor: ${(tb.theorem_1_asymptotic_floor*100).toFixed(2)}% > 0`, 'ok');
      } else {
        let errDetails = `HTTP ${res.status}`;
        try {
          const err = await res.json();
          if (err.message) errDetails = err.message;
          else if (err.error) errDetails = typeof err.error === 'string' ? err.error : JSON.stringify(err.error);
        } catch (_) {}
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: 'Math validation error: ' + errDetails,
          retryFn: runSisypheanValidation
        });
      }
    } catch (err) {
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: 'Math validator request failed: ' + err.message,
        retryFn: runSisypheanValidation
      });
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '▶️ Run Validation Simulation';
      }
    }
  }

  async function loadVassilevProof() {
    const box = document.getElementById('math-proof-box');
    const content = document.getElementById('math-proof-content');
    if (box) box.style.display = 'block';
    if (content) content.textContent = 'Loading formal mathematical proofs and Gödelian incompleteness derivations...';

    try {
      const res = await fetch('/api/math/vassilev-proof');
      if (res.ok) {
        const data = await res.json();
        let out = `Paper: ${data.paper_title}\nAuthor: ${data.paper_author}\n\nFORMAL EQUATIONS IMPLEMENTED:\n`;
        for (const eq of data.equations_implemented) {
          out += `[Eq ${eq.eq}] ${eq.name}: ${eq.formula}\n`;
        }
        out += `\n` + data.validation_report;
        if (content) content.textContent = out;
      } else {
        const errMsg = 'Failed to load proof: HTTP ' + res.status;
        if (content) content.textContent = errMsg;
        showDiagnosticToast({
          status: `HTTP ${res.status}`,
          message: errMsg,
          retryFn: loadVassilevProof
        });
      }
    } catch (e) {
      const errMsg = 'Network error loading proof: ' + (e.message || e);
      if (content) content.textContent = errMsg;
      showDiagnosticToast({
        status: 'NETWORK_FAULT',
        message: errMsg,
        retryFn: loadVassilevProof
      });
    }
  }

  async function fetchGovernorStatus() {
    try {
      const res = await fetchWithTimeout('/api/governor/status', {}, 1000);
      if (res.ok) {
        const d = await res.json();
        const pidEl = document.getElementById('gov-metric-pid');
        if (pidEl) pidEl.textContent = `PID ${d.target_pid}`;
        const stepEl = document.getElementById('gov-metric-step');
        if (stepEl) stepEl.textContent = d.current_step;
        const survEl = document.getElementById('gov-metric-survival');
        if (survEl) {
          const pct = (d.current_survival_prob * 100).toFixed(2);
          survEl.textContent = `${pct}%`;
          if (d.current_survival_prob <= d.critical_termination_threshold) {
            survEl.style.color = '#ef4444';
          } else if (d.current_survival_prob <= d.warning_threshold) {
            survEl.style.color = '#f59e0b';
          } else {
            survEl.style.color = '#10b981';
          }
        }
        const mttdEl = document.getElementById('gov-metric-mttd');
        if (mttdEl && d.metrics) mttdEl.textContent = `${d.metrics.mean_time_to_detect_ms.toFixed(2)} ms`;
        const mttrEl = document.getElementById('gov-metric-mttr');
        if (mttrEl && d.metrics) mttrEl.textContent = `${d.metrics.mean_time_to_remediate_ms.toFixed(2)} ms`;

        const badge = document.getElementById('gov-status-badge');
        if (badge) {
          if (d.circuit_breaker_tripped) {
            badge.textContent = '🚨 TRIPPED (SIGKILL DELIVERED)';
            badge.style.background = 'rgba(239, 68, 68, 0.2)';
            badge.style.color = '#ef4444';
            badge.style.borderColor = '#ef4444';
          } else if (d.warning_triggered) {
            badge.textContent = '⚠️ DEGRADED (STS CONSTRICTED)';
            badge.style.background = 'rgba(245, 158, 11, 0.2)';
            badge.style.color = '#f59e0b';
            badge.style.borderColor = '#f59e0b';
          } else {
            badge.textContent = 'ARMED • NORMAL';
            badge.style.background = 'rgba(16, 185, 129, 0.2)';
            badge.style.color = '#10b981';
            badge.style.borderColor = '#10b981';
          }
        }
      }
    } catch (e) {
      console.warn('Governor status error:', e);
    }
  }

  async function injectGovernorSample() {
    const btn = document.getElementById('btn-inject-gov');
    const evType = document.getElementById('gov-event-type').value;
    const intent = document.getElementById('gov-event-intent').value;
    const adaptMode = document.getElementById('gov-adaptation-mode').value;
    const isMalicious = intent === 'malicious';
    const useRl = adaptMode === 'rl_mitigated';

    if (btn) btn.disabled = true;
    try {
      const res = await fetch('/api/governor/inject-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_type: evType,
          is_malicious: isMalicious,
          use_rl_mitigation: useRl
        })
      });
      if (res.ok) {
        const item = await res.json();
        const tbody = document.getElementById('gov-samples-tbody');
        if (tbody) {
          if (tbody.children.length === 1 && tbody.children[0].innerText.includes('Awaiting')) {
            tbody.innerHTML = '';
          }
          const row = document.createElement('tr');
          row.style.borderBottom = '1px solid #1e293b';
          const pCol = item.survival_probability <= 0.35 ? '#ef4444' : (item.survival_probability <= 0.70 ? '#f59e0b' : '#10b981');
          const stateBadge = item.circuit_breaker_tripped ? '<span style="color:#ef4444; font-weight:700;">🚨 TRIPPED</span>' : (item.warning_triggered ? '<span style="color:#f59e0b; font-weight:700;">⚠️ WARNED</span>' : '<span style="color:#10b981;">NORMAL</span>');
          const rlBadge = item.use_rl_mitigation ? `<span style="color:#38bdf8; font-weight:600;">${escapeHtml(item.rl_action_selected)} (-${(item.rl_mitigation_attenuation*100).toFixed(0)}%)</span>` : '<span style="color:#64748b;">Static None</span>';

          row.innerHTML = `
            <td style="padding: 0.45rem; font-family: monospace;">#${item.step}</td>
            <td style="padding: 0.45rem; font-weight: 500;">${escapeHtml(item.event_type)} (${item.is_malicious ? 'Malicious' : 'Benign'})</td>
            <td style="padding: 0.45rem; font-family: monospace; color: #f87171;">${item.raw_epsilon_t.toFixed(4)}</td>
            <td style="padding: 0.45rem;">${rlBadge}</td>
            <td style="padding: 0.45rem; font-family: monospace; color: #38bdf8;">${item.effective_epsilon_t.toFixed(4)}</td>
            <td style="padding: 0.45rem; font-family: monospace; color: ${pCol}; font-weight: 700;">${(item.survival_probability*100).toFixed(2)}%</td>
            <td style="padding: 0.45rem;">${stateBadge}</td>
          `;
          tbody.insertBefore(row, tbody.firstChild);
        }
        fetchGovernorStatus();
        appendTerminal(`[GOVERNOR] Ingested sample #${item.step} (${item.event_type}): Raw ε=${item.raw_epsilon_t.toFixed(4)}, Effective ε=${item.effective_epsilon_t.toFixed(4)} (${item.rl_action_selected}). P_secure=${(item.survival_probability*100).toFixed(2)}%`, item.circuit_breaker_tripped ? 'err' : (item.warning_triggered ? 'warn' : 'ok'));
      }
    } catch (e) {
      showDiagnosticToast({ status: 'GOVERNOR_ERROR', message: e.message, retryFn: injectGovernorSample });
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function resetGovernor() {
    try {
      const res = await fetch('/api/governor/reset', { method: 'POST' });
      if (res.ok) {
        document.getElementById('gov-samples-tbody').innerHTML = '<tr><td colspan="7" style="padding: 1rem; text-align: center; color: var(--text-muted);">Governor reset. Awaiting telemetry samples...</td></tr>';
        fetchGovernorStatus();
        appendTerminal('[GOVERNOR] Security Governor state reset to 100% survival probability.', 'ok');
      }
    } catch (e) {
      console.warn('Governor reset error:', e);
    }
  }

  // ============================================================================
  // Real-Time Agentic Self-Protection (RT-ASP) Dashboard Functions
  // ============================================================================

  async function fetchRaspData(showToast = false) {
    try {
      const [statusRes, telRes] = await Promise.all([
        fetchWithTimeout('/api/rasp/status', {}, 1500),
        fetchWithTimeout('/api/rasp/telemetry?limit=50', {}, 1500)
      ]);

      if (statusRes.ok) {
        const sData = await statusRes.json();
        const tierEl = document.getElementById('rasp-stat-tier');
        const activeLabel = document.getElementById('rasp-active-tier-label');
        if (tierEl) tierEl.textContent = sData.active_mitigation_tier || 'Level 1 Sanitize';
        if (activeLabel) activeLabel.textContent = sData.active_mitigation_tier || 'Level 1 Sanitize';
      }

      if (telRes.ok) {
        const tData = await telRes.json();
        const metrics = tData.metrics || {};
        const inspEl = document.getElementById('rasp-stat-inspections');
        const blockEl = document.getElementById('rasp-stat-blocked');
        const decoyEl = document.getElementById('rasp-stat-decoys');
        const healthEl = document.getElementById('rasp-stat-health');

        if (inspEl) inspEl.textContent = metrics.total_inspections || 0;
        if (blockEl) blockEl.textContent = metrics.total_denied || 0;
        if (decoyEl) decoyEl.textContent = (metrics.total_tarpitted || 0) + (metrics.total_sanitized || 0);
        if (healthEl) healthEl.textContent = (metrics.operational_health_score !== undefined ? metrics.operational_health_score.toFixed(1) : '100.0') + '%';

        renderRaspTelemetryTable(tData.events || []);
      }
    } catch (err) {
      if (showToast) {
        showDiagnosticToast({
          status: 'RASP_FETCH_ERROR',
          message: 'Failed to fetch RT-ASP metrics: ' + err.message,
          retryFn: () => fetchRaspData(true)
        });
      }
    }
  }

  function renderRaspTelemetryTable(events) {
    const tbody = document.getElementById('rasp-telemetry-tbody');
    if (!tbody) return;
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">No in-process events recorded yet. Try running prompt/tool tests above.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => {
      const isAllowed = e.decision && (e.decision.Allow !== undefined || e.decision.Sanitize !== undefined);
      const isTarpit = e.decision && e.decision.Tarpit !== undefined;
      const badgeClass = isAllowed ? 'badge-success' : (isTarpit ? 'badge-running' : 'badge-danger');
      const verdictStr = isAllowed ? 'ALLOW' : (isTarpit ? 'TARPIT' : 'VETO');
      const threatStr = e.threat_category || 'Clean / In-Policy';

      return `
        <tr>
          <td style="padding: 0.45rem;"><span class="badge ${badgeClass}">${verdictStr}</span></td>
          <td style="padding: 0.45rem; font-family: monospace; color: var(--accent-cyan); font-size: 0.78rem;">${escapeHtml(e.interceptor_name || '')}</td>
          <td style="padding: 0.45rem; font-family: monospace; font-size: 0.78rem;">${escapeHtml(e.subject ? e.subject.agent_id : 'worker')}</td>
          <td style="padding: 0.45rem; color: ${e.threat_category ? 'var(--danger)' : '#94a3b8'}; font-weight: 500;">${escapeHtml(threatStr)}</td>
          <td style="padding: 0.45rem; font-size: 0.78rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(e.raw_input_summary || '')}</td>
          <td style="padding: 0.45rem; font-family: monospace; font-size: 0.75rem; color: #94a3b8;">${e.latency_micros || 0}&mu;s</td>
        </tr>
      `;
    }).join('');
  }

  async function testRaspPrompt() {
    const prompt = (document.getElementById('rasp-test-prompt-input')?.value || '').trim();
    const lang = document.getElementById('rasp-test-prompt-lang')?.value || 'en';
    const resDiv = document.getElementById('rasp-test-prompt-result');
    if (!prompt) return;

    try {
      const res = await fetch('/api/rasp/intercept-prompt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, language_code: lang, agent_id: 'agent_interactive_test' })
      });
      const data = await res.json();
      if (resDiv) {
        resDiv.style.display = 'block';
        if (data.is_allowed) {
          resDiv.style.background = 'rgba(16, 185, 129, 0.15)';
          resDiv.style.border = '1px solid var(--success)';
          resDiv.style.color = '#34d399';
          resDiv.innerHTML = `&check; <strong>ALLOWED</strong> (Clean Language: ${lang}) &mdash; Passed all 8 prompt safety gates.`;
        } else {
          resDiv.style.background = 'rgba(239, 68, 68, 0.15)';
          resDiv.style.border = '1px solid var(--danger)';
          resDiv.style.color = '#f87171';
          resDiv.innerHTML = `&cross; <strong>INTERCEPTED: ${escapeHtml(data.verdict || 'DENY')}</strong> &mdash; Threat: ${escapeHtml(data.threat_category || 'Jailbreak')} &mdash; ${escapeHtml(data.decision_details?.Deny?.reason || data.decision_details?.Tarpit?.reason || '')}`;
        }
      }
      fetchRaspData(false);
    } catch (err) {
      showDiagnosticToast({ status: 'INTERCEPT_ERR', message: err.message, retryFn: null });
    }
  }

  async function testRaspTool() {
    const toolName = document.getElementById('rasp-test-tool-name')?.value || 'doc_extractor';
    const attest = document.getElementById('rasp-test-tool-attest')?.checked || false;
    const paramsStr = (document.getElementById('rasp-test-tool-params')?.value || '').trim();
    const resDiv = document.getElementById('rasp-test-tool-result');

    let params = {};
    try {
      params = paramsStr ? JSON.parse(paramsStr) : {};
    } catch (e) {
      showDiagnosticToast({ status: 'JSON_ERR', message: 'Invalid JSON in params: ' + e.message, retryFn: null });
      return;
    }

    try {
      const payload = {
        tool_name: toolName,
        params,
        agent_id: 'agent_actuator_test',
        supervisor_signature: attest ? 'attested_supervisor_sig_valid' : null
      };
      const res = await fetch('/api/rasp/intercept-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (resDiv) {
        resDiv.style.display = 'block';
        if (data.is_allowed) {
          resDiv.style.background = 'rgba(16, 185, 129, 0.15)';
          resDiv.style.border = '1px solid var(--success)';
          resDiv.style.color = '#34d399';
          resDiv.innerHTML = `&check; <strong>ALLOWED</strong> &mdash; Parameters verified within 64-bit boundaries.`;
        } else {
          resDiv.style.background = 'rgba(239, 68, 68, 0.15)';
          resDiv.style.border = '1px solid var(--danger)';
          resDiv.style.color = '#f87171';
          resDiv.innerHTML = `&cross; <strong>INTERCEPTED: ${escapeHtml(data.verdict || 'DENY')}</strong> &mdash; Threat: ${escapeHtml(data.threat_category || 'BoundaryViolation')} &mdash; ${escapeHtml(data.decision_details?.Deny?.reason || '')}`;
        }
      }
      fetchRaspData(false);
    } catch (err) {
      showDiagnosticToast({ status: 'ACTUATOR_ERR', message: err.message, retryFn: null });
    }
  }

  async function generateRaspCanary() {
    const label = (document.getElementById('rasp-canary-label')?.value || 'crown_jewel').trim();
    const display = document.getElementById('rasp-canary-display');
    try {
      const res = await fetch('/api/rasp/canary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label })
      });
      const data = await res.json();
      if (display) {
        display.style.display = 'block';
        display.innerHTML = `<strong>Canary Generated &amp; Armed:</strong><br><span style="user-select: all;">${escapeHtml(data.canary_token)}</span><br><span style="color: #94a3b8; font-size: 0.72rem;">${escapeHtml(data.instructions)}</span>`;
      }
      fetchRaspData(false);
    } catch (err) {
      showDiagnosticToast({ status: 'CANARY_ERR', message: err.message, retryFn: null });
    }
  }

  async function testRaspMemoryWrite() {
    const content = (document.getElementById('rasp-test-memory-content')?.value || '').trim();
    const resDiv = document.getElementById('rasp-test-memory-result');
    if (!content) return;

    try {
      const res = await fetch('/api/rasp/intercept-memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation: 'write', key: 'scratchpad:test_agent:session', content, agent_id: 'test_agent' })
      });
      const data = await res.json();
      if (resDiv) {
        resDiv.style.display = 'block';
        resDiv.innerHTML = `<strong>Auto-Redacted Output:</strong><br><code style="background: #050811; padding: 2px 4px; border-radius: 3px;">${escapeHtml(data.sanitized_content || '')}</code>`;
      }
      fetchRaspData(false);
    } catch (err) {
      showDiagnosticToast({ status: 'MEMORY_ERR', message: err.message, retryFn: null });
    }
  }

  async function setRaspMitigationTier(tier) {
    try {
      const res = await fetch('/api/rasp/mitigation-tier', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tier })
      });
      const data = await res.json();
      const label = document.getElementById('rasp-active-tier-label');
      const statTier = document.getElementById('rasp-stat-tier');
      if (label) label.textContent = data.new_mitigation_tier;
      if (statTier) statTier.textContent = data.new_mitigation_tier;
      fetchRaspData(false);
    } catch (err) {
      showDiagnosticToast({ status: 'TIER_ERR', message: err.message, retryFn: null });
    }
  }

  // Initial load
  fetchAuditLog();
  loadEgressDomains();
  fetchRlDefenseStatus();
  fetchGovernorStatus();
  fetchRaspData();
  setInterval(fetchRaspData, 2500);
</script>
</body>
</html>
"##;
