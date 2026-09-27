'use strict';
/* LoveDiary-Timeline 主脚本（重构版）
 * 单文件 IIFE 模块划分，保持 file:// 可用（无 ES Module、无构建步骤）。
 * 对外行为与原版兼容：所有元素 id / class 保持不变。
 */
(() => {
  // ---------- 0. 小工具 ----------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const pad2 = (n) => String(n).padStart(2, '0');

  /** 文本转义：用于标题 / 日期 / 属性等纯文本插值，防 XSS */
  const escapeHtml = (s) => String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  /** 描述允许的简易 HTML 白名单消毒（原 placeholder 注明“支持HTML”） */
  const sanitizeDescription = (html) => {
    const tpl = document.createElement('template');
    // 先转义再还原白名单标签，避免 script/iframe/on* 注入
    const escaped = escapeHtml(html).replace(/&lt;(br|b|strong|i|em|u|p|span|a)(\s[^&]*?)?&gt;/gi, (m, tag, attrs = '') => {
      if (tag.toLowerCase() === 'a') {
        const href = /href=&quot;(.*?)&quot;/i.exec(attrs);
        const safeHref = href && /^(https?:|mailto:|#|\/)/i.test(href[1]) ? ` href="${escapeHtml(href[1])}" target="_blank" rel="noopener"` : '';
        return `<${tag}${safeHref}>`;
      }
      return `<${tag}>`;
    }).replace(/&lt;\/(b|strong|i|em|u|p|span|a)&gt;/gi, (m, tag) => `</${tag}>`);
    tpl.innerHTML = escaped;
    // 纵深防御：删掉残留的可执行节点与事件属性
    tpl.content.querySelectorAll('script, iframe, object, embed, form, input, button').forEach((n) => n.remove());
    tpl.content.querySelectorAll('*').forEach((el) => {
      Array.from(el.attributes).forEach((attr) => {
        if (/^on/i.test(attr.name) || (attr.name === 'href' && /^\s*javascript:/i.test(attr.value))) {
          el.removeAttribute(attr.name);
        }
      });
    });
    return tpl.innerHTML;
  };

  /** 图片 URL 安全校验：仅允许 http(s)/相对路径/images/data:image */
  const sanitizeImageUrl = (url) => {
    const s = String(url || '').trim();
    if (!s) return '';
    if (/^\s*javascript:/i.test(s) || /^\s*data:text\/html/i.test(s)) return '';
    return s;
  };

  const safeJsonParse = (text, fallback) => {
    try {
      const v = JSON.parse(text);
      return v ?? fallback;
    } catch {
      return fallback;
    }
  };

  /** SHA-256 纯 JS 实现（无外部依赖；输入先 UTF-8 编码，file:// / 非 https 下也可用） */
  const sha256Ascii = (ascii) => {
    const rightRotate = (v, a) => (v >>> a) | (v << (32 - a));
    const maxWord = Math.pow(2, 32);
    let result = '';
    const words = [];
    const bitLen = ascii.length * 8;
    let hash = sha256Ascii.h = sha256Ascii.h || [];
    const k = sha256Ascii.k = sha256Ascii.k || [];
    let primeCounter = k.length;
    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (let i = 0; i < ascii.length; i++) {
      const code = ascii.charCodeAt(i);
      if (code >> 8) return '';
      words[i >> 2] |= code << ((3 - i) % 4) * 8;
    }
    words[words.length] = (bitLen / maxWord) | 0;
    words[words.length] = bitLen;
    for (let j = 0; j < words.length;) {
      const w = words.slice(j, (j += 16));
      const oldHash = hash;
      hash = hash.slice(0, 8);
      for (let i = 0; i < 64; i++) {
        const w15 = w[i - 15];
        const w2 = w[i - 2];
        const a = hash[0];
        const e = hash[4];
        const temp1 = (hash[7]
          + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
          + ((e & hash[5]) ^ (~e & hash[6]))
          + k[i]
          + (w[i] = i < 16 ? w[i] : (w[i - 16]
            + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) | 0)) | 0;
        const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
          + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (let i = 0; i < 8; i++) {
      for (let j = 3; j + 1; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += (b < 16 ? '0' : '') + b.toString(16);
      }
    }
    return result;
  };

  const sha256Hex = (str) => {
    const bytes = new TextEncoder().encode(String(str));
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return sha256Ascii(bin);
  };

  // 开机自检：若实现被误改，哈希登录将不可用；失败时拒绝哈希比对并报错，避免把人锁在门外无提示
  const SHA256_OK = (() => {
    try {
      return sha256Hex('abc') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    } catch {
      return false;
    }
  })();
  if (!SHA256_OK) console.error('内置 SHA-256 自检失败，哈希密码将无法验证');

  /** rAF 节流：滚动等高频事件共用 */
  const rafThrottle = (fn) => {
    let queued = false;
    return (...args) => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => {
        queued = false;
        fn(...args);
      });
    };
  };

  /** 本地日期解析（避免 new Date('yyyy-MM-dd') 的 UTC 偏移坑） */
  const parseLocalDate = (dateStr, timeStr = '00:00:00') => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dateStr || '').trim());
    if (!m) return null;
    const t = /^(\d{2}):(\d{2})(?::(\d{2}))?/.exec(String(timeStr || '00:00:00').trim()) || [];
    const d = new Date(+m[1], +m[2] - 1, +m[3], +(t[1] || 0), +(t[2] || 0), +(t[3] || 0));
    return Number.isNaN(d.getTime()) ? null : d;
  };

  /** 日历差值：年/月/日按自然月进位，而非 365.25/30.44 近似 */
  const diffCalendar = (from, to) => {
    if (to < from) return { years: 0, months: 0, days: 0, hours: 0, minutes: 0, seconds: 0 };
    let years = to.getFullYear() - from.getFullYear();
    let months = to.getMonth() - from.getMonth();
    let days = to.getDate() - from.getDate();
    let hours = to.getHours() - from.getHours();
    let minutes = to.getMinutes() - from.getMinutes();
    let seconds = to.getSeconds() - from.getSeconds();
    if (seconds < 0) { seconds += 60; minutes -= 1; }
    if (minutes < 0) { minutes += 60; hours -= 1; }
    if (hours < 0) { hours += 24; days -= 1; }
    if (days < 0) {
      months -= 1;
      const prevMonth = new Date(to.getFullYear(), to.getMonth(), 0).getDate();
      days += prevMonth;
    }
    if (months < 0) { months += 12; years -= 1; }
    return { years, months, days, hours, minutes, seconds };
  };

  const startOfDay = (d) => {
    const c = new Date(d);
    c.setHours(0, 0, 0, 0);
    return c;
  };

  // ---------- 1. Store（localStorage 统一出入口） ----------
  const Store = {
    getSettings() {
      return safeJsonParse(localStorage.getItem('settings'), {});
    },
    saveSettings(patch) {
      const next = { ...Store.getSettings(), ...patch };
      try {
        localStorage.setItem('settings', JSON.stringify(next));
      } catch (e) {
        console.warn('保存设置失败:', e);
      }
      return next;
    },
    getLocalTimeline() {
      const v = safeJsonParse(localStorage.getItem('timelineEvents'), null);
      if (v && Array.isArray(v.added) && Array.isArray(v.deleted) && v.modified) return v;
      return { added: [], deleted: [], modified: {} };
    },
    saveLocalTimeline(data) {
      try {
        localStorage.setItem('timelineEvents', JSON.stringify(data));
      } catch (e) {
        console.warn('保存时间线失败:', e);
      }
    },
  };

  // ---------- 2. Data（时间线数据源 + 缓存） ----------
  const Data = {
    cache: null,
    async get() {
      if (Data.cache) return Data.cache;
      try {
        const res = await fetch('data/timeline.json', { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        Data.cache = await res.json();
      } catch (e) {
        const el = document.getElementById('timeline-data');
        if (!el) throw e;
        Data.cache = safeJsonParse(el.textContent, null);
        if (!Data.cache) throw e;
        console.warn('fetch timeline.json 失败，已使用页面内嵌数据:', e.message);
      }
      ConfigStore.applyToLiveConfig(Data.cache);
      return Data.cache;
    },
  };

  // ---------- 2.5 ConfigStore（配置项的本地待同步补丁，如密码哈希） ----------
  const ConfigStore = {
    KEY: 'configPatch',
    getPending() {
      return safeJsonParse(localStorage.getItem(ConfigStore.KEY), null) || null;
    },
    savePending(patch) {
      const next = { ...(ConfigStore.getPending() || {}), ...patch };
      try {
        localStorage.setItem(ConfigStore.KEY, JSON.stringify(next));
      } catch (e) {
        console.warn('保存配置补丁失败:', e);
      }
      if (Data.cache?.config) {
        Object.assign(Data.cache.config, next);
        if (Data.cache.config.passwordHash) delete Data.cache.config.password;
      }
      return next;
    },
    clearPending() {
      localStorage.removeItem(ConfigStore.KEY);
    },
    applyToLiveConfig(config) {
      const p = ConfigStore.getPending();
      if (p && config) {
        Object.assign(config, p);
        if (config.passwordHash) delete config.password;
      }
    },
    forExport(config) {
      const out = { ...(config || {}), ...(ConfigStore.getPending() || {}) };
      if (out.passwordHash) delete out.password; // 有哈希就不再落盘明文
      return out;
    },
  };

  // ---------- 3. Theme（夜间模式） ----------
  const Theme = {
    media: window.matchMedia('(prefers-color-scheme: dark)'),
    inited: false,
    darkToggle: null,
    sysToggle: null,

    resolveTarget(darkMode, systemTheme) {
      if (systemTheme) return Theme.media.matches ? 'dark' : 'light';
      return darkMode ? 'dark' : 'light';
    },
    apply(darkMode, systemTheme) {
      const target = Theme.resolveTarget(darkMode, systemTheme);
      const current = document.documentElement.getAttribute('data-theme');
      if (Theme.inited && current && current !== target) Theme.play(target === 'dark');
      document.documentElement.setAttribute('data-theme', target);
      document.body.setAttribute('data-theme', target);
    },
    play(toDark) {
      const overlay = document.getElementById('theme-transition');
      if (!overlay) return;
      overlay.classList.remove('play-day', 'play-night');
      void overlay.offsetWidth; // 强制重排使动画可重复播放
      overlay.classList.add(toDark ? 'play-night' : 'play-day');
      clearTimeout(overlay._ttTimer);
      overlay._ttTimer = setTimeout(() => overlay.classList.remove('play-day', 'play-night'), 1700);
    },
    buildStars() {
      const overlay = document.getElementById('theme-transition');
      if (!overlay || overlay.dataset.stars === '1') return;
      overlay.dataset.stars = '1';
      const frag = document.createDocumentFragment();
      for (let i = 0; i < 26; i++) {
        const s = document.createElement('span');
        s.className = 'tt-star';
        const size = (Math.random() * 2 + 1).toFixed(1);
        s.style.left = `${(Math.random() * 100).toFixed(1)}%`;
        s.style.top = `${(Math.random() * 70).toFixed(1)}%`;
        s.style.width = `${size}px`;
        s.style.height = `${size}px`;
        s.style.animationDelay = `${(Math.random() * 0.8).toFixed(2)}s`;
        frag.appendChild(s);
      }
      overlay.appendChild(frag);
    },
    init() {
      Theme.darkToggle = document.getElementById('dark-mode');
      Theme.sysToggle = document.getElementById('system-theme');
      if (!Theme.darkToggle || !Theme.sysToggle) return;
      const settings = Store.getSettings();
      Theme.darkToggle.checked = !!settings.darkMode;
      Theme.sysToggle.checked = !!settings.systemTheme;
      Theme.apply(Theme.darkToggle.checked, Theme.sysToggle.checked);
      Theme.inited = true;
      Theme.buildStars();

      Theme.media.addEventListener('change', (e) => {
        if (Store.getSettings().systemTheme) {
          Theme.play(e.matches);
          const t = e.matches ? 'dark' : 'light';
          document.documentElement.setAttribute('data-theme', t);
          document.body.setAttribute('data-theme', t);
        }
      });
      // 主题开关即时生效 + 即时持久化；排序仍走“保存设置”按钮
      Theme.darkToggle.addEventListener('change', () => {
        if (Theme.darkToggle.checked) Theme.sysToggle.checked = false;
        Theme.apply(Theme.darkToggle.checked, Theme.sysToggle.checked);
        Store.saveSettings({ darkMode: Theme.darkToggle.checked, systemTheme: Theme.sysToggle.checked });
      });
      Theme.sysToggle.addEventListener('change', () => {
        if (Theme.sysToggle.checked) Theme.darkToggle.checked = Theme.media.matches;
        Theme.apply(Theme.darkToggle.checked, Theme.sysToggle.checked);
        Store.saveSettings({ darkMode: Theme.darkToggle.checked, systemTheme: Theme.sysToggle.checked });
      });
    },
  };

  // ---------- 4. Auth（密码门） ----------
  const Auth = {
    entered: '',
    fails: [],
    els: {},
    config: null,
    onSuccess: null,

    init(config, onSuccess) {
      Auth.config = config;
      Auth.onSuccess = onSuccess;
      Auth.els.screen = document.getElementById('password-screen');
      Auth.els.container = document.querySelector('.password-container');
      Auth.els.title = document.querySelector('.password-title');
      Auth.els.dots = $$('.dot');
      Auth.els.keys = $$('.key');
      document.body.style.overflow = 'hidden';
      document.documentElement.style.overflow = 'hidden';

      Auth.els.keys.forEach((key) => {
        key.addEventListener('click', () => {
          if (key.dataset.value === undefined || key.classList.contains('key-empty')) return;
          Auth.press(key.dataset.value, key);
        });
      });
      // 键盘监听立即注册，不等待数据加载
      document.addEventListener('keydown', (e) => {
        if (!Auth.els.screen || Auth.els.screen.style.display === 'none') return;
        if (/^[0-9]$/.test(e.key)) {
          const btn = document.querySelector(`.key[data-value="${e.key}"]`);
          Auth.press(e.key, btn);
        } else if ((e.key === 'Backspace' || e.key === 'Delete') && Auth.entered.length > 0) {
          Auth.press('delete', document.querySelector('.key-delete'));
        }
      });
    },
    paintDots() {
      Auth.els.dots.forEach((dot, i) => dot.classList.toggle('filled', i < Auth.entered.length));
    },
    checkPassword(entered) {
      const c = Auth.config || {};
      if (c.passwordHash) {
        if (!SHA256_OK) {
          console.error('SHA-256 不可用，无法验证哈希密码');
          return false;
        }
        return sha256Hex(`${c.passwordSalt || ''}${entered}`) === c.passwordHash;
      }
      if (c.password != null) {
        console.warn('当前配置仍是明文密码，建议在设置 → 密码安全中升级为哈希存储');
        return entered === String(c.password);
      }
      return false;
    },
    flashKey(btn) {
      if (!btn) return;
      btn.classList.add('active');
      setTimeout(() => btn.classList.remove('active'), 200);
    },
    press(value, btn) {
      if (value === 'delete') {
        if (!Auth.entered.length) return;
        Auth.flashKey(btn);
        Auth.entered = Auth.entered.slice(0, -1);
        Auth.paintDots();
        return;
      }
      if (Auth.entered.length >= 6 || !/^[0-9]$/.test(value)) return;
      Auth.flashKey(btn);
      Auth.entered += value;
      Auth.paintDots();
      if (Auth.entered.length === 6) setTimeout(Auth.verify, 200);
    },
    verify() {
      // 简单限流：30s 内 5 次失败则锁定 10s
      const now = Date.now();
      Auth.fails = Auth.fails.filter((t) => now - t < 30000);
      if (Auth.fails.length >= 5) {
        Auth.error('尝试过多，稍后再试');
        Auth.entered = '';
        Auth.paintDots();
        return;
      }
      if (Auth.checkPassword(Auth.entered)) {
        Auth.els.screen.style.display = 'none';
        const container = document.querySelector('.container');
        if (container) container.style.display = 'block';
        document.body.style.overflow = '';
        document.documentElement.style.overflow = '';
        try {
          localStorage.setItem('lastLogin', String(Date.now()));
        } catch { /* 忽略 */ }
        Auth.onSuccess && Auth.onSuccess();
      } else {
        Auth.fails.push(now);
        Auth.entered = '';
        Auth.paintDots();
        Auth.error('密码错误');
      }
    },
    error(msg) {
      Auth.els.title.textContent = msg;
      Auth.els.container.classList.add('error');
      clearTimeout(Auth.error._t);
      Auth.error._t = setTimeout(() => {
        Auth.els.title.textContent = '请输入密码';
        Auth.els.container.classList.remove('error');
      }, 1500);
    },
  };

  // ---------- 5. Counter（天数 + 年月日时分秒） ----------
  const Counter = {
    timer: null,
    raf: 0,
    els: {},
    start: null,

    init() {
      Counter.els.section = document.querySelector('.counter-section');
      Counter.els.text = document.getElementById('counter-text');
      Counter.els.days = document.getElementById('counter-days');
      Counter.els.start = document.getElementById('start-date');
      Counter.els.units = $$('#time-counter .time-unit');
    },
    renderHead(config) {
      Counter.start = parseLocalDate(config.startDate, config.startTime || '00:00:00');
      if (!Counter.start) {
        console.error('起始日期格式无效:', config.startDate);
        return;
      }
      const today = startOfDay(new Date());
      const startDay = startOfDay(Counter.start);
      const diffMs = startDay.getTime() - today.getTime();
      let text;
      let days;
      if (diffMs > 0) {
        text = config.counterTextBefore || `距离和${config.partnerName || ''}在一起还有`;
        days = Math.round(diffMs / 86400000);
      } else {
        text = config.counterTextAfter || `和${config.partnerName || ''}在一起已经`;
        days = Math.floor((today - startDay) / 86400000) + 1; // 当天记为第 1 天
      }
      if (Counter.els.text) Counter.els.text.textContent = text;
      if (Counter.els.start) {
        Counter.els.start.textContent = `起始日: ${Counter.start.toLocaleDateString('zh-CN', {
          year: 'numeric', month: 'long', day: 'numeric', weekday: 'long',
        })}`;
      }
      Counter.animateDays(days);
      Counter.applyBackground(config.counterBackground);
      Counter.tick();
      clearInterval(Counter.timer);
      Counter.timer = setInterval(Counter.tick, 1000);
    },
    applyBackground(bg = {}) {
      const section = Counter.els.section;
      if (!section) return;
      const raw = String(bg.image || '').trim();
      section.style.setProperty('--bg-image', raw ? `url('${raw.replace(/'/g, '%27')}')` : 'none');
      section.style.setProperty('--bg-blur', bg.blur || '0px');
      section.style.setProperty('--bg-opacity', bg.opacity ?? 1);
      section.style.setProperty('--bg-overlay', bg.colorOverlay || 'transparent');
      if (raw && !/^(https?:|data:)/i.test(raw)) {
        const probe = new Image();
        probe.onerror = () => console.warn(`计数器背景图加载失败，请检查路径是否存在: ${raw}`);
        probe.src = raw;
      }
    },
    animateDays(target) {
      const el = Counter.els.days;
      if (!el) return;
      cancelAnimationFrame(Counter.raf);
      const t = Math.max(0, Math.floor(target) || 0);
      if (t === 0) {
        el.textContent = '0';
        return;
      }
      const duration = Math.min(1500, 300 + t * 2);
      const t0 = performance.now();
      const step = (now) => {
        const p = Math.min(1, (now - t0) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = String(Math.round(t * eased));
        if (p < 1) Counter.raf = requestAnimationFrame(step);
      };
      Counter.raf = requestAnimationFrame(step);
    },
    tick() {
      if (!Counter.start || Counter.els.units.length < 6) return;
      const d = diffCalendar(Counter.start, new Date());
      const vals = [d.years, d.months, d.days, d.hours, d.minutes, d.seconds];
      Counter.els.units.forEach((el, i) => {
        el.textContent = pad2(vals[i]);
      });
    },
  };

  // ---------- 6. Timeline（数据合并 / 排序 / 渲染 / 增删改） ----------
  const eventIdOf = (event) => {
    if (event.id) return String(event.id);
    const str = `${event.date || ''}-${event.title || ''}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return `evt_${Math.abs(hash).toString(36)}`;
  };

  const Timeline = {
    els: {},
    init() {
      Timeline.els.section = document.getElementById('timeline-section');
    },
    merge(base) {
      const local = Store.getLocalTimeline();
      const del = new Set(local.deleted || []);
      let merged = (base || []).filter((e) => !del.has(eventIdOf(e)));
      merged = merged.map((e) => {
        const id = eventIdOf(e);
        const patch = (local.modified || {})[id];
        return patch ? { ...e, ...patch, id } : { ...e, id };
      });
      (local.added || []).forEach((e) => {
        merged.push(e.id ? e : { ...e, id: eventIdOf(e) });
      });
      return merged;
    },
    sort(events) {
      const reverse = Store.getSettings().timelineOrder === true; // true=正序
      const pinned = events.filter((e) => e.top === true);
      const rest = events.filter((e) => e.top !== true);
      rest.sort((a, b) => {
        const ta = parseLocalDate(a.date)?.getTime() ?? 0;
        const tb = parseLocalDate(b.date)?.getTime() ?? 0;
        return reverse ? ta - tb : tb - ta;
      });
      return [...pinned, ...rest];
    },
    async load() {
      try {
        const data = await Data.get();
        document.title = data.config?.pageTitle || '我们的故事';
        Counter.renderHead(data.config || {});
        const events = Timeline.sort(Timeline.merge(data.timeline));
        Timeline.render(events);
        Lazy.observeNew();
        Management.refresh();
      } catch (e) {
        console.error('加载时间线数据失败:', e);
      }
    },
    render(events) {
      const box = Timeline.els.section;
      if (!box) return;
      box.innerHTML = '';
      const frag = document.createDocumentFragment();
      events.forEach((e) => frag.appendChild(Timeline.createItem(e)));
      box.appendChild(frag);
    },
    createItem(eventData) {
      const item = document.createElement('div');
      item.className = 'timeline-item' + (eventData.top ? ' pinned' : '');

      const dateEl = document.createElement('div');
      dateEl.className = 'timeline-date';
      const h3 = document.createElement('h3');
      h3.textContent = eventData.title || '';
      const p = document.createElement('p');
      p.innerHTML = sanitizeDescription(eventData.description || '');

      const d = parseLocalDate(eventData.date);
      if (d && !Number.isNaN(d)) {
        dateEl.textContent = `${d.getFullYear()}年${pad2(d.getMonth() + 1)}月${pad2(d.getDate())}日`;
      } else {
        dateEl.textContent = '无效日期';
        console.error('时间线事件中的日期格式无效:', eventData.date);
      }
      item.append(dateEl, h3, p);

      const imgUrl = sanitizeImageUrl(eventData.image);
      if (imgUrl) {
        const wrap = document.createElement('div');
        wrap.className = 'image-container';
        const img = document.createElement('img');
        img.className = 'lazy-image';
        img.setAttribute('data-src', imgUrl);
        img.alt = eventData.title || '时间线图片';
        img.decoding = 'async';
        img.addEventListener('error', () => {
          img.style.display = 'none';
          img.classList.add('loaded');
          wrap.classList.add('loaded');
          console.warn('图片未找到: ' + imgUrl);
        }, { once: true });
        wrap.appendChild(img);
        item.appendChild(wrap);
      }

      const badge = document.createElement('div');
      badge.className = 'timeline-days-badge';
      if (d && !Number.isNaN(d)) {
        const diff = Math.floor((startOfDay(new Date()) - startOfDay(d)) / 86400000);
        badge.textContent = diff >= 0 ? `${diff}天` : `${Math.abs(diff)}天后`;
      } else {
        badge.textContent = '--';
      }
      item.appendChild(badge);
      return item;
    },

    // --- 本地增删改（导出 JSON 后手动替换文件即持久化） ---
    add(event) {
      const local = Store.getLocalTimeline();
      const withId = event.id ? event : { ...event, id: eventIdOf(event) };
      local.added.push(withId);
      Store.saveLocalTimeline(local);
      Timeline.load();
    },
    remove(eventId) {
      const local = Store.getLocalTimeline();
      const idx = local.added.findIndex((e) => e.id === eventId);
      if (idx !== -1) local.added.splice(idx, 1);
      else {
        if (!local.deleted.includes(eventId)) local.deleted.push(eventId);
        delete local.modified[eventId];
      }
      Store.saveLocalTimeline(local);
      Timeline.load();
    },
    update(eventId, updates) {
      const local = Store.getLocalTimeline();
      const idx = local.added.findIndex((e) => e.id === eventId);
      if (idx !== -1) local.added[idx] = { ...local.added[idx], ...updates };
      else local.modified[eventId] = { ...(local.modified[eventId] || {}), ...updates };
      Store.saveLocalTimeline(local);
      Timeline.load();
    },
    async togglePin(eventId) {
      const data = await Data.get();
      const target = Timeline.merge(data.timeline).find((e) => e.id === eventId);
      if (target) Timeline.update(eventId, { top: !target.top });
    },
    async export() {
      try {
        const data = await Data.get();
        const merged = Timeline.merge(data.timeline).map(({ id, ...rest }) => rest);
        const blob = new Blob([JSON.stringify({ config: ConfigStore.forExport(data.config), timeline: merged }, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'timeline.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        alert('导出成功！请将下载的 timeline.json 替换 data/timeline.json 文件');
      } catch (e) {
        console.error('导出失败:', e);
        alert('导出失败，请查看控制台');
      }
    },
  };

  // ---------- 7. Lazy（单例 IntersectionObserver） ----------
  const Lazy = {
    observer: null,
    ensure() {
      if (Lazy.observer || !('IntersectionObserver' in window)) return;
      Lazy.observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const img = entry.target;
          Lazy.observer.unobserve(img);
          const src = img.getAttribute('data-src');
          if (!src) return;
          img.src = src;
          img.removeAttribute('data-src');
          img.addEventListener('load', () => {
            img.classList.add('loaded');
            img.parentElement?.classList.add('loaded');
          }, { once: true });
          // error 监听在创建时已绑定
        });
      }, { rootMargin: '100px 0px', threshold: 0.01 });
    },
    observeNew() {
      Lazy.ensure();
      const imgs = $$('.lazy-image:not(.loaded):not([data-observed])');
      if (!imgs.length) return;
      if (!Lazy.observer) {
        // 降级：直接加载
        imgs.forEach((img) => {
          const src = img.getAttribute('data-src');
          if (src) img.src = src;
          img.classList.add('loaded');
          img.parentElement?.classList.add('loaded');
        });
        return;
      }
      imgs.forEach((img) => {
        img.setAttribute('data-observed', '1');
        Lazy.observer.observe(img);
      });
    },
  };

  // ---------- 8. Management（设置面板中的时间线管理） ----------
  const Management = {
    busy: false,
    els: {},
    init() {
      Management.els.list = document.getElementById('timeline-events-list');
      Management.els.addBtn = document.getElementById('add-timeline-btn');
      Management.els.modal = document.getElementById('timeline-event-modal');
      Management.els.form = document.getElementById('timeline-event-form');
      if (!Management.els.addBtn || !Management.els.modal || !Management.els.form) {
        console.warn('时间线管理元素未找到，跳过初始化');
        return;
      }
      Management.els.addBtn.addEventListener('click', () => Management.openForm());
      $('#close-timeline-event-modal')?.addEventListener('click', Management.closeForm);
      $('#cancel-event-form')?.addEventListener('click', Management.closeForm);
      Management.els.modal.addEventListener('click', (e) => {
        if (e.target === Management.els.modal) Management.closeForm();
      });
      Management.els.form.addEventListener('submit', (e) => {
        e.preventDefault();
        const fd = new FormData(Management.els.form);
        const id = $('#event-id').value;
        const payload = {
          date: String(fd.get('date') || ''),
          title: String(fd.get('title') || '').trim(),
          description: String(fd.get('description') || ''),
          image: String(fd.get('image') || '').trim(),
          top: fd.get('top') === 'on',
        };
        if (!payload.date || !payload.title) return;
        if (id) Timeline.update(id, payload);
        else Timeline.add(payload);
        Management.closeForm();
      });
      // 列表内按钮走事件委托，避免每次 innerHTML 后重复绑定
      Management.els.list?.addEventListener('click', async (e) => {
        const btn = e.target.closest('.timeline-event-btn');
        if (!btn) return;
        const id = btn.dataset.id;
        if (btn.classList.contains('edit')) Management.openForm(id);
        else if (btn.classList.contains('pin')) Timeline.togglePin(id);
        else if (btn.classList.contains('delete') && confirm('确定要删除这个事件吗？')) Timeline.remove(id);
      });
      Management.refresh();
    },
    async openForm(eventId = null) {
      Management.els.form.reset();
      $('#event-id').value = '';
      $('#timeline-event-modal-title').textContent = eventId ? '编辑事件' : '新增事件';
      if (!eventId) $('#event-date').value = new Date().toISOString().slice(0, 10);
      else {
        const data = await Data.get();
        const target = Timeline.merge(data.timeline).find((e) => e.id === eventId);
        if (target) {
          $('#event-id').value = eventId;
          $('#event-date').value = target.date || '';
          $('#event-title').value = target.title || '';
          $('#event-description').value = target.description || '';
          $('#event-image').value = target.image || '';
          $('#event-top').checked = target.top === true;
        }
      }
      Management.els.modal.style.display = 'block';
    },
    closeForm() {
      if (Management.els.modal) Management.els.modal.style.display = 'none';
    },
    async refresh() {
      const box = Management.els.list;
      if (!box || Management.busy) return;
      Management.busy = true;
      try {
        const data = await Data.get();
        if (!Array.isArray(data.timeline)) throw new Error('JSON 格式错误：缺少 timeline 数组');
        const merged = Timeline.merge(data.timeline);
        const addedIds = new Set(Store.getLocalTimeline().added.map((e) => e.id));
        box.innerHTML = '';
        const frag = document.createDocumentFragment();
        merged.forEach((event) => {
          const row = document.createElement('div');
          row.className = 'timeline-event-item';
          const info = document.createElement('div');
          info.className = 'timeline-event-info';
          const date = document.createElement('div');
          date.className = 'timeline-event-date';
          date.textContent = event.date || '';
          const title = document.createElement('div');
          title.className = 'timeline-event-title';
          title.textContent = `${event.title || ''}${addedIds.has(event.id) ? ' (新增)' : ''}${event.top ? ' (置顶)' : ''}`;
          info.append(date, title);
          const actions = document.createElement('div');
          actions.className = 'timeline-event-actions';
          actions.innerHTML =
            `<button class="timeline-event-btn edit" title="编辑" data-id="${escapeHtml(event.id)}" aria-label="编辑事件">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></button>` +
            `<button class="timeline-event-btn pin${event.top ? ' active' : ''}" title="${event.top ? '取消置顶' : '置顶'}" data-id="${escapeHtml(event.id)}" aria-label="置顶事件">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 17v5"></path><path d="M9 17h6"></path><path d="M20 7a2 2 0 0 0-2-2V5a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v2a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"></path></svg></button>` +
            `<button class="timeline-event-btn delete" title="删除" data-id="${escapeHtml(event.id)}" aria-label="删除事件">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>`;
          row.append(info, actions);
          frag.appendChild(row);
        });
        box.appendChild(frag);
      } catch (err) {
        console.error('加载时间线列表失败:', err);
        box.innerHTML = `<div style="padding:20px;text-align:center;color:#e74c3c;">加载失败：${escapeHtml(err.message)}<br><small style="color:#999;">请用本地服务器运行（如 npx serve / python -m http.server）</small></div>`;
      } finally {
        Management.busy = false;
      }
    },
  };

  // ---------- 8.5 GitHub（直写仓库：同步 timeline.json + 上传图片） ----------
  // 原理：调用 GitHub Contents API 直接 commit 文件，Pages 随后自动重新部署。
  // Token 仅存本机 localStorage；建议用只授权单个仓库 Contents 读写的 token。
  const GitHub = {
    KEY: 'githubSync',
    getConfig() {
      const v = safeJsonParse(localStorage.getItem(GitHub.KEY), {});
      return {
        owner: String(v.owner || '').trim(),
        repo: String(v.repo || '').trim(),
        branch: String(v.branch || 'main').trim() || 'main',
        token: String(v.token || '').trim(),
      };
    },
    saveConfig(patch) {
      try {
        localStorage.setItem(GitHub.KEY, JSON.stringify({ ...GitHub.getConfig(), ...patch }));
      } catch (e) {
        console.warn('保存 GitHub 配置失败:', e);
      }
    },
    utf8ToBase64(str) {
      const bytes = new TextEncoder().encode(str);
      let bin = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(bin);
    },
    bufferToBase64(buf) {
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(bin);
    },
    async api(path, token, options = {}) {
      const res = await fetch(`https://api.github.com${path}`, {
        ...options,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'X-GitHub-Api-Version': '2022-11-28',
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const err = new Error(body.message || `GitHub API 错误（${res.status}）`);
        err.status = res.status;
        throw err;
      }
      return body;
    },
    status(msg, kind = '') {
      const el = document.getElementById('github-sync-status');
      if (el) {
        el.textContent = msg;
        el.className = `github-sync-status${kind ? ` ${kind}` : ''}`;
      }
    },
    buildExportObject(data) {
      const merged = Timeline.merge(data.timeline).map(({ id, ...rest }) => rest);
      return { config: ConfigStore.forExport(data.config), timeline: merged };
    },
    base64ToUtf8(b64) {
      const bin = atob(String(b64 || '').replace(/\s/g, ''));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder().decode(bytes);
    },
    downloadBackup(name, text) {
      try {
        const blob = new Blob([text], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
      } catch (e) {
        console.warn('备份下载失败:', e);
      }
    },
    async sync() {
      const cfg = GitHub.getConfig();
      if (!cfg.owner || !cfg.repo || !cfg.token) {
        GitHub.status('请先填写 Owner、仓库名和 Token', 'error');
        return;
      }
      // file:// 下 fetch 读到的只是内嵌兜底数据（仅 1 条），此时同步会覆盖远端真数据，必须拦截
      if (location.protocol === 'file:') {
        GitHub.status('当前是 file:// 直接打开，读到的只是内嵌兜底数据。请用部署后的 https 地址（或本地服务器如 npx serve）打开后再同步，否则会覆盖远端文件', 'error');
        return;
      }
      const btn = document.getElementById('sync-github-btn');
      if (btn) btn.disabled = true;
      try {
        GitHub.status('正在读取本地与远端…');
        const localData = await Data.get();
        const localMerged = Timeline.merge(localData.timeline);
        const localIds = new Set(localMerged.map(eventIdOf));
        const path = 'data/timeline.json';
        let sha = null;
        let remoteRaw = '';
        let remoteTimeline = null;
        try {
          const cur = await GitHub.api(
            `/repos/${cfg.owner}/${cfg.repo}/contents/${path}?ref=${encodeURIComponent(cfg.branch)}`,
            cfg.token,
          );
          sha = cur.sha;
          remoteRaw = GitHub.base64ToUtf8(cur.content || '');
          const remoteJson = safeJsonParse(remoteRaw, null);
          if (remoteJson && Array.isArray(remoteJson.timeline)) {
            remoteTimeline = remoteJson.timeline;
          } else if (sha) {
            const ok = confirm('远端 data/timeline.json 无法解析（可能是手改时写坏了 JSON）。继续同步将用本地数据覆盖远端。\n\n继续吗？（建议先取消，去 GitHub 网页修好 JSON）');
            if (!ok) {
              GitHub.status('已取消同步，远端文件未动', '');
              return;
            }
          }
        } catch (e) {
          if (e.status !== 404) throw e; // 404 = 文件尚不存在，走创建分支
        }
        // 以远端为底应用本地增删改：别处加的事件不会被本次同步吞掉
        const base = remoteTimeline || localData.timeline;
        const merged = Timeline.merge(base).map(({ id, ...rest }) => rest);
        const mergedIds = new Set(merged.map(eventIdOf));
        const remoteOnly = remoteTimeline ? remoteTimeline.filter((e) => !localIds.has(eventIdOf(e))) : [];
        const dropped = remoteTimeline ? remoteTimeline.filter((e) => !mergedIds.has(eventIdOf(e))) : [];
        if (dropped.length > 0) {
          const ok = confirm(`远端 ${remoteTimeline.length} 条，合并后 ${merged.length} 条：其中远端独有的 ${remoteOnly.length} 条会被保留，${dropped.length} 条会被删除（你在本机删过）。\n\n继续同步吗？`);
          if (!ok) {
            GitHub.status('已取消同步，远端文件未动', '');
            return;
          }
        } else if (remoteOnly.length > 0) {
          GitHub.status(`检测到远端独有的 ${remoteOnly.length} 条事件，已自动合并保留`, '');
        }
        // 先备份远端原文，再提交
        if (sha && remoteRaw) {
          const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
          GitHub.downloadBackup(`timeline-backup-${ts}.json`, remoteRaw);
        }
        GitHub.status('正在提交到 GitHub…');
        const payload = { config: ConfigStore.forExport(localData.config), timeline: merged };
        const content = `${JSON.stringify(payload, null, 2)}\n`;
        await GitHub.api(`/repos/${cfg.owner}/${cfg.repo}/contents/${path}`, cfg.token, {
          method: 'PUT',
          body: JSON.stringify({
            message: `更新时间线（页面同步 ${new Date().toLocaleString('zh-CN')})`,
            content: GitHub.utf8ToBase64(content),
            branch: cfg.branch,
            ...(sha ? { sha } : {}),
          }),
        });
        // 用已提交的内容刷新本地缓存与页面，再清空本地草稿
        Data.cache = payload;
        Store.saveLocalTimeline({ added: [], deleted: [], modified: {} });
        ConfigStore.clearPending();
        GitHub.status(`同步成功！本地 ${localMerged.length} 条 + 远端独有 ${remoteOnly.length} 条 → ${merged.length} 条（远端旧文件已自动下载备份）。Pages 约 1～2 分钟后重新部署`, 'success');
        Timeline.load();
        Password.refreshStatus();
      } catch (e) {
        console.error('GitHub 同步失败:', e);
        const hint = e.status === 401 ? '（Token 无效或过期）'
          : e.status === 404 ? '（仓库/分支不存在，或 Token 无权访问）'
          : e.status === 409 ? '（分支冲突，请重试）' : '';
        GitHub.status(`同步失败：${e.message}${hint}。本地数据未动，可放心重试`, 'error');
      } finally {
        if (btn) btn.disabled = false;
      }
    },
    extOf(name) {
      const m = /\.([a-z0-9]+)$/i.exec(String(name || ''));
      return m ? `.${m[1].toLowerCase()}` : '.jpg';
    },
    async compressImage(file) {
      // GIF 保持原图（避免动画丢失）；其余走 canvas 压缩，手机原图通常能从几 MB 压到几百 KB
      if (file.type === 'image/gif') {
        return { buffer: await file.arrayBuffer(), ext: '.gif' };
      }
      const bitmap = await createImageBitmap(file).catch(() => null);
      if (!bitmap) return { buffer: await file.arrayBuffer(), ext: GitHub.extOf(file.name) };
      const MAX = 1600;
      const scale = Math.min(1, MAX / Math.max(bitmap.width, bitmap.height));
      const w = Math.max(1, Math.round(bitmap.width * scale));
      const h = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
      if (typeof bitmap.close === 'function') bitmap.close();
      const keepPng = file.type === 'image/png';
      const blob = await new Promise((res) => canvas.toBlob(res, keepPng ? 'image/png' : 'image/jpeg', 0.82));
      if (!blob) return { buffer: await file.arrayBuffer(), ext: GitHub.extOf(file.name) };
      return { buffer: await blob.arrayBuffer(), ext: keepPng ? '.png' : '.jpg' };
    },
    async uploadImage(file) {
      const cfg = GitHub.getConfig();
      const statusEl = document.getElementById('event-image-upload-status');
      const say = (t) => { if (statusEl) statusEl.textContent = t; };
      if (!file) return;
      if (!cfg.owner || !cfg.repo || !cfg.token) {
        say('请先在下方「GitHub 同步」填好 Owner / 仓库名 / Token');
        return;
      }
      if (!file.type.startsWith('image/')) {
        say('请选择图片文件');
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        say('图片超过 10MB，请压缩后再传');
        return;
      }
      try {
        say(`正在处理 ${file.name}…`);
        const year = new Date().getFullYear();
        const { buffer, ext } = await GitHub.compressImage(file);
        if (buffer.byteLength > 8 * 1024 * 1024) {
          say('压缩后仍超过 8MB，请换一张小图');
          return;
        }
        const cleanBase = (file.name || 'image').replace(/\.[^.]+$/, '').replace(/[^\w\-]+/g, '_') || 'image';
        const path = `images/${year}/${Date.now()}_${cleanBase}${ext}`;
        say(`正在上传 ${path}（${(buffer.byteLength / 1024).toFixed(0)}KB）…`);
        await GitHub.api(`/repos/${cfg.owner}/${cfg.repo}/contents/${path}`, cfg.token, {
          method: 'PUT',
          body: JSON.stringify({
            message: `上传图片 ${path}`,
            content: GitHub.bufferToBase64(buffer),
            branch: cfg.branch,
          }),
        });
        const input = document.getElementById('event-image');
        if (input) input.value = path;
        say(`上传成功，已回填路径：${path}`);
      } catch (e) {
        console.error('图片上传失败:', e);
        say(`上传失败：${e.message}`);
      }
    },
    initForm() {
      const owner = $('#github-owner');
      const repo = $('#github-repo');
      const branch = $('#github-branch');
      const token = $('#github-token');
      if (!owner || !repo || !branch || !token) return;
      const cfg = GitHub.getConfig();
      owner.value = cfg.owner;
      repo.value = cfg.repo;
      branch.value = cfg.branch;
      // token 有值时不回显明文，只占位提示
      if (cfg.token) token.placeholder = '已保存（重新输入可覆盖）';
      owner.addEventListener('change', () => GitHub.saveConfig({ owner: owner.value.trim() }));
      repo.addEventListener('change', () => GitHub.saveConfig({ repo: repo.value.trim() }));
      branch.addEventListener('change', () => GitHub.saveConfig({ branch: branch.value.trim() || 'main' }));
      token.addEventListener('change', () => {
        if (token.value.trim()) {
          GitHub.saveConfig({ token: token.value.trim() });
          token.value = '';
          token.placeholder = '已保存（重新输入可覆盖）';
        }
      });
      $('#sync-github-btn')?.addEventListener('click', GitHub.sync);
    },
  };

  // ---------- 8.6 Password（改密码：生成盐值哈希，随同步/导出落盘） ----------
  const Password = {
    status(msg, kind = '') {
      const el = document.getElementById('password-mgmt-status');
      if (el) {
        el.textContent = msg;
        el.className = `github-sync-status${kind ? ` ${kind}` : ''}`;
      }
    },
    refreshStatus() {
      const el = document.getElementById('password-current-status');
      if (!el) return;
      Data.get().then((data) => {
        const c = (data && data.config) || {};
        const pending = ConfigStore.getPending();
        if (pending && pending.passwordHash) el.textContent = '已生成新哈希，待同步到 GitHub（或导出 JSON）后写入文件';
        else if (c.passwordHash) el.textContent = '已加密存储（SHA-256 + 盐值）';
        else el.textContent = '明文存储，建议立即升级';
      }).catch(() => {});
    },
    randomSalt() {
      const buf = new Uint8Array(16);
      if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(buf);
      else for (let i = 0; i < buf.length; i++) buf[i] = (Math.random() * 256) | 0;
      return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
    },
    setNew() {
      const input = $('#new-password');
      if (!input) return;
      const v = input.value.trim();
      if (!/^\d{6}$/.test(v)) {
        Password.status('请输入 6 位数字新密码', 'error');
        return;
      }
      if (!SHA256_OK) {
        Password.status('内置 SHA-256 自检失败，无法生成哈希', 'error');
        return;
      }
      const salt = Password.randomSalt();
      ConfigStore.savePending({ passwordSalt: salt, passwordHash: sha256Hex(salt + v) });
      input.value = '';
      Password.status('新密码已在本地生效，请点「同步到 GitHub」写入仓库（或用导出 JSON 手动替换）', 'success');
      Password.refreshStatus();
    },
    initForm() {
      $('#set-password-btn')?.addEventListener('click', Password.setNew);
      Password.refreshStatus();
    },
  };

  // ---------- 9. Settings（排序设置 + 弹窗开关） ----------
  const Settings = {
    init() {
      const btn = $('#settings-button');
      const modal = $('#settings-modal');
      const order = $('#timeline-order');
      const save = $('#save-settings');
      if (!btn || !modal || !order || !save) return;
      order.checked = Store.getSettings().timelineOrder === true;

      btn.addEventListener('click', () => {
        // 拖拽后 suppress 的 click 不应打开面板
        if (btn.dataset.suppress === '1') return;
        modal.style.display = 'block';
        Management.refresh();
      });
      modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
      });
      $('.settings-close-button')?.addEventListener('click', () => {
        modal.style.display = 'none';
      });
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          modal.style.display = 'none';
          Management.closeForm();
        }
      });
      save.addEventListener('click', () => {
        Store.saveSettings({ timelineOrder: order.checked });
        modal.style.display = 'none';
        Timeline.load();
      });
      $('#export-timeline-btn')?.addEventListener('click', Timeline.export);
      GitHub.initForm();
      Password.initForm();

      // 事件表单内的图片直传
      $('#event-image-file')?.addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) GitHub.uploadImage(file);
        // 允许重复选择同一文件
        e.target.value = '';
      });

      Draggable.attach(btn);
    },
  };

  // ---------- 10. Draggable（设置按钮拖拽，区分点击/拖动） ----------
  const Draggable = {
    attach(el) {
      let sx = 0, sy = 0, ox = 0, oy = 0, dragging = false, moved = 0;
      try {
        const pos = safeJsonParse(localStorage.getItem('settingsButtonPosition'), {});
        ox = +pos.x || 0;
        oy = +pos.y || 0;
        el.style.transform = `translate(${ox}px, ${oy}px)`;
      } catch { /* 忽略 */ }

      const onMove = (cx, cy) => {
        const dx = cx - sx;
        const dy = cy - sy;
        moved = Math.max(moved, Math.abs(dx), Math.abs(dy));
        if (Math.max(Math.abs(dx), Math.abs(dy)) > 4 && !dragging) {
          dragging = true;
          el.classList.add('dragging');
        }
        if (dragging) el.style.transform = `translate(${ox + dx}px, ${oy + dy}px)`;
      };
      const onEnd = (cx, cy) => {
        if (dragging) {
          ox += cx - sx;
          oy += cy - sy;
          try {
            localStorage.setItem('settingsButtonPosition', JSON.stringify({ x: ox, y: oy }));
          } catch { /* 忽略 */ }
        }
        if (moved > 4) {
          // 抑制拖拽抬起后冒泡的 click
          el.dataset.suppress = '1';
          setTimeout(() => delete el.dataset.suppress, 50);
          const cap = (e) => {
            e.stopPropagation();
            e.preventDefault();
            el.removeEventListener('click', cap, true);
          };
          el.addEventListener('click', cap, true);
        }
        dragging = false;
        moved = 0;
        el.classList.remove('dragging');
        document.removeEventListener('mousemove', mm);
        document.removeEventListener('mouseup', mu);
        document.removeEventListener('touchmove', tm, { passive: false });
        document.removeEventListener('touchend', tu);
      };
      const mm = (e) => onMove(e.clientX, e.clientY);
      const mu = (e) => onEnd(e.clientX, e.clientY);
      const tm = (e) => {
        if (e.cancelable && dragging) e.preventDefault();
        const t = e.touches[0];
        if (t) onMove(t.clientX, t.clientY);
      };
      const tu = (e) => {
        const t = e.changedTouches[0];
        onEnd(t ? t.clientX : sx, t ? t.clientY : sy);
      };

      el.addEventListener('mousedown', (e) => {
        sx = e.clientX;
        sy = e.clientY;
        document.addEventListener('mousemove', mm);
        document.addEventListener('mouseup', mu);
      });
      el.addEventListener('touchstart', (e) => {
        const t = e.touches[0];
        if (!t) return;
        sx = t.clientX;
        sy = t.clientY;
        document.addEventListener('touchmove', tm, { passive: false });
        document.addEventListener('touchend', tu);
      }, { passive: true });
    },
  };

  // ---------- 11. BackToTop + 全局滚动（单监听、passive） ----------
  const BackToTop = {
    init() {
      const btn = $('#back-to-top');
      if (!btn) return;
      const onScroll = rafThrottle(() => {
        btn.classList.toggle('visible', window.pageYOffset > 300);
      });
      window.addEventListener('scroll', onScroll, { passive: true });
      btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    },
  };

  // ---------- 12. 启动 ----------
  document.addEventListener('DOMContentLoaded', async () => {
    // 禁止双指缩放（移自内联脚本，统一收敛到主脚本）
    document.addEventListener('touchstart', (e) => {
      if (e.touches.length > 1) e.preventDefault();
    }, { passive: false });
    document.addEventListener('gesturestart', (e) => e.preventDefault());

    Theme.init();
    Counter.init();
    Timeline.init();
    Settings.init();
    BackToTop.init();
    Management.init();

    try {
      const data = await Data.get();
      if (!data.config || (data.config.passwordHash == null && data.config.password == null)) {
        const screen = $('#password-screen');
        if (screen) screen.innerHTML = '<p style="color: red;">配置缺少密码字段，无法验证身份。<br>请检查 data/timeline.json 的 config 是否包含 passwordHash。</p>';
        return;
      }
      Auth.init(data.config, Lazy.observeNew);
      Timeline.load(); // 未解锁也预渲染，解锁后立刻可见
    } catch (e) {
      console.error('获取配置时出错:', e);
      const screen = $('#password-screen');
      if (screen) screen.innerHTML = '<p style="color: red;">无法加载配置。请检查 `data/timeline.json` 文件是否存在且格式正确。</p>';
    }
    window.addEventListener('load', Lazy.observeNew);
  });

  // 兼容旧 HTML 内联可能调用的全局（保留最小面）
  window.updateTimelineEventsList = () => Management.refresh();
})();
