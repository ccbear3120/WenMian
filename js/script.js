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

  /** 指定时区偏移（小时）取时间分量 */
  const zoneParts = (offsetHours, date = new Date()) => {
    const b = new Date(date.getTime() + offsetHours * 3600 * 1000);
    const p = (n) => String(n).padStart(2, '0');
    return {
      yy: String(b.getUTCFullYear()).slice(2),
      MM: p(b.getUTCMonth() + 1),
      dd: p(b.getUTCDate()),
      HH: p(b.getUTCHours()),
      mm: p(b.getUTCMinutes()),
    };
  };

  /** 上传用时间文件夹名：如 2026-09-27 12:12（北京）→ 260927_1212 */
  const uploadFolderName = (date = new Date()) => {
    const t = zoneParts(8, date);
    return `${t.yy}${t.MM}${t.dd}_${t.HH}${t.mm}`;
  };

  /** 图片 URL 安全校验：仅允许 http(s)/相对路径/images/data:image */
  const sanitizeImageUrl = (url) => {
    const s = String(url || '').trim();
    if (!s) return '';
    if (/^\s*javascript:/i.test(s) || /^\s*data:text\/html/i.test(s)) return '';
    return s;
  };

  /** 图片路径输入解析：一行一张，也兼容逗号分隔 */
  const parseImageList = (text) => String(text || '')
    .split(/[\n,]+/)
    .map((s) => sanitizeImageUrl(s))
    .filter(Boolean);

  /** 取事件的全部图片：兼容老格式 image（单图）与新格式 images（数组） */
  const getEventImages = (event) => {
    const list = [];
    const one = sanitizeImageUrl(event.image);
    if (one) list.push(one);
    if (Array.isArray(event.images)) {
      event.images.forEach((u) => {
        const s = sanitizeImageUrl(u);
        if (s && !list.includes(s)) list.push(s);
      });
    }
    return list;
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

  // ---------- 2.55 GeoLang（按网络 IP 判定国家，仅用于默认语言） ----------
  const GeoLang = {
    KEY: 'geoCountry',
    async country() {
      try {
        const c = safeJsonParse(localStorage.getItem(GeoLang.KEY), null);
        if (c && Date.now() - c.ts < 86400000 && c.cc) return c.cc;
      } catch { /* 忽略 */ }
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 5000);
        const res = await fetch('https://ipapi.co/json/', { signal: ctrl.signal });
        clearTimeout(timer);
        if (res.ok) {
          const j = await res.json();
          const cc = String(j.country_code || '').toUpperCase();
          try {
            localStorage.setItem(GeoLang.KEY, JSON.stringify({ cc, ts: Date.now() }));
          } catch { /* 忽略 */ }
          return cc;
        }
      } catch { /* 忽略 */ }
      return '';
    },
  };

  // ---------- 2.6 I18n（中文 / 越南语切换） ----------
  const I18n = {
    dict: {
      zh: {
        pw_title: '请输入密码', pw_wrong: '密码错误', pw_many: '尝试过多，稍后再试',
        cfg_nopw: '配置缺少密码字段，无法验证身份。<br>请检查 data/timeline.json 的 config 是否包含 passwordHash。',
        cfg_fail: '无法加载配置。请检查 `data/timeline.json` 文件是否存在且格式正确。',
        u_day: '天', t_year: '年', t_month: '月', t_day: '日', t_hour: '时', t_min: '分', t_sec: '秒',
        start_prefix: '起始日: ', invalid_date: '无效日期',
        fmt_days: '{n}天', fmt_days_future: '{n}天后',
        img_alt: '时间线图片', more_tip: '查看更多', empty: '没有匹配的事件，换个条件试试',
        found: '找到 {a} 条（共 {b} 条）',
        opt_all_year: '全部年份', opt_all_month: '全部月份', opt_all_category: '全部类型',
        ph_search: '搜索标题 / 描述…', btn_clear: '清除',
        form_add: '新增事件', form_edit: '编辑事件',
        mgmt_added: ' (新增)', mgmt_pinned: ' (置顶)',
        act_edit: '编辑', act_pin: '置顶', act_unpin: '取消置顶', act_del: '删除',
        del_confirm: '确定要删除这个事件吗？',
        list_bad_json: 'JSON 格式错误：缺少 timeline 数组',
        list_fail: '加载失败：', list_fail_hint: '请用本地服务器运行（如 npx serve / python -m http.server）',
        pwd_loading: '读取中…',
        exp_ok: '导出成功！请将下载的 timeline.json 替换 data/timeline.json 文件',
        exp_fail: '导出失败，请查看控制台',
        gh_need_cfg: '请先填写 Owner、仓库名和 Token',
        gh_api_err: 'GitHub API 错误（{s}）',
        gh_file_block: '当前是 file:// 直接打开，读到的只是内嵌兜底数据。请用部署后的 https 地址（或本地服务器如 npx serve）打开后再同步，否则会覆盖远端文件',
        gh_reading: '正在读取本地与远端…',
        gh_remote_bad: '远端 data/timeline.json 无法解析（可能是手改时写坏了 JSON）。继续同步将用本地数据覆盖远端。\n\n继续吗？（建议先取消，去 GitHub 网页修好 JSON）',
        gh_cancelled: '已取消同步，远端文件未动',
        gh_drop_confirm: '远端 {r} 条，合并后 {m} 条：其中远端独有的 {k} 条会被保留，{d} 条会被删除（你在本机删过）。\n\n继续同步吗？',
        gh_merged_note: '检测到远端独有的 {n} 条事件，已自动合并保留',
        gh_pushing: '正在提交到 GitHub…',
        gh_ok: '同步成功！本地 {l} 条 + 远端独有 {k} 条 → {m} 条（远端旧文件已自动下载备份）。Pages 约 1～2 分钟后重新部署',
        gh_fail: '同步失败：{e}{h}。本地数据未动，可放心重试',
        gh_h401: '（Token 无效或过期）', gh_h404: '（仓库/分支不存在，或 Token 无权访问）', gh_h409: '（分支冲突，请重试）',
        up_need_cfg: '请先在下方「GitHub 同步」填好 Owner / 仓库名 / Token',
        up_pick: '请选择图片文件', up_max9: '一次最多 9 张，请分批上传',
        up_toobig: '有图片超过 10MB，请压缩后再传',
        up_toobig_after: '“{n}”压缩后仍超过 8MB，请换一张小图',
        up_progress: '正在上传 {i}/{t}：{n}…',
        up_done: '上传成功 {n} 张，已追加到上面的路径框（每行一张）',
        up_fail: '上传失败：{e}',
        token_saved_ph: '已保存（重新输入可覆盖）',
        pwd_pending: '已生成新哈希，待同步到 GitHub（或导出 JSON）后写入文件',
        pwd_hashed: '已加密存储（SHA-256 + 盐值）',
        pwd_plain: '明文存储，建议立即升级',
        pwd_need6: '请输入 6 位数字新密码',
        pwd_sha_fail: '内置 SHA-256 自检失败，无法生成哈希',
        pwd_set_ok: '新密码已在本地生效，请点「同步到 GitHub」写入仓库（或用导出 JSON 手动替换）',
        lb_view: '照片浏览', lb_close: '关闭', lb_prev: '上一张', lb_next: '下一张', lb_zin: '放大', lb_zout: '缩小',
        photo_alt: '照片 {i} / {n}',
        music_on: '关闭背景音乐', music_off: '打开背景音乐',
        set_title: '设置', set_order: '时间线显示顺序',
        set_order_desc: '切换时间线的显示顺序（正序/倒序）',
        theme_dark: '夜间模式', theme_dark_desc: '切换到深色主题',
        theme_sys: '跟随系统', theme_sys_desc: '根据系统设置自动切换主题',
        sec_timeline: '时间线管理', btn_add: '新增事件', btn_export: '导出 JSON', btn_sync: '同步到 GitHub',
        desc_mgmt: '「导出 JSON」是手动备份；配置下方 GitHub 信息后，可用「同步到 GitHub」把新增/修改直接写进仓库的 <code>data/timeline.json</code> 并自动重新部署',
        gh_owner: '仓库 Owner', gh_repo: '仓库名', gh_branch: '分支', gh_token: 'Token（需 Contents 读写权限）',
        desc_gh_token: 'Token 只保存在本机浏览器 localStorage。建议用 Fine-grained token，仅授权这一个仓库的 Contents 读写权限。获取位置：GitHub → Settings → Developer settings → Personal access tokens',
        sec_pwd: '密码安全', lb_newpwd: '新密码（6 位数字）', btn_setpwd: '设为新密码',
        desc_pwd: '密码以 SHA-256 + 随机盐值存储，不再是明文。设置后需「同步到 GitHub」才会写入仓库文件',
        btn_save: '保存设置',
        f_date: '日期', f_time: '时间（可选）', f_title: '标题', f_category: '类型', f_desc: '描述',
        f_image: '图片路径（一行一张，可多张）', f_upload: '上传图片到 GitHub（可多选，一次最多 9 张）',
        f_top: '置顶显示', btn_cancel: '取消', btn_form_save: '保存',
        ph_ev_title: '事件标题', ph_ev_desc: '事件描述（支持HTML）',
        ph_ev_image: 'images/xxx.jpg，一行一张，可填多张',
        ph_owner: '例如：zhangsan', ph_repo: '例如：love-diary',
        ph_newpw: '输入 6 位数字',
        desc_ev_upload: '选择本地图片后自动上传到仓库时间文件夹（北京时间命名，如 <code>images/260927_1212/</code>），并追加到上面的路径框',
        aria_pw: '密码验证', aria_keypad: '数字键盘', key_del: '删除',
        aria_f_search: '搜索事件', aria_f_year: '按年份筛选', aria_f_month: '按月份筛选', aria_f_category: '按类型筛选',
        aria_precise: '精确时间', aria_top: '回到顶部',
        aria_settings_dlg: '设置', aria_event_dlg: '时间线事件',
        aria_settings_btn: '打开设置', aria_close: '关闭设置', aria_close2: '关闭',
      },
      vi: {
        pw_title: 'Nhập mật khẩu', pw_wrong: 'Sai mật khẩu', pw_many: 'Thử quá nhiều, vui lòng đợi',
        cfg_nopw: 'Thiếu trường mật khẩu, không thể xác thực.<br>Vui lòng kiểm tra config trong data/timeline.json.',
        cfg_fail: 'Không tải được cấu hình. Kiểm tra tệp `data/timeline.json`.',
        u_day: 'Ngày', t_year: 'Năm', t_month: 'Tháng', t_day: 'Ngày', t_hour: 'Giờ', t_min: 'Phút', t_sec: 'Giây',
        start_prefix: 'Ngày bắt đầu: ', invalid_date: 'Ngày không hợp lệ',
        fmt_days: '{n} ngày', fmt_days_future: '{n} ngày nữa',
        img_alt: 'Ảnh dòng thời gian', more_tip: 'Xem thêm', empty: 'Không có sự kiện phù hợp, thử điều kiện khác',
        found: 'Tìm thấy {a} (tổng {b})',
        opt_all_year: 'Tất cả các năm', opt_all_month: 'Tất cả các tháng', opt_all_category: 'Tất cả thể loại',
        ph_search: 'Tìm tiêu đề / mô tả…', btn_clear: 'Xóa lọc',
        form_add: 'Thêm sự kiện', form_edit: 'Sửa sự kiện',
        mgmt_added: ' (mới)', mgmt_pinned: ' (ghim)',
        act_edit: 'Sửa', act_pin: 'Ghim', act_unpin: 'Bỏ ghim', act_del: 'Xóa',
        del_confirm: 'Xóa sự kiện này?',
        list_bad_json: 'Lỗi định dạng JSON: thiếu mảng timeline',
        list_fail: 'Tải thất bại: ', list_fail_hint: 'Hãy chạy máy chủ nội bộ (ví dụ: npx serve / python -m http.server)',
        pwd_loading: 'Đang đọc…',
        exp_ok: 'Xuất thành công! Thay timeline.json vừa tải vào data/timeline.json',
        exp_fail: 'Xuất thất bại, xem console',
        gh_need_cfg: 'Vui lòng điền Owner, tên repo và Token',
        gh_api_err: 'Lỗi GitHub API ({s})',
        gh_file_block: 'Đang mở bằng file://, chỉ đọc được dữ liệu mẫu. Hãy mở bằng địa chỉ https đã deploy (hoặc máy chủ nội bộ như npx serve) rồi đồng bộ, nếu không sẽ ghi đè file remote',
        gh_reading: 'Đang đọc local và remote…',
        gh_remote_bad: 'Không phân tích được data/timeline.json ở remote (có thể sửa tay bị sai JSON). Tiếp tục sẽ ghi đè remote bằng dữ liệu local.\n\nTiếp tục? (Nên hủy và sửa JSON trên web GitHub)',
        gh_cancelled: 'Đã hủy, file remote không thay đổi',
        gh_drop_confirm: 'Remote có {r} mục, sau khi gộp còn {m} mục: giữ {k} mục chỉ có ở remote, xóa {d} mục (bạn đã xóa trên máy này).\n\nTiếp tục đồng bộ?',
        gh_merged_note: 'Phát hiện {n} sự kiện chỉ có ở remote, đã tự động giữ lại',
        gh_pushing: 'Đang gửi lên GitHub…',
        gh_ok: 'Đồng bộ thành công! Local {l} + remote riêng {k} → {m} mục (đã tự tải backup file remote cũ). Pages deploy lại sau ~1–2 phút',
        gh_fail: 'Đồng bộ thất bại: {e}{h}. Dữ liệu local không đổi, cứ thử lại',
        gh_h401: '(Token sai hoặc hết hạn)', gh_h404: '(repo/nhánh không tồn tại hoặc Token thiếu quyền)', gh_h409: '(xung đột nhánh, thử lại)',
        up_need_cfg: 'Hãy điền Owner / tên repo / Token ở mục「Đồng bộ GitHub」trước',
        up_pick: 'Hãy chọn tệp ảnh', up_max9: 'Tối đa 9 ảnh một lần, chia nhiều lần tải',
        up_toobig: 'Có ảnh quá 10MB, nén rồi tải lại',
        up_toobig_after: 'Ảnh “{n}” sau khi nén vẫn quá 8MB, đổi ảnh khác',
        up_progress: 'Đang tải {i}/{t}: {n}…',
        up_done: 'Tải thành công {n} ảnh, đã thêm vào ô đường dẫn (mỗi dòng một ảnh)',
        up_fail: 'Tải lên thất bại: {e}',
        token_saved_ph: 'Đã lưu (nhập lại để ghi đè)',
        pwd_pending: 'Đã tạo hash mới, đồng bộ lên GitHub (hoặc xuất JSON) để ghi vào file',
        pwd_hashed: 'Đã mã hóa (SHA-256 + salt)',
        pwd_plain: 'Đang lưu plaintext, nên nâng cấp ngay',
        pwd_need6: 'Nhập mật khẩu mới 6 chữ số',
        pwd_sha_fail: 'Tự kiểm SHA-256 thất bại, không tạo được hash',
        pwd_set_ok: 'Mật khẩu mới đã có hiệu lực local, nhấn「Đồng bộ GitHub」để ghi vào repo (hoặc xuất JSON thay tay)',
        lb_view: 'Duyệt ảnh', lb_close: 'Đóng', lb_prev: 'Ảnh trước', lb_next: 'Ảnh sau', lb_zin: 'Phóng to', lb_zout: 'Thu nhỏ',
        photo_alt: 'Ảnh {i} / {n}',
        music_on: 'Tắt nhạc nền', music_off: 'Bật nhạc nền',
        set_title: 'Cài đặt', set_order: 'Thứ tự dòng thời gian',
        set_order_desc: 'Đổi thứ tự hiển thị (cũ→mới / mới→cũ)',
        theme_dark: 'Chế độ tối', theme_dark_desc: 'Chuyển sang giao diện tối',
        theme_sys: 'Theo hệ thống', theme_sys_desc: 'Tự đổi theo cài đặt hệ thống',
        sec_timeline: 'Quản lý dòng thời gian', btn_add: 'Thêm sự kiện', btn_export: 'Xuất JSON', btn_sync: 'Đồng bộ GitHub',
        desc_mgmt: '「Xuất JSON」là sao lưu thủ công; điền thông tin GitHub bên dưới rồi dùng「Đồng bộ GitHub」để ghi thẳng vào <code>data/timeline.json</code> và tự deploy lại',
        gh_owner: 'Chủ repo', gh_repo: 'Tên repo', gh_branch: 'Nhánh', gh_token: 'Token (cần quyền đọc-ghi Contents)',
        desc_gh_token: 'Token chỉ lưu ở localStorage trình duyệt máy này. Nên dùng Fine-grained token, chỉ cấp quyền Contents cho đúng repo này. Lấy ở: GitHub → Settings → Developer settings → Personal access tokens',
        sec_pwd: 'Mật khẩu & bảo mật', lb_newpwd: 'Mật khẩu mới (6 chữ số)', btn_setpwd: 'Đặt mật khẩu mới',
        desc_pwd: 'Mật khẩu lưu dạng SHA-256 + salt ngẫu nhiên, không còn plaintext. Đặt xong cần「Đồng bộ GitHub」mới ghi vào file repo',
        btn_save: 'Lưu cài đặt',
        f_date: 'Ngày', f_time: 'Giờ (không bắt buộc)', f_title: 'Tiêu đề', f_category: 'Thể loại', f_desc: 'Mô tả',
        f_image: 'Đường dẫn ảnh (mỗi dòng một ảnh)', f_upload: 'Tải ảnh lên GitHub (chọn nhiều, tối đa 9)',
        f_top: 'Ghim lên đầu', btn_cancel: 'Hủy', btn_form_save: 'Lưu',
        ph_ev_title: 'Tiêu đề sự kiện', ph_ev_desc: 'Mô tả sự kiện (hỗ trợ HTML)',
        ph_ev_image: 'images/xxx.jpg, mỗi dòng một ảnh',
        ph_owner: 'Ví dụ: zhangsan', ph_repo: 'Ví dụ: love-diary',
        ph_newpw: 'Nhập 6 chữ số',
        desc_ev_upload: 'Chọn ảnh local sẽ tự tải lên thư mục thời gian của repo (đặt tên theo giờ Bắc Kinh, ví dụ <code>images/260927_1212/</code>) và thêm vào ô đường dẫn',
        aria_pw: 'Xác thực mật khẩu', aria_keypad: 'Bàn phím số', key_del: 'Xóa',
        aria_f_search: 'Tìm sự kiện', aria_f_year: 'Lọc theo năm', aria_f_month: 'Lọc theo tháng', aria_f_category: 'Lọc theo thể loại',
        aria_precise: 'Thời gian chính xác', aria_top: 'Về đầu trang',
        aria_settings_dlg: 'Cài đặt', aria_event_dlg: 'Sự kiện dòng thời gian',
        aria_settings_btn: 'Mở cài đặt', aria_close: 'Đóng cài đặt', aria_close2: 'Đóng',
      },
    },
    cur: 'zh',
    t(key, params) {
      const d = I18n.dict[I18n.cur] || {};
      let s = d[key] !== undefined ? d[key] : (I18n.dict.zh[key] !== undefined ? I18n.dict.zh[key] : key);
      if (params) {
        Object.keys(params).forEach((k) => {
          s = String(s).split(`{${k}}`).join(String(params[k]));
        });
      }
      return s;
    },
    locale() {
      return I18n.cur === 'vi' ? 'vi-VN' : 'zh-CN';
    },
    monthName(n) {
      return I18n.cur === 'vi' ? `Tháng ${n}` : `${n} 月`;
    },
    dateBadge(d) {
      const y = d.getFullYear();
      const m = pad2(d.getMonth() + 1);
      const day = pad2(d.getDate());
      return I18n.cur === 'vi' ? `${day}/${m}/${y}` : `${y}年${m}月${day}日`;
    },
    // 事件日期+时间：存量时间视为北京时间，按当前语言时区换算（CN=UTC+8，VN=UTC+7）
    eventDateTime(d, timeStr) {
      const tm = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(timeStr || '').trim());
      if (!tm) return I18n.dateBadge(d);
      const instant = Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), +tm[1] - 8, +tm[2]);
      const off = I18n.cur === 'vi' ? 7 : 8;
      const p = zoneParts(off, new Date(instant));
      const yyyy = `20${p.yy}`;
      return I18n.cur === 'vi'
        ? `${p.dd}/${p.MM}/${yyyy} ${p.HH}:${p.mm}`
        : `${yyyy}年${p.MM}月${p.dd}日 ${p.HH}:${p.mm}`;
    },
    init() {
      I18n.cur = Store.getSettings().lang === 'vi' ? 'vi' : 'zh';
      const btn = document.getElementById('lang-button');
      if (btn) btn.addEventListener('click', I18n.toggle);
      I18n.apply(false);
      // 无手动选择时按 IP 给默认语言：越南 IP 默认越南语，其他默认中文
      if (!Store.getSettings().lang) {
        GeoLang.country().then((cc) => {
          if (cc === 'VN' && !Store.getSettings().lang && I18n.cur !== 'vi') {
            I18n.cur = 'vi';
            I18n.apply(true);
          }
        });
      }
    },
    toggle() {
      I18n.cur = I18n.cur === 'zh' ? 'vi' : 'zh';
      Store.saveSettings({ lang: I18n.cur });
      I18n.apply(true);
    },
    paintButton() {
      const btn = document.getElementById('lang-button');
      if (btn) btn.textContent = I18n.cur === 'zh' ? 'CN' : 'VN';
    },
    applyTitle(config) {
      const c = config || {};
      document.title = I18n.cur === 'vi'
        ? (c.pageTitleVi || c.pageTitle || 'Câu chuyện của chúng ta')
        : (c.pageTitle || '我们的故事');
    },
    apply(rerender) {
      document.documentElement.setAttribute('data-lang', I18n.cur);
      if (document.body) document.body.setAttribute('data-lang', I18n.cur);
      $$('[data-i18n]').forEach((el) => { el.textContent = I18n.t(el.getAttribute('data-i18n')); });
      $$('[data-i18n-ph]').forEach((el) => { el.placeholder = I18n.t(el.getAttribute('data-i18n-ph')); });
      $$('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', I18n.t(el.getAttribute('data-i18n-aria'))); });
      $$('[data-i18n-html]').forEach((el) => { el.innerHTML = I18n.t(el.getAttribute('data-i18n-html')); });
      I18n.paintButton();
      if (!rerender || !Data.cache) return;
      Filter.syncOptions(Timeline.allEvents);
      Filter.applyStored();
      Timeline.render(Filter.apply(Timeline.allEvents));
      Lazy.observeNew();
      Management.refresh();
      Counter.renderHead(Data.cache.config || {});
      I18n.applyTitle(Data.cache.config);
      Password.refreshStatus();
      Lightbox.relabel();
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
      // 跟随系统默认打开：只有用户明确关过才保持关闭
      const systemTheme = 'systemTheme' in settings ? !!settings.systemTheme : true;
      const darkMode = 'darkMode' in settings ? !!settings.darkMode : Theme.media.matches;
      Theme.darkToggle.checked = darkMode;
      Theme.sysToggle.checked = systemTheme;
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
      // 手动切换（白天/夜间都算）优先于跟随系统：动了这个开关就关掉跟随
      Theme.darkToggle.addEventListener('change', () => {
        Theme.sysToggle.checked = false;
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
    authed: false,
    isAuthed() {
      return Auth.authed;
    },

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
        Auth.error(I18n.t('pw_many'));
        Auth.entered = '';
        Auth.paintDots();
        return;
      }
      if (Auth.checkPassword(Auth.entered)) {
        Auth.authed = true;
        Auth.els.screen.style.display = 'none';
        const container = document.querySelector('.container');
        if (container) container.style.display = 'block';
        document.body.style.overflow = '';
        document.documentElement.style.overflow = '';
        // 解锁后才露出设置与回到顶部按钮
        const settingsBtn = document.getElementById('settings-button');
        if (settingsBtn) settingsBtn.style.display = '';
        const backTop = document.getElementById('back-to-top');
        if (backTop) backTop.style.display = '';
        try {
          localStorage.setItem('lastLogin', String(Date.now()));
        } catch { /* 忽略 */ }
        Auth.onSuccess && Auth.onSuccess();
      } else {
        Auth.fails.push(now);
        Auth.entered = '';
        Auth.paintDots();
        Auth.error(I18n.t('pw_wrong'));
      }
    },
    error(msg) {
      Auth.els.title.textContent = msg;
      Auth.els.container.classList.add('error');
      clearTimeout(Auth.error._t);
      Auth.error._t = setTimeout(() => {
        Auth.els.title.textContent = I18n.t('pw_title');
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
    startMs: null,

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
      // 起始墙钟时间不变，按当前语言时区起算（CN=UTC+8，VN=UTC+7），中越动态时长相差 1 小时
      const sm = /^(\d{2}):(\d{2})(?::(\d{2}))?/.exec(String(config.startTime || '00:00:00').trim());
      const off = I18n.cur === 'vi' ? 7 : 8;
      Counter.startMs = sm
        ? Date.UTC(Counter.start.getFullYear(), Counter.start.getMonth(), Counter.start.getDate(), +sm[1] - off, +sm[2], +(sm[3] || 0))
        : Counter.start.getTime();
      const today = startOfDay(new Date());
      const startDay = startOfDay(Counter.start);
      const diffMs = startDay.getTime() - today.getTime();
      const vi = I18n.cur === 'vi';
      let text;
      let days;
      if (diffMs > 0) {
        text = vi
          ? (config.counterTextBeforeVi || config.counterTextBefore || `距离和${config.partnerName || ''}在一起还有`)
          : (config.counterTextBefore || `距离和${config.partnerName || ''}在一起还有`);
        days = Math.round(diffMs / 86400000);
      } else {
        text = vi
          ? (config.counterTextAfterVi || config.counterTextAfter || `和${config.partnerName || ''}在一起已经`)
          : (config.counterTextAfter || `和${config.partnerName || ''}在一起已经`);
        days = Math.floor((today - startDay) / 86400000) + 1; // 当天记为第 1 天
      }
      if (Counter.els.text) Counter.els.text.textContent = text;
      if (Counter.els.start) {
        Counter.els.start.textContent = `${I18n.t('start_prefix')}${Counter.start.toLocaleDateString(I18n.locale(), {
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
      if (!Counter.start || Counter.startMs == null || Counter.els.units.length < 6) return;
      const d = diffCalendar(new Date(Counter.startMs), new Date());
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
    allEvents: [],
    init() {
      Timeline.els.section = document.getElementById('timeline-list');
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
      // 未解锁不渲染，验证通过后才加载数据
      if (!Auth.isAuthed()) return;
      try {
        const data = await Data.get();
        I18n.applyTitle(data.config);
        Counter.renderHead(data.config || {});
        const events = Timeline.sort(Timeline.merge(data.timeline));
        Timeline.allEvents = events;
        Filter.syncOptions(events);
        Filter.applyStored();
        Timeline.render(Filter.apply(events));
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
      if (!events.length) {
        const empty = document.createElement('div');
        empty.className = 'timeline-empty';
        empty.textContent = I18n.t('empty');
        box.appendChild(empty);
        return;
      }
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
        dateEl.textContent = I18n.eventDateTime(d, eventData.time);
      } else {
        dateEl.textContent = I18n.t('invalid_date');
        console.error('时间线事件中的日期格式无效:', eventData.date);
      }
      if (eventData.category) {
        const chip = document.createElement('span');
        chip.className = 'timeline-category';
        chip.textContent = eventData.category;
        dateEl.appendChild(chip);
      }
      item.append(dateEl, h3, p);

      const imgUrls = getEventImages(eventData);
      const MAX_SHOW = 4;
      if (imgUrls.length === 1) {
        item.appendChild(Timeline.createImageWrap(imgUrls[0], eventData.title, 0, imgUrls));
      } else if (imgUrls.length > 1) {
        const grid = document.createElement('div');
        grid.className = 'image-grid';
        imgUrls.slice(0, MAX_SHOW).forEach((url, i) => {
          const more = imgUrls.length > MAX_SHOW && i === MAX_SHOW - 1
            ? imgUrls.length - MAX_SHOW
            : 0;
          grid.appendChild(Timeline.createImageWrap(url, eventData.title, i, imgUrls, more));
        });
        item.appendChild(grid);
      }

      const badge = document.createElement('div');
      badge.className = 'timeline-days-badge';
      if (d && !Number.isNaN(d)) {
        const diff = Math.floor((startOfDay(new Date()) - startOfDay(d)) / 86400000);
        badge.textContent = diff >= 0
          ? I18n.t('fmt_days', { n: diff })
          : I18n.t('fmt_days_future', { n: Math.abs(diff) });
      } else {
        badge.textContent = '--';
      }
      item.appendChild(badge);
      return item;
    },
    createImageWrap(imgUrl, title, index, allImages, moreCount = 0) {
      const wrap = document.createElement('div');
      wrap.className = 'image-container';
      wrap.style.cursor = 'zoom-in';
      const img = document.createElement('img');
      img.className = 'lazy-image';
      img.setAttribute('data-src', imgUrl);
      img.alt = title || I18n.t('img_alt');
      img.decoding = 'async';
      img.addEventListener('error', () => {
        img.style.display = 'none';
        img.classList.add('loaded');
        wrap.classList.add('loaded');
        console.warn('图片未找到: ' + imgUrl);
      }, { once: true });
      wrap.appendChild(img);
      if (moreCount > 0) {
        wrap.classList.add('more');
        const ov = document.createElement('div');
        ov.className = 'image-more-overlay';
        const num = document.createElement('span');
        num.textContent = `+${moreCount}`;
        const tip = document.createElement('small');
        tip.textContent = I18n.t('more_tip');
        ov.append(num, tip);
        wrap.appendChild(ov);
      }
      wrap.addEventListener('click', () => Lightbox.open(allImages || [imgUrl], index || 0));
      return wrap;
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
        alert(I18n.t('exp_ok'));
      } catch (e) {
        console.error('导出失败:', e);
        alert(I18n.t('exp_fail'));
      }
    },
  };

  // ---------- 6.5 Filter（时间 + 类型 + 关键词筛选） ----------
  const Filter = {
    els: {},
    value: { keyword: '', year: '', month: '', category: '' },
    init() {
      Filter.els = {
        keyword: document.getElementById('filter-keyword'),
        year: document.getElementById('filter-year'),
        month: document.getElementById('filter-month'),
        category: document.getElementById('filter-category'),
        clear: document.getElementById('filter-clear'),
        count: document.getElementById('filter-count'),
      };
      if (!Filter.els.keyword) return;
      let deb = null;
      Filter.els.keyword.addEventListener('input', () => {
        clearTimeout(deb);
        deb = setTimeout(Filter.onChange, 200);
      });
      [Filter.els.year, Filter.els.month, Filter.els.category].forEach((el) => {
        if (el) el.addEventListener('change', Filter.onChange);
      });
      if (Filter.els.clear) Filter.els.clear.addEventListener('click', Filter.reset);
    },
    readControls() {
      Filter.value = {
        keyword: ((Filter.els.keyword && Filter.els.keyword.value) || '').trim(),
        year: (Filter.els.year && Filter.els.year.value) || '',
        month: (Filter.els.month && Filter.els.month.value) || '',
        category: (Filter.els.category && Filter.els.category.value) || '',
      };
    },
    onChange() {
      Filter.readControls();
      Store.saveSettings({ timelineFilter: Filter.value });
      Timeline.render(Filter.apply(Timeline.allEvents));
      Lazy.observeNew();
    },
    reset() {
      if (Filter.els.keyword) Filter.els.keyword.value = '';
      if (Filter.els.year) Filter.els.year.value = '';
      if (Filter.els.month) Filter.els.month.value = '';
      if (Filter.els.category) Filter.els.category.value = '';
      Filter.onChange();
    },
    applyStored() {
      const s = Store.getSettings().timelineFilter || {};
      if (Filter.els.keyword) Filter.els.keyword.value = s.keyword || '';
      if (Filter.els.year) Filter.els.year.value = s.year || '';
      if (Filter.els.month) Filter.els.month.value = s.month || '';
      if (Filter.els.category) Filter.els.category.value = s.category || '';
      Filter.readControls();
    },
    buildMonths() {
      const el = Filter.els.month;
      if (!el) return;
      const cur = el.value;
      el.innerHTML = '';
      const all = document.createElement('option');
      all.value = '';
      all.textContent = I18n.t('opt_all_month');
      el.appendChild(all);
      for (let m = 1; m <= 12; m++) {
        const o = document.createElement('option');
        o.value = pad2(m);
        o.textContent = I18n.monthName(m);
        el.appendChild(o);
      }
      const valid = cur === '' || (/^(0[1-9]|1[0-2])$/.test(cur));
      el.value = valid ? cur : '';
    },
    fillSelect(el, values, allLabel) {
      if (!el) return;
      const cur = el.value;
      el.innerHTML = '';
      const all = document.createElement('option');
      all.value = '';
      all.textContent = allLabel;
      el.appendChild(all);
      values.forEach((v) => {
        const o = document.createElement('option');
        o.value = v;
        o.textContent = v;
        el.appendChild(o);
      });
      el.value = values.includes(cur) ? cur : '';
    },
    syncOptions(events) {
      const years = new Set();
      const cats = new Set();
      (events || []).forEach((e) => {
        const d = parseLocalDate(e.date);
        if (d) years.add(String(d.getFullYear()));
        if (e.category) cats.add(String(e.category));
      });
      Filter.buildMonths();
      Filter.fillSelect(Filter.els.year, [...years].sort().reverse(), I18n.t('opt_all_year'));
      Filter.fillSelect(Filter.els.category, [...cats].sort(), I18n.t('opt_all_category'));
    },
    apply(events) {
      const f = Filter.value;
      const kw = (f.keyword || '').toLowerCase();
      const out = (events || []).filter((e) => {
        if (f.year || f.month) {
          const d = parseLocalDate(e.date);
          if (!d) return false;
          if (f.year && String(d.getFullYear()) !== f.year) return false;
          if (f.month && pad2(d.getMonth() + 1) !== f.month) return false;
        }
        if (f.category && String(e.category || '') !== f.category) return false;
        if (kw) {
          const hay = `${e.title || ''}\n${e.description || ''}\n${e.date || ''}`.toLowerCase();
          if (!hay.includes(kw)) return false;
        }
        return true;
      });
      Filter.paintCount(events ? events.length : 0, out.length);
      return out;
    },
    paintCount(total, shown) {
      const el = Filter.els.count;
      if (!el) return;
      const f = Filter.value;
      const active = f.keyword || f.year || f.month || f.category;
      el.textContent = active ? I18n.t('found', { a: shown, b: total }) : '';
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

  // ---------- 7.5 Lightbox（全屏浏览事件全部照片） ----------
  const Lightbox = {
    images: [],
    index: 0,
    els: {},
    prevOverflow: '',
    touchX: null,
    touchStartY: 0,
    touchTime: 0,
    lastTap: 0,
    scale: 1,
    tx: 0,
    ty: 0,
    pinch: null,
    pan: null,
    mousePan: null,
    build() {
      if (Lightbox.els.overlay) return;
      const overlay = document.createElement('div');
      overlay.className = 'lightbox';
      overlay.style.display = 'none';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.setAttribute('aria-label', I18n.t('lb_view'));
      overlay.innerHTML = ''
        + '<div class="lightbox-counter"></div>'
        + `<button type="button" class="lightbox-close" aria-label="${I18n.t('lb_close')}">`
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>'
        + '</button>'
        + `<button type="button" class="lightbox-prev" aria-label="${I18n.t('lb_prev')}">`
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>'
        + '</button>'
        + `<img class="lightbox-img" alt="${I18n.t('img_alt')}">`
        + `<button type="button" class="lightbox-next" aria-label="${I18n.t('lb_next')}">`
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>'
        + '</button>'
        + `<button type="button" class="lightbox-zoom-out" aria-label="${I18n.t('lb_zout')}">`
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/></svg>'
        + '</button>'
        + `<button type="button" class="lightbox-zoom-in" aria-label="${I18n.t('lb_zin')}">`
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>'
        + '</button>';
      document.body.appendChild(overlay);
      Lightbox.els.overlay = overlay;
      Lightbox.els.img = overlay.querySelector('.lightbox-img');
      Lightbox.els.counter = overlay.querySelector('.lightbox-counter');
      Lightbox.els.prev = overlay.querySelector('.lightbox-prev');
      Lightbox.els.next = overlay.querySelector('.lightbox-next');
      overlay.querySelector('.lightbox-close').addEventListener('click', Lightbox.close);
      overlay.querySelector('.lightbox-prev').addEventListener('click', (e) => { e.stopPropagation(); Lightbox.go(-1); });
      overlay.querySelector('.lightbox-next').addEventListener('click', (e) => { e.stopPropagation(); Lightbox.go(1); });
      overlay.querySelector('.lightbox-zoom-in').addEventListener('click', (e) => { e.stopPropagation(); Lightbox.zoomIn(); });
      overlay.querySelector('.lightbox-zoom-out').addEventListener('click', (e) => { e.stopPropagation(); Lightbox.zoomOut(); });
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) Lightbox.close();
      });
      const img = overlay.querySelector('.lightbox-img');
      // 桌面：双击缩放、滚轮缩放、放大后拖拽平移
      img.addEventListener('dblclick', (e) => Lightbox.toggleZoom(e.clientX, e.clientY));
      img.addEventListener('wheel', (e) => {
        e.preventDefault();
        Lightbox.setZoom(Lightbox.scale * (e.deltaY < 0 ? 1.15 : 1 / 1.15), e.clientX, e.clientY);
      }, { passive: false });
      img.addEventListener('mousedown', (e) => {
        if (Lightbox.scale <= 1 || e.button !== 0) return;
        Lightbox.mousePan = { x: e.clientX, y: e.clientY, tx: Lightbox.tx, ty: Lightbox.ty };
        img.style.cursor = 'grabbing';
        e.preventDefault();
      });
      document.addEventListener('mousemove', (e) => {
        const mp = Lightbox.mousePan;
        if (!mp || !Lightbox.els.overlay || Lightbox.els.overlay.style.display === 'none') return;
        Lightbox.tx = mp.tx + (e.clientX - mp.x);
        Lightbox.ty = mp.ty + (e.clientY - mp.y);
        Lightbox.clampPan();
        Lightbox.applyTransform();
      });
      document.addEventListener('mouseup', () => {
        Lightbox.mousePan = null;
        if (Lightbox.els.img) Lightbox.els.img.style.cursor = Lightbox.scale > 1 ? 'grab' : 'zoom-in';
      });
      // 移动端：单指滑动翻页（未放大时）、单指拖拽平移（放大后）、双指缩放、双击缩放
      overlay.addEventListener('touchstart', (e) => {
        if (e.touches.length === 2) {
          const a = e.touches[0], b = e.touches[1];
          Lightbox.pinch = {
            dist: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY),
            scale: Lightbox.scale,
          };
          Lightbox.touchX = null;
          Lightbox.pan = null;
        } else if (e.touches.length === 1) {
          const t = e.touches[0];
          Lightbox.touchX = t.clientX;
          Lightbox.touchStartY = t.clientY;
          Lightbox.touchTime = Date.now();
          Lightbox.pan = Lightbox.scale > 1
            ? { x: t.clientX, y: t.clientY, tx: Lightbox.tx, ty: Lightbox.ty, moved: false }
            : null;
        }
      }, { passive: true });
      overlay.addEventListener('touchmove', (e) => {
        if (Lightbox.pinch && e.touches.length === 2) {
          e.preventDefault();
          const a = e.touches[0], b = e.touches[1];
          const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
          if (dist > 0 && Lightbox.pinch.dist > 0) {
            Lightbox.setZoom(
              Lightbox.pinch.scale * dist / Lightbox.pinch.dist,
              (a.clientX + b.clientX) / 2,
              (a.clientY + b.clientY) / 2,
            );
          }
        } else if (Lightbox.pan && e.touches.length === 1) {
          e.preventDefault();
          const t = e.touches[0];
          if (Math.abs(t.clientX - Lightbox.touchX) > 6 || Math.abs(t.clientY - Lightbox.touchStartY) > 6) {
            Lightbox.pan.moved = true;
          }
          Lightbox.tx = Lightbox.pan.tx + (t.clientX - Lightbox.pan.x);
          Lightbox.ty = Lightbox.pan.ty + (t.clientY - Lightbox.pan.y);
          Lightbox.clampPan();
          Lightbox.applyTransform();
        }
      }, { passive: false });
      overlay.addEventListener('touchend', (e) => {
        if (Lightbox.pinch) {
          if (e.touches.length < 2) Lightbox.pinch = null;
          Lightbox.touchX = null;
          Lightbox.pan = null;
          return;
        }
        const t = e.changedTouches[0];
        const now = Date.now();
        const quickTap = t && Lightbox.touchX != null
          && Math.abs(t.clientX - Lightbox.touchX) < 12
          && Math.abs(t.clientY - Lightbox.touchStartY) < 12
          && now - Lightbox.touchTime < 300;
        if (quickTap && now - Lightbox.lastTap < 350) {
          // 双击：放大 / 还原
          Lightbox.lastTap = 0;
          Lightbox.touchX = null;
          Lightbox.pan = null;
          Lightbox.toggleZoom(t.clientX, t.clientY);
          return;
        }
        if (quickTap) Lightbox.lastTap = now;
        if ((Lightbox.pan && Lightbox.pan.moved) || Lightbox.scale > 1) {
          Lightbox.touchX = null;
          Lightbox.pan = null;
          return;
        }
        if (Lightbox.touchX == null) { Lightbox.pan = null; return; }
        const dx = t ? t.clientX - Lightbox.touchX : 0;
        Lightbox.touchX = null;
        Lightbox.pan = null;
        if (Math.abs(dx) > 40) Lightbox.go(dx < 0 ? 1 : -1);
      }, { passive: true });
    },
    onKey(e) {
      if (e.key === 'Escape') Lightbox.close();
      else if (e.key === 'ArrowRight') Lightbox.go(1);
      else if (e.key === 'ArrowLeft') Lightbox.go(-1);
    },
    resetZoom() {
      Lightbox.scale = 1;
      Lightbox.tx = 0;
      Lightbox.ty = 0;
      Lightbox.pinch = null;
      Lightbox.pan = null;
      Lightbox.mousePan = null;
      Lightbox.applyTransform();
    },
    applyTransform() {
      const img = Lightbox.els.img;
      if (!img) return;
      img.style.transform = Lightbox.scale === 1
        ? ''
        : `translate(${Lightbox.tx}px, ${Lightbox.ty}px) scale(${Lightbox.scale})`;
      img.style.cursor = Lightbox.scale > 1 ? 'grab' : 'zoom-in';
    },
    // 未变换时的布局盒（相对 overlay），用于缩放焦点与平移限位
    layoutBox() {
      const img = Lightbox.els.img;
      const ov = Lightbox.els.overlay.getBoundingClientRect();
      const r = img.getBoundingClientRect();
      const s = Lightbox.scale || 1;
      const w = r.width / s;
      const h = r.height / s;
      const cx = r.left + r.width / 2 - Lightbox.tx - ov.left;
      const cy = r.top + r.height / 2 - Lightbox.ty - ov.top;
      return { x: cx - w / 2, y: cy - h / 2, w, h };
    },
    setZoom(next, fx, fy) {
      const s = Math.min(4, Math.max(1, next));
      const ov = Lightbox.els.overlay.getBoundingClientRect();
      if (fx == null) fx = ov.left + ov.width / 2;
      if (fy == null) fy = ov.top + ov.height / 2;
      const box = Lightbox.layoutBox();
      const lcx = box.x + ov.left + box.w / 2;
      const lcy = box.y + ov.top + box.h / 2;
      const k = s / Lightbox.scale;
      Lightbox.tx = fx - lcx - (fx - lcx - Lightbox.tx) * k;
      Lightbox.ty = fy - lcy - (fy - lcy - Lightbox.ty) * k;
      Lightbox.scale = s;
      if (s === 1) {
        Lightbox.tx = 0;
        Lightbox.ty = 0;
      } else {
        Lightbox.clampPan();
      }
      Lightbox.applyTransform();
    },
    clampPan() {
      const box = Lightbox.layoutBox();
      const ov = Lightbox.els.overlay.getBoundingClientRect();
      const maxX = Math.max(0, ((box.w * Lightbox.scale - ov.width) / 2) + 40);
      const maxY = Math.max(0, ((box.h * Lightbox.scale - ov.height) / 2) + 40);
      Lightbox.tx = Math.min(maxX, Math.max(-maxX, Lightbox.tx));
      Lightbox.ty = Math.min(maxY, Math.max(-maxY, Lightbox.ty));
    },
    toggleZoom(fx, fy) {
      Lightbox.setZoom(Lightbox.scale > 1.2 ? 1 : 2.5, fx, fy);
    },
    zoomIn() {
      Lightbox.setZoom(Lightbox.scale * 1.4);
    },
    zoomOut() {
      Lightbox.setZoom(Lightbox.scale / 1.4);
    },
    relabel() {
      const ov = Lightbox.els.overlay;
      if (!ov) return;
      ov.setAttribute('aria-label', I18n.t('lb_view'));
      const set = (sel, key) => {
        const b = ov.querySelector(sel);
        if (b) b.setAttribute('aria-label', I18n.t(key));
      };
      set('.lightbox-close', 'lb_close');
      set('.lightbox-prev', 'lb_prev');
      set('.lightbox-next', 'lb_next');
      set('.lightbox-zoom-out', 'lb_zout');
      set('.lightbox-zoom-in', 'lb_zin');
      if (Lightbox.images.length && Lightbox.els.overlay.style.display !== 'none') {
        Lightbox.render();
      }
    },
    open(images, index) {
      const list = (images || []).filter(Boolean);
      if (!list.length) return;
      Lightbox.build();
      Lightbox.images = list;
      Lightbox.index = Math.min(Math.max(index || 0, 0), list.length - 1);
      Lightbox.prevOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      Lightbox.els.overlay.style.display = 'flex';
      document.addEventListener('keydown', Lightbox.onKey);
      Lightbox.render();
    },
    close() {
      if (!Lightbox.els.overlay) return;
      Lightbox.els.overlay.style.display = 'none';
      document.body.style.overflow = Lightbox.prevOverflow;
      document.removeEventListener('keydown', Lightbox.onKey);
      Lightbox.resetZoom();
    },
    go(step) {
      if (Lightbox.images.length < 2) return;
      Lightbox.index = (Lightbox.index + step + Lightbox.images.length) % Lightbox.images.length;
      Lightbox.render();
    },
    render() {
      const { images, index } = Lightbox;
      Lightbox.resetZoom();
      Lightbox.els.img.src = images[index];
      Lightbox.els.img.alt = I18n.t('photo_alt', { i: index + 1, n: images.length });
      Lightbox.els.counter.textContent = images.length > 1 ? `${index + 1} / ${images.length}` : '';
      const showNav = images.length > 1 ? '' : 'none';
      Lightbox.els.prev.style.display = showNav;
      Lightbox.els.next.style.display = showNav;
      // 预加载前后各一张，翻页不卡
      [index + 1, index - 1].forEach((i) => {
        const u = images[(i + images.length) % images.length];
        if (u) { const pre = new Image(); pre.src = u; }
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
        const imgList = parseImageList(fd.get('image'));
        const payload = {
          date: String(fd.get('date') || ''),
          time: String(fd.get('time') || '').trim(),
          title: String(fd.get('title') || '').trim(),
          category: String(fd.get('category') || '').trim(),
          description: String(fd.get('description') || ''),
          // 1 张存 image（兼容老格式），多张存 images 数组；清空时两者都清掉
          image: imgList.length <= 1 ? (imgList[0] || '') : '',
          images: imgList.length > 1 ? imgList : [],
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
        else if (btn.classList.contains('delete') && confirm(I18n.t('del_confirm'))) Timeline.remove(id);
      });
      Management.refresh();
    },
    async openForm(eventId = null) {
      Management.els.form.reset();
      $('#event-id').value = '';
      $('#timeline-event-modal-title').textContent = eventId ? I18n.t('form_edit') : I18n.t('form_add');
      if (!eventId) $('#event-date').value = new Date().toISOString().slice(0, 10);
      else {
        const data = await Data.get();
        const target = Timeline.merge(data.timeline).find((e) => e.id === eventId);
        if (target) {
          $('#event-id').value = eventId;
          $('#event-date').value = target.date || '';
          $('#event-time').value = target.time || '';
          $('#event-title').value = target.title || '';
          $('#event-category').value = target.category || '';
          $('#event-description').value = target.description || '';
          $('#event-image').value = getEventImages(target).join('\n');
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
      // 未解锁不渲染管理列表，避免标题从 DOM 泄漏
      if (!box || Management.busy || !Auth.isAuthed()) return;
      Management.busy = true;
      try {
        const data = await Data.get();
        if (!Array.isArray(data.timeline)) throw new Error(I18n.t('list_bad_json'));
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
          title.textContent = `${event.title || ''}${addedIds.has(event.id) ? I18n.t('mgmt_added') : ''}${event.top ? I18n.t('mgmt_pinned') : ''}`;
          info.append(date, title);
          const actions = document.createElement('div');
          actions.className = 'timeline-event-actions';
          actions.innerHTML =
            `<button class="timeline-event-btn edit" title="${I18n.t('act_edit')}" data-id="${escapeHtml(event.id)}" aria-label="${I18n.t('act_edit')}">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></button>` +
            `<button class="timeline-event-btn pin${event.top ? ' active' : ''}" title="${event.top ? I18n.t('act_unpin') : I18n.t('act_pin')}" data-id="${escapeHtml(event.id)}" aria-label="${event.top ? I18n.t('act_unpin') : I18n.t('act_pin')}">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 17v5"></path><path d="M9 17h6"></path><path d="M20 7a2 2 0 0 0-2-2V5a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v2a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"></path></svg></button>` +
            `<button class="timeline-event-btn delete" title="${I18n.t('act_del')}" data-id="${escapeHtml(event.id)}" aria-label="${I18n.t('act_del')}">` +
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>`;
          row.append(info, actions);
          frag.appendChild(row);
        });
        box.appendChild(frag);
        // 类型输入框的联想：补上已存在的自定义类型
        const dl = document.getElementById('category-suggestions');
        if (dl) {
          const existing = new Set();
          dl.querySelectorAll('option').forEach((o) => existing.add(o.value));
          merged.forEach((event) => {
            if (event.category && !existing.has(event.category)) {
              const o = document.createElement('option');
              o.value = event.category;
              dl.appendChild(o);
              existing.add(event.category);
            }
          });
        }
      } catch (err) {
        console.error('加载时间线列表失败:', err);
        box.innerHTML = `<div style="padding:20px;text-align:center;color:#e74c3c;">${I18n.t('list_fail')}${escapeHtml(err.message)}<br><small style="color:#999;">${I18n.t('list_fail_hint')}</small></div>`;
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
        owner: String(v.owner || 'ccbear3120').trim(),
        repo: String(v.repo || 'WenMian').trim(),
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
        const err = new Error(body.message || I18n.t('gh_api_err', { s: res.status }));
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
        GitHub.status(I18n.t('gh_need_cfg'), 'error');
        return;
      }
      // file:// 下 fetch 读到的只是内嵌兜底数据（仅 1 条），此时同步会覆盖远端真数据，必须拦截
      if (location.protocol === 'file:') {
        GitHub.status(I18n.t('gh_file_block'), 'error');
        return;
      }
      const btn = document.getElementById('sync-github-btn');
      if (btn) btn.disabled = true;
      try {
        GitHub.status(I18n.t('gh_reading'));
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
            const ok = confirm(I18n.t('gh_remote_bad'));
            if (!ok) {
              GitHub.status(I18n.t('gh_cancelled'), '');
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
          const ok = confirm(I18n.t('gh_drop_confirm', {
            r: remoteTimeline.length, m: merged.length, k: remoteOnly.length, d: dropped.length,
          }));
          if (!ok) {
            GitHub.status(I18n.t('gh_cancelled'), '');
            return;
          }
        } else if (remoteOnly.length > 0) {
          GitHub.status(I18n.t('gh_merged_note', { n: remoteOnly.length }), '');
        }
        // 先备份远端原文，再提交
        if (sha && remoteRaw) {
          const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
          GitHub.downloadBackup(`timeline-backup-${ts}.json`, remoteRaw);
        }
        GitHub.status(I18n.t('gh_pushing'));
        const payload = { config: ConfigStore.forExport(localData.config), timeline: merged };
        const content = `${JSON.stringify(payload, null, 2)}\n`;
        await GitHub.api(`/repos/${cfg.owner}/${cfg.repo}/contents/${path}`, cfg.token, {
          method: 'PUT',
          body: JSON.stringify({
            message: `更新时间线（页面同步 ${new Date().toLocaleString(I18n.locale())})`,
            content: GitHub.utf8ToBase64(content),
            branch: cfg.branch,
            ...(sha ? { sha } : {}),
          }),
        });
        // 用已提交的内容刷新本地缓存与页面，再清空本地草稿
        Data.cache = payload;
        Store.saveLocalTimeline({ added: [], deleted: [], modified: {} });
        ConfigStore.clearPending();
        GitHub.status(I18n.t('gh_ok', { l: localMerged.length, k: remoteOnly.length, m: merged.length }), 'success');
        Timeline.load();
        Password.refreshStatus();
      } catch (e) {
        console.error('GitHub 同步失败:', e);
        const hint = e.status === 401 ? I18n.t('gh_h401')
          : e.status === 404 ? I18n.t('gh_h404')
          : e.status === 409 ? I18n.t('gh_h409') : '';
        GitHub.status(I18n.t('gh_fail', { e: e.message, h: hint }), 'error');
      } finally {
        if (btn) btn.disabled = false;
      }
    },
    extOf(name) {
      const m = /\.([a-z0-9]+)$/i.exec(String(name || ''));
      return m ? `.${m[1].toLowerCase()}` : '.jpg';
    },
    async compressImage(file) {
      // GIF 保持原图（避免动画丢失）
      if (file.type === 'image/gif') {
        return { buffer: await file.arrayBuffer(), ext: '.gif' };
      }
      const bitmap = await createImageBitmap(file).catch(() => null);
      if (!bitmap) return { buffer: await file.arrayBuffer(), ext: GitHub.extOf(file.name) };
      const done = (buffer, ext) => {
        if (typeof bitmap.close === 'function') bitmap.close();
        return { buffer, ext };
      };
      // 已经够小的 JPEG/WebP 直接原图上传，不做二次压缩（保清晰、省时间）
      if ((file.type === 'image/jpeg' || file.type === 'image/webp')
          && bitmap.width <= 1600 && bitmap.height <= 1600 && file.size <= 800 * 1024) {
        const ext = file.type === 'image/webp' ? '.webp' : '.jpg';
        return done(await file.arrayBuffer(), ext);
      }
      const MAX = 1600;
      const scale = Math.min(1, MAX / Math.max(bitmap.width, bitmap.height));
      const w = Math.max(1, Math.round(bitmap.width * scale));
      const h = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
      const encode = (type, q) => new Promise((res) => canvas.toBlob(res, type, q));
      // 优先 WebP：同等清晰度体积比 JPEG 小约三成；不支持的浏览器回退 JPEG
      let blob = await encode('image/webp', 0.8);
      let ext = '.webp';
      if (!blob) {
        blob = await encode('image/jpeg', 0.82);
        ext = '.jpg';
      }
      if (!blob) return done(await file.arrayBuffer(), GitHub.extOf(file.name));
      // PNG 原图（如简单图形）若比压完还小，就保留原图
      if (file.type === 'image/png' && file.size < blob.size) {
        return done(await file.arrayBuffer(), '.png');
      }
      return done(await blob.arrayBuffer(), ext);
    },
    async uploadOne(file, cfg) {
      const { buffer, ext } = await GitHub.compressImage(file);
      if (buffer.byteLength > 8 * 1024 * 1024) {
        throw new Error(I18n.t('up_toobig_after', { n: file.name }));
      }
      const folder = uploadFolderName();
      const cleanBase = (file.name || 'image').replace(/\.[^.]+$/, '').replace(/[^\w\-]+/g, '_') || 'image';
      const path = `images/${folder}/${Date.now()}_${cleanBase}${ext}`;
      await GitHub.api(`/repos/${cfg.owner}/${cfg.repo}/contents/${path}`, cfg.token, {
        method: 'PUT',
        body: JSON.stringify({
          message: `上传图片 ${path}`,
          content: GitHub.bufferToBase64(buffer),
          branch: cfg.branch,
        }),
      });
      return { path, kb: (buffer.byteLength / 1024).toFixed(0) };
    },
    async uploadImages(fileList) {
      const cfg = GitHub.getConfig();
      const statusEl = document.getElementById('event-image-upload-status');
      const say = (t) => { if (statusEl) statusEl.textContent = t; };
      const files = Array.from(fileList || []).filter((f) => f.type.startsWith('image/'));
      if (!cfg.owner || !cfg.repo || !cfg.token) {
        say(I18n.t('up_need_cfg'));
        return;
      }
      if (!files.length) {
        say(I18n.t('up_pick'));
        return;
      }
      if (files.length > 9) {
        say(I18n.t('up_max9'));
        return;
      }
      if (files.some((f) => f.size > 10 * 1024 * 1024)) {
        say(I18n.t('up_toobig'));
        return;
      }
      try {
        const paths = [];
        for (let i = 0; i < files.length; i++) {
          say(I18n.t('up_progress', { i: i + 1, t: files.length, n: files[i].name }));
          const { path } = await GitHub.uploadOne(files[i], cfg);
          paths.push(path);
        }
        const input = document.getElementById('event-image');
        if (input) {
          const cur = parseImageList(input.value);
          input.value = [...cur, ...paths].join('\n');
        }
        say(I18n.t('up_done', { n: paths.length }));
      } catch (e) {
        console.error('图片上传失败:', e);
        say(I18n.t('up_fail', { e: e.message }));
      }
    },
    async uploadImage(file) {
      // 兼容旧调用：单文件走批量通道
      return GitHub.uploadImages(file ? [file] : []);
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
      if (cfg.token) token.placeholder = I18n.t('token_saved_ph');
      owner.addEventListener('change', () => GitHub.saveConfig({ owner: owner.value.trim() }));
      repo.addEventListener('change', () => GitHub.saveConfig({ repo: repo.value.trim() }));
      branch.addEventListener('change', () => GitHub.saveConfig({ branch: branch.value.trim() || 'main' }));
      token.addEventListener('change', () => {
        if (token.value.trim()) {
          GitHub.saveConfig({ token: token.value.trim() });
          token.value = '';
          token.placeholder = I18n.t('token_saved_ph');
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
        if (pending && pending.passwordHash) el.textContent = I18n.t('pwd_pending');
        else if (c.passwordHash) el.textContent = I18n.t('pwd_hashed');
        else el.textContent = I18n.t('pwd_plain');
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
        Password.status(I18n.t('pwd_need6'), 'error');
        return;
      }
      if (!SHA256_OK) {
        Password.status(I18n.t('pwd_sha_fail'), 'error');
        return;
      }
      const salt = Password.randomSalt();
      ConfigStore.savePending({ passwordSalt: salt, passwordHash: sha256Hex(salt + v) });
      input.value = '';
      Password.status(I18n.t('pwd_set_ok'), 'success');
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

      // 事件表单内的图片直传（支持多选）
      $('#event-image-file')?.addEventListener('change', (e) => {
        const files = e.target.files;
        if (files && files.length) GitHub.uploadImages(files);
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

  // ---------- 11.5 Music（背景音乐） ----------
  const Music = {
    FILE: 'music/background_music.mp3',
    audio: null,
    btn: null,
    init() {
      Music.btn = document.getElementById('music-button');
      if (!Music.btn) return;
      Music.audio = new Audio(Music.FILE);
      Music.audio.loop = true;
      Music.audio.preload = 'auto';
      Music.audio.volume = 0.6;
      Music.paint(Music.isOn());
      Music.btn.addEventListener('click', Music.toggle);
      Music.btn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          Music.toggle();
        }
      });
      // 自动播放被拦截时，等用户第一次交互再补播
      const resume = () => {
        if (Music.isOn() && Music.audio.paused) Music.tryStart();
      };
      document.addEventListener('pointerdown', resume, { once: true });
      Music.audio.addEventListener('error', () => {
        console.warn('背景音乐加载失败:', Music.FILE);
      });
    },
    isOn() {
      return Store.getSettings().musicOn !== false; // 默认开
    },
    paint(on) {
      if (!Music.btn) return;
      Music.btn.classList.toggle('muted', !on);
      Music.btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      Music.btn.setAttribute('aria-label', on ? I18n.t('music_on') : I18n.t('music_off'));
    },
    async toggle() {
      if (!Music.audio) return;
      const on = Music.audio.paused;
      if (on) {
        try {
          await Music.audio.play();
        } catch (e) {
          console.warn('音乐播放被拦截:', e);
          return;
        }
      } else {
        Music.audio.pause();
      }
      Store.saveSettings({ musicOn: on });
      Music.paint(on);
    },
    tryStart() {
      // 登录成功（用户手势链路上）尝试播放；被拦截则等 pointerdown 补播
      if (Music.audio && Music.isOn() && Music.audio.paused) {
        Music.audio.play().catch(() => {});
      }
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
    I18n.init();
    Filter.init();
    Settings.init();
    BackToTop.init();
    Music.init();
    Management.init();

    try {
      const data = await Data.get();
      if (!data.config || (data.config.passwordHash == null && data.config.password == null)) {
        const screen = $('#password-screen');
        if (screen) screen.innerHTML = `<p style="color: red;">${I18n.t('cfg_nopw')}</p>`;
        return;
      }
      Auth.init(data.config, () => {
        Timeline.load(); // 验证通过后才开始渲染
        Lazy.observeNew();
        Music.tryStart();
      });
    } catch (e) {
      console.error('获取配置时出错:', e);
      const screen = $('#password-screen');
      if (screen) screen.innerHTML = `<p style="color: red;">${I18n.t('cfg_fail')}</p>`;
    }
    window.addEventListener('load', Lazy.observeNew);
  });

  // 兼容旧 HTML 内联可能调用的全局（保留最小面）
  window.updateTimelineEventsList = () => Management.refresh();
})();
