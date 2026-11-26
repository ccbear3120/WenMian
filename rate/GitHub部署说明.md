# 白俄汇率速查 · GitHub Pages 部署说明

部署后是一个纯静态网页，**不需要运行 Python、不需要服务器**。汇率数据由 GitHub Actions 每天自动更新。

## 一、需要的文件

把仓库里的这些文件/目录提交到 GitHub（本项目采用 `rate/` 子目录，不影响根目录现有站点）：

```
rate/index.html                     ← 网页（主文件）
rate/rates.json                     ← 汇率数据（Actions 会自动更新）
.github/workflows/update-rates.yml  ← 定时更新配置
.github/scripts/update_rates.py     ← 抓取脚本
```

> 因为放在 `rate/` 子目录，访问地址为 `https://你的用户名.github.io/仓库名/rate/`。
> 根目录的 `index.html`（现有站点）不受影响。

## 二、部署步骤

1. **使用现有仓库**：本页已放在当前仓库的 `rate/` 子目录，直接提交并推送到 GitHub 即可（`.github` 是隐藏目录，注意一起提交）。

2. **开启 Pages**（若尚未开启）：仓库 → `Settings` → 左侧 `Pages` → Build and deployment：
   - Source 选 `Deploy from a branch`
   - Branch 选 `main`，目录选 `/ (root)` → Save

3. **等待部署**：几十秒后，访问地址形如：
   ```
   https://你的用户名.github.io/仓库名/rate/
   ```
   例如本仓库为 `https://ccbear3120.github.io/WenMian/rate/`

5. **（重要）允许 Actions 写入仓库**：仓库 → `Settings` → 左侧 `Actions` → General → 拉到底 `Workflow permissions` → 选 **Read and write permissions** → Save。
   （否则定时任务无法提交更新后的 rates.json）

## 三、数据更新机制

- `.github/workflows/update-rates.yml` 配置了**每小时第 25 分钟**（明斯克时间）抓一次汇率，重新生成 `rates.json` 并自动提交。避开整点是为了减少 GitHub Actions 高负载导致任务被丢弃的概率。
- 也可以随时手动触发：仓库 `Actions` 页面 → 选「每日更新汇率」→ `Run workflow`。
- 银联周末/节假日没有当日数据，脚本会自动回退到最近有数据的工作日。

## 四、数据说明

- 银联：CNY/BYN，报价来自银联国际，四舍五入保留三位。
- Myfin：USD/BYN，报价来自 myfin.uk，保留三位。
- 页面上的两个按钮在静态部署下读取的是**每日快照**（不是点击瞬间的实时值）。
- 每次点击按钮仍会把数据记入本机历史，用于绘制趋势图；数据只存在你自己的浏览器里。

## 五、本地开发（可选）

如果想在本地用实时接口（点击即查最新值），保留 `server.py`：

```bash
python3 server.py        # 然后打开 http://127.0.0.1:8000
```

页面会自动探测：有 `/api/rate` 就走实时接口，没有就走静态 `rates.json`，无需改代码。
