#!/bin/sh
# 注册 one-line clean filter：本地文件保持多行可读，
# `git add` / `git push` 存进仓库的是 1 行版本。
# 新克隆仓库后运行一次：  sh tools/setup-filter.sh
set -e
git config filter.oneline.clean 'python3 tools/one-line.py clean %f'
git config filter.oneline.smudge 'cat'
git config filter.oneline.required 'false'
echo "filter.oneline registered:"
git config --get filter.oneline.clean
