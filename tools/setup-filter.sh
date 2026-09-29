#!/bin/sh
# 注册 one-line filter：工作区文件保持多行可读，
# `git add` / `git push` 存进仓库的是 1 行版本（压缩+剥离注释），
# `git checkout` / `git pull` 会把 1 行版展开回多行。
# 新克隆仓库后运行一次：  sh tools/setup-filter.sh
set -e
git config filter.oneline.clean 'python3 tools/one-line.py clean %f'
git config filter.oneline.smudge 'python3 tools/one-line.py smudge %f'
git config filter.oneline.required 'false'
echo "filter.oneline registered:"
git config --get filter.oneline.clean
git config --get filter.oneline.smudge
