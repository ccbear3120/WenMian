@echo off
REM Register one-line filter on Windows. Run once after cloning.
REM Worktree stays multi-line; clean stores 1-line, smudge expands back.
REM If `python3` is not found, use `py` or `python` instead.
git config filter.oneline.clean "python3 tools/one-line.py clean %%f"
git config filter.oneline.smudge "python3 tools/one-line.py smudge %%f"
git config filter.oneline.required "false"
git config --get filter.oneline.clean
git config --get filter.oneline.smudge
