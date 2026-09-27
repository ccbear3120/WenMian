@echo off
REM Register one-line clean filter on Windows. Run once after cloning.
REM If `python3` is not found, use `py` or `python` instead.
git config filter.oneline.clean "python3 tools/one-line.py clean %%f"
git config filter.oneline.smudge "cat"
git config filter.oneline.required "false"
git config --get filter.oneline.clean
