#!/bin/sh
# PostToolUse hook: clang-format the C++ file that was just edited, if clang-format is available.
file=$(sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
case "$file" in
  *.cpp|*.hpp|*.h|*.cc) command -v clang-format >/dev/null 2>&1 && clang-format -i "$file" ;;
esac
exit 0
