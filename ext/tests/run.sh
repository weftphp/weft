#!/bin/sh
# Runs every tests/php/*.php with the built extension and compares stdout with the matching
# .expect file. Usage: tests/run.sh [debug|release]   (build first with `cargo build`).
set -u
profile=${1:-debug}
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
case $(uname) in
    Darwin) lib=libweft_php.dylib ;;
    *) lib=libweft_php.so ;;
esac
so="$root/target/$profile/weft.so"
cp "$root/target/$profile/$lib" "$so" || exit 2

failed=0
for script in "$here"/php/*.php; do
    name=$(basename "$script" .php)
    actual=$(WEFT_EXT="$so" php -n -d "extension=$so" "$script" 2>&1)
    if [ "$actual" = "$(cat "${script%.php}.expect")" ]; then
        echo "ok   $name"
    else
        echo "FAIL $name"
        printf '%s\n' "$actual" | diff - "${script%.php}.expect" | head -20
        failed=1
    fi
done
exit $failed
