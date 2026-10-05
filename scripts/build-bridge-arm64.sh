#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$root/dist"}

if [ -n "$(git -C "$root" status --porcelain)" ]; then
    echo "refusing to build a release artifact from a dirty checkout" >&2
    exit 1
fi

docker info >/dev/null
mkdir -p "$output"
stage=$(mktemp -d "$output/.xusdc-arm64.XXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

commit=$(git -C "$root" rev-parse HEAD)
tree=$(git -C "$root" rev-parse HEAD^{tree})

docker buildx build \
    --file "$root/crates/xusdc-bridge/Dockerfile" \
    --platform linux/arm64 \
    --target binary \
    --output "type=local,dest=$stage" \
    "$root"

staged="$stage/xusdc-bridge"
description=$(file "$staged")
case "$description" in
    *'ELF 64-bit'*'ARM aarch64'*) ;;
    *) echo "expected a Linux ARM64 executable: $description" >&2; exit 1 ;;
esac
checksum=$(shasum -a 256 "$staged")
hash=${checksum%% *}
if ! printf '%s\n' "$hash" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    echo "invalid SHA-256 checksum" >&2
    exit 1
fi
chmod 0755 "$staged"
cat > "$stage/xusdc-bridge-linux-arm64.manifest" <<EOF
source_commit=$commit
source_tree=$tree
sha256=$hash
platform=linux/arm64
EOF

mv -f "$staged" "$output/xusdc-bridge-linux-arm64"
mv -f "$stage/xusdc-bridge-linux-arm64.manifest" "$output/xusdc-bridge-linux-arm64.manifest"
printf '%s  xusdc-bridge-linux-arm64\n' "$hash"
