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
trap 'rm -rf "$stage"' EXIT HUP INT TERM

commit=$(git -C "$root" rev-parse HEAD)
tree=$(git -C "$root" rev-parse HEAD^{tree})
version=$(git -C "$root" describe --always --dirty)
created=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

docker buildx build \
    --platform linux/arm64 \
    --target binary \
    --output "type=local,dest=$stage" \
    --build-arg "COMMIT=$commit" \
    --build-arg "CREATED=$created" \
    --build-arg "VERSION=$version" \
    "$root"

artifact="$output/xusdc-bridge-linux-arm64"
install -m 0755 "$stage/xusdc-bridge" "$artifact"
file "$artifact" | grep -q 'ARM aarch64'
hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
cat > "$output/xusdc-bridge-linux-arm64.manifest" <<EOF
source_commit=$commit
source_tree=$tree
sha256=$hash
platform=linux/arm64
EOF

printf '%s  %s\n' "$hash" "$(basename "$artifact")"
