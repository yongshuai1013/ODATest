#!/usr/bin/env bash
# 構建 ApparitionAnisette Rust 靜態庫（aarch64-apple-ios，部署目標 15.0）
# 佈局比照 Apparition 上游 scripts/build-core.sh：
#   build/anisette-out/include/apparition_anisette.h
#   build/anisette-out/lib/iphoneos/libapparition_anisette.a
# project.yml 以 $(PLATFORM_NAME) 挑 lib 目錄、以 include 目錄找標頭。
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
export IPHONEOS_DEPLOYMENT_TARGET=15.0

cd "$root/ApparitionAnisette"
cargo build --release --target aarch64-apple-ios

out="$root/build/anisette-out"
mkdir -p "$out/include" "$out/lib/iphoneos"
cp include/apparition_anisette.h "$out/include/"
cp target/aarch64-apple-ios/release/libapparition_anisette.a "$out/lib/iphoneos/"
echo "staged -> $out"
