#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
SAMPLE_DIR="$ROOT_DIR/samples/bench"
KEY_DIR="$ROOT_DIR/keys/bench"
SIG_DIR="$ROOT_DIR/sigs/bench"
RESULT_DIR="$ROOT_DIR/results"

TOOL="$BUILD_DIR/sigtool.exe"

if [ ! -f "$TOOL" ]; then
    TOOL="$BUILD_DIR/sigtool"
fi

if [ ! -f "$TOOL" ]; then
    echo "[ERROR] sigtool not found. Please build Lab 5 first."
    exit 1
fi

PROFILE="${1:-quick}"

if [ "$PROFILE" = "quick" ]; then
    RUNS_KEYGEN=3
    RUNS_SIGN=5
elif [ "$PROFILE" = "full" ]; then
    RUNS_KEYGEN=10
    RUNS_SIGN=30
else
    echo "[ERROR] Unknown profile: $PROFILE"
    echo "Usage: ./scripts/benchmark_lab5.sh quick|full"
    exit 1
fi

mkdir -p "$SAMPLE_DIR" "$KEY_DIR" "$SIG_DIR" "$RESULT_DIR"

RESULT_FILE="$RESULT_DIR/lab5_signature_benchmark_${PROFILE}.csv"

echo "category,algorithm,size_label,bytes,operation,runs,mean_ms,throughput_mib_s,signature_size_bytes" > "$RESULT_FILE"

measure_once_ms() {
    local start
    local end
    local elapsed_ns
    local elapsed_ms

    start=$(date +%s%N)
    "$@" > /dev/null 2>&1
    end=$(date +%s%N)

    elapsed_ns=$((end - start))
    elapsed_ms=$(awk -v ns="$elapsed_ns" 'BEGIN { printf "%.3f", ns / 1000000.0 }')
    echo "$elapsed_ms"
}

mean_ms() {
    awk '{ sum += $1; n += 1 } END { if (n > 0) printf "%.3f", sum / n; else print "0.000" }'
}

throughput_mib_s() {
    local bytes="$1"
    local ms="$2"

    awk -v b="$bytes" -v t="$ms" 'BEGIN {
        if (t <= 0) {
            printf "0.00"
        } else {
            printf "%.2f", (b / 1048576.0) / (t / 1000.0)
        }
    }'
}

make_random_file() {
    local path="$1"
    local bs="$2"
    local count="$3"

    if [ ! -f "$path" ]; then
        echo "[INFO] Generating $path"
        dd if=/dev/urandom of="$path" bs="$bs" count="$count" status=none
    fi
}

bench_keygen() {
    local algo="$1"
    local runs="$2"

    local pub="$KEY_DIR/keygen_${algo}_pub.pem"
    local priv="$KEY_DIR/keygen_${algo}_priv.pem"
    local tmp="$SAMPLE_DIR/tmp_keygen_${algo}.txt"

    : > "$tmp"

    echo "[INFO] Benchmark keygen $algo"

    for i in $(seq 1 "$runs"); do
        rm -f "$pub" "$priv"

        measure_once_ms "$TOOL" keygen \
            --algo "$algo" \
            --pub "$pub" \
            --priv "$priv" >> "$tmp"
    done

    local avg
    avg=$(mean_ms < "$tmp")

    echo "keygen,$algo,none,0,keygen,$runs,$avg,0.00,0" >> "$RESULT_FILE"
    echo "[OK] $algo keygen mean=${avg} ms"
}

ensure_keypair() {
    local algo="$1"
    local pub="$2"
    local priv="$3"

    if [ ! -f "$pub" ] || [ ! -f "$priv" ]; then
        "$TOOL" keygen \
            --algo "$algo" \
            --pub "$pub" \
            --priv "$priv" > /dev/null
    fi
}

bench_sign_verify() {
    local algo="$1"
    local label="$2"
    local bytes="$3"
    local msg="$4"
    local pub="$5"
    local priv="$6"
    local runs="$7"

    local sig="$SIG_DIR/${algo}_${label}.sig"
    local sign_times="$SAMPLE_DIR/tmp_sign_${algo}_${label}.txt"
    local verify_times="$SAMPLE_DIR/tmp_verify_${algo}_${label}.txt"

    : > "$sign_times"
    : > "$verify_times"

    echo "[INFO] Benchmark $algo sign/verify $label"

    for i in $(seq 1 "$runs"); do
        rm -f "$sig"

        measure_once_ms "$TOOL" sign \
            --algo "$algo" \
            --in "$msg" \
            --priv "$priv" \
            --out "$sig" \
            --hash sha256 \
            --encode raw >> "$sign_times"

        measure_once_ms "$TOOL" verify \
            --algo "$algo" \
            --in "$msg" \
            --sig "$sig" \
            --pub "$pub" \
            --hash sha256 \
            --encode raw >> "$verify_times"
    done

    local sign_avg
    local verify_avg
    local sign_speed
    local verify_speed
    local sig_size

    sign_avg=$(mean_ms < "$sign_times")
    verify_avg=$(mean_ms < "$verify_times")

    sign_speed=$(throughput_mib_s "$bytes" "$sign_avg")
    verify_speed=$(throughput_mib_s "$bytes" "$verify_avg")

    sig_size=$(wc -c < "$sig" | tr -d ' ')

    echo "signverify,$algo,$label,$bytes,sign,$runs,$sign_avg,$sign_speed,$sig_size" >> "$RESULT_FILE"
    echo "signverify,$algo,$label,$bytes,verify,$runs,$verify_avg,$verify_speed,$sig_size" >> "$RESULT_FILE"

    echo "[OK] $algo $label sign mean=${sign_avg} ms speed=${sign_speed} MiB/s sig=${sig_size} bytes"
    echo "[OK] $algo $label verify mean=${verify_avg} ms speed=${verify_speed} MiB/s sig=${sig_size} bytes"
}

echo ">> LAB 5 SIGNATURE BENCHMARK"
echo "Profile     : $PROFILE"
echo "Tool        : $TOOL"
echo "Result file : $RESULT_FILE"
echo

make_random_file "$SAMPLE_DIR/msg_1k.bin" 1K 1
make_random_file "$SAMPLE_DIR/msg_1m.bin" 1M 1
make_random_file "$SAMPLE_DIR/msg_8m.bin" 1M 8

ECDSA_PUB="$KEY_DIR/ecdsa_pub.pem"
ECDSA_PRIV="$KEY_DIR/ecdsa_priv.pem"
RSA_PUB="$KEY_DIR/rsa_pub.pem"
RSA_PRIV="$KEY_DIR/rsa_priv.pem"

ensure_keypair "ecdsa-p256" "$ECDSA_PUB" "$ECDSA_PRIV"
ensure_keypair "rsa-pss-3072" "$RSA_PUB" "$RSA_PRIV"

bench_keygen "ecdsa-p256" "$RUNS_KEYGEN"
bench_keygen "rsa-pss-3072" "$RUNS_KEYGEN"

echo

bench_sign_verify "ecdsa-p256" "1KiB" 1024 "$SAMPLE_DIR/msg_1k.bin" "$ECDSA_PUB" "$ECDSA_PRIV" "$RUNS_SIGN"
bench_sign_verify "rsa-pss-3072" "1KiB" 1024 "$SAMPLE_DIR/msg_1k.bin" "$RSA_PUB" "$RSA_PRIV" "$RUNS_SIGN"

echo

bench_sign_verify "ecdsa-p256" "1MiB" 1048576 "$SAMPLE_DIR/msg_1m.bin" "$ECDSA_PUB" "$ECDSA_PRIV" "$RUNS_SIGN"
bench_sign_verify "rsa-pss-3072" "1MiB" 1048576 "$SAMPLE_DIR/msg_1m.bin" "$RSA_PUB" "$RSA_PRIV" "$RUNS_SIGN"

echo

bench_sign_verify "ecdsa-p256" "8MiB" 8388608 "$SAMPLE_DIR/msg_8m.bin" "$ECDSA_PUB" "$ECDSA_PRIV" "$RUNS_SIGN"
bench_sign_verify "rsa-pss-3072" "8MiB" 8388608 "$SAMPLE_DIR/msg_8m.bin" "$RSA_PUB" "$RSA_PRIV" "$RUNS_SIGN"

echo
echo ">> BENCHMARK DONE"
echo "CSV output: $RESULT_FILE"
