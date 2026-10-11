# Shared helpers for the warm, idle and steady-state benchmarks. Sourced, not
# run. Every runtime gets the same Alpine tree and kiln's default limits.

KILN=${KILN:-/usr/local/bin/kiln}
BENCH=/var/lib/kiln-bench
LIMITS="--memory 512m --cpus 1 --pids-limit 128"

if pgrep -f review-regressions >/dev/null; then
    echo "review-regressions.sh is running; measure later" >&2
    exit 1
fi

# start_idle RUNTIME [NAME] prints an ID for an idle sandbox: a persistent
# kiln sandbox (only kiln-init inside), or a container running `sleep
# infinity`. RUNTIME is kiln, kiln-net, docker, docker-net, runc or crun.
start_idle() {
    case $1 in
    kiln) "$KILN" create ;;
    kiln-net) "$KILN" create --net full ;;
    docker) docker run -d --network none $LIMITS kiln-alpine sleep infinity ;;
    docker-net) docker run -d $LIMITS kiln-alpine sleep infinity ;;
    runc | crun)
        "$1" run -d --bundle "$BENCH/idle" "$2" </dev/null >/dev/null 2>&1
        echo "$2"
        ;;
    esac
}

# stop_idle RUNTIME ID
stop_idle() {
    case $1 in
    kiln*) "$KILN" rm "$2" ;;
    docker*) docker rm -f "$2" >/dev/null ;;
    runc | crun) "$1" delete -f "$2" ;;
    esac
}

# exec_cmd RUNTIME ID prints the command that runs `true` in the sandbox.
exec_cmd() {
    case $1 in
    kiln*) echo "$KILN exec $2 -- true" ;;
    docker*) echo "docker exec $2 true" ;;
    runc | crun) echo "$1 exec $2 true" ;;
    esac
}
