#!/usr/bin/env sh
# shellcheck shell=dash

#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

# Stalwart install script -- based on the rustup installation script.

set -e
set -u

readonly BASE_URL="https://github.com/stalwartlabs/stalwart/releases/latest/download"

main() {
    downloader --check
    need_cmd uname
    need_cmd mktemp
    need_cmd chmod
    need_cmd chown
    need_cmd mkdir
    need_cmd rm
    need_cmd tar
    need_cmd cp
    need_cmd hostname

    # Require root
    if [ "$(id -u)" -ne 0 ]; then
        err "❌ Install failed: This program needs to run as root."
    fi

    # Detect OS
    local _os _uname _account
    _uname="$(uname)"
    case "$_uname" in
        Linux)   _os="linux"; _account="stalwart" ;;
        Darwin)  _os="macos"; _account="_stalwart" ;;
        FreeBSD) _os="freebsd"; _account="stalwart" ;;
        *)       err "❌ Install failed: Unsupported OS: $_uname" ;;
    esac

    # Parse arguments
    local _component="stalwart"
    local _prefix=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --fdb)
                _component="stalwart-foundationdb"
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            --*|-*)
                err "❌ Unknown flag: $1 (try --help)"
                ;;
            *)
                if [ -n "$_prefix" ]; then
                    err "❌ Only one prefix argument is allowed, got: $_prefix $1"
                fi
                _prefix="$1"
                ;;
        esac
        shift
    done

    # Derive install paths — FHS by default, self-contained under a custom prefix
    local _bin_dir _bin_file _conf_dir _log_dir _data_dir _env_file _config_file
    if [ -z "$_prefix" ]; then
        _bin_dir="/usr/local/bin"
        _log_dir="/var/log/stalwart"
        if [ "$_os" = "freebsd" ]; then
            # hier(7): third-party config lives under /usr/local/etc,
            # variable data under /var/db
            _conf_dir="/usr/local/etc/stalwart"
            _data_dir="/var/db/stalwart"
        else
            _conf_dir="/etc/stalwart"
            _data_dir="/var/lib/stalwart"
        fi
    else
        _bin_dir="${_prefix}/bin"
        _conf_dir="${_prefix}/etc"
        _log_dir="${_prefix}/logs"
        _data_dir="${_prefix}/data"
    fi
    _bin_file="${_bin_dir}/stalwart"
    _config_file="${_conf_dir}/config.json"
    _env_file="${_conf_dir}/stalwart.env"

    # Detect architecture
    get_architecture || return 1
    local _arch="$RETVAL"
    assert_nz "$_arch" "arch"

    # Create service account
    create_account "$_os" "$_account"

    # Create directories
    ensure mkdir -p "$_bin_dir" "$_conf_dir" "$_log_dir" "$_data_dir"

    # Download and install the binary
    say "⏳ Downloading ${_component} for ${_arch}..."
    local _tmp _tar _src_name
    _tmp="$(mktemp -d)"
    _tar="${_tmp}/stalwart.tar.gz"
    ensure downloader "${BASE_URL}/${_component}-${_arch}.tar.gz" "$_tar" "$_arch"
    ensure tar zxf "$_tar" -C "$_tmp"
    _src_name="stalwart"
    if [ "$_component" = "stalwart-foundationdb" ]; then
        _src_name="stalwart-foundationdb"
    fi
    ensure cp "${_tmp}/${_src_name}" "$_bin_file"
    ensure chmod 0755 "$_bin_file"
    ensure rm -rf "$_tmp"

    # Create env file if absent (preserve user edits on reinstall)
    if [ ! -e "$_env_file" ]; then
        say "📝 Writing env file at ${_env_file}..."
        write_env_file "$_env_file"
    fi

    # Ownership and permissions
    say "🔐 Setting permissions..."
    ensure chown "${_account}:${_account}" "$_conf_dir" "$_log_dir" "$_data_dir"
    ensure chmod 0750 "$_conf_dir" "$_log_dir" "$_data_dir"
    ensure chown "root:${_account}" "$_env_file"
    ensure chmod 0640 "$_env_file"

    # Install and start the service
    say "🚀 Starting service..."
    local _service_type=""
    case "$_os" in
        linux)
            if check_cmd systemctl; then
                create_service_linux_systemd "$_bin_file" "$_config_file" "$_env_file" "$_account"
                _service_type="systemd"
            else
                create_service_linux_initd "$_bin_file" "$_config_file" "$_env_file" "$_account"
                _service_type="initd"
            fi
            ;;
        macos)
            create_service_macos "$_bin_file" "$_config_file" "$_env_file" "$_account"
            _service_type="launchd"
            ;;
        freebsd)
            create_service_freebsd "$_bin_file" "$_config_file" "$_env_file" "$_account" "$_log_dir"
            _service_type="rcd"
            ;;
    esac

    # Completion message
    local _host
    _host="$(hostname -f 2>/dev/null || hostname)"
    say ""
    say "🎉 Installation complete!"
    say ""
    say "Stalwart is running in bootstrap mode. A temporary administrator"
    say "password was generated at startup and printed to the service logs."
    say ""
    say "👉 To find the password, inspect the service logs:"
    case "$_service_type" in
        systemd)
            say "     journalctl -u stalwart -n 200 | grep -A8 'bootstrap mode'"
            ;;
        initd)
            say "     grep -A8 'bootstrap mode' /var/log/syslog 2>/dev/null \\"
            say "       || grep -A8 'bootstrap mode' /var/log/messages"
            ;;
        launchd)
            say "     sudo log show --predicate 'process == \"stalwart\"' --last 5m"
            ;;
        rcd)
            say "     grep -A8 'bootstrap mode' ${_log_dir}/stalwart.log"
            ;;
    esac
    say ""
    say "   Or set STALWART_RECOVERY_ADMIN=admin:<password> in"
    say "   ${_env_file} and restart the service to pin a credential."
    say ""
    say "   Finish setup at: http://${_host}:8080/admin"
    say ""

    return 0
}

print_usage() {
    cat <<'EOF'
Usage: install.sh [--fdb] [PREFIX]

Install Stalwart into standard FHS paths or under a custom prefix.

Options:
  --fdb       Install the FoundationDB build.
  -h, --help  Show this help.

With no PREFIX, Stalwart is installed under standard FHS paths:
  binary   /usr/local/bin/stalwart
  config   /etc/stalwart/config.json      (/usr/local/etc/stalwart/config.json on FreeBSD)
  env      /etc/stalwart/stalwart.env     (/usr/local/etc/stalwart/stalwart.env on FreeBSD)
  logs     /var/log/stalwart/
  data     /var/lib/stalwart/             (/var/db/stalwart on FreeBSD)

When PREFIX is provided, a self-contained layout is used instead:
  binary   $PREFIX/bin/stalwart
  config   $PREFIX/etc/config.json
  env      $PREFIX/etc/stalwart.env
  logs     $PREFIX/logs/
  data     $PREFIX/data/
EOF
}

write_env_file() {
    cat > "$1" <<'EOF'
# Environment variables for the Stalwart service.
# Uncomment and edit an entry to override its default.

# Override the hostname used in HTTP responses
#STALWART_HOSTNAME=mail.example.com

# Override the public base URL published in OAuth, OIDC, and JMAP discovery
# documents. Accepts scheme, host, optional port, and optional path prefix.
#STALWART_PUBLIC_URL=https://mail.example.com

# Enable bootstrap / recovery mode on startup. Accepted: 1, true. Default: false.
#STALWART_RECOVERY_MODE=true

# Log level while in recovery mode. Default: info.
#STALWART_RECOVERY_MODE_LOG_LEVEL=debug

# HTTP port used in recovery mode. Default: 8080.
#STALWART_RECOVERY_MODE_PORT=9090

# Fixed administrator credentials — format: username:password
# Default: a temporary random password is generated and printed to the logs.
#STALWART_RECOVERY_ADMIN=admin:changeme

# Cluster role assigned to this node. Must match a role name defined in the
# cluster registry. Leave unset for a standalone (non-clustered) deployment.
#STALWART_ROLE=primary

# Push-notification shard this node is responsible for, when running in a
# cluster.
#STALWART_PUSH_SHARD=1
EOF
}

create_account() {
    local _os="$1"
    local _account="$2"
    if id -u "$_account" > /dev/null 2>&1; then
        return 0
    fi
    say "🖥️  Creating '${_account}' account..."
    if [ "$_os" = "macos" ]; then
        local _last_uid _last_gid _uid _gid
        _last_uid="$(dscacheutil -q user | grep uid | awk '{print $2}' | sort -n | tail -n 1)"
        _last_gid="$(dscacheutil -q group | grep gid | awk '{print $2}' | sort -n | tail -n 1)"
        _uid="$((_last_uid+1))"
        _gid="$((_last_gid+1))"

        ensure dscl /Local/Default -create Groups/_stalwart
        ensure dscl /Local/Default -create Groups/_stalwart Password \*
        ensure dscl /Local/Default -create Groups/_stalwart PrimaryGroupID $_gid
        ensure dscl /Local/Default -create Groups/_stalwart RealName "Stalwart service"
        ensure dscl /Local/Default -create Groups/_stalwart RecordName _stalwart stalwart

        ensure dscl /Local/Default -create Users/_stalwart
        ensure dscl /Local/Default -create Users/_stalwart NFSHomeDirectory /var/empty
        ensure dscl /Local/Default -create Users/_stalwart Password \*
        ensure dscl /Local/Default -create Users/_stalwart PrimaryGroupID $_gid
        ensure dscl /Local/Default -create Users/_stalwart RealName "Stalwart service"
        ensure dscl /Local/Default -create Users/_stalwart RecordName _stalwart stalwart
        ensure dscl /Local/Default -create Users/_stalwart UniqueID $_uid
        ensure dscl /Local/Default -create Users/_stalwart UserShell /usr/bin/false

        ensure dscl /Local/Default -delete /Users/_stalwart AuthenticationAuthority
        ensure dscl /Local/Default -delete /Users/_stalwart PasswordPolicyOptions
    elif [ "$_os" = "freebsd" ]; then
        ensure pw useradd -n "$_account" -c "Stalwart service" -d /nonexistent -s /usr/sbin/nologin -w no
    else
        ensure useradd "$_account" -s /usr/sbin/nologin -M -r -U
    fi
}

create_service_linux_systemd() {
    local _bin="$1" _config="$2" _env="$3" _user="$4"
    cat > /etc/systemd/system/stalwart.service <<EOF
[Unit]
Description=Stalwart
Conflicts=postfix.service sendmail.service exim4.service
After=network-online.target

[Service]
Type=simple
LimitNOFILE=65536
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
EnvironmentFile=-${_env}
ExecStart=${_bin} --config=${_config}
SyslogIdentifier=stalwart
User=${_user}
Group=${_user}
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable stalwart.service
    systemctl restart stalwart.service
}

create_service_linux_initd() {
    local _bin="$1" _config="$2" _env="$3" _user="$4"
    cat > /etc/init.d/stalwart <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          stalwart
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Stalwart Server
# Description:       Starts and stops the Stalwart Server
# Conflicts:         postfix sendmail
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /lib/init/vars.sh
. /lib/lsb/init-functions

DAEMON=${_bin}
DAEMON_ARGS="--config=${_config}"
ENV_FILE=${_env}
PIDFILE=/var/run/stalwart.pid
ULIMIT_NOFILE=65536

[ -x "\$DAEMON" ] || exit 0

if [ -r "\$ENV_FILE" ]; then
    set -a
    . "\$ENV_FILE"
    set +a
fi

ulimit -n \$ULIMIT_NOFILE

do_start()
{
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON --test > /dev/null \\
        || return 1
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON \\
        --background --make-pidfile --chuid ${_user}:${_user} \\
        -- \$DAEMON_ARGS \\
        || return 2
}

do_stop()
{
    start-stop-daemon --stop --quiet --retry=INT/30/KILL/5 --pidfile \$PIDFILE --name stalwart
    RETVAL="\$?"
    [ "\$RETVAL" = 2 ] && return 2
    start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec \$DAEMON
    [ "\$?" = 2 ] && return 2
    rm -f \$PIDFILE
    return "\$RETVAL"
}

case "\$1" in
  start)
    [ "\$VERBOSE" != no ] && log_daemon_msg "Starting Stalwart Server" "stalwart"
    do_start
    case "\$?" in
        0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
        2)   [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
    esac
    ;;
  stop)
    [ "\$VERBOSE" != no ] && log_daemon_msg "Stopping Stalwart Server" "stalwart"
    do_stop
    case "\$?" in
        0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
        2)   [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
    esac
    ;;
  status)
    status_of_proc "\$DAEMON" "stalwart" && exit 0 || exit \$?
    ;;
  restart)
    log_daemon_msg "Restarting Stalwart Server" "stalwart"
    do_stop
    case "\$?" in
      0|1)
        do_start
        case "\$?" in
            0) log_end_msg 0 ;;
            *) log_end_msg 1 ;;
        esac
        ;;
      *)
        log_end_msg 1
        ;;
    esac
    ;;
  *)
    echo "Usage: /etc/init.d/stalwart {start|stop|status|restart}" >&2
    exit 3
    ;;
esac

exit 0
EOF
    chmod +x /etc/init.d/stalwart
    update-rc.d stalwart defaults
    service stalwart start
}

create_service_macos() {
    local _bin="$1" _config="$2" _env="$3" _user="$4"
    local _plist="/Library/LaunchDaemons/stalwart.mail.plist"

    # Remove any legacy LaunchDaemons from a prior install
    if [ -f "$_plist" ]; then
        launchctl bootout system/ "$_plist" 2>/dev/null || true
        rm -f "$_plist"
    fi

    # launchd has no EnvironmentFile equivalent — wrap with sh to source the env file
    cat > "$_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>stalwart</string>
        <key>ServiceDescription</key>
        <string>Stalwart</string>
        <key>UserName</key>
        <string>${_user}</string>
        <key>GroupName</key>
        <string>${_user}</string>
        <key>ProgramArguments</key>
        <array>
            <string>/bin/sh</string>
            <string>-c</string>
            <string>set -a; if [ -r "${_env}" ]; then . "${_env}"; fi; set +a; exec "${_bin}" --config="${_config}"</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
    </dict>
</plist>
EOF
    chmod 0644 "$_plist"
    chown root:wheel "$_plist"
    launchctl bootout system/ "$_plist" 2>/dev/null || true
    launchctl bootstrap system/ "$_plist"
}

create_service_freebsd() {
    local _bin="$1" _config="$2" _env="$3" _user="$4" _log_dir="$5"
    ensure mkdir -p /usr/local/etc/rc.d
    cat > /usr/local/etc/rc.d/stalwart <<EOF
#!/bin/sh

# PROVIDE: stalwart
# REQUIRE: NETWORKING LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="stalwart"
rcvar="stalwart_enable"
desc="Stalwart Server"

load_rc_config \$name

: \${stalwart_enable:="NO"}
: \${stalwart_runas_user:="${_user}"}
: \${stalwart_runas_group:="${_user}"}
: \${stalwart_config:="${_config}"}
: \${stalwart_envfile:="${_env}"}
: \${stalwart_logfile:="${_log_dir}/stalwart.log"}
: \${stalwart_fdlimit:="65536"}

pidfile="/var/run/stalwart.pid"
procname="${_bin}"
command="/usr/sbin/daemon"
command_args="-f -o \${stalwart_logfile} -p \${pidfile} ${_bin} --config=\${stalwart_config}"
sig_stop="INT"
start_precmd="stalwart_precmd"

stalwart_precmd()
{
    # daemon(8) passes its environment through to the service
    if [ -r "\${stalwart_envfile}" ]; then
        set -a
        . "\${stalwart_envfile}"
        set +a
    fi

    # Stalwart binds its listeners as root, then setuid()s to this account
    export RUN_AS_USER="\${stalwart_runas_user}"
    export RUN_AS_GROUP="\${stalwart_runas_group}"

    ulimit -n "\${stalwart_fdlimit}"
}

run_rc_command "\$1"
EOF
    chmod +x /usr/local/etc/rc.d/stalwart
    sysrc stalwart_enable=YES
    service stalwart stop > /dev/null 2>&1 || true
    service stalwart start
}


get_architecture() {
    local _ostype _cputype _bitness _arch _clibtype
    _ostype="$(uname -s)"
    _cputype="$(uname -m)"
    _clibtype="gnu"

    if [ "$_ostype" = Linux ]; then
        if [ "$(uname -o)" = Android ]; then
            _ostype=Android
        fi
        if ldd --version 2>&1 | grep -q 'musl'; then
            _clibtype="musl"
        fi
    fi

    if [ "$_ostype" = Darwin ] && [ "$_cputype" = i386 ]; then
        # Darwin `uname -m` lies
        if sysctl hw.optional.x86_64 | grep -q ': 1'; then
            _cputype=x86_64
        fi
    fi

    if [ "$_ostype" = SunOS ]; then
        # Both Solaris and illumos presently announce as "SunOS" in "uname -s"
        # so use "uname -o" to disambiguate.  We use the full path to the
        # system uname in case the user has coreutils uname first in PATH,
        # which has historically sometimes printed the wrong value here.
        if [ "$(/usr/bin/uname -o)" = illumos ]; then
            _ostype=illumos
        fi

        # illumos systems have multi-arch userlands, and "uname -m" reports the
        # machine hardware name; e.g., "i86pc" on both 32- and 64-bit x86
        # systems.  Check for the native (widest) instruction set on the
        # running kernel:
        if [ "$_cputype" = i86pc ]; then
            _cputype="$(isainfo -n)"
        fi
    fi

    case "$_ostype" in

        Android)
            _ostype=linux-android
            ;;

        Linux)
            check_proc
            _ostype=unknown-linux-$_clibtype
            _bitness=$(get_bitness)
            ;;

        FreeBSD)
            _ostype=unknown-freebsd
            ;;

        NetBSD)
            _ostype=unknown-netbsd
            ;;

        DragonFly)
            _ostype=unknown-dragonfly
            ;;

        Darwin)
            _ostype=apple-darwin
            ;;

        illumos)
            _ostype=unknown-illumos
            ;;

        MINGW* | MSYS* | CYGWIN* | Windows_NT)
            _ostype=pc-windows-gnu
            ;;

        *)
            err "unrecognized OS type: $_ostype"
            ;;

    esac

    case "$_cputype" in

        i386 | i486 | i686 | i786 | x86)
            _cputype=i686
            ;;

        xscale | arm)
            _cputype=arm
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            fi
            ;;

        armv6l)
            _cputype=arm
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            else
                _ostype="${_ostype}eabihf"
            fi
            ;;

        armv7l | armv8l)
            _cputype=armv7
            if [ "$_ostype" = "linux-android" ]; then
                _ostype=linux-androideabi
            else
                _ostype="${_ostype}eabihf"
            fi
            ;;

        aarch64 | arm64)
            _cputype=aarch64
            ;;

        x86_64 | x86-64 | x64 | amd64)
            _cputype=x86_64
            ;;

        mips)
            _cputype=$(get_endianness mips '' el)
            ;;

        mips64)
            if [ "$_bitness" -eq 64 ]; then
                # only n64 ABI is supported for now
                _ostype="${_ostype}abi64"
                _cputype=$(get_endianness mips64 '' el)
            fi
            ;;

        ppc)
            _cputype=powerpc
            ;;

        ppc64)
            _cputype=powerpc64
            ;;

        ppc64le)
            _cputype=powerpc64le
            ;;

        s390x)
            _cputype=s390x
            ;;
        riscv64)
            _cputype=riscv64gc
            ;;
        *)
            err "unknown CPU type: $_cputype"

    esac

    # Detect 64-bit linux with 32-bit userland
    if [ "${_ostype}" = unknown-linux-gnu ] && [ "${_bitness}" -eq 32 ]; then
        case $_cputype in
            x86_64)
                if [ -n "${RUSTUP_CPUTYPE:-}" ]; then
                    _cputype="$RUSTUP_CPUTYPE"
                else {
                    # 32-bit executable for amd64 = x32
                    if is_host_amd64_elf; then {
                         echo "This host is running an x32 userland; as it stands, x32 support is poor," 1>&2
                         echo "and there isn't a native toolchain -- you will have to install" 1>&2
                         echo "multiarch compatibility with i686 and/or amd64, then select one" 1>&2
                         echo "by re-running this script with the RUSTUP_CPUTYPE environment variable" 1>&2
                         echo "set to i686 or x86_64, respectively." 1>&2
                         echo 1>&2
                         echo "You will be able to add an x32 target after installation by running" 1>&2
                         echo "  rustup target add x86_64-unknown-linux-gnux32" 1>&2
                         exit 1
                    }; else
                        _cputype=i686
                    fi
                }; fi
                ;;
            mips64)
                _cputype=$(get_endianness mips '' el)
                ;;
            powerpc64)
                _cputype=powerpc
                ;;
            aarch64)
                _cputype=armv7
                if [ "$_ostype" = "linux-android" ]; then
                    _ostype=linux-androideabi
                else
                    _ostype="${_ostype}eabihf"
                fi
                ;;
            riscv64gc)
                err "riscv64 with 32-bit userland unsupported"
                ;;
        esac
    fi

    # Detect armv7 but without the CPU features Rust needs in that build,
    # and fall back to arm.
    # See https://github.com/rust-lang/rustup.rs/issues/587.
    if [ "$_ostype" = "unknown-linux-gnueabihf" ] && [ "$_cputype" = armv7 ]; then
        if ensure grep '^Features' /proc/cpuinfo | grep -q -v neon; then
            # At least one processor does not have NEON.
            _cputype=arm
        fi
    fi

    _arch="${_cputype}-${_ostype}"

    RETVAL="$_arch"
}

check_proc() {
    # Check for /proc by looking for the /proc/self/exe link
    # This is only run on Linux
    if ! test -L /proc/self/exe ; then
        err "fatal: Unable to find /proc/self/exe.  Is /proc mounted?  Installation cannot proceed without /proc."
    fi
}

get_bitness() {
    need_cmd head
    # Architecture detection without dependencies beyond coreutils.
    # ELF files start out "\x7fELF", and the following byte is
    #   0x01 for 32-bit and
    #   0x02 for 64-bit.
    # The printf builtin on some shells like dash only supports octal
    # escape sequences, so we use those.
    local _current_exe_head
    _current_exe_head=$(head -c 5 /proc/self/exe )
    if [ "$_current_exe_head" = "$(printf '\177ELF\001')" ]; then
        echo 32
    elif [ "$_current_exe_head" = "$(printf '\177ELF\002')" ]; then
        echo 64
    else
        err "unknown platform bitness"
    fi
}

is_host_amd64_elf() {
    need_cmd head
    need_cmd tail
    # ELF e_machine detection without dependencies beyond coreutils.
    # Two-byte field at offset 0x12 indicates the CPU,
    # but we're interested in it being 0x3E to indicate amd64, or not that.
    local _current_exe_machine
    _current_exe_machine=$(head -c 19 /proc/self/exe | tail -c 1)
    [ "$_current_exe_machine" = "$(printf '\076')" ]
}

get_endianness() {
    local cputype=$1
    local suffix_eb=$2
    local suffix_el=$3

    # detect endianness without od/hexdump, like get_bitness() does.
    need_cmd head
    need_cmd tail

    local _current_exe_endianness
    _current_exe_endianness="$(head -c 6 /proc/self/exe | tail -c 1)"
    if [ "$_current_exe_endianness" = "$(printf '\001')" ]; then
        echo "${cputype}${suffix_el}"
    elif [ "$_current_exe_endianness" = "$(printf '\002')" ]; then
        echo "${cputype}${suffix_eb}"
    else
        err "unknown platform endianness"
    fi
}

say() {
    printf '%s\n' "$1"
}

err() {
    say "$1" >&2
    exit 1
}

need_cmd() {
    if ! check_cmd "$1"; then
        err "need '$1' (command not found)"
    fi
}

check_cmd() {
    command -v "$1" > /dev/null 2>&1
}

assert_nz() {
    if [ -z "$1" ]; then err "assert_nz $2"; fi
}

# Run a command that should never fail. If the command fails execution
# will immediately terminate with an error showing the failing
# command.
ensure() {
    if ! "$@"; then err "command failed: $*"; fi
}

# This wraps curl or wget. Try curl first, if not installed,
# use wget instead.
downloader() {
    local _dld
    local _ciphersuites
    local _err
    local _status
    local _retry
    if check_cmd curl; then
        _dld=curl
    elif check_cmd wget; then
        _dld=wget
    else
        _dld='curl or wget' # to be used in error message of need_cmd
    fi

    if [ "$1" = --check ]; then
        need_cmd "$_dld"
    elif [ "$_dld" = curl ]; then
        check_curl_for_retry_support
        _retry="$RETVAL"
        get_ciphersuites_for_curl
        _ciphersuites="$RETVAL"
        if [ -n "$_ciphersuites" ]; then
            _err=$(curl $_retry --proto '=https' --tlsv1.2 --ciphers "$_ciphersuites" --silent --show-error --fail --location "$1" --output "$2" 2>&1)
            _status=$?
        else
            echo "Warning: Not enforcing strong cipher suites for TLS, this is potentially less secure"
            if ! check_help_for "$3" curl --proto --tlsv1.2; then
                echo "Warning: Not enforcing TLS v1.2, this is potentially less secure"
                _err=$(curl $_retry --silent --show-error --fail --location "$1" --output "$2" 2>&1)
                _status=$?
            else
                _err=$(curl $_retry --proto '=https' --tlsv1.2 --silent --show-error --fail --location "$1" --output "$2" 2>&1)
                _status=$?
            fi
        fi
        if [ -n "$_err" ]; then
            if echo "$_err" | grep -q 404; then
                err "❌  Binary for platform '$3' not found, this platform may be unsupported."
            else
                echo "$_err" >&2
            fi
        fi
        return $_status
    elif [ "$_dld" = wget ]; then
        if [ "$(wget -V 2>&1|head -2|tail -1|cut -f1 -d" ")" = "BusyBox" ]; then
            echo "Warning: using the BusyBox version of wget.  Not enforcing strong cipher suites for TLS or TLS v1.2, this is potentially less secure"
            _err=$(wget "$1" -O "$2" 2>&1)
            _status=$?
        else
            get_ciphersuites_for_wget
            _ciphersuites="$RETVAL"
            if [ -n "$_ciphersuites" ]; then
                _err=$(wget --https-only --secure-protocol=TLSv1_2 --ciphers "$_ciphersuites" "$1" -O "$2" 2>&1)
                _status=$?
            else
                echo "Warning: Not enforcing strong cipher suites for TLS, this is potentially less secure"
                if ! check_help_for "$3" wget --https-only --secure-protocol; then
                    echo "Warning: Not enforcing TLS v1.2, this is potentially less secure"
                    _err=$(wget "$1" -O "$2" 2>&1)
                    _status=$?
                else
                    _err=$(wget --https-only --secure-protocol=TLSv1_2 "$1" -O "$2" 2>&1)
                    _status=$?
                fi
            fi
        fi
        if [ -n "$_err" ]; then
            if echo "$_err" | grep -q ' 404 Not Found'; then
                err "❌  Binary for platform '$3' not found, this platform may be unsupported."
            else
                echo "$_err" >&2
            fi
        fi
        return $_status
    else
        err "Unknown downloader"   # should not reach here
    fi
}

# Check if curl supports the --retry flag, then pass it to the curl invocation.
check_curl_for_retry_support() {
  local _retry_supported=""
  # "unspecified" is for arch, allows for possibility old OS using macports, homebrew, etc.
  if check_help_for "notspecified" "curl" "--retry"; then
    _retry_supported="--retry 3"
  fi

  RETVAL="$_retry_supported"

}

check_help_for() {
    local _arch
    local _cmd
    local _arg
    _arch="$1"
    shift
    _cmd="$1"
    shift

    local _category
    if "$_cmd" --help | grep -q 'For all options use the manual or "--help all".'; then
      _category="all"
    else
      _category=""
    fi

    case "$_arch" in

        *darwin*)
        if check_cmd sw_vers; then
            case $(sw_vers -productVersion) in
                10.*)
                    # If we're running on macOS, older than 10.13, then we always
                    # fail to find these options to force fallback
                    if [ "$(sw_vers -productVersion | cut -d. -f2)" -lt 13 ]; then
                        # Older than 10.13
                        echo "Warning: Detected macOS platform older than 10.13"
                        return 1
                    fi
                    ;;
                11.*)
                    # We assume Big Sur will be OK for now
                    ;;
                *)
                    # Unknown product version, warn and continue
                    echo "Warning: Detected unknown macOS major version: $(sw_vers -productVersion)"
                    echo "Warning TLS capabilities detection may fail"
                    ;;
            esac
        fi
        ;;

    esac

    for _arg in "$@"; do
        if ! "$_cmd" --help $_category | grep -q -- "$_arg"; then
            return 1
        fi
    done

    true # not strictly needed
}

# Return cipher suite string specified by user, otherwise return strong TLS 1.2-1.3 cipher suites
# if support by local tools is detected. Detection currently supports these curl backends:
# GnuTLS and OpenSSL (possibly also LibreSSL and BoringSSL). Return value can be empty.
get_ciphersuites_for_curl() {
    if [ -n "${RUSTUP_TLS_CIPHERSUITES-}" ]; then
        # user specified custom cipher suites, assume they know what they're doing
        RETVAL="$RUSTUP_TLS_CIPHERSUITES"
        return
    fi

    local _openssl_syntax="no"
    local _gnutls_syntax="no"
    local _backend_supported="yes"
    if curl -V | grep -q ' OpenSSL/'; then
        _openssl_syntax="yes"
    elif curl -V | grep -iq ' LibreSSL/'; then
        _openssl_syntax="yes"
    elif curl -V | grep -iq ' BoringSSL/'; then
        _openssl_syntax="yes"
    elif curl -V | grep -iq ' GnuTLS/'; then
        _gnutls_syntax="yes"
    else
        _backend_supported="no"
    fi

    local _args_supported="no"
    if [ "$_backend_supported" = "yes" ]; then
        # "unspecified" is for arch, allows for possibility old OS using macports, homebrew, etc.
        if check_help_for "notspecified" "curl" "--tlsv1.2" "--ciphers" "--proto"; then
            _args_supported="yes"
        fi
    fi

    local _cs=""
    if [ "$_args_supported" = "yes" ]; then
        if [ "$_openssl_syntax" = "yes" ]; then
            _cs=$(get_strong_ciphersuites_for "openssl")
        elif [ "$_gnutls_syntax" = "yes" ]; then
            _cs=$(get_strong_ciphersuites_for "gnutls")
        fi
    fi

    RETVAL="$_cs"
}

# Return cipher suite string specified by user, otherwise return strong TLS 1.2-1.3 cipher suites
# if support by local tools is detected. Detection currently supports these wget backends:
# GnuTLS and OpenSSL (possibly also LibreSSL and BoringSSL). Return value can be empty.
get_ciphersuites_for_wget() {
    if [ -n "${RUSTUP_TLS_CIPHERSUITES-}" ]; then
        # user specified custom cipher suites, assume they know what they're doing
        RETVAL="$RUSTUP_TLS_CIPHERSUITES"
        return
    fi

    local _cs=""
    if wget -V | grep -q '\-DHAVE_LIBSSL'; then
        # "unspecified" is for arch, allows for possibility old OS using macports, homebrew, etc.
        if check_help_for "notspecified" "wget" "TLSv1_2" "--ciphers" "--https-only" "--secure-protocol"; then
            _cs=$(get_strong_ciphersuites_for "openssl")
        fi
    elif wget -V | grep -q '\-DHAVE_LIBGNUTLS'; then
        # "unspecified" is for arch, allows for possibility old OS using macports, homebrew, etc.
        if check_help_for "notspecified" "wget" "TLSv1_2" "--ciphers" "--https-only" "--secure-protocol"; then
            _cs=$(get_strong_ciphersuites_for "gnutls")
        fi
    fi

    RETVAL="$_cs"
}

# Return strong TLS 1.2-1.3 cipher suites in OpenSSL or GnuTLS syntax. TLS 1.2
# excludes non-ECDHE and non-AEAD cipher suites. DHE is excluded due to bad
# DH params often found on servers (see RFC 7919). Sequence matches or is
# similar to Firefox 68 ESR with weak cipher suites disabled via about:config.
# $1 must be openssl or gnutls.
get_strong_ciphersuites_for() {
    if [ "$1" = "openssl" ]; then
        # OpenSSL is forgiving of unknown values, no problems with TLS 1.3 values on versions that don't support it yet.
        echo "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    elif [ "$1" = "gnutls" ]; then
        # GnuTLS isn't forgiving of unknown values, so this may require a GnuTLS version that supports TLS 1.3 even if wget doesn't.
        # Begin with SECURE128 (and higher) then remove/add to build cipher suites. Produces same 9 cipher suites as OpenSSL but in slightly different order.
        echo "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS-ALL:-CIPHER-ALL:-MAC-ALL:-KX-ALL:+AEAD:+ECDHE-ECDSA:+ECDHE-RSA:+AES-128-GCM:+CHACHA20-POLY1305:+AES-256-GCM"
    fi
}

# This is just for indicating that commands' results are being
# intentionally ignored. Usually, because it's being executed
# as part of error handling.
ignore() {
    "$@"
}

main "$@" || exit 1
