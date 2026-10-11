#!/usr/bin/env bash
# ============================================================================
# harden_ssh_with_fail2ban.sh  (v2.5 - 自适应加固版)
# 功能：安装并配置 fail2ban；SSH 登录失败 3 次（5 分钟窗口）即永久封禁该 IP
#       （封禁该 IP 的所有端口）
# ---------------------------------------------------------------------------
# 用法：  sudo bash harden_ssh_with_fail2ban.sh
# 放行你的管理 IP（可选）：
#         sudo EXTRA_IGNOREIP="1.2.3.4" bash harden_ssh_with_fail2ban.sh
# ---------------------------------------------------------------------------
# v2.5：最后的「日志源校验」（fail2ban-regex）全程套 timeout（默认 30s）。
#   原因：fail2ban-regex 走 systemd-journal 时会从 journal 最早一条开始【全量扫描】，
#   条目多时要跑几分钟，中途没有任何输出 —— 看起来就像脚本卡死或在等你输入。
#   现在超时/失败会自动退回「最近 1 小时日志快照」再测一次（秒级完成），
#   并且 stderr 不再被丢掉，出错时能直接看到原因。
# ============================================================================

set -uo pipefail

CONF=/etc/fail2ban/jail.d/zz-sshd-permanent-ban.local
LEGACY_CONF=/etc/fail2ban/jail.d/ssh-permanent-ban.conf
SOCK=/run/fail2ban/fail2ban.sock

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
ylw() { printf '\033[33m%s\033[0m\n' "$*"; }

# ---------- 0. root 检查 ----------
if [ "$(id -u)" -ne 0 ]; then
    red "请使用 sudo 或 root 运行：sudo bash $0"
    exit 1
fi

echo "=== Fail2Ban SSH 永久封禁配置脚本 (v2.5 自适应版) ==="
if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "系统：${PRETTY_NAME:-unknown}    内核：$(uname -r)"
fi

# ---------- 1. 识别包管理器 ----------
if command -v apt-get >/dev/null 2>&1; then
    PKG=apt
elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf
elif command -v yum >/dev/null 2>&1; then
    PKG=yum
else
    red "不支持的包管理器，请手动安装 fail2ban 后重试"
    exit 1
fi

pkg_install() {
    case "$PKG" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get -qq update 2>/dev/null \
                || ylw "  (apt update 有警告，忽略继续)"
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf) dnf install -y "$@" ;;
        yum) yum install -y "$@" ;;
    esac
}

# ---------- 2. 安装 fail2ban ----------
echo "-> 安装 fail2ban ..."
pkg_install fail2ban >/dev/null 2>&1 || { red "fail2ban 安装失败，请检查软件源"; exit 1; }
command -v fail2ban-server >/dev/null 2>&1 || { red "未找到 fail2ban-server，安装异常"; exit 1; }
echo "   fail2ban 版本：$(fail2ban-server --version 2>/dev/null | tail -1)"

# ---------- 3. 选择日志后端 ----------
USE_SD=0
BACKEND_LINE=""
LOGPATH_LINE=""
JOURNALMATCH_LINE=""
JM_VALUE=""
AUTH_LOG=""

if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    USE_SD=1
    # systemd 后端需要 python3-systemd（Debian 12 里只是 Recommends，精简系统常缺；
    # Debian 13 已改为硬依赖）
    if ! python3 -c 'import systemd' >/dev/null 2>&1; then
        echo "-> 安装 python3-systemd（systemd 日志后端依赖）..."
        pkg_install python3-systemd >/dev/null 2>&1 || true
    fi
    if python3 -c 'import systemd' >/dev/null 2>&1; then
        BACKEND_LINE="backend  = systemd"
        LOGPATH_LINE="# 用 systemd 后端时不写 logpath（写了也不会读，且旧版会据此报错）"
        echo "-> 日志后端：systemd journal"
    else
        ylw "python3-systemd 不可用，回退到文件后端"
        USE_SD=0
    fi
fi

if [ "$USE_SD" = 0 ]; then
    for f in /var/log/auth.log /var/log/secure; do
        [ -f "$f" ] && { AUTH_LOG="$f"; break; }
    done
    if [ -z "$AUTH_LOG" ]; then
        ylw "未找到认证日志文件，尝试安装并启动 rsyslog ..."
        pkg_install rsyslog >/dev/null 2>&1 || true
        systemctl enable --now rsyslog >/dev/null 2>&1 || true
        sleep 1
        for f in /var/log/auth.log /var/log/secure; do
            [ -f "$f" ] && { AUTH_LOG="$f"; break; }
        done
    fi
    if [ -n "$AUTH_LOG" ]; then
        BACKEND_LINE="backend  = auto"
        LOGPATH_LINE="logpath  = %(sshd_log)s"
        echo "-> 日志后端：文件（$AUTH_LOG）"
    else
        red "既无 systemd journal 也无认证日志文件，无法确定日志来源"
        exit 1
    fi
fi

# ---------- 3b. 生成 journalmatch ----------
# 关键：Debian 12 的 fail2ban 包自带配置里【没有】journalmatch，必须显式写。
# 否则用 systemd 后端时 fail2ban 默认去找 _SYSTEMD_UNIT=sshd.service，
# 而 Debian 上 sshd 的 systemd unit 实际叫 ssh.service → jail 起来了却抓不到日志。
# journalmatch 沿用 journalctl 的匹配语法：空格 = AND，'+' = OR。
if [ "$USE_SD" = 1 ]; then
    JM_VALUE="_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session"
    JOURNALMATCH_LINE="journalmatch = ${JM_VALUE}"
    echo "-> journalmatch：已显式指定（覆盖 ssh.service / sshd.service / sshd-session）"
fi

# ---------- 4. 选择防火墙后端 ----------
FIREWALL=""
BANACTION_ALLPORTS=""

UFW_ACTIVE=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    UFW_ACTIVE=1
fi

if [ "$UFW_ACTIVE" = 1 ]; then
    # ufw 活跃时沿用 iptables 链路，避免与 nft 规则表相互打架
    command -v iptables >/dev/null 2>&1 || pkg_install iptables >/dev/null 2>&1 || true
    FIREWALL=iptables
    BANACTION_ALLPORTS='iptables-allports'
elif command -v nft >/dev/null 2>&1; then
    FIREWALL=nftables
    BANACTION_ALLPORTS='nftables[type=allports]'
elif command -v iptables >/dev/null 2>&1; then
    FIREWALL=iptables
    BANACTION_ALLPORTS='iptables-allports'
else
    echo "-> 未检测到防火墙工具，尝试安装 nftables ..."
    pkg_install nftables >/dev/null 2>&1 || pkg_install iptables >/dev/null 2>&1 || true
    if command -v nft >/dev/null 2>&1; then
        FIREWALL=nftables; BANACTION_ALLPORTS='nftables[type=allports]'
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL=iptables; BANACTION_ALLPORTS='iptables-allports'
    else
        red "无法安装任何防火墙后端（nftables / iptables）"
        exit 1
    fi
fi
echo "-> 防火墙后端：$FIREWALL   (banaction_allports = $BANACTION_ALLPORTS)"

# ---------- 5. 写配置 ----------
mkdir -p /etc/fail2ban/jail.d
if [ -f "$CONF" ]; then
    cp -a "$CONF" "${CONF}.bak.$(date +%s)"
    ylw "已备份旧配置：${CONF}.bak.*"
fi

# v1 写的旧文件（jail.d/*.conf 优先级低于本脚本，但留着容易看混，直接清掉）
if [ -f "$LEGACY_CONF" ]; then
    rm -f "$LEGACY_CONF"
    ylw "已移除 v1 的旧配置：$LEGACY_CONF"
fi
if [ -f /etc/fail2ban/jail.local ]; then
    ylw "提示：检测到 /etc/fail2ban/jail.local；本脚本写在 jail.d/*.local，优先级更高，会覆盖它"
fi

IGNOREIP_LINE="ignoreip = 127.0.0.1/8 ::1"
if [ -n "${EXTRA_IGNOREIP:-}" ]; then
    IGNOREIP_LINE="$IGNOREIP_LINE ${EXTRA_IGNOREIP}"
fi

write_conf() {
cat > "$CONF" <<EOF
# 由 harden_ssh_with_fail2ban.sh (v2.5) 自动生成  $(date '+%F %T')
# 目标：5 分钟内 SSH 失败 3 次 -> 该 IP 永久封禁（所有端口）

[DEFAULT]
# 封禁动作的底层实现，自动匹配本机防火墙后端
banaction_allports = ${BANACTION_ALLPORTS}

[sshd]
enabled  = true
port     = ssh
filter   = sshd
${BACKEND_LINE}
${LOGPATH_LINE}
${JOURNALMATCH_LINE}

# 检测窗口内允许的失败次数
maxretry = 3
# 检测窗口：5 分钟
findtime = 300
# 封禁时长：-1 表示永久
bantime  = -1
# 使用 allports 动作：封禁该 IP 的所有端口
# 注意：不能写 %(action_allports)s（jail.conf 里没有这个键），照抄 action_ 的结构
action   = %(banaction_allports)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
# 不封禁本机（可追加你的管理 IP）
${IGNOREIP_LINE}
EOF
}
write_conf
echo "-> 已写入 $CONF"

# ---------- 5b. 配置自检（必须先过，再谈启动）----------
# v2.3 的教训：自检失败时【不要】盲目换后端。上次真正的报错是模板引用了不存在的
# %(action_allports)s，跟 nftables / iptables 毫无关系，换后端照样失败还带偏方向。
FAIL_CFG=0
TLOG=$(mktemp)

if fail2ban-server -t >"$TLOG" 2>&1; then
    echo "-> 配置自检通过（fail2ban-server -t）"
else
    ylw "✗ 配置自检未通过（当前 banaction_allports = $BANACTION_ALLPORTS），真实报错："
    tail -n 6 "$TLOG" | sed 's/^/    /'
    if grep -qi 'Bad value substitution' "$TLOG"; then
        red "  ↑ 配置模板引用了不存在的变量：换防火墙后端解决不了，必须改模板。"
        FAIL_CFG=1
    elif [ "$BANACTION_ALLPORTS" = 'iptables-allports' ]; then
        red "  ↑ 已经是 iptables-allports 仍不通过，看上面这 6 行。"
        FAIL_CFG=1
    else
        ylw "-> 疑似动作不受支持，回退到 iptables-allports 重试 ..."
        command -v iptables >/dev/null 2>&1 || pkg_install iptables >/dev/null 2>&1 || true
        if command -v iptables >/dev/null 2>&1; then
            FIREWALL=iptables
            BANACTION_ALLPORTS='iptables-allports'
            write_conf
            if fail2ban-server -t >"$TLOG" 2>&1; then
                echo "-> 已改用 iptables-allports 重写 $CONF，自检通过"
            else
                red "✗ 回退后仍不通过，报错："
                tail -n 6 "$TLOG" | sed 's/^/    /'
                FAIL_CFG=1
            fi
        else
            red "✗ 装不上 iptables，无法回退"
            FAIL_CFG=1
        fi
    fi
fi
rm -f "$TLOG"

if [ "$FAIL_CFG" = 1 ]; then
    echo
    red "配置本身不合法，停在这里，不再去启动服务（免得又只看到一个含糊的『启动失败』）。"
    red "请把上面这段报错发出来。"
    exit 1
fi

# ---------- 6. 启动服务 ----------
echo "-> 启动 fail2ban ..."
rm -f "$SOCK" 2>/dev/null || true
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl reset-failed fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true   # 故意吞掉输出，失败在下面统一诊断
sleep 3

# ---------- 7. 验证服务 ----------
FAIL=0
if ! systemctl is-active --quiet fail2ban; then
    red "✗ fail2ban 服务未启动，以下是真实原因（v1 里被吞掉的那部分）："
    echo "-------- systemctl status fail2ban --------"
    systemctl status fail2ban --no-pager -l 2>&1 | tail -n 40
    echo "-------- journalctl -u fail2ban（最近 50 行）--------"
    journalctl -u fail2ban -n 50 --no-pager 2>&1 || true
    echo "-------- 配置语法自检 --------"
    fail2ban-server -t 2>&1 | tail -n 30 || true
    FAIL=1
elif ! fail2ban-client status sshd >/dev/null 2>&1; then
    ylw "⚠ 服务在运行，但 sshd jail 未加载："
    fail2ban-client status 2>&1 || true
    FAIL=1
fi

# ---------- 8. 校验「日志源」是否真的接通 ----------
# 服务 active 不等于在干活：日志源没接上时，jail 会安静地一条都不抓。
# 注意：fail2ban-regex 走 systemd-journal 时会【从 journal 最早一条开始全量扫描】，
#       条目多时要跑几分钟且中途无输出（看着像卡死/等你输入），所以一律套 timeout。
REGEX_TIMEOUT=${REGEX_TIMEOUT:-30}

# 统一封装：跑一次 fail2ban-regex，只取 "Lines:" 那一行；成功输出该行并返回 0
regex_check() {
    local label="$1"; shift
    local ro rr rc lines matched ok=1
    ro=$(mktemp); rr=$(mktemp)
    timeout "$REGEX_TIMEOUT" fail2ban-regex "$@" >"$ro" 2>"$rr"
    rc=$?
    lines=$(grep -o 'Lines:.*' "$ro" 2>/dev/null | tail -1)
    printf '   %s: ' "$label"
    if [ -n "$lines" ]; then
        echo "$lines"
        ok=0
        matched=$(printf '%s\n' "$lines" | grep -o '[0-9]* matched' | grep -o '^[0-9]*')
        if [ "${matched:-0}" = 0 ]; then
            ylw "      ⚠ 0 匹配：若这台机器近期确实有过 SSH 失败登录，说明日志源没接上"
        fi
    elif [ "$rc" = 124 ]; then
        echo "超过 ${REGEX_TIMEOUT}s 未完成（journal 条目过多），跳过全量扫描"
    else
        echo "未能完成（exit=$rc），原始报错："
        tail -n 5 "$rr" | sed 's/^/      /'
    fi
    rm -f "$ro" "$rr"
    return $ok
}

if [ "$FAIL" = 0 ]; then
    grn "✓ fail2ban 运行正常，sshd jail 已加载"
    fail2ban-client status sshd

    echo "-> 校验日志源..."
    echo "   （fail2ban-regex 会扫描 journal，最长等 ${REGEX_TIMEOUT}s，期间无输出是正常的）"
    if [ "$USE_SD" = 1 ]; then
        echo "   journalmatch = $(fail2ban-client get sshd journalmatch 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"
        # 必须用 -m 把 jail 里的 journalmatch 传给 fail2ban-regex。
        # 不带 -m 时它只会用 filter.d/sshd.conf 自带的
        #   journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd
        # 这条不含 _SYSTEMD_UNIT=ssh.service。在 Debian 13（OpenSSH 10.x）上更糟：
        # 认证失败日志由 sshd-session 进程产生，_COMM 是 sshd-session，
        # 于是会打印 "0 matched" —— 假报警，jail 本身是好的。
        if command -v fail2ban-regex >/dev/null 2>&1; then
            if ! regex_check "fail2ban-regex(journal)" \
                    -m "$JM_VALUE" systemd-journal /etc/fail2ban/filter.d/sshd.conf; then
                # 兜底：导出最近 1 小时日志做快照再测，秒级完成且必定有结果
                SNAP=$(mktemp)
                if journalctl --since '-1h' --no-pager -o short >"$SNAP" 2>/dev/null && [ -s "$SNAP" ]; then
                    regex_check "fail2ban-regex(最近1h快照)" "$SNAP" /etc/fail2ban/filter.d/sshd.conf \
                        || ylw "      快照内也没有匹配，可能这 1 小时确实没有 SSH 失败登录"
                else
                    ylw "      拿不到日志快照，跳过该步（不影响 fail2ban 本身）"
                fi
                rm -f "$SNAP"
            fi
        fi
        echo "   提示：用另一台机器故意输错密码 3 次，再回来执行 fail2ban-client status sshd"
        echo "         看 Currently failed / Total failed 是否增长，这是最终验收标准。"
    else
        echo "   logpath = ${AUTH_LOG}"
        if command -v fail2ban-regex >/dev/null 2>&1 && [ -n "$AUTH_LOG" ]; then
            regex_check "fail2ban-regex(file)" "$AUTH_LOG" /etc/fail2ban/filter.d/sshd.conf
        fi
    fi

    # ---------- 9. 封禁链路自测 ----------
    TESTIP=198.51.100.7   # RFC5737 保留测试网段，不会是真实主机
    echo "-> 自测封禁链路（临时封禁 $TESTIP）..."
    if fail2ban-client set sshd banip "$TESTIP" >/dev/null 2>&1; then
        RULE_OK=0
        if [ "$FIREWALL" = nftables ]; then
            nft list ruleset 2>/dev/null | grep -q "$TESTIP" && RULE_OK=1
        else
            iptables -L -n 2>/dev/null | grep -q "$TESTIP" && RULE_OK=1
        fi
        fail2ban-client set sshd unbanip "$TESTIP" >/dev/null 2>&1 || true
        if [ "$RULE_OK" = 1 ]; then
            grn "✓ 防火墙规则已下发，封禁链路正常"
        else
            ylw "⚠ 封禁已记录，但未在 $FIREWALL 中看到规则，请检查防火墙后端是否匹配"
        fi
    else
        ylw "⚠ 封禁自测失败，请查看 /var/log/fail2ban.log"
    fi
fi

# ---------- 10. 结果 ----------
echo
echo "=== 结果 ==="
if [ "$FAIL" = 0 ]; then
    grn "✓ Fail2Ban 已成功配置"
    echo "  规则：5 分钟内 SSH 登录失败 3 次 → 该 IP 永久封禁（所有端口）"
else
    red "✗ 配置未生效，请把上面的诊断输出发出来"
fi
echo
echo "常用命令："
echo "  查看状态     : fail2ban-client status sshd"
echo "  查看日志源   : fail2ban-client get sshd journalmatch"
echo "  解封 IP      : fail2ban-client set sshd unbanip <IP>"
echo "  查看日志     : tail -f /var/log/fail2ban.log"
echo "  语法自检     : fail2ban-server -t"
echo
ylw "防自锁提醒：如需放行固定管理 IP，编辑 $CONF，"
ylw "把 ignoreip 改成：ignoreip = 127.0.0.1/8 ::1 你的公网IP"
echo
echo "注意：请确保您不会意外锁定自己！"

exit "$FAIL"
