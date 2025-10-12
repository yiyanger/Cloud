#!/bin/bash

# ==============================================================================
# Fail2ban SSH Permanent Ban Automation Script
#
# Description:
# This script automates the installation and configuration of Fail2ban on
# major Linux distributions to permanently ban IP addresses that fail SSH
# login attempts multiple times within a 5-minute window.
#
# Supported Distributions:
# - Debian / Ubuntu (and derivatives)
# - RHEL / CentOS / AlmaLinux / Rocky Linux
# - Fedora
#
# Author: System Engineering Expert Team
# Version: 1.2 (Corrected Subshell Syntax Error)
# ==============================================================================

# --- Script Execution Safeguards ---
# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines return the exit status of the last command to exit with a
# non-zero status, or zero if all commands exit successfully.
set -o pipefail

# --- Prerequisite Validation ---
# Ensure the script is run with root privileges.
if [ "$(id -u)" -ne 0 ]; then
    echo "错误：此脚本必须以root权限运行。请使用 'sudo' 执行。" >&2
    exit 1
fi

# --- Function Definitions ---
# A standardized function for logging messages.
log_info() {
    echo "[信息] $1"
}

log_success() {
    echo -e "\033[0;32m[成功] $1\033[0m"
}

log_error() {
    echo -e "\033[0;31m[错误] $1\033
# 启用此jail
enabled = true

# 监控的端口 (使用服务名更具可移植性)
port = ssh

# 使用内置的sshd过滤器
filter = sshd

# 使用Fail2ban的变量自动检测日志路径，兼容Debian/RHEL系
logpath = %(sshd_log)s

# 自动检测日志后端 (如systemd-journal或文件)
backend = auto

# 在5分钟 (300秒) 内
findtime = 300

# 达到3次失败尝试
maxretry = 3

# 则永久封禁 (bantime = -1)
bantime = -1
EOF

log_success "SSH永久封禁规则配置完成。"

# --- Finalizing and Restarting Service ---
log_info "正在重新加载Fail2ban配置以应用新规则..."
fail2ban-client reload

# A small delay to allow the service to process the new configuration.
sleep 2

# --- Verification and Post-Execution Instructions ---
log_success "Fail2ban自动化部署已成功完成！"
echo "-----------------------------------------------------------------"
echo "重要操作指令:"
echo ""
echo "1. 验证sshd jail状态:"
echo "   sudo fail2ban-client status sshd"
echo ""
echo "2. 如果意外封禁了合法IP，请使用以下命令解封 (将<IP_ADDRESS>替换为实际IP):"
echo "   sudo fail2ban-client set sshd unbanip <IP_ADDRESS>"
echo ""
echo "3. 建议将您的可信IP地址加入白名单，编辑文件 '$JAIL_CONFIG_FILE' 并添加一行:"
echo "   ignoreip = 127.0.0.1/8 ::1 YOUR_STATIC_IP_HERE"
echo "   添加后，执行 'sudo fail2ban-client reload' 重载配置。"
echo "-----------------------------------------------------------------"

exit 0
