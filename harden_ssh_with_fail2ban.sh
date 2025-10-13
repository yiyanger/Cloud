#!/bin/bash

# 一键配置fail2ban永久封禁SSH失败IP脚本
# 使用方法：sudo bash ssh-permanent-ban.sh

set -e

echo "=== Fail2Ban SSH永久封禁配置脚本 ==="

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或以root用户运行此脚本"
    exit 1
fi

# 检测系统类型并安装fail2ban
echo "正在安装fail2ban..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y fail2ban
elif command -v yum &> /dev/null; then
    yum install -y fail2ban
elif command -v dnf &> /dev/null; then
    dnf install -y fail2ban
else
    echo "不支持的包管理器，请手动安装fail2ban"
    exit 1
fi

# 创建自定义配置文件
echo "正在配置fail2ban规则..."
cat > /etc/fail2ban/jail.d/ssh-permanent-ban.conf << 'EOF'
[sshd]
# 启用此规则
enabled = true

# 监控的端口
port    = ssh

# 日志路径
logpath = %(sshd_log)s

# 5分钟内最多允许的失败次数
maxretry = 3

# 检测时间窗口（5分钟=300秒）
findtime = 300

# 封禁时间：-1表示永久封禁
bantime = -1

# 封禁动作（封禁所有端口）
action = iptables-allports[name=sshd, protocol=all]

# 可选：忽略本地IP
# ignoreip = 127.0.0.1/8 ::1
EOF

# 重启fail2ban服务
echo "正在启动fail2ban服务..."
systemctl enable fail2ban
systemctl restart fail2ban

# 等待服务启动
sleep 3

# 检查服务状态
if systemctl is-active --quiet fail2ban; then
    echo "✓ Fail2Ban服务运行正常"
else
    echo "✗ Fail2Ban服务启动失败，请检查日志"
    exit 1
fi

# 显示配置信息
echo ""
echo "=== 配置完成 ==="
echo "✓ Fail2Ban已成功配置"
echo "✓ 规则：5分钟内SSH登录失败3次，IP将被永久封禁"
echo "✓ 封禁范围：所有端口"
echo ""
echo "常用命令："
echo "查看被封禁IP: fail2ban-client status sshd"
echo "解封特定IP: fail2ban-client set sshd unbanip IP地址"
echo "查看fail2ban日志: tail -f /var/log/fail2ban.log"
echo ""
echo "注意：请确保您不会意外锁定自己！"
