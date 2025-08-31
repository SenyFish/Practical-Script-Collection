#!/bin/bash

# Ubuntu系统启用root用户登录脚本
# 基于CSDN文章: https://blog.csdn.net/thebestleo/article/details/123451471
# 作者: AI Assistant
# 功能: 自动配置Ubuntu系统允许root用户SSH登录

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[信息]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[成功]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 检查是否为root用户运行
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "请不要以root用户身份运行此脚本！"
        log_info "请使用普通用户运行: ./enable_root_login.sh"
        exit 1
    fi
}

# 检查是否为Ubuntu系统
check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log_warning "检测到非Ubuntu系统，脚本可能不完全适用"
        read -p "是否继续执行？(y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "脚本已取消"
            exit 0
        fi
    else
        log_success "检测到Ubuntu系统"
    fi
}

# 检查sudo权限
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log_info "需要sudo权限来执行系统配置"
        sudo -v || {
            log_error "无法获取sudo权限"
            exit 1
        }
    fi
    log_success "sudo权限验证通过"
}

# 设置root密码
set_root_password() {
    log_info "开始设置root用户密码..."
    
    while true; do
        echo -n "请输入root用户的新密码: "
        read -s password1
        echo
        
        if [[ ${#password1} -lt 6 ]]; then
            log_error "密码长度至少6位，请重新输入"
            continue
        fi
        
        echo -n "请再次确认密码: "
        read -s password2
        echo
        
        if [[ "$password1" != "$password2" ]]; then
            log_error "两次输入的密码不一致，请重新输入"
            continue
        fi
        
        break
    done
    
    # 设置root密码
    echo "root:$password1" | sudo chpasswd
    
    if [[ $? -eq 0 ]]; then
        log_success "root密码设置成功"
    else
        log_error "root密码设置失败"
        exit 1
    fi
}

# 备份SSH配置文件
backup_ssh_config() {
    local config_file="/etc/ssh/sshd_config"
    local backup_file="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    
    log_info "备份SSH配置文件..."
    sudo cp "$config_file" "$backup_file"
    
    if [[ $? -eq 0 ]]; then
        log_success "SSH配置文件已备份到: $backup_file"
    else
        log_error "备份SSH配置文件失败"
        exit 1
    fi
}

# 修改SSH配置
modify_ssh_config() {
    local config_file="/etc/ssh/sshd_config"
    
    log_info "修改SSH配置文件..."
    
    # 创建临时文件
    local temp_file=$(mktemp)
    
    # 处理PermitRootLogin配置
    if grep -q "^#*PermitRootLogin" "$config_file"; then
        # 如果存在该配置项，则修改它
        sudo sed 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$config_file" > "$temp_file"
        sudo cp "$temp_file" "$config_file"
        log_success "已修改PermitRootLogin为yes"
    else
        # 如果不存在，则添加
        echo "PermitRootLogin yes" | sudo tee -a "$config_file" > /dev/null
        log_success "已添加PermitRootLogin yes配置"
    fi
    
    # 处理PasswordAuthentication配置
    if grep -q "^#*PasswordAuthentication" "$config_file"; then
        # 如果存在该配置项，则修改它
        sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$config_file"
        log_success "已修改PasswordAuthentication为yes"
    else
        # 如果不存在，则添加
        echo "PasswordAuthentication yes" | sudo tee -a "$config_file" > /dev/null
        log_success "已添加PasswordAuthentication yes配置"
    fi
    
    # 清理临时文件
    rm -f "$temp_file"
}

# 验证SSH配置
verify_ssh_config() {
    log_info "验证SSH配置文件语法..."
    
    if sudo sshd -t; then
        log_success "SSH配置文件语法正确"
    else
        log_error "SSH配置文件语法错误，请检查配置"
        exit 1
    fi
}

# 重启SSH服务
restart_ssh_service() {
    log_info "重启SSH服务..."
    
    # 尝试不同的服务名称
    if systemctl is-active --quiet ssh; then
        sudo systemctl restart ssh
        service_name="ssh"
    elif systemctl is-active --quiet sshd; then
        sudo systemctl restart sshd
        service_name="sshd"
    else
        log_error "无法找到SSH服务"
        exit 1
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet "$service_name"; then
        log_success "SSH服务重启成功"
    else
        log_error "SSH服务重启失败"
        exit 1
    fi
}

# 显示连接信息
show_connection_info() {
    local ip_address=$(hostname -I | awk '{print $1}')
    
    echo
    log_success "=== 配置完成 ==="
    echo -e "${GREEN}现在可以使用以下信息登录:${NC}"
    echo -e "  ${BLUE}用户名:${NC} root"
    echo -e "  ${BLUE}IP地址:${NC} $ip_address"
    echo -e "  ${BLUE}端口:${NC} 22 (默认)"
    echo -e "  ${BLUE}密码:${NC} 刚才设置的root密码"
    echo
    echo -e "${YELLOW}安全提示:${NC}"
    echo "  1. 请确保设置了强密码"
    echo "  2. 建议配置防火墙规则"
    echo "  3. 考虑使用SSH密钥认证替代密码认证"
    echo "  4. 定期更新系统和SSH服务"
    echo
}

# 安全警告
show_security_warning() {
    echo -e "${RED}=== 安全警告 ===${NC}"
    echo "启用root用户SSH登录会增加系统安全风险！"
    echo "建议仅在测试环境或必要情况下使用。"
    echo
    read -p "您确定要继续吗？(y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "脚本已取消"
        exit 0
    fi
}

# 主函数
main() {
    echo -e "${BLUE}=== Ubuntu Root用户登录配置脚本 ===${NC}"
    echo "基于文章: https://blog.csdn.net/thebestleo/article/details/123451471"
    echo
    
    # 安全警告
    show_security_warning
    
    # 系统检查
    log_info "开始系统检查..."
    check_root
    check_ubuntu
    check_sudo
    
    # 执行配置
    log_info "开始配置过程..."
    set_root_password
    backup_ssh_config
    modify_ssh_config
    verify_ssh_config
    restart_ssh_service
    
    # 显示结果
    show_connection_info
    
    log_success "所有配置已完成！"
}

# 错误处理
trap 'log_error "脚本执行过程中发生错误，请检查上述输出信息"' ERR

# 执行主函数
main "$@"
