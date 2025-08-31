#!/bin/bash

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
CONFIG_MODE=""
USER_PUBLIC_KEY=""
PASSWORD_AUTH_DISABLED=false

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

# 添加用户公钥
add_user_public_key() {
    log_info "添加用户SSH公钥..."
    
    echo "请选择添加公钥的方式:"
    echo "1) 直接粘贴公钥内容"
    echo "2) 从文件路径读取公钥"
    read -p "请选择 (1-2): " input_method
    
    local public_key_content=""
    
    case $input_method in
        1)
            echo
            log_info "请粘贴您的SSH公钥内容 (通常以ssh-rsa, ssh-ed25519, 或 ecdsa-sha2- 开头):"
            echo "输入完成后按回车，然后输入 'END' 并按回车结束输入:"
            echo
            
            while IFS= read -r line; do
                if [[ "$line" == "END" ]]; then
                    break
                fi
                public_key_content+="$line"$'\n'
            done
            
            # 移除末尾的换行符
            public_key_content=$(echo "$public_key_content" | sed 's/[[:space:]]*$//')
            ;;
        2)
            read -p "请输入公钥文件的完整路径: " key_file_path
            
            if [[ ! -f "$key_file_path" ]]; then
                log_error "文件不存在: $key_file_path"
                return 1
            fi
            
            public_key_content=$(cat "$key_file_path")
            ;;
        *)
            log_error "无效选择"
            return 1
            ;;
    esac
    
    # 验证公钥格式
    if [[ ! "$public_key_content" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-) ]]; then
        log_error "无效的SSH公钥格式"
        log_info "公钥应该以 ssh-rsa, ssh-ed25519, 或 ecdsa-sha2- 开头"
        return 1
    fi
    
    # 保存公钥内容供后续使用
    USER_PUBLIC_KEY="$public_key_content"
    log_success "公钥内容已获取"
    
    # 显示公钥信息
    local key_type=$(echo "$public_key_content" | awk '{print $1}')
    local key_comment=$(echo "$public_key_content" | awk '{print $3}')
    log_info "密钥类型: $key_type"
    if [[ -n "$key_comment" ]]; then
        log_info "密钥注释: $key_comment"
    fi
}

# 配置SSH密钥认证
setup_ssh_key_auth() {
    log_info "配置SSH密钥认证..."
    
    # 确保root用户的.ssh目录存在
    sudo mkdir -p /root/.ssh
    sudo chmod 700 /root/.ssh
    
    # 将用户公钥添加到root用户的authorized_keys
    if [[ -n "$USER_PUBLIC_KEY" ]]; then
        # 检查是否已存在authorized_keys文件
        if [[ -f /root/.ssh/authorized_keys ]]; then
            # 检查公钥是否已存在
            if sudo grep -Fq "$USER_PUBLIC_KEY" /root/.ssh/authorized_keys; then
                log_warning "公钥已存在于authorized_keys中"
            else
                echo "$USER_PUBLIC_KEY" | sudo tee -a /root/.ssh/authorized_keys > /dev/null
                log_success "公钥已添加到authorized_keys"
            fi
        else
            echo "$USER_PUBLIC_KEY" | sudo tee /root/.ssh/authorized_keys > /dev/null
            log_success "已创建authorized_keys并添加公钥"
        fi
        
        sudo chmod 600 /root/.ssh/authorized_keys
        sudo chown root:root /root/.ssh/authorized_keys
        
        log_success "SSH密钥认证配置完成"
    else
        log_error "未找到用户公钥内容"
        exit 1
    fi
}

# 配置SSH密钥认证相关设置
configure_ssh_key_settings() {
    local config_file="/etc/ssh/sshd_config"
    
    log_info "配置SSH密钥认证设置..."
    
    # 启用公钥认证
    if grep -q "^#*PubkeyAuthentication" "$config_file"; then
        sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$config_file"
        log_success "已启用PubkeyAuthentication"
    else
        echo "PubkeyAuthentication yes" | sudo tee -a "$config_file" > /dev/null
        log_success "已添加PubkeyAuthentication yes配置"
    fi
    
    # 设置AuthorizedKeysFile
    if grep -q "^#*AuthorizedKeysFile" "$config_file"; then
        sudo sed -i 's/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' "$config_file"
        log_success "已配置AuthorizedKeysFile"
    else
        echo "AuthorizedKeysFile .ssh/authorized_keys" | sudo tee -a "$config_file" > /dev/null
        log_success "已添加AuthorizedKeysFile配置"
    fi
}

# 询问是否禁用密码认证
ask_disable_password_auth() {
    echo
    log_warning "安全建议: 配置密钥认证后，建议禁用密码认证以提高安全性"
    read -p "是否禁用密码认证？(推荐选择y) (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local config_file="/etc/ssh/sshd_config"
        sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$config_file"
        log_success "已禁用密码认证，现在只能使用密钥登录"
        PASSWORD_AUTH_DISABLED=true
    else
        log_info "保持密码认证启用状态"
        PASSWORD_AUTH_DISABLED=false
    fi
}

# 显示密钥信息
show_key_info() {
    if [[ -n "$USER_PUBLIC_KEY" ]]; then
        echo
        log_success "=== SSH密钥信息 ==="
        echo -e "${GREEN}已配置的公钥:${NC}"
        echo "$USER_PUBLIC_KEY"
        echo
        echo -e "${YELLOW}使用密钥登录的方法:${NC}"
        echo "  在您的本地机器上使用对应的私钥连接:"
        echo "  ssh -i /path/to/your/private_key root@$(hostname -I | awk '{print $1}')"
        echo
        echo -e "${YELLOW}注意事项:${NC}"
        echo "  1. 确保您的私钥文件权限为 600"
        echo "  2. 私钥文件路径通常为 ~/.ssh/id_rsa 或 ~/.ssh/id_ed25519"
        echo "  3. 如果使用PuTTY，需要将私钥转换为.ppk格式"
        echo
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
    local permit_root_value="yes"
    
    log_info "修改SSH配置文件..."
    
    # 根据配置模式决定PermitRootLogin的值
    if [[ "$CONFIG_MODE" == "key_only" ]]; then
        permit_root_value="prohibit-password"
        log_info "仅密钥模式：设置PermitRootLogin为prohibit-password"
    else
        permit_root_value="yes"
        log_info "密码模式：设置PermitRootLogin为yes"
    fi
    
    # 创建临时文件
    local temp_file=$(mktemp)
    
    # 处理PermitRootLogin配置
    if grep -q "^#*PermitRootLogin" "$config_file"; then
        # 如果存在该配置项，则修改它
        sudo sed "s/^#*PermitRootLogin.*/PermitRootLogin $permit_root_value/" "$config_file" > "$temp_file"
        sudo cp "$temp_file" "$config_file"
        log_success "已修改PermitRootLogin为$permit_root_value"
    else
        # 如果不存在，则添加
        echo "PermitRootLogin $permit_root_value" | sudo tee -a "$config_file" > /dev/null
        log_success "已添加PermitRootLogin $permit_root_value配置"
    fi
    
    # 处理PasswordAuthentication配置（仅在非仅密钥模式下启用）
    if [[ "$CONFIG_MODE" != "key_only" ]]; then
        if grep -q "^#*PasswordAuthentication" "$config_file"; then
            # 如果存在该配置项，则修改它
            sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$config_file"
            log_success "已修改PasswordAuthentication为yes"
        else
            # 如果不存在，则添加
            echo "PasswordAuthentication yes" | sudo tee -a "$config_file" > /dev/null
            log_success "已添加PasswordAuthentication yes配置"
        fi
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
    
    if [[ "$PASSWORD_AUTH_DISABLED" == "true" ]]; then
        echo -e "  ${BLUE}认证方式:${NC} 仅SSH密钥"
    else
        echo -e "  ${BLUE}认证方式:${NC} 密码 + SSH密钥"
        echo -e "  ${BLUE}密码:${NC} 刚才设置的root密码"
    fi
    
    echo
    echo -e "${YELLOW}安全提示:${NC}"
    echo "  1. 请确保设置了强密码"
    echo "  2. 建议配置防火墙规则"
    if [[ "$PASSWORD_AUTH_DISABLED" != "true" ]]; then
        echo "  3. 考虑使用SSH密钥认证替代密码认证"
    fi
    echo "  4. 定期更新系统和SSH服务"
    echo "  5. 妥善保管SSH私钥文件"
    echo
}

# 显示配置选择菜单
show_config_menu() {
    echo -e "${BLUE}=== 配置选择 ===${NC}"
    echo "请选择要执行的配置:"
    echo "1) 仅配置密码登录 (基础配置)"
    echo "2) 仅配置SSH密钥登录 (推荐) - 使用您的公钥"
    echo "3) 同时配置密码和SSH密钥登录 (完整配置)"
    echo "4) 退出脚本"
    echo
    read -p "请选择 (1-4): " config_choice
    echo
    
    case $config_choice in
        1)
            CONFIG_MODE="password_only"
            log_info "选择: 仅配置密码登录"
            ;;
        2)
            CONFIG_MODE="key_only"
            log_info "选择: 仅配置SSH密钥登录"
            ;;
        3)
            CONFIG_MODE="both"
            log_info "选择: 同时配置密码和SSH密钥登录"
            ;;
        4)
            log_info "脚本已退出"
            exit 0
            ;;
        *)
            log_error "无效选择，默认使用完整配置"
            CONFIG_MODE="both"
            ;;
    esac
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
    echo -e "${BLUE}=== Ubuntu Root用户登录配置脚本 (增强版) ===${NC}"
    echo
    
    # 安全警告
    show_security_warning
    
    # 显示配置选择菜单
    show_config_menu
    
    # 系统检查
    log_info "开始系统检查..."
    check_root
    check_ubuntu
    check_sudo
    
    # 备份SSH配置文件
    backup_ssh_config
    
    # 根据选择执行不同的配置
    log_info "开始配置过程..."
    
    case $CONFIG_MODE in
        "password_only")
            log_info "执行密码登录配置..."
            set_root_password
            modify_ssh_config
            ;;
        "key_only")
            log_info "执行SSH密钥登录配置..."
            set_root_password  # 仍需设置密码用于sudo等操作
            add_user_public_key
            setup_ssh_key_auth
            configure_ssh_key_settings
            modify_ssh_config
            # 对于仅密钥模式，自动禁用密码认证
            sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            PASSWORD_AUTH_DISABLED=true
            log_success "已配置仅密钥登录模式"
            ;;
        "both")
            log_info "执行完整配置..."
            set_root_password
            add_user_public_key
            setup_ssh_key_auth
            configure_ssh_key_settings
            modify_ssh_config
            ask_disable_password_auth
            ;;
    esac
    
    # 验证配置并重启服务
    verify_ssh_config
    restart_ssh_service
    
    # 显示结果
    show_connection_info
    show_key_info
    
    log_success "所有配置已完成！"
}

# 错误处理
trap 'log_error "脚本执行过程中发生错误，请检查上述输出信息"' ERR

# 执行主函数
main "$@"
