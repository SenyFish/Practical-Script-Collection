# Ubuntu Root用户登录配置脚本 (增强版)

基于CSDN文章 [Ubuntu 系统如何使用 root 用户登录实例](https://blog.csdn.net/thebestleo/article/details/123451471) 创建的自动化配置脚本，现已增加SSH密钥认证功能。

## 🚀 新增功能

### SSH密钥认证支持
- ✅ **多种密钥类型** - 支持RSA、ED25519、ECDSA密钥
- ✅ **自动密钥生成** - 一键生成高强度SSH密钥对
- ✅ **智能配置** - 自动配置SSH服务器密钥认证
- ✅ **安全选项** - 可选择禁用密码认证，仅使用密钥登录
- ✅ **灵活配置** - 支持仅密码、仅密钥、或混合认证模式

## 功能说明

此脚本可以自动完成以下操作：

### 基础功能
1. **设置root密码** - 为root用户设置登录密码
2. **修改SSH配置** - 启用root用户SSH登录权限
3. **启用密码认证** - 允许使用密码进行SSH认证
4. **重启SSH服务** - 使配置生效
5. **安全检查** - 包含多项安全验证和错误处理

### 新增密钥功能
6. **SSH密钥生成** - 支持RSA(4096位)、ED25519、ECDSA(256位)
7. **密钥配置** - 自动配置公钥认证和authorized_keys
8. **安全增强** - 可选择禁用密码认证，提升安全性
9. **详细指导** - 提供完整的密钥使用说明

## 使用方法

### 1. 下载脚本
```bash
# 使用wget下载
wget https://raw.githubusercontent.com/SenyFish/Practical-Script-Collection/main/enable_root_login.sh

# 或使用curl下载
curl -O https://raw.githubusercontent.com/SenyFish/Practical-Script-Collection/main/enable_root_login.sh
```

### 2. 添加执行权限
```bash
chmod +x enable_root_login.sh
```

### 3. 运行脚本
```bash
./enable_root_login.sh
```

**注意：请使用普通用户（非root）运行此脚本，脚本会自动请求sudo权限。**

## 配置选项

脚本运行时会提供以下配置选择：

### 1️⃣ 仅配置密码登录 (基础配置)
- 设置root密码
- 启用SSH密码认证
- 适合快速测试环境

### 2️⃣ 仅配置SSH密钥登录 (推荐)
- 生成SSH密钥对
- 配置密钥认证
- 禁用密码认证
- **最安全的选项**

### 3️⃣ 同时配置密码和SSH密钥登录 (完整配置)
- 设置root密码
- 生成SSH密钥对
- 同时支持密码和密钥认证
- 可选择是否禁用密码认证

## SSH密钥类型选择

### RSA (4096位) - 推荐
- 兼容性最好
- 广泛支持
- 安全性高

### ED25519 - 更安全，更快
- 现代加密算法
- 性能优异
- 密钥文件更小

### ECDSA (256位)
- 椭圆曲线加密
- 平衡性能和安全性

## 脚本特性

### 🔒 安全特性
- **权限检查** - 确保不以root身份运行脚本
- **系统检测** - 验证是否为Ubuntu系统
- **配置备份** - 自动备份原始SSH配置文件
- **语法验证** - 验证SSH配置文件语法正确性
- **安全警告** - 提醒用户潜在的安全风险
- **密钥权限** - 自动设置正确的文件权限

### 🎨 用户体验
- **彩色输出** - 使用不同颜色区分信息类型
- **详细日志** - 每个步骤都有清晰的状态反馈
- **交互菜单** - 友好的配置选择界面
- **错误处理** - 完善的错误捕获和处理机制
- **交互确认** - 重要操作前需要用户确认

### 🛡️ 错误处理
- **密码验证** - 确保密码长度和一致性
- **服务检查** - 自动检测SSH服务名称
- **回滚机制** - 配置文件备份便于恢复
- **密钥检查** - 验证密钥生成和配置状态

## 执行流程

1. **安全警告阶段**
   - 显示安全风险提示
   - 用户确认继续

2. **配置选择阶段**
   - 显示配置选项菜单
   - 用户选择配置模式

3. **系统检查阶段**
   - 检查运行用户权限
   - 验证操作系统类型
   - 确认sudo权限

4. **配置执行阶段**
   - 根据选择执行相应配置
   - 密码设置/密钥生成
   - SSH服务配置

5. **服务重启阶段**
   - 验证配置文件语法
   - 重启SSH服务
   - 验证服务状态

6. **结果展示阶段**
   - 显示连接信息
   - 显示密钥信息
   - 提供使用指导

## 使用SSH密钥登录

### Windows用户
```cmd
# 使用PuTTY
# 1. 下载私钥文件到本地
# 2. 使用PuTTYgen转换密钥格式
# 3. 在PuTTY中配置私钥路径

# 使用OpenSSH (Windows 10+)
ssh -i C:\path\to\private_key root@服务器IP
```

### Linux/Mac用户
```bash
# 下载私钥文件到本地
scp user@server:~/.ssh/id_rsa_root ~/.ssh/

# 设置正确权限
chmod 600 ~/.ssh/id_rsa_root

# 使用密钥登录
ssh -i ~/.ssh/id_rsa_root root@服务器IP
```

## 安全警告

⚠️ **重要安全提示**

启用root用户SSH登录会增加系统安全风险！建议：

### 密码安全
1. **设置强密码** - 使用复杂密码组合
2. **定期更换** - 定期更新密码

### 密钥安全
1. **妥善保管私钥** - 私钥文件不要泄露
2. **设置密钥密码** - 为私钥设置额外密码保护
3. **定期轮换** - 定期生成新的密钥对

### 系统安全
1. **配置防火墙** - 限制SSH访问来源
2. **更改默认端口** - 考虑更改SSH默认端口
3. **监控日志** - 定期检查SSH登录日志
4. **定期更新** - 保持系统和SSH服务最新版本
5. **仅在必要时使用** - 测试环境或特殊需求场景

## 故障排除

### 常见问题

**Q: 脚本提示"请不要以root用户身份运行此脚本"**
A: 请切换到普通用户账户运行脚本，脚本会自动请求sudo权限。

**Q: SSH服务重启失败**
A: 检查SSH配置文件语法，查看系统日志获取详细错误信息。

**Q: 无法使用密钥连接**
A: 检查私钥文件权限(600)，确认公钥已正确添加到authorized_keys。

**Q: 密钥生成失败**
A: 确保系统已安装openssh-client，检查磁盘空间是否充足。

### 恢复原始配置

如果需要恢复原始SSH配置：

```bash
# 查找备份文件
sudo ls -la /etc/ssh/sshd_config.backup.*

# 恢复配置（替换为实际的备份文件名）
sudo cp /etc/ssh/sshd_config.backup.YYYYMMDD_HHMMSS /etc/ssh/sshd_config

# 重启SSH服务
sudo systemctl restart ssh
```

### 重新生成密钥

如果需要重新生成密钥：

```bash
# 删除现有密钥
rm -f ~/.ssh/id_*_root*

# 重新运行脚本
./enable_root_login.sh
```

## 技术细节

### 支持的系统
- Ubuntu 18.04+
- Debian 10+
- 其他基于Debian的发行版（可能需要调整）

### 修改的配置项
- `PermitRootLogin yes` - 允许root用户登录
- `PasswordAuthentication yes/no` - 密码认证开关
- `PubkeyAuthentication yes` - 启用公钥认证
- `AuthorizedKeysFile .ssh/authorized_keys` - 指定公钥文件位置

### 生成的文件
- **私钥文件**: `~/.ssh/id_[type]_root`
- **公钥文件**: `~/.ssh/id_[type]_root.pub`
- **授权密钥**: `/root/.ssh/authorized_keys`
- **配置备份**: `/etc/ssh/sshd_config.backup.YYYYMMDD_HHMMSS`

### 文件权限
- 私钥文件: 600 (仅所有者可读写)
- 公钥文件: 644 (所有者可读写，其他人可读)
- .ssh目录: 700 (仅所有者可访问)
- authorized_keys: 600 (仅所有者可读写)

## 更新日志

### v2.0 (当前版本)
- ✅ 新增SSH密钥认证支持
- ✅ 支持多种密钥类型(RSA/ED25519/ECDSA)
- ✅ 添加配置选择菜单
- ✅ 增强安全选项
- ✅ 改进用户界面和错误处理

### v1.0
- ✅ 基础密码认证配置
- ✅ SSH服务配置
- ✅ 安全检查和备份

## 许可证

本脚本基于CSDN文章内容创建，遵循开源精神，仅供学习和研究使用。

## 参考资料

- [Ubuntu 系统如何使用 root 用户登录实例](https://blog.csdn.net/thebestleo/article/details/123451471)
- [OpenSSH Server Configuration](https://www.openssh.com/manual.html)
- [Ubuntu Server Guide - OpenSSH Server](https://ubuntu.com/server/docs/service-openssh)
- [SSH Key Types and Security](https://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys)
