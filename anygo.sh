#!/bin/bash

Red="\033[31m"
Green="\033[32m"
Yellow="\033[33m"
Blue="\033[34m"
Nc="\033[0m"
Red_globa="\033[41;37m"
Green_globa="\033[42;37m"
Yellow_globa="\033[43;37m"
Blue_globa="\033[44;37m"
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

work_dir="/var/anygo"
anygo_bin="$work_dir/anygo"
config_path="$work_dir/config.yaml"
service_path="/lib/systemd/system/anygo.service"
raw_conf_path="$work_dir/rawconf"
version_file="$work_dir/version"
github_repo="bryet/anygo"

check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Nc} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

check_arch() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|x64|amd64)
            arch="amd64"
            ;;
        i*86|x86)
            arch="386"
            ;;
        aarch64|arm64|armv8*)
            arch="arm64"
            ;;
        armv7*)
            arch="armv7"
            ;;
        armv6*)
            arch="armv6"
            ;;
        *)
            echo -e "${Error} 检测到您的架构不支持: $arch"
            exit 1
            ;;
    esac
    echo -e "${Info} 检测到架构: ${Green}$arch${Nc}"
}

check_release() {
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo $VERSION_ID | cut -d. -f1,2 2>/dev/null)

    if [[ "${release}" == "ol" ]]; then
        release=oracle
    elif [[ ! "${release}" =~ ^(kali|centos|ubuntu|fedora|debian|almalinux|rocky|alpine|oracle|arch|manjaro|opensuse-tumbleweed)$ ]]; then
        echo -e "${Error} 抱歉，此脚本不支持您的操作系统: $release"
        echo -e "${Info} 支持的系统: Ubuntu, Debian, CentOS, Fedora, Kali, AlmaLinux, Rocky, Oracle, Alpine, Arch, Manjaro, OpenSUSE"
        exit 1
    fi
}

check_pmc() {
    check_release
    case "$release" in
        debian|ubuntu|kali)
            updates="apt update -y"
            installs="apt install -y"
            apps=("wget" "curl" "tar")
            ;;
        almalinux|centos|rocky|oracle|fedora)
            updates="dnf update -y"
            installs="dnf install -y"
            apps=("wget" "curl" "tar")
            ;;
        opensuse-tumbleweed)
            updates="zypper refresh"
            installs="zypper install -y"
            apps=("wget" "curl" "tar")
            ;;
        arch|manjaro|parch)
            updates="pacman -Syu"
            installs="pacman -Syu --noconfirm"
            apps=("wget" "curl" "tar")
            ;;
        alpine)
            updates="apk update"
            installs="apk add"
            apps=("wget" "curl" "tar")
            ;;
        *)
            echo -e "${Error} 不支持的发行版: $release"
            exit 1
            ;;
    esac
}

install_base() {
    check_pmc
    cmds=("wget" "curl" "tar")
    echo -e "${Info} 你的系统是 ${Red}$release $os_version${Nc}"
    echo

    for i in "${!cmds[@]}"; do
        if ! command -v "${cmds[i]}" &>/dev/null; then
            DEPS+=("${apps[i]}")
        fi
    done

    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${DEPS[*]}${Nc} 请稍后..."
        $updates
        $installs "${DEPS[@]}"
    else
        echo -e "${Info} 所有依赖已存在，不需要额外安装。"
    fi
}

check_new_ver() {
    new_ver=$(curl -Ls "https://api.github.com/repos/${github_repo}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z ${new_ver} ]]; then
        echo -e "${Error} anygo 最新版本获取失败，请检查网络"
        exit 1
    else
        echo -e "${Info} anygo 目前最新版本为 ${Green}${new_ver}${Nc}"
    fi
}

check_installed_ver() {
    if [ -f "$version_file" ]; then
        installed_ver=$(cat "$version_file")
        echo -e "${Info} 当前安装的 anygo 版本: ${Green}${installed_ver}${Nc}"
    else
        installed_ver="未安装"
    fi
}

download_anygo() {
    local ver=$1
    local dl_url="https://github.com/${github_repo}/releases/download/${ver}/anygo-linux-${arch}.tar.gz"
    local tarball="anygo-linux-${arch}.tar.gz"
    echo -e "${Info} 正在从 ${Blue}${dl_url}${Nc} 下载 anygo..."
    mkdir -p "$work_dir"
    cd "$work_dir"
    if ! wget --no-check-certificate -q --show-progress "$dl_url" -O "$tarball"; then
        echo -e "${Error} 下载失败，请检查网络或版本号"
        rm -f "$tarball"
        exit 1
    fi
    tar -xzf "$tarball"
    rm -f "$tarball"
    echo "$ver" >"$version_file"
}

Install_anygo() {
    check_root
    install_base
    check_arch
    check_new_ver

    echo -e "${Tip} 即将安装 anygo v${new_ver}"
    download_anygo "$new_ver"

    # Stop existing service
    systemctl stop anygo 2>/dev/null

    # Install binary (already extracted in work_dir)
    chmod +x "$anygo_bin"

    # Install service from existing template
    if [ -f "$work_dir/anygo.service" ]; then
        cp -f "$work_dir/anygo.service" "$service_path"
    else
        echo -e "${Error} 找不到 anygo.service 模板文件"
        exit 1
    fi

    # Copy default config if not exists
    if [ ! -f "$config_path" ] && [ -f "$work_dir/config.yaml" ]; then
        cp -f "$work_dir/config.yaml" "$config_path"
    fi

    # Create rawconf if not exists
    if [ ! -f "$raw_conf_path" ]; then
        touch "$raw_conf_path"
    fi

    systemctl daemon-reload
    systemctl enable anygo

    if [ -f "$anygo_bin" ] && [ -f "$service_path" ] && [ -f "$config_path" ]; then
        echo -e "${Info} anygo ${new_ver} 安装成功！"
        echo -e "${Tip} 使用 ${Green}systemctl start anygo${Nc} 启动服务"
    else
        echo -e "${Error} anygo 安装失败，请检查"
        exit 1
    fi
}

Update_anygo() {
    check_root
    check_arch

    if [ ! -f "$anygo_bin" ]; then
        echo -e "${Error} anygo 尚未安装，请先安装"
        return
    fi

    check_installed_ver
    check_new_ver

    if [ "$installed_ver" == "$new_ver" ]; then
        echo -e "${Info} 已经是最新版本 v${new_ver}，无需更新"
        read -e -p "是否强制重新安装？[y/n]:" force_update
        [[ -z ${force_update} ]] && force_update="n"
        if [[ ${force_update} != [Yy] ]]; then
            return
        fi
    fi

    echo -e "${Tip} 即将更新 anygo: v${installed_ver} -> v${new_ver}"
    read -e -p "确认更新？[y/n]:" confirm
    [[ -z ${confirm} ]] && confirm="n"
    if [[ ${confirm} != [Yy] ]]; then
        echo -e "${Info} 已取消更新"
        return
    fi

    # Backup config to /tmp before update
    cp -f "$config_path" /tmp/config.yaml 2>/dev/null
    cp -f "$raw_conf_path" /tmp/rawconf 2>/dev/null

    download_anygo "$new_ver"
    systemctl stop anygo 2>/dev/null
    chmod +x "$anygo_bin"

    # Restore config from /tmp
    cp -f /tmp/config.yaml "$config_path" 2>/dev/null
    cp -f /tmp/rawconf "$raw_conf_path" 2>/dev/null
    rm -f /tmp/config.yaml /tmp/rawconf

    systemctl start anygo 2>/dev/null

    echo -e "${Info} anygo 已更新至 v${new_ver}"
}

Uninstall_anygo() {
    check_root
    echo -e "${Yellow}================================${Nc}"
    echo -e "${Red}警告: 即将卸载 anygo!${Nc}"
    echo -e "${Yellow}================================${Nc}"
    read -e -p "确认卸载？[y/n]:" confirm
    [[ -z ${confirm} ]] && confirm="n"
    if [[ ${confirm} != [Yy] ]]; then
        echo -e "${Info} 已取消卸载"
        return
    fi

    systemctl stop anygo 2>/dev/null
    systemctl disable anygo 2>/dev/null
    rm -f "$anygo_bin"
    rm -f "$service_path"
    rm -rf "$work_dir"
    systemctl daemon-reload
    echo -e "${Info} anygo 已成功卸载"
}

Start_anygo() {
    check_root
    if [ ! -f "$service_path" ]; then
        echo -e "${Error} anygo 服务文件不存在，请先安装"
        return
    fi
    systemctl start anygo
    if systemctl is-active --quiet anygo; then
        echo -e "${Info} anygo 已启动"
    else
        echo -e "${Error} anygo 启动失败，请检查: systemctl status anygo"
    fi
}

Stop_anygo() {
    check_root
    systemctl stop anygo 2>/dev/null
    echo -e "${Info} anygo 已停止"
}

Restart_anygo() {
    check_root
    if [ ! -f "$service_path" ]; then
        echo -e "${Error} anygo 服务文件不存在，请先安装"
        return
    fi
    systemctl restart anygo
    if systemctl is-active --quiet anygo; then
        echo -e "${Info} anygo 已重启"
    fi
}

Status_anygo() {
    if systemctl is-active --quiet anygo 2>/dev/null; then
        echo -e "${Info} anygo 运行状态: ${Green}运行中${Nc}"
        systemctl status anygo --no-pager -l 2>/dev/null || true
    else
        echo -e "${Info} anygo 运行状态: ${Red}未运行${Nc}"
    fi
}

View_log() {
    local log_file="$work_dir/anygo.log"
    if [ -f "$log_file" ]; then
        echo -e "${Info} 按 ${Red}Ctrl+C${Nc} 退出日志查看"
        tail -f "$log_file"
    else
        echo -e "${Tip} 日志文件尚未生成，尝试查看 systemd 日志..."
        journalctl -u anygo -f --no-pager 2>/dev/null || echo -e "${Error} 暂无日志"
    fi
}

# ============ Config Management ============

# rawconf format: mode|listen|remote|sni|password|max_conns|insecure|cert|key|remarks
# mode: client / server

read_tunnel_mode() {
    echo -e "-----------------------------------"
    echo -e "请选择隧道模式: "
    echo -e "-----------------------------------"
    echo -e "[1] ${Green}客户端模式${Nc} (加密转发)"
    echo -e "    说明: 监听本地端口，通过TLS隧道转发到远程服务器"
    echo -e "    适用于: 国内中转机 -> 境外服务器"
    echo -e "-----------------------------------"
    echo -e "[2] ${Green}服务端模式${Nc} (解密接收)"
    echo -e "    说明: 接收TLS加密流量，解密后转发到目标地址"
    echo -e "    适用于: 境外服务器接收并解密 -> 转发到本地代理"
    echo -e "-----------------------------------"
    read -p "请选择 [1-2]: " tunnel_mode
    case "$tunnel_mode" in
        1) flag_mode="client" ;;
        2) flag_mode="server" ;;
        *) echo -e "${Error} 选择错误"; exit 1 ;;
    esac
}

read_listen() {
    echo -e "-----------------------------------"
    echo -e "请输入监听地址和端口: "
    echo -e "示例: ${Green}[::]:44713${Nc} (监听所有IPv6+IPv4)"
    echo -e "示例: ${Green}0.0.0.0:44713${Nc} (监听所有IPv4)"
    echo -e "示例: ${Green}:44713${Nc} (监听所有地址的44713端口)"
    read -p "请输入: " flag_listen
    [[ -z ${flag_listen} ]] && echo -e "${Error} 监听地址不能为空" && exit 1
}

read_remote() {
    echo -e "-----------------------------------"
    echo -e "请输入目标转发地址: "
    if [ "$flag_mode" == "client" ]; then
        echo -e "说明: 境外出口服务器的地址，例如 ${Green}vps.example.com:44713${Nc}"
    else
        echo -e "说明: 解密后要转发到的目标地址，例如 ${Green}127.0.0.1:25256${Nc}"
    fi
    read -p "请输入 [地址:端口]: " flag_remote
    [[ -z ${flag_remote} ]] && echo -e "${Error} 目标地址不能为空" && exit 1
}

read_sni() {
    echo -e "-----------------------------------"
    echo -e "请输入 TLS SNI (伪装域名): "
    echo -e "示例: ${Green}bing.com${Nc}, ${Green}www.microsoft.com${Nc}"
    read -p "请输入: " flag_sni
    [[ -z ${flag_sni} ]] && flag_sni="bing.com"
}

read_password() {
    echo -e "-----------------------------------"
    echo -e "请输入隧道密码 (入口与出口必须一致): "
    read -p "请输入: " flag_password
    [[ -z ${flag_password} ]] && echo -e "${Error} 密码不能为空" && exit 1
}

read_max_conns() {
    echo -e "-----------------------------------"
    echo -e "请输入最大并发连接数 (0或不填表示不限制): "
    read -p "请输入 [默认: 0]: " flag_max_conns
    [[ -z ${flag_max_conns} ]] && flag_max_conns="0"
}

read_insecure() {
    echo -e "-----------------------------------"
    echo -e "是否跳过TLS证书验证? "
    echo -e "${Yellow}注意: 使用自签证书时请选择 y，使用Let's Encrypt等正规证书选择 n${Nc}"
    read -e -p "跳过证书验证？[y/n]:" flag_insecure
    [[ -z ${flag_insecure} ]] && flag_insecure="y"
    if [[ ${flag_insecure} == [Yy] ]]; then
        flag_insecure="true"
    else
        flag_insecure="false"
    fi
}

read_cert() {
    if [ "$flag_mode" == "server" ]; then
        echo -e "-----------------------------------"
        echo -e "请输入TLS证书路径: "
        echo -e "示例: ${Green}/var/anygo/server.crt${Nc}"
        read -p "请输入: " flag_cert
        [[ -z ${flag_cert} ]] && flag_cert=""
        if [ -n "$flag_cert" ]; then
            echo -e "请输入TLS私钥路径: "
            echo -e "示例: ${Green}/var/anygo/server.key${Nc}"
            read -p "请输入: " flag_key
            [[ -z ${flag_key} ]] && flag_key=""
        else
            flag_key=""
        fi
    else
        flag_cert=""
        flag_key=""
    fi
}

read_remarks() {
    echo -e "-----------------------------------"
    echo -e "请输入备注信息 (可选): "
    read -p "请输入: " flag_remarks
    [[ -z ${flag_remarks} ]] && flag_remarks=""
}

write_rawconf() {
    # format: mode|listen|remote|sni|password|max_conns|insecure|cert|key|remarks
    echo "${flag_mode}|${flag_listen}|${flag_remote}|${flag_sni}|${flag_password}|${flag_max_conns}|${flag_insecure}|${flag_cert}|${flag_key}|${flag_remarks}" >>"$raw_conf_path"
}

generate_yaml_config() {
    cat > "$config_path" <<'YAMLHEADER'
log_level: "info"

idle_session_check_interval: "30s"
idle_session_timeout: "60s"
min_idle_session: 2

padding_scheme: |
  stop=8
  0=30-30
  1=100-400
  2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
  3=9-9,500-1000
  4=500-1000
  5=500-1000
  6=500-1000
  7=500-1000

tunnels:
YAMLHEADER

    if [ ! -s "$raw_conf_path" ]; then
        echo "  []" >>"$config_path"
        return
    fi

    local count=0
    while IFS='|' read -r mode listen remote sni password max_conns insecure cert key remarks; do
        [ -z "$mode" ] && continue
        count=$((count + 1))

        cat >>"$config_path" <<TUNNEL
  - listen: "${listen}"
    remote: "${remote}"
    sni: "${sni}"
    password: "${password}"
    max_conns: ${max_conns}
TUNNEL

        if [ "$mode" == "client" ]; then
            echo "    insecure: ${insecure}" >>"$config_path"
        fi
        if [ -n "$cert" ]; then
            echo "    cert: \"${cert}\"" >>"$config_path"
        fi
        if [ -n "$key" ]; then
            echo "    key: \"${key}\"" >>"$config_path"
        fi
        # Add empty line between tunnels
        echo "" >>"$config_path"
    done <"$raw_conf_path"
}

Add_tunnel() {
    check_root
    read_tunnel_mode
    read_listen
    read_remote
    read_sni
    read_password
    read_max_conns
    if [ "$flag_mode" == "client" ]; then
        read_insecure
    else
        flag_insecure="false"
    fi
    read_cert
    read_remarks
    write_rawconf

    generate_yaml_config
    systemctl restart anygo 2>/dev/null
    echo -e "${Info} 隧道配置已添加并生效"
    echo -e "--------------------------------------------------------"
    show_all_conf
}

show_all_conf() {
    echo -e "                      ${Green}Anygo 隧道配置${Nc}"
    echo -e "--------------------------------------------------------"
    echo -e "序号|   模式   |   监听地址    |   目标地址    | SNI | 密码"
    echo -e "--------------------------------------------------------"

    if [ ! -s "$raw_conf_path" ]; then
        echo -e "        ${Yellow}(暂无配置)${Nc}"
        echo -e "--------------------------------------------------------"
        return
    fi

    local i=1
    while IFS='|' read -r mode listen remote sni password max_conns insecure cert key remarks; do
        [ -z "$mode" ] && continue
        if [ "$mode" == "client" ]; then
            mode_str="客户端"
        else
            mode_str="服务端"
        fi
        # Truncate long fields for display
        local display_remote="$remote"
        local display_remarks="$remarks"
        [ -n "$remarks" ] && display_remarks=" [${remarks}]"
        echo -e " $i   | ${mode_str} | ${listen} | ${display_remote} | ${sni} | ${password}${display_remarks}"
        echo -e "--------------------------------------------------------"
        i=$((i + 1))
    done <"$raw_conf_path"
}

Delete_tunnel() {
    check_root
    if [ ! -s "$raw_conf_path" ]; then
        echo -e "${Error} 当前没有任何隧道配置"
        return
    fi

    show_all_conf
    echo ""
    read -p "请输入你要删除的配置编号: " numdelete
    if ! echo "$numdelete" | grep -q '^[0-9]\+$'; then
        echo -e "${Error} 请输入正确的数字"
        return
    fi

    total=$(wc -l <"$raw_conf_path")
    if [ "$numdelete" -gt "$total" ] || [ "$numdelete" -lt 1 ]; then
        echo -e "${Error} 编号超出范围 (1-${total})"
        return
    fi

    sed -i "${numdelete}d" "$raw_conf_path"
    generate_yaml_config
    systemctl restart anygo 2>/dev/null
    echo -e "${Info} 配置已删除，服务已重启"
}

# ============ TLS Certificate ============

Cert_manage() {
    check_root
    echo -e "-----------------------------------"
    echo -e "${Green}[1]${Nc} ACME 一键申请证书 (ZeroSSL)"
    echo -e "${Green}[2]${Nc} 手动上传证书"
    echo -e "${Green}[3]${Nc} 查看证书状态"
    echo -e "${Green}[4]${Nc} 删除自定义证书 (恢复使用内置证书)"
    echo -e "-----------------------------------"
    echo -e "说明: 自定义TLS证书仅用于服务端模式，提高安全性"
    echo -e "      删除证书目录后重启 anygo 将自动使用内置证书"
    read -p "请选择: " numcert

    case "$numcert" in
        1)
            acme_apply
            ;;
        2)
            manual_cert
            ;;
        3)
            cert_status
            ;;
        4)
            remove_cert
            ;;
        *)
            echo -e "${Error} 选择错误"
            ;;
    esac
}

cert_status() {
    if [ -f "$work_dir/server.crt" ] && [ -f "$work_dir/server.key" ]; then
        echo -e "${Info} 自定义证书状态: ${Green}已配置${Nc}"
        echo -e "  证书路径: ${Green}$work_dir/server.crt${Nc}"
        echo -e "  私钥路径: ${Green}$work_dir/server.key${Nc}"
        # Show certificate info
        openssl x509 -in "$work_dir/server.crt" -noout -subject -issuer -dates 2>/dev/null
    else
        echo -e "${Info} 自定义证书状态: ${Yellow}未配置${Nc} (使用内置证书)"
    fi
}

remove_cert() {
    read -e -p "确认删除自定义证书？[y/n]:" confirm
    [[ -z ${confirm} ]] && confirm="n"
    if [[ ${confirm} != [Yy] ]]; then
        echo -e "${Info} 已取消"
        return
    fi
    rm -f "$work_dir/server.crt" "$work_dir/server.key"
    echo -e "${Info} 自定义证书已删除，重启 anygo 后生效"
    read -e -p "是否立即重启？[y/n]:" restart
    if [[ ${restart} == [Yy] ]]; then
        Restart_anygo
    fi
}

acme_apply() {
    check_release
    install_base

    case "$release" in
        debian|ubuntu|kali|alpine)
            $installs socat
            ;;
        almalinux|centos|rocky|oracle|fedora|arch|manjaro)
            $installs socat
            ;;
    esac

    read -p "请输入 ZeroSSL 账户邮箱 (至 zerossl.com 注册): " zeromail
    read -p "请输入解析到本机的域名: " domain

    curl https://get.acme.sh | sh
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server zerossl
    "$HOME"/.acme.sh/acme.sh --register-account -m "${zeromail}" --server zerossl
    echo -e "${Info} ACME 证书申请程序安装成功"

    echo -e "-----------------------------------"
    echo -e "${Green}[1]${Nc} HTTP 申请 (需要80端口未被占用)"
    echo -e "${Green}[2]${Nc} Cloudflare DNS API 申请"
    echo -e "-----------------------------------"
    read -p "请选择申请方式: " certmethod

    if [ "$certmethod" == "1" ]; then
        echo -e "${Tip} 请确认本机 ${Red}80${Nc} 端口未被占用"
        if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
            echo -e "${Info} SSL 证书生成成功"
            if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "$work_dir/server.crt" --keypath "$work_dir/server.key" --ecc --force; then
                echo -e "${Info} 证书已安装到 ${Green}$work_dir${Nc}"
                echo -e "${Tip} 证书到期将自动续签"
            fi
        else
            echo -e "${Error} SSL 证书生成失败"
            return 1
        fi
    elif [ "$certmethod" == "2" ]; then
        read -p "请输入 Cloudflare 账户邮箱: " cfmail
        read -p "请输入 Cloudflare Global API Key: " cfkey
        export CF_Key="${cfkey}"
        export CF_Email="${cfmail}"
        if "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" -k ec-256 --force; then
            echo -e "${Info} SSL 证书生成成功"
            if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "$work_dir/server.crt" --keypath "$work_dir/server.key" --ecc --force; then
                echo -e "${Info} 证书已安装到 ${Green}$work_dir${Nc}"
                echo -e "${Tip} 证书到期将自动续签"
            fi
        else
            echo -e "${Error} SSL 证书生成失败"
            return 1
        fi
    else
        echo -e "${Error} 选择错误"
        return 1
    fi

    echo -e "${Tip} 证书已配置，请确保服务端隧道配置中已填写证书路径:"
    echo -e "  cert: \"$work_dir/server.crt\""
    echo -e "  key: \"$work_dir/server.key\""
}

manual_cert() {
    read -p "请输入证书文件路径 (.crt/.pem): " src_cert
    read -p "请输入私钥文件路径 (.key): " src_key

    if [ ! -f "$src_cert" ]; then
        echo -e "${Error} 证书文件不存在: $src_cert"
        return 1
    fi
    if [ ! -f "$src_key" ]; then
        echo -e "${Error} 私钥文件不存在: $src_key"
        return 1
    fi

    cp -f "$src_cert" "$work_dir/server.crt"
    cp -f "$src_key" "$work_dir/server.key"
    chmod 600 "$work_dir/server.crt" "$work_dir/server.key"
    echo -e "${Info} 证书已上传到 ${Green}$work_dir${Nc}"
    echo -e "${Tip} 请确保服务端隧道配置中已填写证书路径，然后重启 anygo"
}

# ============ Cron Restart ============

Cron_manage() {
    echo -e "-----------------------------------"
    echo -e "Anygo 定时重启任务管理: "
    echo -e "-----------------------------------"
    echo -e "${Green}[1]${Nc} 配置定时重启"
    echo -e "${Green}[2]${Nc} 删除定时重启"
    echo -e "${Green}[3]${Nc} 查看现有定时任务"
    echo -e "-----------------------------------"
    read -p "请选择: " numcron

    case "$numcron" in
        1)
            Cron_add
            ;;
        2)
            sed -i "/anygo/d" /etc/crontab 2>/dev/null
            echo -e "${Info} 定时重启任务已删除"
            ;;
        3)
            echo -e "${Info} 当前 anygo 相关定时任务:"
            grep -i "anygo" /etc/crontab 2>/dev/null || echo -e "${Yellow}   (无)${Nc}"
            ;;
        *)
            echo -e "${Error} 选择错误"
            ;;
    esac
}

Cron_add() {
    echo -e "-----------------------------------"
    echo -e "定时重启类型: "
    echo -e "-----------------------------------"
    echo -e "${Green}[1]${Nc} 每隔N小时重启"
    echo -e "${Green}[2]${Nc} 每日固定时间重启"
    echo -e "-----------------------------------"
    read -p "请选择: " numcrontype

    case "$numcrontype" in
        1)
            read -p "每隔几小时重启: " cronhr
            if echo "$cronhr" | grep -q '^[0-9]\+$'; then
                echo "0 */${cronhr} * * * root systemctl restart anygo" >>/etc/crontab
                echo -e "${Info} 定时重启设置成功 (每${cronhr}小时)"
            else
                echo -e "${Error} 请输入有效数字"
            fi
            ;;
        2)
            read -p "每日几点重启 (0-23): " cronhr
            if echo "$cronhr" | grep -q '^[0-9]\+$' && [ "$cronhr" -ge 0 ] && [ "$cronhr" -le 23 ]; then
                echo "0 ${cronhr} * * * root systemctl restart anygo" >>/etc/crontab
                echo -e "${Info} 定时重启设置成功 (每日${cronhr}点)"
            else
                echo -e "${Error} 请输入有效时间 (0-23)"
            fi
            ;;
        *)
            echo -e "${Error} 选择错误"
            ;;
    esac
}

# ============ Backup/Restore ============

Backup_config() {
    local backup_file="$work_dir/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    cd "$work_dir"
    tar -czf "$backup_file" config.yaml rawconf server.crt server.key 2>/dev/null
    cd - >/dev/null
    echo -e "${Info} 配置已备份到: ${Green}$backup_file${Nc}"
}

Restore_config() {
    echo -e "${Info} 可用的备份文件:"
    ls -lh "$work_dir"/backup_*.tar.gz 2>/dev/null || echo -e "  ${Yellow}(无备份文件)${Nc}"
    echo ""
    read -p "请输入要恢复的备份文件完整路径: " backup_file
    if [ ! -f "$backup_file" ]; then
        echo -e "${Error} 备份文件不存在"
        return 1
    fi
    read -e -p "确认恢复？这将覆盖当前配置 [y/n]:" confirm
    [[ ${confirm} != [Yy] ]] && return
    systemctl stop anygo 2>/dev/null
    tar -xzf "$backup_file" -C "$work_dir/"
    systemctl start anygo 2>/dev/null
    echo -e "${Info} 配置已恢复"
}

# ============ Main Menu ============

main_menu() {
    echo && echo -e "                 ${Green}Anygo 一键安装配置脚本${Nc}"
    echo -e "  ${Blue}-----------------------------------------------------${Nc}"
    echo -e "  特性: (1) 本脚本采用 systemd 及配置文件对 anygo 进行管理"
    echo -e "        (2) 支持多组隧道规则同时生效"
    echo -e "        (3) 机器重启后转发不失效"
    echo -e "        (4) 支持 TLS 加密伪装 (SNI)"
    echo -e "  ${Blue}-----------------------------------------------------${Nc}"
    echo -e "  项目地址: ${Green}https://github.com/${github_repo}${Nc}"
    echo -e "  ${Blue}-----------------------------------------------------${Nc}"

    if [ -f "$anygo_bin" ]; then
        if systemctl is-active --quiet anygo 2>/dev/null; then
            echo -e "  当前状态: ${Green}已安装${Nc} 并 ${Green}已启动${Nc}"
        else
            echo -e "  当前状态: ${Green}已安装${Nc} 但 ${Red}未启动${Nc}"
        fi
    else
        echo -e "  当前状态: ${Red}未安装${Nc}"
    fi

    echo
    echo -e " ${Green}1.${Nc} 安装 anygo"
    echo -e " ${Green}2.${Nc} 更新 anygo"
    echo -e " ${Green}3.${Nc} 卸载 anygo"
    echo -e " ————————————"
    echo -e " ${Green}4.${Nc} 启动 anygo"
    echo -e " ${Green}5.${Nc} 停止 anygo"
    echo -e " ${Green}6.${Nc} 重启 anygo"
    echo -e " ${Green}7.${Nc} 查看运行状态"
    echo -e " ${Green}8.${Nc} 查看运行日志"
    echo -e " ————————————"
    echo -e " ${Green}9.${Nc} 新增隧道配置"
    echo -e " ${Green}10.${Nc} 查看所有隧道配置"
    echo -e " ${Green}11.${Nc} 删除隧道配置"
    echo -e " ————————————"
    echo -e " ${Green}12.${Nc} TLS 证书管理"
    echo -e " ${Green}13.${Nc} 定时重启管理"
    echo -e " ${Green}14.${Nc} 备份配置"
    echo -e " ${Green}15.${Nc} 恢复配置"
    echo && echo
    read -e -p " 请输入数字 [1-15]:" num

    case "$num" in
        1)
            Install_anygo
            ;;
        2)
            Update_anygo
            ;;
        3)
            Uninstall_anygo
            ;;
        4)
            Start_anygo
            ;;
        5)
            Stop_anygo
            ;;
        6)
            Restart_anygo
            ;;
        7)
            Status_anygo
            ;;
        8)
            View_log
            ;;
        9)
            Add_tunnel
            ;;
        10)
            show_all_conf
            ;;
        11)
            Delete_tunnel
            ;;
        12)
            Cert_manage
            ;;
        13)
            Cron_manage
            ;;
        14)
            Backup_config
            ;;
        15)
            Restore_config
            ;;
        *)
            echo -e "${Error} 请输入正确数字 [1-15]"
            ;;
    esac
}

# 支持命令行参数
case "$1" in
    install)
        Install_anygo
        ;;
    update)
        Update_anygo
        ;;
    uninstall)
        Uninstall_anygo
        ;;
    start)
        Start_anygo
        ;;
    stop)
        Stop_anygo
        ;;
    restart)
        Restart_anygo
        ;;
    status)
        Status_anygo
        ;;
    log)
        View_log
        ;;
    add)
        Add_tunnel
        ;;
    list)
        show_all_conf
        ;;
    delete)
        Delete_tunnel
        ;;
    cert)
        Cert_manage
        ;;
    cron)
        Cron_manage
        ;;
    backup)
        Backup_config
        ;;
    restore)
        Restore_config
        ;;
    *)
        main_menu
        ;;
esac
