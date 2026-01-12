#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# 检查 root 权限
[[ $EUID -ne 0 ]] && echo -e "${red}致命错误：${plain} 请以 root 权限运行此脚本 \n" && exit 1

# 检查操作系统并设置发行版变量
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "无法检测系统操作系统，请联系脚本作者！" >&2
    exit 1
fi
echo "操作系统版本：$release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}不支持的 CPU 架构！ ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "系统架构：$(arch)"

# 简单的帮助函数
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+[A-Za-z]{2,}$ ]] && return 0 || return 1
}

install_base() {
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update && apt-get install -y -q curl tar tzdata openssl socat
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y update && dnf install -y -q curl tar tzdata openssl socat
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y update && yum install -y curl tar tzdata openssl socat
            else
                dnf -y update && dnf install -y -q curl tar tzdata openssl socat
            fi
            ;;
        arch | manjaro | parch)
            pacman -Syu && pacman -Syu --noconfirm curl tar tzdata openssl socat
            ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper refresh && zypper -q install -y curl tar timezone openssl socat
            ;;
        alpine)
            apk update && apk add curl tar tzdata openssl socat
            ;;
        *)
            apt-get update && apt-get install -y -q curl tar tzdata openssl socat
            ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

install_acme() {
    echo -e "${green}正在安装 acme.sh 用于 SSL 证书管理...${plain}"
    cd ~ || return 1
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${red}安装 acme.sh 失败${plain}"
        return 1
    else
        echo -e "${green}acme.sh 安装成功${plain}"
    fi
    return 0
}

setup_ssl_certificate() {
    local domain="$1"
    local server_ip="$2"
    local existing_port="$3"
    local existing_webBasePath="$4"
    
    echo -e "${green}正在设置 SSL 证书...${plain}"
    
    # 检查 acme.sh 是否已安装
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${yellow}安装 acme.sh 失败，跳过 SSL 设置${plain}"
            return 1
        fi
    fi
    
    # 创建证书目录
    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"
    
    # 申请证书
    echo -e "${green}为 ${domain} 申请 SSL 证书...${plain}"
    echo -e "${yellow}注意：端口 80 必须打开并且能被外部访问${plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport 80 --force
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}为 ${domain} 申请证书失败${plain}"
        echo -e "${yellow}请确保端口 80 已打开并可访问，再试一次${plain}"
        rm -rf ~/.acme.sh/${domain} 2>/dev/null
        rm -rf "$certPath" 2>/dev/null
        return 1
    fi
    
    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}证书安装失败${plain}"
        return 1
    fi
    
    # 启用自动续期
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    chmod 755 $certPath/* 2>/dev/null
    
    # 设置证书到面板
    local webCertFile="/root/cert/${domain}/fullchain.pem"
    local webKeyFile="/root/cert/${domain}/privkey.pem"
    
    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile" >/dev/null 2>&1
        echo -e "${green}SSL 证书安装并配置成功！${plain}"
        return 0
    else
        echo -e "${yellow}证书文件未找到${plain}"
        return 1
    fi
}

# 生成自签名证书（不受信任）
setup_self_signed_certificate() {
    local name="$1"   # domain or IP to place in SAN
    local certDir="/root/cert/selfsigned"

    echo -e "${yellow}生成一个自签名证书（浏览器可能不受信任）...${plain}"

    mkdir -p "$certDir"

    local sanExt=""
    if is_ip "$name"; then
        sanExt="IP:${name}"
    else
        sanExt="DNS:${name}"
    fi

    # 使用 -addext 如果支持；如果不支持，回退到配置文件
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "${certDir}/privkey.pem" \
        -out "${certDir}/fullchain.pem" \
        -subj "/CN=${name}" \
        -addext "subjectAltName=${sanExt}" >/dev/null 2>&1

    if [[ $? -ne 0 ]]; then
        # 如果 OpenSSL 版本较旧，使用临时配置文件
        local tmpCfg="${certDir}/openssl.cnf"
        cat > "$tmpCfg" <<EOF
[req]
distinguished_name=req_distinguished_name
req_extensions=v3_req
[req_distinguished_name]
[v3_req]
subjectAltName=${sanExt}
EOF
        openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
            -keyout "${certDir}/privkey.pem" \
            -out "${certDir}/fullchain.pem" \
            -subj "/CN=${name}" \
            -config "$tmpCfg" -extensions v3_req >/dev/null 2>&1
        rm -f "$tmpCfg"
    fi

    if [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]]; then
        echo -e "${red}生成自签名证书失败${plain}"
        return 1
    fi

    chmod 755 ${certDir}/* 2>/dev/null
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem" >/dev/null 2>&1
    echo -e "${yellow}自签名证书已配置，浏览器可能会显示警告。${plain}"
    return 0
}

# 综合的手动 SSL 证书申请
ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep 'webBasePath:' | awk -F': ' '{print $2}' | tr -d '[:space:]' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep 'port:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    
    # 首先检查是否已安装 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "找不到 acme.sh，正在安装..."
        cd ~ || return 1
        curl -s https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo -e "${red}安装 acme.sh 失败${plain}"
            return 1
        else
            echo -e "${green}acme.sh 安装成功${plain}"
        fi
    fi

    # 获取域名并验证
    local domain=""
    while true; do
        read -rp "请输入您的域名： " domain
        domain="${domain// /}"  # 去除空格
        
        if [[ -z "$domain" ]]; then
            echo -e "${red}域名不能为空，请重新输入。${plain}"
            continue
        fi
        
        if ! is_domain "$domain"; then
            echo -e "${red}域名格式无效：${domain}。请输入有效的域名。${plain}"
            continue
        fi
        
        break
    done
    echo -e "${green}您的域名是：${domain}，正在检查...${plain}"

    # 检查是否已有证书
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ "${currentCert}" == "${domain}" ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        echo -e "${red}系统已为此域名配置证书，不能重复申请。${plain}"
        echo -e "${yellow}当前证书信息：${plain}"
        echo "$certInfo"
        return 1
    else
        echo -e "${green}您的域名已准备好申请证书...${plain}"
    fi

    # 创建证书目录
    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    # 获取端口号
    local WebPort=80
    read -rp "请选择使用的端口（默认是 80）： " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        echo -e "${yellow}您输入的端口 ${WebPort} 无效，将使用默认端口 80。${plain}"
        WebPort=80
    fi
    echo -e "${green}将使用端口：${WebPort} 申请证书，请确保此端口已开放。${plain}"

    # 临时停止面板
    echo -e "${yellow}正在暂时停止面板...${plain}"
    systemctl stop x-ui 2>/dev/null || rc-service x-ui stop 2>/dev/null

    # 申请证书
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport ${WebPort} --force
    if [ $? -ne 0 ]; then
        echo -e "${red}申请证书失败，请检查日志。${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}证书申请成功，正在安装证书...${plain}"
    fi

    # 设置重新加载命令
    reloadCmd="systemctl restart x-ui || rc-service x-ui restart"
    echo -e "${green}ACME 的默认 --reloadcmd 是：${yellow}systemctl restart x-ui || rc-service x-ui restart${plain}"
    echo -e "${green}每次证书申请和更新时，都会运行此命令。${plain}"
    read -rp "是否修改 --reloadcmd？ (y/n): " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} 默认：systemctl reload nginx ; systemctl restart x-ui"
        echo -e "${green}\t2.${plain} 输入您的自定义命令"
        echo -e "${green}\t0.${plain} 保持默认 reloadcmd"
        read -rp "请选择一个选项： " choice
        case "$choice" in
        1)
            echo -e "${green}Reloadcmd 是：systemctl reload nginx ; systemctl restart x-ui${plain}"
            reloadCmd="systemctl reload nginx ; systemctl restart x-ui"
            ;;
        2)
            echo -e "${yellow}建议将 x-ui 重启命令放到最后。${plain}"
            read -rp "请输入您的自定义 reloadcmd： " reloadCmd
            echo -e "${green}Reloadcmd 是：${reloadCmd}${plain}"
            ;;
        *)
            echo -e "${green}保持默认 reloadcmd${plain}"
            ;;
        esac
    fi

    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}"

    if [ $? -ne 0 ]; then
        echo -e "${red}安装证书失败，正在退出...${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}证书安装成功，启用自动续期...${plain}"
    fi

    # 启用自动续期
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        echo -e "${yellow}自动续期设置存在问题，证书详情：${plain}"
        ls -lah /root/cert/${domain}/
        chmod 755 $certPath/*
    else
        echo -e "${green}自动续期设置成功，证书详情：${plain}"
        ls -lah /root/cert/${domain}/
        chmod 755 $certPath/*
    fi

    # 重启面板
    systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null

    # 提示用户设置面板证书路径
    read -rp "是否为面板设置此证书？ (y/n): " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            echo -e "${green}证书路径已设置到面板${plain}"
            echo -e "${green}证书文件：$webCertFile${plain}"
            echo -e "${green}私钥文件：$webKeyFile${plain}"
            echo ""
            echo -e "${green}访问地址：https://${domain}:${existing_port}/${existing_webBasePath}${plain}"
            echo -e "${yellow}面板将重新启动以应用 SSL 证书...${plain}"
            systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
        else
            echo -e "${red}错误：未找到证书或私钥文件，域名：$domain${plain}"
        fi
    else
        echo -e "${yellow}跳过面板证书路径设置。${plain}"
    fi
    
    return 0
}

# 交互式 SSL 设置（域名或自签名证书）
prompt_and_setup_ssl() {
    local panel_port="$1"
    local web_base_path="$2"   # 不带斜杠
    local server_ip="$3"

    local ssl_choice=""

    echo -e "${yellow}请选择 SSL 证书配置方式：${plain}"
    echo -e "${green}1.${plain} Let's Encrypt（需要域名，推荐）"
    echo -e "${green}2.${plain} 自签名证书（浏览器不受信任）"
    read -rp "请选择一个选项（默认 2）： " ssl_choice
    ssl_choice="${ssl_choice// /}"  # 去除空格
    
    # 如果不是 1，默认为 2（自签名）
    if [[ "$ssl_choice" != "1" ]]; then
        ssl_choice="2"
    fi

    case "$ssl_choice" in
    1)
        # 用户选择 Let's Encrypt 域名选项
        echo -e "${green}正在使用 ssl_cert_issue() 配置域名证书...${plain}"
        ssl_cert_issue
        # 从证书中提取域名
        local cert_domain=$(~/.acme.sh/acme.sh --list 2>/dev/null | tail -1 | awk '{print $1}')
        if [[ -n "${cert_domain}" ]]; then
            SSL_HOST="${cert_domain}"
            echo -e "${green}✓ SSL 证书配置成功，域名：${cert_domain}${plain}"
        else
            echo -e "${yellow}SSL 配置可能已完成，但提取域名失败${plain}"
            SSL_HOST="${server_ip}"
        fi
        ;;
    2)
        # 用户选择自签名选项
        # 停止面板
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop >/dev/null 2>&1
        else
            systemctl stop x-ui >/dev/null 2>&1
        fi
        echo -e "${yellow}使用服务器 IP 创建自签名证书：${server_ip}${plain}"
        setup_self_signed_certificate "${server_ip}"
        if [ $? -eq 0 ]; then
            SSL_HOST="${server_ip}"
            echo -e "${green}✓ 自签名 SSL 配置成功${plain}"
        else
            echo -e "${red}✗ 自签名 SSL 配置失败${plain}"
            SSL_HOST="${server_ip}"
        fi
        # 配置完成后启动面板
        if [[ $release == "alpine" ]]; then
            rc-service x-ui start >/dev/null 2>&1
        else
            systemctl start x-ui >/dev/null 2>&1
        fi
        ;;
    *)
        echo -e "${red}无效选项，跳过 SSL 配置。${plain}"
        SSL_HOST="${server_ip}"
        ;;
    esac
}

config_after_install() {
    local existing_hasDefaultCredential=$(${xui_folder}/x-ui setting -show true | grep -Eo 'hasDefaultCredential: .+' | awk '{print $2}')
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    # 正确检测证书是否为空
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    local URL_lists=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://ipv4.myexternalip.com/raw"
        "https://4.ident.me"
        "https://check-host.net/ip"
    )
    local server_ip=""
    for ip_address in "${URL_lists[@]}"; do
        server_ip=$(curl -s --max-time 3 "${ip_address}" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "${server_ip}" ]]; then
            break
        fi
    done
    
    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_webBasePath=$(gen_random_string 18)
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            read -rp "是否自定义面板端口设置？（如果不设置，将应用随机端口）[y/n]： " config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -rp "请设置面板端口： " config_port
                echo -e "${yellow}您的面板端口是： ${config_port}${plain}"
            else
                local config_port=$(shuf -i 1024-62000 -n 1)
                echo -e "${yellow}生成的随机端口： ${config_port}${plain}"
            fi
            
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL 证书配置（必需）${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}为了安全，所有面板必须启用 SSL 证书。${plain}"
            echo -e "${yellow}Let's Encrypt 需要域名（无法为 IP 生成证书）。${plain}"
            echo ""

            prompt_and_setup_ssl "${config_port}" "${config_webBasePath}" "${server_ip}"
            
            # 显示最终的登录信息和访问地址
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     面板安装完成！${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}用户名：    ${config_username}${plain}"
            echo -e "${green}密码：    ${config_password}${plain}"
            echo -e "${green}端口：    ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            echo -e "${green}访问地址： https://${SSL_HOST}:${config_port}/${config_webBasePath}${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}⚠ 请妥善保存这些凭证！${plain}"
            echo -e "${yellow}⚠ SSL 证书：已启用并配置${plain}"
        else
            local config_webBasePath=$(gen_random_string 18)
            echo -e "${yellow}WebBasePath 缺失或太短，正在生成新值...${plain}"
            ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
            echo -e "${green}新的 WebBasePath：${config_webBasePath}${plain}"

            # 如果面板已安装，但未配置证书，则提示配置 SSL
            if [[ -z "${existing_cert}" ]]; then
                echo ""
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${green}     SSL 证书配置（推荐）${plain}"
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${yellow}Let's Encrypt 需要域名（无法为 IP 生成证书）。${plain}"
                echo ""
                prompt_and_setup_ssl "${existing_port}" "${config_webBasePath}" "${server_ip}"
                echo -e "${green}访问地址： https://${SSL_HOST}:${existing_port}/${config_webBasePath}${plain}"
            else
                # 如果已配置证书，直接显示访问地址
                echo -e "${green}访问地址： https://${server_ip}:${existing_port}/${config_webBasePath}${plain}"
            fi
        fi
    else
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            echo -e "${yellow}检测到默认凭证。需要进行安全更新...${plain}"
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}"
            echo -e "生成的新随机登录凭证："
            echo -e "###############################################"
            echo -e "${green}用户名： ${config_username}${plain}"
            echo -e "${green}密码： ${config_password}${plain}"
            echo -e "###############################################"
        else
            echo -e "${green}用户名、密码和 WebBasePath 已正确设置。${plain}"
        fi

        # 如果没有证书，提示用户配置域名或自签证书
        existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$existing_cert" ]]; then
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL 证书配置（推荐）${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}Let's Encrypt 需要域名（无法为 IP 生成证书）。${plain}"
            echo ""
            prompt_and_setup_ssl "${existing_port}" "${existing_webBasePath}" "${server_ip}"
            echo -e "${green}访问地址： https://${SSL_HOST}:${existing_port}/${existing_webBasePath}${plain}"
        else
            echo -e "${green}SSL 证书已经配置，无需操作。${plain}"
        fi
    fi
    
    ${xui_folder}/x-ui migrate
}

install_x-ui() {
    cd ${xui_folder%/x-ui}/
    
    # 下载资源
    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo -e "${yellow}尝试使用 IPv4 获取版本...${plain}"
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                echo -e "${red}获取 x-ui 版本失败，可能是 GitHub API 限制，稍后再试${plain}"
                exit 1
            fi
        fi
        echo -e "获取到 x-ui 最新版本：${tag_version}，开始安装..."
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz -z ${xui_folder}-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui 失败，请确保服务器能访问 GitHub ${plain}"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"
        
        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo -e "${red}请使用更高版本（至少 v2.3.5）。安装已终止。${plain}"
            exit 1
        fi
        
        url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "开始安装 x-ui $1"
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz -z ${xui_folder}-linux-$(arch).tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui $1 失败，请检查版本是否存在 ${plain}"
            exit 1
        fi
    fi
    curl -4fLRo /usr/bin/x-ui-temp https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载 x-ui.sh 失败${plain}"
        exit 1
    fi
    
    # 停止 x-ui 服务并删除旧资源
    if [[ -e ${xui_folder}/ ]]; then
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        rm ${xui_folder}/ -rf
    fi
    
    # 解压资源并设置权限
    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f
    
    cd x-ui
    chmod +x x-ui
    chmod +x x-ui.sh
    
    # 检查系统架构并相应重命名文件
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)
    
    # 更新 x-ui cli 并设置权限
    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    mkdir -p /var/log/x-ui
    config_after_install

    # 与 Etckeeper 兼容
    if [ -d "/etc/.git" ]; then
        if [ -f "/etc/.gitignore" ]; then
            if ! grep -q "x-ui/x-ui.db" "/etc/.gitignore"; then
                echo "" >> "/etc/.gitignore"
                echo "x-ui/x-ui.db" >> "/etc/.gitignore"
                echo -e "${green}已将 x-ui.db 添加到 /etc/.gitignore 以兼容 etckeeper${plain}"
            fi
        else
            echo "x-ui/x-ui.db" > "/etc/.gitignore"
            echo -e "${green}已创建 /etc/.gitignore 并添加 x-ui.db 以兼容 etckeeper${plain}"
        fi
    fi
    
    if [[ $release == "alpine" ]]; then
        curl -4fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/x-ui.rc
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui.rc 失败${plain}"
            exit 1
        fi
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        # 安装 systemd 服务文件
        service_installed=false
        
        if [ -f "x-ui.service" ]; then
            echo -e "${green}找到 x-ui.service 文件，正在安装...${plain}"
            cp -f x-ui.service ${xui_service}/ >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                service_installed=true
            fi
        fi
        
        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    if [ -f "x-ui.service.debian" ]; then
                        echo -e "${green}找到 x-ui.service.debian 文件，正在安装...${plain}"
                        cp -f x-ui.service.debian ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
                *)
                    if [ -f "x-ui.service.rhel" ]; then
                        echo -e "${green}找到 x-ui.service.rhel 文件，正在安装...${plain}"
                        cp -f x-ui.service.rhel ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
            esac
        fi
        
        # 如果没有找到服务文件，则从 GitHub 下载
        if [ "$service_installed" = false ]; then
            echo -e "${yellow}在 tar.gz 中未找到服务文件，正在从 GitHub 下载...${plain}"
            case "${release}" in
                ubuntu | debian | armbian)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/x-ui.service.debian >/dev/null 2>&1
                ;;
                *)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/x-ui.service.rhel >/dev/null 2>&1
                ;;
            esac
            
            if [[ $? -ne 0 ]]; then
                echo -e "${red}从 GitHub 安装 x-ui.service 文件失败${plain}"
                exit 1
            fi
            service_installed=true
        fi
        
        if [ "$service_installed" = true ]; then
            echo -e "${green}正在设置 systemd 单元...${plain}"
            chown root:root ${xui_service}/x-ui.service >/dev/null 2>&1
            chmod 644 ${xui_service}/x-ui.service >/dev/null 2>&1
            systemctl daemon-reload
            systemctl enable x-ui
            systemctl start x-ui
        else
            echo -e "${red}安装 x-ui.service 文件失败${plain}"
            exit 1
        fi
    fi
    
    echo -e "${green}x-ui ${tag_version}${plain} 安装完成，现在正在运行...${plain}"
    echo -e ""
    echo -e "┌───────────────────────────────────────────────────────┐
│  ${blue}x-ui 控制面板命令使用（子命令）：${plain}              │
│                                                       │
│  ${blue}x-ui${plain}              - 管理员管理脚本              │
│  ${blue}x-ui start${plain}        - 启动                        │
│  ${blue}x-ui stop${plain}         - 停止                        │
│  ${blue}x-ui restart${plain}      - 重启                        │
│  ${blue}x-ui status${plain}       - 当前状态                    │
│  ${blue}x-ui settings${plain}     - 当前设置                    │
│  ${blue}x-ui enable${plain}       - 启用开机自启                │
│  ${blue}x-ui disable${plain}      - 禁用开机自启                │
│  ${blue}x-ui log${plain}          - 查看日志                    │
│  ${blue}x-ui banlog${plain}       - 查看 Fail2ban 封禁日志      │
│  ${blue}x-ui update${plain}       - 更新                        │
│  ${blue}x-ui legacy${plain}       - 旧版                        │
│  ${blue}x-ui install${plain}      - 安装                        │
│  ${blue}x-ui uninstall${plain}    - 卸载                        │
└───────────────────────────────────────────────────────┘"
}

echo -e "${green}Running...${plain}"
install_base
install_x-ui $1
