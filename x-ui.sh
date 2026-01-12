#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

#Add some basic function here
function LOGD() {
    echo -e "${yellow}[DEG] $* ${plain}"
}

function LOGE() {
    echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
    echo -e "${green}[INF] $* ${plain}"
}

# Simple helpers for domain/IP validation
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

# check root
[[ $EUID -ne 0 ]] && LOGE "错误：必须使用 root 运行此脚本！ \n" && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "系统 OS 检测失败，请联系作者！" >&2
    exit 1
fi
echo "系统发行版为：$release"

os_version=""
os_version=$(grep "^VERSION_ID" /etc/os-release | cut -d '=' -f2 | tr -d '"' | tr -d '.')

# Declare Variables
xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"
log_folder="${XUI_LOG_FOLDER:=/var/log/x-ui}"
mkdir -p "${log_folder}"
iplimit_log_path="${log_folder}/3xipl.log"
iplimit_banned_log_path="${log_folder}/3xipl-banned.log"

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -rp "$1 [默认 $2]: " temp
        if [[ "${temp}" == "" ]]; then
            temp=$2
        fi
    else
        read -rp "$1 [y/n]: " temp
    fi
    if [[ "${temp}" == "y" || "${temp}" == "Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "是否重启面板？注意：重启面板也会重启 xray" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}按回车键返回主菜单： ${plain}" && read -r temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    confirm "此功能将把所有 x-ui 组件更新到最新版本，数据不会丢失。是否继续？" "y"
    if [[ $? != 0 ]]; then
        LOGE "已取消"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi
    bash <(curl -Ls https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/update.sh)
    if [[ $? == 0 ]]; then
        LOGI "更新完成，面板已自动重启 "
        before_show_menu
    fi
}

update_menu() {
    echo -e "${yellow}正在更新菜单${plain}"
    confirm "此功能将把菜单更新到最新版本改动。" "y"
    if [[ $? != 0 ]]; then
        LOGE "已取消"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi

    curl -fLRo /usr/bin/x-ui https://raw.githubusercontent.com/YSeverything/3x-ui-cn/main/x-ui.sh
    chmod +x ${xui_folder}/x-ui.sh
    chmod +x /usr/bin/x-ui

    if [[ $? == 0 ]]; then
        echo -e "${green}更新成功。面板已自动重启。${plain}"
        exit 0
    else
        echo -e "${red}菜单更新失败。${plain}"
        return 1
    fi
}

legacy_version() {
    echo -n "请输入面板版本（如 2.4.0）："
    read -r tag_version

    if [ -z "$tag_version" ]; then
        echo "面板版本不能为空。退出。"
        exit 1
    fi
    # Use the entered panel version in the download link
    install_command="bash <(curl -Ls "https://raw.githubusercontent.com/mhsanaei/3x-ui/v$tag_version/install.sh") v$tag_version"

    echo "正在下载并安装面板版本 $tag_version..."
    eval $install_command
}

# Function to handle the deletion of the script file
delete_script() {
    rm "$0" # Remove the script file itself
    exit 1
}

uninstall() {
    confirm "确认卸载面板？xray 也会被卸载！" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi

    if [[ $release == "alpine" ]]; then
        rc-service x-ui stop
        rc-update del x-ui
        rm /etc/init.d/x-ui -f
    else
        systemctl stop x-ui
        systemctl disable x-ui
        rm ${xui_service}/x-ui.service -f
        systemctl daemon-reload
        systemctl reset-failed
    fi

    rm /etc/x-ui/ -rf
    rm ${xui_folder}/ -rf

    echo ""
    echo -e "卸载成功。\n"
    echo "如需再次安装面板，可使用以下命令："
    echo -e "${green}bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)${plain}"
    echo ""
    # Trap the SIGTERM signal
    trap delete_script SIGTERM
    delete_script
}

reset_user() {
    confirm "确认重置面板用户名与密码？" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    
    read -rp "请设置登录用户名 [默认随机用户名]： " config_account
    [[ -z $config_account ]] && config_account=$(gen_random_string 10)
    read -rp "请设置登录密码 [默认随机密码]： " config_password
    [[ -z $config_password ]] && config_password=$(gen_random_string 18)

    read -rp "是否禁用当前已配置的两步验证？(y/n)： " twoFactorConfirm
    if [[ $twoFactorConfirm != "y" && $twoFactorConfirm != "Y" ]]; then
        ${xui_folder}/x-ui setting -username ${config_account} -password ${config_password} -resetTwoFactor false >/dev/null 2>&1
    else
        ${xui_folder}/x-ui setting -username ${config_account} -password ${config_password} -resetTwoFactor true >/dev/null 2>&1
        echo -e "两步验证已禁用。"
    fi
    
    echo -e "面板登录用户名已重置为：${green} ${config_account} ${plain}"
    echo -e "面板登录密码已重置为：${green} ${config_password} ${plain}"
    echo -e "${green} 请使用新的用户名和密码访问 X-UI 面板，并务必牢记！ ${plain}"
    confirm_restart
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

# Generate and configure a self-signed SSL certificate
setup_self_signed_certificate() {
    local name="$1"   # domain or IP to place in SAN
    local certDir="/root/cert/selfsigned"

    LOGI "正在生成自签名证书（不被公网信任）..."

    mkdir -p "$certDir"

    local sanExt=""
    if [[ "$name" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$name" =~ : ]]; then
        sanExt="IP:${name}"
    else
        sanExt="DNS:${name}"
    fi

    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "${certDir}/privkey.pem" \
        -out "${certDir}/fullchain.pem" \
        -subj "/CN=${name}" \
        -addext "subjectAltName=${sanExt}" >/dev/null 2>&1

    if [[ $? -ne 0 ]]; then
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
        LOGE "生成自签名证书失败"
        return 1
    fi

    chmod 755 ${certDir}/* >/dev/null 2>&1
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem" >/dev/null 2>&1
    LOGI "已配置自签名证书。浏览器将会显示安全警告。"
    return 0
}

reset_webbasepath() {
    echo -e "${yellow}正在重置 Web Base Path${plain}"

    read -rp "确认重置 Web Base Path？(y/n)： " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo -e "${yellow}操作已取消。${plain}"
        return
    fi

    config_webBasePath=$(gen_random_string 18)

    # Apply the new web base path setting
    ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}" >/dev/null 2>&1

    echo -e "Web Base Path 已重置为：${green}${config_webBasePath}${plain}"
    echo -e "${green}请使用新的 Web Base Path 访问面板。${plain}"
    restart
}

reset_config() {
    confirm "确认重置所有面板设置？账号数据不会丢失，用户名和密码不会改变" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    ${xui_folder}/x-ui setting -reset
    echo -e "所有面板设置已重置为默认值。"
    restart
}

check_config() {
    local info=$(${xui_folder}/x-ui setting -show true)
    if [[ $? != 0 ]]; then
        LOGE "获取当前设置失败，请查看日志"
        show_menu
        return
    fi
    LOGI "${info}"

    local existing_webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    local server_ip=$(curl -s --max-time 3 https://api.ipify.org)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s --max-time 3 https://4.ident.me)
    fi

    if [[ -n "$existing_cert" ]]; then
        local domain=$(basename "$(dirname "$existing_cert")")

        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${green}访问地址： https://${domain}:${existing_port}${existing_webBasePath}${plain}"
        else
            echo -e "${green}访问地址： https://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
        fi
    else
        echo -e "${red}⚠ 警告：未配置 SSL 证书！${plain}"
        read -rp "现在生成自签名 SSL 证书吗？[y/N]: " gen_self
        if [[ "$gen_self" == "y" || "$gen_self" == "Y" ]]; then
            stop >/dev/null 2>&1
            setup_self_signed_certificate "${server_ip}"
            if [[ $? -eq 0 ]]; then
                restart >/dev/null 2>&1
                echo -e "${green}访问地址： https://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
            else
                LOGE "自签名 SSL 配置失败。"
                echo -e "${yellow}你可以在选项 18（SSL 证书管理）中再次尝试。${plain}"
            fi
        else
            echo -e "${yellow}访问地址： http://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
            echo -e "${yellow}为确保安全，请通过选项 18（SSL 证书管理）配置 SSL 证书${plain}"
        fi
    fi
}

set_port() {
    echo -n "请输入端口号[1-65535]： "
    read -r port
    if [[ -z "${port}" ]]; then
        LOGD "已取消"
        before_show_menu
    else
        ${xui_folder}/x-ui setting -port ${port}
        echo -e "端口已设置。请现在重启面板，并使用新端口 ${green}${port}${plain} 访问 Web 面板"
        confirm_restart
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        LOGI "面板正在运行，无需再次启动。如需重启，请选择 restart"
    else
        if [[ $release == "alpine" ]]; then
            rc-service x-ui start
        else
            systemctl start x-ui
        fi
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            LOGI "x-ui 启动成功"
        else
            LOGE "面板启动失败，可能是启动超过两秒。请稍后查看日志信息"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    check_status
    if [[ $? == 1 ]]; then
        echo ""
        LOGI "面板已停止，无需再次停止！"
    else
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        sleep 2
        check_status
        if [[ $? == 1 ]]; then
            LOGI "x-ui 和 xray 已成功停止"
        else
            LOGE "面板停止失败，可能是停止超过两秒。请稍后查看日志信息"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    if [[ $release == "alpine" ]]; then
        rc-service x-ui restart
    else
        systemctl restart x-ui
    fi
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        LOGI "x-ui 和 xray 重启成功"
    else
        LOGE "面板重启失败，可能是启动超过两秒。请稍后查看日志信息"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    if [[ $release == "alpine" ]]; then
        rc-service x-ui status
    else
        systemctl status x-ui -l
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    if [[ $release == "alpine" ]]; then
        rc-update add x-ui
    else
        systemctl enable x-ui
    fi
    if [[ $? == 0 ]]; then
        LOGI "已成功设置 x-ui 开机自启动"
    else
        LOGE "设置开机自启动失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    if [[ $release == "alpine" ]]; then
        rc-update del x-ui
    else
        systemctl disable x-ui
    fi
    if [[ $? == 0 ]]; then
        LOGI "已成功取消 x-ui 开机自启动"
    else
        LOGE "取消开机自启动失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    if [[ $release == "alpine" ]]; then
        echo -e "${green}\t1.${plain} 调试日志"
        echo -e "${green}\t0.${plain} 返回主菜单"
        read -rp "请选择一个选项： " choice

        case "$choice" in
        0)
            show_menu
            ;;
        1)
            grep -F 'x-ui[' /var/log/messages
            if [[ $# == 0 ]]; then
                before_show_menu
            fi
            ;;
        *)
            echo -e "${red}无效选项。请选择有效数字。${plain}\n"
            show_log
            ;;
        esac
    else
        echo -e "${green}\t1.${plain} 调试日志"
        echo -e "${green}\t2.${plain} 清理所有日志"
        echo -e "${green}\t0.${plain} 返回主菜单"
        read -rp "请选择一个选项： " choice

        case "$choice" in
        0)
            show_menu
            ;;
        1)
            journalctl -u x-ui -e --no-pager -f -p debug
            if [[ $# == 0 ]]; then
                before_show_menu
            fi
            ;;
        2)
            sudo journalctl --rotate
            sudo journalctl --vacuum-time=1s
            echo "所有日志已清理。"
            restart
            ;;
        *)
            echo -e "${red}无效选项。请选择有效数字。${plain}\n"
            show_log
            ;;
        esac
    fi
}

bbr_menu() {
    echo -e "${green}\t1.${plain} 启用 BBR"
    echo -e "${green}\t2.${plain} 禁用 BBR"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        enable_bbr
        bbr_menu
        ;;
    2)
        disable_bbr
        bbr_menu
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        bbr_menu
        ;;
    esac
}

disable_bbr() {

    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${yellow}当前未启用 BBR。${plain}"
        before_show_menu
    fi

    # Replace BBR with CUBIC configurations
    sed -i 's/net.core.default_qdisc=fq/net.core.default_qdisc=pfifo_fast/' /etc/sysctl.conf
    sed -i 's/net.ipv4.tcp_congestion_control=bbr/net.ipv4.tcp_congestion_control=cubic/' /etc/sysctl.conf

    # Apply changes
    sysctl -p

    # Verify that BBR is replaced with CUBIC
    if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "cubic" ]]; then
        echo -e "${green}已成功将 BBR 替换为 CUBIC。${plain}"
    else
        echo -e "${red}将 BBR 替换为 CUBIC 失败，请检查系统配置。${plain}"
    fi
}

enable_bbr() {
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${green}BBR 已启用！${plain}"
        before_show_menu
    fi

    # Check the OS and install necessary packages
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update && apt-get install -yqq --no-install-recommends ca-certificates
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update && dnf -y install ca-certificates
        ;;
    centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y update && yum -y install ca-certificates
            else
                dnf -y update && dnf -y install ca-certificates
            fi
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm ca-certificates
        ;;
	opensuse-tumbleweed | opensuse-leap)
        zypper refresh && zypper -q install -y ca-certificates
        ;;
    alpine)
        apk add ca-certificates
        ;;
    *)
        echo -e "${red}不支持的操作系统。请检查脚本并手动安装所需依赖。${plain}\n"
        exit 1
        ;;
    esac

    # Enable BBR
    echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf

    # Apply changes
    sysctl -p

    # Verify that BBR is enabled
    if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "bbr" ]]; then
        echo -e "${green}BBR 启用成功。${plain}"
    else
        echo -e "${red}BBR 启用失败，请检查系统配置。${plain}"
    fi
}

update_shell() {
    curl -fLRo /usr/bin/x-ui -z /usr/bin/x-ui https://github.com/YSeverything/3x-ui-cn/raw/main/x-ui.sh
    if [[ $? != 0 ]]; then
        echo ""
        LOGE "脚本下载失败，请检查机器是否能够连接 Github"
        before_show_menu
    else
        chmod +x /usr/bin/x-ui
        LOGI "脚本升级成功，请重新运行脚本"
        before_show_menu
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ $release == "alpine" ]]; then
        if [[ ! -f /etc/init.d/x-ui ]]; then
            return 2
        fi
        if [[ $(rc-service x-ui status | grep -F 'status: started' -c) == 1 ]]; then
            return 0
        else
            return 1
        fi
    else
        if [[ ! -f ${xui_service}/x-ui.service ]]; then
            return 2
        fi
        temp=$(systemctl status x-ui | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ "${temp}" == "running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

check_enabled() {
    if [[ $release == "alpine" ]]; then
        if [[ $(rc-update show | grep -F 'x-ui' | grep default -c) == 1 ]]; then
            return 0
        else
            return 1
        fi
    else
        temp=$(systemctl is-enabled x-ui)
        if [[ "${temp}" == "enabled" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        LOGE "面板已安装，请勿重复安装"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        LOGE "请先安装面板"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
    0)
        echo -e "面板状态：${green}运行中${plain}"
        show_enable_status
        ;;
    1)
        echo -e "面板状态：${yellow}未运行${plain}"
        show_enable_status
        ;;
    2)
        echo -e "面板状态：${red}未安装${plain}"
        ;;
    esac
    show_xray_status
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "开机自启：${green}是${plain}"
    else
        echo -e "开机自启：${red}否${plain}"
    fi
}

check_xray_status() {
    count=$(ps -ef | grep "xray-linux" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_xray_status() {
    check_xray_status
    if [[ $? == 0 ]]; then
        echo -e "xray 状态：${green}运行中${plain}"
    else
        echo -e "xray 状态：${red}未运行${plain}"
    fi
}

firewall_menu() {
    echo -e "${green}\t1.${plain} ${green}安装${plain} 防火墙"
    echo -e "${green}\t2.${plain} 端口列表 [带编号]"
    echo -e "${green}\t3.${plain} ${green}开放${plain} 端口"
    echo -e "${green}\t4.${plain} ${red}从列表删除${plain} 端口"
    echo -e "${green}\t5.${plain} ${green}启用${plain} 防火墙"
    echo -e "${green}\t6.${plain} ${red}禁用${plain} 防火墙"
    echo -e "${green}\t7.${plain} 防火墙状态"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        install_firewall
        firewall_menu
        ;;
    2)
        ufw status numbered
        firewall_menu
        ;;
    3)
        open_ports
        firewall_menu
        ;;
    4)
        delete_ports
        firewall_menu
        ;;
    5)
        ufw enable
        firewall_menu
        ;;
    6)
        ufw disable
        firewall_menu
        ;;
    7)
        ufw status verbose
        firewall_menu
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        firewall_menu
        ;;
    esac
}

install_firewall() {
    if ! command -v ufw &>/dev/null; then
        echo "未安装 ufw 防火墙。正在安装..."
        apt-get update
        apt-get install -y ufw
    else
        echo "ufw 防火墙已安装"
    fi

    # Check if the firewall is inactive
    if ufw status | grep -q "Status: active"; then
        echo "防火墙已处于启用状态"
    else
        echo "正在启用防火墙..."
        # Open the necessary ports
        ufw allow ssh
        ufw allow http
        ufw allow https
        ufw allow 2053/tcp #webPort
        ufw allow 2096/tcp #subport

        # Enable the firewall
        ufw --force enable
    fi
}

open_ports() {
    # Prompt the user to enter the ports they want to open
    read -rp "请输入要开放的端口（例如 80,443,2053 或范围 400-500）： " ports

    # Check if the input is valid
    if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
        echo "错误：输入无效。请输入逗号分隔的端口列表或端口范围（例如 80,443,2053 或 400-500）。" >&2
        exit 1
    fi

    # Open the specified ports using ufw
    IFS=',' read -ra PORT_LIST <<<"$ports"
    for port in "${PORT_LIST[@]}"; do
        if [[ $port == *-* ]]; then
            # Split the range into start and end ports
            start_port=$(echo $port | cut -d'-' -f1)
            end_port=$(echo $port | cut -d'-' -f2)
            # Open the port range
            ufw allow $start_port:$end_port/tcp
            ufw allow $start_port:$end_port/udp
        else
            # Open the single port
            ufw allow "$port"
        fi
    done

    # Confirm that the ports are opened
    echo "已开放以下端口："
    for port in "${PORT_LIST[@]}"; do
        if [[ $port == *-* ]]; then
            start_port=$(echo $port | cut -d'-' -f1)
            end_port=$(echo $port | cut -d'-' -f2)
            # Check if the port range has been successfully opened
            (ufw status | grep -q "$start_port:$end_port") && echo "$start_port-$end_port"
        else
            # Check if the individual port has been successfully opened
            (ufw status | grep -q "$port") && echo "$port"
        fi
    done
}

delete_ports() {
    # Display current rules with numbers
    echo "当前 UFW 规则："
    ufw status numbered

    # Ask the user how they want to delete rules
    echo "你希望通过以下方式删除规则："
    echo "1) 规则编号"
    echo "2) 端口"
    read -rp "请输入你的选择（1 或 2）： " choice

    if [[ $choice -eq 1 ]]; then
        # Deleting by rule numbers
        read -rp "请输入要删除的规则编号（1,2 等）： " rule_numbers

        # Validate the input
        if ! [[ $rule_numbers =~ ^([0-9]+)(,[0-9]+)*$ ]]; then
            echo "错误：输入无效。请输入逗号分隔的规则编号列表。" >&2
            exit 1
        fi

        # Split numbers into an array
        IFS=',' read -ra RULE_NUMBERS <<<"$rule_numbers"
        for rule_number in "${RULE_NUMBERS[@]}"; do
            # Delete the rule by number
            ufw delete "$rule_number" || echo "删除规则编号 $rule_number 失败"
        done

        echo "已删除所选规则。"

    elif [[ $choice -eq 2 ]]; then
        # Deleting by ports
        read -rp "请输入要删除的端口（例如 80,443,2053 或范围 400-500）： " ports

        # Validate the input
        if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
            echo "错误：输入无效。请输入逗号分隔的端口列表或端口范围（例如 80,443,2053 或 400-500）。" >&2
            exit 1
        fi

        # Split ports into an array
        IFS=',' read -ra PORT_LIST <<<"$ports"
        for port in "${PORT_LIST[@]}"; do
            if [[ $port == *-* ]]; then
                # Split the port range
                start_port=$(echo $port | cut -d'-' -f1)
                end_port=$(echo $port | cut -d'-' -f2)
                # Delete the port range
                ufw delete allow $start_port:$end_port/tcp
                ufw delete allow $start_port:$end_port/udp
            else
                # Delete a single port
                ufw delete allow "$port"
            fi
        done

        # Confirmation of deletion
        echo "已删除以下端口："
        for port in "${PORT_LIST[@]}"; do
            if [[ $port == *-* ]]; then
                start_port=$(echo $port | cut -d'-' -f1)
                end_port=$(echo $port | cut -d'-' -f2)
                # Check if the port range has been deleted
                (ufw status | grep -q "$start_port:$end_port") || echo "$start_port-$end_port"
            else
                # Check if the individual port has been deleted
                (ufw status | grep -q "$port") || echo "$port"
            fi
        done
    else
        echo "${red}错误：${plain} 无效选择。请输入 1 或 2。" >&2
        exit 1
    fi
}

update_all_geofiles() {
        update_main_geofiles
        update_ir_geofiles
        update_ru_geofiles
}

update_main_geofiles() {
        curl -fLRo geoip.dat       https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
        curl -fLRo geosite.dat     https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
}

update_ir_geofiles() {
        curl -fLRo geoip_IR.dat    https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
        curl -fLRo geosite_IR.dat  https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
}

update_ru_geofiles() {
        curl -fLRo geoip_RU.dat    https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
        curl -fLRo geosite_RU.dat  https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
}

update_geo() {
    echo -e "${green}\t1.${plain} Loyalsoldier (geoip.dat, geosite.dat)"
    echo -e "${green}\t2.${plain} chocolate4u (geoip_IR.dat, geosite_IR.dat)"
    echo -e "${green}\t3.${plain} runetfreedom (geoip_RU.dat, geosite_RU.dat)"
    echo -e "${green}\t4.${plain} 全部"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " choice

    cd ${xui_folder}/bin

    case "$choice" in
    0)
        show_menu
        ;;
    1)
        update_main_geofiles
        echo -e "${green}Loyalsoldier 数据集更新成功！${plain}"
        restart
        ;;
    2)
        update_ir_geofiles
        echo -e "${green}chocolate4u 数据集更新成功！${plain}"
        restart
        ;;
    3)
        update_ru_geofiles
        echo -e "${green}runetfreedom 数据集更新成功！${plain}"
        restart
        ;;
    4)
        update_all_geofiles
        echo -e "${green}所有 Geo 文件更新成功！${plain}"
        restart
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        update_geo
        ;;
    esac

    before_show_menu
}

install_acme() {
    # Check if acme.sh is already installed
    if command -v ~/.acme.sh/acme.sh &>/dev/null; then
        LOGI "acme.sh 已安装。"
        return 0
    fi

    LOGI "正在安装 acme.sh..."
    cd ~ || return 1 # Ensure you can change to the home directory

    curl -s https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        LOGE "安装 acme.sh 失败。"
        return 1
    else
        LOGI "安装 acme.sh 成功。"
    fi

    return 0
}

ssl_cert_issue_main() {
    echo -e "${green}\t1.${plain} 获取 SSL"
    echo -e "${green}\t2.${plain} 吊销"
    echo -e "${green}\t3.${plain} 强制续期"
    echo -e "${green}\t4.${plain} 显示已有域名"
    echo -e "${green}\t5.${plain} 为面板设置证书路径"
    echo -e "${green}\t6.${plain} 为服务器 IP 自动申请 SSL"
    echo -e "${green}\t0.${plain} 返回主菜单"

    read -rp "请选择一个选项： " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        ssl_cert_issue
        ssl_cert_issue_main
        ;;
    2)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "未找到可吊销的证书。"
        else
            echo "已有域名："
            echo "$domains"
            read -rp "请输入列表中的域名以吊销证书： " domain
            if echo "$domains" | grep -qw "$domain"; then
                ~/.acme.sh/acme.sh --revoke -d ${domain}
                LOGI "已吊销域名证书：$domain"
            else
                echo "输入的域名无效。"
            fi
        fi
        ssl_cert_issue_main
        ;;
    3)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "未找到可续期的证书。"
        else
            echo "已有域名："
            echo "$domains"
            read -rp "请输入列表中的域名以续期 SSL 证书： " domain
            if echo "$domains" | grep -qw "$domain"; then
                ~/.acme.sh/acme.sh --renew -d ${domain} --force
                LOGI "已强制续期域名证书：$domain"
            else
                echo "输入的域名无效。"
            fi
        fi
        ssl_cert_issue_main
        ;;
    4)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "未找到任何证书。"
        else
            echo "已有域名及其路径："
            for domain in $domains; do
                local cert_path="/root/cert/${domain}/fullchain.pem"
                local key_path="/root/cert/${domain}/privkey.pem"
                if [[ -f "${cert_path}" && -f "${key_path}" ]]; then
                    echo -e "域名：${domain}"
                    echo -e "\t证书路径：${cert_path}"
                    echo -e "\t私钥路径：${key_path}"
                else
                    echo -e "域名：${domain} - 证书或私钥缺失。"
                fi
            done
        fi
        ssl_cert_issue_main
        ;;
    5)
        local domains=$(find /root/cert/ -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ -z "$domains" ]; then
            echo "未找到任何证书。"
        else
            echo "可用域名："
            echo "$domains"
            read -rp "请选择一个域名来设置面板证书路径： " domain

            if echo "$domains" | grep -qw "$domain"; then
                local webCertFile="/root/cert/${domain}/fullchain.pem"
                local webKeyFile="/root/cert/${domain}/privkey.pem"

                if [[ -f "${webCertFile}" && -f "${webKeyFile}" ]]; then
                    ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
                    echo "已为域名设置面板路径：$domain"
                    echo "  - 证书文件：$webCertFile"
                    echo "  - 私钥文件：$webKeyFile"
                    restart
                else
                    echo "未找到该域名的证书或私钥：$domain。"
                fi
            else
                echo "输入的域名无效。"
            fi
        fi
        ssl_cert_issue_main
        ;;
    6)
        echo -e "${yellow}为服务器 IP 自动申请 SSL 证书${plain}"
        echo -e "将为你的服务器 IP 自动获取并配置 SSL 证书。"
        echo -e "${yellow}注意：Let's Encrypt 支持 IP 证书。请确保 80 端口已开放。${plain}"
        confirm "是否继续？" "y"
        if [[ $? == 0 ]]; then
            ssl_cert_issue_for_ip
        fi
        ssl_cert_issue_main
        ;;

    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        ssl_cert_issue_main
        ;;
    esac
}

ssl_cert_issue_for_ip() {
    LOGI "开始为服务器 IP 自动生成 SSL 证书..."
    
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    
    # Get server IP
    local server_ip=$(curl -s --max-time 3 https://api.ipify.org)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s --max-time 3 https://4.ident.me)
    fi
    
    if [ -z "$server_ip" ]; then
        LOGE "获取服务器 IP 地址失败"
        return 1
    fi
    
    LOGI "检测到服务器 IP：${server_ip}"
    
    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        LOGI "未找到 acme.sh，正在安装..."
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "安装 acme.sh 失败"
            return 1
        fi
    fi
    
    # install socat
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update >/dev/null 2>&1 && apt-get install socat -y >/dev/null 2>&1
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum -y update >/dev/null 2>&1 && yum -y install socat >/dev/null 2>&1
        else
            dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        fi
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm socat >/dev/null 2>&1
        ;;
    opensuse-tumbleweed | opensuse-leap)
        zypper refresh >/dev/null 2>&1 && zypper -q install -y socat >/dev/null 2>&1
        ;;
    alpine)
        apk add socat curl openssl >/dev/null 2>&1
        ;;
    *)
        LOGW "不支持的系统，无法自动安装 socat"
        ;;
    esac
    
    # check if certificate already exists for this IP
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ "${currentCert}" == "${server_ip}" ]; then
        LOGI "该 IP 已存在证书：${server_ip}"
        certPath="/root/cert/${server_ip}"
    else
        # create directory for certificate
        certPath="/root/cert/${server_ip}"
        if [ ! -d "$certPath" ]; then
            mkdir -p "$certPath"
        else
            rm -rf "$certPath"
            mkdir -p "$certPath"
        fi
        
        # Use port 80 for certificate issuance
        local WebPort=80
        LOGI "将使用端口 ${WebPort} 为 IP 申请证书：${server_ip}"
        LOGI "请确保端口 ${WebPort} 已开放且未被占用..."
        
        # issue the certificate for IP
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        ~/.acme.sh/acme.sh --issue -d ${server_ip} --listen-v6 --standalone --httpport ${WebPort} --force
        if [ $? -ne 0 ]; then
            LOGE "为 IP 申请证书失败：${server_ip}"
            LOGE "请确保端口 ${WebPort} 已开放，且服务器可从公网访问"
            rm -rf ~/.acme.sh/${server_ip}
            return 1
        else
            LOGI "为 IP 申请证书成功：${server_ip}"
        fi
        
        # install the certificate
        ~/.acme.sh/acme.sh --installcert -d ${server_ip} \
            --key-file /root/cert/${server_ip}/privkey.pem \
            --fullchain-file /root/cert/${server_ip}/fullchain.pem \
            --reloadcmd "x-ui restart"
        
        if [ $? -ne 0 ]; then
            LOGE "安装证书失败"
            rm -rf ~/.acme.sh/${server_ip}
            return 1
        else
            LOGI "证书安装成功"
        fi
        
        # enable auto-renew
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
        chmod 755 $certPath/*
    fi
    
    # Set certificate paths for the panel
    local webCertFile="/root/cert/${server_ip}/fullchain.pem"
    local webKeyFile="/root/cert/${server_ip}/privkey.pem"
    
    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
        LOGI "已为面板配置证书"
        LOGI "  - 证书文件：$webCertFile"
        LOGI "  - 私钥文件：$webKeyFile"
        echo -e "${green}访问地址： https://${server_ip}:${existing_port}${existing_webBasePath}${plain}"
        LOGI "面板将重启以应用 SSL 证书..."
        restart
        return 0
    else
        LOGE "安装完成后未找到证书文件"
        return 1
    fi
}

ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "未找到 acme.sh，将进行安装"
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "安装 acme 失败，请检查日志"
            exit 1
        fi
    fi

    # install socat
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update >/dev/null 2>&1 && apt-get install socat -y >/dev/null 2>&1
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum -y update >/dev/null 2>&1 && yum -y install socat >/dev/null 2>&1
        else
            dnf -y update >/dev/null 2>&1 && dnf -y install socat >/dev/null 2>&1
        fi
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm socat >/dev/null 2>&1
        ;;
    opensuse-tumbleweed | opensuse-leap)
        zypper refresh >/dev/null 2>&1 && zypper -q install -y socat >/dev/null 2>&1
        ;;
    alpine)
        apk add socat curl openssl >/dev/null 2>&1
        ;;
    *)
        LOGW "不支持的系统，无法自动安装 socat"
        ;;
    esac
    if [ $? -ne 0 ]; then
        LOGE "安装 socat 失败，请检查日志"
        exit 1
    else
        LOGI "安装 socat 成功..."
    fi

    # get the domain here, and we need to verify it
    local domain=""
    while true; do
        read -rp "请输入你的域名： " domain
        domain="${domain// /}"  # Trim whitespace
        
        if [[ -z "$domain" ]]; then
            LOGE "域名不能为空，请重试。"
            continue
        fi
        
        if ! is_domain "$domain"; then
            LOGE "域名格式无效：${domain}。请输入有效域名。"
            continue
        fi
        
        break
    done
    LOGD "你的域名是：${domain}，正在检查..."

    # check if there already exists a certificate
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ "${currentCert}" == "${domain}" ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        LOGE "系统已存在该域名的证书，无法再次签发。当前证书信息："
        LOGI "$certInfo"
        exit 1
    else
        LOGI "域名已准备好签发证书..."
    fi

    # create a directory for the certificate
    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    # get the port number for the standalone server
    local WebPort=80
    read -rp "请选择使用的端口（默认 80）： " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        LOGE "输入的端口 ${WebPort} 无效，将使用默认端口 80。"
        WebPort=80
    fi
    LOGI "将使用端口：${WebPort} 签发证书。请确保该端口已开放。"

    # issue the certificate
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport ${WebPort} --force
    if [ $? -ne 0 ]; then
        LOGE "签发证书失败，请检查日志。"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        LOGE "签发证书成功，正在安装证书..."
    fi

    reloadCmd="x-ui restart"

    LOGI "ACME 默认 --reloadcmd 为：${yellow}x-ui restart"
    LOGI "该命令会在每次签发与续期时执行。"
    read -rp "是否要修改 ACME 的 --reloadcmd？(y/n)： " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} 预设：systemctl reload nginx ; x-ui restart"
        echo -e "${green}\t2.${plain} 自定义命令"
        echo -e "${green}\t0.${plain} 保持默认 reloadcmd"
        read -rp "请选择一个选项： " choice
        case "$choice" in
        1)
            LOGI "Reloadcmd 为：systemctl reload nginx ; x-ui restart"
            reloadCmd="systemctl reload nginx ; x-ui restart"
            ;;
        2)  
            LOGD "建议把 x-ui restart 放在最后，这样即使其他服务重载失败也不会导致 x-ui 报错"
            read -rp "请输入 reloadcmd（例：systemctl reload nginx ; x-ui restart）： " reloadCmd
            LOGI "你的 reloadcmd 为：${reloadCmd}"
            ;;
        *)
            LOGI "保持默认 reloadcmd"
            ;;
        esac
    fi

    # install the certificate
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}"

    if [ $? -ne 0 ]; then
        LOGE "安装证书失败，退出。"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        LOGI "安装证书成功，正在启用自动续期..."
    fi

    # enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        LOGE "启用自动续期失败，证书详情："
        ls -lah cert/*
        chmod 755 $certPath/*
        exit 1
    else
        LOGI "自动续期启用成功，证书详情："
        ls -lah cert/*
        chmod 755 $certPath/*
    fi

    # Prompt user to set panel paths after successful certificate installation
    read -rp "是否将此证书设置给面板使用？(y/n)： " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            LOGI "已为域名设置面板路径：$domain"
            LOGI "  - 证书文件：$webCertFile"
            LOGI "  - 私钥文件：$webKeyFile"
            echo -e "${green}访问地址： https://${domain}:${existing_port}${existing_webBasePath}${plain}"
            restart
        else
            LOGE "错误：未找到该域名的证书或私钥文件：$domain。"
        fi
    else
        LOGI "已跳过设置面板证书路径。"
    fi
}

ssl_cert_issue_CF() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    LOGI "****** 使用说明 ******"
    LOGI "请按以下步骤完成流程："
    LOGI "1. Cloudflare 注册邮箱"
    LOGI "2. Cloudflare 全局 API Key"
    LOGI "3. 域名"
    LOGI "4. 证书签发后会提示是否为面板设置证书（可选）"
    LOGI "5. 脚本支持安装后自动续期 SSL 证书"

    confirm "请确认信息无误并继续？ [y/n]" "y"

    if [ $? -eq 0 ]; then
        # Check for acme.sh first
        if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
            echo "未找到 acme.sh，将进行安装。"
            install_acme
            if [ $? -ne 0 ]; then
                LOGE "安装 acme 失败，请检查日志。"
                exit 1
            fi
        fi

        CF_Domain=""

        LOGD "请设置域名："
        read -rp "在此输入域名： " CF_Domain
        LOGD "你的域名已设置为：${CF_Domain}"

        # Set up Cloudflare API details
        CF_GlobalKey=""
        CF_AccountEmail=""
        LOGD "请设置 API Key："
        read -rp "在此输入 Key： " CF_GlobalKey
        LOGD "你的 API Key 为：${CF_GlobalKey}"

        LOGD "请设置注册邮箱："
        read -rp "在此输入邮箱： " CF_AccountEmail
        LOGD "你的注册邮箱为：${CF_AccountEmail}"

        # Set the default CA to Let's Encrypt
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        if [ $? -ne 0 ]; then
            LOGE "设置默认 CA（Let's Encrypt）失败，脚本退出..."
            exit 1
        fi

        export CF_Key="${CF_GlobalKey}"
        export CF_Email="${CF_AccountEmail}"

        # Issue the certificate using Cloudflare DNS
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${CF_Domain} -d *.${CF_Domain} --log --force
        if [ $? -ne 0 ]; then
            LOGE "签发证书失败，脚本退出..."
            exit 1
        else
            LOGI "证书签发成功，正在安装..."
        fi

         # Install the certificate
        certPath="/root/cert/${CF_Domain}"
        if [ -d "$certPath" ]; then
            rm -rf ${certPath}
        fi

        mkdir -p ${certPath}
        if [ $? -ne 0 ]; then
            LOGE "创建目录失败：${certPath}"
            exit 1
        fi

        reloadCmd="x-ui restart"

        LOGI "ACME 默认 --reloadcmd 为：${yellow}x-ui restart"
        LOGI "该命令会在每次签发与续期时执行。"
        read -rp "是否要修改 ACME 的 --reloadcmd？(y/n)： " setReloadcmd
        if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
            echo -e "\n${green}\t1.${plain} 预设：systemctl reload nginx ; x-ui restart"
            echo -e "${green}\t2.${plain} 自定义命令"
            echo -e "${green}\t0.${plain} 保持默认 reloadcmd"
            read -rp "请选择一个选项： " choice
            case "$choice" in
            1)
                LOGI "Reloadcmd 为：systemctl reload nginx ; x-ui restart"
                reloadCmd="systemctl reload nginx ; x-ui restart"
                ;;
            2)  
                LOGD "建议把 x-ui restart 放在最后，这样即使其他服务重载失败也不会导致 x-ui 报错"
                read -rp "请输入 reloadcmd（例：systemctl reload nginx ; x-ui restart）： " reloadCmd
                LOGI "你的 reloadcmd 为：${reloadCmd}"
                ;;
            *)
                LOGI "保持默认 reloadcmd"
                ;;
            esac
        fi
        ~/.acme.sh/acme.sh --installcert -d ${CF_Domain} -d *.${CF_Domain} \
            --key-file ${certPath}/privkey.pem \
            --fullchain-file ${certPath}/fullchain.pem --reloadcmd "${reloadCmd}"
        
        if [ $? -ne 0 ]; then
            LOGE "安装证书失败，脚本退出..."
            exit 1
        else
            LOGI "证书安装成功，正在启用自动更新..."
        fi

        # Enable auto-update
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        if [ $? -ne 0 ]; then
            LOGE "启用自动更新失败，脚本退出..."
            exit 1
        else
            LOGI "证书已安装并启用自动续期。具体信息如下："
            ls -lah ${certPath}/*
            chmod 755 ${certPath}/*
        fi

        # Prompt user to set panel paths after successful certificate installation
        read -rp "是否将此证书设置给面板使用？(y/n)： " setPanel
        if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
            local webCertFile="${certPath}/fullchain.pem"
            local webKeyFile="${certPath}/privkey.pem"

            if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
                ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
                LOGI "已为域名设置面板路径：$CF_Domain"
                LOGI "  - 证书文件：$webCertFile"
                LOGI "  - 私钥文件：$webKeyFile"
                echo -e "${green}访问地址： https://${CF_Domain}:${existing_port}${existing_webBasePath}${plain}"
                restart
            else
                LOGE "错误：未找到该域名的证书或私钥文件：$CF_Domain。"
            fi
        else
            LOGI "已跳过设置面板证书路径。"
        fi
    else
        show_menu
    fi
}

run_speedtest() {
    # Check if Speedtest is already installed
    if ! command -v speedtest &>/dev/null; then
        # If not installed, determine installation method
        if command -v snap &>/dev/null; then
            # Use snap to install Speedtest
            echo "正在使用 snap 安装 Speedtest..."
            snap install speedtest
        else
            # Fallback to using package managers
            local pkg_manager=""
            local speedtest_install_script=""

            if command -v dnf &>/dev/null; then
                pkg_manager="dnf"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
            elif command -v yum &>/dev/null; then
                pkg_manager="yum"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
            elif command -v apt-get &>/dev/null; then
                pkg_manager="apt-get"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
            elif command -v apt &>/dev/null; then
                pkg_manager="apt"
                speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
            fi

            if [[ -z $pkg_manager ]]; then
                echo "错误：未找到包管理器。你可能需要手动安装 Speedtest。"
                return 1
            else
                echo "正在使用 $pkg_manager 安装 Speedtest..."
                curl -s $speedtest_install_script | bash
                $pkg_manager install -y speedtest
            fi
        fi
    fi

    speedtest
}



ip_validation() {
    ipv6_regex="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    ipv4_regex="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)$"
}

iplimit_main() {
    echo -e "\n${green}\t1.${plain} 安装 Fail2ban 并配置 IP 限制"
    echo -e "${green}\t2.${plain} 修改封禁时长"
    echo -e "${green}\t3.${plain} 解封所有人"
    echo -e "${green}\t4.${plain} 封禁日志"
    echo -e "${green}\t5.${plain} 手动封禁 IP"
    echo -e "${green}\t6.${plain} 手动解封 IP"
    echo -e "${green}\t7.${plain} 实时日志"
    echo -e "${green}\t8.${plain} 服务状态"
    echo -e "${green}\t9.${plain} 重启服务"
    echo -e "${green}\t10.${plain} 卸载 Fail2ban 和 IP 限制"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        confirm "确认安装 Fail2ban 与 IP 限制？" "y"
        if [[ $? == 0 ]]; then
            install_iplimit
        else
            iplimit_main
        fi
        ;;
    2)
        read -rp "请输入新的封禁时长（分钟）[默认 30]： " NUM
        if [[ $NUM =~ ^[0-9]+$ ]]; then
            create_iplimit_jails ${NUM}
            if [[ $release == "alpine" ]]; then
                rc-service fail2ban restart
            else
                systemctl restart fail2ban
            fi
        else
            echo -e "${red}${NUM} 不是数字！请重试。${plain}"
        fi
        iplimit_main
        ;;
    3)
        confirm "确认解封 IP Limit jail 中的所有用户？" "y"
        if [[ $? == 0 ]]; then
            fail2ban-client reload --restart --unban 3x-ipl
            truncate -s 0 "${iplimit_banned_log_path}"
            echo -e "${green}已成功解封所有用户。${plain}"
            iplimit_main
        else
            echo -e "${yellow}已取消。${plain}"
        fi
        iplimit_main
        ;;
    4)
        show_banlog
        iplimit_main
        ;;
    5)
        read -rp "请输入要封禁的 IP 地址： " ban_ip
        ip_validation
        if [[ $ban_ip =~ $ipv4_regex || $ban_ip =~ $ipv6_regex ]]; then
            fail2ban-client set 3x-ipl banip "$ban_ip"
            echo -e "${green}IP 地址 ${ban_ip} 已成功封禁。${plain}"
        else
            echo -e "${red}IP 地址格式无效！请重试。${plain}"
        fi
        iplimit_main
        ;;
    6)
        read -rp "请输入要解封的 IP 地址： " unban_ip
        ip_validation
        if [[ $unban_ip =~ $ipv4_regex || $unban_ip =~ $ipv6_regex ]]; then
            fail2ban-client set 3x-ipl unbanip "$unban_ip"
            echo -e "${green}IP 地址 ${unban_ip} 已成功解封。${plain}"
        else
            echo -e "${red}IP 地址格式无效！请重试。${plain}"
        fi
        iplimit_main
        ;;
    7)
        tail -f /var/log/fail2ban.log
        iplimit_main
        ;;
    8)
        service fail2ban status
        iplimit_main
        ;;
    9)
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban restart
        else
            systemctl restart fail2ban
        fi
        iplimit_main
        ;;
    10)
        remove_iplimit
        iplimit_main
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        iplimit_main
        ;;
    esac
}

install_iplimit() {
    if ! command -v fail2ban-client &>/dev/null; then
        echo -e "${green}未安装 Fail2ban，正在安装...！${plain}\n"

        # Check the OS and install necessary packages
        case "${release}" in
        ubuntu)
            apt-get update
            if [[ "${os_version}" -ge 24 ]]; then
                apt-get install python3-pip -y
                python3 -m pip install pyasynchat --break-system-packages
            fi
            apt-get install fail2ban -y
            ;;
        debian)
            apt-get update
            if [ "$os_version" -ge 12 ]; then
                apt-get install -y python3-systemd
            fi
            apt-get install -y fail2ban
            ;;
        armbian)
            apt-get update && apt-get install fail2ban -y
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y update && dnf -y install fail2ban
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum update -y && yum install epel-release -y
                yum -y install fail2ban
            else
                dnf -y update && dnf -y install fail2ban
            fi
            ;;
        arch | manjaro | parch)
            pacman -Syu --noconfirm fail2ban
            ;;
        alpine)
            apk add fail2ban
            ;;
        *)
            echo -e "${red}不支持的操作系统。请检查脚本并手动安装所需依赖。${plain}\n"
            exit 1
            ;;
        esac

        if ! command -v fail2ban-client &>/dev/null; then
            echo -e "${red}Fail2ban 安装失败。${plain}\n"
            exit 1
        fi

        echo -e "${green}Fail2ban 安装成功！${plain}\n"
    else
        echo -e "${yellow}Fail2ban 已安装。${plain}\n"
    fi

    echo -e "${green}正在配置 IP 限制...${plain}\n"

    # make sure there's no conflict for jail files
    iplimit_remove_conflicts

    # Check if log file exists
    if ! test -f "${iplimit_banned_log_path}"; then
        touch ${iplimit_banned_log_path}
    fi

    # Check if service log file exists so fail2ban won't return error
    if ! test -f "${iplimit_log_path}"; then
        touch ${iplimit_log_path}
    fi

    # Create the iplimit jail files
    # we didn't pass the bantime here to use the default value
    create_iplimit_jails

    # Launching fail2ban
    if [[ $release == "alpine" ]]; then
        if [[ $(rc-service fail2ban status | grep -F 'status: started' -c) == 0 ]]; then
            rc-service fail2ban start
        else
            rc-service fail2ban restart
        fi
        rc-update add fail2ban
    else
        if ! systemctl is-active --quiet fail2ban; then
            systemctl start fail2ban
        else
            systemctl restart fail2ban
        fi
        systemctl enable fail2ban
    fi

    echo -e "${green}IP 限制安装并配置成功！${plain}\n"
    before_show_menu
}

remove_iplimit() {
    echo -e "${green}\t1.${plain} 仅移除 IP 限制配置"
    echo -e "${green}\t2.${plain} 卸载 Fail2ban 和 IP 限制"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " num
    case "$num" in
    1)
        rm -f /etc/fail2ban/filter.d/3x-ipl.conf
        rm -f /etc/fail2ban/action.d/3x-ipl.conf
        rm -f /etc/fail2ban/jail.d/3x-ipl.conf
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban restart
        else
            systemctl restart fail2ban
        fi
        echo -e "${green}IP 限制移除成功！${plain}\n"
        before_show_menu
        ;;
    2)
        rm -rf /etc/fail2ban
        if [[ $release == "alpine" ]]; then
            rc-service fail2ban stop
        else
            systemctl stop fail2ban
        fi
        case "${release}" in
        ubuntu | debian | armbian)
            apt-get remove -y fail2ban
            apt-get purge -y fail2ban -y
            apt-get autoremove -y
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf remove fail2ban -y
            dnf autoremove -y
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then    
                yum remove fail2ban -y
                yum autoremove -y
            else
                dnf remove fail2ban -y
                dnf autoremove -y
            fi
            ;;
        arch | manjaro | parch)
            pacman -Rns --noconfirm fail2ban
            ;;
        alpine)
            apk del fail2ban
            ;;
        *)
            echo -e "${red}不支持的操作系统。请手动卸载 Fail2ban。${plain}\n"
            exit 1
            ;;
        esac
        echo -e "${green}Fail2ban 与 IP 限制移除成功！${plain}\n"
        before_show_menu
        ;;
    0)
        show_menu
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        remove_iplimit
        ;;
    esac
}

show_banlog() {
    local system_log="/var/log/fail2ban.log"

    echo -e "${green}正在检查封禁日志...${plain}\n"

    if [[ $release == "alpine" ]]; then
        if [[ $(rc-service fail2ban status | grep -F 'status: started' -c) == 0 ]]; then
            echo -e "${red}Fail2ban 服务未运行！${plain}\n"
            return 1
        fi
    else
        if ! systemctl is-active --quiet fail2ban; then
            echo -e "${red}Fail2ban 服务未运行！${plain}\n"
            return 1
        fi
    fi

    if [[ -f "$system_log" ]]; then
        echo -e "${green}fail2ban.log 中最近的封禁/解封记录：${plain}"
        grep "3x-ipl" "$system_log" | grep -E "Ban|Unban" | tail -n 10 || echo -e "${yellow}未找到最近的系统封禁活动${plain}"
        echo ""
    fi

    if [[ -f "${iplimit_banned_log_path}" ]]; then
        echo -e "${green}3X-IPL 封禁日志条目：${plain}"
        if [[ -s "${iplimit_banned_log_path}" ]]; then
            grep -v "INIT" "${iplimit_banned_log_path}" | tail -n 10 || echo -e "${yellow}未找到封禁记录${plain}"
        else
            echo -e "${yellow}封禁日志文件为空${plain}"
        fi
    else
        echo -e "${red}未找到封禁日志文件：${iplimit_banned_log_path}${plain}"
    fi

    echo -e "\n${green}当前 jail 状态：${plain}"
    fail2ban-client status 3x-ipl || echo -e "${yellow}无法获取 jail 状态${plain}"
}

create_iplimit_jails() {
    # Use default bantime if not passed => 30 minutes
    local bantime="${1:-30}"

    # Uncomment 'allowipv6 = auto' in fail2ban.conf
    sed -i 's/#allowipv6 = auto/allowipv6 = auto/g' /etc/fail2ban/fail2ban.conf

    # On Debian 12+ fail2ban's default backend should be changed to systemd
    if [[  "${release}" == "debian" && ${os_version} -ge 12 ]]; then
        sed -i '0,/action =/s/backend = auto/backend = systemd/' /etc/fail2ban/jail.conf
    fi

    cat << EOF > /etc/fail2ban/jail.d/3x-ipl.conf
[3x-ipl]
enabled=true
backend=auto
filter=3x-ipl
action=3x-ipl
logpath=${iplimit_log_path}
maxretry=2
findtime=32
bantime=${bantime}m
EOF

    cat << EOF > /etc/fail2ban/filter.d/3x-ipl.conf
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*SRC\s*=\s*<ADDR>
ignoreregex =
EOF

    cat << EOF > /etc/fail2ban/action.d/3x-ipl.conf
[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   BAN   [Email] = <F-USER> [IP] = <ip> banned for <bantime> seconds." >> ${iplimit_banned_log_path}

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   UNBAN   [Email] = <F-USER> [IP] = <ip> unbanned." >> ${iplimit_banned_log_path}

[Init]
name = default
protocol = tcp
chain = INPUT
EOF

    echo -e "${green}已创建 IP 限制 jail 文件，封禁时长为 ${bantime} 分钟。${plain}"
}

iplimit_remove_conflicts() {
    local jail_files=(
        /etc/fail2ban/jail.conf
        /etc/fail2ban/jail.local
    )

    for file in "${jail_files[@]}"; do
        # Check for [3x-ipl] config in jail file then remove it
        if test -f "${file}" && grep -qw '3x-ipl' ${file}; then
            sed -i "/\[3x-ipl\]/,/^$/d" ${file}
            echo -e "${yellow}正在移除 jail（${file}）中 [3x-ipl] 的冲突配置！${plain}\n"
        fi
    done
}

SSH_port_forwarding() {
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
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_listenIP=$(${xui_folder}/x-ui setting -getListen true | grep -Eo 'listenIP: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep -Eo 'cert: .+' | awk '{print $2}')
    local existing_key=$(${xui_folder}/x-ui setting -getCert true | grep -Eo 'key: .+' | awk '{print $2}')

    local config_listenIP=""
    local listen_choice=""

    if [[ -n "$existing_cert" && -n "$existing_key" ]]; then
        echo -e "${green}面板已启用 SSL，连接安全。${plain}"
        before_show_menu
    fi
    if [[ -z "$existing_cert" && -z "$existing_key" && (-z "$existing_listenIP" || "$existing_listenIP" == "0.0.0.0") ]]; then
        echo -e "\n${red}警告：未找到证书与私钥！面板连接不安全。${plain}"
        echo "请获取证书或设置 SSH 端口转发。"
    fi

    if [[ -n "$existing_listenIP" && "$existing_listenIP" != "0.0.0.0" && (-z "$existing_cert" && -z "$existing_key") ]]; then
        echo -e "\n${green}当前 SSH 端口转发配置：${plain}"
        echo -e "标准 SSH 命令："
        echo -e "${yellow}ssh -L 2222:${existing_listenIP}:${existing_port} root@${server_ip}${plain}"
        echo -e "\n若使用 SSH Key："
        echo -e "${yellow}ssh -i <sshkeypath> -L 2222:${existing_listenIP}:${existing_port} root@${server_ip}${plain}"
        echo -e "\n连接后访问面板："
        echo -e "${yellow}http://localhost:2222${existing_webBasePath}${plain}"
    fi

    echo -e "\n请选择一个选项："
    echo -e "${green}1.${plain} 设置 listen IP"
    echo -e "${green}2.${plain} 清除 listen IP"
    echo -e "${green}0.${plain} 返回主菜单"
    read -rp "请选择一个选项： " num

    case "$num" in
    1)
        if [[ -z "$existing_listenIP" || "$existing_listenIP" == "0.0.0.0" ]]; then
            echo -e "\n当前未配置 listenIP。请选择："
            echo -e "1. 使用默认 IP（127.0.0.1）"
            echo -e "2. 自定义 IP"
            read -rp "请选择（1 或 2）： " listen_choice

            config_listenIP="127.0.0.1"
            [[ "$listen_choice" == "2" ]] && read -rp "请输入自定义 listen IP： " config_listenIP

            ${xui_folder}/x-ui setting -listenIP "${config_listenIP}" >/dev/null 2>&1
            echo -e "${green}listen IP 已设置为 ${config_listenIP}。${plain}"
            echo -e "\n${green}SSH 端口转发配置：${plain}"
            echo -e "标准 SSH 命令："
            echo -e "${yellow}ssh -L 2222:${config_listenIP}:${existing_port} root@${server_ip}${plain}"
            echo -e "\n若使用 SSH Key："
            echo -e "${yellow}ssh -i <sshkeypath> -L 2222:${config_listenIP}:${existing_port} root@${server_ip}${plain}"
            echo -e "\n连接后访问面板："
            echo -e "${yellow}http://localhost:2222${existing_webBasePath}${plain}"
            restart
        else
            config_listenIP="${existing_listenIP}"
            echo -e "${green}当前 listen IP 已设置为 ${config_listenIP}。${plain}"
        fi
        ;;
    2)
        ${xui_folder}/x-ui setting -listenIP 0.0.0.0 >/dev/null 2>&1
        echo -e "${green}已清除 listen IP。${plain}"
        restart
        ;;
    0)
        show_menu
        ;;
    *)
        echo -e "${red}无效选项。请选择有效数字。${plain}\n"
        SSH_port_forwarding
        ;;
    esac
}

show_usage() {
    echo -e "┌────────────────────────────────────────────────────────────────┐
│  ${blue}x-ui 控制菜单用法（子命令）：${plain}                        │
│                                                                    │
│  ${blue}x-ui${plain}                       - 管理脚本主命令         │
│  ${blue}x-ui start${plain}                 - 启动                  │
│  ${blue}x-ui stop${plain}                  - 停止                  │
│  ${blue}x-ui restart${plain}               - 重启                  │
│  ${blue}x-ui status${plain}                - 当前状态              │
│  ${blue}x-ui settings${plain}              - 当前设置              │
│  ${blue}x-ui enable${plain}                - 启用开机自启动        │
│  ${blue}x-ui disable${plain}               - 禁用开机自启动        │
│  ${blue}x-ui log${plain}                   - 查看日志              │
│  ${blue}x-ui banlog${plain}                - 查看 Fail2ban 封禁日志 │
│  ${blue}x-ui update${plain}                - 更新                  │
│  ${blue}x-ui update-all-geofiles${plain}   - 更新所有 Geo 文件     │
│  ${blue}x-ui legacy${plain}                - 旧版本                │
│  ${blue}x-ui install${plain}               - 安装                  │
│  ${blue}x-ui uninstall${plain}             - 卸载                  │
└────────────────────────────────────────────────────────────────┘"
}

show_menu() {
    echo -e "
╔────────────────────────────────────────────────╗
│   ${green}3X-UI 面板管理脚本${plain}                        │
│   ${green}0.${plain} 退出脚本                              │
│────────────────────────────────────────────────│
│   ${green}1.${plain} 安装面板                              │
│   ${green}2.${plain} 更新面板                              │
│   ${green}3.${plain} 更新管理菜单                          │
│   ${green}4.${plain} 使用旧版本                            │
│   ${green}5.${plain} 卸载面板                              │
│────────────────────────────────────────────────│
│   ${green}6.${plain} 重置用户名和密码                      │
│   ${green}7.${plain} 重置 Web Base Path                   │
│   ${green}8.${plain} 重置所有设置                          │
│   ${green}9.${plain} 修改端口                              │
│  ${green}10.${plain} 查看当前配置                          │
│────────────────────────────────────────────────│
│  ${green}11.${plain} 启动服务                              │
│  ${green}12.${plain} 停止服务                              │
│  ${green}13.${plain} 重启服务                              │
│  ${green}14.${plain} 查看运行状态                          │
│  ${green}15.${plain} 日志管理                              │
│────────────────────────────────────────────────│
│  ${green}16.${plain} 启用开机自启动                        │
│  ${green}17.${plain} 禁用开机自启动                        │
│────────────────────────────────────────────────│
│  ${green}18.${plain} SSL 证书管理                          │
│  ${green}19.${plain} Cloudflare SSL 证书                   │
│  ${green}20.${plain} IP 限制管理                           │
│  ${green}21.${plain} 防火墙管理                            │
│  ${green}22.${plain} SSH 端口转发管理                      │
│────────────────────────────────────────────────│
│  ${green}23.${plain} 启用 BBR                              │
│  ${green}24.${plain} 更新 Geo 文件                         │
│  ${green}25.${plain} Ookla 网络测速                        │
╚────────────────────────────────────────────────╝
"
    show_status
    echo && read -rp "请输入你的选择 [0-25]： " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && update_menu
        ;;
    4)
        check_install && legacy_version
        ;;
    5)
        check_install && uninstall
        ;;
    6)
        check_install && reset_user
        ;;
    7)
        check_install && reset_webbasepath
        ;;
    8)
        check_install && reset_config
        ;;
    9)
        check_install && set_port
        ;;
    10)
        check_install && check_config
        ;;
    11)
        check_install && start
        ;;
    12)
        check_install && stop
        ;;
    13)
        check_install && restart
        ;;
    14)
        check_install && status
        ;;
    15)
        check_install && show_log
        ;;
    16)
        check_install && enable
        ;;
    17)
        check_install && disable
        ;;
    18)
        ssl_cert_issue_main
        ;;
    19)
        ssl_cert_issue_CF
        ;;
    20)
        iplimit_main
        ;;
    21)
        firewall_menu
        ;;
    22)
        SSH_port_forwarding
        ;;
    23)
        bbr_menu
        ;;
    24)
        update_geo
        ;;
    25)
        run_speedtest
        ;;
    *)
        LOGE "请输入正确的数字 [0-25]"
        ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start 0
        ;;
    "stop")
        check_install 0 && stop 0
        ;;
    "restart")
        check_install 0 && restart 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "settings")
        check_install 0 && check_config 0
        ;;
    "enable")
        check_install 0 && enable 0
        ;;
    "disable")
        check_install 0 && disable 0
        ;;
    "log")
        check_install 0 && show_log 0
        ;;
    "banlog")
        check_install 0 && show_banlog 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "legacy")
        check_install 0 && legacy_version 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    "update-all-geofiles")
        check_install 0 && update_all_geofiles 0 && restart 0
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi
