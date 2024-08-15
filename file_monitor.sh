#!/bin/bash

# 严格模式
set -euo pipefail

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# 基础目录和配置文件
readonly BASE_DIR="/var/lib/file_monitor"
readonly CONFIG_FILE="$BASE_DIR/config.ini"
readonly INIT_FLAG_FILE="$BASE_DIR/initialized"

# 默认配置
declare -A DEFAULT_CONFIG=(
    [LOG_FILE]="$BASE_DIR/file_monitor.log"
    [INITIAL_STATE_FILE]="$BASE_DIR/initial_state.txt"
    [NEW_ITEMS_FILE]="$BASE_DIR/new_items.txt"
    [PID_FILE]="$BASE_DIR/file_monitor.pid"
    [IGNORE_PATTERNS]="^/proc/|^/sys/|^/dev/|^/run/|^/tmp/|^/var/log/|^/var/cache/|^/home/|^/bin/|^/boot/"
    [SYSTEM_PARAMS_FILE]="$BASE_DIR/system_params.txt"
    [SYSCTL_CONF]="/etc/sysctl.d/99-sysctl.conf"
    [WHITELIST_FILE]="$BASE_DIR/whitelist.txt"
)

# 全局变量
declare -A config
for key in "${!DEFAULT_CONFIG[@]}"; do
    config[$key]="${DEFAULT_CONFIG[$key]}"
done
TEMP_FILES=()
HOSTNAME=""

# 错误处理函数
error_exit() {
    echo -e "${RED}错误: $1${NC}" >&2
    exit 1
}

# 清理函数
cleanup() {
    for file in "${TEMP_FILES[@]}"; do
        [ -f "$file" ] && rm -f "$file"
    done
}

trap cleanup EXIT

# 日志轮转
rotate_log() {
    local max_size=$((2*1024*1024))  # 2MB
    local log_file="${config[LOG_FILE]}"

    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file") -gt $max_size ]; then
        mv "$log_file" "${log_file}.1"
        touch "$log_file"
        chmod 600 "$log_file"
        log "INFO" "日志文件已轮转"
    fi
}

# 检查并设置 nohup
check_nohup() {
    if [ -z "${NOHUP_EXECUTED:-}" ]; then
        log "INFO" "设置 nohup 环境..."
        export NOHUP_EXECUTED=1
        nohup "$0" "$@" > /dev/null 2>&1 &
        log "INFO" "脚本已在 nohup 环境中启动，进程 ID: $!"
        exit 0
    fi
}

# 日志函数
log() {
    local level="$1"
    local message="$2"
    local log_file="${config[LOG_FILE]:-${DEFAULT_CONFIG[LOG_FILE]}}"
    echo "$(date "+%Y-%m-%d %H:%M:%S") [$level] [$HOSTNAME] - $message" >> "$log_file"
    rotate_log
}

# 获取主机名函数
get_hostname() {
    local hostname
    if [ -f /etc/hostname ]; then
        hostname=$(cat /etc/hostname)
    elif command -v hostname >/dev/null 2>&1; then
        hostname=$(hostname)
    elif command -v uname >/dev/null 2>&1; then
        hostname=$(uname -n)
    else
        hostname="unknown_host"
    fi
    hostname=${hostname%%.*}
    echo "$hostname"
}

# 检查并创建配置文件
create_config() {
    local config_dir=$(dirname "$CONFIG_FILE")
    mkdir -p "$config_dir" || error_exit "无法创建配置文件目录: $config_dir"

    touch "$CONFIG_FILE" || error_exit "无法创建配置文件: $CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" || error_exit "无法设置配置文件权限"

    for key in "${!DEFAULT_CONFIG[@]}"; do
        echo "$key=\"${DEFAULT_CONFIG[$key]}\"" >> "$CONFIG_FILE"
    done
    log "INFO" "已创建默认配置文件 $CONFIG_FILE"
}

# 读取配置文件
read_config() {
    [ -f "$CONFIG_FILE" ] || error_exit "配置文件 $CONFIG_FILE 不存在"
    while IFS='=' read -r key value; do
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//')
        if [[ -n $key && -n $value ]]; then
            config["$key"]="$value"
        fi
    done < "$CONFIG_FILE"

    # 使用默认值填充未设置的配置项
    for key in "${!DEFAULT_CONFIG[@]}"; do
        if [[ -z ${config[$key]} ]]; then
            config[$key]="${DEFAULT_CONFIG[$key]}"
        fi
    done
}

# 检查root权限
check_root() {
    [ "$(id -u)" = "0" ] || error_exit "此脚本需要 root 权限运行。"
}

# 初始化系统
initialize_system() {
    check_root

    # 确保基本目录存在
    mkdir -p "$BASE_DIR" || error_exit "无法创建基本目录 $BASE_DIR"
    chmod 700 "$BASE_DIR" || error_exit "无法设置基本目录权限"

    # 如果配置文件不存在，创建它
    if [ ! -f "$CONFIG_FILE" ]; then
        create_config
    fi

    if [ ! -f "$INIT_FLAG_FILE" ]; then
        create_config
        read_config
        install_dependencies
        initialize_whitelist

        HOSTNAME=$(get_hostname)
        touch "$INIT_FLAG_FILE" || error_exit "无法创建初始化标志文件"
        log "INFO" "系统初始化完成"
    else
        read_config
        HOSTNAME=$(get_hostname)
    fi

    # 设置包管理器日志文件
    if [ -f /etc/debian_version ]; then
        config[PACKAGE_LOG_FILE]="/var/log/dpkg.log"
    elif [ -f /etc/redhat-release ]; then
        config[PACKAGE_LOG_FILE]="/var/log/$([ -f /var/log/dnf.log ] && echo 'dnf' || echo 'yum').log"
    else
        log "WARN" "不支持的系统类型,无法监控包安装"
    fi

    ensure_file_exists "${config[LOG_FILE]}"
    ensure_file_exists "${config[NEW_ITEMS_FILE]}"
    ensure_dir_exists "$(dirname "${config[INITIAL_STATE_FILE]}")"
}

# 辅助函数：确保文件存在
ensure_file_exists() {
    local file="$1"
    touch "$file" || error_exit "无法创建文件: $file"
    chmod 600 "$file" || error_exit "无法设置文件权限: $file"
}

# 辅助函数：确保目录存在
ensure_dir_exists() {
    local dir="$1"
    mkdir -p "$dir" || error_exit "无法创建目录: $dir"
    chmod 700 "$dir" || error_exit "无法设置目录权限: $dir"
}

# 安装依赖
install_dependencies() {
    local packages_to_install=()

    if [ -f /etc/debian_version ]; then
        local package_manager="apt-get"
        local install_command="apt-get install -y"
    elif [ -f /etc/redhat-release ]; then
        local package_manager="yum"
        local install_command="yum install -y"
    else
        error_exit "不支持的系统类型，无法自动安装依赖"
    fi

    command -v inotifywait &> /dev/null || packages_to_install+=("inotify-tools")

    if [ ${#packages_to_install[@]} -ne 0 ]; then
        log "INFO" "需要安装以下包: ${packages_to_install[*]}"
        log "INFO" "正在使用 $package_manager 安装..."
        $install_command "${packages_to_install[@]}" > /dev/null 2>&1 || error_exit "无法安装所需的包"
        log "INFO" "所需的包已成功安装"
    else
        log "INFO" "所有必需的包都已安装"
    fi
}

# 记录初始状态
record_initial_state() {
    log "INFO" "${BLUE}开始记录系统初始状态...${NC}"
    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")

    find / -xdev \( -type d -o -type f \) -print0 2>/dev/null | 
    grep -vzZ "${config[IGNORE_PATTERNS]}" | 
    sort -z > "$temp_file" || error_exit "记录初始状态时出错。find 命令失败。"

    [ -s "$temp_file" ] || error_exit "初始状态文件为空。可能是 find 命令执行失败或权限不足。"

    tr '\0' '\n' < "$temp_file" > "${config[INITIAL_STATE_FILE]}"

    [ -s "${config[INITIAL_STATE_FILE]}" ] || error_exit "无法创建可读的初始状态文件。"

    log "INFO" "${GREEN}初始状态已成功记录到 ${config[INITIAL_STATE_FILE]}${NC}"
}

# 初始化白名单
initialize_whitelist() {
    local whitelist_dir=$(dirname "${config[WHITELIST_FILE]}")
    mkdir -p "$whitelist_dir" || error_exit "无法创建白名单目录: $whitelist_dir"
    touch "${config[WHITELIST_FILE]}" || error_exit "无法创建白名单文件: ${config[WHITELIST_FILE]}"
    chmod 600 "${config[WHITELIST_FILE]}" || error_exit "无法设置白名单文件权限"
    log "INFO" "已创建白名单文件 ${config[WHITELIST_FILE]}"
}

# 检查文件是否在白名单中
is_whitelisted() {
    local file="$1"
    [ -f "${config[WHITELIST_FILE]}" ] && grep -qFx "$file" "${config[WHITELIST_FILE]}"
}

# 添加文件到白名单
add_to_whitelist() {
    local file="$1"
    ensure_file_exists "${config[WHITELIST_FILE]}"
    if ! grep -q "^$file$" "${config[WHITELIST_FILE]}"; then
        echo "$file" >> "${config[WHITELIST_FILE]}"
        log "INFO" "${GREEN}已将 $file 添加到白名单${NC}"
    else
        log "INFO" "${YELLOW}$file 已经在白名单中${NC}"
    fi
}

# 显示白名单并返回项目数量
show_whitelist() {
    if [ ! -f "${config[WHITELIST_FILE]}" ]; then
        echo -e "${YELLOW}白名单文件不存在${NC}"
        return 0
    fi
    if [ ! -s "${config[WHITELIST_FILE]}" ]; then
        echo -e "${YELLOW}白名单为空${NC}"
        return 0
    fi
    echo -e "${BLUE}白名单内容：${NC}"
    cat -n "${config[WHITELIST_FILE]}" | while read -r num line; do
        echo -e "${GREEN}$num. $line${NC}"
    done
}

# 交互式处理 Docker 容器
handle_docker_container_interactive() {
    local container_id="$1"
    local items="$2"

    echo -e "${YELLOW}发现新增的Docker容器:${NC}"
    echo -e "容器ID: ${BLUE}$container_id${NC}"
    echo -e "关联项目: ${BLUE}$items${NC}"

    if ! docker inspect "$container_id" >/dev/null 2>&1; then
        echo -e "${YELLOW}警告: Docker容器 $container_id 不存在，可能已被删除${NC}"
        return
    fi

    local container_name=$(docker inspect --format '{{.Name}}' "$container_id" | sed 's/^\///')
    local image_name=$(docker inspect --format '{{.Config.Image}}' "$container_id")

    echo -e "容器名称: ${BLUE}$container_name${NC}"
    echo -e "镜像: ${BLUE}$image_name${NC}"

    while true; do
        echo -e "${YELLOW}请选择操作:${NC}"
        echo "1) 停止并删除容器"
        echo "2) 仅停止容器"
        echo "3) 保留容器不做操作"
        read -p "请输入选项 (1/2/3): " choice

        case "$choice" in
            1)
                if docker stop "$container_id" && docker rm "$container_id"; then
                    log "INFO" "已停止并删除Docker容器: $container_id"
                    return 0
                else
                    log "ERROR" "无法停止或删除Docker容器: $container_id"
                    return 1
                fi
                ;;
            2)
                if docker stop "$container_id"; then
                    log "INFO" "已停止Docker容器: $container_id"
                    return 0
                else
                    log "ERROR" "无法停止Docker容器: $container_id"
                    return 1
                fi
                ;;
            3)
                log "INFO" "保留Docker容器: $container_id"
                return 1
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

# 处理目录
handle_directory() {
    local dir="$1"
    local temp_file="$2"

    if [ -z "$(ls -A "$dir")" ]; then
        echo -e "${GREEN}发现可删除目录: $dir（目录为空）${NC}"
        local delete_level="green"
    else
        case "$dir" in
            /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/etc/*|/var/*)
                echo -e "${RED}警告：可能是系统关键目录: $dir${NC}"
                local delete_level="red"
                ;;
            *)
                if lsof +D "$dir" > /dev/null 2>&1; then
                    echo -e "${RED}警告：目录可能包含正在运行的进程: $dir${NC}"
                    local delete_level="red"
                elif find "$dir" -type f \( -name "*.conf" -o -name "*.json" -o -name "*.db" -o -name "*.sqlite" \) | grep -q .; then
                    echo -e "${YELLOW}警告：目录可能包含重要配置或数据文件: $dir${NC}"
                    local delete_level="yellow"
                else
                    echo -e "${GREEN}发现可能可以删除的目录: $dir${NC}"
                    local delete_level="green"
                fi
                ;;
        esac
    fi

    case "$delete_level" in
        "green") echo -e "${GREEN}建议：可以安全删除${NC}" ;;
        "yellow") echo -e "${YELLOW}建议：谨慎删除，可能影响某些软件${NC}" ;;
        "red") echo -e "${RED}建议：不要删除，可能影响系统或重要软件${NC}" ;;
    esac

    read -p "是否删除此目录？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$delete_level" = "red" ]; then
            echo -e "${RED}警告：你正在尝试删除一个可能影响系统的目录。${NC}"
            read -p "你确定要继续吗？这可能会导致系统不稳定。(y/n) " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && { echo -e "${YELLOW}已取消删除 $dir${NC}"; return; }
        fi

        rm -rf "$dir" && log "INFO" "已删除目录: $dir" || { log "ERROR" "删除目录失败: $dir"; echo "$dir" >> "$temp_file"; }
    else
        log "INFO" "跳过删除: $dir"
    fi
}

# 处理文件
handle_file() {
    local file="$1"
    local temp_file="$2"
    echo -e "${YELLOW}发现新增文件: $file${NC}"

    case "$file" in
        /etc/*|/var/spool/cron/*|/var/spool/anacron/*)
            echo -e "${RED}警告：这是一个系统关键文件。删除可能会导致系统不稳定。${NC}"
            read -p "您确定要删除此文件吗？这可能会影响系统运行。(y/N) " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && { echo -e "${YELLOW}已取消删除 $file${NC}"; echo "$file" >> "$temp_file"; return; }
            ;;
        *)
            echo -e "${RED}警告：即将删除文件: $file${NC}"
            ;;
    esac

    read -p "是否确定要删除？(y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$file" && log "INFO" "${GREEN}已删除文件: $file${NC}" || { log "ERROR" "删除文件失败: $file"; echo "$file" >> "$temp_file"; }
    else
        log "INFO" "${YELLOW}跳过删除: $file${NC}"
        echo "$file" >> "$temp_file"
    fi
}

# 从白名单中移除文件
remove_from_whitelist() {
    [ -f "${config[WHITELIST_FILE]}" ] || { echo -e "${YELLOW}白名单文件不存在，无需移除${NC}"; return 1; }

    local items=()
    while IFS= read -r line; do
        [ -n "$line" ] && items+=("$line")
    done < "${config[WHITELIST_FILE]}"

    [ ${#items[@]} -eq 0 ] && { echo -e "${YELLOW}白名单为空，无需移除${NC}"; return 1; }

    while true; do
        echo -e "${BLUE}当前白名单内容：${NC}"
        for i in "${!items[@]}"; do
            echo -e "${GREEN}$((i+1)). ${items[i]}${NC}"
        done

        echo -e "${YELLOW}请输入要删除的项目编号（输入 0 返回，输入 'all' 删除所有）：${NC}"
        read -r choice

        case "$choice" in
            0) return 0 ;;
            all) 
                > "${config[WHITELIST_FILE]}"
                echo -e "${GREEN}已删除所有白名单项${NC}"
                return 1
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#items[@]}" ] && [ "$choice" -gt 0 ]; then
                    local removed_item="${items[$((choice-1))]}"
                    unset 'items[$((choice-1))]'
                    printf '%s\n' "${items[@]}" > "${config[WHITELIST_FILE]}"
                    echo -e "${GREEN}已从白名单中移除: $removed_item${NC}"
                    return 1
                else
                    echo -e "${RED}无效的选择，请重新输入。${NC}"
                fi
                ;;
        esac
    done
}

# 监控包安装
monitor_package_installation() {
    [ -z "${config[PACKAGE_LOG_FILE]}" ] && { log "WARN" "未设置包管理器日志文件,无法监控包安装"; return 1; }

    log "INFO" "开始监控包安装: ${config[PACKAGE_LOG_FILE]}"

    tail -n0 -F "${config[PACKAGE_LOG_FILE]}" | grep --line-buffered -E 'status installed|Installed:' | while read -r line; do
        if [ -f /etc/debian_version ]; then
            package=$(echo "$line" | awk '{print $5}')
        elif [ -f /etc/redhat-release ]; then
            package=$(echo "$line" | awk '{print $3}')
        fi
        if [ -n "$package" ]; then
            log "INFO" "检测到新安装包: $package"
            echo "$(date "+%Y-%m-%d %H:%M:%S") - 新安装包: $package" >> "${config[NEW_ITEMS_FILE]}"
        fi
    done &
    PACKAGE_MONITOR_PID=$!
    echo "$PACKAGE_MONITOR_PID" > "/tmp/package_monitor.pid"
    log "INFO" "${GREEN}包安装监控已启动，PID: $PACKAGE_MONITOR_PID${NC}"
    return 0
}

# 获取新增项目相关的服务名
get_related_services() {
    [ ! -f "${config[NEW_ITEMS_FILE]}" ] && { log "ERROR" "${RED}错误：新增项目文件不存在。${NC}"; return 1; }

    log "INFO" "${BLUE}正在分析新增项目相关的服务...${NC}"

    local services=()
    while IFS= read -r line; do
        item=$(echo "$line" | cut -d' ' -f5-)
        if [[ "$item" == /usr/bin/* || "$item" == /usr/lib/* || "$item" == /etc/systemd/system/* ]]; then
            local service_name=$(systemctl list-unit-files --full --all | grep "$item" | awk '{print $1}')
            if [ -n "$service_name" ]; then
                services+=("$service_name")
            else
                local package=$(dpkg -S "$item" 2>/dev/null | cut -d: -f1)
                [ -n "$package" ] && services+=("$package (包)")
            fi
        fi
    done < "${config[NEW_ITEMS_FILE]}"

    if [ ${#services[@]} -eq 0 ]; then
        log "INFO" "${YELLOW}未发现与新增项目直接相关的服务。${NC}"
    else
        log "INFO" "${GREEN}发现以下可能相关的服务或包：${NC}"
        printf '%s\n' "${services[@]}" | sort -u
    fi
}

# 清理新增项目
check_new_items() {
    [ "$(id -u)" != "0" ] && { echo -e "${RED}错误: 此脚本需要 root 权限运行。${NC}"; return 1; }
    [ ! -f "${config[NEW_ITEMS_FILE]}" ] && { log "WARN" "新增项目文件不存在：${config[NEW_ITEMS_FILE]}"; echo -e "${YELLOW}警告：新增项目文件不存在。没有需要清理的项目。${NC}"; return 0; }
    return 0
}

# 分类新增项目
categorize_new_items() {
    while IFS= read -r line; do
        item=$(echo "$line" | cut -d' ' -f5-)
        categorize_item "$item"
    done < "${config[NEW_ITEMS_FILE]}"

    # 如果没有检测到任何新增项目，输出提示信息
    if [ ${#global_new_packages[@]} -eq 0 ] && [ ${#global_docker_containers[@]} -eq 0 ] && [ ${#global_files_and_dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}没有检测到任何新增项目。${NC}"
    fi
}

# 分类单个项目
categorize_item() {
    local item="$1"

    local package_name=""
    if [ -f /etc/debian_version ]; then
        package_name=$(dpkg -S "$item" 2>/dev/null | cut -d: -f1)
    elif [ -f /etc/redhat-release ]; then
        package_name=$(rpm -qf "$item" 2>/dev/null)
    fi

    if [ -n "$package_name" ] && [ "$package_name" != "dpkg-query: no path found matching pattern $item" ]; then
        global_new_packages["$package_name"]="$item"
    elif [[ "$item" =~ /var/lib/docker/containers/([a-f0-9]{64}) ]]; then
        global_docker_containers["${BASH_REMATCH[1]}"]="$item"
    elif [ -e "$item" ]; then
        global_files_and_dirs+=("$item")
    else
        echo -e "${YELLOW}警告: 项目不存在，跳过: $item${NC}"
    fi
}


# 处理新安装的包
handle_new_packages() {
    [ ${#global_new_packages[@]} -eq 0 ] && return 0

    echo -e "\n${YELLOW}检测到新安装的包：${NC}"
    for package in "${!global_new_packages[@]}"; do
        echo -e "${BLUE}$package${NC} (${global_new_packages[$package]})"
    done
    echo -e "${YELLOW}是否要处理这些包？(y/n)${NC}"
    read -r handle_packages
    [[ ! $handle_packages =~ ^[Yy]$ ]] && { echo -e "${YELLOW}跳过处理新安装的包${NC}"; return 0; }

    for package in "${!packages[@]}"; do
        handle_single_package "$package"
    done

    [ -f /etc/debian_version ] && apt-get autoremove -y || yum autoremove -y
    echo -e "${GREEN}已清理不再需要的依赖${NC}"
}

# 处理单个包
handle_single_package() {
    local package=$1
    echo -e "${YELLOW}是否要卸载包 $package？(y/n)${NC}"
    read -r uninstall_package
    [[ ! $uninstall_package =~ ^[Yy]$ ]] && { echo -e "${YELLOW}跳过卸载包 $package${NC}"; return 0; }

    if [ -f /etc/debian_version ]; then
        dpkg -s "$package" >/dev/null 2>&1 && apt-get remove -y "$package" && echo -e "${GREEN}已卸载包: $package${NC}" || echo -e "${YELLOW}包 $package 不存在，跳过卸载${NC}"
    elif [ -f /etc/redhat-release ]; then
        rpm -q "$package" >/dev/null 2>&1 && yum remove -y "$package" && echo -e "${GREEN}已卸载包: $package${NC}" || echo -e "${YELLOW}包 $package 不存在，跳过卸载${NC}"
    fi
}

# 处理 Docker 容器
handle_docker_containers() {
    [ ${#global_docker_containers[@]} -eq 0 ] && return 1

    echo -e "${YELLOW}是否要处理这些 Docker 容器？(y/n)${NC}"
    read -r handle_containers
    [[ ! $handle_containers =~ ^[Yy]$ ]] && { echo -e "${YELLOW}跳过处理 Docker 容器${NC}"; return 1; }

    local containers_deleted=false
    for container_id in "${!global_docker_containers[@]}"; do
        if handle_docker_container_interactive "$container_id" "${global_docker_containers[$container_id]}"; then
            containers_deleted=true
            # 从全局数组中移除已处理的容器
            unset "global_docker_containers[$container_id]"
        fi
    done

    if [ "$containers_deleted" = true ]; then
        # 重新扫描和更新新增项目列表
        update_new_items_list
    fi

    return $containers_deleted
}

#重新获取新增目录
update_new_items_list() {
    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")

    # 保存仍然存在的项目
    while IFS= read -r line; do
        item=$(echo "$line" | cut -d' ' -f5-)
        if [ -e "$item" ]; then
            echo "$line" >> "$temp_file"
        fi
    done < "${config[NEW_ITEMS_FILE]}"

    # 用更新后的列表替换原文件
    mv "$temp_file" "${config[NEW_ITEMS_FILE]}"

    # 重新分类剩余项目
    categorize_remaining_items
}

# 处理文件和目录
handle_files_and_dirs() {
    [ ${#global_files_and_dirs[@]} -eq 0 ] && return 1

    echo -e "\n${YELLOW}发现以下新增文件/目录：${NC}"
    for i in "${!global_files_and_dirs[@]}"; do
        item="${global_files_and_dirs[$i]}"
        display_item "$item" "$i"
    done

    select_items_to_delete
    if [ ${#items_to_delete[@]} -gt 0 ]; then
        delete_selected_items
        return 0
    else
        echo -e "${YELLOW}未选择任何文件或目录删除。${NC}"
        return 2  
    fi
}

# 显示文件和目录
display_files_and_dirs() {
    local -n files_dirs=$1
    echo -e "\n${YELLOW}发现以下新增文件/目录：${NC}"
    for i in "${!files_dirs[@]}"; do
        item="${files_dirs[$i]}"
        display_item "$item" "$i"
    done
}

# 显示单个项目
display_item() {
    local item=$1
    local index=$2
    if [ -d "$item" ]; then
        dirname=$(basename "$item")
        if [ ${#dirname} -gt 8 ]; then
            shortened_dirname="${dirname:0:3}~${dirname: -3}"
            echo -e "${GREEN}$((index+1)).${NC} ${item%/*}/$shortened_dirname"
        else
            echo -e "${GREEN}$((index+1)).${NC} $item"
        fi
    else
        echo -e "${GREEN}$((index+1)).${NC} $item"
    fi
}

# 选择要删除的项目
select_items_to_delete() {
    echo -e "\n${YELLOW}请选择要删除的项目编号（用空格分隔），输入 'a' 删除所有，直接回车取消：${NC}"
    read -r selection

    items_to_delete=()
    if [ "$selection" = "a" ]; then
        items_to_delete=("${global_files_and_dirs[@]}")
    elif [ -n "$selection" ]; then
        for num in $selection; do
            if [[ "$num" =~ ^[0-9]+$ ]]; then
                index=$((num-1))
                if [ "$index" -ge 0 ] && [ "$index" -lt "${#global_files_and_dirs[@]}" ]; then
                    items_to_delete+=("${global_files_and_dirs[$index]}")
                else
                    echo -e "${RED}警告：选择 $num 超出范围，已忽略${NC}"
                fi
            else
                echo -e "${RED}警告：无效的输入 $num，不是数字${NC}"
            fi
        done
    fi
}

# 删除选中的项目
delete_selected_items() {
    [ ${#items_to_delete[@]} -eq 0 ] && { echo -e "${YELLOW}未选择任何项目删除。${NC}"; return 0; }

    echo -e "\n${YELLOW}以下项目将被删除：${NC}"
    for item in "${items_to_delete[@]}"; do
        echo -e "${GREEN}$item${NC}"
        display_item_info "$item"
    done

    echo -e "${RED}警告：此操作不可逆。是否确认删除？(y/N)${NC}"
    read -r confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo -e "${YELLOW}取消删除操作${NC}"; return 0; }

    for item in "${items_to_delete[@]}"; do
        delete_item "$item"
    done

    # 更新 global_files_and_dirs 数组
    for item in "${items_to_delete[@]}"; do
        for i in "${!global_files_and_dirs[@]}"; do
            if [[ "${global_files_and_dirs[$i]}" = "$item" ]]; then
                unset 'global_files_and_dirs[$i]'
            fi
        done
    done
    global_files_and_dirs=("${global_files_and_dirs[@]}")
}

# 显示项目信息
display_item_info() {
    local item=$1
    if [ -d "$item" ]; then
        display_directory_info "$item"
    elif [ -f "$item" ]; then
        display_file_info "$item"
    fi
    check_item_in_use "$item"
}

# 显示目录信息
display_directory_info() {
    local dir=$1
    echo -e "${YELLOW}  - 这是一个目录，删除可能会影响以下方面：${NC}"
    echo -e "${YELLOW}    • 目录中的所有文件和子目录将被永久删除${NC}"
    echo -e "${YELLOW}    • 可能影响依赖这些文件的应用程序或服务${NC}"
    echo -e "${YELLOW}    • 如果是配置目录，可能导致相关服务无法正常启动${NC}"

    local dir_contents=$(find "$dir" -mindepth 1 -maxdepth 1)
    [ -n "$dir_contents" ] && { echo -e "${YELLOW}    • 目录内容：${NC}"; echo "$dir_contents" | sed 's/^/      /'; }
}

# 显示文件信息
display_file_info() {
    local file=$1
    case "$file" in
        *.env)
            echo -e "${RED}  - 警告：这是一个环境配置文件${NC}"
            echo -e "${RED}    • 删除可能导致相关应用程序无法正确加载配置${NC}"
            echo -e "${RED}    • 可能影响应用程序的安全性（如果包含敏感信息）${NC}"
            ;;
        *.sqlite3*|*.db)
            echo -e "${RED}  - 警告：这可能是一个数据库文件${NC}"
            echo -e "${RED}    • 删除可能导致数据丢失${NC}"
            echo -e "${RED}    • 相关应用程序可能无法正常运行${NC}"
            ;;
        *.pem|*.key|*.crt|*.cer)
            echo -e "${RED}  - 警告：这可能是一个密钥或证书文件${NC}"
            echo -e "${RED}    • 删除可能影响加密和认证功能${NC}"
            echo -e "${RED}    • 可能导致安全相关服务无法正常工作${NC}"
            ;;
        /var/lib/docker/*)
            echo -e "${YELLOW}  - 这是 Docker 相关的文件${NC}"
            echo -e "${YELLOW}    • 删除可能影响 Docker 容器或镜像${NC}"
            echo -e "${YELLOW}    • 可能导致某些容器无法启动或数据丢失${NC}"
            ;;
        /etc/*)
            echo -e "${RED}  - 警告：这是一个系统配置文件${NC}"
            echo -e "${RED}    • 删除可能影响系统或特定服务的正常运行${NC}"
            echo -e "${RED}    • 可能需要重新配置相关服务${NC}"
            ;;
        /var/log/*)
            echo -e "${YELLOW}  - 这是一个日志文件${NC}"
            echo -e "${YELLOW}    • 删除将丢失历史日志记录${NC}"
            echo -e "${YELLOW}    • 可能影响问题诊断和系统审计${NC}"
            ;;
        /home/*)
            echo -e "${YELLOW}  - 这是用户目录中的文件${NC}"
            echo -e "${YELLOW}    • 删除可能影响特定用户的数据或配置${NC}"
            echo -e "${YELLOW}    • 可能导致用户相关的应用程序出现问题${NC}"
            ;;
        /opt/*)
            echo -e "${YELLOW}  - 这是可选应用程序目录中的文件${NC}"
            echo -e "${YELLOW}    • 删除可能影响特定的第三方应用程序${NC}"
            echo -e "${YELLOW}    • 可能导致某些服务或功能不可用${NC}"
            ;;
        *)
            echo -e "${YELLOW}  - 删除此文件可能会影响相关的应用程序或系统功能${NC}"
            echo -e "${YELLOW}    • 具体影响取决于文件的用途和内容${NC}"
            ;;
    esac
}

# 检查项目是否在使用中
check_item_in_use() {
    local item=$1
    if lsof "$item" > /dev/null 2>&1; then
        echo -e "${RED}  - 警告：此项目正在被某些进程使用${NC}"
        echo -e "${RED}    • 删除可能导致正在运行的进程出错或崩溃${NC}"
        echo -e "${RED}    • 建议在删除前停止相关服务或进程${NC}"
    fi
}

# 删除单个项目
delete_item() {
    local item=$1
    if [ -d "$item" ]; then
        rm -rf "$item" && echo -e "${GREEN}已删除目录: $item${NC}" || echo -e "${RED}无法删除目录: $item${NC}"
    elif [ -f "$item" ]; then
        rm -f "$item" && echo -e "${GREEN}已删除文件: $item${NC}" || echo -e "${RED}无法删除文件: $item${NC}"
    else
        echo -e "${YELLOW}无法删除，未知类型: $item${NC}"
    fi
}

# 处理剩余项目
handle_remaining_items() {
    local temp_file="$1"
    local remaining_count=${#global_files_and_dirs[@]}
    echo -e "\n${GREEN}清理完成。剩余 $remaining_count 个未处理的项目。${NC}"

    if [ $remaining_count -eq 0 ]; then
        > "${config[NEW_ITEMS_FILE]}"
        echo -e "${GREEN}没有剩余项目，已清空新增项目列表${NC}"
        return 0
    fi

    echo -e "${YELLOW}是否将这些项目添加到白名单？(Y/n) ${NC}"
    read -r add_to_whitelist
    add_to_whitelist=${add_to_whitelist:-Y}

    if [[ $add_to_whitelist =~ ^[Yy]$ ]]; then
        for item in "${global_files_and_dirs[@]}"; do
            add_to_whitelist "$item"
            echo -e "${GREEN}已添加到白名单：$item${NC}"
        done
        echo -e "${GREEN}已将剩余项目添加到白名单${NC}"
        > "${config[NEW_ITEMS_FILE]}"
        echo -e "${GREEN}已清空新增项目列表${NC}"
    else
        echo -e "${YELLOW}剩余项目保留在新增列表中${NC}"
        # 重新写入未处理的项目到新增项目列表
        > "${config[NEW_ITEMS_FILE]}"
        for item in "${global_files_and_dirs[@]}"; do
            echo "$(date "+%Y-%m-%d %H:%M:%S") - 检测到新增: $item" >> "${config[NEW_ITEMS_FILE]}"
        done
    fi
}

#清空
categorize_remaining_items() {
    # 清空全局变量
    global_new_packages=()
    global_docker_containers=()
    global_files_and_dirs=()

    # 重新读取和分类新增项目
    while IFS= read -r line; do
        item=$(echo "$line" | cut -d' ' -f5-)
        categorize_item "$item"
    done < "${config[NEW_ITEMS_FILE]}"
}


# 主清理函数
clean_new_items() {
    log "DEBUG" "进入 clean_new_items 函数"

    check_new_items || return 1

    echo -e "${BLUE}开始智能清理新增项目...${NC}"
    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")
    log "DEBUG" "创建临时文件: $temp_file"

    # 清空全局变量
    global_new_packages=()
    global_docker_containers=()
    global_files_and_dirs=()

    # 重新读取和分类新增项目
    categorize_new_items

    local items_deleted=false
    local user_cancelled=false

    if [ ${#global_new_packages[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}检测到新安装的包：${NC}"
        for package in "${!global_new_packages[@]}"; do
            echo -e "${BLUE}$package${NC} (${global_new_packages[$package]})"
        done
        if handle_new_packages; then
            items_deleted=true
            # 重新分类剩余项目
            categorize_remaining_items
        fi
    else
        echo -e "\n${YELLOW}没有检测到新安装的包。${NC}"
    fi

    if [ ${#global_docker_containers[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}检测到新增的 Docker 容器：${NC}"
        for container_id in "${!global_docker_containers[@]}"; do
            echo -e "${BLUE}容器 ID: $container_id${NC}"
            echo -e "相关信息: ${global_docker_containers[$container_id]}"
        done
        if handle_docker_containers; then
            items_deleted=true
            update_new_items_list
        fi
    else
        echo -e "\n${YELLOW}没有检测到新增的 Docker 容器。${NC}"
    fi

    if [ ${#global_files_and_dirs[@]} -gt 0 ]; then
        if handle_files_and_dirs; then
            items_deleted=true
        else
            user_cancelled=true
        fi
    else
        echo -e "\n${YELLOW}没有检测到新增的文件或目录。${NC}"
    fi

    if $items_deleted; then
        handle_remaining_items "$temp_file"
    elif ! $user_cancelled; then
        echo -e "${YELLOW}未进行任何删除操作。${NC}"
        echo -e "${YELLOW}是否要查看当前的新增项目列表？(y/N)${NC}"
        read -r view_items
        if [[ $view_items =~ ^[Yy]$ ]]; then
            view_new_items
        fi
    fi

    log "DEBUG" "clean_new_items 函数执行完毕"
    return 0
}
#清理结尾

# 检查并添加开机自启
add_to_startup() {
    local script_path=$(readlink -f "$0")
    local startup_command="@reboot root $script_path start"
    local crontab_file="/etc/crontab"

    if ! grep -q "$script_path" "$crontab_file"; then
        echo "$startup_command" >> "$crontab_file"
        log "INFO" "已将脚本添加到开机自启"
    else
        log "INFO" "脚本已在开机自启列表中"
    fi
}

# 从开机自启中移除
remove_from_startup() {
    local script_path=$(readlink -f "$0")
    local crontab_file="/etc/crontab"

    if grep -q "$script_path" "$crontab_file"; then
        sed -i "\|$script_path|d" "$crontab_file"
        log "INFO" "已从开机自启中移除脚本"
    else
        log "INFO" "脚本未在开机自启列表中"
    fi
}

check_startup_entry() {
    grep -q "$(realpath "$0")" /etc/crontab
}

# 启动守护进程
start_daemon() {
    echo -e "${BLUE}正在尝试启动守护进程...${NC}"
    log "INFO" "开始启动守护进程"

    local daemon_started=false

    local available_space=$(df -k / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1048576 ]; then
        log "ERROR" "磁盘空间不足。可用空间: ${available_space}KB"
        echo -e "${RED}错误: 磁盘空间不足。可用空间: ${available_space}KB${NC}"
        return 1
    fi

    if [ -f "${config[PID_FILE]}" ]; then
        local pid=$(cat "${config[PID_FILE]}")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "守护进程已在运行，PID: $pid"
            echo -e "${GREEN}守护进程正在运行，PID: $pid${NC}"
            daemon_started=true
        else
            log "WARN" "发现陈旧的 PID 文件，将被删除"
            echo -e "${YELLOW}发现陈旧的 PID 文件，将被删除。${NC}"
            rm -f "${config[PID_FILE]}"
        fi
    fi

    if [ "$daemon_started" = false ]; then
        log "INFO" "开始记录初始状态"
        record_initial_state || { log "ERROR" "无法记录初始状态"; echo -e "${RED}错误: 无法记录初始状态。${NC}"; return 1; }

        log "INFO" "开始监控变化"
        monitor_changes || { log "ERROR" "无法启动文件系统监控"; echo -e "${RED}错误: 无法启动文件系统监控。${NC}"; echo -e "${YELLOW}请查看日志文件以获取更多信息: ${config[LOG_FILE]}${NC}"; tail -n 20 "${config[LOG_FILE]}"; return 1; }

        [ ! -f "${config[PID_FILE]}" ] && { log "ERROR" "PID 文件未创建，监控可能未成功启动"; echo -e "${RED}错误: PID 文件未创建，监控可能未成功启动。${NC}"; return 1; }

        local monitor_pid=$(cat "${config[PID_FILE]}")

        sleep 2

        if ! kill -0 "$monitor_pid" 2>/dev/null; then
            log "ERROR" "守护进程启动失败，无法找到进程 PID: $monitor_pid"
            echo -e "${RED}错误: 守护进程启动失败，无法找到进程 PID: $monitor_pid${NC}"
            echo -e "${YELLOW}最后 20 行日志:${NC}"
            tail -n 20 "${config[LOG_FILE]}"
            return 1
        fi

        log "INFO" "守护进程启动成功，PID: $monitor_pid"
        echo -e "${GREEN}守护进程已成功启动，PID: $monitor_pid${NC}"
    fi

    # 启动包安装监控
    if ! monitor_package_installation; then
        log "ERROR" "无法启动包安装监控"
        echo -e "${RED}错误: 无法启动包安装监控。${NC}"
    else
        log "INFO" "包安装监控已启动"
        echo -e "${GREEN}包安装监控已启动。${NC}"
    fi

    if check_startup_entry; then
        log "INFO" "脚本已在开机自启列表中"
        echo -e "${GREEN}脚本已在开机自启列表中。${NC}"
    else
        if add_to_startup; then
            log "INFO" "已添加到开机自启"
            echo -e "${GREEN}已添加到开机自启。${NC}"
        else
            log "WARN" "无法添加到开机自启"
            echo -e "${YELLOW}警告: 无法添加到开机自启。${NC}"
        fi
    fi

    echo -e "${YELLOW}监控进程正在后台运行。您可以继续使用其他功能。${NC}"
    return 0
}

# 停止守护进程
stop_daemon() {
    echo -e "${BLUE}正在停止守护进程...${NC}"

    if [ -f "${config[PID_FILE]}" ]; then
        local pid=$(cat "${config[PID_FILE]}")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}正在停止守护进程 (PID: $pid)${NC}"
            kill "$pid"
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${YELLOW}守护进程没有立即停止，尝试强制终止${NC}"
                kill -9 "$pid"
                sleep 1
            fi
            kill -0 "$pid" 2>/dev/null && echo -e "${RED}无法停止守护进程 (PID: $pid)${NC}" || echo -e "${GREEN}已成功停止守护进程 (PID: $pid)${NC}"
        else
            echo -e "${YELLOW}守护进程 (PID: $pid) 不存在，可能已经停止${NC}"
        fi
        rm -f "${config[PID_FILE]}"
    else
        echo -e "${YELLOW}PID 文件不存在，守护进程可能未在运行${NC}"
    fi

    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid=$(cat "/tmp/package_monitor.pid")
        if [ -n "$package_pid" ] && kill -0 "$package_pid" 2>/dev/null; then
            echo -e "${YELLOW}正在停止包安装监控 (PID: $package_pid)${NC}"
            kill "$package_pid"
            sleep 1
            if kill -0 "$package_pid" 2>/dev/null; then
                echo -e "${YELLOW}包安装监控没有立即停止，尝试强制终止${NC}"
                kill -9 "$package_pid"
                sleep 1
            fi
            kill -0 "$package_pid" 2>/dev/null && echo -e "${RED}无法停止包安装监控 (PID: $package_pid)${NC}" || echo -e "${GREEN}已成功停止包安装监控 (PID: $package_pid)${NC}"
        else
            echo -e "${YELLOW}包安装监控进程 (PID: $package_pid) 不存在，可能已经停止${NC}"
        fi
        rm -f "/tmp/package_monitor.pid"
    else
        echo -e "${YELLOW}包安装监控 PID 文件不存在，可能未在运行${NC}"
    fi

    pkill -f "inotifywait" && echo -e "${GREEN}已停止所有 inotifywait 进程${NC}" || echo -e "${YELLOW}没有找到运行中的 inotifywait 进程${NC}"

    remove_from_startup && echo -e "${GREEN}已从开机自启中移除${NC}" || echo -e "${YELLOW}无法从开机自启中移除${NC}"

    echo -e "${GREEN}守护进程停止操作完成${NC}"
}

# 监控删除
remove_from_file() {
    local file="$1"
    local pattern="$2"
    local temp_file=$(mktemp)
    grep -v "$pattern" "$file" > "$temp_file"
    mv "$temp_file" "$file"
}

# 监控文件系统变化
monitor_changes() {
    log "INFO" "${BLUE}开始监控文件系统变化（仅创建和删除）...${NC}"

    command -v inotifywait >/dev/null 2>&1 || { log "ERROR" "inotifywait 命令不可用，请安装 inotify-tools"; echo -e "${RED}错误: inotifywait 命令不可用，请安装 inotify-tools${NC}"; return 1; }

    for dir in "${BASE_DIR}" "$(dirname "${config[NEW_ITEMS_FILE]}")" "$(dirname "${config[PID_FILE]}")"; do
        mkdir -p "$dir" || { log "ERROR" "无法创建目录: $dir"; echo -e "${RED}错误: 无法创建目录: $dir${NC}"; return 1; }
        [ ! -w "$dir" ] && { log "ERROR" "没有写入权限: $dir"; echo -e "${RED}错误: 没有写入权限: $dir${NC}"; return 1; }
    done

    touch "${config[NEW_ITEMS_FILE]}" || { log "ERROR" "无法创建或访问新增项目文件：${config[NEW_ITEMS_FILE]}"; echo -e "${RED}错误: 无法创建或访问新增项目文件：${config[NEW_ITEMS_FILE]}${NC}"; return 1; }

    [ "$(id -u)" = "0" ] && {
        echo 1048576 > /proc/sys/fs/inotify/max_user_watches
        echo 1048576 > /proc/sys/fs/inotify/max_queued_events
        echo 1048576 > /proc/sys/fs/inotify/max_user_instances
    }

    log "INFO" "正在启动 inotifywait..."

    local ignore_patterns="${config[IGNORE_PATTERNS]}"

    (
        inotifywait -m -r -e create,delete,moved_to,moved_from \
            --format '%w%f|%e' \
            --exclude "$ignore_patterns" \
            / 2>> "${config[LOG_FILE]}" | while IFS='|' read -r full_path events; do
            log "DEBUG" "检测到事件: $events $full_path"
            case "$events" in
                CREATE|MOVED_TO)
                    if [ -e "$full_path" ] && ! is_whitelisted "$full_path"; then
                        echo "$(date "+%Y-%m-%d %H:%M:%S") - 检测到新增: $full_path" >> "${config[NEW_ITEMS_FILE]}"
                        log "INFO" "检测到新增: $full_path"
                    fi
                    ;;
                DELETE|MOVED_FROM)
                    if [ -f "${config[NEW_ITEMS_FILE]}" ]; then
                        remove_from_file "${config[NEW_ITEMS_FILE]}" "$full_path"
                        log "INFO" "检测到删除: $full_path"
                    fi
                    ;;
            esac
        done
    ) &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "${config[PID_FILE]}"
    log "INFO" "${GREEN}文件系统监控守护进程已启动，PID: $MONITOR_PID${NC}"

    sleep 2

    if ! kill -0 "$MONITOR_PID" 2>/dev/null; then
        log "ERROR" "守护进程启动后立即退出，PID: $MONITOR_PID"
        echo -e "${RED}错误: 守护进程启动后立即退出，PID: $MONITOR_PID${NC}"
        if [ -f "${config[LOG_FILE]}" ]; then
            log "ERROR" "inotifywait 错误输出:"
            tail -n 20 "${config[LOG_FILE]}" | while IFS= read -r line; do
                log "ERROR" "$line"
            done
        fi
        return 1
    fi

    log "INFO" "文件系统监控成功启动"
    return 0
}

# 检查进程状态
display_status() {
    echo -e "${BLUE}检查进程状态...${NC}"

    # 检查是否在 nohup 环境中运行
    if [ -n "$NOHUP_EXECUTED" ]; then
        echo -e "${GREEN}脚本正在 nohup 环境中运行${NC}"
    else
        echo -e "${YELLOW}脚本不在 nohup 环境中运行${NC}"
    fi

    # 检查守护进程状态
    if [ -f "${config[PID_FILE]}" ]; then
        local pid=$(cat "${config[PID_FILE]}")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${GREEN}守护进程正在运行，PID: $pid${NC}"
        else
            echo -e "${YELLOW}PID 文件存在，但进程 $pid 不存在。守护进程可能已异常退出。${NC}"
        fi
    else
        echo -e "${YELLOW}守护进程未在运行。${NC}"
    fi

    # 检查包安装监控状态
    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid=$(cat "/tmp/package_monitor.pid")
        if [ -n "$package_pid" ] && kill -0 "$package_pid" 2>/dev/null; then
            echo -e "${GREEN}包安装监控正在运行，PID: $package_pid${NC}"
        else
            echo -e "${YELLOW}包安装监控进程不存在。可能已异常退出。${NC}"
        fi
    else
        echo -e "${YELLOW}包安装监控未在运行。${NC}"
    fi
}

# 保存新增项目
save_new_items() {
    log "INFO" "${BLUE}开始清空新增项目...${NC}"

    if [ ! -f "${config[NEW_ITEMS_FILE]}" ]; then
        log "WARN" "${YELLOW}新增项目文件不存在：${config[NEW_ITEMS_FILE]}${NC}"
        echo -e "${YELLOW}警告：新增项目文件不存在。${NC}"
        return 0
    fi

    local item_count=$(wc -l < "${config[NEW_ITEMS_FILE]}" || echo 0)

    if [ "$item_count" -eq 0 ]; then
        log "INFO" "${YELLOW}新增项目文件已经为空${NC}"
        echo -e "${YELLOW}新增项目文件已经为空，无需清空。${NC}"
        return 0
    fi

    # 清空新增项目文件
    > "${config[NEW_ITEMS_FILE]}"

    if [ $? -eq 0 ]; then
        log "INFO" "${GREEN}已成功清空新增项目文件 ${config[NEW_ITEMS_FILE]}${NC}"
        echo -e "${GREEN}已成功清空 $item_count 条新增项目。${NC}"
    else
        log "ERROR" "${RED}清空新增项目文件时出错${NC}"
        echo -e "${RED}清空新增项目失败。${NC}"
        return 1
    fi

    return 0
}


# 保存系统参数和 99-sysctl.conf 配置
save_system_params() {
    log "INFO" "${BLUE}保存可修改的系统参数...${NC}"
    [ -z "${config[SYSTEM_PARAMS_FILE]}" ] && { log "ERROR" "${RED}错误：SYSTEM_PARAMS_FILE 未设置。使用默认值 $DEFAULT_SYSTEM_PARAMS_FILE${NC}"; config[SYSTEM_PARAMS_FILE]="$DEFAULT_SYSTEM_PARAMS_FILE"; }
    log "INFO" "使用系统参数文件: ${config[SYSTEM_PARAMS_FILE]}"

    [ -f "${config[SYSTEM_PARAMS_FILE]}.bak" ] && { rm "${config[SYSTEM_PARAMS_FILE]}.bak"; log "INFO" "${YELLOW}删除旧的系统参数文件备份${NC}"; }

    [ -f "${config[SYSTEM_PARAMS_FILE]}" ] && { mv "${config[SYSTEM_PARAMS_FILE]}" "${config[SYSTEM_PARAMS_FILE]}.bak"; log "INFO" "${GREEN}已备份当前系统参数文件到 ${config[SYSTEM_PARAMS_FILE]}.bak${NC}"; }

    sysctl -a 2>/dev/null | grep -E '^[a-z]' | while read -r line; do
        param=$(echo "$line" | cut -d = -f1 | tr -d ' ')
        sysctl -w "$param=$param" &>/dev/null && echo "$line" >> "${config[SYSTEM_PARAMS_FILE]}"
    done

    [ ! -s "${config[SYSTEM_PARAMS_FILE]}" ] && { log "ERROR" "${RED}错误：无法保存系统参数到 ${config[SYSTEM_PARAMS_FILE]}${NC}"; return 1; }
    log "INFO" "${GREEN}当前可修改的系统参数已保存到 ${config[SYSTEM_PARAMS_FILE]}${NC}"

    if [ -f "${config[SYSCTL_CONF]}" ]; then
        [ -f "${config[SYSCTL_CONF]}.bak" ] && { rm "${config[SYSCTL_CONF]}.bak"; log "INFO" "${YELLOW}删除旧的 99-sysctl.conf 备份${NC}"; }
        cp "${config[SYSCTL_CONF]}" "${config[SYSCTL_CONF]}.bak"
        log "INFO" "${GREEN}已备份当前 99-sysctl.conf 到 ${config[SYSCTL_CONF]}.bak${NC}"
    else
        log "INFO" "${YELLOW}99-sysctl.conf 不存在，无需备份${NC}"
    fi

    log "INFO" "${GREEN}系统参数和 99-sysctl.conf 配置保存操作完成${NC}"
}

# 恢复系统参数和 99-sysctl.conf 配置
restore_system_params() {
    [ -z "${config[SYSTEM_PARAMS_FILE]}" ] && { log "ERROR" "${RED}错误：SYSTEM_PARAMS_FILE 未设置。${NC}"; return 1; }
    [ ! -f "${config[SYSTEM_PARAMS_FILE]}" ] && { log "ERROR" "${RED}错误：系统参数文件不存在。${NC}"; return 1; }
    log "INFO" "${BLUE}正在检查系统参数和 99-sysctl.conf 配置...${NC}"

    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")
    echo "# 系统参数配置" > "$temp_file"

    local changes_detected=false
    while IFS= read -r line; do
        param=$(echo "$line" | cut -d = -f1 | tr -d ' ')
        saved_value=$(echo "$line" | cut -d = -f2-)
        current_value=$(sysctl -n "$param" 2>/dev/null)

        if [ "$current_value" != "$saved_value" ]; then
            changes_detected=true
            echo "$param = $saved_value" >> "$temp_file"
            log "INFO" "${YELLOW}参数 $param 需要更新${NC}"
        else
            echo "$param = $current_value" >> "$temp_file"
        fi
    done < "${config[SYSTEM_PARAMS_FILE]}"

    if [ "$changes_detected" = true ]; then
        echo -e "${YELLOW}检测到系统参数有变化。是否要更新 99-sysctl.conf 并应用这些更改？ (y/n)${NC}"
        read -r response
        if [[ $response =~ ^[Yy]$ ]]; then
            [ -f "${config[SYSCTL_CONF]}" ] && { cp "${config[SYSCTL_CONF]}" "${config[SYSCTL_CONF]}.bak"; log "INFO" "${GREEN}已备份当前 99-sysctl.conf 到 ${config[SYSCTL_CONF]}.bak${NC}"; }

            mv "$temp_file" "${config[SYSCTL_CONF]}"
            log "INFO" "${GREEN}已更新 99-sysctl.conf${NC}"

            log "INFO" "${BLUE}正在应用 sysctl 更改...${NC}"
            sysctl -p "${config[SYSCTL_CONF]}" > /dev/null 2>&1 && log "INFO" "${GREEN}所有 sysctl 更改已成功应用${NC}" || log "WARN" "${YELLOW}应用 sysctl 更改时出现问题，请检查日志${NC}"
        else
            log "INFO" "${YELLOW}用户选择不更新 99-sysctl.conf${NC}"
            rm "$temp_file"
        fi
    else
        log "INFO" "${GREEN}系统参数没有变化，无需更新 99-sysctl.conf${NC}"
        rm "$temp_file"
    fi

    log "INFO" "${GREEN}系统参数检查和更新操作已完成${NC}"
}

# 查看最近更改
view_new_items() {
    clear_screen
    show_title
    log "INFO" "尝试查看新增项目"
    log "DEBUG" "NEW_ITEMS_FILE 路径: ${config[NEW_ITEMS_FILE]}"

    if [ ! -f "${config[NEW_ITEMS_FILE]}" ]; then
        log "WARN" "新增项目文件不存在：${config[NEW_ITEMS_FILE]}"
        echo -e "${YELLOW}警告：新增项目文件不存在。${NC}"
        echo -e "${YELLOW}这可能是因为守护进程尚未启动，或者还没有检测到任何新增项目。${NC}"
        echo -e "${YELLOW}请确保守护进程已启动并运行一段时间。${NC}"
        echo -e "${YELLOW}按 Enter 键返回...${NC}"
        read -r
        return 1
    fi

    local total_count=$(wc -l < "${config[NEW_ITEMS_FILE]}" || echo 0)

    echo -e "${BLUE}共有 $total_count 条新增项目${NC}"
    echo -e "${YELLOW}请输入要查看的条数（输入 'a' 查看所有项目，直接按 Enter 返回上级菜单）：${NC}"
    read -r input

    if [ -z "$input" ]; then
        echo -e "${YELLOW}返回上级菜单...${NC}"
        sleep 1
        return 0
    elif [[ "$input" == "a" ]]; then
        less "${config[NEW_ITEMS_FILE]}" || {
            log "ERROR" "无法使用 less 查看文件"
            echo -e "${RED}错误：无法查看完整文件${NC}"
        }
    elif [[ "$input" =~ ^[0-9]+$ ]]; then
        if [ "$input" -gt "$total_count" ]; then
            input=$total_count
        fi
        head -n "$input" "${config[NEW_ITEMS_FILE]}" || {
            log "ERROR" "无法读取新增项目文件：${config[NEW_ITEMS_FILE]}"
            echo -e "${RED}错误：无法读取新增项目文件${NC}"
            echo -e "${YELLOW}按 Enter 键返回...${NC}"
            read -r
            return 1
        }
    else
        echo -e "${RED}无效的输入。请输入数字或 'a'。${NC}"
        sleep 2
        return 1
    fi

    echo -e "\n${YELLOW}按 Enter 键返回...${NC}"
    read -r

    return 0
}

# 停止监控并删除数据
stop_and_delete_monitoring() {
    # 暂时禁用中断处理
    trap '' INT TERM

    log "INFO" "${BLUE}开始删除监控数据并停止相关进程...${NC}"

    local cleanup_successful=true
    local steps=("停止相关进程" "删除相关文件" "移除开机自启" "清理系统日志")
    local step_functions=(stop_processes delete_files remove_from_startup clean_system_logs)

    for ((i=0; i<${#steps[@]}; i++)); do
        echo -e "${YELLOW}步骤 $((i+1))/${#steps[@]}: ${steps[i]}${NC}"

        if "${step_functions[i]}"; then
            echo -e "${GREEN}${steps[i]}成功完成${NC}"
            log "INFO" "${steps[i]}成功完成"
        else
            echo -e "${RED}${steps[i]}时遇到问题${NC}"
            log "WARN" "${steps[i]}时遇到问题"
            cleanup_successful=false
        fi
    done

    echo -e "\n${BLUE}清理过程摘要：${NC}"
    for ((i=0; i<${#steps[@]}; i++)); do
        echo -e "${steps[i]}: $("${step_functions[i]}" > /dev/null 2>&1 && echo "${GREEN}成功${NC}" || echo "${RED}失败${NC}")"
    done

    if [ "$cleanup_successful" = true ]; then
        echo -e "\n${GREEN}监控已成功停止，所有相关数据和进程已删除。${NC}"
        log "INFO" "监控清理成功完成"
    else
        echo -e "\n${YELLOW}监控停止过程完成，但有一些操作未能成功执行。${NC}"
        log "WARN" "监控清理过程完成，但存在一些问题"
    fi

    echo -e "${BLUE}如果您在系统中发现任何遗留的监控相关文件或进程，请手动删除或终止它们。${NC}"

    read -p "按 Enter 键继续..."

    # 重新启用中断处理
    trap 'echo -e "\n${RED}脚本被中断${NC}" >&2; exit 1' INT TERM

    return 0
}

# 辅助函数：停止进程
stop_processes() {
    local all_stopped=true

    # 停止守护进程
    if [ -f "${config[PID_FILE]}" ]; then
        local pid=$(cat "${config[PID_FILE]}" 2>/dev/null)
        if [ -n "$pid" ]; then
            kill_process "$pid" "守护进程" || all_stopped=false
        fi
        rm -f "${config[PID_FILE]}" || log "WARN" "无法删除 PID 文件"
    fi

    # 停止包安装监控
    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid=$(cat "/tmp/package_monitor.pid" 2>/dev/null)
        if [ -n "$package_pid" ]; then
            kill_process "$package_pid" "包安装监控" || all_stopped=false
        fi
        rm -f "/tmp/package_monitor.pid" || log "WARN" "无法删除包安装监控 PID 文件"
    fi

    # 停止所有相关的 inotifywait 进程
    local inotify_pids=$(pgrep -f "inotifywait.*${config[IGNORE_PATTERNS]}" 2>/dev/null || true)
    if [ -n "$inotify_pids" ]; then
        for pid in $inotify_pids; do
            kill_process "$pid" "inotifywait" || all_stopped=false
        done
    fi

    if [ "$all_stopped" = true ]; then
        log "INFO" "所有相关进程已成功停止"
        return 0
    else
        log "WARN" "一些进程可能未能成功停止"
        return 1
    fi
}


# 辅助函数：杀死进程
kill_process() {
    local pid=$1
    local process_name=$2
    if kill -0 "$pid" 2>/dev/null; then
        if kill "$pid" 2>/dev/null; then
            log "INFO" "已停止 $process_name (PID: $pid)"
            return 0
        else
            log "WARN" "无法停止 $process_name (PID: $pid)，尝试强制终止"
            if kill -9 "$pid" 2>/dev/null; then
                log "INFO" "已强制终止 $process_name (PID: $pid)"
                return 0
            else
                log "ERROR" "无法强制终止 $process_name (PID: $pid)"
                return 1
            fi
        fi
    else
        log "INFO" "$process_name (PID: $pid) 不存在或已停止"
        return 0
    fi
}

# 辅助函数：删除文件
delete_files() {
    local all_deleted=0  # 0 表示成功，1 表示失败
    local files_to_delete=(
        "${config[NEW_ITEMS_FILE]}"
        "${config[NEW_ITEMS_FILE]}.saved"
        "${config[INITIAL_STATE_FILE]}"
        "${config[SYSTEM_PARAMS_FILE]}"
        "${config[SYSTEM_PARAMS_FILE]}.bak"
        "${config[WHITELIST_FILE]}"
        "$INIT_FLAG_FILE"
        "$CONFIG_FILE"
        "${config[LOG_FILE]}"
    )

    for file in "${files_to_delete[@]}"; do
        if [ -f "$file" ]; then
            if rm -f "$file"; then
                log "INFO" "已删除文件: $file"
            else
                log "WARN" "无法删除文件: $file"
                all_deleted=1
            fi
        else
            log "INFO" "文件不存在，跳过: $file"
        fi
    done

    # 删除 99-sysctl.conf 备份
    if [ -f "${config[SYSCTL_CONF]}.bak" ]; then
        if rm -f "${config[SYSCTL_CONF]}.bak"; then
            log "INFO" "已删除 99-sysctl.conf 备份"
        else
            log "WARN" "无法删除 99-sysctl.conf 备份"
            all_deleted=1
        fi
    fi

    return $all_deleted
}

# 辅助函数：清理系统日志
clean_system_logs() {
    if [ -f /var/log/syslog ]; then
        if sudo sed -i '/file_monitor/d' /var/log/syslog 2>/dev/null; then
            log "INFO" "已从系统日志中清理相关条目"
            return 0
        else
            log "WARN" "无法清理系统日志中的相关条目"
            return 1
        fi
    fi
    return 0
}


# 清屏函数
clear_screen() {
    if command -v tput > /dev/null 2>&1; then
        tput clear
    elif command -v clear > /dev/null 2>&1; then
        clear
    else
        printf '\033[2J\033[H'
    fi

    local lines
    if command -v tput > /dev/null 2>&1; then
        lines=$(tput lines)
    else
        lines=24
    fi

    for ((i=1; i<lines; i++)); do
        echo
    done

    tput cup 0 0 2>/dev/null || echo -en "\033[0;0H"
}

# 终端宽度检测
get_terminal_width() {
    if command -v tput > /dev/null 2>&1; then
        tput cols
    else
        echo 80
    fi
}

# 动态宽度来显示标题
show_title() {
    local width=$(get_terminal_width)
    local title="文件系统监控与系统参数管理 - $HOSTNAME"
    printf "${BLUE}%s${NC}\n" "$title"
    printf '%*s\n' "$width" | tr ' ' '-'
}

# 白名单管理菜单
whitelist_menu() {
    while true; do
        clear_screen
        show_title
        echo -e "${BLUE}白名单管理：${NC}"
        echo "1. 查看白名单"
        echo "2. 添加文件到白名单"
        echo "3. 从白名单移除文件"
        echo "4. 返回上级菜单"
        echo -e "${YELLOW}请输入选项（1-4）：${NC}"

        local choice
        read -r choice

        case "$choice" in
            1) view_whitelist ;;
            2) add_to_whitelist_interactive ;;
            3) remove_from_whitelist_interactive ;;
            4) return ;;
            *)
                echo -e "${RED}无效的选项，请重新输入。${NC}"
                sleep 1
                ;;
        esac
    done
}

# 交互式添加文件到白名单
add_to_whitelist_interactive() {
    echo -e "${YELLOW}请输入要添加到白名单的文件路径（每行一个，输入空行结束）：${NC}"
    local files=()
    while IFS= read -r file; do
        [ -z "$file" ] && break
        files+=("$file")
    done

    if [ ${#files[@]} -eq 0 ]; then
        echo -e "${RED}未输入任何文件路径，操作取消。${NC}"
    else
        for file in "${files[@]}"; do
            if [ -e "$file" ]; then
                if ! is_whitelisted "$file"; then
                    echo "$file" >> "${config[WHITELIST_FILE]}"
                    echo -e "${GREEN}已将 $file 添加到白名单。${NC}"
                else
                    echo -e "${YELLOW}$file 已经在白名单中。${NC}"
                fi
            else
                echo -e "${RED}文件不存在: $file，跳过。${NC}"
            fi
        done
    fi
    echo
    read -p "按 Enter 键继续..."
}

# 交互式从白名单移除文件
remove_from_whitelist_interactive() {
    if [ ! -f "${config[WHITELIST_FILE]}" ] || [ ! -s "${config[WHITELIST_FILE]}" ]; then
        echo -e "${YELLOW}白名单为空，无需移除。${NC}"
        echo
        read -p "按 Enter 键继续..."
        return
    fi

    while true; do
        clear_screen
        show_title
        echo -e "${BLUE}当前白名单内容：${NC}"
        cat -n "${config[WHITELIST_FILE]}"
        echo
        echo -e "${YELLOW}请输入要删除的项目编号（输入 0 返回，输入 'all' 删除所有）：${NC}"

        local choice
        read -r choice

        if [ "$choice" = "0" ]; then
            return
        elif [ "$choice" = "all" ]; then
            > "${config[WHITELIST_FILE]}"
            echo -e "${GREEN}已删除所有白名单项${NC}"
            echo
            read -p "按 Enter 键继续..."
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "$(wc -l < "${config[WHITELIST_FILE]}")" ] && [ "$choice" -gt 0 ]; then
            local removed_item
            removed_item=$(sed -n "${choice}p" "${config[WHITELIST_FILE]}")
            sed -i "${choice}d" "${config[WHITELIST_FILE]}"
            echo -e "${GREEN}已从白名单中移除: $removed_item${NC}"
            echo
            read -p "按 Enter 键继续..."
            return
        else
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            sleep 1
        fi
    done
}

# 查看白名单
view_whitelist() {
    if [ ! -f "${config[WHITELIST_FILE]}" ] || [ ! -s "${config[WHITELIST_FILE]}" ]; then
        echo -e "${YELLOW}白名单为空。${NC}"
    else
        echo -e "${BLUE}当前白名单内容：${NC}"
        cat -n "${config[WHITELIST_FILE]}"
    fi
    echo
    read -p "按 Enter 键继续..."
}

# 数据信息管理菜单
data_info_menu() {
    while true; do
        clear_screen
        show_title
        echo -e "${BLUE}数据信息管理：${NC}"
        echo "1. 清空新增项目"
        echo "2. 保存系统参数和 99-sysctl.conf 配置"
        echo "3. 恢复系统参数和 99-sysctl.conf 配置"
        echo "4. 查看新增项目"
        echo "5. 查看进程状态"
        echo "6. 白名单管理"
        echo "7. 停止监控并删除数据"
        echo "8. 返回主菜单"
        echo -e "${YELLOW}请输入选项（1-8）：${NC}"

        local choice
        read -r choice

        case "$choice" in
            1)  if save_new_items; then
                    echo -e "${GREEN}新增项目已成功清空${NC}"
                else
                    echo -e "${RED}清空新增项目失败${NC}"
                fi
                ;;
            2)  if save_system_params; then
                    echo -e "${GREEN}系统参数和配置保存成功${NC}"
                else
                    echo -e "${RED}保存系统参数和配置失败${NC}"
                fi
                ;;
            3)  if restore_system_params; then
                    echo -e "${GREEN}系统参数和配置恢复成功${NC}"
                else
                    echo -e "${RED}恢复系统参数和配置失败${NC}"
                fi
                ;;
            4)  view_new_items
                continue
                ;;
            5)  display_status
                ;;
            6)  whitelist_menu
                continue
                ;;
            7)  if stop_and_delete_monitoring; then
                    echo -e "${GREEN}监控已停止并且数据已删除${NC}"
                    echo -e "${YELLOW}监控系统已完全移除。如需重新启用，请退出并重新运行脚本。${NC}"
                    return
                else
                    echo -e "${RED}停止监控和删除数据时遇到问题，请检查日志获取详细信息${NC}"
                fi
                ;;
            8)  return
                ;;
            *)  echo -e "${RED}无效的选项，请重新输入。${NC}"
                sleep 1
                continue
                ;;
        esac

        echo -e "${YELLOW}按 Enter 键继续...${NC}"
        read -r
    done
}

# 执行操作并处理结果
execute_action() {
    "$@"
    local result=$?
    if [ $result -eq 0 ]; then
        echo -e "${GREEN}操作成功完成。${NC}"
    else
        echo -e "${RED}操作失败。${NC}"
    fi
    echo -e "${YELLOW}按 Enter 键继续...${NC}"
    read -r
}

# 等待用户输入
wait_for_input() {
    echo -e "${YELLOW}按 Enter 键返回菜单...${NC}"
    read -r
}

# 安全读取用户输入
safe_read() {
    read -r input || true
    echo "$input"
}

# 主菜单函数
main_menu() {
    while true; do
        clear_screen
        show_title
        echo "1. 启动守护进程"
        echo "2. 停止守护进程"
        echo "3. 清理新增项目"
        echo "4. 数据信息管理"
        echo "5. 退出"
        echo -e "${YELLOW}请输入选项（1-5）：${NC}"

        choice=$(safe_read)
        case "$choice" in
            1) start_daemon || echo -e "${RED}启动守护进程失败${NC}"; wait_for_input ;;
            2) stop_daemon || echo -e "${RED}停止守护进程失败${NC}"; wait_for_input ;;
            3) clean_new_items || echo -e "${RED}清理新增项目失败${NC}"; wait_for_input ;;
            4) data_info_menu ;;
            5) echo -e "${GREEN}退出脚本${NC}"; exit 0 ;;
            *) echo -e "${RED}无效的选项，请重新输入。${NC}"; sleep 1 ;;
        esac
    done
}

# 错误处理函数
handle_error() {
    local error_message="$1"
    echo -e "${RED}错误: $error_message${NC}" >&2
}

# 安全执行函数
safe_execute() {
    local func_name="$1"
    shift
    if ! "$func_name" "$@"; then
        handle_error "${func_name} 执行失败"
        return 1
    fi
    return 0
}

# 使用说明
usage() {
    echo "用法: $0 [选项] [命令]"
    echo "选项:"
    echo "  -v, --verbose    显示详细输出"
    echo "命令:"
    echo "  start            启动守护进程"
    echo "  stop             停止守护进程"
    echo "  status           显示守护进程状态"
    echo "  clean            清理新增项目"
    echo "如果没有提供命令，将启动交互式菜单。"
    exit 1
}

declare -A global_new_packages
declare -A global_docker_containers
declare -a global_files_and_dirs

# 主函数
main() {
    export LC_ALL=C
    local VERBOSE=false
    local CMD=""

    # 确保 NOHUP_EXECUTED 变量被定义
    NOHUP_EXECUTED=${NOHUP_EXECUTED:-0}

    # 检查并设置 nohup
    check_nohup "$@"

    # 初始化系统和读取配置
    initialize_system || { handle_error "系统初始化失败" >&2; exit 1; }

    # 检查并安装必要的包
    install_dependencies

    # 解析命令行参数
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                ;;
            start|stop|status|clean)
                CMD="$1"
                ;;
            *)
                echo "未知参数: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    trap 'echo -e "\n${RED}脚本被中断${NC}" >&2; sleep 1; main_menu' INT TERM

    if [ -z "$CMD" ]; then
        main_menu
    else
        case "$CMD" in
            start) start_daemon; add_to_startup ;;
            stop) stop_daemon; remove_from_startup ;;
            status) display_status ;;
            clean) clean_new_items ;;
            *) echo "无效的命令: $CMD"; exit 1 ;;
        esac
    fi
}

# 执行主函数
main "$@"
