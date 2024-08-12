#!/bin/bash

# 严格模式
set -euo pipefail

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# 配置文件和默认值
readonly CONFIG_FILE="config.ini"
readonly DEFAULT_SYSTEM_PARAMS_FILE="/tmp/system_params.txt"
readonly DEFAULT_SYSCTL_CONF="/etc/sysctl.d/99-sysctl.conf"
readonly INIT_FLAG_FILE="/tmp/file_monitor_initialized"
readonly DEFAULT_WHITELIST_FILE="/etc/file_monitor_whitelist.txt"
readonly DEFAULT_NEW_ITEMS_FILE="/tmp/new_items.txt"

# 全局变量
SYSTEM_PARAMS_FILE=""
SYSCTL_CONF=""
WHITELIST_FILE=""
LOG_FILE=""
INITIAL_STATE_FILE=""
NEW_ITEMS_FILE=""
PID_FILE=""
IGNORE_PATTERNS=""
PACKAGE_LOG_FILE=""
PACKAGE_MONITOR_PID=""

# 获取主机名函数
get_hostname() {
    if [ -f /etc/hostname ]; then
        cat /etc/hostname
    elif command -v hostname >/dev/null 2>&1; then
        hostname
    elif command -v uname >/dev/null 2>&1; then
        uname -n
    else
        echo "unknown_host"
    fi
}

# 错误处理函数
error_exit() {
    echo -e "${RED}错误: $1${NC}" >&2
    exit 1
}

# 日志函数
log() {
    local level="$1"
    local message="$2"
    echo "$(date "+%Y-%m-%d %H:%M:%S") [$level] [$HOSTNAME] - $message" >> "$LOG_FILE"
}

# 检查并创建配置文件
create_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log "INFO" "尝试创建配置文件 $CONFIG_FILE"

        # 确保目录存在
        local config_dir=$(dirname "$CONFIG_FILE")
        if [ ! -d "$config_dir" ]; then
            if ! mkdir -p "$config_dir"; then
                log "ERROR" "无法创建配置文件目录: $config_dir"
                return 1
            fi
        fi

        # 尝试创建配置文件
        if ! touch "$CONFIG_FILE" 2>/dev/null; then
            log "WARN" "无法直接创建配置文件，尝试使用 sudo"
            if ! sudo touch "$CONFIG_FILE"; then
                log "ERROR" "无法创建配置文件: $CONFIG_FILE"
                return 1
            fi
            sudo chown $(id -u):$(id -g) "$CONFIG_FILE"
        fi

        # 写入配置内容
        cat > "$CONFIG_FILE" <<EOL
# 配置文件
LOG_FILE="/var/log/file_monitor.log"
INITIAL_STATE_FILE="/tmp/initial_state.txt"
NEW_ITEMS_FILE="/tmp/new_items.txt"
PID_FILE="/var/run/file_monitor.pid"
IGNORE_PATTERNS="^/proc/|^/sys/|^/dev/|^/run/|^/tmp/|^/var/log/|^/var/cache/|^/root/|^/home/"
SYSTEM_PARAMS_FILE="$DEFAULT_SYSTEM_PARAMS_FILE"
SYSCTL_CONF="$DEFAULT_SYSCTL_CONF"
WHITELIST_FILE="$DEFAULT_WHITELIST_FILE"
EOL
        log "INFO" "${GREEN}已创建默认配置文件 $CONFIG_FILE${NC}"
    fi

    # 确保所有必要的配置项都被设置
    local configs=("SYSTEM_PARAMS_FILE" "SYSCTL_CONF" "WHITELIST_FILE")
    for config in "${configs[@]}"; do
        if ! grep -q "$config" "$CONFIG_FILE"; then
            echo "$config=\"${!config}\"" >> "$CONFIG_FILE"
        fi
    done

    # 验证配置文件是否可读
    if [ ! -r "$CONFIG_FILE" ]; then
        log "ERROR" "无法读取配置文件: $CONFIG_FILE"
        return 1
    fi

    log "INFO" "配置文件检查完成"
    return 0
}

# 读取配置文件
read_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        error_exit "配置文件 $CONFIG_FILE 不存在"
    fi
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    SYSTEM_PARAMS_FILE="${SYSTEM_PARAMS_FILE:-$DEFAULT_SYSTEM_PARAMS_FILE}"
    SYSCTL_CONF="${SYSCTL_CONF:-$DEFAULT_SYSCTL_CONF}"
    WHITELIST_FILE="${WHITELIST_FILE:-$DEFAULT_WHITELIST_FILE}"
    NEW_ITEMS_FILE="${NEW_ITEMS_FILE:-$DEFAULT_NEW_ITEMS_FILE}"
}

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行。"
    fi
}

# 初始化系统
initialize_system() {
    if [ ! -f "$INIT_FLAG_FILE" ]; then
        check_root || return 1
        if ! create_config; then
            log "ERROR" "无法创建或访问配置文件"
            return 1
        fi
        read_config || return 1
        install_dependencies || return 1
        setup_sysctl_params || return 1
        initialize_whitelist || return 1
        HOSTNAME=$(get_hostname)
        touch "$INIT_FLAG_FILE" > /dev/null 2>&1 || return 1
        log "INFO" "${GREEN}系统初始化完成${NC}"
    else
        read_config || return 1
        HOSTNAME=$(get_hostname)
    fi

    # 设置包管理器日志文件
    if [ -f /etc/debian_version ]; then
        PACKAGE_LOG_FILE="/var/log/dpkg.log"
    elif [ -f /etc/redhat-release ]; then
        if [ -f /var/log/dnf.log ]; then
            PACKAGE_LOG_FILE="/var/log/dnf.log"
        else
            PACKAGE_LOG_FILE="/var/log/yum.log"
        fi
    else
        log "WARN" "不支持的系统类型,无法监控包安装"
    fi

    return 0
}

setup_sysctl_params() {
    # 移除不兼容的参数
    sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' /etc/sysctl.conf > /dev/null 2>&1

    # 设置其他参数（根据需要调整）
    echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf

    # 使用 -q 选项使 sysctl 安静运行
    sysctl -q -p > /dev/null 2>&1
}

# 安装依赖
install_dependencies() {
    local packages_to_install=()

    # 检查 inotify-tools
    if ! command -v inotifywait &> /dev/null; then
        packages_to_install+=("inotify-tools")
    fi

    if [ ${#packages_to_install[@]} -ne 0 ]; then
        if [ -f /etc/debian_version ]; then
            apt-get update -qq
            apt-get install -qq -y "${packages_to_install[@]}" > /dev/null 2>&1 || error_exit "无法安装所需的包"
        elif [ -f /etc/redhat-release ]; then
            yum install -q -y "${packages_to_install[@]}" > /dev/null 2>&1 || error_exit "无法安装所需的包"
        else
            error_exit "不支持的 Linux 发行版，请手动安装所需的包"
        fi
    fi
}

# 记录初始状态
record_initial_state() {
    log "INFO" "${BLUE}开始记录系统初始状态...${NC}"
    local temp_file="/tmp/initial_state_temp.txt"

    # 使用更安全的 find 命令
    if ! find / -xdev \( -type d -o -type f \) -print0 2>/dev/null | grep -vzZ "$IGNORE_PATTERNS" | sort -z > "$temp_file"; then
        log "ERROR" "${RED}记录初始状态时出错。find 命令失败。${NC}"
        log "ERROR" "${RED}错误详情: $(find / -xdev \( -type d -o -type f \) -print 2>&1 | head -n 5)${NC}"
        return 1
    fi

    if [ ! -s "$temp_file" ]; then
        log "ERROR" "${RED}初始状态文件为空。可能是 find 命令执行失败或权限不足。${NC}"
        return 1
    fi

    # 转换为可读格式
    tr '\0' '\n' < "$temp_file" > "$INITIAL_STATE_FILE"
    rm "$temp_file"

    if [ ! -s "$INITIAL_STATE_FILE" ]; then
        log "ERROR" "${RED}无法创建可读的初始状态文件。${NC}"
        return 1
    fi

    log "INFO" "${GREEN}初始状态已成功记录到 $INITIAL_STATE_FILE${NC}"
    return 0
}

# 初始化白名单
initialize_whitelist() {
    if [ ! -f "$WHITELIST_FILE" ]; then
        touch "$WHITELIST_FILE"
        log "INFO" "${GREEN}已创建白名单文件 $WHITELIST_FILE${NC}"
    fi
}

# 检查文件是否在白名单中
is_whitelisted() {
    local file="$1"
    if [ ! -f "$WHITELIST_FILE" ]; then
        return 1  # 如果白名单文件不存在，返回 false
    fi
    grep -q "^$file$" "$WHITELIST_FILE"
}

# 添加文件到白名单
add_to_whitelist() {
    local file="$1"
    if [ ! -f "$WHITELIST_FILE" ]; then
        touch "$WHITELIST_FILE"
        log "INFO" "${GREEN}已创建白名单文件 $WHITELIST_FILE${NC}"
    fi
    if ! grep -q "^$file$" "$WHITELIST_FILE"; then
        echo "$file" >> "$WHITELIST_FILE"
        log "INFO" "${GREEN}已将 $file 添加到白名单${NC}"
    else
        log "INFO" "${YELLOW}$file 已经在白名单中${NC}"
    fi
}

# 显示白名单并返回项目数量
show_whitelist() {
    if [ ! -f "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}白名单文件不存在${NC}"
        return 0
    fi
    if [ ! -s "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}白名单为空${NC}"
        return 0
    fi
    echo -e "${BLUE}白名单内容：${NC}"
    local count=1
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -n "$line" ]]; then
            echo -e "${GREEN}$count. $line${NC}"
            ((count++))
        fi
    done < "$WHITELIST_FILE"
    return 0
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
                else
                    log "ERROR" "无法停止或删除Docker容器: $container_id"
                fi
                return
                ;;
            2)
                if docker stop "$container_id"; then
                    log "INFO" "已停止Docker容器: $container_id"
                else
                    log "ERROR" "无法停止Docker容器: $container_id"
                fi
                return
                ;;
            3)
                log "INFO" "保留Docker容器: $container_id"
                return
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

    # 检查目录是否为空
    if [ -z "$(ls -A "$dir")" ]; then
        echo -e "${GREEN}发现可删除目录: $dir（目录为空）${NC}"
        local delete_level="green"
    else
        # 检查是否是系统关键目录
        case "$dir" in
            /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/etc/*|/var/*)
                echo -e "${RED}警告：可能是系统关键目录: $dir${NC}"
                local delete_level="red"
                ;;
            *)
                # 检查目录是否包含正在运行的进程
                if lsof +D "$dir" > /dev/null 2>&1; then
                    echo -e "${RED}警告：目录可能包含正在运行的进程: $dir${NC}"
                    local delete_level="red"
                else
                    # 检查目录是否包含配置文件或数据文件
                    if find "$dir" -type f \( -name "*.conf" -o -name "*.json" -o -name "*.db" -o -name "*.sqlite" \) | grep -q .; then
                        echo -e "${YELLOW}警告：目录可能包含重要配置或数据文件: $dir${NC}"
                        local delete_level="yellow"
                    else
                        echo -e "${GREEN}发现可能可以删除的目录: $dir${NC}"
                        local delete_level="green"
                    fi
                fi
                ;;
        esac
    fi

    case "$delete_level" in
        "green")
            echo -e "${GREEN}建议：可以安全删除${NC}"
            ;;
        "yellow")
            echo -e "${YELLOW}建议：谨慎删除，可能影响某些软件${NC}"
            ;;
        "red")
            echo -e "${RED}建议：不要删除，可能影响系统或重要软件${NC}"
            ;;
    esac

    read -p "是否删除此目录？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$delete_level" = "red" ]; then
            echo -e "${RED}警告：你正在尝试删除一个可能影响系统的目录。${NC}"
            read -p "你确定要继续吗？这可能会导致系统不稳定。(y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}已取消删除 $dir${NC}"
                return
            fi
        fi

        if ! rm -rf "$dir"; then
            log "ERROR" "删除目录失败: $dir"
            echo "$dir" >> "$temp_file"
        else
            log "INFO" "已删除目录: $dir"
        fi
    else
        log "INFO" "跳过删除: $dir"
        # 不将目录添加到临时文件中，相当于从新增项目列表中移除
    fi
}

# 处理文件
handle_file() {
    local file="$1"
    local temp_file="$2"
    echo -e "${YELLOW}发现新增文件: $file${NC}"
    echo -e "${RED}警告：即将删除文件: $file${NC}"
    read -p "是否确定要删除？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! rm -f "$file"; then
            log "ERROR" "删除文件失败: $file"
            echo "$file" >> "$temp_file"
        else
            log "INFO" "${GREEN}已删除文件: $file${NC}"
        fi
    else
        log "INFO" "${YELLOW}跳过删除: $file${NC}"
        # 不将文件添加到临时文件中，相当于从新增项目列表中移除
    fi
}

# 从白名单中移除文件
remove_from_whitelist() {
    if [ ! -f "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}白名单文件不存在，无需移除${NC}"
        sleep 2
        return 1
    fi

    local items=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -n "$line" ]]; then
            items+=("$line")
        fi
    done < "$WHITELIST_FILE"

    if [ ${#items[@]} -eq 0 ]; then
        echo -e "${YELLOW}白名单为空，无需移除${NC}"
        sleep 2
        return 1
    fi

    while true; do
        echo -e "${BLUE}当前白名单内容：${NC}"
        for i in "${!items[@]}"; do
            echo -e "${GREEN}$((i+1)). ${items[i]}${NC}"
        done

        echo -e "${YELLOW}请输入要删除的项目编号（输入 0 返回，输入 'all' 删除所有）：${NC}"
        read -r choice

        if [ "$choice" = "0" ]; then
            echo -e "${BLUE}返回上级菜单${NC}"
            return 0
        elif [ "$choice" = "all" ]; then
            > "$WHITELIST_FILE"
            echo -e "${GREEN}已删除所有白名单项${NC}"
            sleep 2
            return 1
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#items[@]}" ] && [ "$choice" -gt 0 ]; then
            local removed_item="${items[$((choice-1))]}"
            unset 'items[$((choice-1))]'
            printf '%s\n' "${items[@]}" > "$WHITELIST_FILE"
            echo -e "${GREEN}已从白名单中移除: $removed_item${NC}"
            sleep 2
            return 1
        else
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            sleep 1
        fi
    done
}

# 监控变化
monitor_changes() {
    log "INFO" "${BLUE}开始持续监控文件系统变化...${NC}"
    (
        inotifywait -m -r -e create,moved_to,delete,moved_from / 2>&1 | while read -r path action file; do
            full_path="${path}${file}"
            case "$action" in
                CREATE|MOVED_TO)
                    if [ -e "$full_path" ] && ! echo "$full_path" | grep -qE "$IGNORE_PATTERNS" && ! is_whitelisted "$full_path"; then
                        # 检查是否为新增文件或目录
                        if [ ! -f "$INITIAL_STATE_FILE" ] || ! grep -q "^$full_path$" "$INITIAL_STATE_FILE"; then
                            echo "$(date "+%Y-%m-%d %H:%M:%S") - 检测到新增: $full_path" >> "$NEW_ITEMS_FILE"
                            log "INFO" "检测到新增: $full_path"
                        fi
                    fi
                    ;;
                DELETE|MOVED_FROM)
                    # 从新增项目文件中删除已经不存在的项目
                    if grep -q "$full_path" "$NEW_ITEMS_FILE"; then
                        sed -i "\|$full_path|d" "$NEW_ITEMS_FILE"
                        log "INFO" "检测到删除，已从监控列表移除: $full_path"
                    fi
                    ;;
            esac
        done
    ) &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "$PID_FILE"
    log "INFO" "${GREEN}守护进程已启动，PID: $MONITOR_PID${NC}"
    return 0
}

# 监控包安装
monitor_package_installation() {
    if [ -z "$PACKAGE_LOG_FILE" ]; then
        log "WARN" "未设置包管理器日志文件,无法监控包安装"
        return 1
    fi

    log "INFO" "开始监控包安装: $PACKAGE_LOG_FILE"

    # 使用 tail 命令持续监控日志文件
    tail -n0 -F "$PACKAGE_LOG_FILE" | while read -r line; do
        if [ -f /etc/debian_version ]; then
            if echo "$line" | grep -q "status installed"; then
                package=$(echo "$line" | awk '{print $5}')
                log "INFO" "检测到新安装包: $package"
                echo "$(date "+%Y-%m-%d %H:%M:%S") - 新安装包: $package" >> "$NEW_ITEMS_FILE"
            fi
        elif [ -f /etc/redhat-release ]; then
            if echo "$line" | grep -q "Installed:"; then
                package=$(echo "$line" | awk '{print $3}')
                log "INFO" "检测到新安装包: $package"
                echo "$(date "+%Y-%m-%d %H:%M:%S") - 新安装包: $package" >> "$NEW_ITEMS_FILE"
            fi
        fi
    done &
    PACKAGE_MONITOR_PID=$!
    echo "$PACKAGE_MONITOR_PID" > "/tmp/package_monitor.pid"  # 保存PID到文件
    log "INFO" "${GREEN}包安装监控已启动，PID: $PACKAGE_MONITOR_PID${NC}"
}

# 获取新增项目相关的服务名
get_related_services() {
    if [ ! -f "$NEW_ITEMS_FILE" ]; then
        log "ERROR" "${RED}错误：新增项目文件不存在。${NC}"
        return 1
    fi

    log "INFO" "${BLUE}正在分析新增项目相关的服务...${NC}"

    local services=()
    while IFS= read -r line; do
        item=$(echo "$line" | cut -d' ' -f5-)
        if [[ "$item" == /usr/bin/* || "$item" == /usr/lib/* || "$item" == /etc/systemd/system/* ]]; then
            # 尝试通过 systemctl 获取服务名
            local service_name=$(systemctl list-unit-files --full --all | grep "$item" | awk '{print $1}')
            if [ -n "$service_name" ]; then
                services+=("$service_name")
            else
                # 如果是可执行文件，尝试获取其所属的包
                local package=$(dpkg -S "$item" 2>/dev/null | cut -d: -f1)
                if [ -n "$package" ]; then
                    services+=("$package (包)")
                fi
            fi
        fi
    done < "$NEW_ITEMS_FILE"

    # 去重并显示结果
    if [ ${#services[@]} -eq 0 ]; then
        log "INFO" "${YELLOW}未发现与新增项目直接相关的服务。${NC}"
    else
        log "INFO" "${GREEN}发现以下可能相关的服务或包：${NC}"
        printf '%s\n' "${services[@]}" | sort -u
    fi
}

# 清理新增项目
clean_new_items() {
    log "DEBUG" "进入 clean_new_items 函数"

    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本需要 root 权限运行${NC}"
        return 1
    fi

    if [ -z "$NEW_ITEMS_FILE" ] || [ ! -f "$NEW_ITEMS_FILE" ]; then
        echo -e "${RED}错误: 新增项目文件不存在或未设置${NC}"
        return 1
    fi

    echo -e "${BLUE}开始智能清理新增项目...${NC}"
    local temp_file=$(mktemp)
    log "DEBUG" "创建临时文件: $temp_file"

    # 初始化关联数组
    declare -A dirs_to_remove=()
    declare -A files_to_remove=()
    declare -A docker_containers=()
    declare -A skipped_items=()
    declare -A new_packages=()

    while IFS= read -r line; do
        if [[ "$line" == *"新安装包:"* ]]; then
            package=$(echo "$line" | awk -F': ' '{print $2}')
            new_packages["$package"]=1
            continue
        fi

        item=$(echo "$line" | cut -d' ' -f5-)
        log "DEBUG" "处理项目: $item"

        if [ ! -e "$item" ]; then
            echo -e "${YELLOW}警告: 项目不存在，跳过: $item${NC}"
            continue
        fi

        if [[ "$item" =~ ^/var/lib/docker/containers/([a-f0-9]{64}) ]]; then
            container_id="${BASH_REMATCH[1]}"
            docker_containers["$container_id"]="${docker_containers["$container_id"]:-}${docker_containers["$container_id"]:+, }$item"
        elif [[ "$item" == /var/lib/docker/* || "$item" == /var/lib/containerd/* ]]; then
            echo -e "${YELLOW}跳过 Docker 系统目录: $item${NC}"
            skipped_items["$item"]=1
        elif [ -d "$item" ]; then
            handle_directory "$item" "$temp_file"
        elif [ -f "$item" ]; then
            handle_file "$item" "$temp_file"
        else
            echo -e "${YELLOW}警告: 项目既不是文件也不是目录: $item${NC}"
            skipped_items["$item"]=1
        fi
    done < "$NEW_ITEMS_FILE"

    # 处理新安装的包
    if [ ${#new_packages[@]} -gt 0 ]; then
        echo -e "${YELLOW}检测到新安装的包：${NC}"
        for package in "${!new_packages[@]}"; do
            echo -e "${BLUE}$package${NC}"
        done
        echo -e "${YELLOW}是否要卸载这些包？(y/n)${NC}"
        read -r uninstall_packages
        if [[ $uninstall_packages =~ ^[Yy]$ ]]; then
            for package in "${!new_packages[@]}"; do
                if [ -f /etc/debian_version ]; then
                    if dpkg -s "$package" >/dev/null 2>&1; then
                        apt-get remove -y "$package"
                        echo -e "${GREEN}已卸载包: $package${NC}"
                    else
                        echo -e "${YELLOW}包 $package 不存在，跳过卸载${NC}"
                    fi
                elif [ -f /etc/redhat-release ]; then
                    if rpm -q "$package" >/dev/null 2>&1; then
                        yum remove -y "$package"
                        echo -e "${GREEN}已卸载包: $package${NC}"
                    else
                        echo -e "${YELLOW}包 $package 不存在，跳过卸载${NC}"
                    fi
                fi
            done
            # 清理不再需要的依赖
            if [ -f /etc/debian_version ]; then
                apt-get autoremove -y
            elif [ -f /etc/redhat-release ]; then
                yum autoremove -y
            fi
            echo -e "${GREEN}已清理不再需要的依赖${NC}"
        else
            echo -e "${YELLOW}跳过卸载新安装的包${NC}"
            for package in "${!new_packages[@]}"; do
                echo "$package" >> "$temp_file"
            done
        fi
    fi

    # 处理 Docker 容器
    for container_id in "${!docker_containers[@]}"; do
        handle_docker_container_interactive "$container_id" "${docker_containers[$container_id]}"
    done

    # 显示清理结果
    local remaining_count=$(wc -l < "$temp_file")
    echo -e "${GREEN}清理完成。剩余 $remaining_count 个未处理的项目。${NC}"

    # 询问是否继续清理
    if [ $remaining_count -gt 0 ]; then
        read -p "是否显示未处理的项目？(Y/n) " show_remaining
        show_remaining=${show_remaining:-Y}
        if [[ $show_remaining =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}未处理的项目：${NC}"
            cat "$temp_file"
        fi

        read -p "是否将这些项目添加到白名单？(Y/n) " add_to_whitelist
        add_to_whitelist=${add_to_whitelist:-Y}
        log "DEBUG" "用户选择：$add_to_whitelist"

        if [[ $add_to_whitelist =~ ^[Yy]$ ]]; then
            log "DEBUG" "开始添加项目到白名单"
            while IFS= read -r item; do
                add_to_whitelist "$item"
                echo -e "${GREEN}已添加到白名单：$item${NC}"
            done < "$temp_file"
            echo -e "${GREEN}已将剩余项目添加到白名单${NC}"
            > "$NEW_ITEMS_FILE"
            echo -e "${GREEN}已清空新增项目列表${NC}"
        else
            read -p "是否删除这些未处理的项目？此操作不可逆。(y/N) " confirm_delete
            confirm_delete=${confirm_delete:-N}
            if [[ $confirm_delete =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}用户选择删除未处理的项目${NC}"
                while IFS= read -r item; do
                    if [ -e "$item" ]; then
                        if [ -d "$item" ]; then
                            rm -rf "$item"
                            echo -e "${GREEN}已删除目录: $item${NC}"
                        elif [ -f "$item" ]; then
                            rm -f "$item"
                            echo -e "${GREEN}已删除文件: $item${NC}"
                        else
                            echo -e "${YELLOW}无法删除，未知类型: $item${NC}"
                        fi
                    else
                        echo -e "${YELLOW}项目不存在，无需删除: $item${NC}"
                    fi
                done < "$temp_file"
                > "$NEW_ITEMS_FILE"
                echo -e "${GREEN}已删除所有未处理的项目并清空新增项目列表${NC}"
            else
                echo -e "${YELLOW}用户取消了删除操作，保留项目在新增列表中${NC}"
                mv "$temp_file" "$NEW_ITEMS_FILE"
            fi
        fi
    else
        > "$NEW_ITEMS_FILE"  # 如果没有剩余项目，清空新增项目文件
        echo -e "${GREEN}没有剩余项目，已清空新增项目列表${NC}"
    fi

    rm -f "$temp_file"
    log "DEBUG" "clean_new_items 函数执行完毕"
    return 0
}

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
    return $?
}

# 启动守护进程
start_daemon() {
    echo -e "${BLUE}正在尝试启动守护进程...${NC}"

    local daemon_started=false

    # 检查磁盘空间
    local available_space
    available_space=$(df -k / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # 检查是否少于 1GB
        echo -e "${RED}错误: 磁盘空间不足。可用空间: ${available_space}KB${NC}"
        return 1
    fi

    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${GREEN}守护进程正在运行，PID: $pid${NC}"
            daemon_started=true
        else
            echo -e "${YELLOW}发现陈旧的 PID 文件，将被删除。${NC}"
            rm -f "$PID_FILE"
        fi
    fi

    if [ "$daemon_started" = false ]; then
        if ! record_initial_state; then
            echo -e "${RED}错误: 无法记录初始状态。${NC}"
            return 1
        fi

        # 确保新增项目文件存在
        touch "$NEW_ITEMS_FILE" || {
            echo -e "${RED}错误: 无法创建新增项目文件：$NEW_ITEMS_FILE${NC}"
            return 1
        }

        if ! monitor_changes; then
            echo -e "${RED}错误: 无法启动文件系统监控。${NC}"
            return 1
        fi

        if [ ! -f "$PID_FILE" ]; then
            echo -e "${RED}错误: PID 文件未创建，监控可能未成功启动。${NC}"
            return 1
        fi

        echo -e "${GREEN}守护进程已成功启动，PID: $(cat "$PID_FILE")${NC}"
    fi

    # 检查包安装监控状态
    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid=$(cat "/tmp/package_monitor.pid")
        if kill -0 "$package_pid" 2>/dev/null; then
            echo -e "${GREEN}包安装监控已在运行，PID: $package_pid${NC}"
        else
            echo -e "${YELLOW}发现陈旧的包安装监控 PID 文件，将被删除。${NC}"
            rm -f "/tmp/package_monitor.pid"
            if monitor_package_installation; then
                echo -e "${GREEN}包安装监控已成功启动。${NC}"
            else
                echo -e "${YELLOW}警告: 无法启动包安装监控。${NC}"
            fi
        fi
    else
        if monitor_package_installation; then
            echo -e "${GREEN}包安装监控已成功启动。${NC}"
        else
            echo -e "${YELLOW}警告: 无法启动包安装监控。${NC}"
        fi
    fi

    # 检查开机自启状态
    if check_startup_entry; then
        echo -e "${GREEN}脚本已在开机自启列表中。${NC}"
    else
        if add_to_startup; then
            echo -e "${GREEN}已添加到开机自启。${NC}"
        else
            echo -e "${YELLOW}警告: 无法添加到开机自启。${NC}"
        fi
    fi

    echo -e "${YELLOW}监控进程正在后台运行。您可以继续使用其他功能。${NC}"
    return 0
}

# 停止守护进程
stop_daemon() {
    echo -e "${BLUE}正在停止守护进程...${NC}"

    # 停止主守护进程
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}正在停止守护进程 (PID: $pid)${NC}"
            kill "$pid"
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${YELLOW}守护进程没有立即停止，尝试强制终止${NC}"
                kill -9 "$pid"
                sleep 1
            fi
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${RED}无法停止守护进程 (PID: $pid)${NC}"
            else
                echo -e "${GREEN}已成功停止守护进程 (PID: $pid)${NC}"
            fi
        else
            echo -e "${YELLOW}守护进程 (PID: $pid) 不存在，可能已经停止${NC}"
        fi
        rm -f "$PID_FILE"
    else
        echo -e "${YELLOW}PID 文件不存在，守护进程可能未在运行${NC}"
    fi

    # 停止包安装监控
    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid
        package_pid=$(cat "/tmp/package_monitor.pid")
        if [ -n "$package_pid" ] && kill -0 "$package_pid" 2>/dev/null; then
            echo -e "${YELLOW}正在停止包安装监控 (PID: $package_pid)${NC}"
            kill "$package_pid"
            sleep 1
            if kill -0 "$package_pid" 2>/dev/null; then
                echo -e "${YELLOW}包安装监控没有立即停止，尝试强制终止${NC}"
                kill -9 "$package_pid"
                sleep 1
            fi
            if kill -0 "$package_pid" 2>/dev/null; then
                echo -e "${RED}无法停止包安装监控 (PID: $package_pid)${NC}"
            else
                echo -e "${GREEN}已成功停止包安装监控 (PID: $package_pid)${NC}"
            fi
        else
            echo -e "${YELLOW}包安装监控进程 (PID: $package_pid) 不存在，可能已经停止${NC}"
        fi
        rm -f "/tmp/package_monitor.pid"
    else
        echo -e "${YELLOW}包安装监控 PID 文件不存在，可能未在运行${NC}"
    fi

    # 停止所有相关的 inotifywait 进程
    if pkill -f "inotifywait"; then
        echo -e "${GREEN}已停止所有 inotifywait 进程${NC}"
    else
        echo -e "${YELLOW}没有找到运行中的 inotifywait 进程${NC}"
    fi

    # 从开机自启中移除
    if remove_from_startup; then
        echo -e "${GREEN}已从开机自启中移除${NC}"
    else
        echo -e "${YELLOW}无法从开机自启中移除${NC}"
    fi

    echo -e "${GREEN}守护进程停止操作完成${NC}"
}

# 检查守护进程状态
display_status() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${GREEN}守护进程正在运行，PID: $pid${NC}"
        else
            echo -e "${YELLOW}PID 文件存在，但进程 $pid 不存在。守护进程可能已异常退出。${NC}"
        fi
    else
        echo -e "${YELLOW}守护进程未在运行。${NC}"
    fi

    if [ -f "/tmp/package_monitor.pid" ]; then
        PACKAGE_MONITOR_PID=$(cat "/tmp/package_monitor.pid")
        if [ -n "$PACKAGE_MONITOR_PID" ] && kill -0 "$PACKAGE_MONITOR_PID" 2>/dev/null; then
            echo -e "${GREEN}包安装监控正在运行，PID: $PACKAGE_MONITOR_PID${NC}"
        else
            echo -e "${YELLOW}包安装监控进程不存在。可能已异常退出。${NC}"
        fi
    else
        echo -e "${YELLOW}包安装监控未在运行。${NC}"
    fi
}

# 保存新增项目
save_new_items() {
    if [ ! -f "$NEW_ITEMS_FILE" ]; then
        log "ERROR" "${RED}错误：新增项目文件不存在。${NC}"
        return 1
    fi

    # 删除之前的保存文件（如果存在）
    if [ -f "${NEW_ITEMS_FILE}.saved" ]; then
        rm "${NEW_ITEMS_FILE}.saved"
        log "INFO" "${YELLOW}已删除之前保存的新增项目文件${NC}"
    fi

    # 保存当前的新增项目
    cp "$NEW_ITEMS_FILE" "${NEW_ITEMS_FILE}.saved"

    # 清空当前的新增项目文件
    > "$NEW_ITEMS_FILE"

    log "INFO" "${GREEN}新增项目已保存到 ${NEW_ITEMS_FILE}.saved，并清空了当前新增项目${NC}"
}

# 保存系统参数和 99-sysctl.conf 配置
save_system_params() {
    log "INFO" "${BLUE}保存可修改的系统参数...${NC}"
    if [ -z "$SYSTEM_PARAMS_FILE" ]; then
        log "ERROR" "${RED}错误：SYSTEM_PARAMS_FILE 未设置。使用默认值 $DEFAULT_SYSTEM_PARAMS_FILE${NC}"
        SYSTEM_PARAMS_FILE="$DEFAULT_SYSTEM_PARAMS_FILE"
    fi
    log "INFO" "使用系统参数文件: $SYSTEM_PARAMS_FILE"

    # 删除旧的系统参数文件备份（如果存在）
    if [ -f "${SYSTEM_PARAMS_FILE}.bak" ]; then
        rm "${SYSTEM_PARAMS_FILE}.bak"
        log "INFO" "${YELLOW}删除旧的系统参数文件备份${NC}"
    fi

    # 如果当前系统参数文件存在，将其备份
    if [ -f "$SYSTEM_PARAMS_FILE" ]; then
        mv "$SYSTEM_PARAMS_FILE" "${SYSTEM_PARAMS_FILE}.bak"
        log "INFO" "${GREEN}已备份当前系统参数文件到 ${SYSTEM_PARAMS_FILE}.bak${NC}"
    fi

    # 保存当前可修改的系统参数
    sysctl -a 2>/dev/null | grep -E '^[a-z]' | while read -r line; do
        param=$(echo "$line" | cut -d = -f1 | tr -d ' ')
        if sysctl -w "$param=$param" &>/dev/null; then
            echo "$line" >> "$SYSTEM_PARAMS_FILE"
        fi
    done

    if [ ! -s "$SYSTEM_PARAMS_FILE" ]; then
        log "ERROR" "${RED}错误：无法保存系统参数到 $SYSTEM_PARAMS_FILE${NC}"
        return 1
    fi
    log "INFO" "${GREEN}当前可修改的系统参数已保存到 $SYSTEM_PARAMS_FILE${NC}"

    # 处理 99-sysctl.conf 文件
    if [ -f "$SYSCTL_CONF" ]; then
        # 删除旧的备份（如果存在）
        if [ -f "${SYSCTL_CONF}.bak" ]; then
            rm "${SYSCTL_CONF}.bak"
            log "INFO" "${YELLOW}删除旧的 99-sysctl.conf 备份${NC}"
        fi
        # 创建新的备份
        cp "$SYSCTL_CONF" "${SYSCTL_CONF}.bak"
        log "INFO" "${GREEN}已备份当前 99-sysctl.conf 到 ${SYSCTL_CONF}.bak${NC}"
    else
        log "INFO" "${YELLOW}99-sysctl.conf 不存在，无需备份${NC}"
    fi

    log "INFO" "${GREEN}系统参数和 99-sysctl.conf 配置保存操作完成${NC}"
}

# 恢复系统参数和 99-sysctl.conf 配置
restore_system_params() {
    if [ -z "$SYSTEM_PARAMS_FILE" ]; then
        log "ERROR" "${RED}错误：SYSTEM_PARAMS_FILE 未设置。${NC}"
        return 1
    fi
    if [ ! -f "$SYSTEM_PARAMS_FILE" ]; then
        log "ERROR" "${RED}错误：系统参数文件不存在。${NC}"
        return 1
    fi
    log "INFO" "${BLUE}正在恢复系统参数和更新 99-sysctl.conf 配置...${NC}"

    # 创建新的 99-sysctl.conf
    echo "# 系统参数配置 - $(date)" > "$SYSCTL_CONF"
    cat "$SYSTEM_PARAMS_FILE" >> "$SYSCTL_CONF"
    log "INFO" "${GREEN}已创建新的 99-sysctl.conf 文件${NC}"

    # 应用 sysctl 更改
    log "INFO" "${BLUE}正在应用 sysctl 更改...${NC}"
    local error_count=0
    local total_count=0
    while IFS= read -r line; do
        total_count=$((total_count + 1))
        param=$(echo "$line" | cut -d = -f1 | tr -d ' ')
        value=$(echo "$line" | cut -d = -f2-)
        if ! sysctl -w "$param=$value" > /dev/null 2>&1; then
            log "WARN" "${YELLOW}无法设置参数: $param${NC}"
            error_count=$((error_count + 1))
        fi
    done < "$SYSTEM_PARAMS_FILE"

    if [ $error_count -eq 0 ]; then
        log "INFO" "${GREEN}所有 sysctl 更改已成功应用${NC}"
    else
        log "WARN" "${YELLOW}应用 sysctl 更改时出现问题。$error_count 个参数无法设置（共 $total_count 个）${NC}"
    fi

    log "INFO" "${GREEN}系统参数恢复和 99-sysctl.conf 更新操作已完成${NC}"
}

# 查看最近更改
view_new_items() {
    clear_screen
    show_title
    log "INFO" "尝试查看新增项目"
    log "DEBUG" "NEW_ITEMS_FILE 路径: $NEW_ITEMS_FILE"

    if [ ! -f "$NEW_ITEMS_FILE" ]; then
        log "WARN" "新增项目文件不存在：$NEW_ITEMS_FILE"
        echo -e "${YELLOW}警告：新增项目文件不存在。${NC}"
        echo -e "${YELLOW}这可能是因为守护进程尚未启动，或者还没有检测到任何新增项目。${NC}"
        echo -e "${YELLOW}请确保守护进程已启动并运行一段时间。${NC}"
        echo -e "${YELLOW}按 Enter 键返回...${NC}"
        read -r
        return 1
    fi

    local total_count=$(wc -l < "$NEW_ITEMS_FILE" || echo 0)

    echo -e "${BLUE}共有 $total_count 条新增项目${NC}"
    echo -e "${YELLOW}请输入要查看的条数（输入 'a' 查看所有项目，直接按 Enter 返回上级菜单）：${NC}"
    read -r input

    if [ -z "$input" ]; then
        echo -e "${YELLOW}返回上级菜单...${NC}"
        sleep 1
        return 0
    elif [[ "$input" == "a" ]]; then
        less "$NEW_ITEMS_FILE" || {
            log "ERROR" "无法使用 less 查看文件"
            echo -e "${RED}错误：无法查看完整文件${NC}"
        }
    elif [[ "$input" =~ ^[0-9]+$ ]]; then
        if [ "$input" -gt "$total_count" ]; then
            input=$total_count
        fi
        head -n "$input" "$NEW_ITEMS_FILE" || {
            log "ERROR" "无法读取新增项目文件：$NEW_ITEMS_FILE"
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
    log "INFO" "${BLUE}开始停止监控并删除所有相关数据...${NC}"

    # 停止守护进程
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || log "WARN" "无法停止守护进程 (PID: $pid)"
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || log "WARN" "无法强制停止守护进程 (PID: $pid)"
            fi
            log "INFO" "${GREEN}守护进程已停止 (PID: $pid)${NC}"
        else
            log "WARN" "${YELLOW}守护进程 (PID: $pid) 不存在，可能已经停止${NC}"
        fi
        rm -f "$PID_FILE" || log "WARN" "无法删除 PID 文件: $PID_FILE"
    else
        log "WARN" "${YELLOW}守护进程未在运行。${NC}"
    fi

    # 停止包安装监控
    if [ -f "/tmp/package_monitor.pid" ]; then
        local package_pid=$(cat "/tmp/package_monitor.pid")
        if kill -0 "$package_pid" 2>/dev/null; then
            kill "$package_pid" 2>/dev/null || log "WARN" "无法停止包安装监控 (PID: $package_pid)"
            log "INFO" "${GREEN}包安装监控已停止 (PID: $package_pid)${NC}"
        else
            log "WARN" "${YELLOW}包安装监控进程不存在，可能已经停止${NC}"
        fi
        rm -f "/tmp/package_monitor.pid" || log "WARN" "无法删除包安装监控 PID 文件"
    else
        log "WARN" "${YELLOW}包安装监控PID文件不存在${NC}"
    fi

    # 删除所有相关文件
    local files_to_delete=(
        "$NEW_ITEMS_FILE"
        "${NEW_ITEMS_FILE}.saved"
        "$INITIAL_STATE_FILE"
        "$SYSTEM_PARAMS_FILE"
        "${SYSTEM_PARAMS_FILE}.bak"
        "$WHITELIST_FILE"
        "$LOG_FILE"
        "$INIT_FLAG_FILE"
        "$CONFIG_FILE"
        "$PID_FILE"
        "/tmp/package_monitor.pid"
    )

    for file in "${files_to_delete[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file" && log "INFO" "${GREEN}已删除文件: $file${NC}" || log "WARN" "无法删除文件: $file"
        else
            log "WARN" "${YELLOW}文件不存在，跳过: $file${NC}"
        fi
    done

    # 从开机自启中移除
    remove_from_startup

    # 处理 99-sysctl.conf 备份
    if [ -f "${SYSCTL_CONF}.bak" ]; then
        rm -f "${SYSCTL_CONF}.bak" && log "INFO" "${GREEN}已删除 99-sysctl.conf 备份${NC}" || log "WARN" "无法删除 99-sysctl.conf 备份"
    else
        log "WARN" "${YELLOW}99-sysctl.conf 备份不存在${NC}"
    fi

    # 删除 inotify 监控
    if command -v inotifywait &> /dev/null; then
        pkill -f "inotifywait" && log "INFO" "${GREEN}已停止所有 inotifywait 进程${NC}" || log "WARN" "无法停止 inotifywait 进程"
    fi

    # 清理系统日志中的相关条目
    if [ -f /var/log/syslog ]; then
        sudo sed -i '/file_monitor/d' /var/log/syslog && log "INFO" "${GREEN}已从系统日志中清理相关条目${NC}" || log "WARN" "无法清理系统日志中的相关条目"
    fi

    log "INFO" "${GREEN}监控已停止，所有相关数据和进程已删除${NC}"
    echo -e "${YELLOW}监控系统已完全移除。如需重新启用，请重新运行脚本。${NC}"

    return 0
}

# 清屏函数
clear_screen() {
    printf "\033c"
}

# 显示标题
show_title() {
    echo -e "${BLUE}文件系统监控与系统参数管理 - $HOSTNAME${NC}"
    echo "----------------------------------------"
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
        if [ -z "$file" ]; then
            break
        fi
        files+=("$file")
    done

    if [ ${#files[@]} -eq 0 ]; then
        echo -e "${RED}未输入任何文件路径，操作取消。${NC}"
    else
        for file in "${files[@]}"; do
            if [ -e "$file" ]; then
                if ! is_whitelisted "$file"; then
                    echo "$file" >> "$WHITELIST_FILE"
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
    if [ ! -f "$WHITELIST_FILE" ] || [ ! -s "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}白名单为空，无需移除。${NC}"
        echo
        read -p "按 Enter 键继续..."
        return
    fi

    while true; do
        clear_screen
        show_title
        echo -e "${BLUE}当前白名单内容：${NC}"
        cat -n "$WHITELIST_FILE"
        echo
        echo -e "${YELLOW}请输入要删除的项目编号（输入 0 返回，输入 'all' 删除所有）：${NC}"

        local choice
        read -r choice

        if [ "$choice" = "0" ]; then
            return
        elif [ "$choice" = "all" ]; then
            > "$WHITELIST_FILE"
            echo -e "${GREEN}已删除所有白名单项${NC}"
            echo
            read -p "按 Enter 键继续..."
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "$(wc -l < "$WHITELIST_FILE")" ] && [ "$choice" -gt 0 ]; then
            local removed_item
            removed_item=$(sed -n "${choice}p" "$WHITELIST_FILE")
            sed -i "${choice}d" "$WHITELIST_FILE"
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
    if [ ! -f "$WHITELIST_FILE" ] || [ ! -s "$WHITELIST_FILE" ]; then
        echo -e "${YELLOW}白名单为空。${NC}"
    else
        echo -e "${BLUE}当前白名单内容：${NC}"
        cat -n "$WHITELIST_FILE"
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
        echo "1. 保存新增项目"
        echo "2. 保存系统参数和 99-sysctl.conf 配置"
        echo "3. 恢复系统参数和 99-sysctl.conf 配置"
        echo "4. 查看新增项目"
        echo "5. 查看守护进程状态"
        echo "6. 白名单管理"  
        echo "7. 停止监控并删除数据"  
        echo "8. 返回主菜单"
        echo -e "${YELLOW}请输入选项（1-8）：${NC}"

        local choice
        read -r choice

        case "$choice" in
            1) 
                if save_new_items; then
                    echo -e "${GREEN}新增项目保存成功${NC}"
                else
                    echo -e "${RED}保存新增项目失败${NC}"
                fi
                ;;
            2) 
                if save_system_params; then
                    echo -e "${GREEN}系统参数和配置保存成功${NC}"
                else
                    echo -e "${RED}保存系统参数和配置失败${NC}"
                fi
                ;;
            3) 
                if restore_system_params; then
                    echo -e "${GREEN}系统参数和配置恢复成功${NC}"
                else
                    echo -e "${RED}恢复系统参数和配置失败${NC}"
                fi
                ;;
            4) 
                view_new_items
                continue
                ;;
            5) 
                display_status
                ;;
            6) 
                whitelist_menu
                continue
                ;;
            7) 
                if stop_and_delete_monitoring; then
                    echo -e "${GREEN}监控已停止并且数据已删除${NC}"
                    echo -e "${YELLOW}监控系统已完全移除。如需重新启用，请退出并重新运行脚本。${NC}"
                    echo -e "${YELLOW}按 Enter 键返回主菜单...${NC}"
                    read -r
                    return
                else
                    echo -e "${RED}停止监控和删除数据失败${NC}"
                fi
                ;;
            8) return ;;
            *) 
                echo -e "${RED}无效的选项，请重新输入。${NC}"
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
            1) 
                if ! start_daemon; then
                    echo -e "${RED}启动守护进程失败${NC}"
                fi
                wait_for_input
                ;;
            2) 
                if ! stop_daemon; then
                    echo -e "${RED}停止守护进程失败${NC}"
                fi
                wait_for_input
                ;;
            3) 
                if ! clean_new_items; then
                    echo -e "${RED}清理新增项目失败${NC}"
                fi
                wait_for_input
                ;;
            4) data_info_menu ;;
            5) 
                echo -e "${GREEN}退出脚本${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}无效的选项，请重新输入。${NC}"
                sleep 1
                ;;
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

# 主函数
main() {
    export LC_ALL=C
    local VERBOSE=false
    local CMD=""

    # 解析命令行参数
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -v|--verbose) VERBOSE=true ;;
            start|stop|status|clean) CMD="$1" ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
        shift
    done

    trap 'echo -e "\n${RED}脚本被中断${NC}" >&2; sleep 1; main_menu' INT TERM

    if ! initialize_system; then
        handle_error "系统初始化失败" >&2
        sleep 2
    fi

    read_config

    if [ -z "$CMD" ]; then
        main_menu
    else
        case "$CMD" in
            start)
                start_daemon
                add_to_startup
                ;;
            stop)
                stop_daemon
                remove_from_startup
                ;;
            status) check_status ;;
            clean) clean_new_items ;;
            *) 
                echo "无效的命令: $CMD"
                exit 1
                ;;
        esac
    fi
}

# 执行主函数
main "$@"