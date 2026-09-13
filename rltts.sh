#!/bin/bash

MAX_JOBS=8          # 并发数
SAMPLE_TIMES=3       # 每个域名握手耗时采样次数（仅在首次探测成功后进行）
CONNECT_TIMEOUT=6
MAX_TIME=10
RETRY_TIMES=3        # 握手失败时的重试次数（含首次），提高容错，避免一次性网络抖动导致误判FAIL

# ---------- 中英文混排对齐 ----------
# 检测一个可用的 UTF-8 locale，用于正确计算中文字符的显示宽度
UTF8_LOCALE=""
detect_utf8_locale() {
    local loc cc
    for loc in C.utf8 C.UTF-8 en_US.UTF-8 en_US.utf8 zh_CN.UTF-8 zh_CN.utf8; do
        cc=$(LC_ALL="$loc" bash -c 'echo -n "${#1}"' _ "中" 2>/dev/null)
        if [ "$cc" = "1" ]; then
            UTF8_LOCALE="$loc"
            return
        fi
    done
}

# 计算字符串的终端显示宽度（中文等宽字符按2列计算，ASCII按1列）
str_width() {
    local s="$1"
    if [ -z "$UTF8_LOCALE" ]; then
        echo "${#s}"
        return
    fi
    local cc bc
    LC_ALL="$UTF8_LOCALE"
    cc=${#s}
    LC_ALL=C
    bc=${#s}
    echo $(( (cc + bc) / 2 ))
}

# 按显示宽度右侧补空格对齐（而非按字节/字符数对齐，避免中英文混排时错位）
pad_field() {
    local s="$1" target="$2" vw sp
    vw=$(str_width "$s")
    sp=$((target - vw))
    [ $sp -lt 0 ] && sp=0
    printf '%s%*s' "$s" "$sp" ""
}

# 打印表格一行，$1-$7 为各列内容，$8 为颜色码
print_row() {
    local color="$8"
    printf "%b%s | %s | %s | %s | %s | %s | %s%b\n" \
        "$color" \
        "$(pad_field "$1" 34)" "$(pad_field "$2" 9)" "$(pad_field "$3" 7)" \
        "$(pad_field "$4" 11)" "$(pad_field "$5" 8)" "$(pad_field "$6" 10)" "$(pad_field "$7" 15)" \
        "\033[0m"
}

# ---------- 依赖检查 ----------
check_deps() {
    for bin in curl awk sort; do
        command -v "$bin" >/dev/null 2>&1 || { echo -e "\033[1;31m[错误] 缺少依赖: $bin，请先安装。\033[0m"; exit 1; }
    done

    curl_ver=$(curl --version | head -n1 | awk '{print $2}')
    min_ver="7.54.0"
    if [ "$(printf '%s\n%s\n' "$min_ver" "$curl_ver" | sort -V | head -n1)" != "$min_ver" ]; then
        echo -e "\033[1;31m[错误] curl 版本过低 ($curl_ver)，--tls-max 参数需要 7.54.0 及以上。\033[0m"
        exit 1
    fi

    command -v getent >/dev/null 2>&1 || \
        echo -e "\033[1;33m[提示] 未找到 getent，无法区分\"无该协议栈DNS记录\"与\"连接失败\"，将统一按失败处理。\033[0m"

    # --curves 参数用于强制指定密钥交换曲线（检测X25519支持），需要 curl 7.73.0+
    CURVES_SUPPORTED=1
    local curves_min="7.73.0"
    if [ "$(printf '%s\n%s\n' "$curves_min" "$curl_ver" | sort -V | head -n1)" != "$curves_min" ]; then
        CURVES_SUPPORTED=0
        echo -e "\033[1;33m[提示] curl 版本 ($curl_ver) 过低，不支持 --curves 参数，将无法检测 X25519 密钥交换支持（需要 7.73.0+）。\033[0m"
    fi
}

# ---------- 域名格式清洗与校验 ----------
clean_domain() {
    local raw="$1"
    raw="${raw#http://}"
    raw="${raw#https://}"
    raw="${raw%%/*}"
    raw="${raw%%:*}"
    raw=$(echo "$raw" | tr -d '[:space:]')
    echo "$raw"
}

is_valid_domain() {
    local dom="$1"
    [[ "$dom" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]
}

# ---------- 单域名测试 ----------
# 参数: $1=域名  $2=协议栈(4 或 6)  $3=结果输出文件
test_domain() {
    local x="$1"
    local stack="$2"
    local outfile="$3"
    local label="$x [IPv${stack}]"
    local stack_flag="-${stack}"

    echo -e "\033[36m▶ 开始测试: $label\033[0m" >&2

    if ! is_valid_domain "$x"; then
        echo "3|$label|格式错误|-|-|9999|-|-" >> "$outfile"
        echo -e "\033[90m✗ 域名格式无效: $label\033[0m" >&2
        return
    fi

    # 先检查该协议栈是否存在对应的DNS记录（A/AAAA）。没有记录不等于连接失败，
    # 单独标记为"无记录"，避免和真正的连接失败混在一起误判
    if command -v getent >/dev/null 2>&1; then
        if [ "$stack" = "6" ]; then
            if ! getent ahostsv6 "$x" >/dev/null 2>&1; then
                echo "4|$label|无AAAA记录|-|-|9999|-|-" >> "$outfile"
                echo -e "\033[90m○ 无IPv6记录: $label\033[0m" >&2
                return
            fi
        else
            if ! getent ahostsv4 "$x" >/dev/null 2>&1; then
                echo "4|$label|无A记录|-|-|9999|-|-" >> "$outfile"
                echo -e "\033[90m○ 无IPv4记录: $label\033[0m" >&2
                return
            fi
        fi
    fi

    # 第一次探测（含一次自动重试，应对偶发抖动）
    # 注意：这里只以"握手是否完成"作为重试条件，不以整个curl是否成功为条件——
    # 因为有些站点（反爬/WAF防护）会正常完成TLS握手，但后续HTTP层故意不响应导致curl整体超时，
    # 这种情况握手数据本身是有效的，不应该被当成完全失败丢弃。
    local attempt=0 curl_exit=1 o="" h="" ip=""
    while [ $attempt -lt $RETRY_TIMES ]; do
        o=$(curl -s -v $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --tls-max 1.3 \
                -I -o /dev/null \
                -w "\n__META__ HANDSHAKE=%{time_appconnect} HTTPCODE=%{http_code} IP=%{remote_ip}\n" \
                "https://$x" 2>&1)
        curl_exit=$?
        h=$(echo "$o" | grep -o "HANDSHAKE=[0-9.]*" | cut -d= -f2)
        [ -n "$h" ] && [ "$h" != "0.000000" ] && break
        attempt=$((attempt + 1))
    done

    # 只有真正连握手都没完成（DNS失败/连接拒绝/握手阶段超时）才算彻底失败
    if [ -z "$h" ] || [ "$h" = "0.000000" ]; then
        echo "3|$label|失败|-|-|9999|-|-" >> "$outfile"
        echo -e "\033[90m✗ 连接失败(握手未完成): $label\033[0m" >&2
        return
    fi

    ip=$(echo "$o" | grep -o "IP=.*" | cut -d= -f2)
    local t a c
    t=$(echo "$o" | grep -o "SSL connection using TLSv[0-9.]*" | awk '{print $4}')
    [ -z "$t" ] && t="未知"

    if echo "$o" | grep -iE "alpn.*(accepted|negotiated).*h2" >/dev/null 2>&1 \
        || echo "$o" | grep -iE "alpn.*h2.*(accepted|negotiated)" >/dev/null 2>&1; then
        a="h2"
    else
        a="非h2"
    fi

    # Cloudflare 判断依赖真实HTTP响应头；如果HTTP层完全没有响应（反爬拦截/超时），
    # 没有任何响应头可看，这时不能默认判"否"，标记为"未知"更准确
    local http_responded=0
    echo "$o" | grep -q "^< " && http_responded=1

    if [ "$http_responded" -eq 1 ]; then
        if echo "$o" | grep -iqE "^< server: cloudflare|^< cf-ray:|^< cf-cache-status:|^< cf-mitigated:"; then
            c="是"
        else
            c="否"
        fi
    else
        c="未知"
    fi

    # 多次采样取平均握手耗时——仅在HTTP层也正常响应时才补充采样，
    # 避免在被拦截/挂起的站点上反复空等（每次都要等满MAX_TIME）
    local avg="$h"
    if [ "$curl_exit" -eq 0 ] && [ "$http_responded" -eq 1 ]; then
        local samples="$h" i hs
        for ((i = 1; i < SAMPLE_TIMES; i++)); do
            hs=$(curl -s -I -o /dev/null $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                    --tls-max 1.3 -w "%{time_appconnect}" "https://$x" 2>/dev/null)
            [ -n "$hs" ] && [ "$hs" != "0.000000" ] && samples="$samples $hs"
        done
        avg=$(echo "$samples" | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; printf "%.3f", s/NF}')
    fi

    # 四档状态：
    # 0=完全OK（TLS1.3+h2+HTTP正常响应+确认非CF，待X25519复核）
    # 1=不确定，需人工确认——非h2（有些非h2的站点实际也能用，不直接判死），或HTTP无响应导致CF状态测不出来
    # 3=不能用——握手本身失败，或者已经明确查清楚是CF，或者明确查清楚不支持X25519（这三种原因不同，
    #   但结论都是"不能用"，所以统一用同一个颜色，不再单独区分）
    # 4=该协议栈无DNS记录（在上面已提前返回，这里不会用到）
    local status
    if [ "$t" != "TLSv1.3" ]; then
        status=3
    elif [ "$a" != "h2" ]; then
        status=1
    elif [ "$http_responded" -ne 1 ]; then
        status=1
    elif [ "$c" = "是" ]; then
        status=3
    else
        status=0
    fi

    # X25519 密钥交换检测：仅对还有希望的候选（status 0/1）做进一步验证，
    # 用 --curves X25519 强制只提供该曲线，握手能成功就说明服务端支持X25519。
    # 加一次重试，避免偶发网络抖动导致误判。
    # 只要明确测出不支持X25519，不管之前是绿是黄，一律归到"不能用"这一档。
    local x25519="未知"
    if [ "$CURVES_SUPPORTED" -eq 1 ] && { [ "$status" -eq 0 ] || [ "$status" -eq 1 ]; }; then
        local x_ok=1 x_try
        for ((x_try = 0; x_try < 2; x_try++)); do
            if curl -s -o /dev/null $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                    --tls-max 1.3 --curves X25519 -I "https://$x" >/dev/null 2>&1; then
                x_ok=0
                break
            fi
        done
        if [ "$x_ok" -eq 0 ]; then
            x25519="是"
        else
            x25519="否"
            status=3
        fi
    fi

    echo "$status|$label|$t|$a|$c|$avg|$ip|$x25519" >> "$outfile"
    case "$status" in
        0) echo -e "\033[32m✓ 完成: $label (OK)\033[0m" >&2 ;;
        1) echo -e "\033[33m⚠ 完成: $label (需人工确认: 非h2 或 HTTP无响应)\033[0m" >&2 ;;
        *) echo -e "\033[90m✗ 完成: $label (不能用)\033[0m" >&2 ;;
    esac
}

# ---------- 主循环 ----------
check_deps
detect_utf8_locale

while true; do
    echo ""
    printf "\033[1;36m请输入域名（空格隔开，0卸载并退出）: \033[0m"
    read -r d

    if [ "$d" = "0" ]; then
        cat /dev/null > ~/.bash_history 2>/dev/null
        history -c 2>/dev/null
        rm -rf ~/.cache/* /tmp/curl_* 2>/dev/null
        echo -e "\033[1;32m[OK] 环境变量、命令历史与临时缓存已彻底清空！\033[0m"
        break
    fi

    [ -z "$d" ] && continue

    tmp_dir=$(mktemp -d)
    result_file="$tmp_dir/results.txt"
    touch "$result_file"

    job_count=0
    total=0
    for x in $d; do total=$((total + 1)); done
    total=$((total * 2))
    echo -e "\033[1;34m共 $total 项测试（每个域名分别测 IPv4/IPv6），并发数: $MAX_JOBS...\033[0m" >&2

    for x in $d; do
        cx=$(clean_domain "$x")
        for stack in 4 6; do
            test_domain "$cx" "$stack" "$result_file" &
            job_count=$((job_count + 1))
            if [ "$job_count" -ge "$MAX_JOBS" ]; then
                wait -n
                job_count=$((job_count - 1))
            fi
        done
    done
    wait

    echo ""
    print_row "域名" "TLS版本" "ALPN" "Cloudflare" "X25519" "平均耗时" "解析IP" "\033[1;33m"
    echo -e "\033[1;33m--------------------------------------------------------------------------------------------\033[0m"

    sort -t'|' -k1,1n -k6,6n "$result_file" | while IFS='|' read -r status dom tls alpn cf hs ip x25519; do
        case "$status" in
            0) color="\033[1;32m" ;;
            1) color="\033[1;33m" ;;
            4) color="\033[36m" ;;
            *) color="\033[90m" ;;
        esac
        if [ "$status" = "4" ]; then
            print_row "$dom" "$tls" "-" "-" "-" "-" "-" "$color"
        else
            print_row "$dom" "$tls" "$alpn" "$cf" "$x25519" "${hs}s" "$ip" "$color"
        fi
    done
    echo -e "\033[32m■\033[0m OK   \033[1;33m■\033[0m 需人工确认(非h2/HTTP无响应)   \033[90m■\033[0m 不能用(握手失败/确认CF/确认非X25519)   \033[36m■\033[0m 无DNS记录"

    rm -rf "$tmp_dir"
done
