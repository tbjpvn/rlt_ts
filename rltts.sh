#!/bin/bash

MAX_JOBS=8          # 并发数
SAMPLE_TIMES=3       # 每个域名握手耗时采样次数（仅在首次探测成功后进行）
CONNECT_TIMEOUT=6
MAX_TIME=10
RETRY_TIMES=3        # 握手失败时的重试次数（含首次）

# ---------- CDN 判定相关配置 ----------
DIG_AVAILABLE=1
CDN_CNAME_REGEX='akamai(edge|ized|hd)?\.net$|edgesuite\.net$|edgekey\.net$|akadns\.net$|cloudfront\.net$|fastly(lb)?\.net$|fastlyedge\.net$|azureedge\.net$|azurefd\.net$|msecnd\.net$|trafficmanager\.net$|incapdns\.net$|impervadns\.net$|sucuri\.net$|kxcdn\.com$|b-cdn\.net$|stackpathdns\.com$|hwcdn\.net$|cachefly\.net$|llnwd\.net$|footprint\.net$|edgecastcdn\.net$|cdn77\.(org|net)$|alikunlun\.com$|kunlun[a-z0-9]*\.com$|tbcache\.com$|wswitch\.[a-z0-9.]*cache\.com$|qcloudcdn\.com$|cdn\.dnsv1\.com$|tencent-cloud\.net$|bdydns\.com$|bcelive\.com$|chinacache\.net$|lxdns\.com$|ourwebpic\.com$|wsdvs\.com$|wscdns\.com$|wscloudcdn\.com$|upaiyun\.com$|qiniudns\.com$|qbox\.me$|jiashule\.(com|org)$|jiasule\.(com|org)$'
CF_RANGES_CACHE_DIR="${TMPDIR:-/tmp}/reality_test_cf_ranges"
CF_RANGES_TTL=86400

# ---------- 中英文混排对齐 ----------
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

pad_field() {
    local s="$1" target="$2" vw sp
    vw=$(str_width "$s")
    sp=$((target - vw))
    [ $sp -lt 0 ] && sp=0
    printf '%s%*s' "$s" "$sp" ""
}

print_row() {
    local color="${11}"
    printf "%b%s | %s | %s | %s | %s | %s | %s | %s | %s | %s%b\n" \
        "$color" \
        "$(pad_field "$1" 28)" "$(pad_field "$2" 9)" "$(pad_field "$3" 5)" \
        "$(pad_field "$4" 5)" "$(pad_field "$5" 5)" "$(pad_field "$6" 5)" \
        "$(pad_field "$7" 7)" "$(pad_field "$8" 6)" "$(pad_field "$9" 8)" "${10}" \
        "\033[0m"
}

print_card() {
    local dom="$1" tls="$2" alpn="$3" cf="$4" redirect="$5" x25519="$6" cert="$7" region="$8" hs="$9" ip="${10}" color="${11}"
    printf "%b● %s\033[0m\n" "$color" "$dom"
    printf "%b  TLS:%s ALPN:%s CDN:%s 跳转:%s X25519:%s 证书:%s 地区:%s\033[0m\n" \
        "$color" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert" "$region"
    printf "%b  耗时:%s  IP:%s\033[0m\n" "$color" "$hs" "$ip"
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

    if ! command -v dig >/dev/null 2>&1; then
        DIG_AVAILABLE=0
        echo -e "\033[1;33m[提示] 未找到 dig（可安装 dnsutils/bind-utils），将跳过CNAME链追溯，CDN判定只能依赖IP段与响应头，准确度会下降。\033[0m"
    fi

    mkdir -p "$CF_RANGES_CACHE_DIR" 2>/dev/null
    local now age
    now=$(date +%s)
    age=$CF_RANGES_TTL
    [ -s "$CF_RANGES_CACHE_DIR/v4" ] && age=$((now - $(date -r "$CF_RANGES_CACHE_DIR/v4" +%s 2>/dev/null || echo 0)))
    if [ ! -s "$CF_RANGES_CACHE_DIR/v4" ] || [ "$age" -ge "$CF_RANGES_TTL" ]; then
        curl -s --max-time 5 "https://www.cloudflare.com/ips-v4" -o "$CF_RANGES_CACHE_DIR/v4.tmp" \
            && [ -s "$CF_RANGES_CACHE_DIR/v4.tmp" ] && mv "$CF_RANGES_CACHE_DIR/v4.tmp" "$CF_RANGES_CACHE_DIR/v4"
        curl -s --max-time 5 "https://www.cloudflare.com/ips-v6" -o "$CF_RANGES_CACHE_DIR/v6.tmp" \
            && [ -s "$CF_RANGES_CACHE_DIR/v6.tmp" ] && mv "$CF_RANGES_CACHE_DIR/v6.tmp" "$CF_RANGES_CACHE_DIR/v6"
    fi
    [ -s "$CF_RANGES_CACHE_DIR/v4" ] || echo -e "\033[1;33m[提示] Cloudflare官方IP段拉取失败，IP段比对这一环会被跳过。\033[0m"

    CURVES_SUPPORTED=1
    local curves_min="7.73.0"
    if [ "$(printf '%s\n%s\n' "$curves_min" "$curl_ver" | sort -V | head -n1)" != "$curves_min" ]; then
        CURVES_SUPPORTED=0
        echo -e "\033[1;33m[提示] curl 版本 ($curl_ver) 过低，不支持 --curves 参数，将无法检测 X25519 密钥交换支持（需要 7.73.0+）。\033[0m"
    fi

    detect_nat64_prefix
}

# ---------- NAT64/DNS64 探测 ----------
# ipv4only.arpa 是 RFC 7050 定义的专用探测域名：只有A记录、无真实AAAA。
# 如果本机/本网络存在DNS64，查询它的AAAA会返回一个"合成"地址，
# 从中即可提取出NAT64前缀，用于后续过滤掉伪造的IPv6结果。
NAT64_PREFIX=""
detect_nat64_prefix() {
    local addr
    if [ "$DIG_AVAILABLE" -eq 1 ]; then
        addr=$(dig +short AAAA ipv4only.arpa 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' | head -n1)
    else
        addr=$(getent ahostsv6 ipv4only.arpa 2>/dev/null | awk '{print $1}' | grep -v '^::ffff:' | head -n1)
    fi
    if [ -n "$addr" ]; then
        # 取前96位（前4个冒号分组）作为前缀，标准NAT64前缀长度为/96
        NAT64_PREFIX=$(echo "$addr" | awk -F: '{printf "%s:%s:%s:%s:", $1,$2,$3,$4}')
        echo -e "\033[1;33m[提示] 检测到本机网络存在 DNS64/NAT64（合成前缀: ${NAT64_PREFIX}/96），将自动过滤该前缀下的伪造IPv6结果，避免把「实际走v4」的域名误判为支持IPv6。\033[0m" >&2
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

# ---------- 真实AAAA记录判定（过滤v4映射地址与NAT64合成地址） ----------
has_real_aaaa() {
    local dom="$1" addr
    local list
    if [ "$DIG_AVAILABLE" -eq 1 ]; then
        list=$(dig +short AAAA "$dom" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$')
    else
        list=$(getent ahostsv6 "$dom" 2>/dev/null | awk '{print $1}')
    fi
    while IFS= read -r addr; do
        [ -z "$addr" ] && continue
        case "$addr" in
            ::ffff:*) continue ;;   # IPv4映射地址，非真实IPv6
        esac
        if [ -n "$NAT64_PREFIX" ] && [[ "$addr" == ${NAT64_PREFIX}* ]]; then
            continue                 # 本机DNS64合成的NAT64地址，非真实IPv6
        fi
        echo "$addr"
        return 0
    done <<< "$list"
    return 1
}

# ---------- CDN 判定辅助函数 ----------
get_cname_chain() {
    local dom="$1" cur="$1" chain="" next hops=0
    while [ $hops -lt 10 ]; do
        next=$(dig +noall +answer +time=3 +tries=1 CNAME "$cur" 2>/dev/null \
                | awk '$4=="CNAME"{print $5}' | head -n1)
        next="${next%.}"
        [ -z "$next" ] && break
        chain="$chain $next"
        cur="$next"
        hops=$((hops + 1))
    done
    echo "$chain"
}

cname_hits_known_cdn() {
    local chain="$1" hop
    for hop in $chain; do
        if echo "$hop" | grep -qiE "$CDN_CNAME_REGEX"; then
            echo "$hop"
            return 0
        fi
    done
    return 1
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    [ -z "$d" ] && { echo -1; return; }
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_in_cidr() {
    local ip="$1" cidr="$2" cidr_ip cidr_mask ip_int cidr_int mask
    cidr_ip="${cidr%/*}"
    cidr_mask="${cidr#*/}"
    ip_int=$(ip_to_int "$ip")
    cidr_int=$(ip_to_int "$cidr_ip")
    [ "$ip_int" -lt 0 ] && return 1
    [ "$cidr_mask" -eq 0 ] && { mask=0; } || mask=$(( 0xFFFFFFFF << (32 - cidr_mask) & 0xFFFFFFFF ))
    [ $(( ip_int & mask )) -eq $(( cidr_int & mask )) ]
}

ip_is_cloudflare() {
    local ip="$1" cidr
    [ -z "$ip" ] && return 1
    [ -s "$CF_RANGES_CACHE_DIR/v4" ] || return 1
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    while IFS= read -r cidr; do
        [ -z "$cidr" ] && continue
        ip_in_cidr "$ip" "$cidr" && return 0
    done < "$CF_RANGES_CACHE_DIR/v4"
    return 1
}

# 获取 IP 所属国家代码（优先 ipinfo.io，失败则尝试 api.ip.sb）
# stack: 4/6，显式绑定协议栈，避免协商耗时；单栈v6环境下适当放宽超时+重试，
# 因为部分GeoIP服务可能需要经NAT64网关中转，RTT比原生连接更高。
get_country_code() {
    local ip="$1" stack="$2" cc="" flag="" try
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    [ -z "$ip" ] && { echo ""; return; }
    [ -n "$stack" ] && flag="-${stack}"

    for try in 1 2; do
        cc=$(curl -s $flag -A "$ua" --max-time 5 "https://ipinfo.io/${ip}/country" 2>/dev/null | tr -d '[:space:]')
        [ -n "$cc" ] && [ ${#cc} -eq 2 ] && { echo "$cc"; return; }
    done

    for try in 1 2; do
        cc=$(curl -s $flag -A "$ua" --max-time 5 "https://api.ip.sb/geoip/${ip}" 2>/dev/null | grep -o '"country_code":"[A-Z][A-Z]"' | head -n1 | cut -d'"' -f4)
        [ -n "$cc" ] && { echo "$cc"; return; }
    done
    echo ""
}

# ---------- 单域名测试 ----------
test_domain() {
    local x="$1"
    local stack="$2"
    local outfile="$3"
    local label="$x [IPv${stack}]"
    local stack_flag="-${stack}"

    echo -e "\033[36m▶ 开始测试: $label\033[0m" >&2

    if ! is_valid_domain "$x"; then
        echo "3|$label|格式错误|-|-|-|-|-|9999|-|-" >> "$outfile"
        echo -e "\033[90m✗ 域名格式无效: $label\033[0m" >&2
        return
    fi

    if [ "$stack" = "6" ]; then
        if [ "$DIG_AVAILABLE" -eq 1 ] || command -v getent >/dev/null 2>&1; then
            if ! has_real_aaaa "$x" >/dev/null; then
                echo "4|$label|无AAAA记录|-|-|-|-|-|9999|-|-" >> "$outfile"
                echo -e "\033[90m○ 无IPv6记录: $label\033[0m" >&2
                return
            fi
        fi
    else
        if command -v getent >/dev/null 2>&1; then
            if ! getent ahostsv4 "$x" >/dev/null 2>&1; then
                echo "4|$label|无A记录|-|-|-|-|-|9999|-|-" >> "$outfile"
                echo -e "\033[90m○ 无IPv4记录: $label\033[0m" >&2
                return
            fi
        fi
    fi

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

    if [ -z "$h" ] || [ "$h" = "0.000000" ]; then
        echo "3|$label|失败|-|-|-|-|-|9999|-|-" >> "$outfile"
        echo -e "\033[90m✗ 连接失败(握手未完成): $label\033[0m" >&2
        return
    fi

    ip=$(echo "$o" | grep -o "IP=.*" | cut -d= -f2)
    local t a c region
    t=$(echo "$o" | grep -o "SSL connection using TLSv[0-9.]*" | awk '{print $4}')
    [ -z "$t" ] && t="未知"

    if echo "$o" | grep -iE "alpn.*(accepted|negotiated).*h2" >/dev/null 2>&1 \
        || echo "$o" | grep -iE "alpn.*h2.*(accepted|negotiated)" >/dev/null 2>&1; then
        a="h2"
    else
        a="非h2"
    fi

    # 地区检查（官方要求：国外网站）
    region=$(get_country_code "$ip" "$stack")
    [ -z "$region" ] && region="未知"
    if [ "$region" = "CN" ]; then
        region="国内"
    fi

    local http_responded=0
    echo "$o" | grep -q "^< " && http_responded=1

    local cname_hit="" cdn_via=""
    if [ "$DIG_AVAILABLE" -eq 1 ]; then
        cname_hit=$(cname_hits_known_cdn "$(get_cname_chain "$x")")
    fi

    if [ -n "$cname_hit" ]; then
        c="是"; cdn_via="CNAME->$cname_hit"
    elif ip_is_cloudflare "$ip"; then
        c="是"; cdn_via="IP段(Cloudflare)"
    elif [ "$http_responded" -eq 1 ]; then
        if echo "$o" | grep -iqE \
            "^< server: cloudflare|^< cf-ray:|^< cf-cache-status:|^< cf-mitigated:|\
^< server: akamaighost|^< x-akamai|\
^< server: cloudfront|^< x-amz-cf-id|^< x-amz-cf-pop|\
^< server: fastly|^< x-served-by:|^< x-fastly-request-id|\
^< x-azure-ref|^< server: ecacc|\
^< x-iinfo:|^< x-cdn:|\
^< server: keycdn|^< server: bunnycdn|^< x-sucuri-id|\
^< server: netdna|^< x-edge-ip|^< x-edge-location|\
^< x-cache-lookup:|^< x-nws-log-uuid:|^< x-daa-tunnel:|\
^< eo-log-uuid:|^< x-swift-cachetime:|^< x-via:.*cdn|\
^< x-cache:.*(hit|miss)|^< via:.*(cdn|varnish)"; then
            c="是"; cdn_via="响应头"
        else
            c="否"
        fi
    else
        c="未知"
    fi

    if [ "$c" = "是" ]; then
        echo -e "\033[90m  ↳ $label 判定为CDN，依据: $cdn_via\033[0m" >&2
    fi

    local httpcode redirect="否" redirect_loc=""
    httpcode=$(echo "$o" | grep -o "HTTPCODE=[0-9]*" | cut -d= -f2)
    if [ "$http_responded" -eq 0 ]; then
        redirect="未知"
    elif [[ "$httpcode" =~ ^3[0-9][0-9]$ ]]; then
        redirect="是"
        redirect_loc=$(echo "$o" | grep -i "^< location:" | head -n1 | sed 's/^< [Ll]ocation: *//I' | tr -d '\r\n')
        echo -e "\033[90m  ↳ $label 检测到跳转($httpcode): $redirect_loc\033[0m" >&2
    fi

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

    local cert_status="未知"
    if echo "$o" | grep -qi "SSL certificate problem\|unable to get local issuer certificate\|certificate verify failed\|self.signed certificate"; then
        cert_status="不合法"
    else
        local cert_start_raw cert_end_raw start_epoch end_epoch now_epoch
        cert_start_raw=$(echo "$o" | grep "start date:" | sed 's/.*start date: //' | head -n1)
        cert_end_raw=$(echo "$o" | grep "expire date:" | sed 's/.*expire date: //' | head -n1)
        if [ -n "$cert_end_raw" ]; then
            now_epoch=$(date +%s)
            end_epoch=$(date -d "$cert_end_raw" +%s 2>/dev/null)
            start_epoch=$(date -d "$cert_start_raw" +%s 2>/dev/null)
            if [ -n "$end_epoch" ]; then
                if [ "$now_epoch" -gt "$end_epoch" ]; then
                    cert_status="已过期"
                elif [ -n "$start_epoch" ] && [ "$now_epoch" -lt "$start_epoch" ]; then
                    cert_status="未生效"
                else
                    cert_status="有效"
                fi
            fi
        elif echo "$o" | grep -q "SSL certificate verify ok."; then
            cert_status="有效"
        fi
    fi

    local status x25519="未知"

    # 硬性不合格条件（官方最低标准 + 实战必要项）
    if [ "$t" != "TLSv1.3" ]; then
        status=3
    elif [ "$region" = "国内" ]; then
        status=3   # 官方明确要求国外网站
    elif [ "$c" = "是" ]; then
        status=3
    elif [ "$redirect" = "是" ]; then
        status=3
    elif [ "$cert_status" = "不合法" ] || [ "$cert_status" = "已过期" ] || [ "$cert_status" = "未生效" ]; then
        status=3
    else
        if [ "$CURVES_SUPPORTED" -eq 1 ]; then
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
            fi
        fi

        if [ "$x25519" = "否" ]; then
            status=3
        elif [ "$a" != "h2" ]; then
            status=1
        else
            status=0
        fi

        # 存在未知项时降级到黄色，方便人工确认
        if [ "$status" -eq 0 ] && { [ "$c" = "未知" ] || [ "$redirect" = "未知" ] || [ "$x25519" = "未知" ] || [ "$cert_status" = "未知" ] || [ "$region" = "未知" ]; }; then
            status=1
        fi
    fi

    echo "$status|$label|$t|$a|$c|$redirect|$x25519|$cert_status|$region|$avg|$ip" >> "$outfile"
    case "$status" in
        0) echo -e "\033[32m✓ 完成: $label (合格)\033[0m" >&2 ;;
        1) echo -e "\033[33m⚠ 完成: $label (需人工确认: 非h2 或 存在未知项)\033[0m" >&2 ;;
        *) echo -e "\033[90m✗ 完成: $label (不合格)\033[0m" >&2 ;;
    esac
}

# ---------- 主循环 ----------
check_deps
detect_utf8_locale

TERM_COLS=$(tput cols 2>/dev/null)
[[ "$TERM_COLS" =~ ^[0-9]+$ ]] || TERM_COLS=80
TABLE_MIN_COLS=130
if [ "$TERM_COLS" -lt "$TABLE_MIN_COLS" ]; then
    TABLE_MODE=0
    echo -e "\033[1;33m[提示] 检测到终端宽度($TERM_COLS列)较窄，结果将以紧凑卡片格式显示而非表格。\033[0m" >&2
else
    TABLE_MODE=1
fi

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
    if [ "$TABLE_MODE" -eq 1 ]; then
        print_row "域名" "TLS版本" "ALPN" "CDN" "跳转" "X25519" "证书" "地区" "平均耗时" "解析IP" "\033[1;33m"
        echo -e "\033[1;33m--------------------------------------------------------------------------------------------------------------\033[0m"
    fi

    sort -t'|' -k1,1n -k10,10n "$result_file" | while IFS='|' read -r status dom tls alpn cf redirect x25519 cert region hs ip; do
        case "$status" in
            0) color="\033[1;32m" ;;
            1) color="\033[1;33m" ;;
            4) color="\033[36m" ;;
            *) color="\033[90m" ;;
        esac
        if [ "$status" = "4" ]; then
            alpn="-"; cf="-"; redirect="-"; x25519="-"; cert="-"; region="-"; hs="-"; ip="-"
        else
            hs="${hs}s"
        fi
        if [ "$TABLE_MODE" -eq 1 ]; then
            print_row "$dom" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert" "$region" "$hs" "$ip" "$color"
        else
            print_card "$dom" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert" "$region" "$hs" "$ip" "$color"
        fi
    done

    echo -e "\033[32m■\033[0m 合格   \033[1;33m■\033[0m 需人工确认(非h2/存在未知项)   \033[90m■\033[0m 不合格(非TLS1.3/国内IP/确认CDN/确认跳转/证书问题/确认非X25519)   \033[36m■\033[0m 无DNS记录"
    echo -e "\033[2m  官方最低标准：国外网站 + TLSv1.3 + H2 + 域名非跳转用。本脚本额外把 CDN、证书有效性、X25519 作为硬性条件（实战必要）。\033[0m"
    echo -e "\033[2m  CDN 综合了 CNAME链 / Cloudflare官方IP段 / 响应头三种信号；地区=CN 直接不合格（符合官方「国外网站」要求）。\033[0m"
    echo -e "\033[2m  如需进一步确认后量子密钥交换(X25519MLKEM768)，官方建议额外执行: xray tls ping <域名>\033[0m"

    rm -rf "$tmp_dir"
done
