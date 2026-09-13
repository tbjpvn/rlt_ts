#!/bin/bash

MAX_JOBS=8          # 并发数
SAMPLE_TIMES=3       # 每个域名握手耗时采样次数（仅在首次探测成功后进行）
X25519_RETRY_TIMES=2
XRAY_TLS_PING_TIMEOUT=12
CONNECT_TIMEOUT=6
MAX_TIME=10
RETRY_TIMES=3        # 握手失败时的重试次数（含首次），提高容错，避免一次性网络抖动导致误判FAIL

# ---------- CDN 判定相关配置 ----------
# 纯响应头嗅探能被CDN/源站轻易隐藏（很多CDN默认不会给正常200响应注入身份头，
# 例如 Akamai 只在自己生成的错误页上才带 AkamaiGHost，正常回源透传的响应完全测不出来）。
# 官方文档说的是"IP地址特殊"，所以补充两种更贴近本质的判定手段：
#   1) CNAME链追溯：很多CDN客户域名会CNAME到CDN自己的域名后缀上，这个信号比响应头稳得多。
#   2) IP段比对：Cloudflare这类不走自定义CNAME、直接用anycast IP的CDN，用官方公布的IP段来判。
# 三种手段（CNAME/IP段/响应头）只要命中一种就判"是"，尽量降低漏判。
DIG_AVAILABLE=1     # 由 check_deps 中检测到 dig 后决定是否开启
XRAY_AVAILABLE=0     # 可选：用于官方 xray tls ping 检测
SERVER_NAME=""      # 可选 SNI；为空时使用 target 本身
CDN_CNAME_REGEX='akamai(edge|ized|hd)?\.net$|edgesuite\.net$|edgekey\.net$|akadns\.net$|cloudfront\.net$|fastly(lb)?\.net$|fastlyedge\.net$|azureedge\.net$|azurefd\.net$|msecnd\.net$|trafficmanager\.net$|incapdns\.net$|impervadns\.net$|sucuri\.net$|kxcdn\.com$|b-cdn\.net$|stackpathdns\.com$|hwcdn\.net$|cachefly\.net$|llnwd\.net$|footprint\.net$|edgecastcdn\.net$|cdn77\.(org|net)$|alikunlun\.com$|kunlun[a-z0-9]*\.com$|tbcache\.com$|wswitch\.[a-z0-9.]*cache\.com$|qcloudcdn\.com$|cdn\.dnsv1\.com$|tencent-cloud\.net$|bdydns\.com$|bcelive\.com$|chinacache\.net$|lxdns\.com$|ourwebpic\.com$|wsdvs\.com$|wscdns\.com$|wscloudcdn\.com$|upaiyun\.com$|qiniudns\.com$|qbox\.me$|jiashule\.(com|org)$|jiasule\.(com|org)$'
CF_RANGES_CACHE_DIR="${TMPDIR:-/tmp}/reality_test_cf_ranges"
CF_RANGES_TTL=86400   # Cloudflare官方IP段缓存有效期（秒），避免每次运行都重新拉取

# ---------- 中英文混排对齐 ----------
# 表格采用“主表 + 明细行”：主表只放最关键字段，避免域名/IPv6/SNI把终端撑爆。
# 明细行单独显示解析IP、SNI、PQ，这样即使IPv6很长也不会破坏主表对齐。
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
    [ "$sp" -lt 0 ] && sp=0
    printf '%s%*s' "$s" "$sp" ""
}

# 主表进一步压缩到约 80 列；IP/SNI/PQ 放到下一行明细。
# 注意：Shell 无法改变终端本身的字体大小，这里通过减少列宽/留白并将明细设为淡色来实现更紧凑的视觉效果。
# 参数：域名、协议栈、结果、TLS、ALPN、CDN、跳转、X25519、证书、耗时、颜色
print_row() {
    local color="${11}"
    printf "%b%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s%b\n" \
        "$color" \
        "$(pad_field "$1" 24)" "$(pad_field "$2" 3)" "$(pad_field "$3" 6)" \
        "$(pad_field "$4" 7)" "$(pad_field "$5" 4)" "$(pad_field "$6" 2)" \
        "$(pad_field "$7" 3)" "$(pad_field "$8" 5)" "$(pad_field "$9" 5)" \
        "$(pad_field "${10}" 6)" \
        "\033[0m"
}

print_detail() {
    local ip="$1" sni="$2" pq="$3" color="$4"
    printf "\033[2m    IP:%s  SNI:%s  PQ:%s\033[0m\n" "$ip" "$sni" "$pq"
}

print_card() {
    local dom="$1" stack="$2" status="$3" tls="$4" alpn="$5" cf="$6" redirect="$7" x25519="$8" cert="$9" hs="${10}" ip="${11}" sni="${12}" pq="${13}" color="${14}"
    printf "%b● %s [IPv%s]  %s\033[0m\n" "$color" "$dom" "$stack" "$status"
    printf "%b  TLS:%s ALPN:%s CDN:%s 跳转:%s X25519:%s 证书:%s\033[0m\n" \
        "$color" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert"
    printf "%b  耗时:%s  IP:%s\033[0m\n" "$color" "$hs" "$ip"
    printf "%b  SNI:%s  PQ:%s\033[0m\n" "$color" "$sni" "$pq"
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

    # 预拉取 Cloudflare 官方IP段，用于IP段比对（Cloudflare走anycast IP，不走自定义CNAME，
    # 响应头/CNAME两种手段都测不出来，只能靠官方公布的IP段直接比对）
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

# ---------- CDN 判定辅助函数 ----------

# 追溯CNAME链，最多跟10跳，返回空格分隔的各跳目标（不含最终A记录）
# 很多站点的CDN是通过 www -> xxx.akamaiedge.net / xxx.fastly.net 这类CNAME接入的，
# 追这条链比看响应头稳得多——源站换个Server头就能骗过响应头检测，但CNAME骗不了。
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

# 判断CNAME链上有没有命中已知CDN域名后缀
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

# 仅支持IPv4：把点分十进制转成整数，方便做位运算比较网段
ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    [ -z "$d" ] && { echo -1; return; }
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# 判断IPv4地址是否落在给定 CIDR 内
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

# 判断解析出的IP是否落在 Cloudflare 官方公布的IPv4段内（Cloudflare走anycast，
# 不会有自定义CNAME，也可能被配置成不带cf-ray之类的响应头，所以专门补一条IP段比对）
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

# ---------- 单域名测试 ----------
# 参数: $1=域名  $2=协议栈(4 或 6)  $3=结果输出文件
test_domain() {
    local x="$1"
    local stack="$2"
    local outfile="$3"
    local sni="${SERVER_NAME:-$x}"
    local label="$x [IPv${stack}]"
    local stack_flag="-${stack}"

    echo -e "\033[36m▶ 开始测试: $label\033[0m" >&2

    if ! is_valid_domain "$x"; then
        echo "3|$label|格式错误|-|-|-|-|-|9999|-|$sni|-" >> "$outfile"
        echo -e "\033[90m✗ 域名格式无效: $label\033[0m" >&2
        return
    fi

    # 先检查该协议栈是否存在对应的DNS记录（A/AAAA）。没有记录不等于连接失败，
    # 单独标记为"无记录"，避免和真正的连接失败混在一起误判
    if command -v getent >/dev/null 2>&1; then
        if [ "$stack" = "6" ]; then
            if ! getent ahostsv6 "$x" >/dev/null 2>&1; then
                echo "4|$label|无AAAA记录|-|-|-|-|-|9999|-|$sni|-" >> "$outfile"
                echo -e "\033[90m○ 无IPv6记录: $label\033[0m" >&2
                return
            fi
        else
            if ! getent ahostsv4 "$x" >/dev/null 2>&1; then
                echo "4|$label|无A记录|-|-|-|-|-|9999|-|$sni|-" >> "$outfile"
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
    local curl_url="https://$x"
    local curl_extra=()
    if [ "$sni" != "$x" ]; then
        curl_url="https://$sni"
        curl_extra+=(--connect-to "${sni}:443:${x}:443")
    fi

    while [ $attempt -lt $RETRY_TIMES ]; do
        o=$(curl -s -v $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" --tls-max 1.3 \
                "${curl_extra[@]}" \
                -I -o /dev/null \
                -w "\n__META__ HANDSHAKE=%{time_appconnect} HTTPCODE=%{http_code} IP=%{remote_ip}\n" \
                "$curl_url" 2>&1)
        curl_exit=$?
        h=$(echo "$o" | grep -o "HANDSHAKE=[0-9.]*" | cut -d= -f2)
        [ -n "$h" ] && [ "$h" != "0.000000" ] && break
        attempt=$((attempt + 1))
    done

    # 只有真正连握手都没完成（DNS失败/连接拒绝/握手阶段超时）才算彻底失败
    if [ -z "$h" ] || [ "$h" = "0.000000" ]; then
        echo "3|$label|失败|-|-|-|-|-|9999|-|$sni|-" >> "$outfile"
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

    # CDN 判断依赖真实HTTP响应头；如果HTTP层完全没有响应（反爬拦截/超时），
    # 没有任何响应头可看，这时不能默认判"否"，标记为"未知"更准确。
    # 注意：不只测Cloudflare，官方REALITY文档原话是"如果target网站的IP地址特殊（如使用了
    # CloudFlare CDN的网站）"——Cloudflare只是举例，真正要避开的是任何CDN共享IP节点，
    # 所以这里覆盖了主流CDN厂商的特征响应头。
    local http_responded=0
    echo "$o" | grep -q "^< " && http_responded=1

    # CDN判定：CNAME链 / Cloudflare官方IP段 / 响应头特征，三者任一命中就判"是"。
    # 响应头很容易被CDN或源站隐藏（比如Akamai正常回源不会给200响应加身份头，
    # 只有自己生成的错误页才带AkamaiGHost），所以优先信CNAME和IP段这两个更硬的信号，
    # 响应头只作为兜底，弥补Cloudflare这种走anycast、没有自定义CNAME的情况之外的补充。
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

    # 跳转检测：社区与多篇实操文档一致强调的最低要求之一是"域名非跳转用"
    # （常见翻车点：裸域名301/302跳到www，或跳到完全不同的域名）。
    # 原理：REALITY对未鉴权流量是直接把原始连接转发给target，如果target对该请求的
    # 真实响应只是一个跳转而非完整页面内容，行为特征上不像一个"正常网站"，
    # 跟CDN一样属于会被直接排除的硬性条件，不是加分项。
    local httpcode redirect="否" redirect_loc=""
    httpcode=$(echo "$o" | grep -o "HTTPCODE=[0-9]*" | cut -d= -f2)
    if [ "$http_responded" -eq 0 ]; then
        redirect="未知"
    elif [[ "$httpcode" =~ ^30[12378]$ ]]; then
        redirect="是"
        redirect_loc=$(echo "$o" | grep -i "^< location:" | head -n1 | sed 's/^< [Ll]ocation: *//I' | tr -d '\r\n')
        echo -e "\033[90m  ↳ $label 检测到跳转($httpcode): $redirect_loc\033[0m" >&2
    fi

    # 多次采样取平均握手耗时——仅在HTTP层也正常响应时才补充采样，
    # 避免在被拦截/挂起的站点上反复空等（每次都要等满MAX_TIME）
    local avg="$h"
    if [ "$curl_exit" -eq 0 ] && [ "$http_responded" -eq 1 ]; then
        local samples="$h" i hs
        for ((i = 1; i < SAMPLE_TIMES; i++)); do
            hs=$(curl -s -I -o /dev/null $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                    --tls-max 1.3 "${curl_extra[@]}" -w "%{time_appconnect}" "$curl_url" 2>/dev/null)
            [ -n "$hs" ] && [ "$hs" != "0.000000" ] && samples="$samples $hs"
        done
        avg=$(echo "$samples" | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; printf "%.3f", s/NF}')
    fi

    # 证书检测：从握手阶段已经拿到的verbose日志里解析，不需要再发一次额外连接。
    # 分两部分：1) 证书链是否受信（curl默认就会校验，没有-k参数的话，链不受信会直接握手失败，
    #    走不到这里；这里是显式确认+防御性兜底）；2) 证书是否在有效期内。
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
            # 拿不到起止日期文本，但curl明确确认了链验证通过，按"有效"处理
            cert_status="有效"
        fi
    fi

    # ---------- 官方 Xray TLS ping（可选） ----------
    # 官方文档建议用 xray tls ping target 检查 target 是否支持 X25519MLKEM768；
    # 这里不把“未安装 xray”当成失败，只作为信息项。
    local pq="未知" xray_ping="未检测"
    if [ "$XRAY_AVAILABLE" -eq 1 ] && [ "$stack" = "4" ]; then
        local ping_target="$x"
        local ping_out
        ping_out=$(timeout "$XRAY_TLS_PING_TIMEOUT" xray tls ping "$ping_target" 2>&1) || true
        xray_ping="通过命令"
        if echo "$ping_out" | grep -qiE 'X25519MLKEM768|X25519.*MLKEM|MLKEM768'; then
            pq="是"
        elif echo "$ping_out" | grep -qiE 'X25519'; then
            pq="否/未发现MLKEM768"
        else
            pq="未知"
        fi
        echo -e "\033[90m  ↳ $label xray tls ping: X25519MLKEM768=$pq\033[0m" >&2
    fi

    # ---------- 最终判定：硬条件一票否决，其余只做提示 ----------
    # 3=不合格：TLS不是1.3、明确CDN、明确301/302/303/307/308、证书明确失效。
    # 1=可用但有警告：H2缺失、X25519未知/不支持、CDN/跳转/证书无法确认等。
    # 0=推荐：硬条件全部通过；H2/X25519确认越完整，推荐度越高。
    # 4=该协议栈无DNS记录。
    # 注意：X25519 不再作为硬性淘汰条件；PQ 更只是信息项。
    local status x25519="未知" warn=""

    if [ "$t" != "TLSv1.3" ]; then
        status=3
        warn="TLS非1.3"
    elif [ "$c" = "是" ]; then
        status=3
        warn="确认CDN"
    elif [ "$redirect" = "是" ]; then
        status=3
        warn="确认跳转"
    elif [ "$cert_status" = "不合法" ] || [ "$cert_status" = "已过期" ] || [ "$cert_status" = "未生效" ]; then
        status=3
        warn="证书无效"
    else
        # TLS1.3 + 非确认CDN + 非确认跳转 + 证书没有明确失效 => 保留候选。
        # X25519仅作兼容性/质量提示，不再因此淘汰。
        if [ "$CURVES_SUPPORTED" -eq 1 ]; then
            local x_ok=1 x_try
            for ((x_try = 0; x_try < X25519_RETRY_TIMES; x_try++)); do
                if curl -s -o /dev/null $stack_flag --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                        --tls-max 1.3 --curves X25519 "${curl_extra[@]}" -I "$curl_url" >/dev/null 2>&1; then
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

        status=0
        [ "$a" != "h2" ] && warn="${warn:+$warn；}非h2"
        [ "$x25519" = "否" ] && warn="${warn:+$warn；}X25519未确认"
        [ "$x25519" = "未知" ] && warn="${warn:+$warn；}X25519未知"
        [ "$c" = "未知" ] && warn="${warn:+$warn；}CDN未知"
        [ "$redirect" = "未知" ] && warn="${warn:+$warn；}跳转未知"
        [ "$cert_status" = "未知" ] && warn="${warn:+$warn；}证书未知"
        [ -n "$warn" ] && status=1
    fi

    echo "$status|$label|$t|$a|$c|$redirect|$x25519|$cert_status|$avg|$ip|$sni|$pq" >> "$outfile"
    case "$status" in
        0) echo -e "\033[32m✓ 完成: $label (合格)\033[0m" >&2 ;;
        1) echo -e "\033[33m⚠ 完成: $label (需人工确认: 非h2 或 存在未知项)\033[0m" >&2 ;;
        *) echo -e "\033[90m✗ 完成: $label (不合格)\033[0m" >&2 ;;
    esac
}

# ---------- 主循环 ----------
check_deps
detect_utf8_locale

# 表格模式需要较宽的终端才不会自己把行撑得换行（尤其是IPv6地址普遍20+字符）。
# 手机SSH客户端这类窄终端下，硬凑表格只会把每一列拆到下一行、完全对不齐，
# 不如自动降级成每条记录几行的紧凑格式，内容多长都不影响可读性。
TERM_COLS=$(tput cols 2>/dev/null)
[[ "$TERM_COLS" =~ ^[0-9]+$ ]] || TERM_COLS=80
TABLE_MIN_COLS=82   # 主表已压缩；普通80列终端自动使用卡片模式
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

    read -r -p $'可选 SNI/serverName（直接回车=每个 target 自己；仅在目标接受该 SNI 时填写）: ' SERVER_NAME

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
        print_row "域名" "栈" "结果" "TLS" "ALPN" "CDN" "跳转" "X25519" "证书" "耗时" "\033[1;33m"
        echo -e "\033[1;33m---------------------------------------------------------------------------------\033[0m"
    fi

    sort -t'|' -k1,1n -k9,9n "$result_file" | while IFS='|' read -r status dom tls alpn cf redirect x25519 cert hs ip sni pq; do
        case "$status" in
            0) color="\033[1;32m"; result_label="推荐" ;;
            1) color="\033[1;33m"; result_label="可用/警告" ;;
            4) color="\033[36m"; result_label="无DNS" ;;
            *) color="\033[90m"; result_label="不合格" ;;
        esac
        stack=$(printf '%s' "$dom" | sed -n 's/.*\[IPv\([46]\)\]$/\1/p')
        [ -z "$stack" ] && stack="?"
        clean_dom=$(printf '%s' "$dom" | sed 's/ \[IPv[46]\]$//')
        if [ "$status" = "4" ]; then
            alpn="-"; cf="-"; redirect="-"; x25519="-"; cert="-"; hs="-"; ip="-"; sni="-"; pq="-"
        else
            hs="${hs}s"
        fi
        if [ "$TABLE_MODE" -eq 1 ]; then
            print_row "$clean_dom" "IPv$stack" "$result_label" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert" "$hs" "$color"
            print_detail "$ip" "$sni" "$pq" "$color"
        else
            print_card "$clean_dom" "$stack" "$result_label" "$tls" "$alpn" "$cf" "$redirect" "$x25519" "$cert" "$hs" "$ip" "$sni" "$pq" "$color"
        fi
    done
    echo -e "\033[32m■\033[0m 推荐   \033[1;33m■\033[0m 硬条件通过但有警告   \033[90m■\033[0m 不合格(仅硬条件)   \033[36m■\033[0m 无DNS记录"
    echo -e "\033[2m  硬条件：TLS1.3、不能确认使用CDN、不能确认301/302/303/307/308跳转、证书不能明确失效。\033[0m"
    echo -e "\033[2m  ALPN/H2、X25519、未知项只作为警告，不再一票否决；IPv4/IPv6分别判断，一个协议栈失败不会拖死另一个。\033[0m"
    echo -e "\033[2m  CDN综合CNAME/Cloudflare官方IP段/响应头；PQ来自可选 xray tls ping，仅作信息项。SNI默认等于target。\033[0m"

    rm -rf "$tmp_dir"
done
