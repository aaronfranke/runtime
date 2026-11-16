// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <softfloat.h>

#include "Win95Thread.h"

/* These C functions register no implicit SEH handlers. The assembly
   startup object declares the explicit handler in its SafeSEH table. */
__asm__(".def @feat.00; .scl 3; .type 0; .endef\n.set @feat.00, 1");

/* Windows 95 does not enable user-mode XMM state. The application-local
   handler implements the instruction forms used by the Native AOT port. */
typedef struct {
    volatile BYTE xmm[8][16];
    DWORD mxcsr;
} win95_xmm_state;

static win95_xmm_state main_xmm = { .mxcsr = 0x1f80 };
static DWORD win95_xmm_tls = TLS_OUT_OF_INDEXES;


static DWORD *register_address(CONTEXT *context, unsigned reg)
{
    switch (reg) {
        case 0: return &context->Eax;
        case 1: return &context->Ecx;
        case 2: return &context->Edx;
        case 3: return &context->Ebx;
        case 4: return &context->Esp;
        case 5: return &context->Ebp;
        case 6: return &context->Esi;
        default: return &context->Edi;
    }
}

static DWORD read_u32(const BYTE **instruction)
{
    const BYTE *p = *instruction;
    DWORD result = (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
    *instruction += 4;
    return result;
}

static volatile BYTE *operand_address(CONTEXT *context, unsigned form, const BYTE **instruction)
{
    unsigned mod = form >> 6;
    unsigned base = form & 7;
    DWORD address = 0;
    if (base == 4) {
        unsigned sib = *(*instruction)++;
        unsigned index = (sib >> 3) & 7;
        if (index != 4) {
            address = *register_address(context, index) << (sib >> 6);
        }
        base = sib & 7;
    }
    if (mod == 0 && base == 5) {
        address += read_u32(instruction);
    }
    else {
        address += *register_address(context, base);
    }
    if (mod == 1) {
        address += (LONG)(signed char)*(*instruction)++;
    }
    else if (mod == 2) {
        address += read_u32(instruction);
    }
    return (volatile BYTE *)address;
}

static void copy_xmm(volatile BYTE *target, const volatile BYTE *source, unsigned count)
{
    for (unsigned i = 0; i < count; ++i) {
        target[i] = source[i];
    }
}

static void shuffle(volatile BYTE *dst, const volatile BYTE *src, unsigned prefix, unsigned pattern)
{
    BYTE result[16];
    copy_xmm(result, src, 16);
    unsigned width = prefix == 0x66 ? 4 : 2;
    unsigned start = prefix == 0xf3 ? 8 : 0;
    for (unsigned i = 0; i < 4; ++i) {
        copy_xmm(result + start + i * width, src + start + ((pattern >> (i * 2)) & 3) * width, width);
    }
    copy_xmm(dst, result, 16);
}

static void unpack(volatile BYTE *dst, const volatile BYTE *src, unsigned width, BOOL high)
{
    BYTE result[16];
    unsigned start = high ? 8 : 0;
    for (unsigned i = 0; i < 8; i += width) {
        copy_xmm(result + i * 2, dst + start + i, width);
        copy_xmm(result + i * 2 + width, src + start + i, width);
    }
    copy_xmm(dst, result, 16);
}

static void compare_equal(volatile BYTE *dst, const volatile BYTE *src, unsigned width)
{
    for (unsigned i = 0; i < 16; i += width) {
        BOOL equal = TRUE;
        for (unsigned j = 0; j < width; ++j) {
            equal = equal && dst[i + j] == src[i + j];
        }
        for (unsigned j = 0; j < width; ++j) {
            dst[i + j] = equal ? 0xff : 0;
        }
    }
}

static int compare_lanes(const volatile BYTE *lhs, const volatile BYTE *rhs, unsigned width, BOOL sign)
{
    for (unsigned i = width; i != 0; --i) {
        unsigned a = lhs[i - 1], b = rhs[i - 1];
        if (sign && i == width) {
            a ^= 0x80;
            b ^= 0x80;
        }
        if (a != b) {
            return a < b ? -1 : 1;
        }
    }
    return 0;
}

static void select_packed(volatile BYTE *dst, const volatile BYTE *src, unsigned width, BOOL sign, BOOL maximum)
{
    for (unsigned i = 0; i < 16; i += width) {
        int order = compare_lanes(dst + i, src + i, width, sign);
        if (maximum ? order < 0 : order > 0) {
            copy_xmm(dst + i, src + i, width);
        }
    }
}

static void compare_greater(volatile BYTE *dst, const volatile BYTE *src, unsigned width)
{
    for (unsigned i = 0; i < 16; i += width) {
        BYTE result = compare_lanes(dst + i, src + i, width, TRUE) > 0 ? 0xff : 0;
        for (unsigned j = 0; j < width; ++j) {
            dst[i + j] = result;
        }
    }
}

static void packed_unsigned_saturate(volatile BYTE *dst, const volatile BYTE *src, unsigned width, BOOL subtract)
{
    unsigned max = width == 1 ? 0xff : 0xffff;
    for (unsigned i = 0; i < 16; i += width) {
        unsigned a = dst[i], b = src[i];
        if (width == 2) {
            a |= (unsigned)dst[i + 1] << 8;
            b |= (unsigned)src[i + 1] << 8;
        }
        unsigned result = subtract ? (a < b ? 0 : a - b) : (a + b > max ? max : a + b);
        dst[i] = (BYTE)result;
        if (width == 2) {
            dst[i + 1] = (BYTE)(result >> 8);
        }
    }
}

static void packed_arithmetic(volatile BYTE *dst, const volatile BYTE *src, unsigned width, BOOL subtract)
{
    for (unsigned i = 0; i < 16; i += width) {
        unsigned carry = 0;
        for (unsigned j = 0; j < width; ++j) {
            unsigned rhs = src[i + j] + carry;
            unsigned value = dst[i + j];
            if (subtract) {
                carry = value < rhs;
                value -= rhs;
            } else {
                value += rhs;
                carry = value >> 8;
            }
            dst[i + j] = (BYTE)value;
        }
    }
}

static void pack_unsigned_bytes(volatile BYTE *dst, const volatile BYTE *src)
{
    BYTE result[16];
    for (unsigned i = 0; i < 16; ++i) {
        const volatile BYTE *input = i < 8 ? dst : src;
        unsigned index = (i & 7) * 2;
        short value = (short)(input[index] | (input[index + 1] << 8));
        result[i] = value < 0 ? 0 : value > 255 ? 255 : (BYTE)value;
    }
    copy_xmm(dst, result, 16);
}

static void packed_shift(volatile BYTE *value, unsigned width, unsigned amount, BOOL left, BOOL arithmetic)
{
    BYTE result[16] = {0};
    unsigned bits = width * 8;
    for (unsigned base = 0; base < 16; base += width) {
        unsigned fill = arithmetic ? value[base + width - 1] >> 7 : 0;
        for (unsigned bit = 0; bit < bits; ++bit) {
            int source = left ? (int)bit - (int)amount : (int)bit + (int)amount;
            unsigned selected = 0;
            if (source >= 0) {
                selected = (unsigned)source < bits ? (value[base + source / 8] >> (source & 7)) & 1 : fill;
            }
            result[base + bit / 8] |= selected << (bit & 7);
        }
    }
    copy_xmm(value, result, 16);
}

static void extend_elements(volatile BYTE *dst, const volatile BYTE *src, unsigned kind, BOOL sign)
{
    static const BYTE input_width[] = {1, 1, 1, 2, 2, 4};
    static const BYTE output_width[] = {2, 4, 8, 4, 8, 8};
    BYTE result[16];
    unsigned from = input_width[kind], to = output_width[kind];
    for (unsigned i = 0; i < 16 / to; ++i) {
        copy_xmm(result + i * to, src + i * from, from);
        BYTE fill = sign && (src[i * from + from - 1] & 0x80) ? 0xff : 0;
        for (unsigned j = from; j < to; ++j) {
            result[i * to + j] = fill;
        }
    }
    copy_xmm(dst, result, 16);
}

static void packed_test(CONTEXT *ctx, const volatile BYTE *dst, const volatile BYTE *src)
{
    BYTE and_bits = 0, and_not_bits = 0;
    for (unsigned i = 0; i < 16; ++i) {
        and_bits |= dst[i] & src[i];
        and_not_bits |= ~dst[i] & src[i];
    }
    /* PTEST clears OF, SF, AF and PF and sets ZF and CF. */
    ctx->EFlags &= ~0x8d5u;
    if (!and_bits) {
        ctx->EFlags |= 0x40;
    }
    if (!and_not_bits) {
        ctx->EFlags |= 1;
    }
}


static volatile LONG softfloat_busy;

static uint64_t load_bits(const volatile BYTE *operand, unsigned width)
{
    uint64_t bits = 0;
    while (width != 0) {
        bits = (bits << 8) | operand[--width];
    }
    return bits;
}

static void store_bits(volatile BYTE *operand, uint64_t bits, unsigned width)
{
    for (unsigned i = 0; i < width; ++i) {
        operand[i] = (BYTE)bits;
        bits >>= 8;
    }
}

static BOOL denormal_bits(uint64_t bits, BOOL single)
{
    uint64_t exponent = single ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    return (bits & exponent) == 0 && (bits & (exponent - 1)) != 0;
}

static BOOL nan_bits(uint64_t bits, BOOL single)
{
    uint64_t exponent = single ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    uint64_t mantissa = single ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    return (bits & exponent) == exponent && (bits & mantissa) != 0;
}

static uint64_t sign_bit(uint64_t bits, BOOL single)
{
    return bits & (single ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000));
}

static uint64_t flush_input(uint64_t bits, BOOL single, DWORD mxcsr)
{
    return (mxcsr & 0x0040) && denormal_bits(bits, single) ? sign_bit(bits, single) : bits;
}

static DWORD exception_bits(uint_fast8_t flags)
{
    return ((flags & softfloat_flag_inexact) ? 0x20 : 0)
         | ((flags & softfloat_flag_underflow) ? 0x10 : 0)
         | ((flags & softfloat_flag_overflow) ? 0x08 : 0)
         | ((flags & softfloat_flag_infinite) ? 0x04 : 0)
         | ((flags & softfloat_flag_invalid) ? 0x01 : 0);
}

static void set_compare_flags(CONTEXT *context, BOOL equal, BOOL less, BOOL unordered)
{
    context->EFlags &= ~0x8d5u;
    if (unordered) {
        context->EFlags |= 0x45;
    }
    else if (less) {
        context->EFlags |= 1;
    }
    else if (equal) {
        context->EFlags |= 0x40;
    }
}

static uint64_t float_arithmetic(unsigned opcode, BOOL single, uint64_t a, uint64_t b)
{
    if (single) {
        float32_t lhs = { (uint32_t)a }, rhs = { (uint32_t)b };
        switch (opcode) {
            case 0x58: return f32_add(lhs, rhs).v;
            case 0x59: return f32_mul(lhs, rhs).v;
            case 0x5c: return f32_sub(lhs, rhs).v;
            default: return f32_div(lhs, rhs).v;
        }
    }
    float64_t lhs = { a }, rhs = { b };
    switch (opcode) {
        case 0x58: return f64_add(lhs, rhs).v;
        case 0x59: return f64_mul(lhs, rhs).v;
        case 0x5c: return f64_sub(lhs, rhs).v;
        default: return f64_div(lhs, rhs).v;
    }
}

static void scalar_softfloat(CONTEXT *context, win95_xmm_state *state, unsigned opcode,
    unsigned reg_index, volatile BYTE *reg, const volatile BYTE *operand, unsigned prefix, BOOL single)
{
    static const BYTE rounding[] = {
        softfloat_round_near_even, softfloat_round_min, softfloat_round_max, softfloat_round_minMag
    };

    DWORD last_error = GetLastError();
    while (InterlockedExchange(&softfloat_busy, 1)) {
        Sleep(0);
    }
    softfloat_roundingMode = rounding[(state->mxcsr >> 13) & 3];
    softfloat_exceptionFlags = 0;
    DWORD flags = 0;
    unsigned width = single ? 4 : 8;
    uint64_t a = 0, b = 0;

    if (opcode == 0x5b && prefix == 0) {
        /* CVTDQ2PS is used by Brotli's high-quality cost model on Windows 95.
           Snapshot all lanes before writing an aliased destination. */
        LONG input[4];
        copy_xmm((BYTE *)input, operand, 16);
        for (unsigned lane = 0; lane < 4; ++lane) {
            store_bits(reg + lane * 4, i32_to_f32(input[lane]).v, 4);
        }
    } else if (opcode == 0x5b || (opcode == 0xe6 && prefix != 0xf3)) {
        /* Packed conversions need software XMM support on Windows 95.
           Read all source lanes before writing an aliased destination. */
        BOOL packed_single = opcode == 0x5b;
        unsigned size = packed_single ? 4 : 8;
        DWORD result[4] = {0};
        for (unsigned lane = 0; lane < 16 / size; ++lane) {
            uint64_t bits = flush_input(load_bits(operand + lane * size, size), packed_single, state->mxcsr);
            softfloat_exceptionFlags = 0;
            int_fast32_t value;
            if (packed_single) {
                float32_t input = { (uint32_t)bits };
                value = prefix == 0xf3 ? f32_to_i32_r_minMag(input, true) :
                    f32_to_i32(input, softfloat_roundingMode, true);
            } else {
                float64_t input = { bits };
                value = prefix == 0x66 ? f64_to_i32_r_minMag(input, true) :
                    f64_to_i32(input, softfloat_roundingMode, true);
            }
            /* SSE returns the integer indefinite value for NaN and overflow. */
            result[lane] = (softfloat_exceptionFlags & softfloat_flag_invalid) ? 0x80000000u : (DWORD)value;
            flags |= exception_bits(softfloat_exceptionFlags);
        }
        copy_xmm(reg, (const BYTE *)result, 16);
    } else if (opcode == 0x2a || opcode == 0xe6) {
        LONG first = (LONG)load_bits(operand, 4);
        if (opcode == 0xe6) {
            LONG second = (LONG)load_bits(operand + 4, 4);
            store_bits(reg + 8, i32_to_f64(second).v, 8);
        }
        store_bits(reg, single ? i32_to_f32(first).v : i32_to_f64(first).v, width);
    } else {
        b = flush_input(load_bits(operand, width), single, state->mxcsr);
        if (opcode == 0x2c || opcode == 0x2d) {
            int_fast32_t value;
            if (single) {
                float32_t input = { (uint32_t)b };
                value = opcode == 0x2c ? f32_to_i32_r_minMag(input, true) : f32_to_i32(input, softfloat_roundingMode, true);
            } else {
                float64_t input = { b };
                value = opcode == 0x2c ? f64_to_i32_r_minMag(input, true) : f64_to_i32(input, softfloat_roundingMode, true);
            }
            *register_address(context, reg_index) = (DWORD)value;
        } else {
            a = flush_input(load_bits(reg, width), single, state->mxcsr);
            if (opcode == 0x2e || opcode == 0x2f) {
                BOOL less, equal;
                BOOL unordered = nan_bits(a, single) || nan_bits(b, single);
                if (single) {
                    float32_t lhs = { (uint32_t)a }, rhs = { (uint32_t)b };
                    less = opcode == 0x2e ? f32_lt_quiet(lhs, rhs) : f32_lt(lhs, rhs);
                    equal = !unordered && f32_eq(lhs, rhs);
                } else {
                    float64_t lhs = { a }, rhs = { b };
                    less = opcode == 0x2e ? f64_lt_quiet(lhs, rhs) : f64_lt(lhs, rhs);
                    equal = !unordered && f64_eq(lhs, rhs);
                }
                set_compare_flags(context, equal, less, unordered);
            } else {
                uint64_t result = float_arithmetic(opcode, single, a, b);
                if ((state->mxcsr & 0x8000) && denormal_bits(result, single)) {
                    result = sign_bit(result, single);
                    flags |= 0x30;
                }
                store_bits(reg, result, width);
            }
        }
        if (!(softfloat_exceptionFlags & softfloat_flag_infinite) &&
            !nan_bits(a, single) && !nan_bits(b, single) && (denormal_bits(a, single) || denormal_bits(b, single))) {
            flags |= 0x02;
        }
    }

    state->mxcsr |= flags | exception_bits(softfloat_exceptionFlags);
    InterlockedExchange(&softfloat_busy, 0);
    SetLastError(last_error);
}


static void compare_mask(win95_xmm_state *state, volatile BYTE *reg, const volatile BYTE *operand,
    BOOL single, unsigned condition)
{
    DWORD last_error = GetLastError();
    while (InterlockedExchange(&softfloat_busy, 1)) {
        Sleep(0);
    }
    softfloat_exceptionFlags = 0;

    unsigned width = single ? 4 : 8;
    uint64_t a = flush_input(load_bits(reg, width), single, state->mxcsr);
    uint64_t b = flush_input(load_bits(operand, width), single, state->mxcsr);
    BOOL unordered = nan_bits(a, single) || nan_bits(b, single);
    BOOL signalling = condition == 1 || condition == 2 || condition == 5 || condition == 6;
    BOOL less, equal;
    if (single) {
        float32_t lhs = { (uint32_t)a }, rhs = { (uint32_t)b };
        less = signalling ? f32_lt(lhs, rhs) : f32_lt_quiet(lhs, rhs);
        equal = !unordered && f32_eq(lhs, rhs);
    } else {
        float64_t lhs = { a }, rhs = { b };
        less = signalling ? f64_lt(lhs, rhs) : f64_lt_quiet(lhs, rhs);
        equal = !unordered && f64_eq(lhs, rhs);
    }

    BOOL result;
    switch (condition) {
        case 0: result = equal; break;
        case 1: result = less; break;
        case 2: result = less || equal; break;
        case 3: result = unordered; break;
        case 4: result = !equal; break;
        case 5: result = !less; break;
        case 6: result = !less && !equal; break;
        default: result = !unordered; break;
    }
    store_bits(reg, result ? UINT64_MAX : 0, width);
    state->mxcsr |= exception_bits(softfloat_exceptionFlags);
    if (!unordered && (denormal_bits(a, single) || denormal_bits(b, single))) {
        state->mxcsr |= 0x02;
    }
    InterlockedExchange(&softfloat_busy, 0);
    SetLastError(last_error);
}


static void select_float(win95_xmm_state *state, volatile BYTE *reg,
    const volatile BYTE *operand, BOOL single, BOOL minimum)
{
    unsigned width = single ? 4 : 8;
    uint64_t a = flush_input(load_bits(reg, width), single, state->mxcsr);
    uint64_t b = flush_input(load_bits(operand, width), single, state->mxcsr);
    uint64_t sign = single ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);

    if (nan_bits(a, single) || nan_bits(b, single)) {
        state->mxcsr |= 0x01;
        store_bits(reg, b, width);
        return;
    }
    if (denormal_bits(a, single) || denormal_bits(b, single)) {
        state->mxcsr |= 0x02;
    }

    if (a == b || ((a | b) & (sign - 1)) == 0) {
        store_bits(reg, b, width);
        return;
    }

    // The sign-magnitude encoding orders same-sign values by magnitude.
    BOOL a_less = ((a ^ b) & sign) ? (a & sign) != 0 : (a & sign) ? a > b : a < b;
    store_bits(reg, a_less == minimum ? a : b, width);
}


static void round_or_sqrt(win95_xmm_state *state, volatile BYTE *reg,
    const volatile BYTE *operand, BOOL single, BOOL square_root, unsigned control)
{
    static const BYTE rounding[] = {
        softfloat_round_near_even, softfloat_round_min, softfloat_round_max, softfloat_round_minMag
    };
    DWORD last_error = GetLastError();
    while (InterlockedExchange(&softfloat_busy, 1)) {
        Sleep(0);
    }
    unsigned mode = square_root || (control & 4) ? (state->mxcsr >> 13) & 3 : control & 3;
    softfloat_roundingMode = rounding[mode];
    softfloat_exceptionFlags = 0;
    BOOL report_inexact = (control & 8) == 0;
    unsigned width = single ? 4 : 8;
    uint64_t bits = flush_input(load_bits(operand, width), single, state->mxcsr);
    uint64_t result;
    if (single) {
        float32_t input = { (uint32_t)bits };
        result = square_root ? f32_sqrt(input).v : f32_roundToInt(input, softfloat_roundingMode, report_inexact).v;
    } else {
        float64_t input = { bits };
        result = square_root ? f64_sqrt(input).v : f64_roundToInt(input, softfloat_roundingMode, report_inexact).v;
    }
    store_bits(reg, result, width);
    state->mxcsr |= exception_bits(softfloat_exceptionFlags);
    if (square_root && denormal_bits(bits, single) && !sign_bit(bits, single)) {
        state->mxcsr |= 0x02;
    }
    InterlockedExchange(&softfloat_busy, 0);
    SetLastError(last_error);
}


static void convert_float_width(win95_xmm_state *state, volatile BYTE *reg,
    const volatile BYTE *operand, unsigned prefix)
{
    static const BYTE rounding[] = {
        softfloat_round_near_even, softfloat_round_min, softfloat_round_max, softfloat_round_minMag
    };
    DWORD last_error = GetLastError();
    while (InterlockedExchange(&softfloat_busy, 1)) {
        Sleep(0);
    }
    softfloat_roundingMode = rounding[(state->mxcsr >> 13) & 3];
    softfloat_exceptionFlags = 0;
    DWORD flags = 0;

    BOOL narrow = prefix == 0xf2 || prefix == 0x66;
    unsigned from = narrow ? 8 : 4, to = narrow ? 4 : 8;
    unsigned count = prefix == 0 || prefix == 0x66 ? 2 : 1;
    BYTE input[16];
    copy_xmm(input, operand, from * count);
    for (unsigned i = 0; i < count; ++i) {
        uint64_t bits = flush_input(load_bits(input + i * from, from), !narrow, state->mxcsr);
        uint64_t result = narrow ? f64_to_f32((float64_t){ bits }).v : f32_to_f64((float32_t){ (uint32_t)bits }).v;
        if (denormal_bits(bits, !narrow)) {
            flags |= 0x02;
        }
        if ((state->mxcsr & 0x8000) && denormal_bits(result, narrow)) {
            result = sign_bit(result, narrow);
            flags |= 0x30;
        }
        store_bits(reg + i * to, result, to);
    }
    if (prefix == 0x66) {
        store_bits(reg + 8, 0, 8);
    }
    state->mxcsr |= flags | exception_bits(softfloat_exceptionFlags);

    InterlockedExchange(&softfloat_busy, 0);
    SetLastError(last_error);
}
static BOOL emulate_xmm(CONTEXT *context, win95_xmm_state *state)
{
    const BYTE *op = (const BYTE *)context->Eip;
    unsigned prefix = *op;
    if (prefix == 0x66 || prefix == 0xf2 || prefix == 0xf3) {
        ++op;
    }
    else {
        prefix = 0;
    }

    if (*op++ != 0x0f) {
        return FALSE;
    }
    unsigned opcode = *op++;
    if (opcode == 0x38 || opcode == 0x3a) {
        opcode = (opcode << 8) | *op++;
    }
    if (opcode == 0xae && prefix == 0) {
        unsigned form = *op++;
        unsigned control = (form >> 3) & 7;
        if ((form >> 6) == 3 || (control != 2 && control != 3)) {
            return FALSE;
        }
        volatile BYTE *memory = operand_address(context, form, &op);
        if (control == 3) {
            for (unsigned i = 0; i < 4; ++i) {
                memory[i] = (BYTE)(state->mxcsr >> (8 * i));
            }
        } else {
            DWORD value = 0;
            for (unsigned i = 0; i < 4; ++i) {
                value |= (DWORD)memory[i] << (8 * i);
            }
            /* The port implements masked SIMD exceptions, as used by Native AOT. */
            if ((value & ~0xffffu) != 0 || (value & 0x1f80u) != 0x1f80u) {
                return FALSE;
            }
            state->mxcsr = value;
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }
    unsigned width = 0;
    BOOL store = FALSE, zero_upper = FALSE;
    unsigned logic = 0;
    BOOL gpr_operand = FALSE;
    BOOL special = FALSE;
    BOOL floating = FALSE;

    switch (opcode) {
        case 0x10:
        case 0x11:
            width = prefix == 0xf2 ? 8 : prefix == 0xf3 ? 4 : 16;
            store = opcode == 0x11;
            zero_upper = !store && width != 16;
            break;
        case 0x12:
        case 0x13:
            if (prefix != 0 && prefix != 0x66 && !(opcode == 0x12 && (prefix == 0xf2 || prefix == 0xf3))) {
                return FALSE;
            }
            width = prefix == 0xf3 ? 16 : 8;
            special = prefix == 0xf3;
            store = opcode == 0x13;
            break;
        case 0x16: // MOVLHPS, MOVHPS/MOVHPD, or MOVSHDUP.
        case 0x17:
            if (prefix != 0 && prefix != 0x66 && !(opcode == 0x16 && prefix == 0xf3)) {
                return FALSE;
            }
            width = prefix == 0xf3 ? 16 : 8;
            special = prefix == 0xf3;
            store = opcode == 0x17;
            break;
        case 0x14:
        case 0x15:
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            special = TRUE;
            break;
        case 0xc4:
        case 0x3a22: // PINSRD, used to construct CRC folding vectors on Windows 95.
        case 0x3a15: // SSE4.1 PEXTRW with a register or memory destination.
        case 0x3a16: // PEXTRD, used to retrieve CRC folding results.
        case 0x3a17: // EXTRACTPS with a 32-bit register or memory destination.
            if (prefix != 0x66) {
                return FALSE;
            }
            gpr_operand = TRUE;
            special = TRUE;
            break;
        case 0x28:
        case 0x29:
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            width = 16;
            store = opcode == 0x29;
            break;
        case 0x6f:
        case 0x7f:
            if (prefix != 0x66 && prefix != 0xf3) {
                return FALSE;
            }
            width = 16;
            store = opcode == 0x7f;
            break;
        case 0xc6: // SHUFPS and SHUFPD, used by vector and matrix operations.
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            special = TRUE;
            break;
        case 0x70:
            if (prefix != 0x66 && prefix != 0xf2 && prefix != 0xf3) {
                return FALSE;
            }
            special = TRUE;
            break;
        case 0x60:
        case 0x61:
        case 0x62:
        case 0x68:
        case 0x69:
        case 0x6a:
        case 0x6c:
        case 0x6d:
        case 0x71:
        case 0x72:
        case 0x73:
        case 0xd3: // PSRLQ with a vector count.
        case 0xf3: // PSLLQ with a vector count.
        case 0x74:
        case 0x75:
        case 0x76:
        case 0xd7:
        case 0xc5:
        case 0x67:
        case 0xf8:
        case 0xf9:
        case 0xfa:
        case 0xfb:
        case 0xfc:
        case 0xfd:
        case 0xfe:
        case 0xd4:
        case 0xd5: // PMULLW.
        case 0xe4: // PMULHUW.
        case 0xf6: // PSADBW, used for Adler-32 byte sums.
        case 0x3802: // PHADDD, used by integer vector dot products on Win95.
        case 0x3804: // PMADDUBSW, used for Adler-32 weighted sums.
        case 0xf5: // PMADDWD.
        case 0xf4: // PMULUDQ, used by the long xxHash3/128 paths.
        case 0x3840: // PMULLD.
        case 0x3a0f: // PALIGNR, used by SearchValues<string> vector searches.
        case 0x3a21: // INSERTPS, including Vector3's unused-lane clearing.
        case 0x3a40: // DPPS.
        case 0x3a41: // DPPD.
        case 0x3a44: // PCLMULQDQ, used by vectorized CRC folding.
        case 0x3800:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0xd8:
        case 0xd9:
        case 0xda:
        case 0xdc:
        case 0xdd:
        case 0xde:
        case 0xea:
        case 0xee:
        case 0x3829:
        case 0x3837:
        case 0x3838:
        case 0x3839:
        case 0x383a:
        case 0x383b:
        case 0x383c:
        case 0x383d:
        case 0x383e:
        case 0x383f:
        case 0x3810:
        case 0x3814:
        case 0x3815:
        case 0x3817:
        case 0x3820:
        case 0x3821:
        case 0x3822:
        case 0x3823:
        case 0x3824:
        case 0x3825:
        case 0x3830:
        case 0x3831:
        case 0x3832:
        case 0x3833:
        case 0x3834:
        case 0x3835:
            if (prefix != 0x66) {
                return FALSE;
            }
            special = TRUE;
            break;
        case 0x3a08: // Packed rounding also needs software XMM support on Win95.
        case 0x3a09:
        case 0x3a0a:
        case 0x3a0b:
            if (prefix != 0x66) {
                return FALSE;
            }
            break;
        case 0x50:
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            special = TRUE;
            break;
        case 0x51:
        case 0x5a:
        case 0x5d:
        case 0x5f:
        case 0xc2:
            break;
        case 0x5b: // CVTDQ2PS, CVTPS2DQ and CVTTPS2DQ.
            if (prefix != 0 && prefix != 0x66 && prefix != 0xf3) {
                return FALSE;
            }
            floating = TRUE;
            break;
        case 0xe6:
            if (prefix != 0xf3 && prefix != 0xf2 && prefix != 0x66) {
                return FALSE;
            }
            floating = TRUE;
            break;
        case 0x2a:
        case 0x2c:
        case 0x2d:
        case 0x58:
        case 0x59:
        case 0x5c:
        case 0x5e:
            if ((opcode == 0x2a || opcode == 0x2c || opcode == 0x2d) && prefix != 0xf2 && prefix != 0xf3) {
                return FALSE;
            }
            gpr_operand = opcode == 0x2a;
            floating = TRUE;
            break;
        case 0x2e:
        case 0x2f:
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            floating = TRUE;
            break;
        case 0x6e:
            if (prefix != 0x66) {
                return FALSE;
            }
            width = 4;
            gpr_operand = TRUE;
            zero_upper = TRUE;
            break;
        case 0x7e:
            if (prefix != 0x66 && prefix != 0xf3) {
                return FALSE;
            }
            store = prefix == 0x66;
            width = store ? 4 : 8;
            gpr_operand = store;
            zero_upper = !store;
            break;
        case 0xd6:
            if (prefix != 0x66) {
                return FALSE;
            }
            store = TRUE;
            width = 8;
            break;
        case 0x57:
        case 0x54:
        case 0x55:
        case 0x56:
            if (prefix != 0 && prefix != 0x66) {
                return FALSE;
            }
            width = 16;
            logic = (opcode & 3) + 1;
            break;
        case 0xdb:
        case 0xdf:
        case 0xeb:
        case 0xef:
            if (prefix != 0x66) {
                return FALSE;
            }
            width = 16;
            logic = opcode == 0xdb ? 1 : opcode == 0xdf ? 2 : opcode == 0xeb ? 3 : 4;
            break;
        default:
            return FALSE;
    }

    unsigned form = *op++;
    BOOL registers = (form >> 6) == 3;
    if (registers && (opcode == 0x13 || opcode == 0x17 ||
        (prefix == 0x66 && (opcode == 0x12 || opcode == 0x16)))) {
        return FALSE;
    }

    volatile BYTE *reg = state->xmm[(form >> 3) & 7];
    volatile BYTE *operand = registers
        ? (gpr_operand ? (volatile BYTE *)register_address(context, form & 7) : state->xmm[form & 7])
        : operand_address(context, form, &op);
    if (!registers && (opcode == 0x28 || opcode == 0x29 || opcode == 0xc6 ||
        opcode == 0x5b || opcode == 0x3802 || opcode == 0x3a08 || opcode == 0x3a09 || opcode == 0x3a0f || opcode == 0x3a40 || opcode == 0x3a41 ||
        (prefix == 0xf3 && (opcode == 0x12 || opcode == 0x16)) ||
        (prefix == 0x66 && (opcode == 0x6f || opcode == 0x7f))) && ((ULONG_PTR)operand & 15)) {
        return FALSE;
    }

    if (opcode >= 0x3a08 && opcode <= 0x3a0b) {
        unsigned control = *op++;
        BOOL single = (opcode & 1) == 0;
        unsigned size = single ? 4 : 8;
        unsigned lanes = opcode < 0x3a0a ? 16 / size : 1;
        for (unsigned i = 0; i < lanes; ++i) {
            round_or_sqrt(state, reg + i * size, operand + i * size, single, FALSE, control);
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }
    if (opcode == 0x51) {
        BOOL single = prefix == 0 || prefix == 0xf3;
        unsigned width = single ? 4 : 8;
        unsigned lanes = prefix == 0xf2 || prefix == 0xf3 ? 1 : 16 / width;
        for (unsigned i = 0; i < lanes; ++i) {
            round_or_sqrt(state, reg + i * width, operand + i * width, single, TRUE, 0);
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }
    if ((opcode == 0x58 || opcode == 0x59 || opcode == 0x5c || opcode == 0x5e) &&
        (prefix == 0 || prefix == 0x66)) {
        unsigned width = prefix == 0 ? 4 : 8;
        for (unsigned i = 0; i < 16; i += width) {
            scalar_softfloat(context, state, opcode, 0, reg + i, operand + i, prefix, prefix == 0);
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }
    if (opcode == 0x5a) {
        convert_float_width(state, reg, operand, prefix);
        context->Eip = (DWORD)op;
        return TRUE;
    }
    if (opcode == 0x5d || opcode == 0x5f) {
        BOOL single = prefix == 0 || prefix == 0xf3;
        unsigned width = single ? 4 : 8;
        unsigned lanes = prefix == 0xf2 || prefix == 0xf3 ? 1 : 16 / width;
        for (unsigned i = 0; i < lanes; ++i) {
            select_float(state, reg + i * width, operand + i * width, single, opcode == 0x5d);
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }
    if (opcode == 0xc2) {
        unsigned predicate = *op++ & 7;
        if (prefix == 0xf2 || prefix == 0xf3) {
            compare_mask(state, reg, operand, prefix == 0xf3, predicate);
        } else {
            unsigned stride = prefix == 0x66 ? 8 : 4;
            for (unsigned i = 0; i < 16; i += stride) {
                compare_mask(state, reg + i, operand + i, stride == 4, predicate);
            }
        }
        context->Eip = (DWORD)op;
        return TRUE;
    }

    if (floating) {
        scalar_softfloat(context, state, opcode, (form >> 3) & 7, reg, operand, prefix,
            (opcode == 0x2e || opcode == 0x2f) ? prefix == 0 : prefix == 0xf3 && opcode != 0xe6);
    } else if (special) {
        if (opcode == 0x3a44) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            unsigned control = *op++;
            uint64_t left = load_bits(reg + ((control & 1) ? 8 : 0), 8);
            uint64_t right = load_bits(operand + ((control & 0x10) ? 8 : 0), 8);
            uint64_t low = 0, high = 0;
            for (unsigned bit = 0; bit < 64; ++bit) {
                if ((right >> bit) & 1) {
                    low ^= left << bit;
                    if (bit != 0) {
                        high ^= left >> (64 - bit);
                    }
                }
            }
            store_bits(reg, low, 8);
            store_bits(reg + 8, high, 8);
        } else if (opcode == 0x3a40 || opcode == 0x3a41) {
            BYTE products[16] = {0}, source[16];
            unsigned control = *op++;
            BOOL single = opcode == 0x3a40;
            unsigned size = single ? 4 : 8;
            unsigned scalar_prefix = single ? 0xf3 : 0xf2;
            copy_xmm(source, operand, 16);
            for (unsigned i = 0; i < 16 / size; ++i) {
                if (control & (0x10u << i)) {
                    copy_xmm(products + i * size, reg + i * size, size);
                    scalar_softfloat(context, state, 0x59, 0, products + i * size, source + i * size, scalar_prefix, single);
                }
            }
            /* Round each multiply and each pairwise addition separately. */
            if (single) {
                scalar_softfloat(context, state, 0x58, 0, products, products + 4, scalar_prefix, TRUE);
                scalar_softfloat(context, state, 0x58, 0, products + 8, products + 12, scalar_prefix, TRUE);
            }
            scalar_softfloat(context, state, 0x58, 0, products, products + 8, scalar_prefix, single);
            for (unsigned i = 0; i < 16 / size; ++i) {
                store_bits(reg + i * size, (control & (1u << i)) ? load_bits(products, size) : 0, size);
            }
        } else if (opcode == 0x3802) {
            BYTE result[16];
            for (unsigned i = 0; i < 4; ++i) {
                const volatile BYTE *source = i < 2 ? reg : operand;
                unsigned offset = (i & 1) * 8;
                uint32_t value = (uint32_t)load_bits(source + offset, 4) +
                    (uint32_t)load_bits(source + offset + 4, 4);
                store_bits(result + i * 4, value, 4);
            }
            copy_xmm(reg, result, 16);
        } else if (opcode == 0x3a0f) {
            BYTE result[16];
            unsigned shift = *op++;
            for (unsigned i = 0; i < 16; ++i) {
                unsigned index = shift + i;
                result[i] = index < 16 ? operand[index] : index < 32 ? reg[index - 16] : 0;
            }
            copy_xmm(reg, result, 16);
        } else if (opcode == 0x3a21) {
            BYTE result[16];
            unsigned control = *op++;
            copy_xmm(result, reg, 16);
            unsigned source = registers ? (control >> 6) * 4 : 0;
            copy_xmm(result + ((control >> 4) & 3) * 4, operand + source, 4);
            for (unsigned i = 0; i < 4; ++i) {
                if (control & (1u << i)) {
                    store_bits(result + i * 4, 0, 4);
                }
            }
            copy_xmm(reg, result, 16);
        } else if (prefix == 0xf3 && (opcode == 0x12 || opcode == 0x16)) {
            BYTE result[16];
            for (unsigned i = 0; i < 4; ++i) {
                unsigned index = (i & 2) + (opcode == 0x16);
                copy_xmm(result + i * 4, operand + index * 4, 4);
            }
            copy_xmm(reg, result, 16);
        } else if (opcode == 0xc6) {
            BYTE result[16];
            unsigned control = *op++;
            unsigned size = prefix == 0x66 ? 8 : 4;
            for (unsigned i = 0; i < 16 / size; ++i) {
                const volatile BYTE *source = i < 8 / size ? reg : operand;
                unsigned index = (control >> (i * (size == 4 ? 2 : 1))) & (16 / size - 1);
                copy_xmm(result + i * size, source + index * size, size);
            }
            copy_xmm(reg, result, 16);
        } else if (opcode == 0x70) {
            shuffle(reg, operand, prefix, *op++);
        } else if (opcode >= 0x71 && opcode <= 0x73) {
            unsigned operation = (form >> 3) & 7;
            if (!registers) {
                return FALSE;
            }
            unsigned shift = *op++;
            if (opcode == 0x73 && (operation == 3 || operation == 7)) {
                packed_shift(operand, 16, shift * 8, operation == 7, FALSE);
            } else if (operation == 2 || operation == 6 || (operation == 4 && opcode != 0x73)) {
                packed_shift(operand, 2u << (opcode - 0x71), shift, operation == 6, operation == 4);
            } else {
                return FALSE;
            }
        } else if (opcode == 0xd3 || opcode == 0xf3) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            uint64_t count = load_bits(operand, 8);
            packed_shift(reg, 8, count < 64 ? (unsigned)count : 64, opcode == 0xf3, FALSE);
        } else if (opcode == 0xf4) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            for (unsigned i = 0; i < 16; i += 8) {
                uint64_t product = (uint64_t)(uint32_t)load_bits(reg + i, 4) * (uint32_t)load_bits(operand + i, 4);
                store_bits(reg + i, product, 8);
            }
        } else if (opcode == 0x3804 || opcode == 0xf5) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            unsigned size = opcode == 0x3804 ? 1 : 2;
            for (unsigned i = 0; i < 16; i += size * 2) {
                int64_t sum;
                if (size == 1) {
                    sum = (int)reg[i] * (int8_t)operand[i] + (int)reg[i + 1] * (int8_t)operand[i + 1];
                    sum = sum < -32768 ? -32768 : sum > 32767 ? 32767 : sum;
                } else {
                    sum = (int64_t)(int16_t)load_bits(reg + i, 2) * (int16_t)load_bits(operand + i, 2) +
                        (int64_t)(int16_t)load_bits(reg + i + 2, 2) * (int16_t)load_bits(operand + i + 2, 2);
                }
                store_bits(reg + i, (uint64_t)sum, size * 2);
            }
        } else if (opcode == 0xf6) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            for (unsigned half = 0; half < 16; half += 8) {
                unsigned sum = 0;
                for (unsigned i = 0; i < 8; ++i) {
                    int difference = (int)reg[half + i] - (int)operand[half + i];
                    sum += difference < 0 ? -difference : difference;
                }
                store_bits(reg + half, sum, 8);
            }
        } else if (opcode == 0xd5 || opcode == 0xe4) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            /* The Base64 encoder uses low and unsigned-high 16-bit products. */
            for (unsigned i = 0; i < 16; i += 2) {
                uint32_t product = (uint32_t)load_bits(reg + i, 2) * (uint32_t)load_bits(operand + i, 2);
                store_bits(reg + i, opcode == 0xe4 ? product >> 16 : product, 2);
            }
        } else if (opcode == 0x3840) {
            if (!registers && ((ULONG_PTR)operand & 15)) {
                return FALSE;
            }
            for (unsigned i = 0; i < 16; i += 4) {
                uint32_t product = (uint32_t)load_bits(reg + i, 4) * (uint32_t)load_bits(operand + i, 4);
                store_bits(reg + i, product, 4);
            }
        } else if (opcode == 0x3810 || opcode == 0x3814 || opcode == 0x3815) {
            unsigned element_size = opcode == 0x3810 ? 1 : opcode == 0x3814 ? 4 : 8;
            for (unsigned i = 0; i < 16; i += element_size) {
                if (state->xmm[0][i + element_size - 1] & 0x80) {
                    copy_xmm(reg + i, operand + i, element_size);
                }
            }
        } else if (opcode == 0x3817) {
            packed_test(context, reg, operand);
        } else if (opcode == 0xda || opcode == 0xde || opcode == 0xea || opcode == 0xee) {
            BOOL sign = (opcode & 0x20) != 0;
            select_packed(reg, operand, sign ? 2 : 1, sign, (opcode & 4) != 0);
        } else if (opcode >= 0x3838 && opcode <= 0x383f) {
            static const BYTE widths[] = {1, 4, 2, 4};
            select_packed(reg, operand, widths[opcode & 3], (opcode & 2) == 0, (opcode & 4) != 0);
        } else if ((opcode >= 0x64 && opcode <= 0x66) || opcode == 0x3837) {
            compare_greater(reg, operand, opcode == 0x3837 ? 8 : 1u << (opcode - 0x64));
        } else if (opcode == 0x3829) {
            compare_equal(reg, operand, 8);
        } else if (opcode == 0xd8 || opcode == 0xd9 || opcode == 0xdc || opcode == 0xdd) {
            packed_unsigned_saturate(reg, operand, (opcode & 1) + 1, (opcode & 4) == 0);
        } else if (opcode >= 0x3820 && opcode <= 0x3835) {
            extend_elements(reg, operand, opcode & 0xf, opcode < 0x3830);
        } else if (opcode == 0x3800) {
            BYTE result[16];
            for (unsigned i = 0; i < 16; ++i) {
                BYTE select = operand[i];
                result[i] = (select & 0x80) ? 0 : reg[select & 15];
            }
            copy_xmm(reg, result, 16);
        } else if (opcode == 0x14 || opcode == 0x15) {
            unpack(reg, operand, prefix == 0x66 ? 8 : 4, opcode == 0x15);
        } else if (opcode == 0xc4) {
            unsigned index = (*op++ & 7) * 2;
            copy_xmm(reg + index, operand, 2);
        } else if (opcode == 0x3a22) {
            unsigned index = (*op++ & 3) * 4;
            copy_xmm(reg + index, operand, 4);
        } else if (opcode == 0x3a15) {
            unsigned index = (*op++ & 7) * 2;
            store_bits(operand, load_bits(reg + index, 2), registers ? 4 : 2);
        } else if (opcode == 0x3a16 || opcode == 0x3a17) {
            unsigned index = (*op++ & 3) * 4;
            store_bits(operand, load_bits(reg + index, 4), 4);
        } else if (opcode == 0xc5) {
            if (!registers) {
                return FALSE;
            }
            unsigned index = (*op++ & 7) * 2;
            DWORD word = operand[index] | ((DWORD)operand[index + 1] << 8);
            *register_address(context, (form >> 3) & 7) = word;
        } else if (opcode == 0x50 || opcode == 0xd7) {
            if (!registers) {
                return FALSE;
            }
            /* MOVMSKPS, MOVMSKPD, and PMOVMSKB extract the top bit of each lane. */
            unsigned lane_width = opcode == 0xd7 ? 1 : prefix == 0x66 ? 8 : 4;
            DWORD mask = 0;
            for (unsigned i = 0; i < 16 / lane_width; ++i) {
                mask |= (DWORD)(operand[(i + 1) * lane_width - 1] >> 7) << i;
            }
            *register_address(context, (form >> 3) & 7) = mask;
        } else if (opcode == 0x67) {
            pack_unsigned_bytes(reg, operand);
        } else if ((opcode >= 0xf8 && opcode <= 0xfe) || opcode == 0xd4) {
            packed_arithmetic(reg, operand, opcode == 0xd4 ? 8 : 1u << (opcode & 3),
                opcode >= 0xf8 && opcode <= 0xfb);
        } else if (opcode >= 0x74) {
            compare_equal(reg, operand, 1u << (opcode - 0x74));
        } else {
            unsigned element_size = opcode == 0x6c || opcode == 0x6d ? 8 : 1u << (opcode & 3);
            unpack(reg, operand, element_size, (opcode & 8) != 0 && opcode != 0x6c);
        }
    } else if (logic != 0) {
        for (unsigned i = 0; i < 16; ++i) {
            BYTE a = reg[i], b = operand[i];
            reg[i] = logic == 1 ? a & b : logic == 2 ? ~a & b : logic == 3 ? a | b : a ^ b;
        }
    } else if (opcode == 0x16) {
        copy_xmm(reg + 8, operand, 8);
    } else if (opcode == 0x17) {
        copy_xmm(operand, reg + 8, 8);
    } else if (opcode == 0x12 && prefix == 0 && registers) {
        copy_xmm(reg, operand + 8, 8);
    } else if (store) {
        copy_xmm(operand, reg, width);
        if (opcode == 0xd6 && registers) {
            for (unsigned i = width; i < 16; ++i) {
                operand[i] = 0;
            }
        }
    } else {
        copy_xmm(reg, operand, width);
        if (opcode == 0x12 && prefix == 0xf2) {
            copy_xmm(reg + 8, reg, 8);
        }
        if (zero_upper && (!registers || opcode == 0x6e || opcode == 0x7e)) {
            for (unsigned i = width; i < 16; ++i) {
                reg[i] = 0;
            }
        }
    }

    context->Eip = (DWORD)op;
    return TRUE;
}


EXCEPTION_DISPOSITION __cdecl Win95ExceptionHandler(EXCEPTION_RECORD *record, void *frame, CONTEXT *context, void *dispatch)
{
    if (record->ExceptionFlags != 0 || record->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) {
        return ExceptionContinueSearch;
    }

    DWORD error = GetLastError();
    win95_xmm_state *state = TlsGetValue(win95_xmm_tls);
    SetLastError(error);
    if (state != NULL && emulate_xmm(context, state)) {
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;
}

BOOL __cdecl Win95Initialize(void)
{
    if ((GetVersion() & 0x8000ffffu) != 0x80000004u) {
        return FALSE;
    }
    win95_xmm_tls = TlsAlloc();
    if (win95_xmm_tls == TLS_OUT_OF_INDEXES || !TlsSetValue(win95_xmm_tls, &main_xmm)) {
        ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
    }
    return TRUE;
}

typedef struct {
    LPTHREAD_START_ROUTINE start;
    void *argument;
} win95_thread;

DWORD __cdecl Win95CallThread(LPTHREAD_START_ROUTINE start, void *argument);

static DWORD WINAPI Win95ThreadStart(void *argument)
{
    win95_thread *start = argument;
    LPTHREAD_START_ROUTINE callback = start->start;
    void *context = start->argument;
    HeapFree(GetProcessHeap(), 0, start);
    win95_xmm_state state;
    for (unsigned reg = 0; reg < 8; ++reg) {
        for (unsigned byte = 0; byte < 16; ++byte) {
            state.xmm[reg][byte] = 0;
        }
    }
    state.mxcsr = 0x1f80;
    if (!TlsSetValue(win95_xmm_tls, &state)) {
        return 1;
    }
    DWORD exit_code = Win95CallThread(callback, context);
    TlsSetValue(win95_xmm_tls, NULL);
    return exit_code;
}

HANDLE Win95CreateThread(Win95CreateThreadFn native, SECURITY_ATTRIBUTES *security, SIZE_T size,
    LPTHREAD_START_ROUTINE start, void *argument, DWORD flags, DWORD *id)
{
    if (win95_xmm_tls == TLS_OUT_OF_INDEXES) {
        return native(security, size, start, argument, flags, id);
    }

    HANDLE heap = GetProcessHeap();
    win95_thread *context = HeapAlloc(heap, 0, sizeof(*context));
    if (context == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    context->start = start;
    context->argument = argument;
    HANDLE thread = native(security, size, Win95ThreadStart, context, flags, id);
    if (thread == NULL) {
        DWORD error = GetLastError();
        HeapFree(heap, 0, context);
        SetLastError(error);
    }
    return thread;
}
