/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static inline bool fd_ft_jcc_opcode_info(uint8_t cc, int *cond, int *id)
{
    static const int cond_by_cc[16] = {
        12, 13, 2, 1,
        4, 5, 3, 0,
        10, 11, 14, 15,
        8, 7, 9, 6,
    };
    static const int id_by_cc[16] = {
        dt_X86_INS_JO, dt_X86_INS_JNO, dt_X86_INS_JB, dt_X86_INS_JAE,
        dt_X86_INS_JE, dt_X86_INS_JNE, dt_X86_INS_JBE, dt_X86_INS_JA,
        dt_X86_INS_JS, dt_X86_INS_JNS, dt_X86_INS_JP, dt_X86_INS_JNP,
        dt_X86_INS_JL, dt_X86_INS_JGE, dt_X86_INS_JLE, dt_X86_INS_JG,
    };

    if (cc >= 16) {
        return false;
    }
    *cond = cond_by_cc[cc];
    *id = id_by_cc[cc];
    return true;
}

static inline FastDecoderFTMatch fd_ft_try_control(FDState *s,
                                                   uint8_t opcode0,
                                                   uint8_t opcode1,
                                                   bool two_byte,
                                                   uint64_t address,
                                                   FastDecodedFT *decoded)
{
    if (!two_byte && ((opcode0 >= 0xe4 && opcode0 <= 0xe7) ||
                      (opcode0 >= 0xec && opcode0 <= 0xef))) {
        int id = (opcode0 == 0xe4 || opcode0 == 0xe5 ||
                  opcode0 == 0xec || opcode0 == 0xed) ?
                 dt_X86_INS_IN : dt_X86_INS_OUT;

        fd_ft_init_fields(&decoded->fields, FT_IO, s, address,
                          opcode0, 0, id);
        if (opcode0 >= 0xe4 && opcode0 <= 0xe7) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = s->code[s->pos++];
        }
        return fd_ft_finish_match(decoded, s, FT_IO, false);
    }

    if (!two_byte && !s->mode && opcode0 == 0xce) {
        fd_ft_init_fields(&decoded->fields, FT_HELPER_INTO, s, address,
                          opcode0, 0, dt_X86_INS_INTO);
        return fd_ft_finish_match(decoded, s, FT_HELPER_INTO, true);
    }

    if (!two_byte && (opcode0 == 0xcc || opcode0 == 0xcd)) {
        FastTemplateKind kind = opcode0 == 0xcc ? FT_HELPER_INT3 :
                                                  FT_HELPER_INT;
        int id = opcode0 == 0xcc ? dt_X86_INS_INT3 : dt_X86_INS_INT;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        if (opcode0 == 0xcd) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = s->code[s->pos++];
        }
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (!two_byte && opcode0 == 0xcf) {
        FastTemplateKind kind;
        int id;

        if (s->rex_w) {
            kind = FT_HELPER_IRETQ;
            id = dt_X86_INS_IRETQ;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = FT_HELPER_IRET;
            id = dt_X86_INS_IRET;
        } else {
            kind = FT_HELPER_IRETD;
            id = dt_X86_INS_IRETD;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (!two_byte && (opcode0 == 0xca || opcode0 == 0xcb)) {
        int width = s->mode && s->rex_w ? 64 :
            (s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32);
        int id = width == 64 ? dt_X86_INS_RETFQ : dt_X86_INS_RETF;

        fd_ft_init_fields(&decoded->fields, FT_HELPER_RETFQ, s, address,
                          opcode0, 0, id);
        decoded->fields.alu_width = width;
        if (opcode0 == 0xca) {
            if (s->pos + 2 > s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
            s->pos += 2;
        }
        return fd_ft_finish_match(decoded, s, FT_HELPER_RETFQ, true);
    }

    if (!two_byte && !s->mode && (opcode0 == 0x9a || opcode0 == 0xea)) {
        int offset_size = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;
        FastTemplateKind kind = opcode0 == 0x9a ? FT_HELPER_LCALL :
                                                      FT_HELPER_LJMP;
        int id = opcode0 == 0x9a ? dt_X86_INS_LCALL : dt_X86_INS_LJMP;

        if (s->pos + offset_size + 2 > s->code_size) {
            return FD_FT_REJECT;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        decoded->fields.imm64 = offset_size == 2 ?
            fd_ft_read_u16(&s->code[s->pos]) : fd_ft_read_u32(&s->code[s->pos]);
        s->pos += offset_size;
        decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
        s->pos += 2;
        decoded->fields.alu_width = offset_size * 8;
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (!two_byte) {
        int id = dt_X86_INS_INVALID;

        switch (opcode0) {
        case 0x6c:
            id = dt_X86_INS_INSB;
            break;
        case 0x6d:
            id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                 dt_X86_INS_INSW : dt_X86_INS_INSD;
            break;
        case 0x6e:
            id = dt_X86_INS_OUTSB;
            break;
        case 0x6f:
            id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                 dt_X86_INS_OUTSW : dt_X86_INS_OUTSD;
            break;
        case 0xf1:
            id = dt_X86_INS_INT1;
            break;
        case 0xfa:
            id = dt_X86_INS_CLI;
            break;
        case 0xfb:
            id = dt_X86_INS_STI;
            break;
        default:
            break;
        }
        if (id == dt_X86_INS_INSB || id == dt_X86_INS_INSW ||
            id == dt_X86_INS_INSD || id == dt_X86_INS_OUTSB ||
            id == dt_X86_INS_OUTSW || id == dt_X86_INS_OUTSD) {
            fd_ft_init_fields(&decoded->fields, FT_STRING_IO, s, address,
                              opcode0, 0, id);
            return fd_ft_finish_match(decoded, s, FT_STRING_IO, false);
        }
        if (id != dt_X86_INS_INVALID) {
            FastTemplateKind kind = id == dt_X86_INS_INT1 ? FT_HELPER_UD2 :
                                    (id == dt_X86_INS_CLI ||
                                     id == dt_X86_INS_STI) ? FT_HELPER_GPF :
                                                             FT_NOP_MULTI;
            bool terminal = kind != FT_NOP_MULTI;

            fd_ft_init_fields(&decoded->fields, kind, s, address,
                              opcode0, 0, id);
            return fd_ft_finish_match(decoded, s, kind, terminal);
        }
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 0) {
        fd_ft_init_fields(&decoded->fields, FT_SLDT, s, address,
                          opcode0, opcode1, dt_X86_INS_SLDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_SLDT, false);
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 1) {
        fd_ft_init_fields(&decoded->fields, FT_STR, s, address,
                          opcode0, opcode1, dt_X86_INS_STR);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_STR, false);
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 2) {
        fd_ft_init_fields(&decoded->fields, FT_LLDT, s, address,
                          opcode0, opcode1, dt_X86_INS_LLDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_LLDT, false);
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 3) {
        fd_ft_init_fields(&decoded->fields, FT_LTR, s, address,
                          opcode0, opcode1, dt_X86_INS_LTR);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_LTR, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 4) {
        fd_ft_init_fields(&decoded->fields, FT_SMSW, s, address,
                          opcode0, opcode1, dt_X86_INS_SMSW);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_SMSW, false);
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 4) {
        fd_ft_init_fields(&decoded->fields, FT_VERR, s, address,
                          opcode0, opcode1, dt_X86_INS_VERR);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_VERR, false);
    }

    if (two_byte && opcode1 == 0x00 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 5) {
        fd_ft_init_fields(&decoded->fields, FT_VERW, s, address,
                          opcode0, opcode1, dt_X86_INS_VERW);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_VERW, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && ((s->code[s->pos] >> 3) & 7) == 0) {
        fd_ft_init_fields(&decoded->fields, FT_SGDT, s, address,
                          opcode0, opcode1, dt_X86_INS_SGDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_SGDT, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && (s->code[s->pos] >> 6) != 3 &&
        ((s->code[s->pos] >> 3) & 7) == 2) {
        fd_ft_init_fields(&decoded->fields, FT_LGDT, s, address,
                          opcode0, opcode1, dt_X86_INS_LGDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_LGDT, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && (s->code[s->pos] >> 6) != 3 &&
        ((s->code[s->pos] >> 3) & 7) == 3) {
        fd_ft_init_fields(&decoded->fields, FT_LIDT, s, address,
                          opcode0, opcode1, dt_X86_INS_LIDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_LIDT, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && (s->code[s->pos] >> 6) != 3 &&
        ((s->code[s->pos] >> 3) & 7) == 1) {
        fd_ft_init_fields(&decoded->fields, FT_SIDT, s, address,
                          opcode0, opcode1, dt_X86_INS_SIDT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_SIDT, false);
    }

    if (two_byte && opcode1 == 0x01 && s->prefix[0] == 0 &&
        s->pos < s->code_size && (s->code[s->pos] >> 6) != 3 &&
        ((s->code[s->pos] >> 3) & 7) == 7) {
        fd_ft_init_fields(&decoded->fields, FT_INVLPG, s, address,
                          opcode0, opcode1, dt_X86_INS_INVLPG);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_INVLPG, true);
    }

    if (two_byte && (opcode1 == 0x02 || opcode1 == 0x03) &&
        s->prefix[0] == 0) {
        FastTemplateKind kind = opcode1 == 0x02 ? FT_LAR : FT_LSL;
        int id = opcode1 == 0x02 ? dt_X86_INS_LAR : dt_X86_INS_LSL;

        fd_ft_init_fields(&decoded->fields, kind, s, address,
                          opcode0, opcode1, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && s->prefix[0] == dt_X86_PREFIX_REP && opcode1 == 0x1e) {
        int tail = fd_read_byte(s);

        if (tail < 0) {
            return FD_FT_REJECT;
        }
        if (tail == 0xfa) {
            fd_ft_init_fields(&decoded->fields, FT_ENDBR64, s, address,
                              opcode0, opcode1, dt_X86_INS_NOP);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_ENDBR64, false);
        }
        if (tail == 0xfb) {
            fd_ft_init_fields(&decoded->fields, FT_ENDBR32, s, address,
                              opcode0, opcode1, dt_X86_INS_NOP);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_ENDBR32, false);
        }
        if ((tail & 0xf8) == 0xc8) {
            fd_ft_init_fields(&decoded->fields, FT_NOP_MULTI, s, address,
                              opcode0, opcode1, dt_X86_INS_NOP);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_NOP_MULTI, false);
        }
        return FD_FT_NO_MATCH;
    }

    if (two_byte && opcode1 == 0x31) {
        fd_ft_init_fields(&decoded->fields, FT_RDTSC, s, address,
                          opcode0, opcode1, dt_X86_INS_RDTSC);
        return fd_ft_finish_match(decoded, s, FT_RDTSC, false);
    }

    if (two_byte && opcode1 == 0x33 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_RDPMC, s, address,
                          opcode0, opcode1, dt_X86_INS_RDPMC);
        return fd_ft_finish_match(decoded, s, FT_RDPMC, false);
    }

    if (two_byte && opcode1 == 0x32 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_RDMSR, s, address,
                          opcode0, opcode1, dt_X86_INS_RDMSR);
        return fd_ft_finish_match(decoded, s, FT_RDMSR, false);
    }

    if (two_byte && opcode1 == 0x30 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_WRMSR, s, address,
                          opcode0, opcode1, dt_X86_INS_WRMSR);
        return fd_ft_finish_match(decoded, s, FT_WRMSR, true);
    }

    if (two_byte && opcode1 == 0xaa && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_RSM, s, address,
                          opcode0, opcode1, dt_X86_INS_RSM);
        return fd_ft_finish_match(decoded, s, FT_RSM, true);
    }

    if (two_byte && opcode1 == 0x06 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_CLTS, s, address,
                          opcode0, opcode1, dt_X86_INS_CLTS);
        /* CR0.TS and hflags change; the following instruction needs a new TB. */
        return fd_ft_finish_match(decoded, s, FT_CLTS, true);
    }

    if (two_byte && opcode1 == 0x08 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_INVD, s, address,
                          opcode0, opcode1, dt_X86_INS_INVD);
        return fd_ft_finish_match(decoded, s, FT_INVD, false);
    }

    if (two_byte && opcode1 == 0x09 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_WBINVD, s, address,
                          opcode0, opcode1, dt_X86_INS_WBINVD);
        return fd_ft_finish_match(decoded, s, FT_WBINVD, false);
    }

    if (two_byte && opcode1 == 0x0d && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        FastTemplateKind kind;
        int id;

        fd_ft_init_fields(&decoded->fields, FT_PREFETCH, s, address,
                          opcode0, opcode1, dt_X86_INS_PREFETCH);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3 ||
            decoded->fields.modrm_reg > 1) {
            return FD_FT_NO_MATCH;
        }
        if (decoded->fields.modrm_reg == 0) {
            kind = FT_PREFETCH;
            id = dt_X86_INS_PREFETCH;
        } else {
            kind = FT_PREFETCHW;
            id = dt_X86_INS_PREFETCHW;
        }
        decoded->fields.kind = kind;
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x18 && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        FastTemplateKind kind;
        int id;

        fd_ft_init_fields(&decoded->fields, FT_PREFETCHT0, s, address,
                          opcode0, opcode1, dt_X86_INS_PREFETCHT0);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3 ||
            decoded->fields.modrm_reg > 3) {
            return FD_FT_NO_MATCH;
        }
        switch (decoded->fields.modrm_reg) {
        case 0:
            kind = FT_PREFETCHNTA;
            id = dt_X86_INS_PREFETCHNTA;
            break;
        case 1:
            kind = FT_PREFETCHT0;
            id = dt_X86_INS_PREFETCHT0;
            break;
        case 2:
            kind = FT_PREFETCHT1;
            id = dt_X86_INS_PREFETCHT1;
            break;
        default:
            kind = FT_PREFETCHT2;
            id = dt_X86_INS_PREFETCHT2;
            break;
        }
        decoded->fields.kind = kind;
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0x1a || opcode1 == 0x1b) &&
        s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_BNDMOV, s, address,
                          opcode0, opcode1, dt_X86_INS_BNDMOV);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (s->rex_r || decoded->fields.modrm_reg > 3 ||
            (decoded->fields.modrm_mod == 3 &&
             (s->rex_b || decoded->fields.modrm_rm > 3))) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_BNDMOV, false);
    }

    if (two_byte && (opcode1 == 0xb9 || opcode1 == 0xff) &&
        s->prefix[0] == 0 &&
        s->prefix[2] == 0 && !s->rex_w) {
        FastTemplateKind kind = opcode1 == 0xb9 ? FT_HELPER_UD1 :
                                                  FT_HELPER_UD0;
        int id = opcode1 == 0xb9 ? dt_X86_INS_UD1 : dt_X86_INS_UD0;

        fd_ft_init_fields(&decoded->fields, kind, s, address,
                          opcode0, opcode1, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (two_byte && opcode1 == 0x1c && s->prefix[0] == 0 &&
        s->prefix[2] == 0) {
        fd_ft_init_fields(&decoded->fields, FT_CLDEMOTE, s, address,
                          opcode0, opcode1, dt_X86_INS_CLDEMOTE);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3 ||
            decoded->fields.modrm_reg != 0) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_CLDEMOTE, false);
    }

    if (two_byte && opcode1 == 0x01) {
        int tail = fd_read_byte(s);

        if (tail < 0) {
            return FD_FT_REJECT;
        }
        if (tail == 0xca) {
            fd_ft_init_fields(&decoded->fields, FT_CLAC, s, address,
                              opcode0, opcode1, dt_X86_INS_CLAC);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_CLAC, false);
        }
        if (tail == 0xcb) {
            fd_ft_init_fields(&decoded->fields, FT_STAC, s, address,
                              opcode0, opcode1, dt_X86_INS_STAC);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_STAC, false);
        }
        if (tail == 0xd0) {
            fd_ft_init_fields(&decoded->fields, FT_XGETBV, s, address,
                              opcode0, opcode1, dt_X86_INS_XGETBV);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_XGETBV, false);
        }
        if (tail == 0xd1) {
            if (s->prefix[0] != 0 || s->prefix[2] != 0 || s->rex != 0) {
                return FD_FT_NO_MATCH;
            }
            fd_ft_init_fields(&decoded->fields, FT_XSETBV, s, address,
                              opcode0, opcode1, dt_X86_INS_XSETBV);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_XSETBV, true);
        }
        if (tail == 0xf8) {
            fd_ft_init_fields(&decoded->fields, FT_SWAPGS, s, address,
                              opcode0, opcode1, dt_X86_INS_SWAPGS);
            ft_fields_set_modrm(&decoded->fields, tail);
            return fd_ft_finish_match(decoded, s, FT_SWAPGS, false);
        }
        if (tail != 0xf9) {
            return FD_FT_NO_MATCH;
        }
        fd_ft_init_fields(&decoded->fields, FT_RDTSCP, s, address,
                          opcode0, opcode1, dt_X86_INS_RDTSCP);
        ft_fields_set_modrm(&decoded->fields, tail);
        return fd_ft_finish_match(decoded, s, FT_RDTSCP, false);
    }

    if (two_byte && opcode1 == 0xb4 && s->prefix[0] == 0 &&
        !s->rex_w && (s->prefix[2] == 0 ||
                      s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
        fd_ft_init_fields(&decoded->fields, FT_LFS, s, address,
                          opcode0, opcode1, dt_X86_INS_LFS);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_LFS, false);
    }

    if (two_byte && opcode1 == 0xb2 && s->prefix[0] == 0 &&
        !s->rex_w && (s->prefix[2] == 0 ||
                      s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
        fd_ft_init_fields(&decoded->fields, FT_LSS, s, address,
                          opcode0, opcode1, dt_X86_INS_LSS);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_LSS, true);
    }

    if (two_byte && opcode1 == 0xb5 && s->prefix[0] == 0 &&
        !s->rex_w && (s->prefix[2] == 0 ||
                      s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
        fd_ft_init_fields(&decoded->fields, FT_LGS, s, address,
                          opcode0, opcode1, dt_X86_INS_LGS);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (decoded->fields.modrm_mod == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_LGS, false);
    }

    if (two_byte && opcode1 == 0xae) {
        FastTemplateKind kind;
        int id;
        int ext;

        fd_ft_init_fields(&decoded->fields, FT_LFENCE, s, address,
                          opcode0, opcode1, dt_X86_INS_LFENCE);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (decoded->fields.modrm_mod != 3 && ext == 7 &&
            s->prefix[0] == 0) {
            if (s->prefix[2] == 0) {
                kind = FT_CLFLUSH;
                id = dt_X86_INS_CLFLUSH;
            } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                kind = FT_CLFLUSHOPT;
                id = dt_X86_INS_CLFLUSHOPT;
            } else {
                return FD_FT_NO_MATCH;
            }
        } else if (decoded->fields.modrm_mod == 3 && ext == 5) {
            kind = FT_LFENCE;
            id = dt_X86_INS_LFENCE;
        } else if (decoded->fields.modrm_mod == 3 && ext == 6) {
            kind = FT_MFENCE;
            id = dt_X86_INS_MFENCE;
        } else if (decoded->fields.modrm_mod == 3 && ext == 7) {
            kind = FT_SFENCE;
            id = dt_X86_INS_SFENCE;
        } else {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.kind = kind;
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xa2 || opcode1 == 0x05 || opcode1 == 0x07 ||
                     opcode1 == 0x34 || opcode1 == 0x35 ||
                     opcode1 == 0x0b)) {
        FastTemplateKind kind;
        int id;
        bool is_tb_ending;

        if (opcode1 == 0xa2) {
            kind = FT_HELPER_CPUID;
            id = dt_X86_INS_CPUID;
            is_tb_ending = false;
        } else if (opcode1 == 0x05) {
            kind = FT_HELPER_SYSCALL;
            id = dt_X86_INS_SYSCALL;
            is_tb_ending = true;
        } else if (opcode1 == 0x34) {
            kind = FT_HELPER_SYSENTER;
            id = dt_X86_INS_SYSENTER;
            is_tb_ending = true;
        } else if (opcode1 == 0x35) {
            if (s->prefix[0] != 0 || s->rex_w ||
                (s->prefix[2] != 0 &&
                 s->prefix[2] != dt_X86_PREFIX_OPSIZE)) {
                return FD_FT_NO_MATCH;
            }
            kind = FT_HELPER_SYSEXIT;
            id = dt_X86_INS_SYSEXIT;
            is_tb_ending = true;
        } else if (opcode1 == 0x07) {
            if (s->prefix[0] != 0 ||
                (s->prefix[2] != 0 &&
                 s->prefix[2] != dt_X86_PREFIX_OPSIZE)) {
                return FD_FT_NO_MATCH;
            }
            kind = FT_HELPER_SYSRET;
            id = dt_X86_INS_SYSRET;
            is_tb_ending = true;
        } else {
            kind = FT_HELPER_UD2;
            id = dt_X86_INS_UD2;
            is_tb_ending = true;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, id);
        return fd_ft_finish_match(decoded, s, kind, is_tb_ending);
    }

    if (!two_byte && opcode0 == 0xc9) {
        fd_ft_init_fields(&decoded->fields, FT_LEAVE, s, address,
                          opcode0, 0, dt_X86_INS_LEAVE);
        decoded->fields.alu_width = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
            16 : s->mode ? 64 : 32;
        return fd_ft_finish_match(decoded, s, FT_LEAVE, false);
    }

    if (!two_byte && opcode0 == 0xf4) {
        fd_ft_init_fields(&decoded->fields, FT_HELPER_GPF, s, address,
                          opcode0, 0, dt_X86_INS_HLT);
        return fd_ft_finish_match(decoded, s, FT_HELPER_GPF, true);
    }

    if (!two_byte && opcode0 == 0x9b) {
        fd_ft_init_fields(&decoded->fields, FT_WAIT, s, address,
                          opcode0, 0, dt_X86_INS_WAIT);
        return fd_ft_finish_match(decoded, s, FT_WAIT, false);
    }

    if (!two_byte && opcode0 == 0x90 &&
        s->prefix[0] == dt_X86_PREFIX_REP) {
        fd_ft_init_fields(&decoded->fields, FT_PAUSE, s, address,
                          opcode0, 0, dt_X86_INS_PAUSE);
        return fd_ft_finish_match(decoded, s, FT_PAUSE, false);
    }

    if (!two_byte) {
        FastTemplateKind kind = FT_UNSUPPORTED;
        int id = dt_X86_INS_INVALID;

        switch (opcode0) {
        case 0xf5:
            kind = FT_CMC;
            id = dt_X86_INS_CMC;
            break;
        case 0xf8:
            kind = FT_CLC;
            id = dt_X86_INS_CLC;
            break;
        case 0xf9:
            kind = FT_STC;
            id = dt_X86_INS_STC;
            break;
        case 0xfc:
            kind = FT_CLD;
            id = dt_X86_INS_CLD;
            break;
        case 0xfd:
            kind = FT_STD;
            id = dt_X86_INS_STD;
            break;
        case 0x9f:
            kind = FT_LAHF;
            id = dt_X86_INS_LAHF;
            break;
        case 0x9e:
            kind = FT_SAHF;
            id = dt_X86_INS_SAHF;
            break;
        case 0x9c:
            kind = FT_PUSHFQ;
            id = dt_X86_INS_PUSHFQ;
            break;
        case 0x9d:
            kind = FT_POPFQ;
            id = dt_X86_INS_POPFQ;
            break;
        default:
            break;
        }
        if (kind != FT_UNSUPPORTED) {
            if (!s->mode && opcode0 == 0x9c) {
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_PUSHF : dt_X86_INS_PUSHFD;
            } else if (!s->mode && opcode0 == 0x9d) {
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_POPF : dt_X86_INS_POPFD;
            }
            fd_ft_init_fields(&decoded->fields, kind, s, address,
                              opcode0, 0, id);
            if (opcode0 == 0x9c || opcode0 == 0x9d) {
                decoded->fields.alu_width =
                    s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 :
                    (s->mode ? 64 : 32);
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
    }

    if (!two_byte && (opcode0 == 0xe0 || opcode0 == 0xe1 ||
                      opcode0 == 0xe2 || opcode0 == 0xe3)) {
        FastTemplateKind kind;
        int id;
        int rel8;

        switch (opcode0) {
        case 0xe0:
            kind = FT_LOOPNE_REL8;
            id = dt_X86_INS_LOOPNE;
            break;
        case 0xe1:
            kind = FT_LOOPE_REL8;
            id = dt_X86_INS_LOOPE;
            break;
        case 0xe2:
            kind = FT_LOOP_REL8;
            id = dt_X86_INS_LOOP;
            break;
        default:
            kind = FT_JRCXZ_REL8;
            id = s->aflag == 16 ? dt_X86_INS_JCXZ :
                 s->aflag == 32 ? dt_X86_INS_JECXZ : dt_X86_INS_JRCXZ;
            break;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        if (s->pos >= s->code_size) {
            return FD_FT_REJECT;
        }
        rel8 = (int8_t)s->code[s->pos++];
        decoded->fields.alu_width = s->aflag;
        decoded->fields.imm64 = address + s->pos + rel8;
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (!two_byte && opcode0 == 0xff) {
        FastTemplateKind kind;
        int id;
        int ext;

        fd_ft_init_fields(&decoded->fields, FT_CALL_RM64, s, address,
                          opcode0, 0, dt_X86_INS_CALL);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext == 2) {
            kind = FT_CALL_RM64;
            id = dt_X86_INS_CALL;
        } else if (ext == 4) {
            kind = FT_JMP_RM64;
            id = dt_X86_INS_JMP;
        } else if (ext == 5 && decoded->fields.modrm_mod != 3) {
            kind = FT_HELPER_LJMP;
            id = dt_X86_INS_LJMP;
            decoded->fields.alu_width = s->mode && s->rex_w ? 64 :
                (s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32);
        } else {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.kind = kind;
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (two_byte && opcode1 >= 0x90 && opcode1 <= 0x9f) {
        int cond;
        int id;

        fd_ft_init_fields(&decoded->fields, FT_SETCC_RM8, s, address,
                          opcode0, opcode1, dt_X86_INS_INVALID);
        if (!fd_ft_jcc_opcode_info(opcode1 & 0xf, &cond, &id) ||
            !fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, FT_SETCC_RM8, false);
    }

    if (!two_byte && opcode0 == 0x68) {
        bool is_16bit = s->prefix[2] == dt_X86_PREFIX_OPSIZE;
        FastTemplateKind kind = is_16bit ? FT_PUSH_IMM16 : FT_PUSH_IMM32;
        int imm_size = is_16bit ? 2 : 4;

        fd_ft_init_fields(&decoded->fields, kind, s, address,
                          opcode0, 0, dt_X86_INS_PUSH);
        if (s->pos + imm_size > s->code_size) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = is_16bit ?
            (int16_t)fd_ft_read_u16(&s->code[s->pos]) :
            (int32_t)fd_ft_read_u32(&s->code[s->pos]);
        decoded->fields.alu_width = is_16bit ? 16 : s->mode ? 64 : 32;
        s->pos += imm_size;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0x6a) {
        fd_ft_init_fields(&decoded->fields, FT_PUSH_IMM8, s, address,
                          opcode0, 0, dt_X86_INS_PUSH);
        if (s->pos >= s->code_size) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = (int8_t)s->code[s->pos++];
        decoded->fields.alu_width =
            s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : s->mode ? 64 : 32;
        return fd_ft_finish_match(decoded, s, FT_PUSH_IMM8, false);
    }

    return FD_FT_NO_MATCH;
}
