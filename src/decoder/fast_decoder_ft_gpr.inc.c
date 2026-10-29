/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static inline FastDecoderFTMatch fd_ft_try_gpr(FDState *s, uint8_t opcode0,
                                               uint8_t opcode1, bool two_byte,
                                               uint64_t address,
                                               FastDecodedFT *decoded)
{
    if (!two_byte && !s->mode &&
        (opcode0 == 0x27 || opcode0 == 0x2f ||
         opcode0 == 0x37 || opcode0 == 0x3f ||
         opcode0 == 0xd4 || opcode0 == 0xd5)) {
        int id;

        switch (opcode0) {
        case 0x27: id = dt_X86_INS_DAA; break;
        case 0x2f: id = dt_X86_INS_DAS; break;
        case 0x37: id = dt_X86_INS_AAA; break;
        case 0x3f: id = dt_X86_INS_AAS; break;
        case 0xd4: id = dt_X86_INS_AAM; break;
        default: id = dt_X86_INS_AAD; break;
        }
        fd_ft_init_fields(&decoded->fields, FT_HELPER_BCD, s, address,
                          opcode0, 0, id);
        if (opcode0 == 0xd4 || opcode0 == 0xd5) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = s->code[s->pos++];
        }
        return fd_ft_finish_match(decoded, s, FT_HELPER_BCD, false);
    }

    if (!two_byte && !s->mode && opcode0 == 0xd6) {
        fd_ft_init_fields(&decoded->fields, FT_SALC, s, address, opcode0,
                          0, dt_X86_INS_SALC);
        return fd_ft_finish_match(decoded, s, FT_SALC, false);
    }

    if (!two_byte && !s->mode && opcode0 == 0x63) {
        fd_ft_init_fields(&decoded->fields, FT_ARPL, s, address, opcode0,
                          0, dt_X86_INS_ARPL);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_ARPL, false);
    }

    if (!two_byte && !s->mode && (opcode0 == 0x60 || opcode0 == 0x61)) {
        FastTemplateKind kind = opcode0 == 0x60 ? FT_PUSHA : FT_POPA;
        int id;

        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            id = opcode0 == 0x60 ? dt_X86_INS_PUSHAW : dt_X86_INS_POPAW;
        } else {
            id = opcode0 == 0x60 ? dt_X86_INS_PUSHAL : dt_X86_INS_POPAL;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        decoded->fields.alu_width = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && !s->mode && (opcode0 == 0xc4 || opcode0 == 0xc5)) {
        FastTemplateKind kind = opcode0 == 0xc4 ? FT_LES : FT_LDS;
        int id = opcode0 == 0xc4 ? dt_X86_INS_LES : dt_X86_INS_LDS;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            decoded->fields.modrm_mod == 3) {
            return FD_FT_REJECT;
        }
        decoded->fields.alu_width = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && !s->mode && opcode0 == 0x62) {
        fd_ft_init_fields(&decoded->fields, FT_NOP_MULTI, s, address,
                          opcode0, 0, dt_X86_INS_BOUND);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            decoded->fields.modrm_mod == 3) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_NOP_MULTI, false);
    }

    if (!two_byte && opcode0 >= 0xa0 && opcode0 <= 0xa3) {
        FastTemplateKind kind = opcode0 < 0xa2 ? FT_MOV_ACC_MOFFS :
                                                  FT_MOV_MOFFS_ACC;
        int addr_size = s->aflag == 64 ? 8 : 4;
        int width = (opcode0 & 1) == 0 ? 8 :
                    s->rex_w ? 64 :
                    s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32;

        if (s->prefix[0] || s->pos + addr_size > s->code_size) {
            return FD_FT_REJECT;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_MOV);
        decoded->fields.imm64 = addr_size == 8 ?
                                fd_ft_read_u64(s->code + s->pos) :
                                fd_ft_read_u32(s->code + s->pos);
        decoded->fields.alu_width = width;
        s->pos += addr_size;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte &&
        (opcode1 == 0xa0 || opcode1 == 0xa1 ||
         opcode1 == 0xa8 || opcode1 == 0xa9)) {
        bool pop = (opcode1 & 1) != 0;
        bool is_16 = s->prefix[2] == dt_X86_PREFIX_OPSIZE;
        FastTemplateKind kind;

        if (s->prefix[0] || s->prefix[1] || s->prefix[3]) {
            return FD_FT_REJECT;
        }
        kind = is_16 ? (pop ? FT_POP_SEG16 : FT_PUSH_SEG16) :
                       (pop ? FT_POP_SEG64 : FT_PUSH_SEG64);
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, pop ? dt_X86_INS_POP : dt_X86_INS_PUSH);
        decoded->fields.reg = opcode1 >= 0xa8 ? FD_FT_SEG_GS :
                                                FD_FT_SEG_FS;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0xc8) {
        FastTemplateKind kind;
        unsigned int allocation;
        unsigned int nesting_level;

        if (s->pos + 3 > s->code_size) {
            return FD_FT_REJECT;
        }
        if (s->prefix[0] || s->prefix[1] || s->prefix[3] || s->has_rex) {
            return FD_FT_NO_MATCH;
        }
        allocation = s->code[s->pos] | (s->code[s->pos + 1] << 8);
        nesting_level = s->code[s->pos + 2] & 31;
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = FT_ENTER16;
        } else if (s->prefix[2] == 0) {
            kind = allocation == 0 && nesting_level == 1 ?
                   FT_ENTER_ZERO_LEVEL1 : FT_ENTER;
        } else {
            return FD_FT_NO_MATCH;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_ENTER);
        decoded->fields.imm = allocation | (nesting_level << 16);
        s->pos += 3;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0xc9) {
        fd_ft_init_fields(&decoded->fields, FT_LEAVE, s, address, opcode0,
                          0, dt_X86_INS_LEAVE);
        decoded->fields.alu_width = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
            16 : s->mode ? 64 : 32;
        return fd_ft_finish_match(decoded, s, FT_LEAVE, false);
    }

    if (!two_byte && opcode0 == 0xd7) {
        if (!s->mode || s->prefix[0] || s->prefix[1] ||
            (s->prefix[2] && s->prefix[2] != dt_X86_PREFIX_OPSIZE)) {
            return FD_FT_NO_MATCH;
        }
        fd_ft_init_fields(&decoded->fields, FT_XLATB, s, address, opcode0,
                          0, dt_X86_INS_XLATB);
        return fd_ft_finish_match(decoded, s, FT_XLATB, false);
    }

    if (!two_byte && opcode0 == 0xc4) {
        uint8_t vex2;
        uint8_t vex3;
        uint8_t vopcode;
        FastTemplateKind kind;
        int id;
        int ext;
        bool rorx;
        bool mulx;

        if (s->pos + 3 > s->code_size) {
            return FD_FT_REJECT;
        }
        vex2 = s->code[s->pos++];
        vex3 = s->code[s->pos++];
        vopcode = s->code[s->pos++];
        rorx = (vex2 & 0x1f) == 3 && (vex3 & 0x7f) == 0x7b &&
               vopcode == 0xf0;
        mulx = (vex2 & 0x1f) == 2 && (vex3 & 7) == 3 &&
               vopcode == 0xf6;
        if (!rorx && !mulx && ((vex2 & 0x1f) != 2 ||
            !(((vex3 & 3) == 0 &&
               (vopcode == 0xf2 || vopcode == 0xf3 || vopcode == 0xf7)) ||
              (((vex3 & 3) == 1 || (vex3 & 3) == 2 ||
                (vex3 & 3) == 3) &&
               vopcode == 0xf7) ||
              (((vex3 & 7) == 0 || (vex3 & 7) == 2 ||
                (vex3 & 7) == 3) &&
               vopcode == 0xf5)))) {
            return FD_FT_NO_MATCH;
        }
        s->rex_r = ((~vex2 >> 7) & 1) << 3;
        s->rex_x = ((~vex2 >> 6) & 1) << 3;
        s->rex_b = ((~vex2 >> 5) & 1) << 3;
        s->rex_w = (vex3 >> 7) & 1;
        s->rex = 0x40 | (s->rex_w << 3) | (s->rex_r >> 1) |
                 (s->rex_x >> 2) | (s->rex_b >> 3);
        s->has_rex = 1;
        s->vex_v = (~vex3 >> 3) & 0xf;
        s->vex_l = (vex3 >> 2) & 1;

        if (rorx) {
            kind = s->rex_w ? FT_RORX_R64_RM64_IMM8 :
                              FT_RORX_R32_RM32_IMM8;
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              vopcode, dt_X86_INS_RORX);
            if (!fd_ft_read_modrm(s, &decoded->fields) ||
                s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.reg = ((decoded->fields.modrm >> 3) & 7) |
                                  s->rex_r;
            decoded->fields.imm = s->code[s->pos++];
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (mulx) {
            kind = s->rex_w ? FT_MULX_R64_R_RM : FT_MULX_R32_R_RM;
            id = dt_X86_INS_MULX;
        } else if (vopcode == 0xf2) {
            kind = s->rex_w ? FT_ANDN_R64_R_RM : FT_ANDN_R32_R_RM;
            id = dt_X86_INS_ANDN;
        } else if (vopcode == 0xf3) {
            kind = s->rex_w ? FT_BLS_R64_RM : FT_BLS_R32_RM;
            id = dt_X86_INS_BLSI;
        } else if (vopcode == 0xf7) {
            if ((vex3 & 3) == 0) {
                kind = s->rex_w ? FT_BEXTR_R64_RM_R : FT_BEXTR_R32_RM_R;
                id = dt_X86_INS_BEXTR;
            } else if ((vex3 & 3) == 1) {
                kind = s->rex_w ? FT_SHLX_R64_RM_R : FT_SHLX_R32_RM_R;
                id = dt_X86_INS_SHLX;
            } else if ((vex3 & 3) == 2) {
                kind = s->rex_w ? FT_SARX_R64_RM_R : FT_SARX_R32_RM_R;
                id = dt_X86_INS_SARX;
            } else {
                kind = s->rex_w ? FT_SHRX_R64_RM_R : FT_SHRX_R32_RM_R;
                id = dt_X86_INS_SHRX;
            }
        } else if (vopcode == 0xf5 && (vex3 & 7) == 0) {
            kind = s->rex_w ? FT_BZHI_R64_RM_R : FT_BZHI_R32_RM_R;
            id = dt_X86_INS_BZHI;
        } else if (vopcode == 0xf5 && (vex3 & 7) == 2) {
            kind = s->rex_w ? FT_PEXT_R64_R_RM : FT_PEXT_R32_R_RM;
            id = dt_X86_INS_PEXT;
        } else if (vopcode == 0xf5 && (vex3 & 7) == 3) {
            kind = s->rex_w ? FT_PDEP_R64_R_RM : FT_PDEP_R32_R_RM;
            id = dt_X86_INS_PDEP;
        } else {
            return FD_FT_NO_MATCH;
        }

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          vopcode, id);
        decoded->fields.vex_v = s->vex_v;
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (mulx) {
            decoded->fields.reg = ext | s->rex_r;
            decoded->fields.imm = s->vex_v;
        } else if (vopcode == 0xf3) {
            if (ext < 1 || ext > 3) {
                return FD_FT_NO_MATCH;
            }
            decoded->fields.id = ext == 1 ? dt_X86_INS_BLSR :
                                  ext == 2 ? dt_X86_INS_BLSMSK :
                                             dt_X86_INS_BLSI;
            decoded->fields.reg = decoded->fields.vex_v;
        } else {
            decoded->fields.reg = ext | s->rex_r;
            decoded->fields.imm = decoded->fields.vex_v;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x04 || opcode0 == 0x05 ||
                      opcode0 == 0x0c || opcode0 == 0x0d ||
                      opcode0 == 0x14 || opcode0 == 0x15 ||
                      opcode0 == 0x1c || opcode0 == 0x1d ||
                      opcode0 == 0x24 || opcode0 == 0x25 ||
                      opcode0 == 0x2c || opcode0 == 0x2d ||
                      opcode0 == 0x34 || opcode0 == 0x35 ||
                      opcode0 == 0x3c || opcode0 == 0x3d ||
                      opcode0 == 0xa8 || opcode0 == 0xa9)) {
        int imm_size = (opcode0 & 1) == 0 || opcode0 == 0xa8 ? 1 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;
        int64_t imm;

        fd_ft_init_fields(&decoded->fields, FT_ALU_ACC_IMM, s, address,
                          opcode0, 0, dt_X86_INS_INVALID);
        if ((size_t)(s->pos + imm_size) > s->code_size ||
            !fd_ft_read_simm_at(s->code, s->code_size, s->pos, imm_size,
                                &imm)) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = (int)imm;
        s->pos += imm_size;
        if (!ft_fill_generic_alu_info(&decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_ALU_ACC_IMM, false);
    }

    if (!two_byte && opcode0 == 0x90 && s->rex_w && s->rex_b) {
        fd_ft_init_fields(&decoded->fields, FT_XCHG_R64_RAX, s, address,
                          opcode0, 0, dt_X86_INS_XCHG);
        decoded->fields.reg = s->rex_b ? 8 : 0;
        return fd_ft_finish_match(decoded, s, FT_XCHG_R64_RAX, false);
    }

    if (!two_byte && opcode0 == 0x90 && s->has_rex && !s->rex_w &&
        s->rex_b) {
        FastTemplateKind kind =
            s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
            FT_XCHG_R16_AX : FT_XCHG_R32_EAX;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_XCHG);
        decoded->fields.reg = 8;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0x90 && (!s->has_rex || !s->rex_b) &&
        s->prefix[0] != dt_X86_PREFIX_REP) {
        fd_ft_init_fields(&decoded->fields, FT_NOP_MULTI, s, address, opcode0, 0,
                          dt_X86_INS_NOP);
        return fd_ft_finish_match(decoded, s, FT_NOP_MULTI, false);
    }

    if (!two_byte && opcode0 >= 0x91 && opcode0 <= 0x97) {
        FastTemplateKind kind = s->rex_w ? FT_XCHG_R64_RAX :
                                s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                FT_XCHG_R16_AX : FT_XCHG_R32_EAX;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_XCHG);
        decoded->fields.reg = (opcode0 & 7) | (s->rex_b ? 8 : 0);
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x1f) {
        fd_ft_init_fields(&decoded->fields, FT_NOP_MULTI, s, address,
                          opcode0, opcode1, dt_X86_INS_NOP);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_NOP_MULTI, false);
    }

    if (!two_byte && (opcode0 == 0x98 || opcode0 == 0x99)) {
        FastTemplateKind kind;

        if (opcode0 == 0x98) {
            kind = s->rex_w ? FT_CDQE :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_CBW :
                   FT_CWDE;
        } else {
            kind = s->rex_w ? FT_CQO :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_CWD :
                   FT_CDQ;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          opcode0 == 0x98 ? dt_X86_INS_CWDE :
                                             dt_X86_INS_CDQ);
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0x31) {
        fd_ft_init_fields(&decoded->fields, FT_XOR_RM_GPR_ZERO, s,
                          address, opcode0, 0, dt_X86_INS_XOR);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if ((decoded->fields.modrm & 0xc0) == 0xc0 &&
            ((decoded->fields.modrm >> 3) & 7) == (decoded->fields.modrm & 7)) {
            return fd_ft_finish_match(decoded, s, FT_XOR_RM_GPR_ZERO, false);
        }
        return FD_FT_NO_MATCH;
    }

    if (!two_byte && (opcode0 == 0x88 || opcode0 == 0x8a)) {
        FastTemplateKind kind = opcode0 == 0x88 ? FT_MOV_RM8_R8 :
                                                  FT_MOV_R8_RM8;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_MOV);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x86 || opcode0 == 0x87)) {
        FastTemplateKind kind = opcode0 == 0x86 ? FT_XCHG_RM8_R8 :
                                s->rex_w ? FT_XCHG_RM64_R64 :
                                FT_XCHG_RM32_R32;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_XCHG);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x8c || opcode0 == 0x8e)) {
        FastTemplateKind kind = opcode0 == 0x8c ? FT_MOV_RM_SEG :
                                                  FT_MOV_SEG_RM;
        int seg;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_MOV);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        seg = decoded->fields.modrm_reg;
        /* ModR/M.reg uses the architectural ES..GS encoding (CS is 1). */
        if (seg >= 6 || (opcode0 == 0x8e && seg == 1)) {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.reg = seg;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 >= 0xb0 && opcode0 <= 0xbf) {
        FastTemplateKind kind;
        int imm_size;

        if (opcode0 < 0xb8) {
            kind = FT_MOV_R8_IMM8;
            imm_size = 1;
        } else if (s->rex_w) {
            kind = FT_MOV_R64_IMM64;
            imm_size = 8;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = FT_MOV_R16_IMM16;
            imm_size = 2;
        } else {
            kind = FT_MOV_R32_IMM32;
            imm_size = 4;
        }

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_MOV);
        decoded->fields.reg = (opcode0 & 7) | (s->rex_b ? 8 : 0);
        if ((size_t)(s->pos + imm_size) > s->code_size) {
            return FD_FT_REJECT;
        }
        if (imm_size == 8) {
            decoded->fields.imm64 = fd_ft_read_u64(&s->code[s->pos]);
        } else if (imm_size == 4) {
            decoded->fields.imm = fd_ft_read_u32(&s->code[s->pos]);
        } else if (imm_size == 2) {
            decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
        } else {
            decoded->fields.imm = s->code[s->pos];
        }
        s->pos += imm_size;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && ((opcode0 >= 0xa4 && opcode0 <= 0xa7) ||
                      opcode0 == 0xaa || opcode0 == 0xab ||
                      opcode0 == 0xac || opcode0 == 0xad ||
                      opcode0 == 0xae || opcode0 == 0xaf)) {
        int width = (opcode0 & 1) == 0 ? 8 : s->dflag;
        int id;

        switch (opcode0) {
        case 0xa4:
            id = dt_X86_INS_MOVSB;
            break;
        case 0xa5:
            id = width == 16 ? dt_X86_INS_MOVSW :
                 width == 64 ? dt_X86_INS_MOVSQ : dt_X86_INS_MOVSD;
            break;
        case 0xa6:
            id = dt_X86_INS_CMPSB;
            break;
        case 0xa7:
            id = width == 16 ? dt_X86_INS_CMPSW :
                 width == 64 ? dt_X86_INS_CMPSQ : dt_X86_INS_CMPSD;
            break;
        case 0xaa:
            id = dt_X86_INS_STOSB;
            break;
        case 0xab:
            id = width == 16 ? dt_X86_INS_STOSW :
                 width == 64 ? dt_X86_INS_STOSQ : dt_X86_INS_STOSD;
            break;
        case 0xac:
            id = dt_X86_INS_LODSB;
            break;
        case 0xad:
            id = width == 16 ? dt_X86_INS_LODSW :
                 width == 64 ? dt_X86_INS_LODSQ : dt_X86_INS_LODSD;
            break;
        case 0xae:
            id = dt_X86_INS_SCASB;
            break;
        default:
            id = width == 16 ? dt_X86_INS_SCASW :
                 width == 64 ? dt_X86_INS_SCASQ : dt_X86_INS_SCASD;
            break;
        }
        fd_ft_init_fields(&decoded->fields, FT_STRING, s, address, opcode0,
                          0, id);
        return fd_ft_finish_match(decoded, s, FT_STRING, false);
    }

    if (!two_byte && (opcode0 == 0xfe || opcode0 == 0xff)) {
        FastTemplateKind kind;
        int ext;

        fd_ft_init_fields(&decoded->fields, FT_INC_RM8, s, address, opcode0,
                          0, dt_X86_INS_INC);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (opcode0 == 0xfe && (ext == 0 || ext == 1)) {
            kind = ext == 0 ? FT_INC_RM8 : FT_DEC_RM8;
        } else if (opcode0 == 0xff && (ext == 0 || ext == 1)) {
            if (s->rex_w) {
                kind = ext == 0 ? FT_INC_RM64 : FT_DEC_RM64;
            } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                kind = ext == 0 ? FT_INC_RM16 : FT_DEC_RM16;
            } else {
                kind = ext == 0 ? FT_INC_RM32 : FT_DEC_RM32;
            }
        } else if (opcode0 == 0xff && ext == 6) {
            kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_PUSH_RM16 :
                                                           FT_PUSH_RM64;
        } else {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.kind = kind;
        decoded->fields.id = ext == 6 ? dt_X86_INS_PUSH :
                             ext == 0 ? dt_X86_INS_INC : dt_X86_INS_DEC;
        if (ext == 6) {
            decoded->fields.alu_width =
                s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : s->mode ? 64 : 32;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0x8f) {
        int ext;
        FastTemplateKind kind;

        fd_ft_init_fields(&decoded->fields, FT_POP_RM64, s, address,
                          opcode0, 0, dt_X86_INS_POP);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext != 0) {
            return FD_FT_NO_MATCH;
        }
        kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_POP_RM16 :
                                                       FT_POP_RM64;
        decoded->fields.kind = kind;
        decoded->fields.alu_width =
            s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : s->mode ? 64 : 32;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0xc6 || opcode0 == 0xc7)) {
        FastTemplateKind kind;
        int imm_size;

        if (opcode0 == 0xc6) {
            kind = FT_MOV_RM8_IMM8;
            imm_size = 1;
        } else if (s->rex_w) {
            kind = FT_MOV_RM64_IMM32;
            imm_size = 4;
        } else {
            kind = FT_MOV_RM32_IMM32;
            imm_size = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_MOV);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (((decoded->fields.modrm >> 3) & 7) != 0) {
            return FD_FT_NO_MATCH;
        }
        if ((size_t)(s->pos + imm_size) > s->code_size) {
            return FD_FT_REJECT;
        }
        if (imm_size == 4) {
            decoded->fields.imm = fd_ft_read_u32(&s->code[s->pos]);
        } else if (imm_size == 2) {
            decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
        } else {
            decoded->fields.imm = s->code[s->pos];
        }
        s->pos += imm_size;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x84 || opcode0 == 0x85)) {
        FastTemplateKind kind = opcode0 == 0x84 ? FT_TEST_RM8_R8 :
                                s->rex_w ? FT_TEST_RM64_R64 :
                                s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                FT_TEST_RM16_R16 : FT_TEST_RM32_R32;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_TEST);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        fd_ft_set_alu(&decoded->fields, FT_ALU_TEST, FT_ALU_FORM_RM_R,
                      opcode0 == 0x84 ? 8 :
                      s->rex_w ? 64 :
                      s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32);
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0xf6 || opcode0 == 0xf7)) {
        FastTemplateKind kind;
        int ext;
        int imm_size;
        int64_t imm;

        fd_ft_init_fields(&decoded->fields, FT_TEST_RM8_IMM8, s, address,
                          opcode0, 0, dt_X86_INS_TEST);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext == 0) {
            if (opcode0 == 0xf6) {
                kind = FT_TEST_RM8_IMM8;
                imm_size = 1;
            } else if (s->rex_w) {
                kind = FT_TEST_RM64_IMM32;
                imm_size = 4;
            } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                kind = FT_TEST_RM16_IMM16;
                imm_size = 2;
            } else {
                kind = FT_TEST_RM32_IMM32;
                imm_size = 4;
            }
            decoded->fields.kind = kind;
            if ((size_t)(s->pos + imm_size) > s->code_size ||
                !fd_ft_read_simm_at(s->code, s->code_size, s->pos, imm_size,
                                    &imm)) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = opcode0 == 0xf6 ? s->code[s->pos] :
                                  (int)imm;
            s->pos += imm_size;
            fd_ft_set_alu(&decoded->fields, FT_ALU_TEST, FT_ALU_FORM_RM_IMM,
                          opcode0 == 0xf6 ? 8 :
                          s->rex_w ? 64 :
                          s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32);
        } else if (ext == 2 || ext == 3) {
            if (opcode0 == 0xf6) {
                kind = ext == 2 ? FT_NOT_RM8 : FT_NEG_RM8;
            } else if (s->rex_w) {
                kind = ext == 2 ? FT_NOT_RM64 : FT_NEG_RM64;
            } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                kind = ext == 2 ? FT_NOT_RM16 : FT_NEG_RM16;
            } else {
                kind = ext == 2 ? FT_NOT_RM32 : FT_NEG_RM32;
            }
            decoded->fields.kind = kind;
            decoded->fields.id = ext == 2 ? dt_X86_INS_NOT : dt_X86_INS_NEG;
        } else if (ext == 5) {
            if (opcode0 == 0xf6) {
                kind = FT_IMUL_RM8;
            } else if (s->rex_w) {
                kind = FT_IMUL_RM64;
            } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                kind = FT_IMUL_RM16;
            } else {
                kind = FT_IMUL_RM32;
            }
            decoded->fields.kind = kind;
            decoded->fields.id = dt_X86_INS_IMUL;
        } else if ((opcode0 == 0xf6 && (ext == 4 || ext == 6 || ext == 7)) ||
                   (opcode0 == 0xf7 &&
                    (ext == 4 || ext == 6 || ext == 7))) {
            if (ext == 4 && opcode0 == 0xf6) {
                kind = FT_MUL_RM8;
                decoded->fields.id = dt_X86_INS_MUL;
            } else if (ext == 6 && opcode0 == 0xf6) {
                kind = FT_DIV_RM8;
                decoded->fields.id = dt_X86_INS_DIV;
            } else if (ext == 7 && opcode0 == 0xf6) {
                kind = FT_IDIV_RM8;
                decoded->fields.id = dt_X86_INS_IDIV;
            } else if (ext == 4) {
                kind = s->rex_w ? FT_MUL_RM64 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_MUL_RM16 : FT_MUL_RM32;
                decoded->fields.id = dt_X86_INS_MUL;
            } else if (ext == 6) {
                kind = s->rex_w ? FT_DIV_RM64 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_DIV_RM16 : FT_DIV_RM32;
                decoded->fields.id = dt_X86_INS_DIV;
            } else {
                kind = s->rex_w ? FT_IDIV_RM64 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_IDIV_RM16 : FT_IDIV_RM32;
                decoded->fields.id = dt_X86_INS_IDIV;
            }
            decoded->fields.kind = kind;
        } else {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x80 || opcode0 == 0x81 ||
                      opcode0 == 0x83)) {
        FastTemplateKind kind;
        int imm_size;
        int64_t imm;

        if (opcode0 == 0x80) {
            kind = FT_GRP1_RM8_IMM8;
            imm_size = 1;
        } else if (opcode0 == 0x83) {
            kind = s->rex_w ? FT_GRP1_RM64_IMM8 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_GRP1_RM16_IMM8 : FT_GRP1_RM32_IMM8;
            imm_size = 1;
        } else {
            kind = s->rex_w ? FT_GRP1_RM64_IMM32 : FT_GRP1_RM32_IMM32;
            imm_size = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_INVALID);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (((decoded->fields.modrm >> 3) & 7) > 7) {
            return FD_FT_NO_MATCH;
        }
        if ((size_t)(s->pos + imm_size) > s->code_size ||
            !fd_ft_read_simm_at(s->code, s->code_size, s->pos, imm_size,
                                &imm)) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = (opcode0 == 0x80) ? s->code[s->pos] :
                              (int)imm;
        s->pos += imm_size;
        if (!ft_fill_group1_alu_info(&decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0xc0 || opcode0 == 0xc1 ||
                      opcode0 == 0xd0 || opcode0 == 0xd1 ||
                      opcode0 == 0xd2 || opcode0 == 0xd3)) {
        static const int shift_id[8] = {
            dt_X86_INS_ROL, dt_X86_INS_ROR, dt_X86_INS_RCL,
            dt_X86_INS_RCR, dt_X86_INS_SHL, dt_X86_INS_SHR,
            dt_X86_INS_SHL, dt_X86_INS_SAR,
        };
        FastTemplateKind kind = (opcode0 == 0xc0 || opcode0 == 0xc1) ?
                                FT_SHIFT_RM_IMM8 :
                                (opcode0 == 0xd0 || opcode0 == 0xd1) ?
                                FT_SHIFT_RM_ONE : FT_SHIFT_RM_CL;
        int ext;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_INVALID);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (shift_id[ext] == dt_X86_INS_INVALID) {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.id = shift_id[ext];
        if (kind == FT_SHIFT_RM_IMM8) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = s->code[s->pos++];
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0x2d) {
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE ||
            (s->has_rex && s->rex_w)) {
            return FD_FT_NO_MATCH;
        }
        fd_ft_init_fields(&decoded->fields, FT_SUB_EAX_IMM32, s, address,
                          opcode0, 0, dt_X86_INS_SUB);
        if (s->pos + 4 > s->code_size) {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.imm = fd_ft_read_u32(&s->code[s->pos]);
        s->pos += 4;
        fd_ft_set_alu(&decoded->fields, FT_ALU_SUB, FT_ALU_FORM_ACC_IMM, 32);
        return fd_ft_finish_match(decoded, s, FT_SUB_EAX_IMM32, false);
    }

    if (!two_byte && opcode0 == 0xf7 &&
        s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_TEST_RM16_IMM16, s, address,
                          opcode0, 0, dt_X86_INS_TEST);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (((decoded->fields.modrm >> 3) & 7) != 0) {
            return FD_FT_NO_MATCH;
        }
        if (s->pos + 2 > s->code_size) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
        s->pos += 2;
        fd_ft_set_alu(&decoded->fields, FT_ALU_TEST, FT_ALU_FORM_RM_IMM, 16);
        return fd_ft_finish_match(decoded, s, FT_TEST_RM16_IMM16, false);
    }

    if (two_byte && opcode1 == 0xaf && s->rex_w) {
        fd_ft_init_fields(&decoded->fields, FT_IMUL_R64_RM64, s, address,
                          opcode0, opcode1, dt_X86_INS_IMUL);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_IMUL_R64_RM64, false);
    }

    if (two_byte && opcode1 == 0xaf) {
        FastTemplateKind kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                FT_IMUL_R16_RM16 : FT_IMUL_R32_RM32;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, dt_X86_INS_IMUL);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && (opcode0 == 0x69 || opcode0 == 0x6b)) {
        FastTemplateKind kind;
        int imm_size = opcode0 == 0x6b ? 1 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;
        int64_t imm;

        if (s->rex_w) {
            kind = opcode0 == 0x6b ? FT_IMUL_R64_RM64_IMM8 :
                                     FT_IMUL_R64_RM64_IMM32;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = opcode0 == 0x6b ? FT_IMUL_R16_RM16_IMM8 :
                                     FT_IMUL_R16_RM16_IMM16;
        } else {
            kind = opcode0 == 0x6b ? FT_IMUL_R32_RM32_IMM8 :
                                     FT_IMUL_R32_RM32_IMM32;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_IMUL);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            (size_t)(s->pos + imm_size) > s->code_size ||
            !fd_ft_read_simm_at(s->code, s->code_size, s->pos, imm_size,
                                &imm)) {
            return FD_FT_REJECT;
        }
        decoded->fields.imm = (int)imm;
        s->pos += imm_size;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && s->prefix[0] == dt_X86_PREFIX_REP &&
        (opcode1 == 0xbc || opcode1 == 0xbd || opcode1 == 0xb8)) {
        FastTemplateKind kind;
        int id;

        if (opcode1 == 0xbd) {
            kind = s->rex_w ? FT_LZCNT_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_LZCNT_R16_RM16 : FT_LZCNT_R32_RM32;
            id = dt_X86_INS_LZCNT;
        } else if (opcode1 == 0xbc) {
            kind = s->rex_w ? FT_TZCNT_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_TZCNT_R16_RM16 : FT_TZCNT_R32_RM32;
            id = dt_X86_INS_TZCNT;
        } else {
            kind = s->rex_w ? FT_POPCNT_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_POPCNT_R16_RM16 : FT_POPCNT_R32_RM32;
            id = dt_X86_INS_POPCNT;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xbc || opcode1 == 0xbd)) {
        FastTemplateKind kind;

        if (opcode1 == 0xbc) {
            kind = s->rex_w ? FT_BSF_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_BSF_R16_RM16 : FT_BSF_R32_RM32;
        } else {
            kind = s->rex_w ? FT_BSR_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                   FT_BSR_R16_RM16 : FT_BSR_R32_RM32;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, opcode1 == 0xbc ? dt_X86_INS_BSF :
                                                      dt_X86_INS_BSR);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 >= 0xc8 && opcode1 <= 0xcf) {
        FastTemplateKind kind = s->rex_w ? FT_BSWAP_R64 : FT_BSWAP_R32;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, dt_X86_INS_BSWAP);
        decoded->fields.reg = (opcode1 & 7) | (s->rex_b ? 8 : 0);
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xb0 || opcode1 == 0xb1 ||
                     opcode1 == 0xc0 || opcode1 == 0xc1)) {
        FastTemplateKind kind;
        int mod;
        bool is_xadd = opcode1 == 0xc0 || opcode1 == 0xc1;
        bool is_8 = opcode1 == 0xb0 || opcode1 == 0xc0;

        fd_ft_init_fields(&decoded->fields, FT_CMPXCHG_RM8_R8, s, address,
                          opcode0, opcode1,
                          is_xadd ? dt_X86_INS_XADD : dt_X86_INS_CMPXCHG);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        mod = (decoded->fields.modrm >> 6) & 3;
        if (is_xadd) {
            if (is_8) {
                kind = mod == 3 ? FT_XADD_R8_R8 : FT_XADD_RM8_R8;
            } else if (mod == 3) {
                kind = s->rex_w ? FT_XADD_R64_R64 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_XADD_R16_R16 : FT_XADD_R32_R32;
            } else {
                kind = s->rex_w ? FT_XADD_RM64_R64 :
                       s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_XADD_RM16_R16 : FT_XADD_RM32_R32;
            }
        } else if (is_8) {
            kind = FT_CMPXCHG_RM8_R8;
        } else if (s->rex_w) {
            kind = FT_CMPXCHG_RM64_R64;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = FT_CMPXCHG_RM16_R16;
        } else {
            kind = FT_CMPXCHG_RM32_R32;
        }
        decoded->fields.kind = kind;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 >= 0x40 && opcode1 <= 0x4f) {
        static const int cmov_id[16] = {
            dt_X86_INS_CMOVO, dt_X86_INS_CMOVNO,
            dt_X86_INS_CMOVB, dt_X86_INS_CMOVAE,
            dt_X86_INS_CMOVE, dt_X86_INS_CMOVNE,
            dt_X86_INS_CMOVBE, dt_X86_INS_CMOVA,
            dt_X86_INS_CMOVS, dt_X86_INS_CMOVNS,
            dt_X86_INS_CMOVP, dt_X86_INS_CMOVNP,
            dt_X86_INS_CMOVL, dt_X86_INS_CMOVGE,
            dt_X86_INS_CMOVLE, dt_X86_INS_CMOVG,
        };

        FastTemplateKind kind = s->rex_w ? FT_CMOV_R64_RM64 :
                                s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                FT_CMOV_R16_RM16 : FT_CMOV_R32_RM32;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, cmov_id[opcode1 & 0xf]);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xa3 || opcode1 == 0xab ||
                     opcode1 == 0xb3 || opcode1 == 0xbb)) {
        int id = opcode1 == 0xa3 ? dt_X86_INS_BT :
                 opcode1 == 0xab ? dt_X86_INS_BTS :
                 opcode1 == 0xb3 ? dt_X86_INS_BTR : dt_X86_INS_BTC;

        fd_ft_init_fields(&decoded->fields, FT_BTX_RM_R, s, address,
                          opcode0, opcode1, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_BTX_RM_R, false);
    }

    if (two_byte && opcode1 == 0xba) {
        static const int btx_imm_id[4] = {
            dt_X86_INS_BT, dt_X86_INS_BTS,
            dt_X86_INS_BTR, dt_X86_INS_BTC,
        };
        int ext;

        fd_ft_init_fields(&decoded->fields, FT_BTX_RM32_IMM8, s, address,
                          opcode0, opcode1, dt_X86_INS_BT);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext < 4 || ext > 7 || s->pos >= s->code_size) {
            return FD_FT_NO_MATCH;
        }
        decoded->fields.id = btx_imm_id[ext - 4];
        decoded->fields.imm = s->code[s->pos++];
        return fd_ft_finish_match(decoded, s, FT_BTX_RM32_IMM8, false);
    }

    if (!two_byte && opcode0 == 0x63) {
        FastTemplateKind kind = s->rex_w ? FT_MOVSXD_R64_RM32 :
                                s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                FT_MOVSXD_R16_RM16 : FT_MOVSXD_R32_RM32;

        fd_ft_init_fields(&decoded->fields, kind, s, address,
                          opcode0, 0, dt_X86_INS_MOVSXD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xbe || opcode1 == 0xbf)) {
        FastTemplateKind kind;

        if (opcode1 == 0xbe) {
            kind = s->rex_w ? FT_MOVSX_R64_RM8 :
                   (s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                    FT_MOVSX_R16_RM8 : FT_MOVSX_R32_RM8);
        } else {
            kind = s->rex_w ? FT_MOVSX_R64_RM16 :
                   (s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                    FT_MOVSX_R16_RM16 : FT_MOVSX_R32_RM16);
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address,
                          opcode0, opcode1, dt_X86_INS_MOVSX);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xb6 || opcode1 == 0xb7)) {
        FastTemplateKind kind;

        if (opcode1 == 0xb6) {
            kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_MOVZX_R16_RM8 :
                                                          FT_MOVZX_R32_RM8;
        } else {
            kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_MOV_R16_RM16 :
                                                          FT_MOVZX_R32_RM16;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, dt_X86_INS_MOVZX);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (!two_byte && opcode0 == 0xff) {
        int ext;
        FastTemplateKind kind;

        fd_ft_init_fields(&decoded->fields, FT_PUSH_RM64, s, address,
                          opcode0, 0, dt_X86_INS_PUSH);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext != 6) {
            return FD_FT_NO_MATCH;
        }
        kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_PUSH_RM16 :
                                                       FT_PUSH_RM64;
        decoded->fields.kind = kind;
        decoded->fields.alu_width =
            s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : s->mode ? 64 : 32;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && (opcode1 == 0xa4 || opcode1 == 0xa5 ||
                     opcode1 == 0xac || opcode1 == 0xad)) {
        FastTemplateKind kind = opcode1 == 0xa4 ? FT_SHLD_RM_R_IMM8 :
                                opcode1 == 0xa5 ? FT_SHLD_RM_R_CL :
                                opcode1 == 0xac ? FT_SHRD_RM_R_IMM8 :
                                                   FT_SHRD_RM_R_CL;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, opcode1 == 0xa4 || opcode1 == 0xa5 ?
                          dt_X86_INS_SHLD : dt_X86_INS_SHRD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (kind == FT_SHLD_RM_R_IMM8 || kind == FT_SHRD_RM_R_IMM8) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = s->code[s->pos++];
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x38 &&
        s->pos < s->code_size && s->code[s->pos] == 0xf6 &&
        ((s->prefix[0] == dt_X86_PREFIX_REP && s->prefix[2] == 0) ||
         (s->prefix[0] == 0 &&
          s->prefix[2] == dt_X86_PREFIX_OPSIZE))) {
        FastTemplateKind kind;
        uint8_t opcode2 = s->code[s->pos++];
        int id;

        if (s->prefix[0] == dt_X86_PREFIX_REP) {
            kind = s->rex_w ? FT_ADOX_R64_RM64 : FT_ADOX_R32_RM32;
            id = dt_X86_INS_ADOX;
        } else {
            kind = s->rex_w ? FT_ADCX_R64_RM64 : FT_ADCX_R32_RM32;
            id = dt_X86_INS_ADCX;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode2, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x38 &&
        s->prefix[0] == dt_X86_PREFIX_REPNE &&
        s->pos < s->code_size &&
        (s->code[s->pos] == 0xf0 || s->code[s->pos] == 0xf1)) {
        FastTemplateKind kind;
        uint8_t opcode2 = s->code[s->pos++];

        if (opcode2 == 0xf0) {
            kind = FT_CRC32_R_RM8;
        } else if (s->rex_w) {
            kind = FT_CRC32_R_RM64;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = FT_CRC32_R_RM16;
        } else {
            kind = FT_CRC32_R_RM32;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode2, dt_X86_INS_CRC32);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x38 &&
        s->pos < s->code_size &&
        (s->code[s->pos] == 0xf0 || s->code[s->pos] == 0xf1)) {
        FastTemplateKind kind;
        uint8_t opcode2 = s->code[s->pos++];
        bool store = opcode2 == 0xf1;

        if (s->rex_w) {
            kind = store ? FT_MOVBE_M64_R64 : FT_MOVBE_R64_M64;
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            kind = store ? FT_MOVBE_M16_R16 : FT_MOVBE_R16_M16;
        } else {
            kind = store ? FT_MOVBE_M32_R32 : FT_MOVBE_R32_M32;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode2, dt_X86_INS_MOVBE);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            ((decoded->fields.modrm >> 6) & 3) == 3) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0xc7) {
        int ext;
        FastTemplateKind kind;

        fd_ft_init_fields(&decoded->fields, FT_RDRAND_R32, s, address,
                          opcode0, opcode1, dt_X86_INS_RDRAND);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        ext = (decoded->fields.modrm >> 3) & 7;
        if (ext == 1 && ((decoded->fields.modrm >> 6) & 3) != 3) {
            kind = s->rex_w ? FT_CMPXCHG16B : FT_CMPXCHG8B;
            decoded->fields.kind = kind;
            decoded->fields.id = s->rex_w ? dt_X86_INS_CMPXCHG16B :
                                           dt_X86_INS_CMPXCHG8B;
            return fd_ft_finish_match(decoded, s, kind, false);
        }
        if (ext != 6 || ((decoded->fields.modrm >> 6) & 3) != 3) {
            return FD_FT_NO_MATCH;
        }
        kind = s->rex_w ? FT_RDRAND_R64 :
               s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_RDRAND_R16 :
               FT_RDRAND_R32;
        decoded->fields.kind = kind;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0xc3) {
        fd_ft_init_fields(&decoded->fields, FT_MOVNTI_M_R, s, address,
                          opcode0, opcode1, dt_X86_INS_MOVNTI);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        if (((decoded->fields.modrm >> 6) & 3) == 3) {
            return FD_FT_NO_MATCH;
        }
        return fd_ft_finish_match(decoded, s, FT_MOVNTI_M_R, false);
    }

    return FD_FT_NO_MATCH;
}
