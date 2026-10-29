/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static inline int fd_ft_x87_const_id(uint8_t modrm)
{
    switch (modrm) {
    case 0xe9:
        return dt_X86_INS_FLDL2T;
    case 0xea:
        return dt_X86_INS_FLDL2E;
    case 0xeb:
        return dt_X86_INS_FLDPI;
    case 0xec:
        return dt_X86_INS_FLDLG2;
    case 0xed:
        return dt_X86_INS_FLDLN2;
    case 0xee:
        return dt_X86_INS_FLDZ;
    default:
        return dt_X86_INS_INVALID;
    }
}

static inline int fd_ft_x87_fcmov_id(uint8_t opcode0, int ext)
{
    static const int da_id[4] = {
        dt_X86_INS_FCMOVB, dt_X86_INS_FCMOVE,
        dt_X86_INS_FCMOVBE, dt_X86_INS_FCMOVU,
    };
    static const int db_id[4] = {
        dt_X86_INS_FCMOVNB, dt_X86_INS_FCMOVNE,
        dt_X86_INS_FCMOVNBE, dt_X86_INS_FCMOVNU,
    };

    if (ext < 0 || ext > 3) {
        return dt_X86_INS_INVALID;
    }
    return opcode0 == 0xda ? da_id[ext] : db_id[ext];
}

static inline int fd_ft_x87_mem_id(uint8_t opcode0, int ext)
{
    switch (opcode0) {
    case 0xd8:
        switch (ext) {
        case 0:
            return dt_X86_INS_FADD;
        case 1:
            return dt_X86_INS_FMUL;
        case 2:
            return dt_X86_INS_FCOM;
        case 3:
            return dt_X86_INS_FCOMP;
        case 4:
            return dt_X86_INS_FSUB;
        case 5:
            return dt_X86_INS_FSUBR;
        case 6:
            return dt_X86_INS_FDIV;
        case 7:
            return dt_X86_INS_FDIVR;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xd9:
        switch (ext) {
        case 0:
            return dt_X86_INS_FLD;
        case 2:
            return dt_X86_INS_FST;
        case 3:
            return dt_X86_INS_FSTP;
        case 4:
            return dt_X86_INS_FLDENV;
        case 5:
            return dt_X86_INS_FLDCW;
        case 6:
            return dt_X86_INS_FNSTENV;
        case 7:
            return dt_X86_INS_FNSTCW;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xda:
        switch (ext) {
        case 0:
            return dt_X86_INS_FIADD;
        case 1:
            return dt_X86_INS_FIMUL;
        case 2:
            return dt_X86_INS_FICOM;
        case 3:
            return dt_X86_INS_FICOMP;
        case 4:
            return dt_X86_INS_FISUB;
        case 5:
            return dt_X86_INS_FISUBR;
        case 6:
            return dt_X86_INS_FIDIV;
        case 7:
            return dt_X86_INS_FIDIVR;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xdb:
        switch (ext) {
        case 0:
            return dt_X86_INS_FILD;
        case 1:
            return dt_X86_INS_FISTTP;
        case 2:
            return dt_X86_INS_FIST;
        case 3:
            return dt_X86_INS_FISTP;
        case 5:
            return dt_X86_INS_FLD;
        case 7:
            return dt_X86_INS_FSTP;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xdc:
        switch (ext) {
        case 0:
            return dt_X86_INS_FADD;
        case 1:
            return dt_X86_INS_FMUL;
        case 2:
            return dt_X86_INS_FCOM;
        case 3:
            return dt_X86_INS_FCOMP;
        case 4:
            return dt_X86_INS_FSUB;
        case 5:
            return dt_X86_INS_FSUBR;
        case 6:
            return dt_X86_INS_FDIV;
        case 7:
            return dt_X86_INS_FDIVR;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xdd:
        switch (ext) {
        case 0:
            return dt_X86_INS_FLD;
        case 1:
            return dt_X86_INS_FISTTP;
        case 2:
            return dt_X86_INS_FST;
        case 3:
            return dt_X86_INS_FSTP;
        case 4:
            return dt_X86_INS_FRSTOR;
        case 6:
            return dt_X86_INS_FNSAVE;
        case 7:
            return dt_X86_INS_FNSTSW;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xde:
        switch (ext) {
        case 0:
            return dt_X86_INS_FIADD;
        case 1:
            return dt_X86_INS_FIMUL;
        case 2:
            return dt_X86_INS_FICOM;
        case 3:
            return dt_X86_INS_FICOMP;
        case 4:
            return dt_X86_INS_FISUB;
        case 5:
            return dt_X86_INS_FISUBR;
        case 6:
            return dt_X86_INS_FIDIV;
        case 7:
            return dt_X86_INS_FIDIVR;
        default:
            return dt_X86_INS_INVALID;
        }
    case 0xdf:
        switch (ext) {
        case 0:
            return dt_X86_INS_FILD;
        case 1:
            return dt_X86_INS_FISTTP;
        case 2:
            return dt_X86_INS_FIST;
        case 3:
            return dt_X86_INS_FISTP;
        case 4:
            return dt_X86_INS_FBLD;
        case 5:
            return dt_X86_INS_FILD;
        case 6:
            return dt_X86_INS_FBSTP;
        case 7:
            return dt_X86_INS_FISTP;
        default:
            return dt_X86_INS_INVALID;
        }
    default:
        return dt_X86_INS_INVALID;
    }
}

static inline bool fd_ft_x87_memory_kind(uint8_t opcode0, int ext,
                                         FastTemplateKind *kind)
{
    switch (opcode0) {
    case 0xd8:
        if (ext == 0 || ext == 1 || ext >= 4) {
            *kind = FT_X87_BIN_M32;
        } else if (ext == 2 || ext == 3) {
            *kind = FT_X87_FCOM_M32;
        } else {
            return false;
        }
        return true;
    case 0xd9:
        if (ext == 0) {
            *kind = FT_X87_FLD_M32;
        } else if (ext == 2) {
            *kind = FT_X87_FST_M32;
        } else if (ext == 3) {
            *kind = FT_X87_FSTP_M32;
        } else if (ext == 4) {
            *kind = FT_HELPER_FLDENV;
        } else if (ext == 5) {
            *kind = FT_X87_FLDCW_M16;
        } else if (ext == 6) {
            *kind = FT_HELPER_FNSTENV;
        } else if (ext == 7) {
            *kind = FT_X87_FNSTCW_M16;
        } else {
            return false;
        }
        return true;
    case 0xda:
        *kind = FT_X87_FI_BIN_M32;
        return true;
    case 0xdb:
        if (ext == 0) {
            *kind = FT_X87_FILD_M32;
        } else if (ext == 1) {
            *kind = FT_X87_FISTTP_M32;
        } else if (ext == 2) {
            *kind = FT_X87_FIST_M32;
        } else if (ext == 3) {
            *kind = FT_X87_FISTP_M32;
        } else if (ext == 5) {
            *kind = FT_X87_FLD_M80;
        } else if (ext == 7) {
            *kind = FT_X87_FSTP_M80;
        } else {
            return false;
        }
        return true;
    case 0xdc:
        if (ext == 0 || ext == 1 || ext >= 4) {
            *kind = FT_X87_BIN_M64;
        } else if (ext == 2 || ext == 3) {
            *kind = FT_X87_FCOM_M64;
        } else {
            return false;
        }
        return true;
    case 0xdd:
        if (ext == 0) {
            *kind = FT_X87_FLD_M64;
        } else if (ext == 1) {
            *kind = FT_X87_FISTTP_M64;
        } else if (ext == 2) {
            *kind = FT_X87_FST_M64;
        } else if (ext == 3) {
            *kind = FT_X87_FSTP_M64;
        } else if (ext == 4) {
            *kind = FT_HELPER_FRSTOR;
        } else if (ext == 6) {
            *kind = FT_HELPER_FNSAVE;
        } else if (ext == 7) {
            *kind = FT_X87_FNSTSW_M16;
        } else {
            return false;
        }
        return true;
    case 0xde:
        *kind = FT_X87_FI_BIN_M16;
        return true;
    case 0xdf:
        if (ext == 0) {
            *kind = FT_X87_FILD_M16;
        } else if (ext == 1) {
            *kind = FT_X87_FISTTP_M16;
        } else if (ext == 2) {
            *kind = FT_X87_FIST_M16;
        } else if (ext == 3) {
            *kind = FT_X87_FISTP_M16;
        } else if (ext == 4) {
            *kind = FT_X87_FBLD;
        } else if (ext == 5) {
            *kind = FT_X87_FILD_M64;
        } else if (ext == 6) {
            *kind = FT_X87_FBSTP;
        } else if (ext == 7) {
            *kind = FT_X87_FISTP_M64;
        } else {
            return false;
        }
        return true;
    default:
        return false;
    }
}

static inline bool fd_ft_x87_register_kind(uint8_t opcode0, uint8_t modrm,
                                           FastTemplateKind *kind, int *id)
{
    switch (opcode0) {
    case 0xd8:
        switch ((modrm >> 3) & 7) {
        case 0: *id = dt_X86_INS_FADD; break;
        case 1: *id = dt_X86_INS_FMUL; break;
        case 4: *id = dt_X86_INS_FSUB; break;
        case 5: *id = dt_X86_INS_FSUBR; break;
        case 6: *id = dt_X86_INS_FDIV; break;
        case 7: *id = dt_X86_INS_FDIVR; break;
        default: *id = dt_X86_INS_INVALID; break;
        }
        if (*id != dt_X86_INS_INVALID) {
            *kind = FT_X87_BIN_REG;
            return true;
        }
        if (modrm >= 0xd0 && modrm <= 0xd7) {
            *kind = FT_X87_FCOM_REG;
            *id = dt_X86_INS_FCOM;
            return true;
        }
        if (modrm >= 0xd8 && modrm <= 0xdf) {
            *kind = FT_X87_FCOMP_REG;
            *id = dt_X86_INS_FCOMP;
            return true;
        }
        return false;
    case 0xd9:
        if (modrm >= 0xc0 && modrm <= 0xc7) {
            *kind = FT_X87_FLD_REG;
            *id = dt_X86_INS_FLD;
            return true;
        }
        if (modrm >= 0xc8 && modrm <= 0xcf) {
            *kind = FT_X87_FXCH;
            *id = dt_X86_INS_FXCH;
            return true;
        }
        if (modrm >= 0xd8 && modrm <= 0xdf) {
            *kind = FT_X87_FSTP_REG;
            *id = dt_X86_INS_FSTPNCE;
            return true;
        }
        switch (modrm) {
        case 0xd0:
            *kind = FT_NOP_MULTI;
            *id = dt_X86_INS_FNOP;
            return true;
        case 0xe0:
            *kind = FT_X87_UNARY;
            *id = dt_X86_INS_FCHS;
            return true;
        case 0xe1:
            *kind = FT_X87_UNARY;
            *id = dt_X86_INS_FABS;
            return true;
        case 0xe4:
            *kind = FT_X87_FTST;
            *id = dt_X86_INS_FTST;
            return true;
        case 0xe5:
            *kind = FT_X87_FXAM;
            *id = dt_X86_INS_FXAM;
            return true;
        case 0xe8:
            *kind = FT_X87_FLD1;
            *id = dt_X86_INS_FLD1;
            return true;
        case 0xf0:
            *kind = FT_X87_F2XM1;
            *id = dt_X86_INS_F2XM1;
            return true;
        case 0xf1:
            *kind = FT_X87_FYL2X;
            *id = dt_X86_INS_FYL2X;
            return true;
        case 0xf2:
            *kind = FT_X87_FPTAN;
            *id = dt_X86_INS_FPTAN;
            return true;
        case 0xf3:
            *kind = FT_X87_FPATAN;
            *id = dt_X86_INS_FPATAN;
            return true;
        case 0xf4:
            *kind = FT_X87_FXTRACT;
            *id = dt_X86_INS_FXTRACT;
            return true;
        case 0xf5:
            *kind = FT_X87_FPREM1;
            *id = dt_X86_INS_FPREM1;
            return true;
        case 0xf6:
            *kind = FT_X87_TOP_ADJ;
            *id = dt_X86_INS_FDECSTP;
            return true;
        case 0xf7:
            *kind = FT_X87_TOP_ADJ;
            *id = dt_X86_INS_FINCSTP;
            return true;
        case 0xf8:
            *kind = FT_X87_FPREM;
            *id = dt_X86_INS_FPREM;
            return true;
        case 0xf9:
            *kind = FT_X87_FYL2XP1;
            *id = dt_X86_INS_FYL2XP1;
            return true;
        case 0xfa:
            *kind = FT_X87_FSQRT;
            *id = dt_X86_INS_FSQRT;
            return true;
        case 0xfb:
            *kind = FT_X87_FSINCOS;
            *id = dt_X86_INS_FSINCOS;
            return true;
        case 0xfc:
            *kind = FT_X87_FRNDINT;
            *id = dt_X86_INS_FRNDINT;
            return true;
        case 0xfd:
            *kind = FT_X87_FSCALE;
            *id = dt_X86_INS_FSCALE;
            return true;
        case 0xfe:
            *kind = FT_X87_FSIN;
            *id = dt_X86_INS_FSIN;
            return true;
        case 0xff:
            *kind = FT_X87_FCOS;
            *id = dt_X86_INS_FCOS;
            return true;
        default:
            *id = fd_ft_x87_const_id(modrm);
            if (*id != dt_X86_INS_INVALID) {
                *kind = FT_X87_FLD_CONST;
                return true;
            }
            return false;
        }
    case 0xda:
        if (modrm == 0xe9) {
            *kind = FT_X87_FUCOMPP;
            *id = dt_X86_INS_FUCOMPP;
            return true;
        }
        if (modrm >= 0xc0 && modrm <= 0xdf) {
            *kind = FT_X87_FCMOVCC;
            *id = fd_ft_x87_fcmov_id(opcode0, (modrm >> 3) & 3);
            return *id != dt_X86_INS_INVALID;
        }
        return false;
    case 0xdb:
        if (modrm == 0xe4) {
            *kind = FT_NOP_MULTI;
            *id = dt_X86_INS_FSETPM;
            return true;
        }
        if (modrm == 0xe2) {
            *kind = FT_FNCLEX;
            *id = dt_X86_INS_FNCLEX;
            return true;
        }
        if (modrm == 0xe3) {
            *kind = FT_FNINIT;
            *id = dt_X86_INS_FNINIT;
            return true;
        }
        if (modrm >= 0xf0 && modrm <= 0xf7) {
            *kind = FT_X87_FCOMI_REG;
            *id = dt_X86_INS_FCOMI;
            return true;
        }
        if (modrm >= 0xe8 && modrm <= 0xef) {
            *kind = FT_X87_FCOMI_REG;
            *id = dt_X86_INS_FUCOMI;
            return true;
        }
        if (modrm >= 0xc0 && modrm <= 0xdf) {
            *kind = FT_X87_FCMOVCC;
            *id = fd_ft_x87_fcmov_id(opcode0, (modrm >> 3) & 3);
            return *id != dt_X86_INS_INVALID;
        }
        return false;
    case 0xdc:
        switch ((modrm >> 3) & 7) {
        case 0: *id = dt_X86_INS_FADD; break;
        case 1: *id = dt_X86_INS_FMUL; break;
        case 4: *id = dt_X86_INS_FSUBR; break;
        case 5: *id = dt_X86_INS_FSUB; break;
        case 6: *id = dt_X86_INS_FDIVR; break;
        case 7: *id = dt_X86_INS_FDIV; break;
        default: *id = dt_X86_INS_INVALID; break;
        }
        if (*id != dt_X86_INS_INVALID) {
            *kind = FT_X87_BIN_REG;
            return true;
        }
        return false;
    case 0xdd:
        if (modrm >= 0xc0 && modrm <= 0xc7) {
            *kind = FT_X87_FFREE;
            *id = dt_X86_INS_FFREE;
            return true;
        }
        if (modrm >= 0xd0 && modrm <= 0xd7) {
            *kind = FT_X87_FST_REG;
            *id = dt_X86_INS_FST;
            return true;
        }
        if (modrm >= 0xd8 && modrm <= 0xdf) {
            *kind = FT_X87_FSTP_REG;
            *id = dt_X86_INS_FSTP;
            return true;
        }
        if (modrm >= 0xe0 && modrm <= 0xe7) {
            *kind = FT_X87_FCOM_REG;
            *id = dt_X86_INS_FUCOM;
            return true;
        }
        if (modrm >= 0xe8 && modrm <= 0xef) {
            *kind = FT_X87_FCOMP_REG;
            *id = dt_X86_INS_FUCOMP;
            return true;
        }
        return false;
    case 0xde:
        if (modrm >= 0xc0 && modrm <= 0xc7) {
            *kind = FT_X87_FADDP;
            *id = dt_X86_INS_FADDP;
            return true;
        }
        if (modrm >= 0xc8 && modrm <= 0xcf) {
            *kind = FT_X87_FMULP;
            *id = dt_X86_INS_FMULP;
            return true;
        }
        if (modrm == 0xd9) {
            *kind = FT_X87_FCOMPP;
            *id = dt_X86_INS_FCOMPP;
            return true;
        }
        if (modrm >= 0xe0 && modrm <= 0xe7) {
            *kind = FT_X87_FSUBRP;
            *id = dt_X86_INS_FSUBR;
            return true;
        }
        if (modrm >= 0xe8 && modrm <= 0xef) {
            *kind = FT_X87_FSUBP;
            *id = dt_X86_INS_FSUBP;
            return true;
        }
        if (modrm >= 0xf0 && modrm <= 0xf7) {
            *kind = FT_X87_FDIVRP;
            *id = dt_X86_INS_FDIVR;
            return true;
        }
        if (modrm >= 0xf8) {
            *kind = FT_X87_FDIVP;
            *id = dt_X86_INS_FDIVP;
            return true;
        }
        return false;
    case 0xdf:
        if (modrm >= 0xc0 && modrm <= 0xc7) {
            *kind = FT_X87_FFREE;
            *id = dt_X86_INS_FFREEP;
            return true;
        }
        if (modrm == 0xe0) {
            *kind = FT_X87_FSTSW_AX;
            *id = dt_X86_INS_FST;
            return true;
        }
        if (modrm >= 0xf0 && modrm <= 0xf7) {
            *kind = FT_X87_FCOMIP_REG;
            *id = dt_X86_INS_FCOMIP;
            return true;
        }
        if (modrm >= 0xe8 && modrm <= 0xef) {
            *kind = FT_X87_FCOMIP_REG;
            *id = dt_X86_INS_FUCOMIP;
            return true;
        }
        return false;
    default:
        return false;
    }
}

static inline FastDecoderFTMatch fd_ft_try_x87(FDState *s, uint8_t opcode0,
                                               uint8_t opcode1, bool two_byte,
                                               uint64_t address,
                                               FastDecodedFT *decoded)
{
    FastTemplateKind kind;
    int id;
    int ext;

    (void)opcode1;
    if (two_byte || opcode0 < 0xd8 || opcode0 > 0xdf) {
        return FD_FT_NO_MATCH;
    }

    fd_ft_init_fields(&decoded->fields, FT_UNSUPPORTED, s, address, opcode0,
                      0, dt_X86_INS_INVALID);
    if (!fd_ft_read_modrm(s, &decoded->fields)) {
        return FD_FT_REJECT;
    }

    if (((decoded->fields.modrm >> 6) & 3) == 3) {
        if (!fd_ft_x87_register_kind(opcode0, decoded->fields.modrm, &kind,
                                     &id)) {
            return FD_FT_NO_MATCH;
        }
    } else {
        ext = (decoded->fields.modrm >> 3) & 7;
        if (!fd_ft_x87_memory_kind(opcode0, ext, &kind)) {
            return FD_FT_NO_MATCH;
        }
        id = fd_ft_x87_mem_id(opcode0, ext);
        if (id == dt_X86_INS_INVALID) {
            return FD_FT_NO_MATCH;
        }
    }

    decoded->fields.kind = kind;
    decoded->fields.id = id;
    return fd_ft_finish_match(decoded, s, kind,
                              kind == FT_HELPER_FRSTOR ||
                              kind == FT_HELPER_FLDENV);
}
