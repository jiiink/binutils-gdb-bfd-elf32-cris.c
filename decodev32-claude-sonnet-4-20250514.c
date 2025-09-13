/* Simulator instruction decoder for crisv32f.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright (C) 1996-2025 Free Software Foundation, Inc.

This file is part of the GNU simulators.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#define WANT_CPU crisv32f
#define WANT_CPU_CRISV32F

#include "sim-main.h"
#include "sim-assert.h"
#include "cgen-mem.h"
#include "cgen-ops.h"

/* The instruction descriptor array.
   This is computed at runtime.  Space for it is not malloc'd to save a
   teensy bit of cpu in the decoder.  Moving it to malloc space is trivial
   but won't be done until necessary (we don't currently support the runtime
   addition of instructions nor an SMP machine with different cpus).  */
static IDESC crisv32f_insn_data[CRISV32F_INSN__MAX];

/* Commas between elements are contained in the macros.
   Some of these are conditionally compiled out.  */

static const struct insn_sem crisv32f_insn_sem[] =
{
  { VIRTUAL_INSN_X_INVALID, CRISV32F_INSN_X_INVALID, CRISV32F_SFMT_EMPTY },
  { VIRTUAL_INSN_X_AFTER, CRISV32F_INSN_X_AFTER, CRISV32F_SFMT_EMPTY },
  { VIRTUAL_INSN_X_BEFORE, CRISV32F_INSN_X_BEFORE, CRISV32F_SFMT_EMPTY },
  { VIRTUAL_INSN_X_CTI_CHAIN, CRISV32F_INSN_X_CTI_CHAIN, CRISV32F_SFMT_EMPTY },
  { VIRTUAL_INSN_X_CHAIN, CRISV32F_INSN_X_CHAIN, CRISV32F_SFMT_EMPTY },
  { VIRTUAL_INSN_X_BEGIN, CRISV32F_INSN_X_BEGIN, CRISV32F_SFMT_EMPTY },
  { CRIS_INSN_MOVE_B_R, CRISV32F_INSN_MOVE_B_R, CRISV32F_SFMT_MOVE_B_R },
  { CRIS_INSN_MOVE_W_R, CRISV32F_INSN_MOVE_W_R, CRISV32F_SFMT_MOVE_B_R },
  { CRIS_INSN_MOVE_D_R, CRISV32F_INSN_MOVE_D_R, CRISV32F_SFMT_MOVE_D_R },
  { CRIS_INSN_MOVEQ, CRISV32F_INSN_MOVEQ, CRISV32F_SFMT_MOVEQ },
  { CRIS_INSN_MOVS_B_R, CRISV32F_INSN_MOVS_B_R, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_MOVS_W_R, CRISV32F_INSN_MOVS_W_R, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_MOVU_B_R, CRISV32F_INSN_MOVU_B_R, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_MOVU_W_R, CRISV32F_INSN_MOVU_W_R, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_MOVECBR, CRISV32F_INSN_MOVECBR, CRISV32F_SFMT_MOVECBR },
  { CRIS_INSN_MOVECWR, CRISV32F_INSN_MOVECWR, CRISV32F_SFMT_MOVECWR },
  { CRIS_INSN_MOVECDR, CRISV32F_INSN_MOVECDR, CRISV32F_SFMT_MOVECDR },
  { CRIS_INSN_MOVSCBR, CRISV32F_INSN_MOVSCBR, CRISV32F_SFMT_MOVSCBR },
  { CRIS_INSN_MOVSCWR, CRISV32F_INSN_MOVSCWR, CRISV32F_SFMT_MOVSCWR },
  { CRIS_INSN_MOVUCBR, CRISV32F_INSN_MOVUCBR, CRISV32F_SFMT_MOVUCBR },
  { CRIS_INSN_MOVUCWR, CRISV32F_INSN_MOVUCWR, CRISV32F_SFMT_MOVUCWR },
  { CRIS_INSN_ADDQ, CRISV32F_INSN_ADDQ, CRISV32F_SFMT_ADDQ },
  { CRIS_INSN_SUBQ, CRISV32F_INSN_SUBQ, CRISV32F_SFMT_ADDQ },
  { CRIS_INSN_CMP_R_B_R, CRISV32F_INSN_CMP_R_B_R, CRISV32F_SFMT_CMP_R_B_R },
  { CRIS_INSN_CMP_R_W_R, CRISV32F_INSN_CMP_R_W_R, CRISV32F_SFMT_CMP_R_B_R },
  { CRIS_INSN_CMP_R_D_R, CRISV32F_INSN_CMP_R_D_R, CRISV32F_SFMT_CMP_R_B_R },
  { CRIS_INSN_CMP_M_B_M, CRISV32F_INSN_CMP_M_B_M, CRISV32F_SFMT_CMP_M_B_M },
  { CRIS_INSN_CMP_M_W_M, CRISV32F_INSN_CMP_M_W_M, CRISV32F_SFMT_CMP_M_W_M },
  { CRIS_INSN_CMP_M_D_M, CRISV32F_INSN_CMP_M_D_M, CRISV32F_SFMT_CMP_M_D_M },
  { CRIS_INSN_CMPCBR, CRISV32F_INSN_CMPCBR, CRISV32F_SFMT_CMPCBR },
  { CRIS_INSN_CMPCWR, CRISV32F_INSN_CMPCWR, CRISV32F_SFMT_CMPCWR },
  { CRIS_INSN_CMPCDR, CRISV32F_INSN_CMPCDR, CRISV32F_SFMT_CMPCDR },
  { CRIS_INSN_CMPQ, CRISV32F_INSN_CMPQ, CRISV32F_SFMT_CMPQ },
  { CRIS_INSN_CMPS_M_B_M, CRISV32F_INSN_CMPS_M_B_M, CRISV32F_SFMT_CMP_M_B_M },
  { CRIS_INSN_CMPS_M_W_M, CRISV32F_INSN_CMPS_M_W_M, CRISV32F_SFMT_CMP_M_W_M },
  { CRIS_INSN_CMPSCBR, CRISV32F_INSN_CMPSCBR, CRISV32F_SFMT_CMPCBR },
  { CRIS_INSN_CMPSCWR, CRISV32F_INSN_CMPSCWR, CRISV32F_SFMT_CMPCWR },
  { CRIS_INSN_CMPU_M_B_M, CRISV32F_INSN_CMPU_M_B_M, CRISV32F_SFMT_CMP_M_B_M },
  { CRIS_INSN_CMPU_M_W_M, CRISV32F_INSN_CMPU_M_W_M, CRISV32F_SFMT_CMP_M_W_M },
  { CRIS_INSN_CMPUCBR, CRISV32F_INSN_CMPUCBR, CRISV32F_SFMT_CMPUCBR },
  { CRIS_INSN_CMPUCWR, CRISV32F_INSN_CMPUCWR, CRISV32F_SFMT_CMPUCWR },
  { CRIS_INSN_MOVE_M_B_M, CRISV32F_INSN_MOVE_M_B_M, CRISV32F_SFMT_MOVE_M_B_M },
  { CRIS_INSN_MOVE_M_W_M, CRISV32F_INSN_MOVE_M_W_M, CRISV32F_SFMT_MOVE_M_W_M },
  { CRIS_INSN_MOVE_M_D_M, CRISV32F_INSN_MOVE_M_D_M, CRISV32F_SFMT_MOVE_M_D_M },
  { CRIS_INSN_MOVS_M_B_M, CRISV32F_INSN_MOVS_M_B_M, CRISV32F_SFMT_MOVS_M_B_M },
  { CRIS_INSN_MOVS_M_W_M, CRISV32F_INSN_MOVS_M_W_M, CRISV32F_SFMT_MOVS_M_W_M },
  { CRIS_INSN_MOVU_M_B_M, CRISV32F_INSN_MOVU_M_B_M, CRISV32F_SFMT_MOVS_M_B_M },
  { CRIS_INSN_MOVU_M_W_M, CRISV32F_INSN_MOVU_M_W_M, CRISV32F_SFMT_MOVS_M_W_M },
  { CRIS_INSN_MOVE_R_SPRV32, CRISV32F_INSN_MOVE_R_SPRV32, CRISV32F_SFMT_MOVE_R_SPRV32 },
  { CRIS_INSN_MOVE_SPR_RV32, CRISV32F_INSN_MOVE_SPR_RV32, CRISV32F_SFMT_MOVE_SPR_RV32 },
  { CRIS_INSN_MOVE_M_SPRV32, CRISV32F_INSN_MOVE_M_SPRV32, CRISV32F_SFMT_MOVE_M_SPRV32 },
  { CRIS_INSN_MOVE_C_SPRV32_P2, CRISV32F_INSN_MOVE_C_SPRV32_P2, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P3, CRISV32F_INSN_MOVE_C_SPRV32_P3, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P5, CRISV32F_INSN_MOVE_C_SPRV32_P5, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P6, CRISV32F_INSN_MOVE_C_SPRV32_P6, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P7, CRISV32F_INSN_MOVE_C_SPRV32_P7, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P9, CRISV32F_INSN_MOVE_C_SPRV32_P9, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P10, CRISV32F_INSN_MOVE_C_SPRV32_P10, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P11, CRISV32F_INSN_MOVE_C_SPRV32_P11, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P12, CRISV32F_INSN_MOVE_C_SPRV32_P12, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P13, CRISV32F_INSN_MOVE_C_SPRV32_P13, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P14, CRISV32F_INSN_MOVE_C_SPRV32_P14, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_C_SPRV32_P15, CRISV32F_INSN_MOVE_C_SPRV32_P15, CRISV32F_SFMT_MOVE_C_SPRV32_P2 },
  { CRIS_INSN_MOVE_SPR_MV32, CRISV32F_INSN_MOVE_SPR_MV32, CRISV32F_SFMT_MOVE_SPR_MV32 },
  { CRIS_INSN_MOVE_SS_R, CRISV32F_INSN_MOVE_SS_R, CRISV32F_SFMT_MOVE_SS_R },
  { CRIS_INSN_MOVE_R_SS, CRISV32F_INSN_MOVE_R_SS, CRISV32F_SFMT_MOVE_R_SS },
  { CRIS_INSN_MOVEM_R_M_V32, CRISV32F_INSN_MOVEM_R_M_V32, CRISV32F_SFMT_MOVEM_R_M_V32 },
  { CRIS_INSN_MOVEM_M_R_V32, CRISV32F_INSN_MOVEM_M_R_V32, CRISV32F_SFMT_MOVEM_M_R_V32 },
  { CRIS_INSN_ADD_B_R, CRISV32F_INSN_ADD_B_R, CRISV32F_SFMT_ADD_B_R },
  { CRIS_INSN_ADD_W_R, CRISV32F_INSN_ADD_W_R, CRISV32F_SFMT_ADD_B_R },
  { CRIS_INSN_ADD_D_R, CRISV32F_INSN_ADD_D_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADD_M_B_M, CRISV32F_INSN_ADD_M_B_M, CRISV32F_SFMT_ADD_M_B_M },
  { CRIS_INSN_ADD_M_W_M, CRISV32F_INSN_ADD_M_W_M, CRISV32F_SFMT_ADD_M_W_M },
  { CRIS_INSN_ADD_M_D_M, CRISV32F_INSN_ADD_M_D_M, CRISV32F_SFMT_ADD_M_D_M },
  { CRIS_INSN_ADDCBR, CRISV32F_INSN_ADDCBR, CRISV32F_SFMT_ADDCBR },
  { CRIS_INSN_ADDCWR, CRISV32F_INSN_ADDCWR, CRISV32F_SFMT_ADDCWR },
  { CRIS_INSN_ADDCDR, CRISV32F_INSN_ADDCDR, CRISV32F_SFMT_ADDCDR },
  { CRIS_INSN_ADDS_B_R, CRISV32F_INSN_ADDS_B_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADDS_W_R, CRISV32F_INSN_ADDS_W_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADDS_M_B_M, CRISV32F_INSN_ADDS_M_B_M, CRISV32F_SFMT_ADDS_M_B_M },
  { CRIS_INSN_ADDS_M_W_M, CRISV32F_INSN_ADDS_M_W_M, CRISV32F_SFMT_ADDS_M_W_M },
  { CRIS_INSN_ADDSCBR, CRISV32F_INSN_ADDSCBR, CRISV32F_SFMT_ADDSCBR },
  { CRIS_INSN_ADDSCWR, CRISV32F_INSN_ADDSCWR, CRISV32F_SFMT_ADDSCWR },
  { CRIS_INSN_ADDU_B_R, CRISV32F_INSN_ADDU_B_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADDU_W_R, CRISV32F_INSN_ADDU_W_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADDU_M_B_M, CRISV32F_INSN_ADDU_M_B_M, CRISV32F_SFMT_ADDS_M_B_M },
  { CRIS_INSN_ADDU_M_W_M, CRISV32F_INSN_ADDU_M_W_M, CRISV32F_SFMT_ADDS_M_W_M },
  { CRIS_INSN_ADDUCBR, CRISV32F_INSN_ADDUCBR, CRISV32F_SFMT_ADDSCBR },
  { CRIS_INSN_ADDUCWR, CRISV32F_INSN_ADDUCWR, CRISV32F_SFMT_ADDSCWR },
  { CRIS_INSN_SUB_B_R, CRISV32F_INSN_SUB_B_R, CRISV32F_SFMT_ADD_B_R },
  { CRIS_INSN_SUB_W_R, CRISV32F_INSN_SUB_W_R, CRISV32F_SFMT_ADD_B_R },
  { CRIS_INSN_SUB_D_R, CRISV32F_INSN_SUB_D_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_SUB_M_B_M, CRISV32F_INSN_SUB_M_B_M, CRISV32F_SFMT_ADD_M_B_M },
  { CRIS_INSN_SUB_M_W_M, CRISV32F_INSN_SUB_M_W_M, CRISV32F_SFMT_ADD_M_W_M },
  { CRIS_INSN_SUB_M_D_M, CRISV32F_INSN_SUB_M_D_M, CRISV32F_SFMT_ADD_M_D_M },
  { CRIS_INSN_SUBCBR, CRISV32F_INSN_SUBCBR, CRISV32F_SFMT_ADDCBR },
  { CRIS_INSN_SUBCWR, CRISV32F_INSN_SUBCWR, CRISV32F_SFMT_ADDCWR },
  { CRIS_INSN_SUBCDR, CRISV32F_INSN_SUBCDR, CRISV32F_SFMT_ADDCDR },
  { CRIS_INSN_SUBS_B_R, CRISV32F_INSN_SUBS_B_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_SUBS_W_R, CRISV32F_INSN_SUBS_W_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_SUBS_M_B_M, CRISV32F_INSN_SUBS_M_B_M, CRISV32F_SFMT_ADDS_M_B_M },
  { CRIS_INSN_SUBS_M_W_M, CRISV32F_INSN_SUBS_M_W_M, CRISV32F_SFMT_ADDS_M_W_M },
  { CRIS_INSN_SUBSCBR, CRISV32F_INSN_SUBSCBR, CRISV32F_SFMT_ADDSCBR },
  { CRIS_INSN_SUBSCWR, CRISV32F_INSN_SUBSCWR, CRISV32F_SFMT_ADDSCWR },
  { CRIS_INSN_SUBU_B_R, CRISV32F_INSN_SUBU_B_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_SUBU_W_R, CRISV32F_INSN_SUBU_W_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_SUBU_M_B_M, CRISV32F_INSN_SUBU_M_B_M, CRISV32F_SFMT_ADDS_M_B_M },
  { CRIS_INSN_SUBU_M_W_M, CRISV32F_INSN_SUBU_M_W_M, CRISV32F_SFMT_ADDS_M_W_M },
  { CRIS_INSN_SUBUCBR, CRISV32F_INSN_SUBUCBR, CRISV32F_SFMT_ADDSCBR },
  { CRIS_INSN_SUBUCWR, CRISV32F_INSN_SUBUCWR, CRISV32F_SFMT_ADDSCWR },
  { CRIS_INSN_ADDC_R, CRISV32F_INSN_ADDC_R, CRISV32F_SFMT_ADD_D_R },
  { CRIS_INSN_ADDC_M, CRISV32F_INSN_ADDC_M, CRISV32F_SFMT_ADDC_M },
  { CRIS_INSN_ADDC_C, CRISV32F_INSN_ADDC_C, CRISV32F_SFMT_ADDCDR },
  { CRIS_INSN_LAPC_D, CRISV32F_INSN_LAPC_D, CRISV32F_SFMT_LAPC_D },
  { CRIS_INSN_LAPCQ, CRISV32F_INSN_LAPCQ, CRISV32F_SFMT_LAPCQ },
  { CRIS_INSN_ADDI_B_R, CRISV32F_INSN_ADDI_B_R, CRISV32F_SFMT_ADDI_B_R },
  { CRIS_INSN_ADDI_W_R, CRISV32F_INSN_ADDI_W_R, CRISV32F_SFMT_ADDI_B_R },
  { CRIS_INSN_ADDI_D_R, CRISV32F_INSN_ADDI_D_R, CRISV32F_SFMT_ADDI_B_R },
  { CRIS_INSN_NEG_B_R, CRISV32F_INSN_NEG_B_R, CRISV32F_SFMT_NEG_B_R },
  { CRIS_INSN_NEG_W_R, CRISV32F_INSN_NEG_W_R, CRISV32F_SFMT_NEG_B_R },
  { CRIS_INSN_NEG_D_R, CRISV32F_INSN_NEG_D_R, CRISV32F_SFMT_NEG_D_R },
  { CRIS_INSN_TEST_M_B_M, CRISV32F_INSN_TEST_M_B_M, CRISV32F_SFMT_TEST_M_B_M },
  { CRIS_INSN_TEST_M_W_M, CRISV32F_INSN_TEST_M_W_M, CRISV32F_SFMT_TEST_M_W_M },
  { CRIS_INSN_TEST_M_D_M, CRISV32F_INSN_TEST_M_D_M, CRISV32F_SFMT_TEST_M_D_M },
  { CRIS_INSN_MOVE_R_M_B_M, CRISV32F_INSN_MOVE_R_M_B_M, CRISV32F_SFMT_MOVE_R_M_B_M },
  { CRIS_INSN_MOVE_R_M_W_M, CRISV32F_INSN_MOVE_R_M_W_M, CRISV32F_SFMT_MOVE_R_M_W_M },
  { CRIS_INSN_MOVE_R_M_D_M, CRISV32F_INSN_MOVE_R_M_D_M, CRISV32F_SFMT_MOVE_R_M_D_M },
  { CRIS_INSN_MULS_B, CRISV32F_INSN_MULS_B, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MULS_W, CRISV32F_INSN_MULS_W, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MULS_D, CRISV32F_INSN_MULS_D, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MULU_B, CRISV32F_INSN_MULU_B, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MULU_W, CRISV32F_INSN_MULU_W, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MULU_D, CRISV32F_INSN_MULU_D, CRISV32F_SFMT_MULS_B },
  { CRIS_INSN_MCP, CRISV32F_INSN_MCP, CRISV32F_SFMT_MCP },
  { CRIS_INSN_DSTEP, CRISV32F_INSN_DSTEP, CRISV32F_SFMT_DSTEP },
  { CRIS_INSN_ABS, CRISV32F_INSN_ABS, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_AND_B_R, CRISV32F_INSN_AND_B_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_AND_W_R, CRISV32F_INSN_AND_W_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_AND_D_R, CRISV32F_INSN_AND_D_R, CRISV32F_SFMT_AND_D_R },
  { CRIS_INSN_AND_M_B_M, CRISV32F_INSN_AND_M_B_M, CRISV32F_SFMT_AND_M_B_M },
  { CRIS_INSN_AND_M_W_M, CRISV32F_INSN_AND_M_W_M, CRISV32F_SFMT_AND_M_W_M },
  { CRIS_INSN_AND_M_D_M, CRISV32F_INSN_AND_M_D_M, CRISV32F_SFMT_AND_M_D_M },
  { CRIS_INSN_ANDCBR, CRISV32F_INSN_ANDCBR, CRISV32F_SFMT_ANDCBR },
  { CRIS_INSN_ANDCWR, CRISV32F_INSN_ANDCWR, CRISV32F_SFMT_ANDCWR },
  { CRIS_INSN_ANDCDR, CRISV32F_INSN_ANDCDR, CRISV32F_SFMT_ANDCDR },
  { CRIS_INSN_ANDQ, CRISV32F_INSN_ANDQ, CRISV32F_SFMT_ANDQ },
  { CRIS_INSN_ORR_B_R, CRISV32F_INSN_ORR_B_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_ORR_W_R, CRISV32F_INSN_ORR_W_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_ORR_D_R, CRISV32F_INSN_ORR_D_R, CRISV32F_SFMT_AND_D_R },
  { CRIS_INSN_OR_M_B_M, CRISV32F_INSN_OR_M_B_M, CRISV32F_SFMT_AND_M_B_M },
  { CRIS_INSN_OR_M_W_M, CRISV32F_INSN_OR_M_W_M, CRISV32F_SFMT_AND_M_W_M },
  { CRIS_INSN_OR_M_D_M, CRISV32F_INSN_OR_M_D_M, CRISV32F_SFMT_AND_M_D_M },
  { CRIS_INSN_ORCBR, CRISV32F_INSN_ORCBR, CRISV32F_SFMT_ANDCBR },
  { CRIS_INSN_ORCWR, CRISV32F_INSN_ORCWR, CRISV32F_SFMT_ANDCWR },
  { CRIS_INSN_ORCDR, CRISV32F_INSN_ORCDR, CRISV32F_SFMT_ANDCDR },
  { CRIS_INSN_ORQ, CRISV32F_INSN_ORQ, CRISV32F_SFMT_ANDQ },
  { CRIS_INSN_XOR, CRISV32F_INSN_XOR, CRISV32F_SFMT_DSTEP },
  { CRIS_INSN_SWAP, CRISV32F_INSN_SWAP, CRISV32F_SFMT_SWAP },
  { CRIS_INSN_ASRR_B_R, CRISV32F_INSN_ASRR_B_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_ASRR_W_R, CRISV32F_INSN_ASRR_W_R, CRISV32F_SFMT_AND_B_R },
  { CRIS_INSN_ASRR_D_R, CRISV32F_INSN_ASRR_D_R, CRISV32F_SFMT_AND_D_R },
  { CRIS_INSN_ASRQ, CRISV32F_INSN_ASRQ, CRISV32F_SFMT_ASRQ },
  { CRIS_INSN_LSRR_B_R, CRISV32F_INSN_LSRR_B_R, CRISV32F_SFMT_LSRR_B_R },
  { CRIS_INSN_LSRR_W_R, CRISV32F_INSN_LSRR_W_R, CRISV32F_SFMT_LSRR_B_R },
  { CRIS_INSN_LSRR_D_R, CRISV32F_INSN_LSRR_D_R, CRISV32F_SFMT_LSRR_D_R },
  { CRIS_INSN_LSRQ, CRISV32F_INSN_LSRQ, CRISV32F_SFMT_ASRQ },
  { CRIS_INSN_LSLR_B_R, CRISV32F_INSN_LSLR_B_R, CRISV32F_SFMT_LSRR_B_R },
  { CRIS_INSN_LSLR_W_R, CRISV32F_INSN_LSLR_W_R, CRISV32F_SFMT_LSRR_B_R },
  { CRIS_INSN_LSLR_D_R, CRISV32F_INSN_LSLR_D_R, CRISV32F_SFMT_LSRR_D_R },
  { CRIS_INSN_LSLQ, CRISV32F_INSN_LSLQ, CRISV32F_SFMT_ASRQ },
  { CRIS_INSN_BTST, CRISV32F_INSN_BTST, CRISV32F_SFMT_BTST },
  { CRIS_INSN_BTSTQ, CRISV32F_INSN_BTSTQ, CRISV32F_SFMT_BTSTQ },
  { CRIS_INSN_SETF, CRISV32F_INSN_SETF, CRISV32F_SFMT_SETF },
  { CRIS_INSN_CLEARF, CRISV32F_INSN_CLEARF, CRISV32F_SFMT_SETF },
  { CRIS_INSN_RFE, CRISV32F_INSN_RFE, CRISV32F_SFMT_RFE },
  { CRIS_INSN_SFE, CRISV32F_INSN_SFE, CRISV32F_SFMT_SFE },
  { CRIS_INSN_RFG, CRISV32F_INSN_RFG, CRISV32F_SFMT_RFG },
  { CRIS_INSN_RFN, CRISV32F_INSN_RFN, CRISV32F_SFMT_RFN },
  { CRIS_INSN_HALT, CRISV32F_INSN_HALT, CRISV32F_SFMT_HALT },
  { CRIS_INSN_BCC_B, CRISV32F_INSN_BCC_B, CRISV32F_SFMT_BCC_B },
  { CRIS_INSN_BA_B, CRISV32F_INSN_BA_B, CRISV32F_SFMT_BA_B },
  { CRIS_INSN_BCC_W, CRISV32F_INSN_BCC_W, CRISV32F_SFMT_BCC_W },
  { CRIS_INSN_BA_W, CRISV32F_INSN_BA_W, CRISV32F_SFMT_BA_W },
  { CRIS_INSN_JAS_R, CRISV32F_INSN_JAS_R, CRISV32F_SFMT_JAS_R },
  { CRIS_INSN_JAS_C, CRISV32F_INSN_JAS_C, CRISV32F_SFMT_JAS_C },
  { CRIS_INSN_JUMP_P, CRISV32F_INSN_JUMP_P, CRISV32F_SFMT_JUMP_P },
  { CRIS_INSN_BAS_C, CRISV32F_INSN_BAS_C, CRISV32F_SFMT_BAS_C },
  { CRIS_INSN_JASC_R, CRISV32F_INSN_JASC_R, CRISV32F_SFMT_JASC_R },
  { CRIS_INSN_JASC_C, CRISV32F_INSN_JASC_C, CRISV32F_SFMT_JAS_C },
  { CRIS_INSN_BASC_C, CRISV32F_INSN_BASC_C, CRISV32F_SFMT_BAS_C },
  { CRIS_INSN_BREAK, CRISV32F_INSN_BREAK, CRISV32F_SFMT_BREAK },
  { CRIS_INSN_BOUND_R_B_R, CRISV32F_INSN_BOUND_R_B_R, CRISV32F_SFMT_DSTEP },
  { CRIS_INSN_BOUND_R_W_R, CRISV32F_INSN_BOUND_R_W_R, CRISV32F_SFMT_DSTEP },
  { CRIS_INSN_BOUND_R_D_R, CRISV32F_INSN_BOUND_R_D_R, CRISV32F_SFMT_DSTEP },
  { CRIS_INSN_BOUND_CB, CRISV32F_INSN_BOUND_CB, CRISV32F_SFMT_BOUND_CB },
  { CRIS_INSN_BOUND_CW, CRISV32F_INSN_BOUND_CW, CRISV32F_SFMT_BOUND_CW },
  { CRIS_INSN_BOUND_CD, CRISV32F_INSN_BOUND_CD, CRISV32F_SFMT_BOUND_CD },
  { CRIS_INSN_SCC, CRISV32F_INSN_SCC, CRISV32F_SFMT_SCC },
  { CRIS_INSN_LZ, CRISV32F_INSN_LZ, CRISV32F_SFMT_MOVS_B_R },
  { CRIS_INSN_ADDOQ, CRISV32F_INSN_ADDOQ, CRISV32F_SFMT_ADDOQ },
  { CRIS_INSN_ADDO_M_B_M, CRISV32F_INSN_ADDO_M_B_M, CRISV32F_SFMT_ADDO_M_B_M },
  { CRIS_INSN_ADDO_M_W_M, CRISV32F_INSN_ADDO_M_W_M, CRISV32F_SFMT_ADDO_M_W_M },
  { CRIS_INSN_ADDO_M_D_M, CRISV32F_INSN_ADDO_M_D_M, CRISV32F_SFMT_ADDO_M_D_M },
  { CRIS_INSN_ADDO_CB, CRISV32F_INSN_ADDO_CB, CRISV32F_SFMT_ADDO_CB },
  { CRIS_INSN_ADDO_CW, CRISV32F_INSN_ADDO_CW, CRISV32F_SFMT_ADDO_CW },
  { CRIS_INSN_ADDO_CD, CRISV32F_INSN_ADDO_CD, CRISV32F_SFMT_ADDO_CD },
  { CRIS_INSN_ADDI_ACR_B_R, CRISV32F_INSN_ADDI_ACR_B_R, CRISV32F_SFMT_ADDI_ACR_B_R },
  { CRIS_INSN_ADDI_ACR_W_R, CRISV32F_INSN_ADDI_ACR_W_R, CRISV32F_SFMT_ADDI_ACR_B_R },
  { CRIS_INSN_ADDI_ACR_D_R, CRISV32F_INSN_ADDI_ACR_D_R, CRISV32F_SFMT_ADDI_ACR_B_R },
  { CRIS_INSN_FIDXI, CRISV32F_INSN_FIDXI, CRISV32F_SFMT_FIDXI },
  { CRIS_INSN_FTAGI, CRISV32F_INSN_FTAGI, CRISV32F_SFMT_FIDXI },
  { CRIS_INSN_FIDXD, CRISV32F_INSN_FIDXD, CRISV32F_SFMT_FIDXI },
  { CRIS_INSN_FTAGD, CRISV32F_INSN_FTAGD, CRISV32F_SFMT_FIDXI },
};

static const struct insn_sem crisv32f_insn_sem_invalid =
{
  VIRTUAL_INSN_X_INVALID, CRISV32F_INSN_X_INVALID, CRISV32F_SFMT_EMPTY
};

/* Initialize an IDESC from the compile-time computable parts.  */

static INLINE void
init_idesc (SIM_CPU *cpu, IDESC *id, const struct insn_sem *t)
{
  const CGEN_INSN *insn_table = CGEN_CPU_INSN_TABLE (CPU_CPU_DESC (cpu))->init_entries;

  id->num = t->index;
  id->sfmt = t->sfmt;
  if ((int) t->type <= 0)
    id->idata = & cgen_virtual_insn_table[- (int) t->type];
  else
    id->idata = & insn_table[t->type];
  id->attrs = CGEN_INSN_ATTRS (id->idata);
  id->length = CGEN_INSN_BITSIZE (id->idata) / 8;

#if WITH_PROFILE_MODEL_P
  id->timing = & MODEL_TIMING (CPU_MODEL (cpu)) [t->index];
  {
    SIM_DESC sd = CPU_STATE (cpu);
    SIM_ASSERT (t->index == id->timing->num);
  }
#endif
}

/* Initialize the instruction descriptor table.  */

void
crisv32f_init_idesc_table (SIM_CPU *cpu)
{
  IDESC *table = crisv32f_insn_data;
  int tabsize = CRISV32F_INSN__MAX;
  
  if (!cpu || !table) {
    return;
  }

  memset(table, 0, tabsize * sizeof(IDESC));

  for (int i = 0; i < tabsize; i++) {
    init_idesc(cpu, &table[i], &crisv32f_insn_sem_invalid);
  }

  int sem_size = ARRAY_SIZE(crisv32f_insn_sem);
  for (int i = 0; i < sem_size; i++) {
    const struct insn_sem *t = &crisv32f_insn_sem[i];
    if (t->index >= 0 && t->index < tabsize) {
      init_idesc(cpu, &table[t->index], t);
    }
  }

  CPU_IDESC(cpu) = table;
}

/* Given an instruction, return a pointer to its IDESC entry.  */

const IDESC *
crisv32f_decode(SIM_CPU *current_cpu, IADDR pc,
               CGEN_INSN_WORD base_insn,
               ARGBUF *abuf)
{
    CRISV32F_INSN_TYPE itype;
    CGEN_INSN_WORD insn = base_insn;
    
    unsigned int val0 = ((insn >> 4) & 255);
    
    if (val0 <= 15) {
        unsigned int val1 = ((insn >> 12) & 15);
        itype = (val1 == 14) ? CRISV32F_INSN_BA_B : CRISV32F_INSN_BCC_B;
        goto extract_dispatch;
    }
    
    switch (val0) {
        case 16 ... 31: itype = CRISV32F_INSN_ADDOQ; break;
        case 32 ... 35: itype = CRISV32F_INSN_ADDQ; break;
        case 36 ... 39: itype = CRISV32F_INSN_MOVEQ; break;
        case 40 ... 43: itype = CRISV32F_INSN_SUBQ; break;
        case 44 ... 47: itype = CRISV32F_INSN_CMPQ; break;
        case 48 ... 51: itype = CRISV32F_INSN_ANDQ; break;
        case 52 ... 55: itype = CRISV32F_INSN_ORQ; break;
        case 56 ... 57: itype = CRISV32F_INSN_BTSTQ; break;
        case 58 ... 59: itype = CRISV32F_INSN_ASRQ; break;
        case 60 ... 61: itype = CRISV32F_INSN_LSLQ; break;
        case 62 ... 63: itype = CRISV32F_INSN_LSRQ; break;
        case 64: itype = CRISV32F_INSN_ADDU_B_R; break;
        case 65: itype = CRISV32F_INSN_ADDU_W_R; break;
        case 66: itype = CRISV32F_INSN_ADDS_B_R; break;
        case 67: itype = CRISV32F_INSN_ADDS_W_R; break;
        case 68: itype = CRISV32F_INSN_MOVU_B_R; break;
        case 69: itype = CRISV32F_INSN_MOVU_W_R; break;
        case 70: itype = CRISV32F_INSN_MOVS_B_R; break;
        case 71: itype = CRISV32F_INSN_MOVS_W_R; break;
        case 72: itype = CRISV32F_INSN_SUBU_B_R; break;
        case 73: itype = CRISV32F_INSN_SUBU_W_R; break;
        case 74: itype = CRISV32F_INSN_SUBS_B_R; break;
        case 75: itype = CRISV32F_INSN_SUBS_W_R; break;
        case 76: itype = CRISV32F_INSN_LSLR_B_R; break;
        case 77: itype = CRISV32F_INSN_LSLR_W_R; break;
        case 78: itype = CRISV32F_INSN_LSLR_D_R; break;
        case 79: itype = CRISV32F_INSN_BTST; break;
        case 80: itype = CRISV32F_INSN_ADDI_B_R; break;
        case 81: itype = CRISV32F_INSN_ADDI_W_R; break;
        case 82: itype = CRISV32F_INSN_ADDI_D_R; break;
        case 83: itype = CRISV32F_INSN_SCC; break;
        case 84: itype = CRISV32F_INSN_ADDI_ACR_B_R; break;
        case 85: itype = CRISV32F_INSN_ADDI_ACR_W_R; break;
        case 86: itype = CRISV32F_INSN_ADDI_ACR_D_R; break;
        case 87: itype = CRISV32F_INSN_ADDC_R; break;
        case 88: itype = CRISV32F_INSN_NEG_B_R; break;
        case 89: itype = CRISV32F_INSN_NEG_W_R; break;
        case 90: itype = CRISV32F_INSN_NEG_D_R; break;
        case 91: itype = CRISV32F_INSN_SETF; break;
        case 92: itype = CRISV32F_INSN_BOUND_R_B_R; break;
        case 93: itype = CRISV32F_INSN_BOUND_R_W_R; break;
        case 94: itype = CRISV32F_INSN_BOUND_R_D_R; break;
        case 95: itype = CRISV32F_INSN_CLEARF; break;
        case 96: itype = CRISV32F_INSN_ADD_B_R; break;
        case 97: itype = CRISV32F_INSN_ADD_W_R; break;
        case 98: itype = CRISV32F_INSN_ADD_D_R; break;
        case 99: itype = CRISV32F_INSN_MOVE_R_SPRV32; break;
        case 100: itype = CRISV32F_INSN_MOVE_B_R; break;
        case 101: itype = CRISV32F_INSN_MOVE_W_R; break;
        case 102: itype = CRISV32F_INSN_MOVE_D_R; break;
        case 103: itype = CRISV32F_INSN_MOVE_SPR_RV32; break;
        case 104: itype = CRISV32F_INSN_SUB_B_R; break;
        case 105: itype = CRISV32F_INSN_SUB_W_R; break;
        case 106: itype = CRISV32F_INSN_SUB_D_R; break;
        case 107: itype = CRISV32F_INSN_ABS; break;
        case 108: itype = CRISV32F_INSN_CMP_R_B_R; break;
        case 109: itype = CRISV32F_INSN_CMP_R_W_R; break;
        case 110: itype = CRISV32F_INSN_CMP_R_D_R; break;
        case 111: itype = CRISV32F_INSN_DSTEP; break;
        case 112: itype = CRISV32F_INSN_AND_B_R; break;
        case 113: itype = CRISV32F_INSN_AND_W_R; break;
        case 114: itype = CRISV32F_INSN_AND_D_R; break;
        case 115: itype = CRISV32F_INSN_LZ; break;
        case 116: itype = CRISV32F_INSN_ORR_B_R; break;
        case 117: itype = CRISV32F_INSN_ORR_W_R; break;
        case 118: itype = CRISV32F_INSN_ORR_D_R; break;
        case 119: itype = CRISV32F_INSN_SWAP; break;
        case 120: itype = CRISV32F_INSN_ASRR_B_R; break;
        case 121: itype = CRISV32F_INSN_ASRR_W_R; break;
        case 122: itype = CRISV32F_INSN_ASRR_D_R; break;
        case 123: itype = CRISV32F_INSN_XOR; break;
        case 124: itype = CRISV32F_INSN_LSRR_B_R; break;
        case 125: itype = CRISV32F_INSN_LSRR_W_R; break;
        case 126: itype = CRISV32F_INSN_LSRR_D_R; break;
        case 127: itype = CRISV32F_INSN_MCP; break;
        
        case 147: {
            unsigned int val1 = ((insn >> 12) & 15);
            switch (val1) {
                case 2:
                    itype = ((base_insn & 0xffff) == 0x2930) ? CRISV32F_INSN_RFE : CRISV32F_INSN_X_INVALID;
                    break;
                case 3:
                    itype = ((base_insn & 0xffff) == 0x3930) ? CRISV32F_INSN_SFE : CRISV32F_INSN_X_INVALID;
                    break;
                case 4:
                    itype = ((base_insn & 0xffff) == 0x4930) ? CRISV32F_INSN_RFG : CRISV32F_INSN_X_INVALID;
                    break;
                case 5:
                    itype = ((base_insn & 0xffff) == 0x5930) ? CRISV32F_INSN_RFN : CRISV32F_INSN_X_INVALID;
                    break;
                case 14:
                    itype = CRISV32F_INSN_BREAK;
                    break;
                case 15:
                    itype = ((base_insn & 0xffff) == 0xf930) ? CRISV32F_INSN_HALT : CRISV32F_INSN_X_INVALID;
                    break;
                default:
                    itype = CRISV32F_INSN_X_INVALID;
            }
            break;
        }
        
        case 171: {
            unsigned int val1 = ((insn >> 12) & 1);
            if (val1 == 0) {
                itype = ((base_insn & 0xfff0) == 0xab0) ? CRISV32F_INSN_FIDXD : CRISV32F_INSN_X_INVALID;
            } else {
                itype = ((base_insn & 0xfff0) == 0x1ab0) ? CRISV32F_INSN_FTAGD : CRISV32F_INSN_X_INVALID;
            }
            break;
        }
        
        case 192 ... 207: {
            unsigned int val1 = (insn & 15);
            static const CRISV32F_INSN_TYPE decode_table_192_207[16][2] = {
                {CRISV32F_INSN_ADDU_M_B_M, CRISV32F_INSN_ADDUCBR},
                {CRISV32F_INSN_ADDU_M_W_M, CRISV32F_INSN_ADDUCWR},
                {CRISV32F_INSN_ADDS_M_B_M, CRISV32F_INSN_ADDSCBR},
                {CRISV32F_INSN_ADDS_M_W_M, CRISV32F_INSN_ADDSCWR},
                {CRISV32F_INSN_MOVU_M_B_M, CRISV32F_INSN_MOVUCBR},
                {CRISV32F_INSN_MOVU_M_W_M, CRISV32F_INSN_MOVUCWR},
                {CRISV32F_INSN_MOVS_M_B_M, CRISV32F_INSN_MOVSCBR},
                {CRISV32F_INSN_MOVS_M_W_M, CRISV32F_INSN_MOVSCWR},
                {CRISV32F_INSN_SUBU_M_B_M, CRISV32F_INSN_SUBUCBR},
                {CRISV32F_INSN_SUBU_M_W_M, CRISV32F_INSN_SUBUCWR},
                {CRISV32F_INSN_SUBS_M_B_M, CRISV32F_INSN_SUBSCBR},
                {CRISV32F_INSN_SUBS_M_W_M, CRISV32F_INSN_SUBSCWR},
                {CRISV32F_INSN_CMPU_M_B_M, CRISV32F_INSN_CMPUCBR},
                {CRISV32F_INSN_CMPU_M_W_M, CRISV32F_INSN_CMPUCWR},
                {CRISV32F_INSN_CMPS_M_B_M, CRISV32F_INSN_CMPSCBR},
                {CRISV32F_INSN_CMPS_M_W_M, CRISV32F_INSN_CMPSCWR}
            };
            itype = decode_table_192_207[val0 - 192][(val1 == 15) ? 1 : 0];
            break;
        }
        
        case 223: {
            unsigned int val1 = ((insn >> 12) & 15);
            if ((base_insn & 0xfff) == 0xdff) {
                itype = (val1 == 14) ? CRISV32F_INSN_BA_W : CRISV32F_INSN_BCC_W;
            } else {
                itype = CRISV32F_INSN_X_INVALID;
            }
            break;
        }
        
        default:
            itype = CRISV32F_INSN_X_INVALID;
    }

extract_dispatch:
    switch (itype) {
        case CRISV32F_INSN_BCC_B: return extract_sfmt_bcc_b(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_BA_B: return extract_sfmt_ba_b(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDOQ: return extract_sfmt_addoq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDQ: return extract_sfmt_addq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVEQ: return extract_sfmt_moveq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMPQ: return extract_sfmt_cmpq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ANDQ: return extract_sfmt_andq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_BTSTQ: return extract_sfmt_btstq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ASRQ: return extract_sfmt_asrq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADD_D_R: return extract_sfmt_add_d_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVS_B_R: return extract_sfmt_movs_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_LSRR_B_R: return extract_sfmt_lsrr_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_LSRR_D_R: return extract_sfmt_lsrr_d_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_BTST: return extract_sfmt_btst(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDI_B_R: return extract_sfmt_addi_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_SCC: return extract_sfmt_scc(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDI_ACR_B_R: return extract_sfmt_addi_acr_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_NEG_B_R: return extract_sfmt_neg_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_NEG_D_R: return extract_sfmt_neg_d_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_SETF: return extract_sfmt_setf(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_DSTEP: return extract_sfmt_dstep(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADD_B_R: return extract_sfmt_add_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_R_SPRV32: return extract_sfmt_move_r_sprv32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_B_R: return extract_sfmt_move_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_D_R: return extract_sfmt_move_d_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_SPR_RV32: return extract_sfmt_move_spr_rv32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMP_R_B_R: return extract_sfmt_cmp_r_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_AND_B_R: return extract_sfmt_and_b_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_AND_D_R: return extract_sfmt_and_d_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_SWAP: return extract_sfmt_swap(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MCP: return extract_sfmt_mcp(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDS_M_B_M: return extract_sfmt_adds_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDS_M_W_M: return extract_sfmt_adds_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVS_M_B_M: return extract_sfmt_movs_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVS_M_W_M: return extract_sfmt_movs_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMP_M_B_M: return extract_sfmt_cmp_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMP_M_W_M: return extract_sfmt_cmp_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMP_M_D_M: return extract_sfmt_cmp_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MULS_B: return extract_sfmt_muls_b(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_RFE: return extract_sfmt_rfe(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_SFE: return extract_sfmt_sfe(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_RFG: return extract_sfmt_rfg(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_RFN: return extract_sfmt_rfn(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_BREAK: return extract_sfmt_break(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_HALT: return extract_sfmt_halt(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_M_B_M: return extract_sfmt_addo_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_M_W_M: return extract_sfmt_addo_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_M_D_M: return extract_sfmt_addo_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_LAPCQ: return extract_sfmt_lapcq(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDC_M: return extract_sfmt_addc_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_JAS_R: return extract_sfmt_jas_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_JUMP_P: return extract_sfmt_jump_p(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADD_M_B_M: return extract_sfmt_add_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADD_M_W_M: return extract_sfmt_add_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADD_M_D_M: return extract_sfmt_add_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_M_SPRV32: return extract_sfmt_move_m_sprv32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_M_B_M: return extract_sfmt_move_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_M_W_M: return extract_sfmt_move_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_M_D_M: return extract_sfmt_move_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_SPR_MV32: return extract_sfmt_move_spr_mv32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_FIDXD: return extract_sfmt_fidxi(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_FTAGD: return extract_sfmt_fidxi(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_AND_M_B_M: return extract_sfmt_and_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_AND_M_W_M: return extract_sfmt_and_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_AND_M_D_M: return extract_sfmt_and_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_JASC_R: return extract_sfmt_jasc_r(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_R_SS: return extract_sfmt_move_r_ss(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_TEST_M_B_M: return extract_sfmt_test_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_TEST_M_W_M: return extract_sfmt_test_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_TEST_M_D_M: return extract_sfmt_test_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVEM_M_R_V32: return extract_sfmt_movem_m_r_v32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_R_M_B_M: return extract_sfmt_move_r_m_b_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_R_M_W_M: return extract_sfmt_move_r_m_w_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVE_R_M_D_M: return extract_sfmt_move_r_m_d_m(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVEM_R_M_V32: return extract_sfmt_movem_r_m_v32(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDSCBR: return extract_sfmt_addscbr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDSCWR: return extract_sfmt_addscwr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVUCBR: return extract_sfmt_movucbr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVUCWR: return extract_sfmt_movucwr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVSCBR: return extract_sfmt_movscbr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_MOVSCWR: return extract_sfmt_movscwr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMPUCBR: return extract_sfmt_cmpucbr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_CMPUCWR: return extract_sfmt_cmpucwr(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_FIDXI: return extract_sfmt_fidxi(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_FTAGI: return extract_sfmt_fidxi(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_CB: return extract_sfmt_addo_cb(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_CW: return extract_sfmt_addo_cw(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDO_CD: return extract_sfmt_addo_cd(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_LAPC_D: return extract_sfmt_lapc_d(current_cpu, pc, base_insn, abuf);
        case CRISV32F_INSN_ADDC_C: return extract_sfmt_addcdr(current_cpu, pc, base_insn, abuf);
