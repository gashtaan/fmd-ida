# https://github.com/gashtaan/fmd-ida
#
# Copyright (C) 2024, Michal Kovacik
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from idaapi import *
from ida_bytes import *
from ida_xref import *

class fmd_processor_t(processor_t):
	id = 0x8F0D

	flag = PRN_HEX | PR_SEGS | PR_SGROTHER | PR_RNAMESOK
	psnames = [ "FMD-F" ]
	plnames = [ "FMD F-Series" ]
	cnbits = 14
	dnbits = 8
	segreg_size = 0
	tbyte_size = 0

	assembler = {
		"flag": ASH_HEXF2 | ASD_DECF3 | ASB_BINF5 | ASO_OCTF5 | AS_N2CHR | AS_NCMAS | AS_ONEDUP,
		"uflag": 0,
		"name": "FMD Assembler",
		"origin": "org",
		"end": "end",
		"cmnt": ";",
		"ascsep": '"',
		"accsep": "'",
		"esccodes": "\"'",
		"a_ascii": "data",
		"a_byte": "byte",
		"a_word": "data",
		"a_dups": "res %s",
		"a_equ" : "equ",
		"a_curip" : "$",
		"a_bss" : "res %s",
		"a_seg" : "",
		"a_public" : "",
		"a_weak" : "",
		"a_extrn" : "",
		"a_comdef" : "",
		"a_align" : "",
		"a_mod": "%",
		"a_band": "&",
		"a_bor": "|",
		"a_xor": "^",
		"a_bnot": "~",
		"a_shl": "<<",
		"a_shr": ">>",
		"lbrace": "(",
		"rbrace": ")",
	}

	reg_names = [
		"w",
		"f",
		"bank",
		"pclath",
		"cs",
		"ds"
	]

	instruc = [
		{ 'name' : 'null',		'feature' : 0 },
		{ 'name' : 'nop',		'feature' : 0 },
		{ 'name' : 'clrwdt',	'feature' : 0 },
		{ 'name' : 'sleep',		'feature' : 0 },
		{ 'name' : 'sttmd',		'feature' : 0 },
		{ 'name' : 'ret',		'feature' : CF_STOP },
		{ 'name' : 'ctlio',		'feature' : 0 },
		{ 'name' : 'clrw',		'feature' : 0 },
		{ 'name' : 'reti',		'feature' : CF_STOP },
		{ 'name' : 'clrr',		'feature' : 0 },
		{ 'name' : 'str',		'feature' : 0 },
		{ 'name' : 'andwr',		'feature' : 0 },
		{ 'name' : 'iorwr',		'feature' : 0 },
		{ 'name' : 'xorwr',		'feature' : 0 },
		{ 'name' : 'rlr',		'feature' : 0 },
		{ 'name' : 'rrr',		'feature' : 0 },
		{ 'name' : 'swapr',		'feature' : 0 },
		{ 'name' : 'ldr',		'feature' : 0 },
		{ 'name' : 'incr',		'feature' : 0 },
		{ 'name' : 'incrsz',	'feature' : 0 },
		{ 'name' : 'addwr',		'feature' : 0 },
		{ 'name' : 'subwr',		'feature' : 0 },
		{ 'name' : 'decr',		'feature' : 0 },
		{ 'name' : 'decrsz',	'feature' : 0 },
		{ 'name' : 'comr',		'feature' : 0 },
		{ 'name' : 'bcr',		'feature' : 0 },
		{ 'name' : 'btsc',		'feature' : 0 },
		{ 'name' : 'bsr',		'feature' : 0 },
		{ 'name' : 'btss',		'feature' : 0 },
		{ 'name' : 'retw',		'feature' : CF_STOP },
		{ 'name' : 'andwi',		'feature' : 0 },
		{ 'name' : 'iorwi',		'feature' : 0 },
		{ 'name' : 'xorwi',		'feature' : 0 },
		{ 'name' : 'addwi',		'feature' : 0 },
		{ 'name' : 'subwi',		'feature' : 0 },
		{ 'name' : 'ldwi',		'feature' : 0 },
		{ 'name' : 'lcall',		'feature' : 0 },
		{ 'name' : 'ljump',		'feature' : 0 },
	]

	def __init__(self):
		processor_t.__init__(self)

		for i in range(len(self.reg_names)):
			setattr(self, 'rtype_' + self.reg_names[i], i)

		self.regs_num = len(self.reg_names)
		self.reg_first_sreg = self.rtype_bank
		self.reg_last_sreg = self.rtype_ds
		self.reg_code_sreg = self.rtype_cs
		self.reg_data_sreg = self.rtype_ds

		self.instruc_start = 0
		self.instruc_end = len(self.instruc)

		for i in range(len(self.instruc)):
			setattr(self, 'itype_' + self.instruc[i]['name'], i)

		self.icode_return = self.itype_ret

	def ev_emu_insn(self, insn):
		feature = insn.get_canon_feature()

		def handle_sreg_change(insn, reg, shift):
			if (insn.itype == self.itype_bcr or insn.itype == self.itype_bsr) and (insn.Op2.value == shift or insn.Op2.value == shift + 1):
				v = get_sreg(insn.ea, reg)
				if v == BADSEL:
					v = 0
				if insn.itype == self.itype_bcr:
					v = v & ~(1 << (insn.Op2.value - shift));
				else:
					v = v | (1 << (insn.Op2.value - shift));
				self.update_sreg(insn, reg, v)
				return True

			elif insn.itype == self.itype_str:
				prev_opcode = get_wide_byte(insn.ea - 1)
				if (prev_opcode >> 8) == 0x2A:
					self.update_sreg(insn, reg, ((prev_opcode & 0xFF) >> shift))
				return True

			return False

		for i in range(4):
			op = insn.ops[i]
			if op.type == o_mem:
				op_ea = self.data_seg.startEA + op.addr
				insn.add_dref(op_ea, op.offb, dr_R)
				insn.create_op_data(op_ea, op)

				if op.addr == 0x0A:
					# PCLATH change
					handle_sreg_change(insn, self.rtype_pclath, 3)
				elif op.addr == 0x03:
					# PAGE change
					handle_sreg_change(insn, self.rtype_bank, 5)

			if op.type == o_near:
				ftype = fl_JN
				if insn.itype == self.itype_lcall:
					ftype = fl_CN

				insn.add_cref(op.addr, op.offb, ftype);

				split_sreg_range(op.addr, self.rtype_pclath, get_sreg(insn.ea, self.rtype_pclath), SR_auto)
				split_sreg_range(op.addr, self.rtype_bank, get_sreg(insn.ea, self.rtype_bank), SR_auto)

		flow = ((feature & CF_STOP) == 0)
		if flow or self.is_conditional(insn):
			add_cref(insn.ea, insn.ea + insn.size, fl_F)

		return True

	def ev_out_operand(self, ctx, op):
		if op.type == o_reg:
			ctx.out_register(self.reg_names[op.reg])
		elif op.type == o_imm:
			ctx.out_value(op, OOFW_IMM | OOFW_8)
		elif op.type == o_mem:
			ctx.out_name_expr(op, self.data_seg.startEA + op.addr, BADADDR)
		elif op.type == o_near:
			ctx.out_name_expr(op, op.addr, BADADDR)
		else:
			return False

		return True

	def ev_out_insn(self, ctx):
		if self.is_conditional(ctx.insn):
			ctx.out_char(' ')
		ctx.out_mnemonic()

		ctx.out_one_operand(0)

		for i in range(1, 3):
			op = ctx.insn[i]
			if op.type == o_void:
				break

			ctx.out_symbol(',')
			ctx.out_char(' ')
			ctx.out_one_operand(i)

		ctx.flush_outbuf()

		return True

	def ev_ana_insn(self, insn):
		opcode = get_wide_byte(insn.ea)
		opcode_h = opcode >> 8
		opcode_l = opcode & 0xFF

		if opcode_h == 0x00:
			itypes = [ self.itype_nop, self.itype_clrwdt, self.itype_sleep, self.itype_sttmd, self.itype_ret, self.itype_ctlio, self.itype_ctlio, self.itype_ctlio, self.itype_clrw, self.itype_reti ]
			if opcode_l < len(itypes):
				insn.itype = itypes[opcode_l]
			else:
				insn.itype = self.itype_clrw

			if insn.itype == self.itype_ctlio:
				insn.Op1.type = o_imm
				insn.Op1.value = (opcode_l & 7)
				insn.Op1.dtype = dt_byte

		elif opcode_h == 0x01:
			itypes = [ self.itype_clrr, self.itype_str ]
			insn.itype = itypes[opcode_l >> 7]
			insn.Op1.type = o_mem
			insn.Op1.addr = self.bank_address(insn.ea, opcode_l & 0x7F)
			insn.Op1.dtype = dt_byte

		elif opcode_h >= 0x02 and opcode_h <= 0x0F:
			itypes = [ self.itype_andwr, self.itype_iorwr, self.itype_xorwr, self.itype_rlr, self.itype_rrr, self.itype_swapr, self.itype_ldr, self.itype_incr, self.itype_incrsz, self.itype_addwr, self.itype_subwr, self.itype_decr, self.itype_decrsz, self.itype_comr ]
			insn.itype = itypes[opcode_h - 2]
			insn.Op1.type = o_mem
			insn.Op1.addr = self.bank_address(insn.ea, opcode_l & 0x7F)
			insn.Op1.dtype = dt_byte
			insn.Op2.type = o_imm
			insn.Op2.value = (opcode_l >> 7)
			insn.Op2.dtype = dt_byte

		elif opcode_h >= 0x10 and opcode_h <= 0x1F:
			itypes = [ self.itype_bcr, self.itype_btsc, self.itype_bsr, self.itype_btss ]
			insn.itype = itypes[(opcode_h >> 2) & 3]
			insn.Op1.type = o_mem
			insn.Op1.addr = self.bank_address(insn.ea, opcode_l & 0x7F)
			insn.Op1.dtype = dt_byte
			insn.Op2.type = o_imm
			insn.Op2.value = ((opcode >> 7) & 7)

		elif opcode_h >= 0x20 and opcode_h <= 0x2F:
			itypes = [ self.itype_null, self.itype_retw, self.itype_null, self.itype_null, self.itype_andwi, self.itype_iorwi, self.itype_xorwi, self.itype_addwi, self.itype_subwi, self.itype_null, self.itype_ldwi, self.itype_null, self.itype_null, self.itype_null, self.itype_null, self.itype_null ]
			insn.itype = itypes[opcode_h - 0x20]
			if insn.itype != self.itype_null:
				insn.Op1.type = o_imm
				insn.Op1.value = opcode_l
				insn.Op1.dtype = dt_byte

		elif opcode_h >= 0x30 and opcode_h <= 0x3F:
			insn.itype = self.itype_lcall + ((opcode_h >> 3) & 1)
			insn.Op1.type = o_near
			insn.Op1.addr = self.pc_address(insn.ea, opcode & 0x07FF)
			insn.Op1.dtype = dt_code

		insn.size = 1

		return True

	def ev_out_data(self, ctx, analyze_only):
		ctx.out_data(analyze_only)
		return True

	def ev_out_assumes(self, ctx):
		pclath = get_sreg(ctx.insn_ea, self.rtype_pclath)
		if pclath != get_sreg(ctx.insn_ea - 1, self.rtype_pclath):
			if pclath == BADSEL:
				pclath = 0
			ctx.gen_cmt_line("assume %s = %s" % (self.reg_names[self.rtype_pclath], pclath))

		bank = get_sreg(ctx.insn_ea, self.rtype_bank)
		if bank != get_sreg(ctx.insn_ea - 1, self.rtype_bank):
			if bank == BADSEL:
				bank = 0
			ctx.gen_cmt_line("assume %s = %s" % (self.reg_names[self.rtype_bank], bank))

		return True

	def ev_newfile(self, fname):
		self.prepare_segments()
		return True

	def ev_oldfile(self, fname):
		self.prepare_segments()
		return True

	def prepare_segments(self):
		set_default_sreg_value(get_first_seg(), self.rtype_pclath, 0)
		set_default_sreg_value(get_first_seg(), self.rtype_bank, 0)

		self.data_seg = get_segm_by_name("DATA")
		if not self.data_seg:
			data_offset = 0;
			data_size = 0x200;
			data_addr = free_chunk(0, data_size, -15);
			data_base = data_addr - data_offset

			self.data_seg = segment_t()
			self.data_seg.startEA = data_addr
			self.data_seg.endEA = data_addr + data_size
			self.data_seg.sel = setup_selector(data_base >> 4)
			self.data_seg.type = SEG_IMEM
			self.data_seg.align = saRelByte
			self.data_seg.comb = scPub
			add_segm_ex(self.data_seg, "DATA", "", ADDSEG_NOSREG | ADDSEG_OR_DIE)

	def update_sreg(self, insn, reg, value):
		split_sreg_range(get_item_end(insn.ea), reg, value, SR_auto)

	def bank_address(self, ea, address):
		bank = get_sreg(ea, self.rtype_bank)
		if bank == BADSEL or address in [0x00, 0x02, 0x03, 0x04, 0x0A, 0x0B] or address >= 0x70:
			bank = 0
		return (bank << 7) | address

	def pc_address(self, ea, address):
		pclath = get_sreg(ea, self.rtype_pclath)
		if pclath == BADSEL:
			pclath = 0
		return (pclath << 11) | address

	@staticmethod
	def is_conditional(insn):
		prev_opcode = get_wide_byte(insn.ea - 1) >> 8
		if prev_opcode in [0x0A, 0x0E] or (prev_opcode & 0xFC) in [0x14, 0x1C]:
			return True
		return False

def PROCESSOR_ENTRY():
	return fmd_processor_t()
