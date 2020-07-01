/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "pt/disassembler.h"
#include "pt/memory_access.h"

#define LOOKUP_TABLES		5
#define IGN_MOD_RM			0
#define IGN_OPODE_PREFIX	0
#define MODRM_REG(x)		(x << 3)
#define MODRM_AND			0b00111000

/* http://stackoverflow.com/questions/29600668/what-meaning-if-any-does-the-mod-r-m-byte-carry-for-the-unconditional-jump-ins */
/* conditional branch */
cofi_ins cb_lookup[] = {
	{X86_INS_JAE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JA,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JBE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JB,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JCXZ,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JECXZ,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JGE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JG,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JLE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JL,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JNE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JNO,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JNP,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JNS,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JO,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JP,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JRCXZ,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JS,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_LOOP,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_LOOPE,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_LOOPNE,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
};

/* unconditional direct branch */
cofi_ins udb_lookup[] = {
	{X86_INS_JMP,		IGN_MOD_RM,	0xe9},
	{X86_INS_JMP,		IGN_MOD_RM, 0xeb},
	{X86_INS_CALL,		IGN_MOD_RM,	0xe8},	
};

/* indirect branch */
cofi_ins ib_lookup[] = {
	{X86_INS_JMP,		MODRM_REG(4),	0xff},
	{X86_INS_CALL,		MODRM_REG(2),	0xff},	
};

/* near ret */
cofi_ins nr_lookup[] = {
	{X86_INS_RET,		IGN_MOD_RM,	0xc3},
	{X86_INS_RET,		IGN_MOD_RM,	0xc2},
};
 
/* far transfers */ 
cofi_ins ft_lookup[] = {
	{X86_INS_INT3,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_INT,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_INT1,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_INTO,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_IRET,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_IRETD,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_IRETQ,		IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_JMP,		IGN_MOD_RM,		0xea},
	{X86_INS_JMP,		MODRM_REG(5),	0xff},
	{X86_INS_CALL,		IGN_MOD_RM,		0x9a},
	{X86_INS_CALL,		MODRM_REG(3),	0xff},
	{X86_INS_RET,		IGN_MOD_RM,		0xcb},
	{X86_INS_RET,		IGN_MOD_RM,		0xca},
	{X86_INS_SYSCALL,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_SYSENTER,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_SYSEXIT,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_SYSRET,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_VMLAUNCH,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
	{X86_INS_VMRESUME,	IGN_MOD_RM,	IGN_OPODE_PREFIX},
};

uint16_t cmp_lookup[] = {
	X86_INS_CMP,
	X86_INS_CMPPD,
	X86_INS_CMPPS,
	X86_INS_CMPSB,
	X86_INS_CMPSD,
	X86_INS_CMPSQ,
	X86_INS_CMPSS,
	X86_INS_CMPSW,
	X86_INS_CMPXCHG16B,
	X86_INS_CMPXCHG,
	X86_INS_CMPXCHG8B,
};


cofi_ins* lookup_tables[] = {
	cb_lookup,
	udb_lookup,
	ib_lookup,
	nr_lookup,
	ft_lookup,
};

uint8_t lookup_table_sizes[] = {
	22,
	3,
	2,
	2,
	19
};

/* ===== kAFL disassembler cofi list ===== */

static cofi_list* create_list_head(void){
	cofi_list* head = malloc(sizeof(cofi_list));
	if (head != NULL){
		head->list_ptr = NULL;
		head->cofi_ptr = NULL;
		head->cofi = NULL;
		return head;
	}
	return NULL;
}

static void free_list(cofi_list* head){
	cofi_list *tmp1, *tmp2;
	tmp1 = head;
	while (1){
		tmp2 = tmp1;
		if(tmp1 == NULL){
			break;
		}
		tmp1 = tmp1->list_ptr;
		if (tmp2->cofi != NULL){
			free(tmp2->cofi);
		}
		free(tmp2);
	}
}

static cofi_list* new_list_element(cofi_list* predecessor, cofi_header* cofi){
	if(predecessor){
		cofi_list* next = malloc(sizeof(cofi_list));
		if (next){
			predecessor->list_ptr = next;
			next->list_ptr = NULL;
			next->cofi_ptr = NULL;
			next->cofi = cofi;
			return next;
		}
	}
	return NULL;
}

static void edit_cofi_ptr(cofi_list* element, cofi_list* target){
	if (element){
		element->cofi_ptr = target;
	}
}

/* ===== kAFL disassembler hashmap ===== */

cofi_list *tmp_cofi;
static void map_put(disassembler_t* self, uint64_t addr, uint64_t ref){
	int ret;
	khiter_t k;
	k = kh_put(ADDR0, self->map, addr, &ret); 
	kh_value(self->map, k) = ref;

}

static int map_get(disassembler_t* self, uint64_t addr, uint64_t* ref){
	khiter_t k;
	k = kh_get(ADDR0, self->map, addr); 
	if(k != kh_end(self->map)){
		*ref = kh_value(self->map, k); 
		return 0;
	} 
	return 1;
}

/* ===== kAFL disassembler engine ===== */

static inline uint64_t fast_strtoull(const char *hexstring){
	uint64_t result = 0;
	uint8_t i = 0;
	if (hexstring[1] == 'x' || hexstring[1] == 'X')
		i = 2;
	for (; hexstring[i]; i++)
		result = (result << 4) + (9 * (hexstring[i] >> 6) + (hexstring[i] & 017));
	return result;
}

static inline uint64_t hex_to_bin(char* str){
	//return (uint64_t)strtoull(str, NULL, 16);
	return fast_strtoull(str);
}

static cofi_type opcode_analyzer(disassembler_t* self, cs_insn *ins){
	uint8_t i, j;
	cs_x86 details = ins->detail->x86;
	
	for (i = 0; i < LOOKUP_TABLES; i++){
		for (j = 0; j < lookup_table_sizes[i]; j++){
			if (ins->id == lookup_tables[i][j].opcode){
				
				/* check MOD R/M */
				if (lookup_tables[i][j].modrm != IGN_MOD_RM && lookup_tables[i][j].modrm != (details.modrm & MODRM_AND))
						continue;	
						
				/* check opcode prefix byte */
				if (lookup_tables[i][j].opcode_prefix != IGN_OPODE_PREFIX && lookup_tables[i][j].opcode_prefix != details.opcode[0])
						continue;
#ifdef DEBUG
				/* found */
				printf("%lx (%d)\t%s\t%s\t\t", ins->address, i, ins->mnemonic, ins->op_str);
				print_string_hex("      \t", ins->bytes, ins->size);
#endif
				return i;
				
			}
		}
	}
	return NO_COFI_TYPE;
}

static cofi_list* analyse_assembly(disassembler_t* self, uint64_t base_address, bool across_page)
{
	csh handle;
	cs_insn *insn;
	cofi_type type;
	cofi_header* tmp = NULL;
	uint64_t tmp_list_element = 0;
	bool last_nop = false, no_munmap = true;
	uint64_t total = 0;
	uint64_t cofi = 0;
	const uint8_t* code = mmap_virtual_memory(base_address, self->cpu);
	uint8_t tmp_code[x86_64_PAGE_SIZE*2];
	size_t code_size = x86_64_PAGE_SIZE - (base_address & x86_64_PAGE_OFF_MASK);
	uint64_t address = base_address;
	cofi_list* predecessor = NULL;
	cofi_list* first = NULL;
				
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return NULL;
	
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	insn = cs_malloc(handle);
	
	if (!code) {
		printf("Fatal error 1 in analyse_assembly.\n");
		asm("int $3\r\n");
	}

	if (across_page) {
		/*
		 * We must parse instructions in two consecutive pages.
		 * */
		code_size = x86_64_PAGE_SIZE*2 - (address & x86_64_PAGE_OFF_MASK);
		if (!read_virtual_memory(address, tmp_code, code_size, self->cpu)) {
			printf("Fatal error 2 in analyse_assembly.\n");
			asm("int $3\r\n");
		}
		if (no_munmap) {
			munmap_virtual_memory((void *)code, self->cpu);
			no_munmap = false;
		}
		code = tmp_code;
	}

	while (cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
		if (insn->address > self->max_addr){
			break;
		}

		type = opcode_analyzer(self, insn);
		total++;
		
		if (self->debug){
			printf("%lx:\t(%d)\t%s\t%s\t\t\n", insn->address, type, insn->mnemonic, insn->op_str);
		}
		
		if (!last_nop){
			tmp = malloc(sizeof(cofi_header));
			tmp->type = NO_COFI_TYPE;
			tmp->ins_addr = 0;
			tmp->target_addr = 0;
	
			if (cofi)
				predecessor = self->list_element;
			self->list_element = new_list_element(self->list_element, tmp);
			edit_cofi_ptr(predecessor, self->list_element);
		}
		
		if (!map_get(self, insn->address, &tmp_list_element)){
			if(((cofi_list *)tmp_list_element)->cofi_ptr){
				edit_cofi_ptr(self->list_element, (cofi_list *)tmp_list_element);
				//printf("EDIT COFI PTR (%p %p %p %d)\n", list_element, (cofi_list*)tmp_list_element, list_element->cofi, list_element->cofi->type);
				break;
			} else {
				self->list_element = (cofi_list *)tmp_list_element;
			}
		}
		
		if (type != NO_COFI_TYPE){
			cofi++;
			last_nop = false;
			tmp->type = type;
			tmp->ins_addr = insn->address;
			tmp->ins_len = (uint64_t)code - (uint64_t)insn->address;
			if (type == COFI_TYPE_CONDITIONAL_BRANCH || type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH){
				tmp->target_addr = hex_to_bin(insn->op_str);	
			} else {
				tmp->target_addr = 0;
			}
			self->list_element->cofi = tmp;
			map_put(self, tmp->ins_addr, (uint64_t)(self->list_element));
		} else {
			last_nop = true;
			self->list_element->cofi->ins_addr = insn->address;
			map_put(self, insn->address, (uint64_t)(self->list_element));
		}
		
		if (!first){
			first = self->list_element;
		}
	}

	cs_free(insn, 1);
	cs_close(&handle);
	if (no_munmap) {
		munmap_virtual_memory((void *)code, self->cpu);
	}
	return first;
}

disassembler_t* init_disassembler(CPUState *cpu, uint64_t min_addr, uint64_t max_addr, void (*handler)(uint64_t)){
	disassembler_t* res = malloc(sizeof(disassembler_t));
	res->cpu = cpu;
	res->min_addr = min_addr;
	res->max_addr = max_addr;
	res->handler = handler;
	res->debug = false;
	res->map = kh_init(ADDR0);
	res->list_head = create_list_head();
	res->list_element = res->list_head;
	return res;
}

void destroy_disassembler(disassembler_t* self){
	kh_destroy(ADDR0, self->map);
	free_list(self->list_head);
	free(self);
}

static inline bool out_of_bounds(disassembler_t* self, uint64_t addr){
	return ((addr < self->min_addr) | (addr > self->max_addr));
}

static inline cofi_list* get_obj(disassembler_t* self, uint64_t entry_point, tnt_cache_t* tnt_cache_state){
	cofi_list *tmp_obj;

	if (!count_tnt(tnt_cache_state))
		return NULL;
	if (out_of_bounds(self, entry_point)){
		return NULL;
	}
	
	if(map_get(self, entry_point, (uint64_t *)&tmp_obj)){
		tmp_obj = analyse_assembly(self, entry_point, false);
	}

	if (!tmp_obj || !tmp_obj->cofi_ptr) {
		tmp_obj = analyse_assembly(self, entry_point, true);
	}

	if (!tmp_obj->cofi_ptr) {
		printf("Fatal error 1 in get_obj.\n");
		asm("int $3\r\n");
	}
	return tmp_obj;
}

static inline cofi_list* get_cofi_ptr(disassembler_t* self, cofi_list *obj)
{
	cofi_list *tmp_obj;

	if (!obj->cofi_ptr) {
		tmp_obj = analyse_assembly(self, obj->cofi->ins_addr, true);
		if (!tmp_obj->cofi_ptr) {
			printf("Fatal error 1 in get_cofi_ptr.\n");
			asm("int $3\r\n");
		}
	} else {
		tmp_obj = obj->cofi_ptr;
	}

	return tmp_obj;
}

bool trace_disassembler(disassembler_t* self, uint64_t entry_point, bool isr, tnt_cache_t* tnt_cache_state){
	cofi_list *obj, *last_obj;
	uint8_t tnt;
		
	obj = get_obj(self, entry_point, tnt_cache_state);
	self->handler(entry_point);
	while(true){		
		
		if(!obj){
			if (!count_tnt(tnt_cache_state))
				return true;
			goto __ret_false;
		}
		
		switch(obj->cofi->type){

			case COFI_TYPE_CONDITIONAL_BRANCH:
				tnt = process_tnt_cache(tnt_cache_state);
				switch(tnt){
					case TNT_EMPTY:
						return true;
					case TAKEN:
						sample_decoded_detailed("(%d)\t%lx\t(Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH, obj->cofi->ins_addr);
						self->handler(obj->cofi->target_addr);
						if (out_of_bounds(self, obj->cofi->ins_addr)) {
							if (!count_tnt(tnt_cache_state))
								return true;
							else
								goto __ret_false;
						}

						obj = get_obj(self, obj->cofi->target_addr, tnt_cache_state);
						break;
					case NOT_TAKEN:
						sample_decoded_detailed("(%d)\t%lx\t(Not Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH ,obj->cofi->ins_addr);
						//if(!count_tnt())
						//	return true;
						self->handler(obj->cofi->ins_addr + obj->cofi->ins_len);
						obj = get_cofi_ptr(self, obj);
						break;
				}
				break;

			case COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH:
				sample_decoded_detailed("(%d)\t%lx\n", COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH ,obj->cofi->ins_addr);
				last_obj = obj;
				if (out_of_bounds(self, obj->cofi->target_addr)){
					if (!count_tnt(tnt_cache_state)){
						return true;
					} else {
						goto __ret_false;
					}
					//obj = get_cofi_ptr(self, obj);
				} else {
					obj = get_obj(self, obj->cofi->target_addr, tnt_cache_state);
				}
				/* loop */
				if(obj && (last_obj->cofi->ins_addr == obj->cofi->ins_addr)){
					goto __ret_false;
				}
				break;

			case COFI_TYPE_INDIRECT_BRANCH:
				self->handler(obj->cofi->target_addr);
				sample_decoded_detailed("(2)\t%lx\n",obj->cofi->ins_addr);
				if (!count_tnt(tnt_cache_state)){
					return true;
				} else {
					goto __ret_false;
				}
				obj = get_cofi_ptr(self, obj);
				break;

			case COFI_TYPE_NEAR_RET:
				sample_decoded_detailed("(3)\t%lx\n",obj->cofi->ins_addr);
				if (!count_tnt(tnt_cache_state))
					return true;
				else
					goto __ret_false;
				obj = get_cofi_ptr(self, obj);
				break;

			case COFI_TYPE_FAR_TRANSFERS:
				sample_decoded_detailed("(4)\t%lx\n",obj->cofi->ins_addr);
				if (!count_tnt(tnt_cache_state))
					return true;
				else
					goto __ret_false;
				obj = get_cofi_ptr(self, obj);
				break;

			case NO_COFI_TYPE:
				sample_decoded_detailed("(5)\t%lx\n",obj->cofi->ins_addr);
				#ifdef DEBUG 
				#endif
				obj = get_cofi_ptr(self, obj);
				break;
		}
	}

__ret_false:
	printf("Fatal error 1 in trace_disassembler.\n");
	asm("int $3\r\n");
	return false;
}

