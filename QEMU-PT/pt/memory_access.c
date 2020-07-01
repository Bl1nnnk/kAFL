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

#include "memory_access.h"

bool read_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
	uint8_t tmp_buf[x86_64_PAGE_SIZE];
	MemTxAttrs attrs;
	hwaddr phys_addr;
	int asidx;
	uint64_t counter, l;
	
	counter = size;
	
	//cpu_synchronize_state(cpu);
	kvm_cpu_synchronize_state(cpu);

	/* copy per page */
	while(counter > 0){
		
		asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
		attrs = MEMTXATTRS_UNSPECIFIED;
		phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
		
		if (phys_addr == -1){
			printf("FAIL 1 (%lx)!\n", address);
			return false;
		}

		l = x86_64_PAGE_SIZE - (address & x86_64_PAGE_OFF_MASK);
		if (l > counter) {
			l = counter;
		}

		phys_addr += (address & ~x86_64_PAGE_MASK);	
		address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, tmp_buf, l, false);
		
		memcpy(data, tmp_buf, l);
		
		data += l;
		address += l;
		counter -= l;
	}
	
	return true;
}


bool write_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu)
{
	/* Todo: later &address_space_memory + phys_addr -> mmap SHARED */
	int asidx;
	MemTxAttrs attrs;
	hwaddr phys_addr;
	MemTxResult res;
	
	uint64_t counter, l;
	
	kvm_cpu_synchronize_state(cpu);

	counter = size;
	while(counter > 0){
		
		asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
		attrs = MEMTXATTRS_UNSPECIFIED;
		phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
		
		if (phys_addr == -1){
			printf("FAIL 1 (%lx)!\n", address);
			return false;
		}

		l = x86_64_PAGE_SIZE - (address & x86_64_PAGE_OFF_MASK);
		if (l > counter) {
			l = counter;
		}

		phys_addr += (address & ~x86_64_PAGE_MASK);	
		res = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, l, true);
		if (res != MEMTX_OK){
			printf("FAIL 1 (%lx)!\n", address);
			return false;
		}
		
		data += l;
		address += l;
		counter -= l;
	}

	return true;
}

/* Mmap guest virtual address to host address with size of 1 */
void *mmap_virtual_memory(uint64_t address, CPUState *cpu)
{
	hwaddr phys_addr;
	hwaddr len = 1;
	//target_ulong host_addr;

	phys_addr = cpu_get_phys_page_debug(cpu, (address & x86_64_PAGE_MASK));
	if (phys_addr == -1){
		printf("pu_get_phys_page_debug return -1 with address of %lx\n", address);
		return NULL;
	}

	return cpu_physical_memory_map(phys_addr + (address & ~x86_64_PAGE_MASK), &len, false);
}

void munmap_virtual_memory(void *buffer, CPUState *cpu)
{
	cpu_physical_memory_unmap(buffer, 1, false, 1);
}
