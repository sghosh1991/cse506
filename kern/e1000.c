#include <kern/e1000.h>
#include <kern/pmap.h>

// LAB 6: Your driver code here


int e1000_attach(struct pci_func *f) {
	// E3: Enable PCI
	pci_func_enable(f);

	// E4: Memory-mapped I/O
	e1000_addr = (volatile uint32_t *) mmio_map_region(f->reg_base[0], f->reg_size[0]);
	//cprintf("e1T_addr[0x00008h]:%x\n", e1T_addr[0x00008/4]);
	/*
	if (e1T_addr[0x00008] == 0x80080783)
		cprintf("Yes, it is correct.");
	else
		cprintf("No.");
	*/

	return 0;
}
