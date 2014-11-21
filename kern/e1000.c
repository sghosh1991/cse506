#include <kern/e1000.h>

// LAB 6: Your driver code here


int e1T_attach(struct pci_func *f) {
	// Enable PCI
	pci_func_enable(f);
	
	return 0;
}
