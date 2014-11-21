#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

#define E1T_VENDORID 0x8086
#define E1T_DEVICEID 0x100e

int e1T_attach(struct pci_func *pcif);

#endif	// JOS_KERN_E1000_H
