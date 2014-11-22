#include <kern/e1000.h>
#include <kern/pmap.h>
#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/error.h>

// LAB 6: Your driver code here

struct tx_desc tx_desc_list[E1000_NUM_OF_TX_DESC] __attribute__((aligned (16)));
struct tx_pkt  tx_pkt_list[E1000_NUM_OF_TX_DESC];

int e1000_attach(struct pci_func *f) {
	// E3: Enable PCI
	pci_func_enable(f);

	// E4: Memory-mapped I/O
	e1000_addr = (volatile uint32_t *) mmio_map_region(f->reg_base[0], f->reg_size[0]);
	// Note: print below is to test E4
	//cprintf("e1T_addr[0x00008h]:%x\n", e1T_addr[0x00008/4]);

	/* Transmit initialization */
	e1000_transmit_init();

	return 0;
}

/*
	Declaration: When debugging this function, I have read the code in the following link:	https://github.com/benwei/MIT-JOS/blob/lab6/kern/e1000.c
	Please take this into consideration when scoring if necessary.
*/
void e1000_transmit_init() {
	// Allocate a region of memory for the transmit descriptor list
        memset(tx_desc_list, 0x0, sizeof(struct tx_desc) * E1000_NUM_OF_TX_DESC);
        memset(tx_pkt_list, 0x0, sizeof(struct tx_pkt) * E1000_NUM_OF_TX_DESC);
        uint32_t i;
        for (i = 0; i < E1000_NUM_OF_TX_DESC; i++) {
                tx_desc_list[i].addr = PADDR(tx_pkt_list[i].buf);
        	tx_desc_list[i].status |= E1000_TXD_STAT_DD;
	}
	
	// Set TDBAL/TDBAH register value with address of region
	e1000_addr[E1000_TDBAL/4] = PADDR(tx_desc_list);
	e1000_addr[E1000_TDBAH/4] = 0x0;

	// Set TDLEN register
	e1000_addr[E1000_TDLEN/4] = sizeof(struct tx_desc) * E1000_NUM_OF_TX_DESC;

	// Set Transmit Descriptor Head and Tail (TDH/TDT)
	e1000_addr[E1000_TDH/4] = 0x0;
	e1000_addr[E1000_TDT/4] = 0x0;

	// Set Transmit Control Register (TCTL)
	e1000_addr[E1000_TCTL/4] |= E1000_TCTL_EN | E1000_TCTL_PSP; 
	e1000_addr[E1000_TCTL/4] &= ~E1000_TCTL_CT;
	e1000_addr[E1000_TCTL/4] |= (0x10) << 4; 
	e1000_addr[E1000_TCTL/4] &= ~E1000_TCTL_COLD;
	e1000_addr[E1000_TCTL/4] |= (0x40) << 12;

	// Set Transmit IPG Register
	e1000_addr[E1000_TIPG/4] = 0x0;
	e1000_addr[E1000_TIPG/4] |= 0xA; // IPGR
	e1000_addr[E1000_TIPG/4] |= (0x6) << 20; // IPGR2
	e1000_addr[E1000_TIPG/4] |= (0x4) << 10; // IPGR1
}

int e1000_transmit(char *data2TX, int len) {
	//cprintf("transmit............................");

	if (len > E1000_MAX_PKT_SIZE) {
		return -E_PKT_TOO_LONG;
	}

	uint32_t tdt = e1000_addr[E1000_TDT/4];
	if (!(tx_desc_list[tdt].status & E1000_TXD_STAT_DD)) {
		return -E_NO_DESC;
	}

	memmove(tx_pkt_list[tdt].buf, data2TX, len);
	tx_desc_list[tdt].length = len;
	tx_desc_list[tdt].status &= ~E1000_TXD_STAT_DD;
	tx_desc_list[tdt].cmd |= E1000_TXD_CMD_RS;
	tx_desc_list[tdt].cmd |= E1000_TXD_CMD_EOP;

	// Move TDT to the next, circularly update 
	e1000_addr[E1000_TDT/4] = (tdt + 1) % E1000_NUM_OF_TX_DESC;

	return 0; 
}
