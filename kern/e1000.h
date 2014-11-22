#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

#define E1000_VENDORID 0x8086
#define E1000_DEVICEID 0x100e

#define E1000_TDBAL 0x03800 /* Transmit Descriptor Base Address Low */
#define E1000_TDBAH 0x03804 /* Transmit Descriptor Base Address High */

#define E1000_TDLEN 0x03808 /* Transmit Descriptor Length */

/* Transmit Descriptor Head and Tail */
#define E1000_TDH 0x03810 
#define E1000_TDT 0x03818

/* Transmit Control Register */
#define E1000_TCTL 0x00400 
#define E1000_TCTL_EN  0x00000002 // Transmit Enable
#define E1000_TCTL_PSP 0x00000008 // Pad Short Packets
#define E1000_TCTL_CT  0x00000ff0 // Collision Threshold
#define E1000_TCTL_COLD 0x003ff000 // Collision Distance

#define E1000_TIPG 0x00410 /* Transmit IPG */

#define E1000_NUM_OF_TX_DESC 64 /* Use the maximum number (64) of descriptors */

#define E1000_MAX_PKT_SIZE 1518 /* Use the maximum size of an Ethernet packet 1518 bytes */

/* Transmit Descriptor bit definitions */
#define E1000_TXD_STAT_DD 0x00000001
#define E1000_TXD_CMD_RS  0x00000008 
#define E1000_TXD_CMD_EOP 0x00000001 

volatile uint32_t *e1000_addr;

struct tx_desc {
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
} __attribute__((packed));

struct tx_pkt {
	uint8_t buf[E1000_MAX_PKT_SIZE];
};

int e1000_attach(struct pci_func *pcif);
void e1000_transmit_init();
int e1000_transmit(char *, int);

#endif	// JOS_KERN_E1000_H
