#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>
#include <inc/types.h>
#include <inc/string.h>
#include <inc/error.h>
// LAB 6: Your driver code here

volatile uint32_t *e1000_mmio_addr;
struct tx_desc tx_desc_list[BUFFER_SIZE];
struct rx_desc rx_desc_list[RX_BUFFER_SIZE];
char packet_buf[BUFFER_SIZE][PACKET_SIZE];
char rx_packet_buf[BUFFER_SIZE][RX_PACKET_SIZE];


int e1000_attach(struct pci_func *pcif)
{
	uint32_t dev_stat_reg;
	
	pci_func_enable(pcif);
	e1000_mmio_addr = mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
	// check if we're mappped correctly
	dev_stat_reg = *(e1000_mmio_addr + 2);

	e1000_initialize();	
	return 1;
}


void e1000_initialize()
{

	//Set the register values
	*(e1000_mmio_addr + e1000_tdbal/4) = PADDR(tx_desc_list);
	// Not initializing TDBAH because 64-bit JOS address space is as good as 32-bit address space

	*(e1000_mmio_addr + e1000_tdlen/4) = sizeof(tx_desc_list);
	*(e1000_mmio_addr + e1000_tdh/4) = 0x0;
	*(e1000_mmio_addr + e1000_tdt/4) = 0x0;

	*(e1000_mmio_addr + e1000_tctl/4) = e1000_tctl_en | e1000_tctl_psp | e1000_tctl_ct | e1000_tctl_cold;

	*(e1000_mmio_addr + e1000_tipg/4) = 0x00802008;

	int i;
	for(i = 0; i < BUFFER_SIZE; i++)
	{	
		tx_desc_list[i].status |= e1000_tx_stat_dd;
		tx_desc_list[i].buf_addr = PADDR(packet_buf[i]);
	}

	//Receive Initialize
	// *(e1000_mmio_addr + e1000_mta/4) = 0;
        // *(e1000_mmio_addr + (e1000_mta/4) +1) = 0;

	for(i = 0;i < RX_BUFFER_SIZE; i++)
	 {
		 rx_desc_list[i].buf_addr = PADDR(rx_packet_buf[i]);
		 //rx_desc_list[i].status |= 0x4 | e1000_rx_stat_dd | e1000_rx_stat_eop;
	 }

	 *(e1000_mmio_addr + e1000_rx_ral/4) = 0x12005452;
	 *(e1000_mmio_addr + e1000_rx_rah/4) = 0x5634 | e1000_rx_rah_av;
	 *(e1000_mmio_addr + e1000_mta/4) = 0;

	 *(e1000_mmio_addr + e1000_rdbal/4) = PADDR(rx_desc_list);
	 *(e1000_mmio_addr + e1000_rdlen/4) = sizeof(rx_desc_list);
	 *(e1000_mmio_addr + e1000_rdh/4) = 0x0;
	 *(e1000_mmio_addr + e1000_rdt/4) = 0x0;

	 *(e1000_mmio_addr + e1000_rctl/4) = e1000_rctl_en | e1000_rctl_bam | e1000_rctl_crc;

	return;

}

int e1000_transmit(char *pkt_buf, uint32_t pkt_length)
{

	uint32_t tdt, next_tdt;
	tdt = *(e1000_mmio_addr + e1000_tdt/4);
	next_tdt = (tdt + 1)%BUFFER_SIZE;

	int status = tx_desc_list[tdt].status & e1000_tx_stat_dd;

	if(!status)
		return -E_TX_RING_FULL;

	int i;
	memmove(packet_buf[tdt], pkt_buf, pkt_length);
	tx_desc_list[tdt].length = pkt_length;

	tx_desc_list[tdt].cmd |= e1000_tx_cmd_rs;
	tx_desc_list[tdt].cmd |= e1000_tx_cmd_eop;
	*(e1000_mmio_addr + e1000_tdt/4) = next_tdt;

	return 0;

}


int e1000_receive(char *pkt_buf)
{

uint32_t rdt, next_rdt;
	rdt = *(e1000_mmio_addr + e1000_rdt/4);
	next_rdt = (rdt+1)%RX_BUFFER_SIZE;
	int status = rx_desc_list[rdt].status & e1000_rx_stat_dd;

//	cprintf("\nstatus = %d\n", status);
	if(status != 0x1)
		return -E_NO_PCKT;
	int len = rx_desc_list[rdt].length;
	//cprintf("length :%d", rdt);
	//cprintf("receive packet buf=%x\n",rx_packet_buf[rdt]);
	int i;
	memmove(pkt_buf,rx_packet_buf[rdt],len);
	rx_desc_list[rdt].status = 0x0;
	 *(e1000_mmio_addr + e1000_rdt/4) = next_rdt;
	return len; 

}
