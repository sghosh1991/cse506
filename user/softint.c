// buggy program - causes an illegal software interrupt

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	//cprintf("This is softint");
	asm volatile("int $14");	// page fault
}

