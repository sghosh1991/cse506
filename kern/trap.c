#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

extern uintptr_t gdtdesc_64;
static struct Taskstate ts;
extern struct Segdesc gdt[];
extern long gdt_pd;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {0,0};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.

	extern void divide_entry(); // "Divide error"
	extern void debug_entry(); //"Debug"
	extern void nmi_entry(); // "Non-Maskable Interrupt"
	extern void brkpt_entry(); // "Breakpoint"
	extern void oflow_entry(); // "Overflow"
	extern void bound_entry(); // "BOUND Range Exceeded"
	extern void illop_entry(); // "Invalid Opcode"
	extern void device_entry(); // "Device Not Available"
	extern void dblflt_entry(); // "Double Fault"
	/*  Note: this is reversed: "Coprocessor Segment Overrun" */
	extern void tss_entry(); // "Invalid TSS"
	extern void segnp_entry(); // "Segment Not Present"
	extern void stack_entry(); // "Stack Fault"
	extern void gpflt_entry(); // "General Protection"
	extern void pgflt_entry(); // "Page Fault"
	/* Note: this is reversed: "(unknown trap)" */
	extern void fperr_entry(); // "x87 FPU Floating-Point Error"
	extern void align_entry(); // "Alignment Check"
	extern void mchk_entry(); // "Machine-Check"
	extern void simderr_entry(); // "SIMD Floating-Point Exception"

	extern void syscall_entry(); // system call

	/* Interrupt entry */
	extern void irq_timer_entry();
	extern void irq_kbd_entry();
	extern void irq_serial_entry();
	extern void irq_spurious_entry();
	extern void irq_ide_entry();
	extern void irq_error_entry();

	/* Initialize idt to point to each entry point */
	SETGATE(idt[T_DIVIDE], 1, GD_KT, divide_entry, 0);
	SETGATE(idt[T_DEBUG], 1, GD_KT, debug_entry, 0);  
   	SETGATE(idt[T_NMI], 0, GD_KT, nmi_entry, 0);  
    	SETGATE(idt[T_BRKPT], 1, GD_KT, brkpt_entry, 3);  
    	SETGATE(idt[T_OFLOW], 1, GD_KT, oflow_entry, 0);  
    	SETGATE(idt[T_BOUND], 1, GD_KT, bound_entry, 0);  
    	SETGATE(idt[T_ILLOP], 1, GD_KT, illop_entry, 0);  
    	SETGATE(idt[T_DEVICE], 1, GD_KT, device_entry, 0);  
    	SETGATE(idt[T_DBLFLT], 1, GD_KT, dblflt_entry, 0);  
    	SETGATE(idt[T_TSS], 1, GD_KT, tss_entry, 0);  
    	SETGATE(idt[T_SEGNP], 1, GD_KT, segnp_entry, 0);  
    	SETGATE(idt[T_STACK], 1, GD_KT, stack_entry, 0);  
    	SETGATE(idt[T_GPFLT], 1, GD_KT, gpflt_entry, 0);  
    	SETGATE(idt[T_PGFLT], 1, GD_KT, pgflt_entry, 0);  
    	SETGATE(idt[T_FPERR], 1, GD_KT, fperr_entry, 0);  
    	SETGATE(idt[T_ALIGN], 1, GD_KT, align_entry, 0);  
    	SETGATE(idt[T_MCHK], 1, GD_KT, mchk_entry, 0);  
    	SETGATE(idt[T_SIMDERR], 1, GD_KT, simderr_entry, 0); 

    	SETGATE(idt[T_SYSCALL], 0, GD_KT, syscall_entry, 3);  
  
    	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, irq_timer_entry, 0);
   	SETGATE(idt[IRQ_OFFSET + IRQ_KBD], 0, GD_KT, irq_kbd_entry, 0);  
    	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], 0, GD_KT, irq_serial_entry, 0);  
    	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, irq_spurious_entry, 0);  
    	SETGATE(idt[IRQ_OFFSET + IRQ_IDE], 0, GD_KT, irq_ide_entry, 0);  
    	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR], 0, GD_KT, irq_error_entry, 0);



    idt_pd.pd_lim = sizeof(idt)-1;
    idt_pd.pd_base = (uint64_t)idt;
	// Per-CPU setup
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;

	// Initialize the TSS slot of the gdt.
	SETTSS((struct SystemSegdesc64 *)((gdt_pd>>16)+40),STS_T64A, (uint64_t) (&ts),sizeof(struct Taskstate), 0);
	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  rip  0x%08x\n", tf->tf_rip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  rsp  0x%08x\n", tf->tf_rsp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  r15  0x%08x\n", regs->reg_r15);
	cprintf("  r14  0x%08x\n", regs->reg_r14);
	cprintf("  r13  0x%08x\n", regs->reg_r13);
	cprintf("  r12  0x%08x\n", regs->reg_r12);
	cprintf("  r11  0x%08x\n", regs->reg_r11);
	cprintf("  r10  0x%08x\n", regs->reg_r10);
	cprintf("  r9  0x%08x\n", regs->reg_r9);
	cprintf("  r8  0x%08x\n", regs->reg_r8);
	cprintf("  rdi  0x%08x\n", regs->reg_rdi);
	cprintf("  rsi  0x%08x\n", regs->reg_rsi);
	cprintf("  rbp  0x%08x\n", regs->reg_rbp);
	cprintf("  rbx  0x%08x\n", regs->reg_rbx);
	cprintf("  rdx  0x%08x\n", regs->reg_rdx);
	cprintf("  rcx  0x%08x\n", regs->reg_rcx);
	cprintf("  rax  0x%08x\n", regs->reg_rax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	int64_t syscall_return;

	if (tf->tf_trapno == T_PGFLT) {
		page_fault_handler(tf);
		return;
	}

	if (tf->tf_trapno == T_BRKPT)
		monitor(tf);

	if (tf->tf_trapno == T_SYSCALL) {
		int64_t syscall_return = syscall(
			tf->tf_regs.reg_rax, tf->tf_regs.reg_rdx,
			tf->tf_regs.reg_rcx, tf->tf_regs.reg_rbx,
			tf->tf_regs.reg_rdi, tf->tf_regs.reg_rsi);
		// uint32_t syscall_ret32 = (uint32_t) syscall_return;
		tf->tf_regs.reg_rax = syscall_return;
		return;
	}

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
    //struct Trapframe *tf = &tf_;
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		assert(curenv);

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint64_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.

	if ((tf->tf_cs & 0x03) == 0)
		panic("ERROR: Page fault occurred in kernel mode : Fault va=%x\n",fault_va);	


	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_rip);
	print_trapframe(tf);
	env_destroy(curenv);
}

