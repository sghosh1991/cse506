// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if ((err & FEC_WR) == 0){
		cprintf("va: %x, err: %d \n", addr, err);
		panic("ERROR: the faulting access was not a write.");
	}
	if ((uvpt[PGNUM(addr)] & PTE_COW) == 0)
		panic("ERROR: the faulting access was not to a COW page.");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	// Allocate a new page, and map it to PFTEMP temporially
	if ((r = sys_page_alloc(0, (void *)PFTEMP, PTE_U|PTE_P|PTE_W)) < 0)
		panic("ERROR in lib/fork.c -- pgfault(): sys_page_alloc error %e", r);	
	
	// Copy the data from old page to the new page
	memmove((void *)PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	// Rebuild the map and terminate the old map
	if ((r = sys_page_map(0, (void *)PFTEMP, 0, ROUNDDOWN(addr, PGSIZE), 
		PTE_U|PTE_P|PTE_W)) < 0)
		panic("ERROR in lib/fork.c -- pgfault(): sys_page_map error %e", r);
	if ((r = sys_page_unmap(0, (void *)PFTEMP)) < 0)
		panic("ERROR in lib/fork.c -- pgfault(): sys_page_unmap error %e", r);

	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void *addr = (void *)((uint64_t)pn * PGSIZE);
	int perm = uvpt[PGNUM(addr)] & PTE_SYSCALL;	
	
	if (perm & PTE_SHARE) {
		if ((r = sys_page_map(0, addr, envid, addr, perm)) < 0)
			panic("ERROR: sys_page_map %e", r);
		return 0;
	}

	if ((perm & PTE_W) || (perm & PTE_COW)) {
		// Copy the mapping from parent to child
		perm &= ~PTE_W;
		perm |= PTE_COW;
		if ((r = sys_page_map(0, addr, envid, addr, perm)) < 0){
			panic("1. ERROR: sys_page_map %e", r);
		}

		// Mark our mapping copy-on-write as well.
		if ((r = sys_page_map(0, addr, 0, addr, perm)) < 0)
			panic("2. ERROR: sys_page_map %e", r);
	}
	else { // Only readable page
		if ((r = sys_page_map(0, addr, envid, addr, perm)) < 0)
                        panic("3. ERROR: sys_page_map %d", r);
	}	

	//panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	set_pgfault_handler(pgfault);

	envid_t envid;
	envid = sys_exofork();
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid since it refer to the parent.
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// Invalid value
	if (envid < 0) {
		panic("sys_exofork: %e", envid);
	} 	

	// Interate through the address space below UTOP, check each
	// page's permission
	uint64_t addr;
	for (addr = UTEXT; addr < UXSTACKTOP - PGSIZE; addr += PGSIZE) {
		if ((uvpml4e[VPML4E(addr)] & PTE_P) > 0 &&
		    (uvpde[VPDPE(addr)] & PTE_P) > 0 && 
		    (uvpd[VPD(addr)] & PTE_P) > 0 && 
		    (uvpt[PGNUM(addr)] & PTE_P) > 0 && 
		    (uvpt[PGNUM(addr)] & PTE_U) > 0)
			duppage (envid, PGNUM(addr));
	
		if ((uvpml4e[VPML4E(addr)] & PTE_P) <= 0) {
			addr += (0x4000000000 - PGSIZE);
		}
		else if ((uvpde[VPDPE(addr)] & PTE_P) <= 0) {
			addr += (0x30000000 - PGSIZE);
		}
		else if ((uvpd[VPD(addr)] & PTE_P) <= 0) {
			addr += (0x200000 - PGSIZE);
		}
	}

	int r;
	// Parent allocae a page for child's exception stack
	if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), 
		PTE_U|PTE_W|PTE_P)) < 0)
		panic("ERROR in lib/fork.c: sys_page_alloc error: %e", r);

	// Parent set the page-fault entrypoint for the child
	extern void _pgfault_upcall();
	sys_env_set_pgfault_upcall(envid, _pgfault_upcall);

	// Set this child environment runable
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("ERROR in lib/fork.c: sys_env_set_status error: %e", r);	

	return envid;
	//panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
