/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
	//user_mem_assert(curenv, (void*)s, len, PTE_P | PTE_U);
	// Print the string supplied by the user.
	user_mem_assert(curenv, (void*)s, len, PTE_P | PTE_U);
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.
	
	struct Env *env;
	struct Env *parent_env;
	//int parent_env_id = thiscpu->cpu_env->env_id;
	int fork_res;

	fork_res = envid2env(0, &parent_env, 1); 
	if(fork_res < 0)
	{ 
	 	cprintf("\nexofork bad envid\n"); 
	 	return fork_res; 
	}
	fork_res = env_alloc(&env, parent_env->env_id);
	if(fork_res < 0)
		return ((envid_t)fork_res);

	env->env_status = ENV_NOT_RUNNABLE;

	env->env_tf = parent_env->env_tf;
	(env->env_tf).tf_regs.reg_rax = 0;
	
	return env->env_id;

	// LAB 4: Your code here.
	panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.
	
	int stat_err;
	struct Env *tar_env;

	stat_err = envid2env(envid, &tar_env, 1);

	if(stat_err < 0)
		return stat_err;

	else if((status != ENV_RUNNABLE) && (status != ENV_NOT_RUNNABLE))
		return -E_INVAL;

	tar_env->env_status = status;
	return 0;

	// LAB 4: Your code here.
	panic("sys_env_set_status not implemented");
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	struct Env *env;
	int r;

	if ((r = envid2env(envid, &env, 1) < 0))
		return -E_BAD_ENV;

	user_mem_assert(env, tf, sizeof(struct Trapframe), PTE_U);

	env->env_tf = *tf;
	env->env_tf.tf_cs = GD_UT | 3;
	env->env_tf.tf_eflags |= FL_IF;

	return 0;
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *curr_task;
	// cprintf("program here.");
	if (envid2env(envid, &curr_task, 1) < 0){
		return -E_BAD_ENV;
	}

	curr_task->env_pgfault_upcall = func;

	return 0;
	//panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	struct Env *env;
	struct PageInfo *page_var;

	if(envid2env(envid, &env, 1) < 0)
		return -E_BAD_ENV;

	if(((uint64_t)va >= UTOP) || (((uint64_t)va % PGSIZE) != 0))
	{
		cprintf("\nI faulted because va is either < UTOP or it's not rounded down\n");
		return -E_INVAL;
	}

	if((!(perm & PTE_U)) || (!(perm & PTE_P)) || (perm & ~PTE_SYSCALL))
	{
		cprintf("\nI faulted because the permissions for the page allocation are not correct\n");
		return -E_INVAL;
	}
	if(!(page_var = page_alloc(ALLOC_ZERO)))
	//if(!(page_var = page_alloc(0)))
	{
		cprintf("\nNo more free memory left\n");
		return -E_NO_MEM;
	}

	if((page_insert(env->env_pml4e, page_var, va, perm)))
	{
		cprintf("\nPage insertion failed\n");
		page_free(page_var);
		return -E_NO_MEM;
	} 

	return 0;

	// LAB 4: Your code here.
	panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.
	
	struct Env *env1, *env2;
	struct PageInfo *page_var;
	pte_t *pte;

	if(envid2env(srcenvid, &env1, 1) < 0)
	{
		cprintf("\nBad parent ENV: %x\n", srcenvid);
		return -E_BAD_ENV;
	}
	if(envid2env(dstenvid, &env2, 1) < 0)
	{
		cprintf("\nBad child ENV: %x\n", dstenvid);
		return -E_BAD_ENV;
	}

	if(((uint64_t)srcva >= UTOP) || (((uint64_t)srcva % PGSIZE) != 0))
	{
		cprintf("\n Source VA(0x%0x) > UTOP\n",srcva);
		return -E_INVAL;
	}
	if(((uint64_t)dstva >= UTOP) || (((uint64_t)dstva % PGSIZE) != 0))
	{
		cprintf("\nDest. VA(0x%0x) > UTOP\n", dstva);
		return -E_INVAL;
	}

	if((!(perm & PTE_U)) && (!(perm & PTE_P)) && (perm & ~PTE_SYSCALL))
	{
		cprintf("\nInvalid perms\n");
		return -E_INVAL;
	}

	if(!(page_var = page_lookup(env1->env_pml4e, srcva, &pte)))
	{
		cprintf("\nPage lookup failure, env1\n");
		return -E_INVAL;
	}

	if(((perm & PTE_W) != 0) && ((*pte & PTE_W) == 0))
	{
		cprintf("\nNo write permissions\n");
		return -E_INVAL;
	}

	if(page_insert(env2->env_pml4e, page_var, dstva, perm))
	{	
		cprintf("\nNo Memory\n");
		page_free(page_var);
		return -E_NO_MEM;
	}

	return 0;
	
	// LAB 4:	 Your code here.
	panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().
	
	struct Env *env;
	int err;

	err = envid2env(envid, &env, 1);
	if(err < 0)
		return -E_BAD_ENV;

	if(((uint64_t)va >= UTOP) || (((uint64_t)va % PGSIZE) != 0))
	{
		cprintf("\nPage_Unmap: VA >= UTOP or VA is not page-aligned\n");
		return -E_INVAL;
	}
	page_remove(env->env_pml4e, va);

	return 0; 

	// LAB 4: Your code here.
	panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.

	struct Env *env;
	pte_t *pte;

	if (envid2env(envid, &env, 0) < 0) {
		cprintf("sys_ipc_try_send failed: Bad env\n");
		return -E_BAD_ENV;
	}

	if ((env->env_status != ENV_NOT_RUNNABLE) || (env->env_ipc_recving != 1))
	    return -E_IPC_NOT_RECV;
	
	if ((uint64_t)srcva < UTOP){
		//Check if the page in alligned.
	   	if ((uint64_t)srcva % PGSIZE != 0) {
			cprintf("sys_ipc_try_send failed: Page is not alligned\n");
	      		return -E_INVAL;
		}

	  	//Check if srcva is mapped to in caller's address space.
	   	pte = pml4e_walk(curenv->env_pml4e, srcva, 0);

	   	if (!pte || !((*pte) & PTE_P)) {
	      		cprintf("\nsys_ipc_try_send failed: Page is not mapped to srcva\n");
	      		return -E_INVAL;
	   	}
	
	   	//Check for permissions
	   	if (!(perm & PTE_U) || !(perm & PTE_P)) {
	      		cprintf("\nsys_try_ipc_send failed: Invalid permissions\n");
	      		return -E_INVAL;
	   	}
	   	if (perm &(!PTE_USER)) {
       	      		cprintf("sys_try_ipc_send failed: Invalid permissions\n");
       	      		return - E_INVAL;
    	   	}
	   	if (!((*pte) & PTE_W) && (perm & PTE_W)) {
	      		cprintf("\nsys_try_ipc_send failed: Writing on read-only page\n");
	      		return -E_INVAL; 
	   	}

	}

	env->env_ipc_recving = 0;
	env->env_ipc_value = value;
	env->env_ipc_from = curenv->env_id;
	env->env_ipc_perm = 0;
	
	if ((uint64_t)srcva < UTOP) {
		pte_t *pite;
		struct PageInfo *pp;
	   	pp = page_lookup(curenv->env_pml4e, srcva, &pte);
	   
	   	if (!pp) {
	      		cprintf("\nsys_try_ipc_send: Page not found\n");
	      		return -1;
	   	}

	   	if (page_insert(env->env_pml4e, pp, env->env_ipc_dstva, perm) < 0)
	       		return -E_NO_MEM;

	   env->env_ipc_perm = perm;
	}
	
	env->env_status = ENV_RUNNABLE;
	return 0;



	panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	if (!curenv)
		return -E_INVAL;
	if ((uint64_t)dstva > UTOP || (ROUNDDOWN(dstva,PGSIZE)!=dstva && ROUNDUP(dstva,PGSIZE)!=dstva)) {
		cprintf("error dstva is not valid dstva=%x\n",dstva);
		return -E_INVAL;
	}


	curenv->env_tf.tf_regs.reg_rax = 0;
	
	curenv->env_ipc_dstva = dstva;
        curenv->env_ipc_perm = 0;
        curenv->env_ipc_from = 0;
        curenv->env_ipc_recving = 1; //Receiver is ready to listen
        curenv->env_status = ENV_NOT_RUNNABLE; //Block the execution of current env.

	sched_yield(); //Give up the cpu. Don't return, instead env_run some other env.


	panic("sys_ipc_recv not implemented");
	return 0;
}


// Return the current time.
static int
sys_time_msec(void)
{
	// LAB 6: Your code here.
	return time_msec();
	//panic("sys_time_msec not implemented");
}



// Dispatches to the correct kernel function, passing the arguments.
int64_t
syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
	int64_t syscall_return = 0;
	//panic("syscall not implemented");
	//cprintf("In kern/syscall.c");
	switch (syscallno) {

	case SYS_cputs :
		sys_cputs((const char *)a1, a2);
		break;
	case SYS_cgetc :
		syscall_return = sys_cgetc();
		break;
	case SYS_getenvid:
		syscall_return = sys_getenvid();
		break;
	case SYS_env_destroy:
		sys_env_destroy((envid_t)a1);
		break;
	case NSYSCALLS:
		break;
	case SYS_yield:
		sys_yield();
		break;
	
	case SYS_exofork:
		syscall_return = sys_exofork();
		break;
	case SYS_env_set_status:
		syscall_return = sys_env_set_status(a1, a2);
		break;
	case  SYS_page_alloc:
		syscall_return = sys_page_alloc(a1, (void *)a2, a3);
		break;
	case SYS_page_unmap:
		return sys_page_unmap(a1, (void *)a2);
	case SYS_page_map:
		syscall_return = sys_page_map(a1, (void *)a2, a3, (void *)a4, a5);
		break;
	case SYS_env_set_pgfault_upcall:
		syscall_return = sys_env_set_pgfault_upcall(a1, (void *)a2);
		break;
	case SYS_ipc_try_send:
                syscall_return = sys_ipc_try_send(a1, a2, (void*)a3, a4);
                break;

	case SYS_ipc_recv:
                syscall_return = sys_ipc_recv((void*)a1);
                break;

	case SYS_env_set_trapframe:
		syscall_return = sys_env_set_trapframe((envid_t) a1, (struct Trapframe *)a2);
		break;

	case SYS_time_msec:
		syscall_return = sys_time_msec();
		break;

	default:
		return -E_INVAL;
		break;
	}
	return syscall_return;
}

