#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

void sched_halt(void);

// Choose a user environment to run and run it.
void
sched_yield(void)
{
	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.
	
	//cprintf("\nin scheduler");
	int i,  cur_env_id;
	cur_env_id = 0;
	if(thiscpu->cpu_env){
		cur_env_id = ENVX(thiscpu->cpu_env->env_id);
	//	cprintf("\n before scheduling call. curr_env_id : %d",cur_env_id);
		}
	for(i = (cur_env_id + 1)%NENV; i != cur_env_id; i = ((i + 1)%NENV))
	{
		//cprintf("");
		if((envs[i].env_status == ENV_RUNNABLE))
			env_run(&envs[i]);
		
	}
	//cprintf("\nAfter loop Value of i %d",i);
	
	if(((envs[cur_env_id].env_status == ENV_RUNNING)||(envs[cur_env_id].env_status == ENV_RUNNABLE)) &&(envs[cur_env_id].env_cpunum == cpunum()))
		{
		//env_run(thiscpu->cpu_env);
		env_run(&envs[cur_env_id]);
		}


#if 0
struct Env *e;
int i, cur=0;
	if (curenv) cur=ENVX(curenv->env_id);
		else cur = 0;



for (i = 0; i < NENV; ++i) {
		int j = (cur+i) % NENV;
		if (j < 2) cprintf("envs[%x].env_status: %x\n", j, envs[j].env_status);
		if (envs[j].env_status == ENV_RUNNABLE) {
			if (j == 1) 
				cprintf("\n");
			env_run(envs + j);
		}
	}
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
#endif

	// sched_halt never returns
	sched_halt();
}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void
sched_halt(void)
{
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(boot_pml4e));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movq $0, %%rbp\n"
		"movq %0, %%rsp\n"
		"pushq $0\n"
		"pushq $0\n"
		"sti\n"
		"hlt\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}

