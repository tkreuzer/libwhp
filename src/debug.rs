use platform::*;
pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;

pub fn dump_run_context(run_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    println!("ExitReason: {:?}", run_context.ExitReason);
    println!("Reserved = {}", run_context.Reserved);
    println!("Run context: {:?}", run_context.VpContext);
    println!("Execution state: {}", run_context.VpContext.ExecutionState);
}

pub fn dump_vp_regs(vp: &VirtualProcessor) {
    dump_gp_regs(vp);
    dump_segment_regs(vp);
    dump_table_regs(vp);
    dump_control_regs(vp);
    dump_debug_regs(vp);
    dump_fp_regs(vp);
    dump_msr_regs(vp);
    dump_interrupt_regs(vp);
}

pub fn dump_gp_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 18;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterRax,
        WHV_REGISTER_NAME::WHvX64RegisterRcx,
        WHV_REGISTER_NAME::WHvX64RegisterRdx,
        WHV_REGISTER_NAME::WHvX64RegisterRbx,
        WHV_REGISTER_NAME::WHvX64RegisterRsp,
        WHV_REGISTER_NAME::WHvX64RegisterRbp,
        WHV_REGISTER_NAME::WHvX64RegisterRsi,
        WHV_REGISTER_NAME::WHvX64RegisterRdi,
        WHV_REGISTER_NAME::WHvX64RegisterR8,
        WHV_REGISTER_NAME::WHvX64RegisterR9,
        WHV_REGISTER_NAME::WHvX64RegisterR10,
        WHV_REGISTER_NAME::WHvX64RegisterR11,
        WHV_REGISTER_NAME::WHvX64RegisterR12,
        WHV_REGISTER_NAME::WHvX64RegisterR13,
        WHV_REGISTER_NAME::WHvX64RegisterR14,
        WHV_REGISTER_NAME::WHvX64RegisterR15,
        WHV_REGISTER_NAME::WHvX64RegisterRip,
        WHV_REGISTER_NAME::WHvX64RegisterRflags,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    let mut idx = 0;
    println!("Regs:");
    for v in reg_names.iter() {
        unsafe {
            println!("{:?} = 0x{:x?}", v, reg_values[idx].Reg64);
        }
        idx += 1;
    }
    println!("");
}

pub fn dump_segment_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 8;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterEs,
        WHV_REGISTER_NAME::WHvX64RegisterCs,
        WHV_REGISTER_NAME::WHvX64RegisterSs,
        WHV_REGISTER_NAME::WHvX64RegisterDs,
        WHV_REGISTER_NAME::WHvX64RegisterFs,
        WHV_REGISTER_NAME::WHvX64RegisterGs,
        WHV_REGISTER_NAME::WHvX64RegisterLdtr,
        WHV_REGISTER_NAME::WHvX64RegisterTr,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    let mut idx = 0;
    println!("Segment regs:");
    for v in reg_names.iter() {
        unsafe {
            println!("{:?} = {}", v, reg_values[idx].Segment);
        }
        idx += 1;
    }
    println!("");
}

pub fn dump_table_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 2;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterIdtr,
        WHV_REGISTER_NAME::WHvX64RegisterGdtr,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    unsafe {
        println!("Idtr = {:?}", reg_values[0].Table);
        println!("Gdtr = {:0?}", reg_values[1].Table);
    }
    println!("");
}

pub fn dump_control_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 5;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterCr0,
        WHV_REGISTER_NAME::WHvX64RegisterCr2,
        WHV_REGISTER_NAME::WHvX64RegisterCr3,
        WHV_REGISTER_NAME::WHvX64RegisterCr4,
        WHV_REGISTER_NAME::WHvX64RegisterCr8,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    let mut idx = 0;
    println!("Control regs:");
    for v in reg_names.iter() {
        unsafe {
            println!("{:?} = 0x{:x?}", v, reg_values[idx].Reg64);
        }
        idx += 1;
    }
    println!("");
}

pub fn dump_debug_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 6;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterDr0,
        WHV_REGISTER_NAME::WHvX64RegisterDr1,
        WHV_REGISTER_NAME::WHvX64RegisterDr2,
        WHV_REGISTER_NAME::WHvX64RegisterDr3,
        WHV_REGISTER_NAME::WHvX64RegisterDr6,
        WHV_REGISTER_NAME::WHvX64RegisterDr7,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    unsafe {
        println!(
            "Dr0={:016x} Dr1={:016x} Dr2={:016x} \n\
             Dr3={:016x} Dr6={:016x} Dr7={:016x}",
            reg_values[0].Reg64,
            reg_values[1].Reg64,
            reg_values[2].Reg64,
            reg_values[3].Reg64,
            reg_values[4].Reg64,
            reg_values[5].Reg64,
        );
    }
}

fn dump_fp_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 26;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterXmm0,
        WHV_REGISTER_NAME::WHvX64RegisterXmm1,
        WHV_REGISTER_NAME::WHvX64RegisterXmm2,
        WHV_REGISTER_NAME::WHvX64RegisterXmm3,
        WHV_REGISTER_NAME::WHvX64RegisterXmm4,
        WHV_REGISTER_NAME::WHvX64RegisterXmm5,
        WHV_REGISTER_NAME::WHvX64RegisterXmm6,
        WHV_REGISTER_NAME::WHvX64RegisterXmm7,
        WHV_REGISTER_NAME::WHvX64RegisterXmm8,
        WHV_REGISTER_NAME::WHvX64RegisterXmm9,
        WHV_REGISTER_NAME::WHvX64RegisterXmm10,
        WHV_REGISTER_NAME::WHvX64RegisterXmm11,
        WHV_REGISTER_NAME::WHvX64RegisterXmm12,
        WHV_REGISTER_NAME::WHvX64RegisterXmm13,
        WHV_REGISTER_NAME::WHvX64RegisterXmm14,
        WHV_REGISTER_NAME::WHvX64RegisterXmm15,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx0,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx1,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx2,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx3,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx4,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx5,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx6,
        WHV_REGISTER_NAME::WHvX64RegisterFpMmx7,
        WHV_REGISTER_NAME::WHvX64RegisterFpControlStatus,
        WHV_REGISTER_NAME::WHvX64RegisterXmmControlStatus,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    unsafe {
        println!(
            "Xmm0={:016x}{:016x}  Xmm1={:016x}{:016x} \n\
             Xmm2={:016x}{:016x}  Xmm3={:016x}{:016x} \n\
             Xmm4={:016x}{:016x}  Xmm5={:016x}{:016x} \n\
             Xmm6={:016x}{:016x}  Xmm7={:016x}{:016x} \n\
             Xmm8={:016x}{:016x}  Xmm9={:016x}{:016x} \n\
             Xmm10={:016x}{:016x} Xmm11={:016x}{:016x} \n\
             Xmm12={:016x}{:016x} Xmm13={:016x}{:016x} \n\
             Xmm14={:016x}{:016x} Xmm15={:016x}{:016x} \n\
             Mmx0={:016x} Mmx1={:016x} Mmx2={:016x} \n\
             Mmx3={:016x} Mmx4={:016x} Mmx5={:016x} \n\
             Mmx6={:016x} Mmx7={:016x} \n\
             Csr={:016x} XCsr={:016x}",
            reg_values[0].Fp.AsUINT128.High64,
            reg_values[0].Fp.AsUINT128.Low64,
            reg_values[1].Fp.AsUINT128.High64,
            reg_values[1].Fp.AsUINT128.Low64,
            reg_values[2].Fp.AsUINT128.High64,
            reg_values[2].Fp.AsUINT128.Low64,
            reg_values[3].Fp.AsUINT128.High64,
            reg_values[3].Fp.AsUINT128.Low64,
            reg_values[4].Fp.AsUINT128.High64,
            reg_values[4].Fp.AsUINT128.Low64,
            reg_values[5].Fp.AsUINT128.High64,
            reg_values[5].Fp.AsUINT128.Low64,
            reg_values[6].Fp.AsUINT128.High64,
            reg_values[6].Fp.AsUINT128.Low64,
            reg_values[7].Fp.AsUINT128.High64,
            reg_values[7].Fp.AsUINT128.Low64,
            reg_values[8].Fp.AsUINT128.High64,
            reg_values[8].Fp.AsUINT128.Low64,
            reg_values[9].Fp.AsUINT128.High64,
            reg_values[9].Fp.AsUINT128.Low64,
            reg_values[10].Fp.AsUINT128.High64,
            reg_values[10].Fp.AsUINT128.Low64,
            reg_values[11].Fp.AsUINT128.High64,
            reg_values[11].Fp.AsUINT128.Low64,
            reg_values[12].Fp.AsUINT128.High64,
            reg_values[12].Fp.AsUINT128.Low64,
            reg_values[13].Fp.AsUINT128.High64,
            reg_values[13].Fp.AsUINT128.Low64,
            reg_values[14].Fp.AsUINT128.High64,
            reg_values[14].Fp.AsUINT128.Low64,
            reg_values[15].Fp.AsUINT128.High64,
            reg_values[15].Fp.AsUINT128.Low64,
            reg_values[16].Reg64,
            reg_values[17].Reg64,
            reg_values[18].Reg64,
            reg_values[19].Reg64,
            reg_values[20].Reg64,
            reg_values[21].Reg64,
            reg_values[22].Reg64,
            reg_values[23].Reg64,
            reg_values[24].Reg64,
            reg_values[25].Reg64,
        );
    }
}

pub fn dump_msr_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 12;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterTsc,
        WHV_REGISTER_NAME::WHvX64RegisterEfer,
        WHV_REGISTER_NAME::WHvX64RegisterKernelGsBase,
        WHV_REGISTER_NAME::WHvX64RegisterApicBase,
        WHV_REGISTER_NAME::WHvX64RegisterPat,
        WHV_REGISTER_NAME::WHvX64RegisterSysenterCs,
        WHV_REGISTER_NAME::WHvX64RegisterSysenterEip,
        WHV_REGISTER_NAME::WHvX64RegisterSysenterEsp,
        WHV_REGISTER_NAME::WHvX64RegisterStar,
        WHV_REGISTER_NAME::WHvX64RegisterLstar,
        WHV_REGISTER_NAME::WHvX64RegisterCstar,
        WHV_REGISTER_NAME::WHvX64RegisterSfmask,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    let mut idx = 0;
    println!("Msr regs:");
    for v in reg_names.iter() {
        unsafe {
            println!("{:?} = 0x{:x?}", v, reg_values[idx].Reg64);
        }
        idx += 1;
    }
    println!("");
}

pub fn dump_interrupt_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 5;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvRegisterPendingInterruption,
        WHV_REGISTER_NAME::WHvRegisterInterruptState,
        WHV_REGISTER_NAME::WHvRegisterPendingEvent,
        WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications,
        WHV_REGISTER_NAME::WHvRegisterInternalActivityState,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    println!("Interrupt regs:");
    let mut idx = 0;
    unsafe {
        println!(
            "{:?} = {}",
            reg_names[idx], reg_values[idx].PendingInterruption
        );
    }
    let event_type = unsafe { reg_values[idx].PendingInterruption.InterruptionType() };

    idx += 1;
    unsafe {
        println!("{:?} = {}", reg_names[idx], reg_values[idx].InterruptState);
    }
    idx += 1;

    if event_type == WHV_X64_PENDING_EVENT_TYPE::WHvX64PendingEventException as u64 {
        unsafe {
            println!("{:?} = {}", reg_names[idx], reg_values[idx].ExceptionEvent);
        }
    } else if event_type == WHV_X64_PENDING_EVENT_TYPE::WHvX64PendingEventException as u64 {
        unsafe {
            println!("{:?} = {}", reg_names[idx], reg_values[idx].ExtIntEvent);
        }
    } else {
        println!("Unknown event type: {}", event_type);
    }
    idx += 1;
    unsafe {
        println!(
            "{:?} = {}",
            reg_names[idx], reg_values[idx].DeliverabilityNotifications
        );
    }
    idx += 1;
    unsafe {
        println!("{:?} = {}", reg_names[idx], reg_values[idx].Reg128);
    }
    println!("");
}

pub fn dump_cpu_counters(vp: &VirtualProcessor) {
    dump_apic_counters(vp);
    dump_cpu_runtime_counters(vp);
    dump_cpu_intercept_counters(vp);
    dump_cpu_event_counters(vp);
}

pub fn dump_apic_counters(vp: &VirtualProcessor) {
    let counters: WHV_PROCESSOR_COUNTERS = vp
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetApic)
        .unwrap();
    unsafe {
        println!("Apic counters: {:#?}\n", counters.ApicCounters);
    }
}

pub fn dump_cpu_runtime_counters(vp: &VirtualProcessor) {
    let counters: WHV_PROCESSOR_COUNTERS = vp
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetRuntime)
        .unwrap();
    unsafe {
        println!("CPU runtime counters: {:#?}\n", counters.RuntimeCounters);
    }
}

pub fn dump_cpu_intercept_counters(vp: &VirtualProcessor) {
    let counters: WHV_PROCESSOR_COUNTERS = vp
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetIntercepts)
        .unwrap();
    unsafe {
        println!(
            "CPU intercept counters: {:#?}\n",
            counters.InterceptCounters
        );
    }
}

pub fn dump_cpu_event_counters(vp: &VirtualProcessor) {
    let counters: WHV_PROCESSOR_COUNTERS = vp
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetEvents)
        .unwrap();
    unsafe {
        println!("CPU event counters: {:#?}\n", counters.EventCounters);
    }
}
