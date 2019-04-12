use platform::*;
pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;

pub fn dump_run_context(run_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    println!("ExitReason: {:?}", run_context.ExitReason);
    println!("Reserved = {}", run_context.Reserved);
    println!("Run context: {:?}", run_context.VpContext);
    println!("Execution state: {}", run_context.VpContext.ExecutionState);

    unsafe {
        match run_context.ExitReason {
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                dump_memory_access_context(&run_context.anon_union.MemoryAccess);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                dump_port_io_context(&run_context.anon_union.IoPortAccess);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                dump_msr_access_context(&run_context.anon_union.MsrAccess);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                dump_cpuid_access_context(&run_context.anon_union.CpuidAccess);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => {
                dump_vp_exception_context(&run_context.anon_union.VpException);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                dump_interrupt_window_context(&run_context.anon_union.InterruptWindow);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnsupportedFeature => {
                dump_unsupported_feature_context(&run_context.anon_union.UnsupportedFeature);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonCanceled => {
                dump_vp_cancelled_context(&run_context.anon_union.CancelReason);
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => {
                dump_apic_eoi_context(&run_context.anon_union.ApicEoi);
            }
            _ => {
                println!("unexected exit reason!");
            }
        }
    }

    println!("");
}

fn dump_instruction_bytes(bytes: &[u8]) {
    for idx in 0..bytes.len() {
        if (idx > 0) && (idx % 16 == 0) {
            println!("");
        }
        print!("{:02x} ", bytes[idx]);
    }
    println!("");
}

fn dump_memory_access_context(context: &WHV_MEMORY_ACCESS_CONTEXT) {
    println!("MemoryAccess:");
    println!("  InstructionByteCount: {}", context.InstructionByteCount);
    print!("  InstructionBytes: ");
    dump_instruction_bytes(&context.InstructionBytes);
    println!("  AccessInfo: 0x{:x}", context.AccessInfo.AsUINT32);
    println!("  Gpa: 0x{:x}", context.Gpa);
    println!("  Gva: 0x{:x}", context.Gva);
}

fn dump_port_io_context(context: &WHV_X64_IO_PORT_ACCESS_CONTEXT) {
    println!("IoPortAccess:");

    // Context of the virtual processor
    println!(
        "  InstructionByteCount: 0x{:x}",
        context.InstructionByteCount
    );
    println!("  Reserved: {:?}", context.Reserved);
    print!("  InstructionBytes: ");
    dump_instruction_bytes(&context.InstructionBytes);

    // I/O port access info
    println!("  AccessInfo: {:?}", context.AccessInfo);
    println!("  PortNumber: 0x{:x}", context.PortNumber);
    println!("  Reserved2: {:?}", context.Reserved2);
    println!(
        "  Rax: 0x{:016x} Rcx: 0x{:016x} Rsi: 0x{:016x} Rdi: 0x{:016x}",
        context.Rax, context.Rcx, context.Rsi, context.Rdi
    );
    println!("  Ds: {:?}", context.Ds);
    println!("  Es: {:?}", context.Es);
}

fn dump_msr_access_context(context: &WHV_X64_MSR_ACCESS_CONTEXT) {
    println!("MsrAccess:");
    println!(
        "  MsrNumber: 0x{:x} AccessInfo: {}",
        context.MsrNumber, context.AccessInfo.AsUINT32
    );
    println!("  Rax: 0x{:016x} Rdx: 0x{:016x}", context.Rax, context.Rdx);
}

fn dump_cpuid_access_context(context: &WHV_X64_CPUID_ACCESS_CONTEXT) {
    println!("CpuidAccess:");
    println!(
        "  Rax: {:016?} Rbx: {:016?} Rcx: {:016?} Rdx: {:016?}",
        context.Rax, context.Rbx, context.Rcx, context.Rdx
    );
    println!(
        "  DefaultResult Rax: {:016?} Rbx: {:016?} Rcx: {:016?} Rdx: {:016?}",
        context.DefaultResultRax,
        context.DefaultResultRbx,
        context.DefaultResultRcx,
        context.DefaultResultRdx
    );
}

fn dump_vp_exception_context(context: &WHV_VP_EXCEPTION_CONTEXT) {
    println!("VpException: {:?}", context);
}

fn dump_interrupt_window_context(context: &WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT) {
    println!("InterruptWindow: {:?}", context);
}

fn dump_unsupported_feature_context(context: &WHV_X64_UNSUPPORTED_FEATURE_CONTEXT) {
    println!("UnsupportedFeature: {:?}", context);
}

fn dump_vp_cancelled_context(context: &WHV_RUN_VP_CANCELED_CONTEXT) {
    println!("CancelReason: {:?}", context);
}

fn dump_apic_eoi_context(context: &WHV_X64_APIC_EOI_CONTEXT) {
    println!("ApicEoi: {:?}", context);
}

pub fn dump_vp_regs(vp: &VirtualProcessor) {
    dump_gp_regs(vp);
    dump_segment_regs(vp);
    dump_table_regs(vp);
    dump_control_regs(vp);
    dump_debug_regs(vp);
    dump_fp_regs(vp);
    dump_msr_regs(vp);
    dump_mtr_regs(vp);
    dump_mtrfix_regs(vp);
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

    println!("Regs:");
    unsafe {
        println!(
            "  Rax: {:016x} Rcx: {:016x} Rdx: {:016x} Rbx: {:016x}\n\
             \x20 Rsp: {:016x} Rbp: {:016x} Rsi: {:016x} Rdi: {:016x}\n\
             \x20 R8:  {:016x} R9:  {:016x} R10: {:016x} R11: {:016x}\n\
             \x20 R12: {:016x} R13: {:016x} R14: {:016x} R15: {:016x}\n\
             \x20 Rip: {:016x} Rflags: {:016x}",
            reg_values[0].Reg64,
            reg_values[1].Reg64,
            reg_values[2].Reg64,
            reg_values[3].Reg64,
            reg_values[4].Reg64,
            reg_values[5].Reg64,
            reg_values[6].Reg64,
            reg_values[7].Reg64,
            reg_values[8].Reg64,
            reg_values[9].Reg64,
            reg_values[10].Reg64,
            reg_values[11].Reg64,
            reg_values[12].Reg64,
            reg_values[13].Reg64,
            reg_values[14].Reg64,
            reg_values[15].Reg64,
            reg_values[16].Reg64,
            reg_values[17].Reg64
        );
    }
    println!("");
}

pub fn dump_segment_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 8;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterCs,
        WHV_REGISTER_NAME::WHvX64RegisterSs,
        WHV_REGISTER_NAME::WHvX64RegisterDs,
        WHV_REGISTER_NAME::WHvX64RegisterEs,
        WHV_REGISTER_NAME::WHvX64RegisterFs,
        WHV_REGISTER_NAME::WHvX64RegisterGs,
        WHV_REGISTER_NAME::WHvX64RegisterTr,
        WHV_REGISTER_NAME::WHvX64RegisterLdtr,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    println!("Segment regs:");
    unsafe {
        println!(
            "  Cs: {:?}\n\
             \x20 Ss: {:?}\n\
             \x20 Ds: {:?}\n\
             \x20 Es: {:?}\n\
             \x20 Fs: {:?}\n\
             \x20 Gs: {:?}\n\
             \x20 Tr: {:?}\n\
             \x20 Ldtr: {:?}",
            reg_values[0].Segment,
            reg_values[1].Segment,
            reg_values[2].Segment,
            reg_values[3].Segment,
            reg_values[4].Segment,
            reg_values[5].Segment,
            reg_values[6].Segment,
            reg_values[7].Segment,
        );
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

pub fn dump_mtr_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 16;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase0,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask0,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase1,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask1,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase2,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask2,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase3,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask3,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase4,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask4,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase5,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask5,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase6,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask6,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase7,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask7,
        /*
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase8,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask8,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBase9,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMask9,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseA,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskA,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseB,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskB,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseC,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskC,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseD,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskD,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseE,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskE,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysBaseF,
                WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrPhysMaskF,
        */
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    unsafe {
        println!(
            "Mtrr0={:016x}, Mask0={:016x}, Mtrr1={:016x}, Mask1={:016x}\n\
             Mtrr2={:016x}, Mask2={:016x}, Mtrr3={:016x}, Mask3={:016x}\n\
             Mtrr4={:016x}, Mask4={:016x}, Mtrr5={:016x}, Mask5={:016x}\n\
             Mtrr6={:016x}, Mask6={:016x}, Mtrr7={:016x}, Mask7={:016x}",
            reg_values[0].Reg64,
            reg_values[1].Reg64,
            reg_values[2].Reg64,
            reg_values[3].Reg64,
            reg_values[4].Reg64,
            reg_values[5].Reg64,
            reg_values[6].Reg64,
            reg_values[7].Reg64,
            reg_values[8].Reg64,
            reg_values[9].Reg64,
            reg_values[10].Reg64,
            reg_values[11].Reg64,
            reg_values[12].Reg64,
            reg_values[13].Reg64,
            reg_values[14].Reg64,
            reg_values[15].Reg64,
        );
    }
}

pub fn dump_mtrfix_regs(vp: &VirtualProcessor) {
    const NUM_REGS: usize = 11;
    let reg_names: [WHV_REGISTER_NAME; NUM_REGS] = [
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix64k00000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix16k80000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix16kA0000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kC0000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kC8000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kD0000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kD8000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kE0000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kE8000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kF0000,
        WHV_REGISTER_NAME::WHvX64RegisterMsrMtrrFix4kF8000,
    ];
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    vp.get_registers(&reg_names, &mut reg_values).unwrap();

    unsafe {
        println!(
            "[00000]:{:016x}, [80000]:{:016x}, [A0000]:{:016x},\n\
             [C0000]:{:016x}, [C8000]:{:016x}, \n\
             [D0000]:{:016x}, [D8000]:{:016x}, \n\
             [E0000]:{:016x}, [E8000]:{:016x}, \n\
             [F0000]:{:016x}, [F8000]:{:016x}",
            reg_values[0].Reg64,
            reg_values[1].Reg64,
            reg_values[2].Reg64,
            reg_values[3].Reg64,
            reg_values[4].Reg64,
            reg_values[5].Reg64,
            reg_values[6].Reg64,
            reg_values[7].Reg64,
            reg_values[8].Reg64,
            reg_values[9].Reg64,
            reg_values[10].Reg64,
        );
    }
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
