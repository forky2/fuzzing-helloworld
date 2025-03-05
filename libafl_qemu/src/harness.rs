use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{
    elf::EasyElf, ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, Qemu, Regs, QemuMappingsViewer,
};

pub struct Harness {
    qemu: Qemu,
    input_addr: GuestAddr, // Mmap for our buffer
    pc: GuestAddr,
    stack_ptr: GuestAddr,
    ret_addr: GuestAddr,
}

pub const MAX_INPUT_SIZE: usize = 1_048_576; // 1MB

impl Harness {
    /// Change environment
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_env(_env: &mut Vec<(String, String)>) {}

    /// Change arguments
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_args(_args: &mut Vec<String>) {}

    /// Initialize the emulator, run to the entrypoint (or jump there) and return the [`Harness`] struct
    pub fn init(qemu: Qemu, start_pc: GuestAddr, exit_pc: GuestAddr) -> Result<Harness, Error> {
        log::info!("start_pc @ {start_pc:#x}");

        // Print out mappings - Useful for checking where the target is mapped.
        let mappings = QemuMappingsViewer::new(&qemu);
        log::info!("\n{:#?}", mappings);

        qemu.entry_break(start_pc);

        log::info!("ret_addr = {exit_pc:#x}");
        qemu.set_breakpoint(exit_pc);

        let input_addr = qemu
            .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map input buffer: {e:}")))?;

        let pc: GuestReg = qemu
            .read_reg(Regs::Pc)
            .map_err(|e| Error::unknown(format!("Failed to read PC: {e:?}")))?;

        let stack_ptr: GuestAddr = qemu
            .read_reg(Regs::Sp)
            .map_err(|e| Error::unknown(format!("Failed to read stack pointer: {e:?}")))?;

        let ret_addr: GuestAddr = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:?}")))?;

        Ok(Harness {
            qemu,
            input_addr,
            pc,
            stack_ptr,
            ret_addr,
        })
    }

    /// If we need to do extra work after forking, we can do that here.
    #[inline]
    #[expect(clippy::unused_self)]
    pub fn post_fork(&self) {}

    pub fn run(&self, input: &BytesInput) -> ExitKind {
        self.reset(input).unwrap();
        ExitKind::Ok
    }

    fn reset(&self, input: &BytesInput) -> Result<(), Error> {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        self.qemu.write_mem(self.input_addr, buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to write to memory@{:#x}: {e:?}",
                self.input_addr
            ))
        })?;

        self.qemu
            .write_reg(Regs::Pc, self.pc)
            .map_err(|e| Error::unknown(format!("Failed to write PC: {e:?}")))?;

        self.qemu
            .write_reg(Regs::Sp, self.stack_ptr)
            .map_err(|e| Error::unknown(format!("Failed to write SP: {e:?}")))?;

        self.qemu
            .write_function_argument(0, self.input_addr)
            .map_err(|e| Error::unknown(format!("Failed to write argument 0: {e:?}")))?;

        unsafe {
            let _ = self.qemu.run();
        };
        Ok(())
    }
}
