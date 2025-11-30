mod cpi {
    use {
        super::*, solana_instruction::Instruction,
        solana_program_runtime::cpi::{
            cpi_common, translate_accounts_c, translate_accounts_rust,
            translate_instruction_c, translate_instruction_rust, translate_signers_c,
            translate_signers_rust, SyscallInvokeSigned, TranslatedAccount,
        },
    };
    /// Cross-program invocation called from Rust
    pub struct SyscallInvokeSignedRust {}
    impl SyscallInvokeSignedRust {
        /// Rust interface
        pub fn rust(
            invoke_context: &mut InvokeContext,
            instruction_addr: u64,
            account_infos_addr: u64,
            account_infos_len: u64,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
            memory_mapping: &mut MemoryMapping,
        ) -> Result<u64, Error> {
            cpi_common::<
                Self,
            >(
                invoke_context,
                instruction_addr,
                account_infos_addr,
                account_infos_len,
                signers_seeds_addr,
                signers_seeds_len,
                memory_mapping,
            )
        }
        /// VM interface
        #[allow(clippy::too_many_arguments)]
        pub fn vm(
            invoke_context: *mut ::solana_sbpf::vm::EbpfVm<InvokeContext>,
            instruction_addr: u64,
            account_infos_addr: u64,
            account_infos_len: u64,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
        ) {
            use ::solana_sbpf::vm::ContextObject;
            let vm = unsafe {
                &mut *(invoke_context
                    .cast::<u64>()
                    .offset(-(::solana_sbpf::vm::get_runtime_environment_key() as isize))
                    .cast::<::solana_sbpf::vm::EbpfVm<InvokeContext>>())
            };
            let config = vm.loader.get_config();
            if config.enable_instruction_meter {
                vm.context_object_pointer
                    .consume(vm.previous_instruction_meter - vm.due_insn_count);
            }
            let converted_result: ::solana_sbpf::error::ProgramResult = Self::rust(
                    vm.context_object_pointer,
                    instruction_addr,
                    account_infos_addr,
                    account_infos_len,
                    signers_seeds_addr,
                    signers_seeds_len,
                    &mut vm.memory_mapping,
                )
                .map_err(|err| ::solana_sbpf::error::EbpfError::SyscallError(err))
                .into();
            vm.program_result = converted_result;
            if config.enable_instruction_meter {
                vm.previous_instruction_meter = vm
                    .context_object_pointer
                    .get_remaining();
            }
        }
    }
    impl SyscallInvokeSigned for SyscallInvokeSignedRust {
        fn translate_instruction(
            addr: u64,
            memory_mapping: &MemoryMapping,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Instruction, Error> {
            translate_instruction_rust(
                addr,
                memory_mapping,
                invoke_context,
                check_aligned,
            )
        }
        fn translate_accounts<'a>(
            account_infos_addr: u64,
            account_infos_len: u64,
            memory_mapping: &MemoryMapping<'_>,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Vec<TranslatedAccount<'a>>, Error> {
            translate_accounts_rust(
                account_infos_addr,
                account_infos_len,
                memory_mapping,
                invoke_context,
                check_aligned,
            )
        }
        fn translate_signers(
            program_id: &Pubkey,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
            memory_mapping: &MemoryMapping,
            check_aligned: bool,
        ) -> Result<Vec<Pubkey>, Error> {
            translate_signers_rust(
                program_id,
                signers_seeds_addr,
                signers_seeds_len,
                memory_mapping,
                check_aligned,
            )
        }
    }
    /// Cross-program invocation called from C
    pub struct SyscallInvokeSignedC {}
    impl SyscallInvokeSignedC {
        /// Rust interface
        pub fn rust(
            invoke_context: &mut InvokeContext,
            instruction_addr: u64,
            account_infos_addr: u64,
            account_infos_len: u64,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
            memory_mapping: &mut MemoryMapping,
        ) -> Result<u64, Error> {
            cpi_common::<
                Self,
            >(
                invoke_context,
                instruction_addr,
                account_infos_addr,
                account_infos_len,
                signers_seeds_addr,
                signers_seeds_len,
                memory_mapping,
            )
        }
        /// VM interface
        #[allow(clippy::too_many_arguments)]
        pub fn vm(
            invoke_context: *mut ::solana_sbpf::vm::EbpfVm<InvokeContext>,
            instruction_addr: u64,
            account_infos_addr: u64,
            account_infos_len: u64,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
        ) {
            use ::solana_sbpf::vm::ContextObject;
            let vm = unsafe {
                &mut *(invoke_context
                    .cast::<u64>()
                    .offset(-(::solana_sbpf::vm::get_runtime_environment_key() as isize))
                    .cast::<::solana_sbpf::vm::EbpfVm<InvokeContext>>())
            };
            let config = vm.loader.get_config();
            if config.enable_instruction_meter {
                vm.context_object_pointer
                    .consume(vm.previous_instruction_meter - vm.due_insn_count);
            }
            let converted_result: ::solana_sbpf::error::ProgramResult = Self::rust(
                    vm.context_object_pointer,
                    instruction_addr,
                    account_infos_addr,
                    account_infos_len,
                    signers_seeds_addr,
                    signers_seeds_len,
                    &mut vm.memory_mapping,
                )
                .map_err(|err| ::solana_sbpf::error::EbpfError::SyscallError(err))
                .into();
            vm.program_result = converted_result;
            if config.enable_instruction_meter {
                vm.previous_instruction_meter = vm
                    .context_object_pointer
                    .get_remaining();
            }
        }
    }
    impl SyscallInvokeSigned for SyscallInvokeSignedC {
        fn translate_instruction(
            addr: u64,
            memory_mapping: &MemoryMapping,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Instruction, Error> {
            translate_instruction_c(addr, memory_mapping, invoke_context, check_aligned)
        }
        fn translate_accounts<'a>(
            account_infos_addr: u64,
            account_infos_len: u64,
            memory_mapping: &MemoryMapping<'_>,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Vec<TranslatedAccount<'a>>, Error> {
            translate_accounts_c(
                account_infos_addr,
                account_infos_len,
                memory_mapping,
                invoke_context,
                check_aligned,
            )
        }
        fn translate_signers(
            program_id: &Pubkey,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
            memory_mapping: &MemoryMapping,
            check_aligned: bool,
        ) -> Result<Vec<Pubkey>, Error> {
            translate_signers_c(
                program_id,
                signers_seeds_addr,
                signers_seeds_len,
                memory_mapping,
                check_aligned,
            )
        }
    }
}
