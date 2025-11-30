#![feature(prelude_import)]
#![deprecated(
    since = "3.1.0",
    note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#[macro_use]
extern crate std;
#[prelude_import]
use std::prelude::rust_2021::*;
pub use solana_sbpf;
pub mod cpi {
    //! Cross-Program Invocation (CPI) error types
    use {
        crate::{
            invoke_context::{InvokeContext, SerializedAccountMetadata},
            memory::{
                translate_slice, translate_type, translate_type_mut_for_cpi,
                translate_vm_slice,
            },
            serialization::{
                create_memory_region_of_account, modify_memory_region_of_account,
            },
        },
        solana_account_info::AccountInfo,
        solana_instruction::{error::InstructionError, AccountMeta, Instruction},
        solana_loader_v3_interface::instruction as bpf_loader_upgradeable,
        solana_program_entrypoint::MAX_PERMITTED_DATA_INCREASE,
        solana_pubkey::{Pubkey, PubkeyError, MAX_SEEDS},
        solana_sbpf::{ebpf, memory_region::MemoryMapping},
        solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, native_loader},
        solana_stable_layout::stable_instruction::StableInstruction,
        solana_svm_log_collector::ic_msg, solana_svm_measure::measure::Measure,
        solana_svm_timings::ExecuteTimings,
        solana_transaction_context::{
            instruction_accounts::BorrowedInstructionAccount, vm_slice::VmSlice,
            IndexOfAccount, MAX_ACCOUNTS_PER_INSTRUCTION, MAX_INSTRUCTION_DATA_LEN,
        },
        std::mem, thiserror::Error,
    };
    /// CPI-specific error types
    pub enum CpiError {
        #[error("Invalid pointer")]
        InvalidPointer,
        #[error("Too many signers")]
        TooManySigners,
        #[error("Could not create program address with signer seeds: {0}")]
        BadSeeds(PubkeyError),
        #[error("InvalidLength")]
        InvalidLength,
        #[error(
            "Invoked an instruction with too many accounts ({num_accounts} > {max_accounts})"
        )]
        MaxInstructionAccountsExceeded { num_accounts: u64, max_accounts: u64 },
        #[error(
            "Invoked an instruction with data that is too large ({data_len} > {max_data_len})"
        )]
        MaxInstructionDataLenExceeded { data_len: u64, max_data_len: u64 },
        #[error(
            "Invoked an instruction with too many account info's ({num_account_infos} > \
         {max_account_infos})"
        )]
        MaxInstructionAccountInfosExceeded {
            num_account_infos: u64,
            max_account_infos: u64,
        },
        #[error("Program {0} not supported by inner instructions")]
        ProgramNotSupported(Pubkey),
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CpiError {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                CpiError::InvalidPointer => {
                    ::core::fmt::Formatter::write_str(f, "InvalidPointer")
                }
                CpiError::TooManySigners => {
                    ::core::fmt::Formatter::write_str(f, "TooManySigners")
                }
                CpiError::BadSeeds(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "BadSeeds",
                        &__self_0,
                    )
                }
                CpiError::InvalidLength => {
                    ::core::fmt::Formatter::write_str(f, "InvalidLength")
                }
                CpiError::MaxInstructionAccountsExceeded {
                    num_accounts: __self_0,
                    max_accounts: __self_1,
                } => {
                    ::core::fmt::Formatter::debug_struct_field2_finish(
                        f,
                        "MaxInstructionAccountsExceeded",
                        "num_accounts",
                        __self_0,
                        "max_accounts",
                        &__self_1,
                    )
                }
                CpiError::MaxInstructionDataLenExceeded {
                    data_len: __self_0,
                    max_data_len: __self_1,
                } => {
                    ::core::fmt::Formatter::debug_struct_field2_finish(
                        f,
                        "MaxInstructionDataLenExceeded",
                        "data_len",
                        __self_0,
                        "max_data_len",
                        &__self_1,
                    )
                }
                CpiError::MaxInstructionAccountInfosExceeded {
                    num_account_infos: __self_0,
                    max_account_infos: __self_1,
                } => {
                    ::core::fmt::Formatter::debug_struct_field2_finish(
                        f,
                        "MaxInstructionAccountInfosExceeded",
                        "num_account_infos",
                        __self_0,
                        "max_account_infos",
                        &__self_1,
                    )
                }
                CpiError::ProgramNotSupported(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "ProgramNotSupported",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[allow(unused_qualifications)]
    #[automatically_derived]
    impl ::thiserror::__private17::Error for CpiError {}
    #[allow(unused_qualifications)]
    #[automatically_derived]
    impl ::core::fmt::Display for CpiError {
        fn fmt(&self, __formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            use ::thiserror::__private17::AsDisplay as _;
            #[allow(unused_variables, deprecated, clippy::used_underscore_binding)]
            match self {
                CpiError::InvalidPointer {} => __formatter.write_str("Invalid pointer"),
                CpiError::TooManySigners {} => __formatter.write_str("Too many signers"),
                CpiError::BadSeeds(_0) => {
                    match (_0.as_display(),) {
                        (__display0,) => {
                            __formatter
                                .write_fmt(
                                    format_args!(
                                        "Could not create program address with signer seeds: {0}",
                                        __display0,
                                    ),
                                )
                        }
                    }
                }
                CpiError::InvalidLength {} => __formatter.write_str("InvalidLength"),
                CpiError::MaxInstructionAccountsExceeded {
                    num_accounts,
                    max_accounts,
                } => {
                    match (num_accounts.as_display(), max_accounts.as_display()) {
                        (__display_num_accounts, __display_max_accounts) => {
                            __formatter
                                .write_fmt(
                                    format_args!(
                                        "Invoked an instruction with too many accounts ({0} > {1})",
                                        __display_num_accounts,
                                        __display_max_accounts,
                                    ),
                                )
                        }
                    }
                }
                CpiError::MaxInstructionDataLenExceeded { data_len, max_data_len } => {
                    match (data_len.as_display(), max_data_len.as_display()) {
                        (__display_data_len, __display_max_data_len) => {
                            __formatter
                                .write_fmt(
                                    format_args!(
                                        "Invoked an instruction with data that is too large ({0} > {1})",
                                        __display_data_len,
                                        __display_max_data_len,
                                    ),
                                )
                        }
                    }
                }
                CpiError::MaxInstructionAccountInfosExceeded {
                    num_account_infos,
                    max_account_infos,
                } => {
                    match (
                        num_account_infos.as_display(),
                        max_account_infos.as_display(),
                    ) {
                        (__display_num_account_infos, __display_max_account_infos) => {
                            __formatter
                                .write_fmt(
                                    format_args!(
                                        "Invoked an instruction with too many account info\'s ({0} > {1})",
                                        __display_num_account_infos,
                                        __display_max_account_infos,
                                    ),
                                )
                        }
                    }
                }
                CpiError::ProgramNotSupported(_0) => {
                    match (_0.as_display(),) {
                        (__display0,) => {
                            __formatter
                                .write_fmt(
                                    format_args!(
                                        "Program {0} not supported by inner instructions",
                                        __display0,
                                    ),
                                )
                        }
                    }
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for CpiError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for CpiError {
        #[inline]
        fn eq(&self, other: &CpiError) -> bool {
            let __self_discr = ::core::intrinsics::discriminant_value(self);
            let __arg1_discr = ::core::intrinsics::discriminant_value(other);
            __self_discr == __arg1_discr
                && match (self, other) {
                    (CpiError::BadSeeds(__self_0), CpiError::BadSeeds(__arg1_0)) => {
                        __self_0 == __arg1_0
                    }
                    (
                        CpiError::MaxInstructionAccountsExceeded {
                            num_accounts: __self_0,
                            max_accounts: __self_1,
                        },
                        CpiError::MaxInstructionAccountsExceeded {
                            num_accounts: __arg1_0,
                            max_accounts: __arg1_1,
                        },
                    ) => __self_0 == __arg1_0 && __self_1 == __arg1_1,
                    (
                        CpiError::MaxInstructionDataLenExceeded {
                            data_len: __self_0,
                            max_data_len: __self_1,
                        },
                        CpiError::MaxInstructionDataLenExceeded {
                            data_len: __arg1_0,
                            max_data_len: __arg1_1,
                        },
                    ) => __self_0 == __arg1_0 && __self_1 == __arg1_1,
                    (
                        CpiError::MaxInstructionAccountInfosExceeded {
                            num_account_infos: __self_0,
                            max_account_infos: __self_1,
                        },
                        CpiError::MaxInstructionAccountInfosExceeded {
                            num_account_infos: __arg1_0,
                            max_account_infos: __arg1_1,
                        },
                    ) => __self_0 == __arg1_0 && __self_1 == __arg1_1,
                    (
                        CpiError::ProgramNotSupported(__self_0),
                        CpiError::ProgramNotSupported(__arg1_0),
                    ) => __self_0 == __arg1_0,
                    _ => true,
                }
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for CpiError {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<PubkeyError>;
            let _: ::core::cmp::AssertParamIsEq<u64>;
            let _: ::core::cmp::AssertParamIsEq<Pubkey>;
        }
    }
    type Error = Box<dyn std::error::Error>;
    const SUCCESS: u64 = 0;
    /// Maximum signers
    const MAX_SIGNERS: usize = 16;
    ///SIMD-0339 based calculation of AccountInfo translation byte size. Fixed size of **80 bytes** for each AccountInfo broken down as:
    /// - 32 bytes for account address
    /// - 32 bytes for owner address
    /// - 8 bytes for lamport balance
    /// - 8 bytes for data length
    const ACCOUNT_INFO_BYTE_SIZE: usize = 80;
    /// Rust representation of C's SolInstruction
    #[repr(C)]
    struct SolInstruction {
        pub program_id_addr: u64,
        pub accounts_addr: u64,
        pub accounts_len: u64,
        pub data_addr: u64,
        pub data_len: u64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SolInstruction {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field5_finish(
                f,
                "SolInstruction",
                "program_id_addr",
                &self.program_id_addr,
                "accounts_addr",
                &self.accounts_addr,
                "accounts_len",
                &self.accounts_len,
                "data_addr",
                &self.data_addr,
                "data_len",
                &&self.data_len,
            )
        }
    }
    /// Rust representation of C's SolAccountMeta
    #[repr(C)]
    struct SolAccountMeta {
        pub pubkey_addr: u64,
        pub is_writable: bool,
        pub is_signer: bool,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SolAccountMeta {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "SolAccountMeta",
                "pubkey_addr",
                &self.pubkey_addr,
                "is_writable",
                &self.is_writable,
                "is_signer",
                &&self.is_signer,
            )
        }
    }
    /// Rust representation of C's SolAccountInfo
    #[repr(C)]
    struct SolAccountInfo {
        pub key_addr: u64,
        pub lamports_addr: u64,
        pub data_len: u64,
        pub data_addr: u64,
        pub owner_addr: u64,
        pub rent_epoch: u64,
        pub is_signer: bool,
        pub is_writable: bool,
        pub executable: bool,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SolAccountInfo {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "key_addr",
                "lamports_addr",
                "data_len",
                "data_addr",
                "owner_addr",
                "rent_epoch",
                "is_signer",
                "is_writable",
                "executable",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.key_addr,
                &self.lamports_addr,
                &self.data_len,
                &self.data_addr,
                &self.owner_addr,
                &self.rent_epoch,
                &self.is_signer,
                &self.is_writable,
                &&self.executable,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "SolAccountInfo",
                names,
                values,
            )
        }
    }
    /// Rust representation of C's SolSignerSeed
    #[repr(C)]
    struct SolSignerSeedC {
        pub addr: u64,
        pub len: u64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SolSignerSeedC {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field2_finish(
                f,
                "SolSignerSeedC",
                "addr",
                &self.addr,
                "len",
                &&self.len,
            )
        }
    }
    /// Rust representation of C's SolSignerSeeds
    #[repr(C)]
    struct SolSignerSeedsC {
        pub addr: u64,
        pub len: u64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SolSignerSeedsC {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field2_finish(
                f,
                "SolSignerSeedsC",
                "addr",
                &self.addr,
                "len",
                &&self.len,
            )
        }
    }
    /// Maximum number of account info structs that can be used in a single CPI invocation
    const MAX_CPI_ACCOUNT_INFOS: usize = 128;
    /// Maximum number of account info structs that can be used in a single CPI invocation with SIMD-0339 active
    const MAX_CPI_ACCOUNT_INFOS_SIMD_0339: usize = 255;
    /// Check that an account info pointer field points to the expected address
    fn check_account_info_pointer(
        invoke_context: &InvokeContext,
        vm_addr: u64,
        expected_vm_addr: u64,
        field: &str,
    ) -> Result<(), Error> {
        if vm_addr != expected_vm_addr {
            {
                {
                    {
                        let lvl = ::log::Level::Debug;
                        if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                            ::log::__private_api::log(
                                { ::log::__private_api::GlobalLogger },
                                format_args!(
                                    "Invalid account info pointer `{0}\': {1:#x} != {2:#x}",
                                    field,
                                    vm_addr,
                                    expected_vm_addr,
                                ),
                                lvl,
                                &(
                                    "solana_runtime::message_processor::stable_log",
                                    "solana_program_runtime::cpi",
                                    ::log::__private_api::loc(),
                                ),
                                (),
                            );
                        }
                    }
                }
            };
            if let Some(log_collector) = invoke_context.get_log_collector().as_ref() {
                if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                    log_collector
                        .log(
                            &::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Invalid account info pointer `{0}\': {1:#x} != {2:#x}",
                                        field,
                                        vm_addr,
                                        expected_vm_addr,
                                    ),
                                )
                            }),
                        );
                }
            }
            return Err(Box::new(CpiError::InvalidPointer));
        }
        Ok(())
    }
    /// Check that an instruction's account and data lengths are within limits
    fn check_instruction_size(
        num_accounts: usize,
        data_len: usize,
    ) -> Result<(), Error> {
        if num_accounts > MAX_ACCOUNTS_PER_INSTRUCTION {
            return Err(
                Box::new(CpiError::MaxInstructionAccountsExceeded {
                    num_accounts: num_accounts as u64,
                    max_accounts: MAX_ACCOUNTS_PER_INSTRUCTION as u64,
                }),
            );
        }
        if data_len > MAX_INSTRUCTION_DATA_LEN {
            return Err(
                Box::new(CpiError::MaxInstructionDataLenExceeded {
                    data_len: data_len as u64,
                    max_data_len: MAX_INSTRUCTION_DATA_LEN as u64,
                }),
            );
        }
        Ok(())
    }
    /// Check that the number of account infos is within the CPI limit
    fn check_account_infos(
        num_account_infos: usize,
        invoke_context: &mut InvokeContext,
    ) -> Result<(), Error> {
        let max_cpi_account_infos = if invoke_context
            .get_feature_set()
            .increase_cpi_account_info_limit
        {
            MAX_CPI_ACCOUNT_INFOS_SIMD_0339
        } else if invoke_context.get_feature_set().increase_tx_account_lock_limit {
            MAX_CPI_ACCOUNT_INFOS
        } else {
            64
        };
        let num_account_infos = num_account_infos as u64;
        let max_account_infos = max_cpi_account_infos as u64;
        if num_account_infos > max_account_infos {
            return Err(
                Box::new(CpiError::MaxInstructionAccountInfosExceeded {
                    num_account_infos,
                    max_account_infos,
                }),
            );
        }
        Ok(())
    }
    /// Check whether a program is authorized for CPI
    fn check_authorized_program(
        program_id: &Pubkey,
        instruction_data: &[u8],
        invoke_context: &InvokeContext,
    ) -> Result<(), Error> {
        if native_loader::check_id(program_id) || bpf_loader::check_id(program_id)
            || bpf_loader_deprecated::check_id(program_id)
            || (solana_sdk_ids::bpf_loader_upgradeable::check_id(program_id)
                && !(bpf_loader_upgradeable::is_upgrade_instruction(instruction_data)
                    || bpf_loader_upgradeable::is_set_authority_instruction(
                        instruction_data,
                    )
                    || (invoke_context
                        .get_feature_set()
                        .enable_bpf_loader_set_authority_checked_ix
                        && bpf_loader_upgradeable::is_set_authority_checked_instruction(
                            instruction_data,
                        ))
                    || (invoke_context.get_feature_set().enable_extend_program_checked
                        && bpf_loader_upgradeable::is_extend_program_checked_instruction(
                            instruction_data,
                        ))
                    || bpf_loader_upgradeable::is_close_instruction(instruction_data)))
            || invoke_context.is_precompile(program_id)
        {
            return Err(Box::new(CpiError::ProgramNotSupported(*program_id)));
        }
        Ok(())
    }
    /// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
    ///
    /// At the start of a CPI, this can be different from the data stored in the
    /// corresponding BorrowedAccount, and needs to be synched.
    pub struct CallerAccount<'a> {
        pub lamports: &'a mut u64,
        pub owner: &'a mut Pubkey,
        pub original_data_len: usize,
        pub serialized_data: &'a mut [u8],
        pub vm_data_addr: u64,
        pub ref_to_len_in_vm: &'a mut u64,
    }
    impl<'a> CallerAccount<'a> {
        pub fn get_serialized_data(
            memory_mapping: &solana_sbpf::memory_region::MemoryMapping<'_>,
            vm_addr: u64,
            len: u64,
            stricter_abi_and_runtime_constraints: bool,
            account_data_direct_mapping: bool,
        ) -> Result<&'a mut [u8], Error> {
            use crate::memory::translate_slice_mut_for_cpi;
            if stricter_abi_and_runtime_constraints && account_data_direct_mapping {
                Ok(&mut [])
            } else if stricter_abi_and_runtime_constraints {
                let serialization_ptr = translate_slice_mut_for_cpi::<
                    u8,
                >(memory_mapping, solana_sbpf::ebpf::MM_INPUT_START, 1, false)?
                    .as_mut_ptr();
                unsafe {
                    Ok(
                        std::slice::from_raw_parts_mut(
                            serialization_ptr
                                .add(
                                    vm_addr.saturating_sub(solana_sbpf::ebpf::MM_INPUT_START)
                                        as usize,
                                ),
                            len as usize,
                        ),
                    )
                }
            } else {
                translate_slice_mut_for_cpi::<u8>(memory_mapping, vm_addr, len, false)
            }
        }
        pub fn from_account_info(
            invoke_context: &InvokeContext,
            memory_mapping: &solana_sbpf::memory_region::MemoryMapping<'_>,
            check_aligned: bool,
            _vm_addr: u64,
            account_info: &solana_account_info::AccountInfo,
            account_metadata: &crate::invoke_context::SerializedAccountMetadata,
        ) -> Result<CallerAccount<'a>, Error> {
            use crate::memory::{translate_type, translate_type_mut_for_cpi};
            let stricter_abi_and_runtime_constraints = invoke_context
                .get_feature_set()
                .stricter_abi_and_runtime_constraints;
            let account_data_direct_mapping = invoke_context
                .get_feature_set()
                .account_data_direct_mapping;
            if stricter_abi_and_runtime_constraints {
                check_account_info_pointer(
                    invoke_context,
                    account_info.key as *const _ as u64,
                    account_metadata.vm_key_addr,
                    "key",
                )?;
                check_account_info_pointer(
                    invoke_context,
                    account_info.owner as *const _ as u64,
                    account_metadata.vm_owner_addr,
                    "owner",
                )?;
            }
            let lamports = {
                let ptr = translate_type::<
                    u64,
                >(memory_mapping, account_info.lamports.as_ptr() as u64, check_aligned)?;
                if stricter_abi_and_runtime_constraints {
                    if account_info.lamports.as_ptr() as u64
                        >= solana_sbpf::ebpf::MM_INPUT_START
                    {
                        return Err(Box::new(CpiError::InvalidPointer));
                    }
                    check_account_info_pointer(
                        invoke_context,
                        *ptr,
                        account_metadata.vm_lamports_addr,
                        "lamports",
                    )?;
                }
                translate_type_mut_for_cpi::<u64>(memory_mapping, *ptr, check_aligned)?
            };
            let owner = translate_type_mut_for_cpi::<
                Pubkey,
            >(memory_mapping, account_info.owner as *const _ as u64, check_aligned)?;
            let (serialized_data, vm_data_addr, ref_to_len_in_vm) = {
                if stricter_abi_and_runtime_constraints
                    && account_info.data.as_ptr() as u64
                        >= solana_sbpf::ebpf::MM_INPUT_START
                {
                    return Err(Box::new(CpiError::InvalidPointer));
                }
                let data = *translate_type::<
                    &[u8],
                >(
                    memory_mapping,
                    account_info.data.as_ptr() as *const _ as u64,
                    check_aligned,
                )?;
                if stricter_abi_and_runtime_constraints {
                    check_account_info_pointer(
                        invoke_context,
                        data.as_ptr() as u64,
                        account_metadata.vm_data_addr,
                        "data",
                    )?;
                }
                invoke_context
                    .consume_checked(
                        (data.len() as u64)
                            .checked_div(
                                invoke_context.get_execution_cost().cpi_bytes_per_unit,
                            )
                            .unwrap_or(u64::MAX),
                    )?;
                let vm_len_addr = (account_info.data.as_ptr() as *const u64 as u64)
                    .saturating_add(std::mem::size_of::<u64>() as u64);
                if stricter_abi_and_runtime_constraints {
                    if vm_len_addr >= solana_sbpf::ebpf::MM_INPUT_START {
                        return Err(Box::new(CpiError::InvalidPointer));
                    }
                }
                let vm_data_addr = data.as_ptr() as u64;
                let serialized_data = CallerAccount::get_serialized_data(
                    memory_mapping,
                    vm_data_addr,
                    data.len() as u64,
                    stricter_abi_and_runtime_constraints,
                    account_data_direct_mapping,
                )?;
                let ref_to_len_in_vm = translate_type_mut_for_cpi::<
                    u64,
                >(memory_mapping, vm_len_addr, false)?;
                (serialized_data, vm_data_addr, ref_to_len_in_vm)
            };
            Ok(CallerAccount {
                lamports,
                owner,
                original_data_len: account_metadata.original_data_len,
                serialized_data,
                vm_data_addr,
                ref_to_len_in_vm,
            })
        }
        fn from_sol_account_info(
            invoke_context: &InvokeContext,
            memory_mapping: &solana_sbpf::memory_region::MemoryMapping<'_>,
            check_aligned: bool,
            vm_addr: u64,
            account_info: &SolAccountInfo,
            account_metadata: &crate::invoke_context::SerializedAccountMetadata,
        ) -> Result<CallerAccount<'a>, Error> {
            use crate::memory::translate_type_mut_for_cpi;
            let stricter_abi_and_runtime_constraints = invoke_context
                .get_feature_set()
                .stricter_abi_and_runtime_constraints;
            let account_data_direct_mapping = invoke_context
                .get_feature_set()
                .account_data_direct_mapping;
            if stricter_abi_and_runtime_constraints {
                check_account_info_pointer(
                    invoke_context,
                    account_info.key_addr,
                    account_metadata.vm_key_addr,
                    "key",
                )?;
                check_account_info_pointer(
                    invoke_context,
                    account_info.owner_addr,
                    account_metadata.vm_owner_addr,
                    "owner",
                )?;
                check_account_info_pointer(
                    invoke_context,
                    account_info.lamports_addr,
                    account_metadata.vm_lamports_addr,
                    "lamports",
                )?;
                check_account_info_pointer(
                    invoke_context,
                    account_info.data_addr,
                    account_metadata.vm_data_addr,
                    "data",
                )?;
            }
            let lamports = translate_type_mut_for_cpi::<
                u64,
            >(memory_mapping, account_info.lamports_addr, check_aligned)?;
            let owner = translate_type_mut_for_cpi::<
                Pubkey,
            >(memory_mapping, account_info.owner_addr, check_aligned)?;
            invoke_context
                .consume_checked(
                    account_info
                        .data_len
                        .checked_div(
                            invoke_context.get_execution_cost().cpi_bytes_per_unit,
                        )
                        .unwrap_or(u64::MAX),
                )?;
            let serialized_data = CallerAccount::get_serialized_data(
                memory_mapping,
                account_info.data_addr,
                account_info.data_len,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
            )?;
            let vm_len_addr = vm_addr
                .saturating_add(&account_info.data_len as *const u64 as u64)
                .saturating_sub(account_info as *const _ as *const u64 as u64);
            let ref_to_len_in_vm = translate_type_mut_for_cpi::<
                u64,
            >(memory_mapping, vm_len_addr, false)?;
            Ok(CallerAccount {
                lamports,
                owner,
                original_data_len: account_metadata.original_data_len,
                serialized_data,
                vm_data_addr: account_info.data_addr,
                ref_to_len_in_vm,
            })
        }
    }
    /// Implemented by language specific data structure translators
    pub trait SyscallInvokeSigned {
        fn translate_instruction(
            addr: u64,
            memory_mapping: &MemoryMapping,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Instruction, Error>;
        fn translate_accounts<'a>(
            account_infos_addr: u64,
            account_infos_len: u64,
            memory_mapping: &MemoryMapping<'_>,
            invoke_context: &mut InvokeContext,
            check_aligned: bool,
        ) -> Result<Vec<TranslatedAccount<'a>>, Error>;
        fn translate_signers(
            program_id: &Pubkey,
            signers_seeds_addr: u64,
            signers_seeds_len: u64,
            memory_mapping: &MemoryMapping,
            check_aligned: bool,
        ) -> Result<Vec<Pubkey>, Error>;
    }
    pub fn translate_instruction_rust(
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
        check_aligned: bool,
    ) -> Result<Instruction, Error> {
        let ix = translate_type::<
            StableInstruction,
        >(memory_mapping, addr, check_aligned)?;
        let account_metas = translate_slice::<
            AccountMeta,
        >(memory_mapping, ix.accounts.as_vaddr(), ix.accounts.len(), check_aligned)?;
        let data = translate_slice::<
            u8,
        >(memory_mapping, ix.data.as_vaddr(), ix.data.len(), check_aligned)?;
        check_instruction_size(account_metas.len(), data.len())?;
        let mut total_cu_translation_cost: u64 = (data.len() as u64)
            .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
            .unwrap_or(u64::MAX);
        if invoke_context.get_feature_set().increase_cpi_account_info_limit {
            let account_meta_translation_cost = (account_metas
                .len()
                .saturating_mul(size_of::<AccountMeta>()) as u64)
                .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                .unwrap_or(u64::MAX);
            total_cu_translation_cost = total_cu_translation_cost
                .saturating_add(account_meta_translation_cost);
        }
        consume_compute_meter(invoke_context, total_cu_translation_cost)?;
        let mut accounts = Vec::with_capacity(account_metas.len());
        #[allow(clippy::needless_range_loop)]
        for account_index in 0..account_metas.len() {
            #[allow(clippy::indexing_slicing)]
            let account_meta = &account_metas[account_index];
            if unsafe {
                std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8)
                    > 1
                    || std::ptr::read_volatile(
                        &account_meta.is_writable as *const _ as *const u8,
                    ) > 1
            } {
                return Err(Box::new(InstructionError::InvalidArgument));
            }
            accounts.push(account_meta.clone());
        }
        Ok(Instruction {
            accounts,
            data: data.to_vec(),
            program_id: ix.program_id,
        })
    }
    pub fn translate_accounts_rust<'a>(
        account_infos_addr: u64,
        account_infos_len: u64,
        memory_mapping: &MemoryMapping<'_>,
        invoke_context: &mut InvokeContext,
        check_aligned: bool,
    ) -> Result<Vec<TranslatedAccount<'a>>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &AccountInfo| account_info.key as *const _ as u64,
            memory_mapping,
            invoke_context,
            check_aligned,
        )?;
        translate_accounts_common(
            &account_info_keys,
            account_infos,
            account_infos_addr,
            invoke_context,
            memory_mapping,
            check_aligned,
            CallerAccount::from_account_info,
        )
    }
    pub fn translate_signers_rust(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        check_aligned: bool,
    ) -> Result<Vec<Pubkey>, Error> {
        let mut signers = Vec::new();
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<
                VmSlice<VmSlice<u8>>,
            >(memory_mapping, signers_seeds_addr, signers_seeds_len, check_aligned)?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(CpiError::TooManySigners));
            }
            for signer_seeds in signers_seeds.iter() {
                let untranslated_seeds = translate_slice::<
                    VmSlice<u8>,
                >(
                    memory_mapping,
                    signer_seeds.ptr(),
                    signer_seeds.len(),
                    check_aligned,
                )?;
                if untranslated_seeds.len() > MAX_SEEDS {
                    return Err(Box::new(InstructionError::MaxSeedLengthExceeded));
                }
                let seeds = untranslated_seeds
                    .iter()
                    .map(|untranslated_seed| {
                        translate_vm_slice(
                            untranslated_seed,
                            memory_mapping,
                            check_aligned,
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let signer = Pubkey::create_program_address(&seeds, program_id)
                    .map_err(CpiError::BadSeeds)?;
                signers.push(signer);
            }
            Ok(signers)
        } else {
            Ok(::alloc::vec::Vec::new())
        }
    }
    pub fn translate_instruction_c(
        addr: u64,
        memory_mapping: &MemoryMapping,
        invoke_context: &mut InvokeContext,
        check_aligned: bool,
    ) -> Result<Instruction, Error> {
        let ix_c = translate_type::<
            SolInstruction,
        >(memory_mapping, addr, check_aligned)?;
        let program_id = translate_type::<
            Pubkey,
        >(memory_mapping, ix_c.program_id_addr, check_aligned)?;
        let account_metas = translate_slice::<
            SolAccountMeta,
        >(memory_mapping, ix_c.accounts_addr, ix_c.accounts_len, check_aligned)?;
        let data = translate_slice::<
            u8,
        >(memory_mapping, ix_c.data_addr, ix_c.data_len, check_aligned)?;
        check_instruction_size(ix_c.accounts_len as usize, data.len())?;
        let mut total_cu_translation_cost: u64 = (data.len() as u64)
            .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
            .unwrap_or(u64::MAX);
        if invoke_context.get_feature_set().increase_cpi_account_info_limit {
            let account_meta_translation_cost = (ix_c
                .accounts_len
                .saturating_mul(size_of::<AccountMeta>() as u64))
                .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                .unwrap_or(u64::MAX);
            total_cu_translation_cost = total_cu_translation_cost
                .saturating_add(account_meta_translation_cost);
        }
        consume_compute_meter(invoke_context, total_cu_translation_cost)?;
        let mut accounts = Vec::with_capacity(ix_c.accounts_len as usize);
        #[allow(clippy::needless_range_loop)]
        for account_index in 0..ix_c.accounts_len as usize {
            #[allow(clippy::indexing_slicing)]
            let account_meta = &account_metas[account_index];
            if unsafe {
                std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8)
                    > 1
                    || std::ptr::read_volatile(
                        &account_meta.is_writable as *const _ as *const u8,
                    ) > 1
            } {
                return Err(Box::new(InstructionError::InvalidArgument));
            }
            let pubkey = translate_type::<
                Pubkey,
            >(memory_mapping, account_meta.pubkey_addr, check_aligned)?;
            accounts
                .push(AccountMeta {
                    pubkey: *pubkey,
                    is_signer: account_meta.is_signer,
                    is_writable: account_meta.is_writable,
                });
        }
        Ok(Instruction {
            accounts,
            data: data.to_vec(),
            program_id: *program_id,
        })
    }
    pub fn translate_accounts_c<'a>(
        account_infos_addr: u64,
        account_infos_len: u64,
        memory_mapping: &MemoryMapping<'_>,
        invoke_context: &mut InvokeContext,
        check_aligned: bool,
    ) -> Result<Vec<TranslatedAccount<'a>>, Error> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |account_info: &SolAccountInfo| account_info.key_addr,
            memory_mapping,
            invoke_context,
            check_aligned,
        )?;
        translate_accounts_common(
            &account_info_keys,
            account_infos,
            account_infos_addr,
            invoke_context,
            memory_mapping,
            check_aligned,
            CallerAccount::from_sol_account_info,
        )
    }
    pub fn translate_signers_c(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &MemoryMapping,
        check_aligned: bool,
    ) -> Result<Vec<Pubkey>, Error> {
        if signers_seeds_len > 0 {
            let signers_seeds = translate_slice::<
                SolSignerSeedsC,
            >(memory_mapping, signers_seeds_addr, signers_seeds_len, check_aligned)?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(Box::new(CpiError::TooManySigners));
            }
            Ok(
                signers_seeds
                    .iter()
                    .map(|signer_seeds| {
                        let seeds = translate_slice::<
                            SolSignerSeedC,
                        >(
                            memory_mapping,
                            signer_seeds.addr,
                            signer_seeds.len,
                            check_aligned,
                        )?;
                        if seeds.len() > MAX_SEEDS {
                            return Err(
                                Box::new(InstructionError::MaxSeedLengthExceeded) as Error,
                            );
                        }
                        let seeds_bytes = seeds
                            .iter()
                            .map(|seed| {
                                translate_slice::<
                                    u8,
                                >(memory_mapping, seed.addr, seed.len, check_aligned)
                            })
                            .collect::<Result<Vec<_>, Error>>()?;
                        Pubkey::create_program_address(&seeds_bytes, program_id)
                            .map_err(|err| Box::new(CpiError::BadSeeds(err)) as Error)
                    })
                    .collect::<Result<Vec<_>, Error>>()?,
            )
        } else {
            Ok(::alloc::vec::Vec::new())
        }
    }
    /// Call process instruction, common to both Rust and C
    pub fn cpi_common<S: SyscallInvokeSigned>(
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        consume_compute_meter(
            invoke_context,
            invoke_context.get_execution_cost().invoke_units,
        )?;
        if let Some(execute_time) = invoke_context.execute_time.as_mut() {
            execute_time.stop();
            invoke_context.timings.execute_us += execute_time.as_us();
        }
        let stricter_abi_and_runtime_constraints = invoke_context
            .get_feature_set()
            .stricter_abi_and_runtime_constraints;
        let account_data_direct_mapping = invoke_context
            .get_feature_set()
            .account_data_direct_mapping;
        let check_aligned = invoke_context.get_check_aligned();
        let instruction = S::translate_instruction(
            instruction_addr,
            memory_mapping,
            invoke_context,
            check_aligned,
        )?;
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context.get_current_instruction_context()?;
        let caller_program_id = instruction_context.get_program_key()?;
        let signers = S::translate_signers(
            caller_program_id,
            signers_seeds_addr,
            signers_seeds_len,
            memory_mapping,
            check_aligned,
        )?;
        check_authorized_program(
            &instruction.program_id,
            &instruction.data,
            invoke_context,
        )?;
        invoke_context.prepare_next_instruction(instruction, &signers)?;
        let mut accounts = S::translate_accounts(
            account_infos_addr,
            account_infos_len,
            memory_mapping,
            invoke_context,
            check_aligned,
        )?;
        if stricter_abi_and_runtime_constraints {
            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context
                .get_current_instruction_context()?;
            for translated_account in accounts.iter_mut() {
                let callee_account = instruction_context
                    .try_borrow_instruction_account(translated_account.index_in_caller)?;
                let update_caller = update_callee_account(
                    memory_mapping,
                    check_aligned,
                    &translated_account.caller_account,
                    callee_account,
                    stricter_abi_and_runtime_constraints,
                    account_data_direct_mapping,
                )?;
                translated_account.update_caller_account_region = translated_account
                    .update_caller_account_info || update_caller;
            }
        }
        let mut compute_units_consumed = 0;
        invoke_context
            .process_instruction(
                &mut compute_units_consumed,
                &mut ExecuteTimings::default(),
            )?;
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context.get_current_instruction_context()?;
        for translated_account in accounts.iter_mut() {
            let mut callee_account = instruction_context
                .try_borrow_instruction_account(translated_account.index_in_caller)?;
            if translated_account.update_caller_account_info {
                update_caller_account(
                    invoke_context,
                    memory_mapping,
                    check_aligned,
                    &mut translated_account.caller_account,
                    &mut callee_account,
                    stricter_abi_and_runtime_constraints,
                    account_data_direct_mapping,
                )?;
            }
        }
        if stricter_abi_and_runtime_constraints {
            for translated_account in accounts.iter() {
                let mut callee_account = instruction_context
                    .try_borrow_instruction_account(translated_account.index_in_caller)?;
                if translated_account.update_caller_account_region {
                    update_caller_account_region(
                        memory_mapping,
                        check_aligned,
                        &translated_account.caller_account,
                        &mut callee_account,
                        account_data_direct_mapping,
                    )?;
                }
            }
        }
        invoke_context.execute_time = Some(Measure::start("execute"));
        Ok(SUCCESS)
    }
    /// Account data and metadata that has been translated from caller space.
    pub struct TranslatedAccount<'a> {
        pub index_in_caller: IndexOfAccount,
        pub caller_account: CallerAccount<'a>,
        pub update_caller_account_region: bool,
        pub update_caller_account_info: bool,
    }
    fn translate_account_infos<'a, T, F>(
        account_infos_addr: u64,
        account_infos_len: u64,
        key_addr: F,
        memory_mapping: &'a MemoryMapping,
        invoke_context: &mut InvokeContext,
        check_aligned: bool,
    ) -> Result<(&'a [T], Vec<&'a Pubkey>), Error>
    where
        F: Fn(&T) -> u64,
    {
        let stricter_abi_and_runtime_constraints = invoke_context
            .get_feature_set()
            .stricter_abi_and_runtime_constraints;
        if stricter_abi_and_runtime_constraints
            && account_infos_addr
                .saturating_add(
                    account_infos_len.saturating_mul(std::mem::size_of::<T>() as u64),
                ) >= ebpf::MM_INPUT_START
        {
            return Err(CpiError::InvalidPointer.into());
        }
        let account_infos = translate_slice::<
            T,
        >(memory_mapping, account_infos_addr, account_infos_len, check_aligned)?;
        check_account_infos(account_infos.len(), invoke_context)?;
        if invoke_context.get_feature_set().increase_cpi_account_info_limit {
            let account_infos_bytes = account_infos
                .len()
                .saturating_mul(ACCOUNT_INFO_BYTE_SIZE);
            consume_compute_meter(
                invoke_context,
                (account_infos_bytes as u64)
                    .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )?;
        }
        let mut account_info_keys = Vec::with_capacity(account_infos_len as usize);
        #[allow(clippy::needless_range_loop)]
        for account_index in 0..account_infos_len as usize {
            #[allow(clippy::indexing_slicing)]
            let account_info = &account_infos[account_index];
            account_info_keys
                .push(
                    translate_type::<
                        Pubkey,
                    >(memory_mapping, key_addr(account_info), check_aligned)?,
                );
        }
        Ok((account_infos, account_info_keys))
    }
    fn translate_accounts_common<'a, T, F>(
        account_info_keys: &[&Pubkey],
        account_infos: &[T],
        account_infos_addr: u64,
        invoke_context: &mut InvokeContext,
        memory_mapping: &MemoryMapping<'_>,
        check_aligned: bool,
        do_translate: F,
    ) -> Result<Vec<TranslatedAccount<'a>>, Error>
    where
        F: Fn(
            &InvokeContext,
            &MemoryMapping<'_>,
            bool,
            u64,
            &T,
            &SerializedAccountMetadata,
        ) -> Result<CallerAccount<'a>, Error>,
    {
        let transaction_context = &invoke_context.transaction_context;
        let next_instruction_context = transaction_context
            .get_next_instruction_context()?;
        let next_instruction_accounts = next_instruction_context.instruction_accounts();
        let instruction_context = transaction_context.get_current_instruction_context()?;
        let mut accounts = Vec::with_capacity(next_instruction_accounts.len());
        let accounts_metadata = &invoke_context
            .get_syscall_context()
            .unwrap()
            .accounts_metadata;
        let stricter_abi_and_runtime_constraints = invoke_context
            .get_feature_set()
            .stricter_abi_and_runtime_constraints;
        let account_data_direct_mapping = invoke_context
            .get_feature_set()
            .account_data_direct_mapping;
        for (instruction_account_index, instruction_account) in next_instruction_accounts
            .iter()
            .enumerate()
        {
            if next_instruction_context
                .is_instruction_account_duplicate(
                    instruction_account_index as IndexOfAccount,
                )?
                .is_some()
            {
                continue;
            }
            let index_in_caller = instruction_context
                .get_index_of_account_in_instruction(
                    instruction_account.index_in_transaction,
                )?;
            let callee_account = instruction_context
                .try_borrow_instruction_account(index_in_caller)?;
            let account_key = invoke_context
                .transaction_context
                .get_key_of_account_at_index(instruction_account.index_in_transaction)?;
            #[allow(deprecated)]
            if callee_account.is_executable() {
                consume_compute_meter(
                    invoke_context,
                    (callee_account.get_data().len() as u64)
                        .checked_div(
                            invoke_context.get_execution_cost().cpi_bytes_per_unit,
                        )
                        .unwrap_or(u64::MAX),
                )?;
            } else if let Some(caller_account_index) = account_info_keys
                .iter()
                .position(|key| *key == account_key)
            {
                let serialized_metadata = accounts_metadata
                    .get(index_in_caller as usize)
                    .ok_or_else(|| {
                        {
                            {
                                {
                                    let lvl = ::log::Level::Debug;
                                    if lvl <= ::log::STATIC_MAX_LEVEL
                                        && lvl <= ::log::max_level()
                                    {
                                        ::log::__private_api::log(
                                            { ::log::__private_api::GlobalLogger },
                                            format_args!(
                                                "Internal error: index mismatch for account {0}",
                                                account_key,
                                            ),
                                            lvl,
                                            &(
                                                "solana_runtime::message_processor::stable_log",
                                                "solana_program_runtime::cpi",
                                                ::log::__private_api::loc(),
                                            ),
                                            (),
                                        );
                                    }
                                }
                            }
                        };
                        if let Some(log_collector) = invoke_context
                            .get_log_collector()
                            .as_ref()
                        {
                            if let Ok(mut log_collector) = log_collector.try_borrow_mut()
                            {
                                log_collector
                                    .log(
                                        &::alloc::__export::must_use({
                                            ::alloc::fmt::format(
                                                format_args!(
                                                    "Internal error: index mismatch for account {0}",
                                                    account_key,
                                                ),
                                            )
                                        }),
                                    );
                            }
                        }
                        Box::new(InstructionError::MissingAccount)
                    })?;
                if caller_account_index >= account_infos.len() {
                    return Err(Box::new(CpiError::InvalidLength));
                }
                #[allow(clippy::indexing_slicing)]
                let caller_account = do_translate(
                    invoke_context,
                    memory_mapping,
                    check_aligned,
                    account_infos_addr
                        .saturating_add(
                            caller_account_index.saturating_mul(mem::size_of::<T>())
                                as u64,
                        ),
                    &account_infos[caller_account_index],
                    serialized_metadata,
                )?;
                let update_caller = if stricter_abi_and_runtime_constraints {
                    true
                } else {
                    update_callee_account(
                        memory_mapping,
                        check_aligned,
                        &caller_account,
                        callee_account,
                        stricter_abi_and_runtime_constraints,
                        account_data_direct_mapping,
                    )?
                };
                accounts
                    .push(TranslatedAccount {
                        index_in_caller,
                        caller_account,
                        update_caller_account_region: instruction_account.is_writable()
                            || update_caller,
                        update_caller_account_info: instruction_account.is_writable(),
                    });
            } else {
                {
                    {
                        {
                            let lvl = ::log::Level::Debug;
                            if lvl <= ::log::STATIC_MAX_LEVEL
                                && lvl <= ::log::max_level()
                            {
                                ::log::__private_api::log(
                                    { ::log::__private_api::GlobalLogger },
                                    format_args!(
                                        "Instruction references an unknown account {0}",
                                        account_key,
                                    ),
                                    lvl,
                                    &(
                                        "solana_runtime::message_processor::stable_log",
                                        "solana_program_runtime::cpi",
                                        ::log::__private_api::loc(),
                                    ),
                                    (),
                                );
                            }
                        }
                    }
                };
                if let Some(log_collector) = invoke_context.get_log_collector().as_ref()
                {
                    if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                        log_collector
                            .log(
                                &::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "Instruction references an unknown account {0}",
                                            account_key,
                                        ),
                                    )
                                }),
                            );
                    }
                }
                return Err(Box::new(InstructionError::MissingAccount));
            }
        }
        Ok(accounts)
    }
    fn consume_compute_meter(
        invoke_context: &InvokeContext,
        amount: u64,
    ) -> Result<(), Error> {
        invoke_context.consume_checked(amount)?;
        Ok(())
    }
    fn update_callee_account(
        memory_mapping: &MemoryMapping,
        check_aligned: bool,
        caller_account: &CallerAccount,
        mut callee_account: BorrowedInstructionAccount<'_, '_>,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
    ) -> Result<bool, Error> {
        let mut must_update_caller = false;
        if callee_account.get_lamports() != *caller_account.lamports {
            callee_account.set_lamports(*caller_account.lamports)?;
        }
        if stricter_abi_and_runtime_constraints {
            let prev_len = callee_account.get_data().len();
            let post_len = *caller_account.ref_to_len_in_vm as usize;
            if prev_len != post_len {
                let is_caller_loader_deprecated = !check_aligned;
                let address_space_reserved_for_account = if is_caller_loader_deprecated {
                    caller_account.original_data_len
                } else {
                    caller_account
                        .original_data_len
                        .saturating_add(MAX_PERMITTED_DATA_INCREASE)
                };
                if post_len > address_space_reserved_for_account {
                    return Err(InstructionError::InvalidRealloc.into());
                }
                if !account_data_direct_mapping && post_len < prev_len {
                    let serialized_data = CallerAccount::get_serialized_data(
                        memory_mapping,
                        caller_account.vm_data_addr,
                        prev_len as u64,
                        stricter_abi_and_runtime_constraints,
                        account_data_direct_mapping,
                    )?;
                    serialized_data
                        .get_mut(post_len..)
                        .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                        .fill(0);
                }
                callee_account.set_data_length(post_len)?;
                must_update_caller = true;
            }
            if !account_data_direct_mapping
                && callee_account.can_data_be_changed().is_ok()
            {
                callee_account.set_data_from_slice(caller_account.serialized_data)?;
            }
        } else {
            match callee_account
                .can_data_be_resized(caller_account.serialized_data.len())
            {
                Ok(()) => {
                    callee_account.set_data_from_slice(caller_account.serialized_data)?
                }
                Err(
                    err,
                ) if callee_account.get_data() != caller_account.serialized_data => {
                    return Err(Box::new(err));
                }
                _ => {}
            }
        }
        if callee_account.get_owner() != caller_account.owner {
            callee_account.set_owner(caller_account.owner.as_ref())?;
            must_update_caller = true;
        }
        Ok(must_update_caller)
    }
    fn update_caller_account_region(
        memory_mapping: &mut MemoryMapping,
        check_aligned: bool,
        caller_account: &CallerAccount,
        callee_account: &mut BorrowedInstructionAccount<'_, '_>,
        account_data_direct_mapping: bool,
    ) -> Result<(), Error> {
        let is_caller_loader_deprecated = !check_aligned;
        let address_space_reserved_for_account = if is_caller_loader_deprecated {
            caller_account.original_data_len
        } else {
            caller_account.original_data_len.saturating_add(MAX_PERMITTED_DATA_INCREASE)
        };
        if address_space_reserved_for_account > 0 {
            let (region_index, region) = memory_mapping
                .find_region(caller_account.vm_data_addr)
                .ok_or_else(|| Box::new(InstructionError::MissingAccount))?;
            if true {
                match (&region.vm_addr, &caller_account.vm_data_addr) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::None,
                            );
                        }
                    }
                };
            }
            let mut new_region;
            if !account_data_direct_mapping {
                new_region = region.clone();
                modify_memory_region_of_account(callee_account, &mut new_region);
            } else {
                new_region = create_memory_region_of_account(
                    callee_account,
                    region.vm_addr,
                )?;
            }
            memory_mapping.replace_region(region_index, new_region)?;
        }
        Ok(())
    }
    fn update_caller_account(
        invoke_context: &InvokeContext,
        memory_mapping: &MemoryMapping<'_>,
        check_aligned: bool,
        caller_account: &mut CallerAccount<'_>,
        callee_account: &mut BorrowedInstructionAccount<'_, '_>,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
    ) -> Result<(), Error> {
        *caller_account.lamports = callee_account.get_lamports();
        *caller_account.owner = *callee_account.get_owner();
        let prev_len = *caller_account.ref_to_len_in_vm as usize;
        let post_len = callee_account.get_data().len();
        let is_caller_loader_deprecated = !check_aligned;
        let address_space_reserved_for_account = if stricter_abi_and_runtime_constraints
            && is_caller_loader_deprecated
        {
            caller_account.original_data_len
        } else {
            caller_account.original_data_len.saturating_add(MAX_PERMITTED_DATA_INCREASE)
        };
        if post_len > address_space_reserved_for_account
            && (stricter_abi_and_runtime_constraints || prev_len != post_len)
        {
            let max_increase = address_space_reserved_for_account
                .saturating_sub(caller_account.original_data_len);
            {
                {
                    {
                        let lvl = ::log::Level::Debug;
                        if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                            ::log::__private_api::log(
                                { ::log::__private_api::GlobalLogger },
                                format_args!(
                                    "Account data size realloc limited to {0} in inner instructions",
                                    max_increase,
                                ),
                                lvl,
                                &(
                                    "solana_runtime::message_processor::stable_log",
                                    "solana_program_runtime::cpi",
                                    ::log::__private_api::loc(),
                                ),
                                (),
                            );
                        }
                    }
                }
            };
            if let Some(log_collector) = invoke_context.get_log_collector().as_ref() {
                if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                    log_collector
                        .log(
                            &::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!(
                                        "Account data size realloc limited to {0} in inner instructions",
                                        max_increase,
                                    ),
                                )
                            }),
                        );
                }
            }
            return Err(Box::new(InstructionError::InvalidRealloc));
        }
        if prev_len != post_len {
            if !(stricter_abi_and_runtime_constraints && account_data_direct_mapping) {
                if post_len < prev_len {
                    caller_account
                        .serialized_data
                        .get_mut(post_len..)
                        .ok_or_else(|| Box::new(InstructionError::AccountDataTooSmall))?
                        .fill(0);
                }
                caller_account.serialized_data = CallerAccount::get_serialized_data(
                    memory_mapping,
                    caller_account.vm_data_addr,
                    post_len as u64,
                    stricter_abi_and_runtime_constraints,
                    account_data_direct_mapping,
                )?;
            }
            *caller_account.ref_to_len_in_vm = post_len as u64;
            let serialized_len_ptr = translate_type_mut_for_cpi::<
                u64,
            >(
                memory_mapping,
                caller_account
                    .vm_data_addr
                    .saturating_sub(std::mem::size_of::<u64>() as u64),
                check_aligned,
            )?;
            *serialized_len_ptr = post_len as u64;
        }
        if !(stricter_abi_and_runtime_constraints && account_data_direct_mapping) {
            let to_slice = &mut caller_account.serialized_data;
            let from_slice = callee_account
                .get_data()
                .get(0..post_len)
                .ok_or(CpiError::InvalidLength)?;
            if to_slice.len() != from_slice.len() {
                return Err(Box::new(InstructionError::AccountDataTooSmall));
            }
            to_slice.copy_from_slice(from_slice);
        }
        Ok(())
    }
}
pub mod execution_budget {
    use {
        solana_fee_structure::FeeDetails, solana_program_entrypoint::HEAP_LENGTH,
        solana_transaction_context::MAX_INSTRUCTION_TRACE_LENGTH, std::num::NonZeroU32,
    };
    /// Max instruction stack depth. This is the maximum nesting of instructions that can happen during
    /// a transaction.
    pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;
    /// Max instruction stack depth with SIMD-0268 enabled. Allows 8 nested CPIs.
    pub const MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268: usize = 9;
    fn get_max_instruction_stack_depth(simd_0268_active: bool) -> usize {
        if simd_0268_active {
            MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268
        } else {
            MAX_INSTRUCTION_STACK_DEPTH
        }
    }
    pub const DEFAULT_INVOCATION_COST: u64 = 1000;
    pub const INVOKE_UNITS_COST_SIMD_0339: u64 = 946;
    fn get_invoke_unit_cost(simd_0339_active: bool) -> u64 {
        if simd_0339_active {
            INVOKE_UNITS_COST_SIMD_0339
        } else {
            DEFAULT_INVOCATION_COST
        }
    }
    /// Max call depth. This is the maximum nesting of SBF to SBF call that can happen within a program.
    pub const MAX_CALL_DEPTH: usize = 64;
    /// The size of one SBF stack frame.
    pub const STACK_FRAME_SIZE: usize = 4096;
    pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
    /// Roughly 0.5us/page, where page is 32K; given roughly 15CU/us, the
    /// default heap page cost = 0.5 * 15 ~= 8CU/page
    pub const DEFAULT_HEAP_COST: u64 = 8;
    pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
    pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
    pub const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
    pub const MIN_HEAP_FRAME_BYTES: u32 = HEAP_LENGTH as u32;
    /// The total accounts data a transaction can load is limited to 64MiB to not break
    /// anyone in Mainnet-beta today. It can be set by set_loaded_accounts_data_size_limit instruction
    pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES: NonZeroU32 = NonZeroU32::new(
            64 * 1024 * 1024,
        )
        .unwrap();
    pub struct SVMTransactionExecutionBudget {
        /// Number of compute units that a transaction or individual instruction is
        /// allowed to consume. Compute units are consumed by program execution,
        /// resources they use, etc...
        pub compute_unit_limit: u64,
        /// Maximum program instruction invocation stack depth. Invocation stack
        /// depth starts at 1 for transaction instructions and the stack depth is
        /// incremented each time a program invokes an instruction and decremented
        /// when a program returns.
        pub max_instruction_stack_depth: usize,
        /// Maximum cross-program invocation and instructions per transaction
        pub max_instruction_trace_length: usize,
        /// Maximum number of slices hashed per syscall
        pub sha256_max_slices: u64,
        /// Maximum SBF to BPF call depth
        pub max_call_depth: usize,
        /// Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend
        pub stack_frame_size: usize,
        /// program heap region size, default: solana_program_entrypoint::HEAP_LENGTH
        pub heap_size: u32,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SVMTransactionExecutionBudget {
        #[inline]
        fn clone(&self) -> SVMTransactionExecutionBudget {
            let _: ::core::clone::AssertParamIsClone<u64>;
            let _: ::core::clone::AssertParamIsClone<usize>;
            let _: ::core::clone::AssertParamIsClone<u32>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for SVMTransactionExecutionBudget {}
    #[automatically_derived]
    impl ::core::fmt::Debug for SVMTransactionExecutionBudget {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "compute_unit_limit",
                "max_instruction_stack_depth",
                "max_instruction_trace_length",
                "sha256_max_slices",
                "max_call_depth",
                "stack_frame_size",
                "heap_size",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.compute_unit_limit,
                &self.max_instruction_stack_depth,
                &self.max_instruction_trace_length,
                &self.sha256_max_slices,
                &self.max_call_depth,
                &self.stack_frame_size,
                &&self.heap_size,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "SVMTransactionExecutionBudget",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for SVMTransactionExecutionBudget {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for SVMTransactionExecutionBudget {
        #[inline]
        fn eq(&self, other: &SVMTransactionExecutionBudget) -> bool {
            self.compute_unit_limit == other.compute_unit_limit
                && self.sha256_max_slices == other.sha256_max_slices
                && self.heap_size == other.heap_size
                && self.max_instruction_stack_depth == other.max_instruction_stack_depth
                && self.max_instruction_trace_length
                    == other.max_instruction_trace_length
                && self.max_call_depth == other.max_call_depth
                && self.stack_frame_size == other.stack_frame_size
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for SVMTransactionExecutionBudget {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<u64>;
            let _: ::core::cmp::AssertParamIsEq<usize>;
            let _: ::core::cmp::AssertParamIsEq<u32>;
        }
    }
    impl SVMTransactionExecutionBudget {
        pub fn new_with_defaults(simd_0268_active: bool) -> Self {
            SVMTransactionExecutionBudget {
                compute_unit_limit: u64::from(MAX_COMPUTE_UNIT_LIMIT),
                max_instruction_stack_depth: get_max_instruction_stack_depth(
                    simd_0268_active,
                ),
                max_instruction_trace_length: MAX_INSTRUCTION_TRACE_LENGTH,
                sha256_max_slices: 20_000,
                max_call_depth: MAX_CALL_DEPTH,
                stack_frame_size: STACK_FRAME_SIZE,
                heap_size: u32::try_from(solana_program_entrypoint::HEAP_LENGTH).unwrap(),
            }
        }
    }
    pub struct SVMTransactionExecutionCost {
        /// Number of compute units consumed by a log_u64 call
        pub log_64_units: u64,
        /// Number of compute units consumed by a create_program_address call
        pub create_program_address_units: u64,
        /// Number of compute units consumed by an invoke call (not including the cost incurred by
        /// the called program)
        pub invoke_units: u64,
        /// Base number of compute units consumed to call SHA256
        pub sha256_base_cost: u64,
        /// Incremental number of units consumed by SHA256 (based on bytes)
        pub sha256_byte_cost: u64,
        /// Number of compute units consumed by logging a `Pubkey`
        pub log_pubkey_units: u64,
        /// Number of account data bytes per compute unit charged during a cross-program invocation
        pub cpi_bytes_per_unit: u64,
        /// Base number of compute units consumed to get a sysvar
        pub sysvar_base_cost: u64,
        /// Number of compute units consumed to call secp256k1_recover
        pub secp256k1_recover_cost: u64,
        /// Number of compute units consumed to do a syscall without any work
        pub syscall_base_cost: u64,
        /// Number of compute units consumed to validate a curve25519 edwards point
        pub curve25519_edwards_validate_point_cost: u64,
        /// Number of compute units consumed to add two curve25519 edwards points
        pub curve25519_edwards_add_cost: u64,
        /// Number of compute units consumed to subtract two curve25519 edwards points
        pub curve25519_edwards_subtract_cost: u64,
        /// Number of compute units consumed to multiply a curve25519 edwards point
        pub curve25519_edwards_multiply_cost: u64,
        /// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
        /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
        pub curve25519_edwards_msm_base_cost: u64,
        /// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
        /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
        pub curve25519_edwards_msm_incremental_cost: u64,
        /// Number of compute units consumed to validate a curve25519 ristretto point
        pub curve25519_ristretto_validate_point_cost: u64,
        /// Number of compute units consumed to add two curve25519 ristretto points
        pub curve25519_ristretto_add_cost: u64,
        /// Number of compute units consumed to subtract two curve25519 ristretto points
        pub curve25519_ristretto_subtract_cost: u64,
        /// Number of compute units consumed to multiply a curve25519 ristretto point
        pub curve25519_ristretto_multiply_cost: u64,
        /// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
        /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
        pub curve25519_ristretto_msm_base_cost: u64,
        /// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
        /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
        pub curve25519_ristretto_msm_incremental_cost: u64,
        /// Number of compute units per additional 32k heap above the default (~.5
        /// us per 32k at 15 units/us rounded up)
        pub heap_cost: u64,
        /// Memory operation syscall base cost
        pub mem_op_base_cost: u64,
        /// Number of compute units consumed to call alt_bn128_addition
        pub alt_bn128_addition_cost: u64,
        /// Number of compute units consumed to call alt_bn128_multiplication.
        pub alt_bn128_multiplication_cost: u64,
        /// Total cost will be alt_bn128_pairing_one_pair_cost_first
        /// + alt_bn128_pairing_one_pair_cost_other * (num_elems - 1)
        pub alt_bn128_pairing_one_pair_cost_first: u64,
        pub alt_bn128_pairing_one_pair_cost_other: u64,
        /// Big integer modular exponentiation base cost
        pub big_modular_exponentiation_base_cost: u64,
        /// Big integer moduler exponentiation cost divisor
        /// The modular exponentiation cost is computed as
        /// `input_length`/`big_modular_exponentiation_cost_divisor` + `big_modular_exponentiation_base_cost`
        pub big_modular_exponentiation_cost_divisor: u64,
        /// Coefficient `a` of the quadratic function which determines the number
        /// of compute units consumed to call poseidon syscall for a given number
        /// of inputs.
        pub poseidon_cost_coefficient_a: u64,
        /// Coefficient `c` of the quadratic function which determines the number
        /// of compute units consumed to call poseidon syscall for a given number
        /// of inputs.
        pub poseidon_cost_coefficient_c: u64,
        /// Number of compute units consumed for accessing the remaining compute units.
        pub get_remaining_compute_units_cost: u64,
        /// Number of compute units consumed to call alt_bn128_g1_compress.
        pub alt_bn128_g1_compress: u64,
        /// Number of compute units consumed to call alt_bn128_g1_decompress.
        pub alt_bn128_g1_decompress: u64,
        /// Number of compute units consumed to call alt_bn128_g2_compress.
        pub alt_bn128_g2_compress: u64,
        /// Number of compute units consumed to call alt_bn128_g2_decompress.
        pub alt_bn128_g2_decompress: u64,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SVMTransactionExecutionCost {
        #[inline]
        fn clone(&self) -> SVMTransactionExecutionCost {
            let _: ::core::clone::AssertParamIsClone<u64>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for SVMTransactionExecutionCost {}
    #[automatically_derived]
    impl ::core::fmt::Debug for SVMTransactionExecutionCost {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "log_64_units",
                "create_program_address_units",
                "invoke_units",
                "sha256_base_cost",
                "sha256_byte_cost",
                "log_pubkey_units",
                "cpi_bytes_per_unit",
                "sysvar_base_cost",
                "secp256k1_recover_cost",
                "syscall_base_cost",
                "curve25519_edwards_validate_point_cost",
                "curve25519_edwards_add_cost",
                "curve25519_edwards_subtract_cost",
                "curve25519_edwards_multiply_cost",
                "curve25519_edwards_msm_base_cost",
                "curve25519_edwards_msm_incremental_cost",
                "curve25519_ristretto_validate_point_cost",
                "curve25519_ristretto_add_cost",
                "curve25519_ristretto_subtract_cost",
                "curve25519_ristretto_multiply_cost",
                "curve25519_ristretto_msm_base_cost",
                "curve25519_ristretto_msm_incremental_cost",
                "heap_cost",
                "mem_op_base_cost",
                "alt_bn128_addition_cost",
                "alt_bn128_multiplication_cost",
                "alt_bn128_pairing_one_pair_cost_first",
                "alt_bn128_pairing_one_pair_cost_other",
                "big_modular_exponentiation_base_cost",
                "big_modular_exponentiation_cost_divisor",
                "poseidon_cost_coefficient_a",
                "poseidon_cost_coefficient_c",
                "get_remaining_compute_units_cost",
                "alt_bn128_g1_compress",
                "alt_bn128_g1_decompress",
                "alt_bn128_g2_compress",
                "alt_bn128_g2_decompress",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.log_64_units,
                &self.create_program_address_units,
                &self.invoke_units,
                &self.sha256_base_cost,
                &self.sha256_byte_cost,
                &self.log_pubkey_units,
                &self.cpi_bytes_per_unit,
                &self.sysvar_base_cost,
                &self.secp256k1_recover_cost,
                &self.syscall_base_cost,
                &self.curve25519_edwards_validate_point_cost,
                &self.curve25519_edwards_add_cost,
                &self.curve25519_edwards_subtract_cost,
                &self.curve25519_edwards_multiply_cost,
                &self.curve25519_edwards_msm_base_cost,
                &self.curve25519_edwards_msm_incremental_cost,
                &self.curve25519_ristretto_validate_point_cost,
                &self.curve25519_ristretto_add_cost,
                &self.curve25519_ristretto_subtract_cost,
                &self.curve25519_ristretto_multiply_cost,
                &self.curve25519_ristretto_msm_base_cost,
                &self.curve25519_ristretto_msm_incremental_cost,
                &self.heap_cost,
                &self.mem_op_base_cost,
                &self.alt_bn128_addition_cost,
                &self.alt_bn128_multiplication_cost,
                &self.alt_bn128_pairing_one_pair_cost_first,
                &self.alt_bn128_pairing_one_pair_cost_other,
                &self.big_modular_exponentiation_base_cost,
                &self.big_modular_exponentiation_cost_divisor,
                &self.poseidon_cost_coefficient_a,
                &self.poseidon_cost_coefficient_c,
                &self.get_remaining_compute_units_cost,
                &self.alt_bn128_g1_compress,
                &self.alt_bn128_g1_decompress,
                &self.alt_bn128_g2_compress,
                &&self.alt_bn128_g2_decompress,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "SVMTransactionExecutionCost",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for SVMTransactionExecutionCost {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for SVMTransactionExecutionCost {
        #[inline]
        fn eq(&self, other: &SVMTransactionExecutionCost) -> bool {
            self.log_64_units == other.log_64_units
                && self.create_program_address_units
                    == other.create_program_address_units
                && self.invoke_units == other.invoke_units
                && self.sha256_base_cost == other.sha256_base_cost
                && self.sha256_byte_cost == other.sha256_byte_cost
                && self.log_pubkey_units == other.log_pubkey_units
                && self.cpi_bytes_per_unit == other.cpi_bytes_per_unit
                && self.sysvar_base_cost == other.sysvar_base_cost
                && self.secp256k1_recover_cost == other.secp256k1_recover_cost
                && self.syscall_base_cost == other.syscall_base_cost
                && self.curve25519_edwards_validate_point_cost
                    == other.curve25519_edwards_validate_point_cost
                && self.curve25519_edwards_add_cost == other.curve25519_edwards_add_cost
                && self.curve25519_edwards_subtract_cost
                    == other.curve25519_edwards_subtract_cost
                && self.curve25519_edwards_multiply_cost
                    == other.curve25519_edwards_multiply_cost
                && self.curve25519_edwards_msm_base_cost
                    == other.curve25519_edwards_msm_base_cost
                && self.curve25519_edwards_msm_incremental_cost
                    == other.curve25519_edwards_msm_incremental_cost
                && self.curve25519_ristretto_validate_point_cost
                    == other.curve25519_ristretto_validate_point_cost
                && self.curve25519_ristretto_add_cost
                    == other.curve25519_ristretto_add_cost
                && self.curve25519_ristretto_subtract_cost
                    == other.curve25519_ristretto_subtract_cost
                && self.curve25519_ristretto_multiply_cost
                    == other.curve25519_ristretto_multiply_cost
                && self.curve25519_ristretto_msm_base_cost
                    == other.curve25519_ristretto_msm_base_cost
                && self.curve25519_ristretto_msm_incremental_cost
                    == other.curve25519_ristretto_msm_incremental_cost
                && self.heap_cost == other.heap_cost
                && self.mem_op_base_cost == other.mem_op_base_cost
                && self.alt_bn128_addition_cost == other.alt_bn128_addition_cost
                && self.alt_bn128_multiplication_cost
                    == other.alt_bn128_multiplication_cost
                && self.alt_bn128_pairing_one_pair_cost_first
                    == other.alt_bn128_pairing_one_pair_cost_first
                && self.alt_bn128_pairing_one_pair_cost_other
                    == other.alt_bn128_pairing_one_pair_cost_other
                && self.big_modular_exponentiation_base_cost
                    == other.big_modular_exponentiation_base_cost
                && self.big_modular_exponentiation_cost_divisor
                    == other.big_modular_exponentiation_cost_divisor
                && self.poseidon_cost_coefficient_a == other.poseidon_cost_coefficient_a
                && self.poseidon_cost_coefficient_c == other.poseidon_cost_coefficient_c
                && self.get_remaining_compute_units_cost
                    == other.get_remaining_compute_units_cost
                && self.alt_bn128_g1_compress == other.alt_bn128_g1_compress
                && self.alt_bn128_g1_decompress == other.alt_bn128_g1_decompress
                && self.alt_bn128_g2_compress == other.alt_bn128_g2_compress
                && self.alt_bn128_g2_decompress == other.alt_bn128_g2_decompress
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for SVMTransactionExecutionCost {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<u64>;
        }
    }
    impl Default for SVMTransactionExecutionCost {
        fn default() -> Self {
            Self::new_with_defaults(false)
        }
    }
    impl SVMTransactionExecutionCost {
        pub fn new_with_defaults(simd_0339_active: bool) -> Self {
            SVMTransactionExecutionCost {
                log_64_units: 100,
                create_program_address_units: 1500,
                invoke_units: get_invoke_unit_cost(simd_0339_active),
                sha256_base_cost: 85,
                sha256_byte_cost: 1,
                log_pubkey_units: 100,
                cpi_bytes_per_unit: 250,
                sysvar_base_cost: 100,
                secp256k1_recover_cost: 25_000,
                syscall_base_cost: 100,
                curve25519_edwards_validate_point_cost: 159,
                curve25519_edwards_add_cost: 473,
                curve25519_edwards_subtract_cost: 475,
                curve25519_edwards_multiply_cost: 2_177,
                curve25519_edwards_msm_base_cost: 2_273,
                curve25519_edwards_msm_incremental_cost: 758,
                curve25519_ristretto_validate_point_cost: 169,
                curve25519_ristretto_add_cost: 521,
                curve25519_ristretto_subtract_cost: 519,
                curve25519_ristretto_multiply_cost: 2_208,
                curve25519_ristretto_msm_base_cost: 2303,
                curve25519_ristretto_msm_incremental_cost: 788,
                heap_cost: DEFAULT_HEAP_COST,
                mem_op_base_cost: 10,
                alt_bn128_addition_cost: 334,
                alt_bn128_multiplication_cost: 3_840,
                alt_bn128_pairing_one_pair_cost_first: 36_364,
                alt_bn128_pairing_one_pair_cost_other: 12_121,
                big_modular_exponentiation_base_cost: 190,
                big_modular_exponentiation_cost_divisor: 2,
                poseidon_cost_coefficient_a: 61,
                poseidon_cost_coefficient_c: 542,
                get_remaining_compute_units_cost: 100,
                alt_bn128_g1_compress: 30,
                alt_bn128_g1_decompress: 398,
                alt_bn128_g2_compress: 86,
                alt_bn128_g2_decompress: 13610,
            }
        }
        /// Returns cost of the Poseidon hash function for the given number of
        /// inputs is determined by the following quadratic function:
        ///
        /// 61*n^2 + 542
        ///
        /// Which approximates the results of benchmarks of light-posiedon
        /// library[0]. These results assume 1 CU per 33 ns. Examples:
        ///
        /// * 1 input
        ///   * light-poseidon benchmark: `18,303 / 33 ≈ 555`
        ///   * function: `61*1^2 + 542 = 603`
        /// * 2 inputs
        ///   * light-poseidon benchmark: `25,866 / 33 ≈ 784`
        ///   * function: `61*2^2 + 542 = 786`
        /// * 3 inputs
        ///   * light-poseidon benchmark: `37,549 / 33 ≈ 1,138`
        ///   * function; `61*3^2 + 542 = 1091`
        ///
        /// [0] https://github.com/Lightprotocol/light-poseidon#performance
        pub fn poseidon_cost(&self, nr_inputs: u64) -> Option<u64> {
            let squared_inputs = nr_inputs.checked_pow(2)?;
            let mul_result = self
                .poseidon_cost_coefficient_a
                .checked_mul(squared_inputs)?;
            let final_result = mul_result.checked_add(self.poseidon_cost_coefficient_c)?;
            Some(final_result)
        }
    }
    pub struct SVMTransactionExecutionAndFeeBudgetLimits {
        pub budget: SVMTransactionExecutionBudget,
        pub loaded_accounts_data_size_limit: NonZeroU32,
        pub fee_details: FeeDetails,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SVMTransactionExecutionAndFeeBudgetLimits {
        #[inline]
        fn clone(&self) -> SVMTransactionExecutionAndFeeBudgetLimits {
            let _: ::core::clone::AssertParamIsClone<SVMTransactionExecutionBudget>;
            let _: ::core::clone::AssertParamIsClone<NonZeroU32>;
            let _: ::core::clone::AssertParamIsClone<FeeDetails>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for SVMTransactionExecutionAndFeeBudgetLimits {}
    #[automatically_derived]
    impl ::core::fmt::Debug for SVMTransactionExecutionAndFeeBudgetLimits {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "SVMTransactionExecutionAndFeeBudgetLimits",
                "budget",
                &self.budget,
                "loaded_accounts_data_size_limit",
                &self.loaded_accounts_data_size_limit,
                "fee_details",
                &&self.fee_details,
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq
    for SVMTransactionExecutionAndFeeBudgetLimits {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for SVMTransactionExecutionAndFeeBudgetLimits {
        #[inline]
        fn eq(&self, other: &SVMTransactionExecutionAndFeeBudgetLimits) -> bool {
            self.budget == other.budget
                && self.loaded_accounts_data_size_limit
                    == other.loaded_accounts_data_size_limit
                && self.fee_details == other.fee_details
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for SVMTransactionExecutionAndFeeBudgetLimits {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<SVMTransactionExecutionBudget>;
            let _: ::core::cmp::AssertParamIsEq<NonZeroU32>;
            let _: ::core::cmp::AssertParamIsEq<FeeDetails>;
        }
    }
}
pub mod invoke_context {
    use {
        crate::{
            execution_budget::{
                SVMTransactionExecutionBudget, SVMTransactionExecutionCost,
            },
            loaded_programs::{
                ProgramCacheEntry, ProgramCacheEntryType, ProgramCacheForTxBatch,
                ProgramRuntimeEnvironments,
            },
            stable_log, sysvar_cache::SysvarCache,
        },
        solana_account::{create_account_shared_data_for_test, AccountSharedData},
        solana_epoch_schedule::EpochSchedule, solana_hash::Hash,
        solana_instruction::{error::InstructionError, AccountMeta, Instruction},
        solana_pubkey::Pubkey,
        solana_sbpf::{
            ebpf::MM_HEAP_START, elf::Executable as GenericExecutable,
            error::{EbpfError, ProgramResult},
            memory_region::MemoryMapping, program::{BuiltinFunction, SBPFVersion},
            vm::{Config, ContextObject, EbpfVm},
        },
        solana_sdk_ids::{
            bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4,
            native_loader, sysvar,
        },
        solana_svm_callback::InvokeContextCallback,
        solana_svm_feature_set::SVMFeatureSet,
        solana_svm_log_collector::{ic_msg, LogCollector},
        solana_svm_measure::measure::Measure,
        solana_svm_timings::{ExecuteDetailsTimings, ExecuteTimings},
        solana_svm_transaction::{instruction::SVMInstruction, svm_message::SVMMessage},
        solana_svm_type_overrides::sync::Arc,
        solana_transaction_context::{
            instruction::InstructionContext, instruction_accounts::InstructionAccount,
            transaction_accounts::KeyedAccountSharedData, IndexOfAccount,
            TransactionContext, MAX_ACCOUNTS_PER_TRANSACTION,
        },
        std::{
            alloc::Layout, borrow::Cow, cell::RefCell, fmt::{self, Debug},
            rc::Rc,
        },
    };
    pub type BuiltinFunctionWithContext = BuiltinFunction<
        InvokeContext<'static, 'static>,
    >;
    pub type Executable = GenericExecutable<InvokeContext<'static, 'static>>;
    pub type RegisterTrace<'a> = &'a [[u64; 12]];
    impl ContextObject for InvokeContext<'_, '_> {
        fn consume(&mut self, amount: u64) {
            let mut compute_meter = self.compute_meter.borrow_mut();
            *compute_meter = compute_meter.saturating_sub(amount);
        }
        fn get_remaining(&self) -> u64 {
            *self.compute_meter.borrow()
        }
    }
    pub struct AllocErr;
    #[automatically_derived]
    impl ::core::clone::Clone for AllocErr {
        #[inline]
        fn clone(&self) -> AllocErr {
            AllocErr
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for AllocErr {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for AllocErr {
        #[inline]
        fn eq(&self, other: &AllocErr) -> bool {
            true
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for AllocErr {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {}
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for AllocErr {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "AllocErr")
        }
    }
    impl fmt::Display for AllocErr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("Error: Memory allocation failed")
        }
    }
    pub struct BpfAllocator {
        len: u64,
        pos: u64,
    }
    impl BpfAllocator {
        pub fn new(len: u64) -> Self {
            Self { len, pos: 0 }
        }
        pub fn alloc(&mut self, layout: Layout) -> Result<u64, AllocErr> {
            let bytes_to_align = (self.pos as *const u8).align_offset(layout.align())
                as u64;
            if self
                .pos
                .saturating_add(bytes_to_align)
                .saturating_add(layout.size() as u64) <= self.len
            {
                self.pos = self.pos.saturating_add(bytes_to_align);
                let addr = MM_HEAP_START.saturating_add(self.pos);
                self.pos = self.pos.saturating_add(layout.size() as u64);
                Ok(addr)
            } else {
                Err(AllocErr)
            }
        }
    }
    pub struct EnvironmentConfig<'a> {
        pub blockhash: Hash,
        pub blockhash_lamports_per_signature: u64,
        epoch_stake_callback: &'a dyn InvokeContextCallback,
        feature_set: &'a SVMFeatureSet,
        pub program_runtime_environments_for_execution: &'a ProgramRuntimeEnvironments,
        pub program_runtime_environments_for_deployment: &'a ProgramRuntimeEnvironments,
        sysvar_cache: &'a SysvarCache,
    }
    impl<'a> EnvironmentConfig<'a> {
        pub fn new(
            blockhash: Hash,
            blockhash_lamports_per_signature: u64,
            epoch_stake_callback: &'a dyn InvokeContextCallback,
            feature_set: &'a SVMFeatureSet,
            program_runtime_environments_for_execution: &'a ProgramRuntimeEnvironments,
            program_runtime_environments_for_deployment: &'a ProgramRuntimeEnvironments,
            sysvar_cache: &'a SysvarCache,
        ) -> Self {
            Self {
                blockhash,
                blockhash_lamports_per_signature,
                epoch_stake_callback,
                feature_set,
                program_runtime_environments_for_execution,
                program_runtime_environments_for_deployment,
                sysvar_cache,
            }
        }
    }
    pub struct SyscallContext {
        pub allocator: BpfAllocator,
        pub accounts_metadata: Vec<SerializedAccountMetadata>,
    }
    pub struct SerializedAccountMetadata {
        pub original_data_len: usize,
        pub vm_data_addr: u64,
        pub vm_key_addr: u64,
        pub vm_lamports_addr: u64,
        pub vm_owner_addr: u64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SerializedAccountMetadata {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field5_finish(
                f,
                "SerializedAccountMetadata",
                "original_data_len",
                &self.original_data_len,
                "vm_data_addr",
                &self.vm_data_addr,
                "vm_key_addr",
                &self.vm_key_addr,
                "vm_lamports_addr",
                &self.vm_lamports_addr,
                "vm_owner_addr",
                &&self.vm_owner_addr,
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SerializedAccountMetadata {
        #[inline]
        fn clone(&self) -> SerializedAccountMetadata {
            SerializedAccountMetadata {
                original_data_len: ::core::clone::Clone::clone(&self.original_data_len),
                vm_data_addr: ::core::clone::Clone::clone(&self.vm_data_addr),
                vm_key_addr: ::core::clone::Clone::clone(&self.vm_key_addr),
                vm_lamports_addr: ::core::clone::Clone::clone(&self.vm_lamports_addr),
                vm_owner_addr: ::core::clone::Clone::clone(&self.vm_owner_addr),
            }
        }
    }
    /// Main pipeline from runtime to program execution.
    pub struct InvokeContext<'a, 'ix_data> {
        /// Information about the currently executing transaction.
        pub transaction_context: &'a mut TransactionContext<'ix_data>,
        /// The local program cache for the transaction batch.
        pub program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
        /// Runtime configurations used to provision the invocation environment.
        pub environment_config: EnvironmentConfig<'a>,
        /// The compute budget for the current invocation.
        compute_budget: SVMTransactionExecutionBudget,
        /// The compute cost for the current invocation.
        execution_cost: SVMTransactionExecutionCost,
        /// Instruction compute meter, for tracking compute units consumed against
        /// the designated compute budget during program execution.
        compute_meter: RefCell<u64>,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        /// Latest measurement not yet accumulated in [ExecuteDetailsTimings::execute_us]
        pub execute_time: Option<Measure>,
        pub timings: ExecuteDetailsTimings,
        pub syscall_context: Vec<Option<SyscallContext>>,
        /// Pairs of index in TX instruction trace and VM register trace
        register_traces: Vec<(usize, Vec<[u64; 12]>)>,
    }
    impl<'a, 'ix_data> InvokeContext<'a, 'ix_data> {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            transaction_context: &'a mut TransactionContext<'ix_data>,
            program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
            environment_config: EnvironmentConfig<'a>,
            log_collector: Option<Rc<RefCell<LogCollector>>>,
            compute_budget: SVMTransactionExecutionBudget,
            execution_cost: SVMTransactionExecutionCost,
        ) -> Self {
            Self {
                transaction_context,
                program_cache_for_tx_batch,
                environment_config,
                log_collector,
                compute_budget,
                execution_cost,
                compute_meter: RefCell::new(compute_budget.compute_unit_limit),
                execute_time: None,
                timings: ExecuteDetailsTimings::default(),
                syscall_context: Vec::new(),
                register_traces: Vec::new(),
            }
        }
        /// Push a stack frame onto the invocation stack
        pub fn push(&mut self) -> Result<(), InstructionError> {
            let instruction_context = self
                .transaction_context
                .get_instruction_context_at_index_in_trace(
                    self.transaction_context.get_instruction_trace_length(),
                )?;
            let program_id = instruction_context
                .get_program_key()
                .map_err(|_| InstructionError::UnsupportedProgramId)?;
            if self.transaction_context.get_instruction_stack_height() != 0 {
                let contains = (0..self
                    .transaction_context
                    .get_instruction_stack_height())
                    .any(|level| {
                        self.transaction_context
                            .get_instruction_context_at_nesting_level(level)
                            .and_then(|instruction_context| {
                                instruction_context.get_program_key()
                            })
                            .map(|program_key| program_key == program_id)
                            .unwrap_or(false)
                    });
                let is_last = self
                    .transaction_context
                    .get_current_instruction_context()
                    .and_then(|instruction_context| {
                        instruction_context.get_program_key()
                    })
                    .map(|program_key| program_key == program_id)
                    .unwrap_or(false);
                if contains && !is_last {
                    return Err(InstructionError::ReentrancyNotAllowed);
                }
            }
            self.syscall_context.push(None);
            self.transaction_context.push()
        }
        /// Pop a stack frame from the invocation stack
        fn pop(&mut self) -> Result<(), InstructionError> {
            self.syscall_context.pop();
            self.transaction_context.pop()
        }
        /// Current height of the invocation stack, top level instructions are height
        /// `solana_instruction::TRANSACTION_LEVEL_STACK_HEIGHT`
        pub fn get_stack_height(&self) -> usize {
            self.transaction_context.get_instruction_stack_height()
        }
        /// Entrypoint for a cross-program invocation from a builtin program
        pub fn native_invoke(
            &mut self,
            instruction: Instruction,
            signers: &[Pubkey],
        ) -> Result<(), InstructionError> {
            self.prepare_next_instruction(instruction, signers)?;
            let mut compute_units_consumed = 0;
            self.process_instruction(
                &mut compute_units_consumed,
                &mut ExecuteTimings::default(),
            )?;
            Ok(())
        }
        /// Helper to prepare for process_instruction() when the instruction is not a top level one,
        /// and depends on `AccountMeta`s
        pub fn prepare_next_instruction(
            &mut self,
            instruction: Instruction,
            signers: &[Pubkey],
        ) -> Result<(), InstructionError> {
            let mut transaction_callee_map: Vec<u16> = ::alloc::vec::from_elem(
                u16::MAX,
                MAX_ACCOUNTS_PER_TRANSACTION,
            );
            let mut instruction_accounts: Vec<InstructionAccount> = Vec::with_capacity(
                instruction.accounts.len(),
            );
            let program_account_index = {
                let instruction_context = self
                    .transaction_context
                    .get_current_instruction_context()?;
                for account_meta in instruction.accounts.iter() {
                    let index_in_transaction = self
                        .transaction_context
                        .find_index_of_account(&account_meta.pubkey)
                        .ok_or_else(|| {
                            {
                                {
                                    {
                                        let lvl = ::log::Level::Debug;
                                        if lvl <= ::log::STATIC_MAX_LEVEL
                                            && lvl <= ::log::max_level()
                                        {
                                            ::log::__private_api::log(
                                                { ::log::__private_api::GlobalLogger },
                                                format_args!(
                                                    "Instruction references an unknown account {0}",
                                                    account_meta.pubkey,
                                                ),
                                                lvl,
                                                &(
                                                    "solana_runtime::message_processor::stable_log",
                                                    "solana_program_runtime::invoke_context",
                                                    ::log::__private_api::loc(),
                                                ),
                                                (),
                                            );
                                        }
                                    }
                                }
                            };
                            if let Some(log_collector) = self
                                .get_log_collector()
                                .as_ref()
                            {
                                if let Ok(mut log_collector) = log_collector
                                    .try_borrow_mut()
                                {
                                    log_collector
                                        .log(
                                            &::alloc::__export::must_use({
                                                ::alloc::fmt::format(
                                                    format_args!(
                                                        "Instruction references an unknown account {0}",
                                                        account_meta.pubkey,
                                                    ),
                                                )
                                            }),
                                        );
                                }
                            }
                            InstructionError::MissingAccount
                        })?;
                    if true {
                        if !((index_in_transaction as usize)
                            < transaction_callee_map.len())
                        {
                            ::core::panicking::panic(
                                "assertion failed: (index_in_transaction as usize) < transaction_callee_map.len()",
                            )
                        }
                    }
                    let index_in_callee = transaction_callee_map
                        .get_mut(index_in_transaction as usize)
                        .unwrap();
                    if (*index_in_callee as usize) < instruction_accounts.len() {
                        let cloned_account = {
                            let instruction_account = instruction_accounts
                                .get_mut(*index_in_callee as usize)
                                .ok_or(InstructionError::MissingAccount)?;
                            instruction_account
                                .set_is_signer(
                                    instruction_account.is_signer() || account_meta.is_signer,
                                );
                            instruction_account
                                .set_is_writable(
                                    instruction_account.is_writable()
                                        || account_meta.is_writable,
                                );
                            *instruction_account
                        };
                        instruction_accounts.push(cloned_account);
                    } else {
                        *index_in_callee = instruction_accounts.len() as u16;
                        instruction_accounts
                            .push(
                                InstructionAccount::new(
                                    index_in_transaction,
                                    account_meta.is_signer,
                                    account_meta.is_writable,
                                ),
                            );
                    }
                }
                for current_index in 0..instruction_accounts.len() {
                    let instruction_account = instruction_accounts
                        .get(current_index)
                        .unwrap();
                    let index_in_callee = *transaction_callee_map
                        .get(instruction_account.index_in_transaction as usize)
                        .unwrap() as usize;
                    if current_index != index_in_callee {
                        let (is_signer, is_writable) = {
                            let reference_account = instruction_accounts
                                .get(index_in_callee)
                                .ok_or(InstructionError::MissingAccount)?;
                            (
                                reference_account.is_signer(),
                                reference_account.is_writable(),
                            )
                        };
                        let current_account = instruction_accounts
                            .get_mut(current_index)
                            .unwrap();
                        current_account
                            .set_is_signer(current_account.is_signer() || is_signer);
                        current_account
                            .set_is_writable(
                                current_account.is_writable() || is_writable,
                            );
                        continue;
                    }
                    let index_in_caller = instruction_context
                        .get_index_of_account_in_instruction(
                            instruction_account.index_in_transaction,
                        )?;
                    let account_key = &instruction
                        .accounts
                        .get(current_index)
                        .unwrap()
                        .pubkey;
                    let caller_instruction_account = instruction_context
                        .instruction_accounts()
                        .get(index_in_caller as usize)
                        .unwrap();
                    if instruction_account.is_writable()
                        && !caller_instruction_account.is_writable()
                    {
                        {
                            {
                                {
                                    let lvl = ::log::Level::Debug;
                                    if lvl <= ::log::STATIC_MAX_LEVEL
                                        && lvl <= ::log::max_level()
                                    {
                                        ::log::__private_api::log(
                                            { ::log::__private_api::GlobalLogger },
                                            format_args!(
                                                "{0}\'s writable privilege escalated",
                                                account_key,
                                            ),
                                            lvl,
                                            &(
                                                "solana_runtime::message_processor::stable_log",
                                                "solana_program_runtime::invoke_context",
                                                ::log::__private_api::loc(),
                                            ),
                                            (),
                                        );
                                    }
                                }
                            }
                        };
                        if let Some(log_collector) = self.get_log_collector().as_ref() {
                            if let Ok(mut log_collector) = log_collector.try_borrow_mut()
                            {
                                log_collector
                                    .log(
                                        &::alloc::__export::must_use({
                                            ::alloc::fmt::format(
                                                format_args!(
                                                    "{0}\'s writable privilege escalated",
                                                    account_key,
                                                ),
                                            )
                                        }),
                                    );
                            }
                        }
                        return Err(InstructionError::PrivilegeEscalation);
                    }
                    if instruction_account.is_signer()
                        && !(caller_instruction_account.is_signer()
                            || signers.contains(account_key))
                    {
                        {
                            {
                                {
                                    let lvl = ::log::Level::Debug;
                                    if lvl <= ::log::STATIC_MAX_LEVEL
                                        && lvl <= ::log::max_level()
                                    {
                                        ::log::__private_api::log(
                                            { ::log::__private_api::GlobalLogger },
                                            format_args!(
                                                "{0}\'s signer privilege escalated",
                                                account_key,
                                            ),
                                            lvl,
                                            &(
                                                "solana_runtime::message_processor::stable_log",
                                                "solana_program_runtime::invoke_context",
                                                ::log::__private_api::loc(),
                                            ),
                                            (),
                                        );
                                    }
                                }
                            }
                        };
                        if let Some(log_collector) = self.get_log_collector().as_ref() {
                            if let Ok(mut log_collector) = log_collector.try_borrow_mut()
                            {
                                log_collector
                                    .log(
                                        &::alloc::__export::must_use({
                                            ::alloc::fmt::format(
                                                format_args!(
                                                    "{0}\'s signer privilege escalated",
                                                    account_key,
                                                ),
                                            )
                                        }),
                                    );
                            }
                        }
                        return Err(InstructionError::PrivilegeEscalation);
                    }
                }
                let callee_program_id = &instruction.program_id;
                let program_account_index_in_transaction = self
                    .transaction_context
                    .find_index_of_account(callee_program_id);
                let program_account_index_in_instruction = program_account_index_in_transaction
                    .map(|index| {
                        instruction_context.get_index_of_account_in_instruction(index)
                    });
                if program_account_index_in_instruction.is_none()
                    || program_account_index_in_instruction.unwrap().is_err()
                {
                    {
                        {
                            {
                                let lvl = ::log::Level::Debug;
                                if lvl <= ::log::STATIC_MAX_LEVEL
                                    && lvl <= ::log::max_level()
                                {
                                    ::log::__private_api::log(
                                        { ::log::__private_api::GlobalLogger },
                                        format_args!("Unknown program {0}", callee_program_id),
                                        lvl,
                                        &(
                                            "solana_runtime::message_processor::stable_log",
                                            "solana_program_runtime::invoke_context",
                                            ::log::__private_api::loc(),
                                        ),
                                        (),
                                    );
                                }
                            }
                        }
                    };
                    if let Some(log_collector) = self.get_log_collector().as_ref() {
                        if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                            log_collector
                                .log(
                                    &::alloc::__export::must_use({
                                        ::alloc::fmt::format(
                                            format_args!("Unknown program {0}", callee_program_id),
                                        )
                                    }),
                                );
                        }
                    }
                    return Err(InstructionError::MissingAccount);
                }
                program_account_index_in_transaction.unwrap()
            };
            self.transaction_context
                .configure_next_instruction(
                    program_account_index,
                    instruction_accounts,
                    transaction_callee_map,
                    Cow::Owned(instruction.data),
                )?;
            Ok(())
        }
        /// Helper to prepare for process_instruction()/process_precompile() when the instruction is
        /// a top level one
        pub fn prepare_next_top_level_instruction(
            &mut self,
            message: &impl SVMMessage,
            instruction: &SVMInstruction,
            program_account_index: IndexOfAccount,
            data: &'ix_data [u8],
        ) -> Result<(), InstructionError> {
            let mut transaction_callee_map: Vec<u16> = ::alloc::vec::from_elem(
                u16::MAX,
                MAX_ACCOUNTS_PER_TRANSACTION,
            );
            let mut instruction_accounts: Vec<InstructionAccount> = Vec::with_capacity(
                instruction.accounts.len(),
            );
            for index_in_transaction in instruction.accounts.iter() {
                if true {
                    if !((*index_in_transaction as usize) < transaction_callee_map.len())
                    {
                        ::core::panicking::panic(
                            "assertion failed: (*index_in_transaction as usize) < transaction_callee_map.len()",
                        )
                    }
                }
                let index_in_callee = transaction_callee_map
                    .get_mut(*index_in_transaction as usize)
                    .unwrap();
                if (*index_in_callee as usize) > instruction_accounts.len() {
                    *index_in_callee = instruction_accounts.len() as u16;
                }
                let index_in_transaction = *index_in_transaction as usize;
                instruction_accounts
                    .push(
                        InstructionAccount::new(
                            index_in_transaction as IndexOfAccount,
                            message.is_signer(index_in_transaction),
                            message.is_writable(index_in_transaction),
                        ),
                    );
            }
            self.transaction_context
                .configure_next_instruction(
                    program_account_index,
                    instruction_accounts,
                    transaction_callee_map,
                    Cow::Borrowed(data),
                )?;
            Ok(())
        }
        /// Processes an instruction and returns how many compute units were used
        pub fn process_instruction(
            &mut self,
            compute_units_consumed: &mut u64,
            timings: &mut ExecuteTimings,
        ) -> Result<(), InstructionError> {
            *compute_units_consumed = 0;
            self.push()?;
            self.process_executable_chain(compute_units_consumed, timings)
                .and(self.pop())
        }
        /// Processes a precompile instruction
        pub fn process_precompile(
            &mut self,
            program_id: &Pubkey,
            instruction_data: &[u8],
            message_instruction_datas_iter: impl Iterator<Item = &'ix_data [u8]>,
        ) -> Result<(), InstructionError> {
            self.push()?;
            let instruction_datas: Vec<_> = message_instruction_datas_iter.collect();
            self.environment_config
                .epoch_stake_callback
                .process_precompile(program_id, instruction_data, instruction_datas)
                .map_err(InstructionError::from)
                .and(self.pop())
        }
        /// Calls the instruction's program entrypoint method
        fn process_executable_chain(
            &mut self,
            compute_units_consumed: &mut u64,
            timings: &mut ExecuteTimings,
        ) -> Result<(), InstructionError> {
            let instruction_context = self
                .transaction_context
                .get_current_instruction_context()?;
            let process_executable_chain_time = Measure::start(
                "process_executable_chain_time",
            );
            let builtin_id = {
                let owner_id = instruction_context.get_program_owner()?;
                if native_loader::check_id(&owner_id) {
                    *instruction_context.get_program_key()?
                } else if bpf_loader_deprecated::check_id(&owner_id)
                    || bpf_loader::check_id(&owner_id)
                    || bpf_loader_upgradeable::check_id(&owner_id)
                    || loader_v4::check_id(&owner_id)
                {
                    owner_id
                } else {
                    return Err(InstructionError::UnsupportedProgramId);
                }
            };
            const ENTRYPOINT_KEY: u32 = 0x71E3CF81;
            let entry = self
                .program_cache_for_tx_batch
                .find(&builtin_id)
                .ok_or(InstructionError::UnsupportedProgramId)?;
            let function = match &entry.program {
                ProgramCacheEntryType::Builtin(program) => {
                    program
                        .get_function_registry()
                        .lookup_by_key(ENTRYPOINT_KEY)
                        .map(|(_name, function)| function)
                }
                _ => None,
            }
                .ok_or(InstructionError::UnsupportedProgramId)?;
            let program_id = *instruction_context.get_program_key()?;
            self.transaction_context.set_return_data(program_id, Vec::new())?;
            let logger = self.get_log_collector();
            stable_log::program_invoke(&logger, &program_id, self.get_stack_height());
            let pre_remaining_units = self.get_remaining();
            let mock_config = Config::default();
            let empty_memory_mapping = MemoryMapping::new(
                    Vec::new(),
                    &mock_config,
                    SBPFVersion::V0,
                )
                .unwrap();
            let mut vm = EbpfVm::new(
                self
                    .environment_config
                    .program_runtime_environments_for_execution
                    .program_runtime_v2
                    .clone(),
                SBPFVersion::V0,
                unsafe {
                    std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(self)
                },
                empty_memory_mapping,
                0,
            );
            vm.invoke_function(function);
            let result = match vm.program_result {
                ProgramResult::Ok(_) => {
                    stable_log::program_success(&logger, &program_id);
                    Ok(())
                }
                ProgramResult::Err(ref err) => {
                    if let EbpfError::SyscallError(syscall_error) = err {
                        if let Some(instruction_err) = syscall_error
                            .downcast_ref::<InstructionError>()
                        {
                            stable_log::program_failure(
                                &logger,
                                &program_id,
                                instruction_err,
                            );
                            Err(instruction_err.clone())
                        } else {
                            stable_log::program_failure(
                                &logger,
                                &program_id,
                                syscall_error,
                            );
                            Err(InstructionError::ProgramFailedToComplete)
                        }
                    } else {
                        stable_log::program_failure(&logger, &program_id, err);
                        Err(InstructionError::ProgramFailedToComplete)
                    }
                }
            };
            let post_remaining_units = self.get_remaining();
            *compute_units_consumed = pre_remaining_units
                .saturating_sub(post_remaining_units);
            if builtin_id == program_id && result.is_ok() && *compute_units_consumed == 0
            {
                return Err(InstructionError::BuiltinProgramsMustConsumeComputeUnits);
            }
            timings.execute_accessories.process_instructions.process_executable_chain_us
                += process_executable_chain_time.end_as_us();
            result
        }
        /// Get this invocation's LogCollector
        pub fn get_log_collector(&self) -> Option<Rc<RefCell<LogCollector>>> {
            self.log_collector.clone()
        }
        /// Consume compute units
        pub fn consume_checked(
            &self,
            amount: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut compute_meter = self.compute_meter.borrow_mut();
            let exceeded = *compute_meter < amount;
            *compute_meter = compute_meter.saturating_sub(amount);
            if exceeded {
                return Err(Box::new(InstructionError::ComputationalBudgetExceeded));
            }
            Ok(())
        }
        /// Set compute units
        ///
        /// Only use for tests and benchmarks
        pub fn mock_set_remaining(&self, remaining: u64) {
            *self.compute_meter.borrow_mut() = remaining;
        }
        /// Get this invocation's compute budget
        pub fn get_compute_budget(&self) -> &SVMTransactionExecutionBudget {
            &self.compute_budget
        }
        /// Get this invocation's compute budget
        pub fn get_execution_cost(&self) -> &SVMTransactionExecutionCost {
            &self.execution_cost
        }
        /// Get the current feature set.
        pub fn get_feature_set(&self) -> &SVMFeatureSet {
            self.environment_config.feature_set
        }
        pub fn get_program_runtime_environments_for_deployment(
            &self,
        ) -> &ProgramRuntimeEnvironments {
            self.environment_config.program_runtime_environments_for_deployment
        }
        pub fn is_stake_raise_minimum_delegation_to_1_sol_active(&self) -> bool {
            self.environment_config.feature_set.stake_raise_minimum_delegation_to_1_sol
        }
        pub fn is_deprecate_legacy_vote_ixs_active(&self) -> bool {
            self.environment_config.feature_set.deprecate_legacy_vote_ixs
        }
        /// Get cached sysvars
        pub fn get_sysvar_cache(&self) -> &SysvarCache {
            self.environment_config.sysvar_cache
        }
        /// Get cached epoch total stake.
        pub fn get_epoch_stake(&self) -> u64 {
            self.environment_config.epoch_stake_callback.get_epoch_stake()
        }
        /// Get cached stake for the epoch vote account.
        pub fn get_epoch_stake_for_vote_account(&self, pubkey: &'a Pubkey) -> u64 {
            self.environment_config
                .epoch_stake_callback
                .get_epoch_stake_for_vote_account(pubkey)
        }
        pub fn is_precompile(&self, pubkey: &Pubkey) -> bool {
            self.environment_config.epoch_stake_callback.is_precompile(pubkey)
        }
        pub fn get_check_aligned(&self) -> bool {
            self.transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| {
                    let owner_id = instruction_context.get_program_owner();
                    if true {
                        if !owner_id.is_ok() {
                            ::core::panicking::panic(
                                "assertion failed: owner_id.is_ok()",
                            )
                        }
                    }
                    owner_id
                })
                .map(|owner_key| owner_key != bpf_loader_deprecated::id())
                .unwrap_or(true)
        }
        pub fn set_syscall_context(
            &mut self,
            syscall_context: SyscallContext,
        ) -> Result<(), InstructionError> {
            *self.syscall_context.last_mut().ok_or(InstructionError::CallDepth)? = Some(
                syscall_context,
            );
            Ok(())
        }
        pub fn get_syscall_context(&self) -> Result<&SyscallContext, InstructionError> {
            self.syscall_context
                .last()
                .and_then(std::option::Option::as_ref)
                .ok_or(InstructionError::CallDepth)
        }
        pub fn get_syscall_context_mut(
            &mut self,
        ) -> Result<&mut SyscallContext, InstructionError> {
            self.syscall_context
                .last_mut()
                .and_then(|syscall_context| syscall_context.as_mut())
                .ok_or(InstructionError::CallDepth)
        }
        /// Insert a VM register trace
        pub fn insert_register_trace(&mut self, register_trace: Vec<[u64; 12]>) {
            if register_trace.is_empty() {
                return;
            }
            let Ok(instruction_context) = self
                .transaction_context
                .get_current_instruction_context() else {
                return;
            };
            self.register_traces
                .push((instruction_context.get_index_in_trace(), register_trace));
        }
        /// Iterates over all VM register traces (including CPI)
        pub fn iterate_vm_traces(
            &self,
            callback: &dyn Fn(InstructionContext, &Executable, RegisterTrace),
        ) {
            for (index_in_trace, register_trace) in &self.register_traces {
                let Ok(instruction_context) = self
                    .transaction_context
                    .get_instruction_context_at_index_in_trace(*index_in_trace) else {
                    continue;
                };
                let Ok(program_id) = instruction_context.get_program_key() else {
                    continue;
                };
                let Some(entry) = self.program_cache_for_tx_batch.find(program_id) else {
                    continue;
                };
                let ProgramCacheEntryType::Loaded(ref executable) = entry.program else {
                    continue;
                };
                callback(instruction_context, executable, register_trace.as_slice());
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn mock_process_instruction_with_feature_set<
        F: FnMut(&mut InvokeContext),
        G: FnMut(&mut InvokeContext),
    >(
        loader_id: &Pubkey,
        program_index: Option<IndexOfAccount>,
        instruction_data: &[u8],
        mut transaction_accounts: Vec<KeyedAccountSharedData>,
        instruction_account_metas: Vec<AccountMeta>,
        expected_result: Result<(), InstructionError>,
        builtin_function: BuiltinFunctionWithContext,
        mut pre_adjustments: F,
        mut post_adjustments: G,
        feature_set: &SVMFeatureSet,
    ) -> Vec<AccountSharedData> {
        let mut instruction_accounts: Vec<InstructionAccount> = Vec::with_capacity(
            instruction_account_metas.len(),
        );
        for account_meta in instruction_account_metas.iter() {
            let index_in_transaction = transaction_accounts
                .iter()
                .position(|(key, _account)| *key == account_meta.pubkey)
                .unwrap_or(transaction_accounts.len()) as IndexOfAccount;
            instruction_accounts
                .push(
                    InstructionAccount::new(
                        index_in_transaction,
                        account_meta.is_signer,
                        account_meta.is_writable,
                    ),
                );
        }
        let program_index = if let Some(index) = program_index {
            index
        } else {
            let processor_account = AccountSharedData::new(0, 0, &native_loader::id());
            transaction_accounts.push((*loader_id, processor_account));
            transaction_accounts.len().saturating_sub(1) as IndexOfAccount
        };
        let pop_epoch_schedule_account = if !transaction_accounts
            .iter()
            .any(|(key, _)| *key == sysvar::epoch_schedule::id())
        {
            transaction_accounts
                .push((
                    sysvar::epoch_schedule::id(),
                    create_account_shared_data_for_test(&EpochSchedule::default()),
                ));
            true
        } else {
            false
        };
        use {
            solana_svm_callback::InvokeContextCallback,
            solana_svm_log_collector::LogCollector,
            crate::{
                __private::{Hash, ReadableAccount, Rent, TransactionContext},
                execution_budget::{
                    SVMTransactionExecutionBudget, SVMTransactionExecutionCost,
                },
                invoke_context::{EnvironmentConfig, InvokeContext},
                loaded_programs::{ProgramCacheForTxBatch, ProgramRuntimeEnvironments},
                sysvar_cache::SysvarCache,
            },
        };
        struct MockInvokeContextCallback {}
        impl InvokeContextCallback for MockInvokeContextCallback {}
        let compute_budget = SVMTransactionExecutionBudget::new_with_defaults(
            feature_set.raise_cpi_nesting_limit_to_8,
        );
        let mut transaction_context = TransactionContext::new(
            transaction_accounts,
            Rent::default(),
            compute_budget.max_instruction_stack_depth,
            compute_budget.max_instruction_trace_length,
        );
        let mut sysvar_cache = SysvarCache::default();
        sysvar_cache
            .fill_missing_entries(|pubkey, callback| {
                for index in 0..transaction_context.get_number_of_accounts() {
                    if transaction_context.get_key_of_account_at_index(index).unwrap()
                        == pubkey
                    {
                        callback(
                            transaction_context
                                .accounts()
                                .try_borrow(index)
                                .unwrap()
                                .data(),
                        );
                    }
                }
            });
        let program_runtime_environments = ProgramRuntimeEnvironments::default();
        let environment_config = EnvironmentConfig::new(
            Hash::default(),
            0,
            &MockInvokeContextCallback {},
            feature_set,
            &program_runtime_environments,
            &program_runtime_environments,
            &sysvar_cache,
        );
        let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            &mut program_cache_for_tx_batch,
            environment_config,
            Some(LogCollector::new_ref()),
            compute_budget,
            SVMTransactionExecutionCost::new_with_defaults(
                feature_set.increase_cpi_account_info_limit,
            ),
        );
        let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
        program_cache_for_tx_batch
            .replenish(
                *loader_id,
                Arc::new(ProgramCacheEntry::new_builtin(0, 0, builtin_function)),
            );
        program_cache_for_tx_batch
            .set_slot_for_tests(
                invoke_context
                    .get_sysvar_cache()
                    .get_clock()
                    .map(|clock| clock.slot)
                    .unwrap_or(1),
            );
        invoke_context.program_cache_for_tx_batch = &mut program_cache_for_tx_batch;
        pre_adjustments(&mut invoke_context);
        invoke_context
            .transaction_context
            .configure_next_instruction_for_tests(
                program_index,
                instruction_accounts,
                instruction_data.to_vec(),
            )
            .unwrap();
        let result = invoke_context
            .process_instruction(&mut 0, &mut ExecuteTimings::default());
        match (&result, &expected_result) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    let kind = ::core::panicking::AssertKind::Eq;
                    ::core::panicking::assert_failed(
                        kind,
                        &*left_val,
                        &*right_val,
                        ::core::option::Option::None,
                    );
                }
            }
        };
        post_adjustments(&mut invoke_context);
        let mut transaction_accounts = transaction_context
            .deconstruct_without_keys()
            .unwrap();
        if pop_epoch_schedule_account {
            transaction_accounts.pop();
        }
        transaction_accounts.pop();
        transaction_accounts
    }
    pub fn mock_process_instruction<
        F: FnMut(&mut InvokeContext),
        G: FnMut(&mut InvokeContext),
    >(
        loader_id: &Pubkey,
        program_index: Option<IndexOfAccount>,
        instruction_data: &[u8],
        transaction_accounts: Vec<KeyedAccountSharedData>,
        instruction_account_metas: Vec<AccountMeta>,
        expected_result: Result<(), InstructionError>,
        builtin_function: BuiltinFunctionWithContext,
        pre_adjustments: F,
        post_adjustments: G,
    ) -> Vec<AccountSharedData> {
        mock_process_instruction_with_feature_set(
            loader_id,
            program_index,
            instruction_data,
            transaction_accounts,
            instruction_account_metas,
            expected_result,
            builtin_function,
            pre_adjustments,
            post_adjustments,
            &SVMFeatureSet::all_enabled(),
        )
    }
}
pub mod loaded_programs {
    use {
        crate::invoke_context::{BuiltinFunctionWithContext, InvokeContext},
        log::{debug, error, log_enabled, trace},
        percentage::PercentageInteger, solana_clock::{Epoch, Slot},
        solana_pubkey::Pubkey,
        solana_sbpf::{
            elf::Executable, program::BuiltinProgram, verifier::RequisiteVerifier,
            vm::Config,
        },
        solana_sdk_ids::{
            bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4,
            native_loader,
        },
        solana_svm_type_overrides::{
            rand::{rng, Rng},
            sync::{
                atomic::{AtomicU64, Ordering},
                Arc, Condvar, Mutex, RwLock,
            },
            thread,
        },
        std::{
            collections::{hash_map::Entry, HashMap},
            fmt::{Debug, Formatter},
            sync::Weak,
        },
    };
    pub type ProgramRuntimeEnvironment = Arc<
        BuiltinProgram<InvokeContext<'static, 'static>>,
    >;
    pub const MAX_LOADED_ENTRY_COUNT: usize = 512;
    pub const DELAY_VISIBILITY_SLOT_OFFSET: Slot = 1;
    /// Relationship between two fork IDs
    pub enum BlockRelation {
        /// The slot is on the same fork and is an ancestor of the other slot
        Ancestor,
        /// The two slots are equal and are on the same fork
        Equal,
        /// The slot is on the same fork and is a descendant of the other slot
        Descendant,
        /// The slots are on two different forks and may have had a common ancestor at some point
        Unrelated,
        /// Either one or both of the slots are either older than the latest root, or are in future
        Unknown,
    }
    #[automatically_derived]
    impl ::core::marker::Copy for BlockRelation {}
    #[automatically_derived]
    impl ::core::clone::Clone for BlockRelation {
        #[inline]
        fn clone(&self) -> BlockRelation {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for BlockRelation {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(
                f,
                match self {
                    BlockRelation::Ancestor => "Ancestor",
                    BlockRelation::Equal => "Equal",
                    BlockRelation::Descendant => "Descendant",
                    BlockRelation::Unrelated => "Unrelated",
                    BlockRelation::Unknown => "Unknown",
                },
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for BlockRelation {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for BlockRelation {
        #[inline]
        fn eq(&self, other: &BlockRelation) -> bool {
            let __self_discr = ::core::intrinsics::discriminant_value(self);
            let __arg1_discr = ::core::intrinsics::discriminant_value(other);
            __self_discr == __arg1_discr
        }
    }
    /// Maps relationship between two slots.
    pub trait ForkGraph {
        /// Returns the BlockRelation of A to B
        fn relationship(&self, a: Slot, b: Slot) -> BlockRelation;
    }
    /// The owner of a programs accounts, thus the loader of a program
    pub enum ProgramCacheEntryOwner {
        #[default]
        NativeLoader,
        LoaderV1,
        LoaderV2,
        LoaderV3,
        LoaderV4,
    }
    #[automatically_derived]
    impl ::core::default::Default for ProgramCacheEntryOwner {
        #[inline]
        fn default() -> ProgramCacheEntryOwner {
            Self::NativeLoader
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ProgramCacheEntryOwner {
        #[inline]
        fn clone(&self) -> ProgramCacheEntryOwner {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for ProgramCacheEntryOwner {}
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for ProgramCacheEntryOwner {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for ProgramCacheEntryOwner {
        #[inline]
        fn eq(&self, other: &ProgramCacheEntryOwner) -> bool {
            let __self_discr = ::core::intrinsics::discriminant_value(self);
            let __arg1_discr = ::core::intrinsics::discriminant_value(other);
            __self_discr == __arg1_discr
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for ProgramCacheEntryOwner {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {}
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProgramCacheEntryOwner {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(
                f,
                match self {
                    ProgramCacheEntryOwner::NativeLoader => "NativeLoader",
                    ProgramCacheEntryOwner::LoaderV1 => "LoaderV1",
                    ProgramCacheEntryOwner::LoaderV2 => "LoaderV2",
                    ProgramCacheEntryOwner::LoaderV3 => "LoaderV3",
                    ProgramCacheEntryOwner::LoaderV4 => "LoaderV4",
                },
            )
        }
    }
    impl TryFrom<&Pubkey> for ProgramCacheEntryOwner {
        type Error = ();
        fn try_from(loader_key: &Pubkey) -> Result<Self, ()> {
            if native_loader::check_id(loader_key) {
                Ok(ProgramCacheEntryOwner::NativeLoader)
            } else if bpf_loader_deprecated::check_id(loader_key) {
                Ok(ProgramCacheEntryOwner::LoaderV1)
            } else if bpf_loader::check_id(loader_key) {
                Ok(ProgramCacheEntryOwner::LoaderV2)
            } else if bpf_loader_upgradeable::check_id(loader_key) {
                Ok(ProgramCacheEntryOwner::LoaderV3)
            } else if loader_v4::check_id(loader_key) {
                Ok(ProgramCacheEntryOwner::LoaderV4)
            } else {
                Err(())
            }
        }
    }
    impl From<ProgramCacheEntryOwner> for Pubkey {
        fn from(program_cache_entry_owner: ProgramCacheEntryOwner) -> Self {
            match program_cache_entry_owner {
                ProgramCacheEntryOwner::NativeLoader => native_loader::id(),
                ProgramCacheEntryOwner::LoaderV1 => bpf_loader_deprecated::id(),
                ProgramCacheEntryOwner::LoaderV2 => bpf_loader::id(),
                ProgramCacheEntryOwner::LoaderV3 => bpf_loader_upgradeable::id(),
                ProgramCacheEntryOwner::LoaderV4 => loader_v4::id(),
            }
        }
    }
    /// Actual payload of [ProgramCacheEntry].
    pub enum ProgramCacheEntryType {
        /// Tombstone for programs which currently do not pass the verifier but could if the feature set changed.
        FailedVerification(ProgramRuntimeEnvironment),
        /// Tombstone for programs that were either explicitly closed or never deployed.
        ///
        /// It's also used for accounts belonging to program loaders, that don't actually contain program code (e.g. buffer accounts for LoaderV3 programs).
        #[default]
        Closed,
        /// Tombstone for programs which have recently been modified but the new version is not visible yet.
        DelayVisibility,
        /// Successfully verified but not currently compiled.
        ///
        /// It continues to track usage statistics even when the compiled executable of the program is evicted from memory.
        Unloaded(ProgramRuntimeEnvironment),
        /// Verified and compiled program
        Loaded(Executable<InvokeContext<'static, 'static>>),
        /// A built-in program which is not stored on-chain but backed into and distributed with the validator
        Builtin(BuiltinProgram<InvokeContext<'static, 'static>>),
    }
    #[automatically_derived]
    impl ::core::default::Default for ProgramCacheEntryType {
        #[inline]
        fn default() -> ProgramCacheEntryType {
            Self::Closed
        }
    }
    impl Debug for ProgramCacheEntryType {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                ProgramCacheEntryType::FailedVerification(_) => {
                    f.write_fmt(
                        format_args!("ProgramCacheEntryType::FailedVerification"),
                    )
                }
                ProgramCacheEntryType::Closed => {
                    f.write_fmt(format_args!("ProgramCacheEntryType::Closed"))
                }
                ProgramCacheEntryType::DelayVisibility => {
                    f.write_fmt(format_args!("ProgramCacheEntryType::DelayVisibility"))
                }
                ProgramCacheEntryType::Unloaded(_) => {
                    f.write_fmt(format_args!("ProgramCacheEntryType::Unloaded"))
                }
                ProgramCacheEntryType::Loaded(_) => {
                    f.write_fmt(format_args!("ProgramCacheEntryType::Loaded"))
                }
                ProgramCacheEntryType::Builtin(_) => {
                    f.write_fmt(format_args!("ProgramCacheEntryType::Builtin"))
                }
            }
        }
    }
    impl ProgramCacheEntryType {
        /// Returns a reference to its environment if it has one
        pub fn get_environment(&self) -> Option<&ProgramRuntimeEnvironment> {
            match self {
                ProgramCacheEntryType::Loaded(program) => Some(program.get_loader()),
                ProgramCacheEntryType::FailedVerification(env)
                | ProgramCacheEntryType::Unloaded(env) => Some(env),
                _ => None,
            }
        }
    }
    /// Holds a program version at a specific address and on a specific slot / fork.
    ///
    /// It contains the actual program in [ProgramCacheEntryType] and a bunch of meta-data.
    pub struct ProgramCacheEntry {
        /// The program of this entry
        pub program: ProgramCacheEntryType,
        /// The loader of this entry
        pub account_owner: ProgramCacheEntryOwner,
        /// Size of account that stores the program and program data
        pub account_size: usize,
        /// Slot in which the program was (re)deployed
        pub deployment_slot: Slot,
        /// Slot in which this entry will become active (can be in the future)
        pub effective_slot: Slot,
        /// How often this entry was used by a transaction
        pub tx_usage_counter: Arc<AtomicU64>,
        /// Latest slot in which the entry was used
        pub latest_access_slot: AtomicU64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProgramCacheEntry {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "program",
                "account_owner",
                "account_size",
                "deployment_slot",
                "effective_slot",
                "tx_usage_counter",
                "latest_access_slot",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.program,
                &self.account_owner,
                &self.account_size,
                &self.deployment_slot,
                &self.effective_slot,
                &self.tx_usage_counter,
                &&self.latest_access_slot,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "ProgramCacheEntry",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for ProgramCacheEntry {
        #[inline]
        fn default() -> ProgramCacheEntry {
            ProgramCacheEntry {
                program: ::core::default::Default::default(),
                account_owner: ::core::default::Default::default(),
                account_size: ::core::default::Default::default(),
                deployment_slot: ::core::default::Default::default(),
                effective_slot: ::core::default::Default::default(),
                tx_usage_counter: ::core::default::Default::default(),
                latest_access_slot: ::core::default::Default::default(),
            }
        }
    }
    /// Global cache statistics for [ProgramCache].
    pub struct ProgramCacheStats {
        /// a program was already in the cache
        pub hits: AtomicU64,
        /// a program was not found and loaded instead
        pub misses: AtomicU64,
        /// a compiled executable was unloaded
        pub evictions: HashMap<Pubkey, u64>,
        /// an unloaded program was loaded again (opposite of eviction)
        pub reloads: AtomicU64,
        /// a program was loaded or un/re/deployed
        pub insertions: AtomicU64,
        /// a program was loaded but can not be extracted on its own fork anymore
        pub lost_insertions: AtomicU64,
        /// a program which was already in the cache was reloaded by mistake
        pub replacements: AtomicU64,
        /// a program was only used once before being unloaded
        pub one_hit_wonders: AtomicU64,
        /// a program became unreachable in the fork graph because of rerooting
        pub prunes_orphan: AtomicU64,
        /// a program got pruned because it was not recompiled for the next epoch
        pub prunes_environment: AtomicU64,
        /// a program had no entries because all slot versions got pruned
        pub empty_entries: AtomicU64,
        /// water level of loaded entries currently cached
        pub water_level: AtomicU64,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProgramCacheStats {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "hits",
                "misses",
                "evictions",
                "reloads",
                "insertions",
                "lost_insertions",
                "replacements",
                "one_hit_wonders",
                "prunes_orphan",
                "prunes_environment",
                "empty_entries",
                "water_level",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.hits,
                &self.misses,
                &self.evictions,
                &self.reloads,
                &self.insertions,
                &self.lost_insertions,
                &self.replacements,
                &self.one_hit_wonders,
                &self.prunes_orphan,
                &self.prunes_environment,
                &self.empty_entries,
                &&self.water_level,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "ProgramCacheStats",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for ProgramCacheStats {
        #[inline]
        fn default() -> ProgramCacheStats {
            ProgramCacheStats {
                hits: ::core::default::Default::default(),
                misses: ::core::default::Default::default(),
                evictions: ::core::default::Default::default(),
                reloads: ::core::default::Default::default(),
                insertions: ::core::default::Default::default(),
                lost_insertions: ::core::default::Default::default(),
                replacements: ::core::default::Default::default(),
                one_hit_wonders: ::core::default::Default::default(),
                prunes_orphan: ::core::default::Default::default(),
                prunes_environment: ::core::default::Default::default(),
                empty_entries: ::core::default::Default::default(),
                water_level: ::core::default::Default::default(),
            }
        }
    }
    impl ProgramCacheStats {
        pub fn reset(&mut self) {
            *self = ProgramCacheStats::default();
        }
        pub fn log(&self) {
            let hits = self.hits.load(Ordering::Relaxed);
            let misses = self.misses.load(Ordering::Relaxed);
            let evictions: u64 = self.evictions.values().sum();
            let reloads = self.reloads.load(Ordering::Relaxed);
            let insertions = self.insertions.load(Ordering::Relaxed);
            let lost_insertions = self.lost_insertions.load(Ordering::Relaxed);
            let replacements = self.replacements.load(Ordering::Relaxed);
            let one_hit_wonders = self.one_hit_wonders.load(Ordering::Relaxed);
            let prunes_orphan = self.prunes_orphan.load(Ordering::Relaxed);
            let prunes_environment = self.prunes_environment.load(Ordering::Relaxed);
            let empty_entries = self.empty_entries.load(Ordering::Relaxed);
            let water_level = self.water_level.load(Ordering::Relaxed);
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!(
                                "Loaded Programs Cache Stats -- Hits: {0}, Misses: {1}, Evictions: {2}, Reloads: {3}, Insertions: {4}, Lost-Insertions: {5}, Replacements: {6}, One-Hit-Wonders: {7}, Prunes-Orphan: {8}, Prunes-Environment: {9}, Empty: {10}, Water-Level: {11}",
                                hits,
                                misses,
                                evictions,
                                reloads,
                                insertions,
                                lost_insertions,
                                replacements,
                                one_hit_wonders,
                                prunes_orphan,
                                prunes_environment,
                                empty_entries,
                                water_level,
                            ),
                            lvl,
                            &(
                                "solana_program_runtime::loaded_programs",
                                "solana_program_runtime::loaded_programs",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            };
            if {
                {
                    let lvl = log::Level::Trace;
                    lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level()
                        && ::log::__private_api::enabled(
                            { ::log::__private_api::GlobalLogger },
                            lvl,
                            "solana_program_runtime::loaded_programs",
                        )
                }
            } && !self.evictions.is_empty()
            {
                let mut evictions = self.evictions.iter().collect::<Vec<_>>();
                evictions.sort_by_key(|e| e.1);
                let evictions = evictions
                    .into_iter()
                    .rev()
                    .map(|(program_id, evictions)| {
                        ::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!(
                                    "  {0:<44}  {1}",
                                    program_id.to_string(),
                                    evictions,
                                ),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let evictions = evictions.join("\n");
                {
                    {
                        let lvl = ::log::Level::Trace;
                        if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                            ::log::__private_api::log(
                                { ::log::__private_api::GlobalLogger },
                                format_args!(
                                    "Eviction Details:\n  {0:<44}  {1}\n{2}",
                                    "Program",
                                    "Count",
                                    evictions,
                                ),
                                lvl,
                                &(
                                    "solana_program_runtime::loaded_programs",
                                    "solana_program_runtime::loaded_programs",
                                    ::log::__private_api::loc(),
                                ),
                                (),
                            );
                        }
                    }
                };
            }
        }
    }
    impl PartialEq for ProgramCacheEntry {
        fn eq(&self, other: &Self) -> bool {
            self.effective_slot == other.effective_slot
                && self.deployment_slot == other.deployment_slot
                && self.is_tombstone() == other.is_tombstone()
        }
    }
    impl ProgramCacheEntry {
        /// Creates a new user program
        pub fn new(
            loader_key: &Pubkey,
            program_runtime_environment: ProgramRuntimeEnvironment,
            deployment_slot: Slot,
            effective_slot: Slot,
            elf_bytes: &[u8],
            account_size: usize,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Self::new_internal(
                loader_key,
                program_runtime_environment,
                deployment_slot,
                effective_slot,
                elf_bytes,
                account_size,
                false,
            )
        }
        /// Reloads a user program, *without* running the verifier.
        ///
        /// # Safety
        ///
        /// This method is unsafe since it assumes that the program has already been verified. Should
        /// only be called when the program was previously verified and loaded in the cache, but was
        /// unloaded due to inactivity. It should also be checked that the `program_runtime_environment`
        /// hasn't changed since it was unloaded.
        pub unsafe fn reload(
            loader_key: &Pubkey,
            program_runtime_environment: Arc<
                BuiltinProgram<InvokeContext<'static, 'static>>,
            >,
            deployment_slot: Slot,
            effective_slot: Slot,
            elf_bytes: &[u8],
            account_size: usize,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Self::new_internal(
                loader_key,
                program_runtime_environment,
                deployment_slot,
                effective_slot,
                elf_bytes,
                account_size,
                true,
            )
        }
        fn new_internal(
            loader_key: &Pubkey,
            program_runtime_environment: Arc<
                BuiltinProgram<InvokeContext<'static, 'static>>,
            >,
            deployment_slot: Slot,
            effective_slot: Slot,
            elf_bytes: &[u8],
            account_size: usize,
            reloading: bool,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            #[allow(unused_mut)]
            let mut executable = Executable::load(
                elf_bytes,
                program_runtime_environment.clone(),
            )?;
            if !reloading {
                executable.verify::<RequisiteVerifier>()?;
            }
            Ok(Self {
                deployment_slot,
                account_owner: ProgramCacheEntryOwner::try_from(loader_key).unwrap(),
                account_size,
                effective_slot,
                tx_usage_counter: Arc::<AtomicU64>::default(),
                program: ProgramCacheEntryType::Loaded(executable),
                latest_access_slot: AtomicU64::new(0),
            })
        }
        pub fn to_unloaded(&self) -> Option<Self> {
            match &self.program {
                ProgramCacheEntryType::Loaded(_) => {}
                ProgramCacheEntryType::FailedVerification(_)
                | ProgramCacheEntryType::Closed
                | ProgramCacheEntryType::DelayVisibility
                | ProgramCacheEntryType::Unloaded(_)
                | ProgramCacheEntryType::Builtin(_) => {
                    return None;
                }
            }
            Some(Self {
                program: ProgramCacheEntryType::Unloaded(
                    self.program.get_environment()?.clone(),
                ),
                account_owner: self.account_owner,
                account_size: self.account_size,
                deployment_slot: self.deployment_slot,
                effective_slot: self.effective_slot,
                tx_usage_counter: self.tx_usage_counter.clone(),
                latest_access_slot: AtomicU64::new(
                    self.latest_access_slot.load(Ordering::Relaxed),
                ),
            })
        }
        /// Creates a new built-in program
        pub fn new_builtin(
            deployment_slot: Slot,
            account_size: usize,
            builtin_function: BuiltinFunctionWithContext,
        ) -> Self {
            let mut program = BuiltinProgram::new_builtin();
            program.register_function("entrypoint", builtin_function).unwrap();
            Self {
                deployment_slot,
                account_owner: ProgramCacheEntryOwner::NativeLoader,
                account_size,
                effective_slot: deployment_slot,
                tx_usage_counter: Arc::<AtomicU64>::default(),
                program: ProgramCacheEntryType::Builtin(program),
                latest_access_slot: AtomicU64::new(0),
            }
        }
        pub fn new_tombstone(
            slot: Slot,
            account_owner: ProgramCacheEntryOwner,
            reason: ProgramCacheEntryType,
        ) -> Self {
            Self::new_tombstone_with_usage_counter(
                slot,
                account_owner,
                reason,
                Arc::<AtomicU64>::default(),
            )
        }
        pub fn new_tombstone_with_usage_counter(
            slot: Slot,
            account_owner: ProgramCacheEntryOwner,
            reason: ProgramCacheEntryType,
            tx_usage_counter: Arc<AtomicU64>,
        ) -> Self {
            let tombstone = Self {
                program: reason,
                account_owner,
                account_size: 0,
                deployment_slot: slot,
                effective_slot: slot,
                tx_usage_counter,
                latest_access_slot: AtomicU64::new(0),
            };
            if true {
                if !tombstone.is_tombstone() {
                    ::core::panicking::panic(
                        "assertion failed: tombstone.is_tombstone()",
                    )
                }
            }
            tombstone
        }
        pub fn is_tombstone(&self) -> bool {
            #[allow(non_exhaustive_omitted_patterns)]
            match self.program {
                ProgramCacheEntryType::FailedVerification(_)
                | ProgramCacheEntryType::Closed
                | ProgramCacheEntryType::DelayVisibility => true,
                _ => false,
            }
        }
        fn is_implicit_delay_visibility_tombstone(&self, slot: Slot) -> bool {
            !#[allow(non_exhaustive_omitted_patterns)]
            match self.program {
                ProgramCacheEntryType::Builtin(_) => true,
                _ => false,
            }
                && self.effective_slot.saturating_sub(self.deployment_slot)
                    == DELAY_VISIBILITY_SLOT_OFFSET && slot >= self.deployment_slot
                && slot < self.effective_slot
        }
        pub fn update_access_slot(&self, slot: Slot) {
            let _ = self.latest_access_slot.fetch_max(slot, Ordering::Relaxed);
        }
        pub fn decayed_usage_counter(&self, now: Slot) -> u64 {
            let last_access = self.latest_access_slot.load(Ordering::Relaxed);
            let decaying_for = std::cmp::min(63, now.saturating_sub(last_access));
            self.tx_usage_counter.load(Ordering::Relaxed) >> decaying_for
        }
        pub fn account_owner(&self) -> Pubkey {
            self.account_owner.into()
        }
    }
    /// Globally shared RBPF config and syscall registry
    ///
    /// This is only valid in an epoch range as long as no feature affecting RBPF is activated.
    pub struct ProgramRuntimeEnvironments {
        /// For program runtime V1
        pub program_runtime_v1: ProgramRuntimeEnvironment,
        /// For program runtime V2
        pub program_runtime_v2: ProgramRuntimeEnvironment,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ProgramRuntimeEnvironments {
        #[inline]
        fn clone(&self) -> ProgramRuntimeEnvironments {
            ProgramRuntimeEnvironments {
                program_runtime_v1: ::core::clone::Clone::clone(
                    &self.program_runtime_v1,
                ),
                program_runtime_v2: ::core::clone::Clone::clone(&self.program_runtime_v2),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProgramRuntimeEnvironments {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field2_finish(
                f,
                "ProgramRuntimeEnvironments",
                "program_runtime_v1",
                &self.program_runtime_v1,
                "program_runtime_v2",
                &&self.program_runtime_v2,
            )
        }
    }
    impl Default for ProgramRuntimeEnvironments {
        fn default() -> Self {
            let empty_loader = Arc::new(BuiltinProgram::new_loader(Config::default()));
            Self {
                program_runtime_v1: empty_loader.clone(),
                program_runtime_v2: empty_loader,
            }
        }
    }
    /// Globally manages the transition between environments at the epoch boundary
    pub struct EpochBoundaryPreparation {
        /// The epoch of the upcoming_environments
        pub upcoming_epoch: Epoch,
        /// Anticipated replacement for `environments` at the next epoch
        ///
        /// This is `None` during most of an epoch, and only `Some` around the boundaries (at the end and beginning of an epoch).
        /// More precisely, it starts with the cache preparation phase a few hundred slots before the epoch boundary,
        /// and it ends with the first rerooting after the epoch boundary.
        pub upcoming_environments: Option<ProgramRuntimeEnvironments>,
        /// List of loaded programs which should be recompiled before the next epoch (but don't have to).
        pub programs_to_recompile: Vec<(Pubkey, Arc<ProgramCacheEntry>)>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for EpochBoundaryPreparation {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "EpochBoundaryPreparation",
                "upcoming_epoch",
                &self.upcoming_epoch,
                "upcoming_environments",
                &self.upcoming_environments,
                "programs_to_recompile",
                &&self.programs_to_recompile,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for EpochBoundaryPreparation {
        #[inline]
        fn default() -> EpochBoundaryPreparation {
            EpochBoundaryPreparation {
                upcoming_epoch: ::core::default::Default::default(),
                upcoming_environments: ::core::default::Default::default(),
                programs_to_recompile: ::core::default::Default::default(),
            }
        }
    }
    impl EpochBoundaryPreparation {
        pub fn new(epoch: Epoch) -> Self {
            Self {
                upcoming_epoch: epoch,
                upcoming_environments: None,
                programs_to_recompile: Vec::default(),
            }
        }
        /// Returns the upcoming environments depending on the given epoch
        pub fn get_upcoming_environments_for_epoch(
            &self,
            epoch: Epoch,
        ) -> Option<ProgramRuntimeEnvironments> {
            if epoch == self.upcoming_epoch {
                return self.upcoming_environments.clone();
            }
            None
        }
        /// Before rerooting the blockstore this concludes the epoch boundary preparation
        pub fn reroot(&mut self, epoch: Epoch) -> Option<ProgramRuntimeEnvironments> {
            if epoch == self.upcoming_epoch {
                if let Some(upcoming_environments) = self.upcoming_environments.take() {
                    self.programs_to_recompile.clear();
                    return Some(upcoming_environments);
                }
            }
            None
        }
    }
    pub struct LoadingTaskCookie(u64);
    #[automatically_derived]
    impl ::core::marker::Copy for LoadingTaskCookie {}
    #[automatically_derived]
    impl ::core::clone::Clone for LoadingTaskCookie {
        #[inline]
        fn clone(&self) -> LoadingTaskCookie {
            let _: ::core::clone::AssertParamIsClone<u64>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for LoadingTaskCookie {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "LoadingTaskCookie",
                &&self.0,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for LoadingTaskCookie {
        #[inline]
        fn default() -> LoadingTaskCookie {
            LoadingTaskCookie(::core::default::Default::default())
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for LoadingTaskCookie {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<u64>;
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for LoadingTaskCookie {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for LoadingTaskCookie {
        #[inline]
        fn eq(&self, other: &LoadingTaskCookie) -> bool {
            self.0 == other.0
        }
    }
    impl LoadingTaskCookie {
        fn new() -> Self {
            Self(0)
        }
        fn update(&mut self) {
            let LoadingTaskCookie(cookie) = self;
            *cookie = cookie.wrapping_add(1);
        }
    }
    /// Suspends the thread in case no cooprative loading task was assigned
    pub struct LoadingTaskWaiter {
        cookie: Mutex<LoadingTaskCookie>,
        cond: Condvar,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for LoadingTaskWaiter {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field2_finish(
                f,
                "LoadingTaskWaiter",
                "cookie",
                &self.cookie,
                "cond",
                &&self.cond,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for LoadingTaskWaiter {
        #[inline]
        fn default() -> LoadingTaskWaiter {
            LoadingTaskWaiter {
                cookie: ::core::default::Default::default(),
                cond: ::core::default::Default::default(),
            }
        }
    }
    impl LoadingTaskWaiter {
        pub fn new() -> Self {
            Self {
                cookie: Mutex::new(LoadingTaskCookie::new()),
                cond: Condvar::new(),
            }
        }
        pub fn cookie(&self) -> LoadingTaskCookie {
            *self.cookie.lock().unwrap()
        }
        pub fn notify(&self) {
            let mut cookie = self.cookie.lock().unwrap();
            cookie.update();
            self.cond.notify_all();
        }
        pub fn wait(&self, cookie: LoadingTaskCookie) -> LoadingTaskCookie {
            let cookie_guard = self.cookie.lock().unwrap();
            *self
                .cond
                .wait_while(cookie_guard, |current_cookie| *current_cookie == cookie)
                .unwrap()
        }
    }
    enum IndexImplementation {
        /// Fork-graph aware index implementation
        V1 {
            /// A two level index:
            ///
            /// - the first level is for the address at which programs are deployed
            /// - the second level for the slot (and thus also fork), sorted by slot number.
            entries: HashMap<Pubkey, Vec<Arc<ProgramCacheEntry>>>,
            /// The entries that are getting loaded and have not yet finished loading.
            ///
            /// The key is the program address, the value is a tuple of the slot in which the program is
            /// being loaded and the thread ID doing the load.
            ///
            /// It is possible that multiple TX batches from different slots need different versions of a
            /// program. The deployment slot of a program is only known after load tho,
            /// so all loads for a given program key are serialized.
            loading_entries: Mutex<HashMap<Pubkey, (Slot, thread::ThreadId)>>,
        },
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for IndexImplementation {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                IndexImplementation::V1 {
                    entries: __self_0,
                    loading_entries: __self_1,
                } => {
                    ::core::fmt::Formatter::debug_struct_field2_finish(
                        f,
                        "V1",
                        "entries",
                        __self_0,
                        "loading_entries",
                        &__self_1,
                    )
                }
            }
        }
    }
    /// This structure is the global cache of loaded, verified and compiled programs.
    ///
    /// It ...
    /// - is validator global and fork graph aware, so it can optimize the commonalities across banks.
    /// - handles the visibility rules of un/re/deployments.
    /// - stores the usage statistics and verification status of each program.
    /// - is elastic and uses a probabilistic eviction strategy based on the usage statistics.
    /// - also keeps the compiled executables around, but only for the most used programs.
    /// - supports various kinds of tombstones to avoid loading programs which can not be loaded.
    /// - cleans up entries on orphan branches when the block store is rerooted.
    /// - supports the cache preparation phase before feature activations which can change cached programs.
    /// - manages the environments of the programs and upcoming environments for the next epoch.
    /// - allows for cooperative loading of TX batches which hit the same missing programs simultaneously.
    /// - enforces that all programs used in a batch are eagerly loaded ahead of execution.
    /// - is not persisted to disk or a snapshot, so it needs to cold start and warm up first.
    pub struct ProgramCache<FG: ForkGraph> {
        /// Index of the cached entries and cooperative loading tasks
        index: IndexImplementation,
        /// The slot of the last rerooting
        pub latest_root_slot: Slot,
        /// Statistics counters
        pub stats: ProgramCacheStats,
        /// Reference to the block store
        pub fork_graph: Option<Weak<RwLock<FG>>>,
        /// Coordinates TX batches waiting for others to complete their task during cooperative loading
        pub loading_task_waiter: Arc<LoadingTaskWaiter>,
    }
    impl<FG: ForkGraph> Debug for ProgramCache<FG> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProgramCache")
                .field("root slot", &self.latest_root_slot)
                .field("stats", &self.stats)
                .field("index", &self.index)
                .finish()
        }
    }
    /// Local view into [ProgramCache] which was extracted for a specific TX batch.
    ///
    /// This isolation enables the global [ProgramCache] to continue to evolve (e.g. evictions),
    /// while the TX batch is guaranteed it will continue to find all the programs it requires.
    /// For program management instructions this also buffers them before they are merged back into the global [ProgramCache].
    pub struct ProgramCacheForTxBatch {
        /// Pubkey is the address of a program.
        /// ProgramCacheEntry is the corresponding program entry valid for the slot in which a transaction is being executed.
        entries: HashMap<Pubkey, Arc<ProgramCacheEntry>>,
        /// Program entries modified during the transaction batch.
        modified_entries: HashMap<Pubkey, Arc<ProgramCacheEntry>>,
        slot: Slot,
        pub hit_max_limit: bool,
        pub loaded_missing: bool,
        pub merged_modified: bool,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ProgramCacheForTxBatch {
        #[inline]
        fn clone(&self) -> ProgramCacheForTxBatch {
            ProgramCacheForTxBatch {
                entries: ::core::clone::Clone::clone(&self.entries),
                modified_entries: ::core::clone::Clone::clone(&self.modified_entries),
                slot: ::core::clone::Clone::clone(&self.slot),
                hit_max_limit: ::core::clone::Clone::clone(&self.hit_max_limit),
                loaded_missing: ::core::clone::Clone::clone(&self.loaded_missing),
                merged_modified: ::core::clone::Clone::clone(&self.merged_modified),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProgramCacheForTxBatch {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "entries",
                "modified_entries",
                "slot",
                "hit_max_limit",
                "loaded_missing",
                "merged_modified",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.entries,
                &self.modified_entries,
                &self.slot,
                &self.hit_max_limit,
                &self.loaded_missing,
                &&self.merged_modified,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "ProgramCacheForTxBatch",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for ProgramCacheForTxBatch {
        #[inline]
        fn default() -> ProgramCacheForTxBatch {
            ProgramCacheForTxBatch {
                entries: ::core::default::Default::default(),
                modified_entries: ::core::default::Default::default(),
                slot: ::core::default::Default::default(),
                hit_max_limit: ::core::default::Default::default(),
                loaded_missing: ::core::default::Default::default(),
                merged_modified: ::core::default::Default::default(),
            }
        }
    }
    impl ProgramCacheForTxBatch {
        pub fn new(slot: Slot) -> Self {
            Self {
                entries: HashMap::new(),
                modified_entries: HashMap::new(),
                slot,
                hit_max_limit: false,
                loaded_missing: false,
                merged_modified: false,
            }
        }
        /// Refill the cache with a single entry. It's typically called during transaction loading, and
        /// transaction processing (for program management instructions).
        /// It replaces the existing entry (if any) with the provided entry. The return value contains
        /// `true` if an entry existed.
        /// The function also returns the newly inserted value.
        pub fn replenish(
            &mut self,
            key: Pubkey,
            entry: Arc<ProgramCacheEntry>,
        ) -> (bool, Arc<ProgramCacheEntry>) {
            (self.entries.insert(key, entry.clone()).is_some(), entry)
        }
        /// Store an entry in `modified_entries` for a program modified during the
        /// transaction batch.
        pub fn store_modified_entry(
            &mut self,
            key: Pubkey,
            entry: Arc<ProgramCacheEntry>,
        ) {
            self.modified_entries.insert(key, entry);
        }
        /// Drain the program cache's modified entries, returning the owned
        /// collection.
        pub fn drain_modified_entries(
            &mut self,
        ) -> HashMap<Pubkey, Arc<ProgramCacheEntry>> {
            std::mem::take(&mut self.modified_entries)
        }
        pub fn find(&self, key: &Pubkey) -> Option<Arc<ProgramCacheEntry>> {
            self.modified_entries
                .get(key)
                .or_else(|| self.entries.get(key))
                .map(|entry| {
                    if entry.is_implicit_delay_visibility_tombstone(self.slot) {
                        Arc::new(
                            ProgramCacheEntry::new_tombstone_with_usage_counter(
                                entry.deployment_slot,
                                entry.account_owner,
                                ProgramCacheEntryType::DelayVisibility,
                                entry.tx_usage_counter.clone(),
                            ),
                        )
                    } else {
                        entry.clone()
                    }
                })
        }
        pub fn slot(&self) -> Slot {
            self.slot
        }
        pub fn set_slot_for_tests(&mut self, slot: Slot) {
            self.slot = slot;
        }
        pub fn merge(
            &mut self,
            modified_entries: &HashMap<Pubkey, Arc<ProgramCacheEntry>>,
        ) {
            modified_entries
                .iter()
                .for_each(|(key, entry)| {
                    self.merged_modified = true;
                    self.replenish(*key, entry.clone());
                })
        }
        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
    }
    pub enum ProgramCacheMatchCriteria {
        DeployedOnOrAfterSlot(Slot),
        Tombstone,
        NoCriteria,
    }
    impl<FG: ForkGraph> ProgramCache<FG> {
        pub fn new(root_slot: Slot) -> Self {
            Self {
                index: IndexImplementation::V1 {
                    entries: HashMap::new(),
                    loading_entries: Mutex::new(HashMap::new()),
                },
                latest_root_slot: root_slot,
                stats: ProgramCacheStats::default(),
                fork_graph: None,
                loading_task_waiter: Arc::new(LoadingTaskWaiter::default()),
            }
        }
        pub fn set_fork_graph(&mut self, fork_graph: Weak<RwLock<FG>>) {
            self.fork_graph = Some(fork_graph);
        }
        /// Insert a single entry. It's typically called during transaction loading,
        /// when the cache doesn't contain the entry corresponding to program `key`.
        pub fn assign_program(
            &mut self,
            program_runtime_environments: &ProgramRuntimeEnvironments,
            key: Pubkey,
            entry: Arc<ProgramCacheEntry>,
        ) -> bool {
            if true {
                if !!#[allow(non_exhaustive_omitted_patterns)]
                match &entry.program {
                    ProgramCacheEntryType::DelayVisibility => true,
                    _ => false,
                } {
                    ::core::panicking::panic(
                        "assertion failed: !matches!(&entry.program, ProgramCacheEntryType::DelayVisibility)",
                    )
                }
            }
            fn is_current_env(
                environments: &ProgramRuntimeEnvironments,
                env_opt: Option<&ProgramRuntimeEnvironment>,
            ) -> bool {
                env_opt
                    .map(|env| {
                        Arc::ptr_eq(env, &environments.program_runtime_v1)
                            || Arc::ptr_eq(env, &environments.program_runtime_v2)
                    })
                    .unwrap_or(true)
            }
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    let slot_versions = &mut entries.entry(key).or_default();
                    match slot_versions
                        .binary_search_by(|at| {
                            at.effective_slot
                                .cmp(&entry.effective_slot)
                                .then(at.deployment_slot.cmp(&entry.deployment_slot))
                                .then(
                                    is_current_env(
                                            program_runtime_environments,
                                            at.program.get_environment(),
                                        )
                                        .cmp(
                                            &is_current_env(
                                                program_runtime_environments,
                                                entry.program.get_environment(),
                                            ),
                                        ),
                                )
                        })
                    {
                        Ok(index) => {
                            let existing = slot_versions.get_mut(index).unwrap();
                            match (&existing.program, &entry.program) {
                                (
                                    ProgramCacheEntryType::Builtin(_),
                                    ProgramCacheEntryType::Builtin(_),
                                )
                                | (
                                    ProgramCacheEntryType::Unloaded(_),
                                    ProgramCacheEntryType::Loaded(_),
                                ) => {}
                                (
                                    ProgramCacheEntryType::Closed,
                                    ProgramCacheEntryType::Closed,
                                ) if existing.account_owner != entry.account_owner => {}
                                _ => {
                                    {
                                        {
                                            let lvl = ::log::Level::Error;
                                            if lvl <= ::log::STATIC_MAX_LEVEL
                                                && lvl <= ::log::max_level()
                                            {
                                                ::log::__private_api::log(
                                                    { ::log::__private_api::GlobalLogger },
                                                    format_args!(
                                                        "ProgramCache::assign_program() failed key={0:?} existing={1:?} entry={2:?}",
                                                        key,
                                                        slot_versions,
                                                        entry,
                                                    ),
                                                    lvl,
                                                    &(
                                                        "solana_program_runtime::loaded_programs",
                                                        "solana_program_runtime::loaded_programs",
                                                        ::log::__private_api::loc(),
                                                    ),
                                                    (),
                                                );
                                            }
                                        }
                                    };
                                    if true {
                                        if !false {
                                            {
                                                ::core::panicking::panic_fmt(
                                                    format_args!("Unexpected replacement of an entry"),
                                                );
                                            }
                                        }
                                    }
                                    self.stats.replacements.fetch_add(1, Ordering::Relaxed);
                                    return true;
                                }
                            }
                            entry
                                .tx_usage_counter
                                .fetch_add(
                                    existing.tx_usage_counter.load(Ordering::Relaxed),
                                    Ordering::Relaxed,
                                );
                            *existing = Arc::clone(&entry);
                            self.stats.reloads.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(index) => {
                            self.stats.insertions.fetch_add(1, Ordering::Relaxed);
                            slot_versions.insert(index, Arc::clone(&entry));
                        }
                    }
                    slot_versions
                        .retain(|existing| {
                            existing.deployment_slot != entry.deployment_slot
                                || existing
                                    .program
                                    .get_environment()
                                    .zip(entry.program.get_environment())
                                    .map(|(a, b)| !Arc::ptr_eq(a, b))
                                    .unwrap_or(false) || existing == &entry
                        });
                }
            }
            false
        }
        pub fn prune_by_deployment_slot(&mut self, slot: Slot) {
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    for second_level in entries.values_mut() {
                        second_level.retain(|entry| entry.deployment_slot != slot);
                    }
                    self.remove_programs_with_no_entries();
                }
            }
        }
        /// Before rerooting the blockstore this removes all superfluous entries
        pub fn prune(
            &mut self,
            new_root_slot: Slot,
            upcoming_environments: Option<ProgramRuntimeEnvironments>,
        ) {
            let Some(fork_graph) = self.fork_graph.clone() else {
                {
                    {
                        let lvl = ::log::Level::Error;
                        if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                            ::log::__private_api::log(
                                { ::log::__private_api::GlobalLogger },
                                format_args!("Program cache doesn\'t have fork graph."),
                                lvl,
                                &(
                                    "solana_program_runtime::loaded_programs",
                                    "solana_program_runtime::loaded_programs",
                                    ::log::__private_api::loc(),
                                ),
                                (),
                            );
                        }
                    }
                };
                return;
            };
            let fork_graph = fork_graph.upgrade().unwrap();
            let Ok(fork_graph) = fork_graph.read() else {
                {
                    {
                        let lvl = ::log::Level::Error;
                        if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                            ::log::__private_api::log(
                                { ::log::__private_api::GlobalLogger },
                                format_args!("Failed to lock fork graph for reading."),
                                lvl,
                                &(
                                    "solana_program_runtime::loaded_programs",
                                    "solana_program_runtime::loaded_programs",
                                    ::log::__private_api::loc(),
                                ),
                                (),
                            );
                        }
                    }
                };
                return;
            };
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    for second_level in entries.values_mut() {
                        let mut first_ancestor_found = false;
                        let mut first_ancestor_env = None;
                        *second_level = second_level
                            .iter()
                            .rev()
                            .filter(|entry| {
                                let relation = fork_graph
                                    .relationship(entry.deployment_slot, new_root_slot);
                                if entry.deployment_slot >= new_root_slot {
                                    #[allow(non_exhaustive_omitted_patterns)]
                                    match relation {
                                        BlockRelation::Equal | BlockRelation::Descendant => true,
                                        _ => false,
                                    }
                                } else if #[allow(non_exhaustive_omitted_patterns)]
                                match relation {
                                    BlockRelation::Ancestor => true,
                                    _ => false,
                                } || entry.deployment_slot <= self.latest_root_slot
                                {
                                    if !first_ancestor_found {
                                        first_ancestor_found = true;
                                        first_ancestor_env = entry.program.get_environment();
                                        return true;
                                    }
                                    if let Some(entry_env) = entry.program.get_environment() {
                                        if let Some(env) = first_ancestor_env {
                                            if !Arc::ptr_eq(entry_env, env) {
                                                return true;
                                            }
                                        }
                                    }
                                    self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                                    false
                                } else {
                                    self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                                    false
                                }
                            })
                            .filter(|entry| {
                                if let Some(upcoming_environments) = upcoming_environments
                                    .as_ref()
                                {
                                    if !Self::matches_environment(
                                        entry,
                                        upcoming_environments,
                                    ) {
                                        self.stats
                                            .prunes_environment
                                            .fetch_add(1, Ordering::Relaxed);
                                        return false;
                                    }
                                }
                                true
                            })
                            .cloned()
                            .collect();
                        second_level.reverse();
                    }
                }
            }
            self.remove_programs_with_no_entries();
            if true {
                if !(self.latest_root_slot <= new_root_slot) {
                    ::core::panicking::panic(
                        "assertion failed: self.latest_root_slot <= new_root_slot",
                    )
                }
            }
            self.latest_root_slot = new_root_slot;
        }
        fn matches_environment(
            entry: &Arc<ProgramCacheEntry>,
            environments: &ProgramRuntimeEnvironments,
        ) -> bool {
            let Some(environment) = entry.program.get_environment() else {
                return true;
            };
            Arc::ptr_eq(environment, &environments.program_runtime_v1)
                || Arc::ptr_eq(environment, &environments.program_runtime_v2)
        }
        fn matches_criteria(
            program: &Arc<ProgramCacheEntry>,
            criteria: &ProgramCacheMatchCriteria,
        ) -> bool {
            match criteria {
                ProgramCacheMatchCriteria::DeployedOnOrAfterSlot(slot) => {
                    program.deployment_slot >= *slot
                }
                ProgramCacheMatchCriteria::Tombstone => program.is_tombstone(),
                ProgramCacheMatchCriteria::NoCriteria => true,
            }
        }
        /// Extracts a subset of the programs relevant to a transaction batch
        /// and returns which program accounts the accounts DB needs to load.
        pub fn extract(
            &self,
            search_for: &mut Vec<(Pubkey, ProgramCacheMatchCriteria)>,
            loaded_programs_for_tx_batch: &mut ProgramCacheForTxBatch,
            program_runtime_environments_for_execution: &ProgramRuntimeEnvironments,
            increment_usage_counter: bool,
            count_hits_and_misses: bool,
        ) -> Option<Pubkey> {
            if true {
                if !self.fork_graph.is_some() {
                    ::core::panicking::panic(
                        "assertion failed: self.fork_graph.is_some()",
                    )
                }
            }
            let fork_graph = self.fork_graph.as_ref().unwrap().upgrade().unwrap();
            let locked_fork_graph = fork_graph.read().unwrap();
            let mut cooperative_loading_task = None;
            match &self.index {
                IndexImplementation::V1 { entries, loading_entries } => {
                    search_for
                        .retain(|(key, match_criteria)| {
                            if let Some(second_level) = entries.get(key) {
                                let mut filter_by_deployment_slot = None;
                                for entry in second_level.iter().rev() {
                                    if filter_by_deployment_slot
                                        .map(|slot| slot != entry.deployment_slot)
                                        .unwrap_or(false)
                                    {
                                        continue;
                                    }
                                    if entry.deployment_slot <= self.latest_root_slot
                                        || #[allow(non_exhaustive_omitted_patterns)]
                                        match locked_fork_graph
                                            .relationship(
                                                entry.deployment_slot,
                                                loaded_programs_for_tx_batch.slot,
                                            )
                                        {
                                            BlockRelation::Equal | BlockRelation::Ancestor => true,
                                            _ => false,
                                        }
                                    {
                                        let entry_to_return = if loaded_programs_for_tx_batch.slot
                                            >= entry.effective_slot
                                        {
                                            if !Self::matches_environment(
                                                entry,
                                                program_runtime_environments_for_execution,
                                            ) {
                                                filter_by_deployment_slot = filter_by_deployment_slot
                                                    .or(Some(entry.deployment_slot));
                                                continue;
                                            }
                                            if !Self::matches_criteria(entry, match_criteria) {
                                                break;
                                            }
                                            if let ProgramCacheEntryType::Unloaded(_environment) = &entry
                                                .program
                                            {
                                                break;
                                            }
                                            entry.clone()
                                        } else if entry
                                            .is_implicit_delay_visibility_tombstone(
                                                loaded_programs_for_tx_batch.slot,
                                            )
                                        {
                                            Arc::new(
                                                ProgramCacheEntry::new_tombstone_with_usage_counter(
                                                    entry.deployment_slot,
                                                    entry.account_owner,
                                                    ProgramCacheEntryType::DelayVisibility,
                                                    entry.tx_usage_counter.clone(),
                                                ),
                                            )
                                        } else {
                                            continue;
                                        };
                                        entry_to_return
                                            .update_access_slot(loaded_programs_for_tx_batch.slot);
                                        if increment_usage_counter {
                                            entry_to_return
                                                .tx_usage_counter
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        loaded_programs_for_tx_batch
                                            .entries
                                            .insert(*key, entry_to_return);
                                        return false;
                                    }
                                }
                            }
                            if cooperative_loading_task.is_none() {
                                let mut loading_entries = loading_entries.lock().unwrap();
                                let entry = loading_entries.entry(*key);
                                if let Entry::Vacant(entry) = entry {
                                    entry
                                        .insert((
                                            loaded_programs_for_tx_batch.slot,
                                            thread::current().id(),
                                        ));
                                    cooperative_loading_task = Some(*key);
                                }
                            }
                            true
                        });
                }
            }
            drop(locked_fork_graph);
            if count_hits_and_misses {
                self.stats.misses.fetch_add(search_for.len() as u64, Ordering::Relaxed);
                self.stats
                    .hits
                    .fetch_add(
                        loaded_programs_for_tx_batch.entries.len() as u64,
                        Ordering::Relaxed,
                    );
            }
            cooperative_loading_task
        }
        /// Called by Bank::replenish_program_cache() for each program that is done loading.
        pub fn finish_cooperative_loading_task(
            &mut self,
            program_runtime_environments: &ProgramRuntimeEnvironments,
            slot: Slot,
            key: Pubkey,
            loaded_program: Arc<ProgramCacheEntry>,
        ) -> bool {
            match &mut self.index {
                IndexImplementation::V1 { loading_entries, .. } => {
                    let loading_thread = loading_entries.get_mut().unwrap().remove(&key);
                    if true {
                        match (&loading_thread, &Some((slot, thread::current().id()))) {
                            (left_val, right_val) => {
                                if !(*left_val == *right_val) {
                                    let kind = ::core::panicking::AssertKind::Eq;
                                    ::core::panicking::assert_failed(
                                        kind,
                                        &*left_val,
                                        &*right_val,
                                        ::core::option::Option::None,
                                    );
                                }
                            }
                        };
                    }
                    if loaded_program.deployment_slot > self.latest_root_slot
                        && !#[allow(non_exhaustive_omitted_patterns)]
                        match self
                            .fork_graph
                            .as_ref()
                            .unwrap()
                            .upgrade()
                            .unwrap()
                            .read()
                            .unwrap()
                            .relationship(loaded_program.deployment_slot, slot)
                        {
                            BlockRelation::Equal | BlockRelation::Ancestor => true,
                            _ => false,
                        }
                    {
                        self.stats.lost_insertions.fetch_add(1, Ordering::Relaxed);
                    }
                    let was_occupied = self
                        .assign_program(
                            program_runtime_environments,
                            key,
                            loaded_program,
                        );
                    self.loading_task_waiter.notify();
                    was_occupied
                }
            }
        }
        pub fn merge(
            &mut self,
            program_runtime_environments: &ProgramRuntimeEnvironments,
            modified_entries: &HashMap<Pubkey, Arc<ProgramCacheEntry>>,
        ) {
            modified_entries
                .iter()
                .for_each(|(key, entry)| {
                    self.assign_program(
                        program_runtime_environments,
                        *key,
                        entry.clone(),
                    );
                })
        }
        /// Returns the list of entries which are verified and compiled.
        pub fn get_flattened_entries(
            &self,
            include_program_runtime_v1: bool,
            _include_program_runtime_v2: bool,
        ) -> Vec<(Pubkey, Arc<ProgramCacheEntry>)> {
            match &self.index {
                IndexImplementation::V1 { entries, .. } => {
                    entries
                        .iter()
                        .flat_map(|(id, second_level)| {
                            second_level
                                .iter()
                                .filter_map(move |program| match program.program {
                                    ProgramCacheEntryType::Loaded(_) => {
                                        if include_program_runtime_v1 {
                                            Some((*id, program.clone()))
                                        } else {
                                            None
                                        }
                                    }
                                    _ => None,
                                })
                        })
                        .collect()
                }
            }
        }
        /// Returns the list of all entries in the cache.
        pub fn get_flattened_entries_for_tests(
            &self,
        ) -> Vec<(Pubkey, Arc<ProgramCacheEntry>)> {
            match &self.index {
                IndexImplementation::V1 { entries, .. } => {
                    entries
                        .iter()
                        .flat_map(|(id, second_level)| {
                            second_level.iter().map(|program| (*id, program.clone()))
                        })
                        .collect()
                }
            }
        }
        /// Returns the slot versions for the given program id.
        pub fn get_slot_versions_for_tests(
            &self,
            key: &Pubkey,
        ) -> &[Arc<ProgramCacheEntry>] {
            match &self.index {
                IndexImplementation::V1 { entries, .. } => {
                    entries
                        .get(key)
                        .map(|second_level| second_level.as_ref())
                        .unwrap_or(&[])
                }
            }
        }
        /// Unloads programs which were used infrequently
        pub fn sort_and_unload(&mut self, shrink_to: PercentageInteger) {
            let mut sorted_candidates = self.get_flattened_entries(true, true);
            sorted_candidates
                .sort_by_cached_key(|(_id, program)| {
                    program.tx_usage_counter.load(Ordering::Relaxed)
                });
            let num_to_unload = sorted_candidates
                .len()
                .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
            self.unload_program_entries(sorted_candidates.iter().take(num_to_unload));
        }
        /// Evicts programs using 2's random selection, choosing the least used program out of the two entries.
        /// The eviction is performed enough number of times to reduce the cache usage to the given percentage.
        pub fn evict_using_2s_random_selection(
            &mut self,
            shrink_to: PercentageInteger,
            now: Slot,
        ) {
            let mut candidates = self.get_flattened_entries(true, true);
            self.stats.water_level.store(candidates.len() as u64, Ordering::Relaxed);
            let num_to_unload = candidates
                .len()
                .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
            fn random_index_and_usage_counter(
                candidates: &[(Pubkey, Arc<ProgramCacheEntry>)],
                now: Slot,
            ) -> (usize, u64) {
                let mut rng = rng();
                #[allow(deprecated)]
                let index = rng.gen_range(0..candidates.len());
                let usage_counter = candidates
                    .get(index)
                    .expect("Failed to get cached entry")
                    .1
                    .decayed_usage_counter(now);
                (index, usage_counter)
            }
            for _ in 0..num_to_unload {
                let (index1, usage_counter1) = random_index_and_usage_counter(
                    &candidates,
                    now,
                );
                let (index2, usage_counter2) = random_index_and_usage_counter(
                    &candidates,
                    now,
                );
                let (program, entry) = if usage_counter1 < usage_counter2 {
                    candidates.swap_remove(index1)
                } else {
                    candidates.swap_remove(index2)
                };
                self.unload_program_entry(&program, &entry);
            }
        }
        /// Removes all the entries at the given keys, if they exist
        pub fn remove_programs(&mut self, keys: impl Iterator<Item = Pubkey>) {
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    for k in keys {
                        entries.remove(&k);
                    }
                }
            }
        }
        /// This function removes the given entry for the given program from the cache.
        /// The function expects that the program and entry exists in the cache. Otherwise it'll panic.
        fn unload_program_entry(
            &mut self,
            program: &Pubkey,
            remove_entry: &Arc<ProgramCacheEntry>,
        ) {
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    let second_level = entries
                        .get_mut(program)
                        .expect("Cache lookup failed");
                    let candidate = second_level
                        .iter_mut()
                        .find(|entry| entry == &remove_entry)
                        .expect("Program entry not found");
                    if let Some(unloaded) = candidate.to_unloaded() {
                        if candidate.tx_usage_counter.load(Ordering::Relaxed) == 1 {
                            self.stats.one_hit_wonders.fetch_add(1, Ordering::Relaxed);
                        }
                        self.stats
                            .evictions
                            .entry(*program)
                            .and_modify(|c| *c = c.saturating_add(1))
                            .or_insert(1);
                        *candidate = Arc::new(unloaded);
                    }
                }
            }
        }
        fn unload_program_entries<'a>(
            &mut self,
            remove: impl Iterator<Item = &'a (Pubkey, Arc<ProgramCacheEntry>)>,
        ) {
            for (program, entry) in remove {
                self.unload_program_entry(program, entry);
            }
        }
        fn remove_programs_with_no_entries(&mut self) {
            match &mut self.index {
                IndexImplementation::V1 { entries, .. } => {
                    let num_programs_before_removal = entries.len();
                    entries.retain(|_key, second_level| !second_level.is_empty());
                    if entries.len() < num_programs_before_removal {
                        self.stats
                            .empty_entries
                            .fetch_add(
                                num_programs_before_removal.saturating_sub(entries.len())
                                    as u64,
                                Ordering::Relaxed,
                            );
                    }
                }
            }
        }
    }
}
pub mod mem_pool {
    use {
        crate::execution_budget::{
            MAX_CALL_DEPTH, MAX_HEAP_FRAME_BYTES, MAX_INSTRUCTION_STACK_DEPTH,
            MIN_HEAP_FRAME_BYTES, STACK_FRAME_SIZE,
        },
        solana_sbpf::{aligned_memory::AlignedMemory, ebpf::HOST_ALIGN},
        std::array,
    };
    trait Reset {
        fn reset(&mut self);
    }
    struct Pool<T: Reset, const SIZE: usize> {
        items: [Option<T>; SIZE],
        next_empty: usize,
    }
    impl<T: Reset, const SIZE: usize> Pool<T, SIZE> {
        fn new(items: [T; SIZE]) -> Self {
            Self {
                items: items.map(|i| Some(i)),
                next_empty: SIZE,
            }
        }
        fn len(&self) -> usize {
            SIZE
        }
        fn get(&mut self) -> Option<T> {
            if self.next_empty == 0 {
                return None;
            }
            self.next_empty = self.next_empty.saturating_sub(1);
            self.items.get_mut(self.next_empty).and_then(|item| item.take())
        }
        fn put(&mut self, mut value: T) -> bool {
            self.items
                .get_mut(self.next_empty)
                .map(|item| {
                    value.reset();
                    item.replace(value);
                    self.next_empty = self.next_empty.saturating_add(1);
                    true
                })
                .unwrap_or(false)
        }
    }
    impl Reset for AlignedMemory<{ HOST_ALIGN }> {
        fn reset(&mut self) {
            self.as_slice_mut().fill(0)
        }
    }
    pub struct VmMemoryPool {
        stack: Pool<AlignedMemory<{ HOST_ALIGN }>, MAX_INSTRUCTION_STACK_DEPTH>,
        heap: Pool<AlignedMemory<{ HOST_ALIGN }>, MAX_INSTRUCTION_STACK_DEPTH>,
    }
    impl VmMemoryPool {
        pub fn new() -> Self {
            Self {
                stack: Pool::new(
                    array::from_fn(|_| {
                        AlignedMemory::zero_filled(STACK_FRAME_SIZE * MAX_CALL_DEPTH)
                    }),
                ),
                heap: Pool::new(
                    array::from_fn(|_| {
                        AlignedMemory::zero_filled(MAX_HEAP_FRAME_BYTES as usize)
                    }),
                ),
            }
        }
        pub fn stack_len(&self) -> usize {
            self.stack.len()
        }
        pub fn heap_len(&self) -> usize {
            self.heap.len()
        }
        pub fn get_stack(&mut self, size: usize) -> AlignedMemory<{ HOST_ALIGN }> {
            if true {
                if !(size == STACK_FRAME_SIZE * MAX_CALL_DEPTH) {
                    ::core::panicking::panic(
                        "assertion failed: size == STACK_FRAME_SIZE * MAX_CALL_DEPTH",
                    )
                }
            }
            self.stack.get().unwrap_or_else(|| AlignedMemory::zero_filled(size))
        }
        pub fn put_stack(&mut self, stack: AlignedMemory<{ HOST_ALIGN }>) -> bool {
            self.stack.put(stack)
        }
        pub fn get_heap(&mut self, heap_size: u32) -> AlignedMemory<{ HOST_ALIGN }> {
            if true {
                if !(MIN_HEAP_FRAME_BYTES..=MAX_HEAP_FRAME_BYTES).contains(&heap_size) {
                    ::core::panicking::panic(
                        "assertion failed: (MIN_HEAP_FRAME_BYTES..=MAX_HEAP_FRAME_BYTES).contains(&heap_size)",
                    )
                }
            }
            self.heap
                .get()
                .unwrap_or_else(|| AlignedMemory::zero_filled(
                    MAX_HEAP_FRAME_BYTES as usize,
                ))
        }
        pub fn put_heap(&mut self, heap: AlignedMemory<{ HOST_ALIGN }>) -> bool {
            let heap_size = heap.len();
            if true {
                if !(heap_size >= MIN_HEAP_FRAME_BYTES as usize
                    && heap_size <= MAX_HEAP_FRAME_BYTES as usize)
                {
                    ::core::panicking::panic(
                        "assertion failed: heap_size >= MIN_HEAP_FRAME_BYTES as usize &&\n    heap_size <= MAX_HEAP_FRAME_BYTES as usize",
                    )
                }
            }
            self.heap.put(heap)
        }
    }
    impl Default for VmMemoryPool {
        fn default() -> Self {
            Self::new()
        }
    }
}
pub mod memory {
    //! Memory translation utilities.
    use {
        solana_sbpf::memory_region::{AccessType, MemoryMapping},
        solana_transaction_context::vm_slice::VmSlice,
        std::{mem::align_of, slice::from_raw_parts_mut},
    };
    /// Error types for memory translation operations.
    pub enum MemoryTranslationError {
        #[error("Unaligned pointer")]
        UnalignedPointer,
        #[error("Invalid length")]
        InvalidLength,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for MemoryTranslationError {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(
                f,
                match self {
                    MemoryTranslationError::UnalignedPointer => "UnalignedPointer",
                    MemoryTranslationError::InvalidLength => "InvalidLength",
                },
            )
        }
    }
    #[allow(unused_qualifications)]
    #[automatically_derived]
    impl ::thiserror::__private17::Error for MemoryTranslationError {}
    #[allow(unused_qualifications)]
    #[automatically_derived]
    impl ::core::fmt::Display for MemoryTranslationError {
        fn fmt(&self, __formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            #[allow(unused_variables, deprecated, clippy::used_underscore_binding)]
            match self {
                MemoryTranslationError::UnalignedPointer {} => {
                    __formatter.write_str("Unaligned pointer")
                }
                MemoryTranslationError::InvalidLength {} => {
                    __formatter.write_str("Invalid length")
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for MemoryTranslationError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for MemoryTranslationError {
        #[inline]
        fn eq(&self, other: &MemoryTranslationError) -> bool {
            let __self_discr = ::core::intrinsics::discriminant_value(self);
            let __arg1_discr = ::core::intrinsics::discriminant_value(other);
            __self_discr == __arg1_discr
        }
    }
    #[automatically_derived]
    impl ::core::cmp::Eq for MemoryTranslationError {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {}
    }
    pub fn address_is_aligned<T>(address: u64) -> bool {
        (address as *mut T as usize)
            .checked_rem(align_of::<T>())
            .map(|rem| rem == 0)
            .expect("T to be non-zero aligned")
    }
    pub fn translate_type<'a, T>(
        memory_mapping: &MemoryMapping,
        vm_addr: u64,
        check_aligned: bool,
    ) -> Result<&'a T, Box<dyn std::error::Error>> {
        {
            let host_addr = Result::<
                u64,
                Box<dyn std::error::Error>,
            >::from(
                memory_mapping
                    .map(AccessType::Load, vm_addr, size_of::<T>() as u64)
                    .map_err(|err| err.into()),
            )?;
            if !check_aligned {
                Ok(unsafe { std::mem::transmute::<u64, &mut T>(host_addr) })
            } else if !crate::memory::address_is_aligned::<T>(host_addr) {
                Err(crate::memory::MemoryTranslationError::UnalignedPointer.into())
            } else {
                Ok(unsafe { &mut *(host_addr as *mut T) })
            }
        }
            .map(|value| &*value)
    }
    pub fn translate_slice<'a, T>(
        memory_mapping: &MemoryMapping,
        vm_addr: u64,
        len: u64,
        check_aligned: bool,
    ) -> Result<&'a [T], Box<dyn std::error::Error>> {
        {
            if len == 0 {
                return Ok(&mut []);
            }
            let total_size = len.saturating_mul(size_of::<T>() as u64);
            if isize::try_from(total_size).is_err() {
                return Err(crate::memory::MemoryTranslationError::InvalidLength.into());
            }
            let host_addr = Result::<
                u64,
                Box<dyn std::error::Error>,
            >::from(
                memory_mapping
                    .map(AccessType::Load, vm_addr, total_size)
                    .map_err(|err| err.into()),
            )?;
            if check_aligned && !crate::memory::address_is_aligned::<T>(host_addr) {
                return Err(
                    crate::memory::MemoryTranslationError::UnalignedPointer.into(),
                );
            }
            Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
        }
            .map(|value| &*value)
    }
    /// CPI-specific version with intentionally different lifetime signature.
    /// This version is missing lifetime 'a of the return type in the parameter &MemoryMapping.
    pub fn translate_type_mut_for_cpi<'a, T>(
        memory_mapping: &MemoryMapping,
        vm_addr: u64,
        check_aligned: bool,
    ) -> Result<&'a mut T, Box<dyn std::error::Error>> {
        {
            let host_addr = Result::<
                u64,
                Box<dyn std::error::Error>,
            >::from(
                memory_mapping
                    .map(AccessType::Store, vm_addr, size_of::<T>() as u64)
                    .map_err(|err| err.into()),
            )?;
            if !check_aligned {
                Ok(unsafe { std::mem::transmute::<u64, &mut T>(host_addr) })
            } else if !crate::memory::address_is_aligned::<T>(host_addr) {
                Err(crate::memory::MemoryTranslationError::UnalignedPointer.into())
            } else {
                Ok(unsafe { &mut *(host_addr as *mut T) })
            }
        }
    }
    /// CPI-specific version with intentionally different lifetime signature.
    /// This version is missing lifetime 'a of the return type in the parameter &MemoryMapping.
    pub fn translate_slice_mut_for_cpi<'a, T>(
        memory_mapping: &MemoryMapping,
        vm_addr: u64,
        len: u64,
        check_aligned: bool,
    ) -> Result<&'a mut [T], Box<dyn std::error::Error>> {
        {
            if len == 0 {
                return Ok(&mut []);
            }
            let total_size = len.saturating_mul(size_of::<T>() as u64);
            if isize::try_from(total_size).is_err() {
                return Err(crate::memory::MemoryTranslationError::InvalidLength.into());
            }
            let host_addr = Result::<
                u64,
                Box<dyn std::error::Error>,
            >::from(
                memory_mapping
                    .map(AccessType::Store, vm_addr, total_size)
                    .map_err(|err| err.into()),
            )?;
            if check_aligned && !crate::memory::address_is_aligned::<T>(host_addr) {
                return Err(
                    crate::memory::MemoryTranslationError::UnalignedPointer.into(),
                );
            }
            Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
        }
    }
    pub fn translate_vm_slice<'a, T>(
        slice: &VmSlice<T>,
        memory_mapping: &'a MemoryMapping,
        check_aligned: bool,
    ) -> Result<&'a [T], Box<dyn std::error::Error>> {
        translate_slice::<T>(memory_mapping, slice.ptr(), slice.len(), check_aligned)
    }
}
pub mod serialization {
    #![allow(clippy::arithmetic_side_effects)]
    use {
        crate::invoke_context::SerializedAccountMetadata,
        solana_instruction::error::InstructionError,
        solana_program_entrypoint::{
            BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, NON_DUP_MARKER,
        },
        solana_pubkey::Pubkey,
        solana_sbpf::{
            aligned_memory::{AlignedMemory, Pod},
            ebpf::{HOST_ALIGN, MM_INPUT_START},
            memory_region::MemoryRegion,
        },
        solana_sdk_ids::bpf_loader_deprecated,
        solana_system_interface::MAX_PERMITTED_DATA_LENGTH,
        solana_transaction_context::{
            instruction::InstructionContext,
            instruction_accounts::BorrowedInstructionAccount, IndexOfAccount,
            MAX_ACCOUNTS_PER_INSTRUCTION,
        },
        std::mem::{self, size_of},
    };
    /// Modifies the memory mapping in serialization and CPI return for stricter_abi_and_runtime_constraints
    pub fn modify_memory_region_of_account(
        account: &mut BorrowedInstructionAccount<'_, '_>,
        region: &mut MemoryRegion,
    ) {
        region.len = account.get_data().len() as u64;
        if account.can_data_be_changed().is_ok() {
            region.writable = true;
            region.access_violation_handler_payload = Some(
                account.get_index_in_transaction(),
            );
        } else {
            region.writable = false;
            region.access_violation_handler_payload = None;
        }
    }
    /// Creates the memory mapping in serialization and CPI return for account_data_direct_mapping
    pub fn create_memory_region_of_account(
        account: &mut BorrowedInstructionAccount<'_, '_>,
        vaddr: u64,
    ) -> Result<MemoryRegion, InstructionError> {
        let can_data_be_changed = account.can_data_be_changed().is_ok();
        let mut memory_region = if can_data_be_changed && !account.is_shared() {
            MemoryRegion::new_writable(account.get_data_mut()?, vaddr)
        } else {
            MemoryRegion::new_readonly(account.get_data(), vaddr)
        };
        if can_data_be_changed {
            memory_region.access_violation_handler_payload = Some(
                account.get_index_in_transaction(),
            );
        }
        Ok(memory_region)
    }
    #[allow(dead_code)]
    enum SerializeAccount<'a, 'ix_data> {
        Account(IndexOfAccount, BorrowedInstructionAccount<'a, 'ix_data>),
        Duplicate(IndexOfAccount),
    }
    struct Serializer {
        buffer: AlignedMemory<HOST_ALIGN>,
        regions: Vec<MemoryRegion>,
        vaddr: u64,
        region_start: usize,
        is_loader_v1: bool,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
    }
    impl Serializer {
        fn new(
            size: usize,
            start_addr: u64,
            is_loader_v1: bool,
            stricter_abi_and_runtime_constraints: bool,
            account_data_direct_mapping: bool,
        ) -> Serializer {
            Serializer {
                buffer: AlignedMemory::with_capacity(size),
                regions: Vec::new(),
                region_start: 0,
                vaddr: start_addr,
                is_loader_v1,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
            }
        }
        fn fill_write(&mut self, num: usize, value: u8) -> std::io::Result<()> {
            self.buffer.fill_write(num, value)
        }
        fn write<T: Pod>(&mut self, value: T) -> u64 {
            self.debug_assert_alignment::<T>();
            let vaddr = self
                .vaddr
                .saturating_add(self.buffer.len() as u64)
                .saturating_sub(self.region_start as u64);
            unsafe {
                self.buffer.write_unchecked(value);
            }
            vaddr
        }
        fn write_all(&mut self, value: &[u8]) -> u64 {
            let vaddr = self
                .vaddr
                .saturating_add(self.buffer.len() as u64)
                .saturating_sub(self.region_start as u64);
            unsafe {
                self.buffer.write_all_unchecked(value);
            }
            vaddr
        }
        fn write_account(
            &mut self,
            account: &mut BorrowedInstructionAccount<'_, '_>,
        ) -> Result<u64, InstructionError> {
            if !self.stricter_abi_and_runtime_constraints {
                let vm_data_addr = self.vaddr.saturating_add(self.buffer.len() as u64);
                self.write_all(account.get_data());
                if !self.is_loader_v1 {
                    let align_offset = (account.get_data().len() as *const u8)
                        .align_offset(BPF_ALIGN_OF_U128);
                    self.fill_write(MAX_PERMITTED_DATA_INCREASE + align_offset, 0)
                        .map_err(|_| InstructionError::InvalidArgument)?;
                }
                Ok(vm_data_addr)
            } else {
                self.push_region();
                let vm_data_addr = self.vaddr;
                if !self.account_data_direct_mapping {
                    self.write_all(account.get_data());
                    if !self.is_loader_v1 {
                        self.fill_write(MAX_PERMITTED_DATA_INCREASE, 0)
                            .map_err(|_| InstructionError::InvalidArgument)?;
                    }
                }
                let address_space_reserved_for_account = if !self.is_loader_v1 {
                    account.get_data().len().saturating_add(MAX_PERMITTED_DATA_INCREASE)
                } else {
                    account.get_data().len()
                };
                if address_space_reserved_for_account > 0 {
                    if !self.account_data_direct_mapping {
                        self.push_region();
                        let region = self.regions.last_mut().unwrap();
                        modify_memory_region_of_account(account, region);
                    } else {
                        let new_region = create_memory_region_of_account(
                            account,
                            self.vaddr,
                        )?;
                        self.vaddr += address_space_reserved_for_account as u64;
                        self.regions.push(new_region);
                    }
                }
                if !self.is_loader_v1 {
                    let align_offset = (account.get_data().len() as *const u8)
                        .align_offset(BPF_ALIGN_OF_U128);
                    if !self.account_data_direct_mapping {
                        self.fill_write(align_offset, 0)
                            .map_err(|_| InstructionError::InvalidArgument)?;
                    } else {
                        self.fill_write(BPF_ALIGN_OF_U128, 0)
                            .map_err(|_| InstructionError::InvalidArgument)?;
                        self.region_start
                            += BPF_ALIGN_OF_U128.saturating_sub(align_offset);
                    }
                }
                Ok(vm_data_addr)
            }
        }
        fn push_region(&mut self) {
            let range = self.region_start..self.buffer.len();
            self.regions
                .push(
                    MemoryRegion::new_writable(
                        self.buffer.as_slice_mut().get_mut(range.clone()).unwrap(),
                        self.vaddr,
                    ),
                );
            self.region_start = range.end;
            self.vaddr += range.len() as u64;
        }
        fn finish(mut self) -> (AlignedMemory<HOST_ALIGN>, Vec<MemoryRegion>) {
            self.push_region();
            if true {
                match (&self.region_start, &self.buffer.len()) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::None,
                            );
                        }
                    }
                };
            }
            (self.buffer, self.regions)
        }
        fn debug_assert_alignment<T>(&self) {
            if true {
                if !(self.is_loader_v1
                    || self
                        .buffer
                        .as_slice()
                        .as_ptr_range()
                        .end
                        .align_offset(mem::align_of::<T>()) == 0)
                {
                    ::core::panicking::panic(
                        "assertion failed: self.is_loader_v1 ||\n    self.buffer.as_slice().as_ptr_range().end.align_offset(mem::align_of::<T>())\n        == 0",
                    )
                }
            }
        }
    }
    pub fn serialize_parameters(
        instruction_context: &InstructionContext,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        mask_out_rent_epoch_in_vm_serialization: bool,
    ) -> Result<
        (
            AlignedMemory<HOST_ALIGN>,
            Vec<MemoryRegion>,
            Vec<SerializedAccountMetadata>,
            usize,
        ),
        InstructionError,
    > {
        let num_ix_accounts = instruction_context.get_number_of_instruction_accounts();
        if num_ix_accounts > MAX_ACCOUNTS_PER_INSTRUCTION as IndexOfAccount {
            return Err(InstructionError::MaxAccountsExceeded);
        }
        let program_id = *instruction_context.get_program_key()?;
        let is_loader_deprecated = instruction_context.get_program_owner()?
            == bpf_loader_deprecated::id();
        let accounts = (0..instruction_context.get_number_of_instruction_accounts())
            .map(|instruction_account_index| {
                if let Some(index) = instruction_context
                    .is_instruction_account_duplicate(instruction_account_index)
                    .unwrap()
                {
                    SerializeAccount::Duplicate(index)
                } else {
                    let account = instruction_context
                        .try_borrow_instruction_account(instruction_account_index)
                        .unwrap();
                    SerializeAccount::Account(instruction_account_index, account)
                }
            })
            .collect::<Vec<_>>();
        if is_loader_deprecated {
            serialize_parameters_unaligned(
                accounts,
                instruction_context.get_instruction_data(),
                &program_id,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
                mask_out_rent_epoch_in_vm_serialization,
            )
        } else {
            serialize_parameters_aligned(
                accounts,
                instruction_context.get_instruction_data(),
                &program_id,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
                mask_out_rent_epoch_in_vm_serialization,
            )
        }
    }
    pub fn deserialize_parameters(
        instruction_context: &InstructionContext,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        buffer: &[u8],
        accounts_metadata: &[SerializedAccountMetadata],
    ) -> Result<(), InstructionError> {
        let is_loader_deprecated = instruction_context.get_program_owner()?
            == bpf_loader_deprecated::id();
        let account_lengths = accounts_metadata.iter().map(|a| a.original_data_len);
        if is_loader_deprecated {
            deserialize_parameters_unaligned(
                instruction_context,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
                buffer,
                account_lengths,
            )
        } else {
            deserialize_parameters_aligned(
                instruction_context,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
                buffer,
                account_lengths,
            )
        }
    }
    fn serialize_parameters_unaligned(
        accounts: Vec<SerializeAccount>,
        instruction_data: &[u8],
        program_id: &Pubkey,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        mask_out_rent_epoch_in_vm_serialization: bool,
    ) -> Result<
        (
            AlignedMemory<HOST_ALIGN>,
            Vec<MemoryRegion>,
            Vec<SerializedAccountMetadata>,
            usize,
        ),
        InstructionError,
    > {
        let mut size = size_of::<u64>();
        for account in &accounts {
            size += 1;
            match account {
                SerializeAccount::Duplicate(_) => {}
                SerializeAccount::Account(_, account) => {
                    size
                        += size_of::<u8>() + size_of::<u8>() + size_of::<Pubkey>()
                            + size_of::<u64>() + size_of::<u64>() + size_of::<Pubkey>()
                            + size_of::<u8>() + size_of::<u64>();
                    if !(stricter_abi_and_runtime_constraints
                        && account_data_direct_mapping)
                    {
                        size += account.get_data().len();
                    }
                }
            }
        }
        size += size_of::<u64>() + instruction_data.len() + size_of::<Pubkey>();
        let mut s = Serializer::new(
            size,
            MM_INPUT_START,
            true,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
        );
        let mut accounts_metadata: Vec<SerializedAccountMetadata> = Vec::with_capacity(
            accounts.len(),
        );
        s.write::<u64>((accounts.len() as u64).to_le());
        for account in accounts {
            match account {
                SerializeAccount::Duplicate(position) => {
                    accounts_metadata
                        .push(accounts_metadata.get(position as usize).unwrap().clone());
                    s.write(position as u8);
                }
                SerializeAccount::Account(_, mut account) => {
                    s.write::<u8>(NON_DUP_MARKER);
                    s.write::<u8>(account.is_signer() as u8);
                    s.write::<u8>(account.is_writable() as u8);
                    let vm_key_addr = s.write_all(account.get_key().as_ref());
                    let vm_lamports_addr = s
                        .write::<u64>(account.get_lamports().to_le());
                    s.write::<u64>((account.get_data().len() as u64).to_le());
                    let vm_data_addr = s.write_account(&mut account)?;
                    let vm_owner_addr = s.write_all(account.get_owner().as_ref());
                    #[allow(deprecated)] s.write::<u8>(account.is_executable() as u8);
                    let rent_epoch = if mask_out_rent_epoch_in_vm_serialization {
                        u64::MAX
                    } else {
                        account.get_rent_epoch()
                    };
                    s.write::<u64>(rent_epoch.to_le());
                    accounts_metadata
                        .push(SerializedAccountMetadata {
                            original_data_len: account.get_data().len(),
                            vm_key_addr,
                            vm_lamports_addr,
                            vm_owner_addr,
                            vm_data_addr,
                        });
                }
            };
        }
        s.write::<u64>((instruction_data.len() as u64).to_le());
        let instruction_data_offset = s.write_all(instruction_data);
        s.write_all(program_id.as_ref());
        let (mem, regions) = s.finish();
        Ok((mem, regions, accounts_metadata, instruction_data_offset as usize))
    }
    fn deserialize_parameters_unaligned<I: IntoIterator<Item = usize>>(
        instruction_context: &InstructionContext,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        buffer: &[u8],
        account_lengths: I,
    ) -> Result<(), InstructionError> {
        let mut start = size_of::<u64>();
        for (instruction_account_index, pre_len) in (0..instruction_context
            .get_number_of_instruction_accounts())
            .zip(account_lengths.into_iter())
        {
            let duplicate = instruction_context
                .is_instruction_account_duplicate(instruction_account_index)?;
            start += 1;
            if duplicate.is_none() {
                let mut borrowed_account = instruction_context
                    .try_borrow_instruction_account(instruction_account_index)?;
                start += size_of::<u8>();
                start += size_of::<u8>();
                start += size_of::<Pubkey>();
                let lamports = buffer
                    .get(start..start.saturating_add(8))
                    .map(<[u8; 8]>::try_from)
                    .and_then(Result::ok)
                    .map(u64::from_le_bytes)
                    .ok_or(InstructionError::InvalidArgument)?;
                if borrowed_account.get_lamports() != lamports {
                    borrowed_account.set_lamports(lamports)?;
                }
                start += size_of::<u64>() + size_of::<u64>();
                if !stricter_abi_and_runtime_constraints {
                    let data = buffer
                        .get(start..start + pre_len)
                        .ok_or(InstructionError::InvalidArgument)?;
                    match borrowed_account.can_data_be_resized(pre_len) {
                        Ok(()) => borrowed_account.set_data_from_slice(data)?,
                        Err(err) if borrowed_account.get_data() != data => {
                            return Err(err);
                        }
                        _ => {}
                    }
                } else if !account_data_direct_mapping
                    && borrowed_account.can_data_be_changed().is_ok()
                {
                    let data = buffer
                        .get(start..start + pre_len)
                        .ok_or(InstructionError::InvalidArgument)?;
                    borrowed_account.set_data_from_slice(data)?;
                } else if borrowed_account.get_data().len() != pre_len {
                    borrowed_account.set_data_length(pre_len)?;
                }
                if !(stricter_abi_and_runtime_constraints && account_data_direct_mapping)
                {
                    start += pre_len;
                }
                start += size_of::<Pubkey>() + size_of::<u8>() + size_of::<u64>();
            }
        }
        Ok(())
    }
    fn serialize_parameters_aligned(
        accounts: Vec<SerializeAccount>,
        instruction_data: &[u8],
        program_id: &Pubkey,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        mask_out_rent_epoch_in_vm_serialization: bool,
    ) -> Result<
        (
            AlignedMemory<HOST_ALIGN>,
            Vec<MemoryRegion>,
            Vec<SerializedAccountMetadata>,
            usize,
        ),
        InstructionError,
    > {
        let mut accounts_metadata = Vec::with_capacity(accounts.len());
        let mut size = size_of::<u64>();
        for account in &accounts {
            size += 1;
            match account {
                SerializeAccount::Duplicate(_) => size += 7,
                SerializeAccount::Account(_, account) => {
                    let data_len = account.get_data().len();
                    size
                        += size_of::<u8>() + size_of::<u8>() + size_of::<u8>()
                            + size_of::<u32>() + size_of::<Pubkey>()
                            + size_of::<Pubkey>() + size_of::<u64>() + size_of::<u64>()
                            + size_of::<u64>();
                    if !(stricter_abi_and_runtime_constraints
                        && account_data_direct_mapping)
                    {
                        size
                            += data_len + MAX_PERMITTED_DATA_INCREASE
                                + (data_len as *const u8).align_offset(BPF_ALIGN_OF_U128);
                    } else {
                        size += BPF_ALIGN_OF_U128;
                    }
                }
            }
        }
        size += size_of::<u64>() + instruction_data.len() + size_of::<Pubkey>();
        let mut s = Serializer::new(
            size,
            MM_INPUT_START,
            false,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
        );
        s.write::<u64>((accounts.len() as u64).to_le());
        for account in accounts {
            match account {
                SerializeAccount::Account(_, mut borrowed_account) => {
                    s.write::<u8>(NON_DUP_MARKER);
                    s.write::<u8>(borrowed_account.is_signer() as u8);
                    s.write::<u8>(borrowed_account.is_writable() as u8);
                    #[allow(deprecated)]
                    s.write::<u8>(borrowed_account.is_executable() as u8);
                    s.write_all(&[0u8, 0, 0, 0]);
                    let vm_key_addr = s.write_all(borrowed_account.get_key().as_ref());
                    let vm_owner_addr = s
                        .write_all(borrowed_account.get_owner().as_ref());
                    let vm_lamports_addr = s
                        .write::<u64>(borrowed_account.get_lamports().to_le());
                    s.write::<u64>((borrowed_account.get_data().len() as u64).to_le());
                    let vm_data_addr = s.write_account(&mut borrowed_account)?;
                    let rent_epoch = if mask_out_rent_epoch_in_vm_serialization {
                        u64::MAX
                    } else {
                        borrowed_account.get_rent_epoch()
                    };
                    s.write::<u64>(rent_epoch.to_le());
                    accounts_metadata
                        .push(SerializedAccountMetadata {
                            original_data_len: borrowed_account.get_data().len(),
                            vm_key_addr,
                            vm_owner_addr,
                            vm_lamports_addr,
                            vm_data_addr,
                        });
                }
                SerializeAccount::Duplicate(position) => {
                    accounts_metadata
                        .push(accounts_metadata.get(position as usize).unwrap().clone());
                    s.write::<u8>(position as u8);
                    s.write_all(&[0u8, 0, 0, 0, 0, 0, 0]);
                }
            };
        }
        s.write::<u64>((instruction_data.len() as u64).to_le());
        let instruction_data_offset = s.write_all(instruction_data);
        s.write_all(program_id.as_ref());
        let (mem, regions) = s.finish();
        Ok((mem, regions, accounts_metadata, instruction_data_offset as usize))
    }
    fn deserialize_parameters_aligned<I: IntoIterator<Item = usize>>(
        instruction_context: &InstructionContext,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
        buffer: &[u8],
        account_lengths: I,
    ) -> Result<(), InstructionError> {
        let mut start = size_of::<u64>();
        for (instruction_account_index, pre_len) in (0..instruction_context
            .get_number_of_instruction_accounts())
            .zip(account_lengths.into_iter())
        {
            let duplicate = instruction_context
                .is_instruction_account_duplicate(instruction_account_index)?;
            start += size_of::<u8>();
            if duplicate.is_some() {
                start += 7;
            } else {
                let mut borrowed_account = instruction_context
                    .try_borrow_instruction_account(instruction_account_index)?;
                start
                    += size_of::<u8>() + size_of::<u8>() + size_of::<u8>()
                        + size_of::<u32>() + size_of::<Pubkey>();
                let owner = buffer
                    .get(start..start + size_of::<Pubkey>())
                    .ok_or(InstructionError::InvalidArgument)?;
                start += size_of::<Pubkey>();
                let lamports = buffer
                    .get(start..start.saturating_add(8))
                    .map(<[u8; 8]>::try_from)
                    .and_then(Result::ok)
                    .map(u64::from_le_bytes)
                    .ok_or(InstructionError::InvalidArgument)?;
                if borrowed_account.get_lamports() != lamports {
                    borrowed_account.set_lamports(lamports)?;
                }
                start += size_of::<u64>();
                let post_len = buffer
                    .get(start..start.saturating_add(8))
                    .map(<[u8; 8]>::try_from)
                    .and_then(Result::ok)
                    .map(u64::from_le_bytes)
                    .ok_or(InstructionError::InvalidArgument)? as usize;
                start += size_of::<u64>();
                if post_len.saturating_sub(pre_len) > MAX_PERMITTED_DATA_INCREASE
                    || post_len > MAX_PERMITTED_DATA_LENGTH as usize
                {
                    return Err(InstructionError::InvalidRealloc);
                }
                if !stricter_abi_and_runtime_constraints {
                    let data = buffer
                        .get(start..start + post_len)
                        .ok_or(InstructionError::InvalidArgument)?;
                    match borrowed_account.can_data_be_resized(post_len) {
                        Ok(()) => borrowed_account.set_data_from_slice(data)?,
                        Err(err) if borrowed_account.get_data() != data => {
                            return Err(err);
                        }
                        _ => {}
                    }
                } else if !account_data_direct_mapping
                    && borrowed_account.can_data_be_changed().is_ok()
                {
                    let data = buffer
                        .get(start..start + post_len)
                        .ok_or(InstructionError::InvalidArgument)?;
                    borrowed_account.set_data_from_slice(data)?;
                } else if borrowed_account.get_data().len() != post_len {
                    borrowed_account.set_data_length(post_len)?;
                }
                start
                    += if !(stricter_abi_and_runtime_constraints
                        && account_data_direct_mapping)
                    {
                        let alignment_offset = (pre_len as *const u8)
                            .align_offset(BPF_ALIGN_OF_U128);
                        pre_len
                            .saturating_add(MAX_PERMITTED_DATA_INCREASE)
                            .saturating_add(alignment_offset)
                    } else {
                        BPF_ALIGN_OF_U128
                    };
                start += size_of::<u64>();
                if borrowed_account.get_owner().to_bytes() != owner {
                    borrowed_account.set_owner(owner)?;
                }
            }
        }
        Ok(())
    }
}
pub mod stable_log {
    //! Stable program log messages
    //!
    //! The format of these log messages should not be modified to avoid breaking downstream consumers
    //! of program logging
    use {
        base64::{prelude::BASE64_STANDARD, Engine},
        itertools::Itertools, solana_pubkey::Pubkey,
        solana_svm_log_collector::{ic_logger_msg, LogCollector},
        std::{cell::RefCell, rc::Rc},
    };
    /// Log a program invoke.
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program <address> invoke [<depth>]"
    /// ```
    pub fn program_invoke(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        program_id: &Pubkey,
        invoke_depth: usize,
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!(
                                "Program {0} invoke [{1}]",
                                program_id,
                                invoke_depth,
                            ),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!(
                                    "Program {0} invoke [{1}]",
                                    program_id,
                                    invoke_depth,
                                ),
                            )
                        }),
                    );
            }
        }
    }
    /// Log a message from the program itself.
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program log: <program-generated output>"
    /// ```
    ///
    /// That is, any program-generated output is guaranteed to be prefixed by "Program log: "
    pub fn program_log(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        message: &str,
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!("Program log: {0}", message),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Program log: {0}", message),
                            )
                        }),
                    );
            }
        }
    }
    /// Emit a program data.
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program data: <binary-data-in-base64>*"
    /// ```
    ///
    /// That is, any program-generated output is guaranteed to be prefixed by "Program data: "
    pub fn program_data(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        data: &[&[u8]],
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!(
                                "Program data: {0}",
                                data.iter().map(|v| BASE64_STANDARD.encode(v)).join(" "),
                            ),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!(
                                    "Program data: {0}",
                                    data.iter().map(|v| BASE64_STANDARD.encode(v)).join(" "),
                                ),
                            )
                        }),
                    );
            }
        }
    }
    /// Log return data as from the program itself. This line will not be present if no return
    /// data was set, or if the return data was set to zero length.
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program return: <program-id> <program-generated-data-in-base64>"
    /// ```
    ///
    /// That is, any program-generated output is guaranteed to be prefixed by "Program return: "
    pub fn program_return(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        program_id: &Pubkey,
        data: &[u8],
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!(
                                "Program return: {0} {1}",
                                program_id,
                                BASE64_STANDARD.encode(data),
                            ),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!(
                                    "Program return: {0} {1}",
                                    program_id,
                                    BASE64_STANDARD.encode(data),
                                ),
                            )
                        }),
                    );
            }
        }
    }
    /// Log successful program execution.
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program <address> success"
    /// ```
    pub fn program_success(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        program_id: &Pubkey,
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!("Program {0} success", program_id),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Program {0} success", program_id),
                            )
                        }),
                    );
            }
        }
    }
    /// Log program execution failure
    ///
    /// The general form is:
    ///
    /// ```notrust
    /// "Program <address> failed: <program error details>"
    /// ```
    pub fn program_failure<E: std::fmt::Display>(
        log_collector: &Option<Rc<RefCell<LogCollector>>>,
        program_id: &Pubkey,
        err: &E,
    ) {
        {
            {
                {
                    let lvl = ::log::Level::Debug;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api::log(
                            { ::log::__private_api::GlobalLogger },
                            format_args!("Program {0} failed: {1}", program_id, err),
                            lvl,
                            &(
                                "solana_runtime::message_processor::stable_log",
                                "solana_program_runtime::stable_log",
                                ::log::__private_api::loc(),
                            ),
                            (),
                        );
                    }
                }
            }
        };
        if let Some(log_collector) = log_collector.as_ref() {
            if let Ok(mut log_collector) = log_collector.try_borrow_mut() {
                log_collector
                    .log(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Program {0} failed: {1}", program_id, err),
                            )
                        }),
                    );
            }
        }
    }
}
pub mod sysvar_cache {
    #[allow(deprecated)]
    use solana_sysvar::{fees::Fees, recent_blockhashes::RecentBlockhashes};
    use {
        crate::invoke_context::InvokeContext, serde::de::DeserializeOwned,
        solana_clock::Clock, solana_epoch_rewards::EpochRewards,
        solana_epoch_schedule::EpochSchedule,
        solana_instruction::error::InstructionError,
        solana_last_restart_slot::LastRestartSlot, solana_pubkey::Pubkey,
        solana_rent::Rent, solana_sdk_ids::sysvar, solana_slot_hashes::SlotHashes,
        solana_stake_interface::stake_history::StakeHistory,
        solana_svm_type_overrides::sync::Arc, solana_sysvar::SysvarSerialize,
        solana_sysvar_id::SysvarId,
        solana_transaction_context::{instruction::InstructionContext, IndexOfAccount},
    };
    pub struct SysvarCache {
        clock: Option<Vec<u8>>,
        epoch_schedule: Option<Vec<u8>>,
        epoch_rewards: Option<Vec<u8>>,
        rent: Option<Vec<u8>>,
        slot_hashes: Option<Vec<u8>>,
        stake_history: Option<Vec<u8>>,
        last_restart_slot: Option<Vec<u8>>,
        slot_hashes_obj: Option<Arc<SlotHashes>>,
        stake_history_obj: Option<Arc<StakeHistory>>,
        #[allow(deprecated)]
        fees: Option<Fees>,
        #[allow(deprecated)]
        recent_blockhashes: Option<RecentBlockhashes>,
    }
    #[automatically_derived]
    impl ::core::default::Default for SysvarCache {
        #[inline]
        fn default() -> SysvarCache {
            SysvarCache {
                clock: ::core::default::Default::default(),
                epoch_schedule: ::core::default::Default::default(),
                epoch_rewards: ::core::default::Default::default(),
                rent: ::core::default::Default::default(),
                slot_hashes: ::core::default::Default::default(),
                stake_history: ::core::default::Default::default(),
                last_restart_slot: ::core::default::Default::default(),
                slot_hashes_obj: ::core::default::Default::default(),
                stake_history_obj: ::core::default::Default::default(),
                fees: ::core::default::Default::default(),
                recent_blockhashes: ::core::default::Default::default(),
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SysvarCache {
        #[inline]
        fn clone(&self) -> SysvarCache {
            SysvarCache {
                clock: ::core::clone::Clone::clone(&self.clock),
                epoch_schedule: ::core::clone::Clone::clone(&self.epoch_schedule),
                epoch_rewards: ::core::clone::Clone::clone(&self.epoch_rewards),
                rent: ::core::clone::Clone::clone(&self.rent),
                slot_hashes: ::core::clone::Clone::clone(&self.slot_hashes),
                stake_history: ::core::clone::Clone::clone(&self.stake_history),
                last_restart_slot: ::core::clone::Clone::clone(&self.last_restart_slot),
                slot_hashes_obj: ::core::clone::Clone::clone(&self.slot_hashes_obj),
                stake_history_obj: ::core::clone::Clone::clone(&self.stake_history_obj),
                fees: ::core::clone::Clone::clone(&self.fees),
                recent_blockhashes: ::core::clone::Clone::clone(&self.recent_blockhashes),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SysvarCache {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "clock",
                "epoch_schedule",
                "epoch_rewards",
                "rent",
                "slot_hashes",
                "stake_history",
                "last_restart_slot",
                "slot_hashes_obj",
                "stake_history_obj",
                "fees",
                "recent_blockhashes",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.clock,
                &self.epoch_schedule,
                &self.epoch_rewards,
                &self.rent,
                &self.slot_hashes,
                &self.stake_history,
                &self.last_restart_slot,
                &self.slot_hashes_obj,
                &self.stake_history_obj,
                &self.fees,
                &&self.recent_blockhashes,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "SysvarCache",
                names,
                values,
            )
        }
    }
    const FEES_ID: Pubkey = Pubkey::from_str_const(
        "SysvarFees111111111111111111111111111111111",
    );
    const RECENT_BLOCKHASHES_ID: Pubkey = Pubkey::from_str_const(
        "SysvarRecentB1ockHashes11111111111111111111",
    );
    impl SysvarCache {
        /// Overwrite a sysvar. For testing purposes only.
        #[allow(deprecated)]
        pub fn set_sysvar_for_tests<T: SysvarSerialize + SysvarId>(
            &mut self,
            sysvar: &T,
        ) {
            let data = bincode::serialize(sysvar).expect("Failed to serialize sysvar.");
            let sysvar_id = T::id();
            match sysvar_id {
                sysvar::clock::ID => {
                    self.clock = Some(data);
                }
                sysvar::epoch_rewards::ID => {
                    self.epoch_rewards = Some(data);
                }
                sysvar::epoch_schedule::ID => {
                    self.epoch_schedule = Some(data);
                }
                FEES_ID => {
                    let fees: Fees = bincode::deserialize(&data)
                        .expect("Failed to deserialize Fees sysvar.");
                    self.fees = Some(fees);
                }
                sysvar::last_restart_slot::ID => {
                    self.last_restart_slot = Some(data);
                }
                RECENT_BLOCKHASHES_ID => {
                    let recent_blockhashes: RecentBlockhashes = bincode::deserialize(
                            &data,
                        )
                        .expect("Failed to deserialize RecentBlockhashes sysvar.");
                    self.recent_blockhashes = Some(recent_blockhashes);
                }
                sysvar::rent::ID => {
                    self.rent = Some(data);
                }
                sysvar::slot_hashes::ID => {
                    let slot_hashes: SlotHashes = bincode::deserialize(&data)
                        .expect("Failed to deserialize SlotHashes sysvar.");
                    self.slot_hashes = Some(data);
                    self.slot_hashes_obj = Some(Arc::new(slot_hashes));
                }
                sysvar::stake_history::ID => {
                    let stake_history: StakeHistory = bincode::deserialize(&data)
                        .expect("Failed to deserialize StakeHistory sysvar.");
                    self.stake_history = Some(data);
                    self.stake_history_obj = Some(Arc::new(stake_history));
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unrecognized Sysvar ID: {0}", sysvar_id),
                    );
                }
            }
        }
        pub fn sysvar_id_to_buffer(&self, sysvar_id: &Pubkey) -> &Option<Vec<u8>> {
            if Clock::check_id(sysvar_id) {
                &self.clock
            } else if EpochSchedule::check_id(sysvar_id) {
                &self.epoch_schedule
            } else if EpochRewards::check_id(sysvar_id) {
                &self.epoch_rewards
            } else if Rent::check_id(sysvar_id) {
                &self.rent
            } else if SlotHashes::check_id(sysvar_id) {
                &self.slot_hashes
            } else if StakeHistory::check_id(sysvar_id) {
                &self.stake_history
            } else if LastRestartSlot::check_id(sysvar_id) {
                &self.last_restart_slot
            } else {
                &None
            }
        }
        fn get_sysvar_obj<T: DeserializeOwned>(
            &self,
            sysvar_id: &Pubkey,
        ) -> Result<Arc<T>, InstructionError> {
            if let Some(sysvar_buf) = self.sysvar_id_to_buffer(sysvar_id) {
                bincode::deserialize(sysvar_buf)
                    .map(Arc::new)
                    .map_err(|_| InstructionError::UnsupportedSysvar)
            } else {
                Err(InstructionError::UnsupportedSysvar)
            }
        }
        pub fn get_clock(&self) -> Result<Arc<Clock>, InstructionError> {
            self.get_sysvar_obj(&Clock::id())
        }
        pub fn get_epoch_schedule(
            &self,
        ) -> Result<Arc<EpochSchedule>, InstructionError> {
            self.get_sysvar_obj(&EpochSchedule::id())
        }
        pub fn get_epoch_rewards(&self) -> Result<Arc<EpochRewards>, InstructionError> {
            self.get_sysvar_obj(&EpochRewards::id())
        }
        pub fn get_rent(&self) -> Result<Arc<Rent>, InstructionError> {
            self.get_sysvar_obj(&Rent::id())
        }
        pub fn get_last_restart_slot(
            &self,
        ) -> Result<Arc<LastRestartSlot>, InstructionError> {
            self.get_sysvar_obj(&LastRestartSlot::id())
        }
        pub fn get_stake_history(&self) -> Result<Arc<StakeHistory>, InstructionError> {
            self.stake_history_obj.clone().ok_or(InstructionError::UnsupportedSysvar)
        }
        pub fn get_slot_hashes(&self) -> Result<Arc<SlotHashes>, InstructionError> {
            self.slot_hashes_obj.clone().ok_or(InstructionError::UnsupportedSysvar)
        }
        #[deprecated]
        #[allow(deprecated)]
        pub fn get_fees(&self) -> Result<Arc<Fees>, InstructionError> {
            self.fees.clone().ok_or(InstructionError::UnsupportedSysvar).map(Arc::new)
        }
        #[deprecated]
        #[allow(deprecated)]
        pub fn get_recent_blockhashes(
            &self,
        ) -> Result<Arc<RecentBlockhashes>, InstructionError> {
            self.recent_blockhashes
                .clone()
                .ok_or(InstructionError::UnsupportedSysvar)
                .map(Arc::new)
        }
        pub fn fill_missing_entries<F: FnMut(&Pubkey, &mut dyn FnMut(&[u8]))>(
            &mut self,
            mut get_account_data: F,
        ) {
            if self.clock.is_none() {
                get_account_data(
                    &Clock::id(),
                    &mut |data: &[u8]| {
                        if bincode::deserialize::<Clock>(data).is_ok() {
                            self.clock = Some(data.to_vec());
                        }
                    },
                );
            }
            if self.epoch_schedule.is_none() {
                get_account_data(
                    &EpochSchedule::id(),
                    &mut |data: &[u8]| {
                        if bincode::deserialize::<EpochSchedule>(data).is_ok() {
                            self.epoch_schedule = Some(data.to_vec());
                        }
                    },
                );
            }
            if self.epoch_rewards.is_none() {
                get_account_data(
                    &EpochRewards::id(),
                    &mut |data: &[u8]| {
                        if bincode::deserialize::<EpochRewards>(data).is_ok() {
                            self.epoch_rewards = Some(data.to_vec());
                        }
                    },
                );
            }
            if self.rent.is_none() {
                get_account_data(
                    &Rent::id(),
                    &mut |data: &[u8]| {
                        if bincode::deserialize::<Rent>(data).is_ok() {
                            self.rent = Some(data.to_vec());
                        }
                    },
                );
            }
            if self.slot_hashes.is_none() {
                get_account_data(
                    &SlotHashes::id(),
                    &mut |data: &[u8]| {
                        if let Ok(obj) = bincode::deserialize::<SlotHashes>(data) {
                            self.slot_hashes = Some(data.to_vec());
                            self.slot_hashes_obj = Some(Arc::new(obj));
                        }
                    },
                );
            }
            if self.stake_history.is_none() {
                get_account_data(
                    &StakeHistory::id(),
                    &mut |data: &[u8]| {
                        if let Ok(obj) = bincode::deserialize::<StakeHistory>(data) {
                            self.stake_history = Some(data.to_vec());
                            self.stake_history_obj = Some(Arc::new(obj));
                        }
                    },
                );
            }
            if self.last_restart_slot.is_none() {
                get_account_data(
                    &LastRestartSlot::id(),
                    &mut |data: &[u8]| {
                        if bincode::deserialize::<LastRestartSlot>(data).is_ok() {
                            self.last_restart_slot = Some(data.to_vec());
                        }
                    },
                );
            }
            #[allow(deprecated)]
            if self.fees.is_none() {
                get_account_data(
                    &Fees::id(),
                    &mut |data: &[u8]| {
                        if let Ok(fees) = bincode::deserialize(data) {
                            self.fees = Some(fees);
                        }
                    },
                );
            }
            #[allow(deprecated)]
            if self.recent_blockhashes.is_none() {
                get_account_data(
                    &RecentBlockhashes::id(),
                    &mut |data: &[u8]| {
                        if let Ok(recent_blockhashes) = bincode::deserialize(data) {
                            self.recent_blockhashes = Some(recent_blockhashes);
                        }
                    },
                );
            }
        }
        pub fn reset(&mut self) {
            *self = Self::default();
        }
    }
    /// These methods facilitate a transition from fetching sysvars from keyed
    /// accounts to fetching from the sysvar cache without breaking consensus. In
    /// order to keep consistent behavior, they continue to enforce legacy checks
    /// despite dynamically loading them instead of deserializing from account data.
    pub mod get_sysvar_with_account_check {
        use super::*;
        fn check_sysvar_account<S: SysvarId>(
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<(), InstructionError> {
            if !S::check_id(
                instruction_context
                    .get_key_of_instruction_account(instruction_account_index)?,
            ) {
                return Err(InstructionError::InvalidArgument);
            }
            Ok(())
        }
        pub fn clock(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<Clock>, InstructionError> {
            check_sysvar_account::<
                Clock,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_clock()
        }
        pub fn rent(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<Rent>, InstructionError> {
            check_sysvar_account::<
                Rent,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_rent()
        }
        pub fn slot_hashes(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<SlotHashes>, InstructionError> {
            check_sysvar_account::<
                SlotHashes,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_slot_hashes()
        }
        #[allow(deprecated)]
        pub fn recent_blockhashes(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<RecentBlockhashes>, InstructionError> {
            check_sysvar_account::<
                RecentBlockhashes,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_recent_blockhashes()
        }
        pub fn stake_history(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<StakeHistory>, InstructionError> {
            check_sysvar_account::<
                StakeHistory,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_stake_history()
        }
        pub fn last_restart_slot(
            invoke_context: &InvokeContext,
            instruction_context: &InstructionContext,
            instruction_account_index: IndexOfAccount,
        ) -> Result<Arc<LastRestartSlot>, InstructionError> {
            check_sysvar_account::<
                LastRestartSlot,
            >(instruction_context, instruction_account_index)?;
            invoke_context.get_sysvar_cache().get_last_restart_slot()
        }
    }
}
pub mod __private {
    pub use {
        solana_account::ReadableAccount, solana_hash::Hash,
        solana_instruction::error::InstructionError, solana_rent::Rent,
        solana_transaction_context::TransactionContext,
    };
}
