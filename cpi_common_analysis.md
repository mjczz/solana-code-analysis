# cpi_common 方法深度分析

> 文件: `solana-program-runtime.rs`  
> 函数: `pub fn cpi_common<S: SyscallInvokeSigned>`  
> 行号: 1099-1211  
> 分析日期: 2025-11-25

---

## 目录

1. [函数签名](#函数签名)
2. [执行流程概览](#执行流程概览)
3. [详细步骤分析](#详细步骤分析)
4. [数据流图](#数据流图)
5. [错误处理](#错误处理)
6. [性能优化](#性能优化)
7. [Feature Gates 影响](#feature-gates-影响)
8. [使用示例](#使用示例)

---

## 函数签名

```rust
pub fn cpi_common<S: SyscallInvokeSigned>(
    invoke_context: &mut InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &mut MemoryMapping,
) -> Result<u64, Error>
```

### 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `invoke_context` | `&mut InvokeContext` | 程序执行上下文（可变引用） |
| `instruction_addr` | `u64` | VM 中指令结构的地址 |
| `account_infos_addr` | `u64` | VM 中账户信息数组的地址 |
| `account_infos_len` | `u64` | 账户信息数组的长度 |
| `signers_seeds_addr` | `u64` | VM 中签名者种子数组的地址 |
| `signers_seeds_len` | `u64` | 签名者种子数组的长度 |
| `memory_mapping` | `&mut MemoryMapping` | VM 内存映射（可变引用） |

### 泛型参数

- `S: SyscallInvokeSigned`: 实现了 `SyscallInvokeSigned` trait 的类型
  - Rust ABI: 使用 `translate_instruction_rust`, `translate_accounts_rust`, `translate_signers_rust`
  - C ABI: 使用 `translate_instruction_c`, `translate_accounts_c`, `translate_signers_c`

### 返回值

- `Result<u64, Error>`: 成功返回 `SUCCESS` (0)，失败返回错误

---

## 执行流程概览

```
┌─────────────────────────────────────────────────────────────┐
│                    cpi_common 执行流程                        │
└─────────────────────────────────────────────────────────────┘

1. 预处理阶段
   ├─ 消耗 invoke_units (946 或 1000 CU)
   ├─ 停止执行时间计时器
   └─ 获取 feature flags

2. 翻译阶段
   ├─ 翻译指令 (S::translate_instruction)
   ├─ 获取调用者程序 ID
   ├─ 翻译签名者种子 (S::translate_signers)
   ├─ 检查程序授权 (check_authorized_program)
   └─ 翻译账户信息 (S::translate_accounts)

3. 准备阶段
   ├─ 准备下一条指令 (prepare_next_instruction)
   └─ [stricter_abi] 更新被调用账户 (update_callee_account)

4. 执行阶段
   └─ 执行指令 (process_instruction)

5. 同步阶段
   ├─ 更新调用者账户信息 (update_caller_account)
   └─ [stricter_abi] 更新调用者账户区域 (update_caller_account_region)

6. 完成阶段
   ├─ 重启执行时间计时器
   └─ 返回 SUCCESS (0)
```

---

## 详细步骤分析

### 步骤 1: 预处理阶段

#### 1.1 消耗计算单元

```rust
consume_compute_meter(
    invoke_context,
    invoke_context.get_execution_cost().invoke_units,
)?;
```

**目的**: 为 CPI 调用本身消耗计算单元

**成本**:
- SIMD-0339 激活: 946 CU
- 默认: 1000 CU

**失败条件**: 如果剩余 CU 不足，返回 `ComputationalBudgetExceeded`

#### 1.2 停止执行时间计时器

```rust
if let Some(execute_time) = invoke_context.execute_time.as_mut() {
    execute_time.stop();
    invoke_context.timings.execute_us += execute_time.as_us();
}
```

**目的**: 
- 停止当前程序的执行时间计时
- 累加到总执行时间统计中
- 为被调用程序准备新的计时器

#### 1.3 获取 Feature Flags

```rust
let stricter_abi_and_runtime_constraints = invoke_context
    .get_feature_set()
    .stricter_abi_and_runtime_constraints;

let account_data_direct_mapping = invoke_context
    .get_feature_set()
    .account_data_direct_mapping;

let check_aligned = invoke_context.get_check_aligned();
```

**Feature Flags 说明**:

| Flag | 作用 |
|------|------|
| `stricter_abi_and_runtime_constraints` | 启用更严格的 ABI 约束和运行时检查 |
| `account_data_direct_mapping` | 启用账户数据直接映射到 VM 内存 |
| `check_aligned` | 检查内存对齐（非 deprecated loader） |

---

### 步骤 2: 翻译阶段

#### 2.1 翻译指令

```rust
let instruction = S::translate_instruction(
    instruction_addr,
    memory_mapping,
    invoke_context,
    check_aligned,
)?;
```

**操作**:
1. 从 VM 内存读取指令结构
2. 翻译 `program_id`
3. 翻译 `accounts` 数组（AccountMeta）
4. 翻译 `data` 字节数组
5. 检查指令大小限制

**Rust ABI 结构**:
```rust
struct StableInstruction {
    program_id: Pubkey,
    accounts: VmSlice<AccountMeta>,
    data: VmSlice<u8>,
}
```

**C ABI 结构**:
```rust
#[repr(C)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
}
```

**计算单元消耗**:
```rust
// 数据翻译成本
let data_cost = (data.len() as u64) / cpi_bytes_per_unit;

// SIMD-0339: 增加 AccountMeta 翻译成本
if increase_cpi_account_info_limit {
    let account_meta_cost = (accounts.len() * size_of::<AccountMeta>() as u64) 
        / cpi_bytes_per_unit;
    total_cost += account_meta_cost;
}
```

**限制检查**:
- `accounts.len() <= MAX_ACCOUNTS_PER_INSTRUCTION` (256)
- `data.len() <= MAX_INSTRUCTION_DATA_LEN` (10 KB)

#### 2.2 获取调用者程序 ID

```rust
let transaction_context = &invoke_context.transaction_context;
let instruction_context = transaction_context.get_current_instruction_context()?;
let caller_program_id = instruction_context.get_program_key()?;
```

**目的**: 获取当前正在执行的程序 ID，用于：
- 验证签名者种子
- 检查权限提升
- 日志记录

#### 2.3 翻译签名者种子

```rust
let signers = S::translate_signers(
    caller_program_id,
    signers_seeds_addr,
    signers_seeds_len,
    memory_mapping,
    check_aligned,
)?;
```

**操作**:
1. 翻译签名者种子数组
2. 对每组种子调用 `Pubkey::create_program_address()`
3. 生成 PDA (Program Derived Address)

**Rust ABI 结构**:
```rust
// signers_seeds: &[&[&[u8]]]
// 外层数组: 多个签名者
// 中层数组: 每个签名者的种子
// 内层数组: 每个种子的字节
```

**C ABI 结构**:
```rust
#[repr(C)]
struct SolSignerSeedsC {
    addr: u64,  // 指向 SolSignerSeedC 数组
    len: u64,   // 种子数量
}

#[repr(C)]
struct SolSignerSeedC {
    addr: u64,  // 指向字节数组
    len: u64,   // 字节长度
}
```

**限制检查**:
- `signers.len() <= MAX_SIGNERS` (16)
- 每组种子: `seeds.len() <= MAX_SEEDS` (16)

**示例**:
```rust
// 生成 PDA
let (pda, bump) = Pubkey::find_program_address(
    &[b"seed1", b"seed2"],
    &program_id,
);

// CPI 时使用 PDA 签名
invoke_signed(
    &instruction,
    &accounts,
    &[&[b"seed1", b"seed2", &[bump]]],
)?;
```

#### 2.4 检查程序授权

```rust
check_authorized_program(
    &instruction.program_id,
    &instruction.data,
    invoke_context,
)?;
```

**禁止调用的程序**:

1. **Native Loader** (`NativeLoader1111111111111111111111111111111`)
   - 原因: 内置程序加载器，不应被 CPI 调用

2. **BPF Loader Deprecated** (`BPFLoader1111111111111111111111111111111`)
   - 原因: 已弃用的加载器

3. **BPF Loader** (`BPFLoader2111111111111111111111111111111111`)
   - 原因: 程序加载器，不应被 CPI 调用

4. **BPF Loader Upgradeable** (`BPFLoaderUpgradeab1e11111111111111111111111`)
   - 例外: 允许以下指令
     - `Upgrade` (需要 feature gate)
     - `SetAuthority` (需要 feature gate)
     - `SetAuthorityChecked` (需要 feature gate)
     - `ExtendProgramChecked` (需要 feature gate)
     - `Close`

5. **预编译程序**
   - Ed25519 验证
   - Secp256k1 恢复
   - 等等

**检查逻辑**:
```rust
fn check_authorized_program(
    program_id: &Pubkey,
    instruction_data: &[u8],
    invoke_context: &InvokeContext,
) -> Result<(), Error> {
    if native_loader::check_id(program_id) 
        || bpf_loader::check_id(program_id)
        || bpf_loader_deprecated::check_id(program_id)
        || (bpf_loader_upgradeable::check_id(program_id)
            && !is_allowed_upgradeable_instruction(instruction_data, invoke_context))
        || invoke_context.is_precompile(program_id)
    {
        return Err(Box::new(CpiError::ProgramNotSupported(*program_id)));
    }
    Ok(())
}
```

#### 2.5 翻译账户信息

```rust
let mut accounts = S::translate_accounts(
    account_infos_addr,
    account_infos_len,
    memory_mapping,
    invoke_context,
    check_aligned,
)?;
```

**操作**:
1. 翻译账户信息数组
2. 创建 `CallerAccount` 结构
3. 检查账户数量限制
4. 验证账户权限

**Rust ABI 结构**:
```rust
pub struct AccountInfo<'a> {
    pub key: &'a Pubkey,
    pub lamports: Rc<RefCell<&'a mut u64>>,
    pub data: Rc<RefCell<&'a mut [u8]>>,
    pub owner: &'a Pubkey,
    pub rent_epoch: Epoch,
    pub is_signer: bool,
    pub is_writable: bool,
    pub executable: bool,
}
```

**C ABI 结构**:
```rust
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
```

**翻译结果**:
```rust
pub struct TranslatedAccount<'a> {
    pub index_in_caller: IndexOfAccount,
    pub caller_account: CallerAccount<'a>,
    pub update_caller_account_region: bool,
    pub update_caller_account_info: bool,
}

pub struct CallerAccount<'a> {
    pub lamports: &'a mut u64,
    pub owner: &'a mut Pubkey,
    pub original_data_len: usize,
    pub serialized_data: &'a mut [u8],
    pub vm_data_addr: u64,
    pub ref_to_len_in_vm: &'a mut u64,
}
```

**限制检查**:
- SIMD-0339: `account_infos.len() <= 255`
- `increase_tx_account_lock_limit`: `account_infos.len() <= 128`
- 默认: `account_infos.len() <= 64`

**计算单元消耗** (SIMD-0339):
```rust
let account_infos_bytes = account_infos.len() * ACCOUNT_INFO_BYTE_SIZE; // 80 bytes
let cost = account_infos_bytes / cpi_bytes_per_unit; // 250 bytes/CU
```

---

### 步骤 3: 准备阶段

#### 3.1 准备下一条指令

```rust
invoke_context.prepare_next_instruction(instruction, &signers)?;
```

**操作**:
1. 配置交易上下文的下一条指令
2. 构建 `instruction_accounts` 列表
3. 检查权限提升
4. 设置指令数据

**权限检查**:

```rust
// 检查可写权限提升
if instruction_account.is_writable() && !caller_instruction_account.is_writable() {
    ic_msg!(invoke_context, "{}'s writable privilege escalated", account_key);
    return Err(InstructionError::PrivilegeEscalation);
}

// 检查签名者权限提升
if instruction_account.is_signer() 
    && !(caller_instruction_account.is_signer() || signers.contains(account_key))
{
    ic_msg!(invoke_context, "{}'s signer privilege escalated", account_key);
    return Err(InstructionError::PrivilegeEscalation);
}
```

**重复账户处理**:
```rust
// 如果账户已在列表中，合并权限
if index_in_callee < instruction_accounts.len() {
    let existing = &mut instruction_accounts[index_in_callee];
    existing.set_is_signer(existing.is_signer() || account_meta.is_signer);
    existing.set_is_writable(existing.is_writable() || account_meta.is_writable);
}
```

#### 3.2 更新被调用账户（stricter_abi 模式）

```rust
if stricter_abi_and_runtime_constraints {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    
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
        
        translated_account.update_caller_account_region = 
            translated_account.update_caller_account_info || update_caller;
    }
}
```

**`update_callee_account` 操作**:

1. **更新 Lamports**:
```rust
if callee_account.get_lamports() != *caller_account.lamports {
    callee_account.set_lamports(*caller_account.lamports)?;
}
```

2. **更新数据长度**:
```rust
let prev_len = callee_account.get_data().len();
let post_len = *caller_account.ref_to_len_in_vm as usize;

if prev_len != post_len {
    // 检查地址空间预留
    let address_space_reserved = if is_caller_loader_deprecated {
        caller_account.original_data_len
    } else {
        caller_account.original_data_len + MAX_PERMITTED_DATA_INCREASE
    };
    
    if post_len > address_space_reserved {
        return Err(InstructionError::InvalidRealloc);
    }
    
    callee_account.set_data_length(post_len)?;
    must_update_caller = true;
}
```

3. **更新数据内容**:
```rust
if !account_data_direct_mapping && callee_account.can_data_be_changed().is_ok() {
    callee_account.set_data_from_slice(caller_account.serialized_data)?;
}
```

4. **更新所有者**:
```rust
if callee_account.get_owner() != caller_account.owner {
    callee_account.set_owner(caller_account.owner.as_ref())?;
    must_update_caller = true;
}
```

**返回值**: `bool` - 是否需要更新调用者账户

---

### 步骤 4: 执行阶段

```rust
let mut compute_units_consumed = 0;
invoke_context.process_instruction(
    &mut compute_units_consumed,
    &mut ExecuteTimings::default(),
)?;
```

**操作**:
1. 压栈（`invoke_context.push()`）
2. 执行被调用程序（`process_executable_chain()`）
3. 出栈（`invoke_context.pop()`）

**执行流程**:
```
push()
  ├─ 检查重入
  ├─ 压入 syscall_context
  └─ 压入 transaction_context

process_executable_chain()
  ├─ 确定程序 ID
  ├─ 从缓存获取程序
  ├─ 设置返回数据
  ├─ 记录日志
  ├─ 创建 EbpfVm
  ├─ 执行程序
  └─ 处理结果

pop()
  ├─ 弹出 syscall_context
  └─ 弹出 transaction_context
```

**重入检查**:
```rust
// 检查程序是否已在调用栈中（但不是最后一个）
let contains = (0..stack_height).any(|level| {
    get_program_at_level(level) == program_id
});

let is_last = get_current_program() == program_id;

if contains && !is_last {
    return Err(InstructionError::ReentrancyNotAllowed);
}
```

---

### 步骤 5: 同步阶段

#### 5.1 更新调用者账户信息

```rust
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
```

**`update_caller_account` 操作**:

1. **更新 Lamports**:
```rust
*caller_account.lamports = callee_account.get_lamports();
```

2. **更新所有者**:
```rust
*caller_account.owner = *callee_account.get_owner();
```

3. **更新数据长度**:
```rust
let prev_len = *caller_account.ref_to_len_in_vm as usize;
let post_len = callee_account.get_data().len();

// 检查 realloc 限制
let address_space_reserved = if stricter_abi && is_loader_deprecated {
    caller_account.original_data_len
} else {
    caller_account.original_data_len + MAX_PERMITTED_DATA_INCREASE
};

if post_len > address_space_reserved && (stricter_abi || prev_len != post_len) {
    return Err(InstructionError::InvalidRealloc);
}

if prev_len != post_len {
    *caller_account.ref_to_len_in_vm = post_len as u64;
    
    // 更新序列化长度指针
    let serialized_len_ptr = translate_type_mut_for_cpi::<u64>(
        memory_mapping,
        caller_account.vm_data_addr - size_of::<u64>() as u64,
        check_aligned,
    )?;
    *serialized_len_ptr = post_len as u64;
}
```

4. **更新数据内容**:
```rust
if !(stricter_abi && account_data_direct_mapping) {
    let to_slice = &mut caller_account.serialized_data;
    let from_slice = callee_account.get_data().get(0..post_len)?;
    to_slice.copy_from_slice(from_slice);
}
```

#### 5.2 更新调用者账户区域（stricter_abi 模式）

```rust
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
```

**`update_caller_account_region` 操作**:

```rust
fn update_caller_account_region(
    memory_mapping: &mut MemoryMapping,
    check_aligned: bool,
    caller_account: &CallerAccount,
    callee_account: &mut BorrowedInstructionAccount,
    account_data_direct_mapping: bool,
) -> Result<(), Error> {
    let address_space_reserved = if is_loader_deprecated {
        caller_account.original_data_len
    } else {
        caller_account.original_data_len + MAX_PERMITTED_DATA_INCREASE
    };
    
    if address_space_reserved > 0 {
        let (region_index, region) = memory_mapping
            .find_region(caller_account.vm_data_addr)?;
        
        assert_eq!(region.vm_addr, caller_account.vm_data_addr);
        
        let mut new_region = if !account_data_direct_mapping {
            let mut new_region = region.clone();
            modify_memory_region_of_account(callee_account, &mut new_region);
            new_region
        } else {
            create_memory_region_of_account(callee_account, region.vm_addr)?
        };
        
        memory_mapping.replace_region(region_index, new_region)?;
    }
    
    Ok(())
}
```

**目的**:
- 更新内存映射中的区域
- 反映账户数据的长度变化
- 更新访问权限（可写/只读）

---

### 步骤 6: 完成阶段

```rust
invoke_context.execute_time = Some(Measure::start("execute"));
Ok(SUCCESS)
```

**操作**:
1. 重启执行时间计时器
2. 返回 `SUCCESS` (0)

---

## 数据流图

```
┌─────────────────────────────────────────────────────────────────┐
│                         CPI 数据流                                │
└─────────────────────────────────────────────────────────────────┘

调用者程序 (Caller)
    │
    ├─ instruction_addr ──────────┐
    ├─ account_infos_addr ────────┤
    ├─ account_infos_len ─────────┤
    ├─ signers_seeds_addr ────────┤
    └─ signers_seeds_len ─────────┤
                                  │
                                  ▼
                          ┌──────────────┐
                          │  翻译阶段     │
                          │              │
                          │ - Instruction│
                          │ - Accounts   │
                          │ - Signers    │
                          └──────────────┘
                                  │
                                  ▼
                          ┌──────────────┐
                          │  准备阶段     │
                          │              │
                          │ - 权限检查   │
                          │ - 账户同步   │
                          └──────────────┘
                                  │
                                  ▼
                          ┌──────────────┐
                          │  执行阶段     │
                          │              │
                          │ - 压栈       │
                          │ - 执行程序   │
                          │ - 出栈       │
                          └──────────────┘
                                  │
                                  ▼
                          ┌──────────────┐
                          │  同步阶段     │
                          │              │
                          │ - 更新账户   │
                          │ - 更新区域   │
                          └──────────────┘
                                  │
                                  ▼
                            返回 SUCCESS

被调用程序 (Callee)
```

---


## 错误处理

### 可能的错误类型

| 错误 | 触发条件 | 阶段 |
|------|----------|------|
| `ComputationalBudgetExceeded` | CU 不足 | 预处理 |
| `InvalidPointer` | 指针未对齐或无效 | 翻译 |
| `InvalidArgument` | 参数无效（如 bool > 1） | 翻译 |
| `InvalidLength` | 长度无效 | 翻译 |
| `TooManySigners` | 签名者超过 16 个 | 翻译 |
| `BadSeeds` | PDA 种子无效 | 翻译 |
| `MaxSeedLengthExceeded` | 种子数超过 16 个 | 翻译 |
| `MaxInstructionAccountsExceeded` | 账户数超过 256 | 翻译 |
| `MaxInstructionDataLenExceeded` | 数据长度超过 10 KB | 翻译 |
| `MaxInstructionAccountInfosExceeded` | AccountInfo 数超限 | 翻译 |
| `ProgramNotSupported` | 调用禁止的程序 | 准备 |
| `MissingAccount` | 账户不存在 | 准备 |
| `PrivilegeEscalation` | 权限提升 | 准备 |
| `ReentrancyNotAllowed` | 重入调用 | 执行 |
| `InvalidRealloc` | 非法的数据重新分配 | 同步 |
| `AccountDataTooSmall` | 账户数据太小 | 同步 |

### 错误处理流程

```rust
// 1. 预处理阶段错误
consume_compute_meter(invoke_context, invoke_units)?;
// ↓ 失败: ComputationalBudgetExceeded

// 2. 翻译阶段错误
let instruction = S::translate_instruction(...)?;
// ↓ 失败: InvalidPointer, InvalidArgument, MaxInstructionAccountsExceeded

let signers = S::translate_signers(...)?;
// ↓ 失败: TooManySigners, BadSeeds, MaxSeedLengthExceeded

let accounts = S::translate_accounts(...)?;
// ↓ 失败: MaxInstructionAccountInfosExceeded, InvalidPointer

// 3. 准备阶段错误
check_authorized_program(&instruction.program_id, &instruction.data, invoke_context)?;
// ↓ 失败: ProgramNotSupported

invoke_context.prepare_next_instruction(instruction, &signers)?;
// ↓ 失败: MissingAccount, PrivilegeEscalation

// 4. 执行阶段错误
invoke_context.process_instruction(&mut compute_units_consumed, &mut timings)?;
// ↓ 失败: ReentrancyNotAllowed, ProgramFailedToComplete

// 5. 同步阶段错误
update_caller_account(...)?;
// ↓ 失败: InvalidRealloc, AccountDataTooSmall
```

### 错误恢复

**重要**: CPI 失败时，所有状态变更会回滚：
- 账户数据恢复到调用前状态
- Lamports 恢复
- 所有者恢复
- 计算单元已消耗的部分**不会**恢复

```rust
// 示例：CPI 失败处理
match invoke(
    &instruction,
    &[account1, account2, program_account],
) {
    Ok(_) => {
        // CPI 成功，账户状态已更新
        msg!("CPI succeeded");
    }
    Err(e) => {
        // CPI 失败，账户状态已回滚
        msg!("CPI failed: {:?}", e);
        // 但已消耗的 CU 不会退还
    }
}
```

---

## 性能优化

### 计算单元消耗分析

#### 基础成本

```rust
// CPI 调用本身
invoke_units: 946 CU (SIMD-0339) 或 1000 CU

// 数据翻译
data_translation: data.len() / 250  // 每 250 字节 1 CU

// AccountMeta 翻译 (SIMD-0339)
account_meta_translation: (accounts.len() * 32) / 250

// AccountInfo 翻译 (SIMD-0339)
account_info_translation: (account_infos.len() * 80) / 250

// 账户数据翻译
account_data_translation: total_account_data_len / 250
```

#### 总成本计算

```rust
total_cu = invoke_units
    + data_translation
    + account_meta_translation  // SIMD-0339
    + account_info_translation  // SIMD-0339
    + account_data_translation
    + callee_program_cu
```

#### 优化建议

1. **减少账户数量**
```rust
// ❌ 不好：传递所有账户
invoke(
    &instruction,
    &[acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8],
)?;

// ✅ 好：只传递必要的账户
invoke(
    &instruction,
    &[acc1, acc2, program_account],
)?;
```

2. **减少指令数据大小**
```rust
// ❌ 不好：传递大量数据
let data = vec![0u8; 10_000];
let instruction = Instruction::new_with_bytes(program_id, &data, accounts);

// ✅ 好：压缩或分批传递
let compressed_data = compress(&data);
let instruction = Instruction::new_with_bytes(program_id, &compressed_data, accounts);
```

3. **合并 CPI 调用**
```rust
// ❌ 不好：多次 CPI
invoke(&instruction1, &accounts)?;  // 946 CU
invoke(&instruction2, &accounts)?;  // 946 CU
invoke(&instruction3, &accounts)?;  // 946 CU
// 总计: 2838 CU

// ✅ 好：单次 CPI 批量处理
invoke(&batch_instruction, &accounts)?;  // 946 CU
```

4. **避免不必要的账户数据复制**
```rust
// 使用 account_data_direct_mapping feature
// 避免在 CPI 前后复制账户数据
```

### 内存优化

#### 栈使用

```rust
// 每个 CPI 调用会压栈
// 栈深度限制:
// - 默认: 5 (4 层 CPI)
// - SIMD-0268: 9 (8 层 CPI)

// 每个栈帧: 4 KB
// 最大栈使用: 9 * 4 KB = 36 KB
```

#### 堆使用

```rust
// BpfAllocator 管理堆分配
// 堆大小: 32 KB - 256 KB
// 每增加 32 KB 消耗 8 CU
```

---

## Feature Gates 影响

### stricter_abi_and_runtime_constraints

**激活时的变化**:

1. **账户指针检查**
```rust
// 检查 key, owner, lamports, data 指针是否指向预期地址
check_account_info_pointer(invoke_context, vm_addr, expected_vm_addr, "key")?;
```

2. **数据长度变更检查**
```rust
// 严格检查数据长度变更
if prev_len != post_len {
    if post_len > address_space_reserved {
        return Err(InstructionError::InvalidRealloc);
    }
    callee_account.set_data_length(post_len)?;
}
```

3. **提前更新被调用账户**
```rust
// 在执行前更新被调用账户
for translated_account in accounts.iter_mut() {
    update_callee_account(...)?;
}
```

4. **更新内存区域**
```rust
// 执行后更新内存区域
for translated_account in accounts.iter() {
    update_caller_account_region(...)?;
}
```

### account_data_direct_mapping

**激活时的变化**:

1. **直接映射账户数据**
```rust
// 不复制账户数据到序列化缓冲区
// 直接映射到 VM 内存
let memory_region = create_memory_region_of_account(account, vaddr)?;
```

2. **避免数据复制**
```rust
// 不需要在 CPI 前后复制数据
if !account_data_direct_mapping {
    callee_account.set_data_from_slice(caller_account.serialized_data)?;
}
```

3. **动态更新内存区域**
```rust
// 数据长度变更时，替换内存区域
memory_mapping.replace_region(region_index, new_region)?;
```

### increase_cpi_account_info_limit

**激活时的变化**:

1. **增加 AccountInfo 限制**
```rust
// 从 64/128 增加到 255
const MAX_CPI_ACCOUNT_INFOS_SIMD_0339: usize = 255;
```

2. **增加翻译成本**
```rust
// 计算 AccountMeta 翻译成本
let account_meta_cost = (accounts.len() * size_of::<AccountMeta>()) / cpi_bytes_per_unit;

// 计算 AccountInfo 翻译成本
let account_info_cost = (account_infos.len() * ACCOUNT_INFO_BYTE_SIZE) / cpi_bytes_per_unit;
```

### raise_cpi_nesting_limit_to_8

**激活时的变化**:

```rust
// 从 4 层 CPI 增加到 8 层
const MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268: usize = 9;
```

---

## 使用示例

### 示例 1: 简单的 CPI 调用

```rust
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    
    // 构造转账指令
    let transfer_instruction = Instruction {
        program_id: *system_program.key,
        accounts: vec![
            AccountMeta::new(*source.key, true),
            AccountMeta::new(*destination.key, false),
        ],
        data: vec![2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0], // Transfer 100 lamports
    };
    
    // 执行 CPI
    invoke(
        &transfer_instruction,
        &[source.clone(), destination.clone(), system_program.clone()],
    )?;
    
    Ok(())
}
```

**内部流程**:
1. `invoke()` 调用 `sol_invoke_signed_rust()`
2. 系统调用进入 `cpi_common::<RustImpl>()`
3. 翻译指令和账户
4. 执行 System Program 的转账逻辑
5. 更新账户状态
6. 返回调用者

### 示例 2: 使用 PDA 签名的 CPI

```rust
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let pda_account = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    
    // 验证 PDA
    let (expected_pda, bump_seed) = Pubkey::find_program_address(
        &[b"vault", program_id.as_ref()],
        program_id,
    );
    
    if pda_account.key != &expected_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 构造转账指令
    let transfer_instruction = Instruction {
        program_id: *system_program.key,
        accounts: vec![
            AccountMeta::new(*pda_account.key, true),  // PDA 作为签名者
            AccountMeta::new(*destination.key, false),
        ],
        data: vec![2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0],
    };
    
    // 使用 PDA 签名执行 CPI
    invoke_signed(
        &transfer_instruction,
        &[pda_account.clone(), destination.clone(), system_program.clone()],
        &[&[b"vault", program_id.as_ref(), &[bump_seed]]],  // 签名者种子
    )?;
    
    Ok(())
}
```

**内部流程**:
1. `invoke_signed()` 调用 `sol_invoke_signed_rust()`
2. 系统调用进入 `cpi_common::<RustImpl>()`
3. 翻译签名者种子
4. 使用种子生成 PDA: `Pubkey::create_program_address(&seeds, program_id)`
5. 将 PDA 添加到签名者列表
6. 执行指令
7. 返回调用者

### 示例 3: 复杂的 CPI 调用（多账户、多签名者）

```rust
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let pda1 = next_account_info(accounts_iter)?;
    let pda2 = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    
    // 验证 authority
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 计算 PDA bump seeds
    let (_, bump1) = Pubkey::find_program_address(&[b"pda1"], program_id);
    let (_, bump2) = Pubkey::find_program_address(&[b"pda2"], program_id);
    
    // 构造复杂指令
    let instruction = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*pda1.key, true),      // PDA 签名者
            AccountMeta::new(*pda2.key, true),      // PDA 签名者
            AccountMeta::new(*user_account.key, false),
            AccountMeta::new_readonly(*authority.key, true), // 用户签名者
        ],
        data: vec![/* token transfer data */],
    };
    
    // 使用多个签名者执行 CPI
    invoke_signed(
        &instruction,
        &[
            pda1.clone(),
            pda2.clone(),
            user_account.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[
            &[b"pda1", &[bump1]],  // 第一个 PDA 的种子
            &[b"pda2", &[bump2]],  // 第二个 PDA 的种子
        ],
    )?;
    
    Ok(())
}
```

**内部流程**:
1. 翻译 2 组签名者种子
2. 生成 2 个 PDA
3. 将 2 个 PDA 和 1 个用户签名者添加到签名者列表
4. 检查权限提升（确保 authority 在调用者中也是签名者）
5. 执行 Token Program 指令
6. 返回调用者

### 示例 4: C 程序的 CPI 调用

```c
#include <solana_sdk.h>

uint64_t process_instruction(
    SolAccountInfo *accounts,
    int accounts_len,
    const uint8_t *instruction_data,
    int instruction_data_len
) {
    // 构造指令
    SolInstruction instruction = {
        .program_id_addr = (uint64_t)&system_program_id,
        .accounts_addr = (uint64_t)account_metas,
        .accounts_len = 2,
        .data_addr = (uint64_t)transfer_data,
        .data_len = 12,
    };
    
    // 构造账户元数据
    SolAccountMeta account_metas[2] = {
        {
            .pubkey_addr = (uint64_t)&source_pubkey,
            .is_writable = true,
            .is_signer = true,
        },
        {
            .pubkey_addr = (uint64_t)&dest_pubkey,
            .is_writable = true,
            .is_signer = false,
        },
    };
    
    // 执行 CPI
    uint64_t result = sol_invoke_signed_c(
        &instruction,
        accounts,
        accounts_len,
        NULL,  // 无签名者种子
        0
    );
    
    return result;
}
```

**内部流程**:
1. `sol_invoke_signed_c()` 系统调用
2. 进入 `cpi_common::<CImpl>()`
3. 使用 C ABI 翻译函数
4. 执行指令
5. 返回调用者

---

## 调试技巧

### 1. 启用日志

```rust
use solana_program::msg;

msg!("Before CPI");
invoke(&instruction, &accounts)?;
msg!("After CPI");
```

**日志输出**:
```
Program log: Before CPI
Program <callee_program_id> invoke [2]
Program <callee_program_id> success
Program log: After CPI
```

### 2. 检查计算单元

```rust
use solana_program::log::sol_log_compute_units;

sol_log_compute_units();  // 输出剩余 CU
invoke(&instruction, &accounts)?;
sol_log_compute_units();  // 输出剩余 CU
```

### 3. 验证账户状态

```rust
msg!("Before: lamports={}, data_len={}", 
    account.lamports(), 
    account.data_len()
);

invoke(&instruction, &accounts)?;

msg!("After: lamports={}, data_len={}", 
    account.lamports(), 
    account.data_len()
);
```

### 4. 捕获 CPI 错误

```rust
match invoke(&instruction, &accounts) {
    Ok(_) => msg!("CPI succeeded"),
    Err(e) => {
        msg!("CPI failed: {:?}", e);
        return Err(e);
    }
}
```

---

## 总结

### 关键要点

1. **CPI 成本**: 基础成本 946 CU + 数据翻译成本
2. **栈深度**: 默认 4 层，SIMD-0268 后 8 层
3. **账户限制**: 最多 255 个 AccountInfo (SIMD-0339)
4. **签名者限制**: 最多 16 个签名者
5. **数据限制**: 指令数据最多 10 KB
6. **重入保护**: 不允许重入调用（除非是最后一个）
7. **权限检查**: 严格的权限提升检查
8. **状态回滚**: CPI 失败时自动回滚状态

### 最佳实践

1. ✅ 只传递必要的账户
2. ✅ 压缩指令数据
3. ✅ 合并多个 CPI 调用
4. ✅ 使用 PDA 进行程序控制
5. ✅ 检查 CPI 返回值
6. ✅ 记录详细日志
7. ❌ 避免深层嵌套 CPI
8. ❌ 避免传递大量数据
9. ❌ 避免不必要的账户复制

### 性能优化

- 减少账户数量
- 减少指令数据大小
- 合并 CPI 调用
- 使用 `account_data_direct_mapping`
- 避免深层嵌套

---

**文档版本**: 1.0  
**最后更新**: 2025-11-25  
**作者**: Kiro AI Assistant
