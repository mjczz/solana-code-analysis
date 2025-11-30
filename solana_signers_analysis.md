# Solana 签名者机制完整分析

## 概述

本文档详细分析 Solana 中 `get_signers()` 的完整实现链路，从交易构建到指令执行的全过程。

---

## 1. 交易构建阶段（SDK）

### 1.1 账户编译和排序

**位置：** `solana-sdk/message/src/compiled_keys.rs`

账户排序由 `CompiledKeys::compile()` 和 `try_into_message_components()` 完成：

```rust
// 第一步：收集所有账户的元数据
pub(crate) fn compile(instructions: &[Instruction], payer: Option<Address>) -> Self {
    let mut key_meta_map = BTreeMap::<Address, CompiledKeyMeta>::new();
    
    // 遍历所有指令，收集账户信息
    for ix in instructions {
        let meta = key_meta_map.entry(ix.program_id).or_default();
        meta.is_invoked = true;
        
        for account_meta in &ix.accounts {
            let meta = key_meta_map.entry(account_meta.pubkey).or_default();
            meta.is_signer |= account_meta.is_signer;      // 合并 signer 标记
            meta.is_writable |= account_meta.is_writable;  // 合并 writable 标记
        }
    }
    
    // payer 自动标记为 signer + writable
    if let Some(payer) = &payer {
        let meta = key_meta_map.entry(*payer).or_default();
        meta.is_signer = true;
        meta.is_writable = true;
    }
}

// 第二步：按规则分组和排序
pub(crate) fn try_into_message_components(self) -> Result<(MessageHeader, Vec<Address>), CompileError> {
    // 1. Writable + Signer (payer 在最前面)
    let writable_signer_keys: Vec<Address> = payer
        .into_iter()
        .chain(
            key_meta_map
                .iter()
                .filter_map(|(key, meta)| (meta.is_signer && meta.is_writable).then_some(*key)),
        )
        .collect();
    
    // 2. Readonly + Signer
    let readonly_signer_keys: Vec<Address> = key_meta_map
        .iter()
        .filter_map(|(key, meta)| (meta.is_signer && !meta.is_writable).then_some(*key))
        .collect();
    
    // 3. Writable + Unsigned
    let writable_non_signer_keys: Vec<Address> = key_meta_map
        .iter()
        .filter_map(|(key, meta)| (!meta.is_signer && meta.is_writable).then_some(*key))
        .collect();
    
    // 4. Readonly + Unsigned
    let readonly_non_signer_keys: Vec<Address> = key_meta_map
        .iter()
        .filter_map(|(key, meta)| (!meta.is_signer && !meta.is_writable).then_some(*key))
        .collect();
    
    // 组装最终的 account_keys 数组
    let static_account_keys = std::iter::empty()
        .chain(writable_signer_keys)
        .chain(readonly_signer_keys)
        .chain(writable_non_signer_keys)
        .chain(readonly_non_signer_keys)
        .collect();
    
    Ok((header, static_account_keys))
}
```

**关键点：**
- 使用 `BTreeMap` 自动去重和排序（按公钥字典序）
- 同一账户在多个指令中出现时，属性会**合并**（OR 操作）
- payer 总是排在第一位

### 1.2 账户排序规则

Solana 交易中的账户按照以下顺序排列：

```
1. Writable + Signer 账户 (payer 在最前)
2. Readonly + Signer 账户  
3. Writable + Unsigned 账户
4. Readonly + Unsigned 账户
```

### 1.3 Message Header 结构

```rust
struct MessageHeader {
    num_required_signatures: u8,        // 签名者总数（类型1+2）
    num_readonly_signed_accounts: u8,   // 只读签名者数量（类型2）
    num_readonly_unsigned_accounts: u8, // 只读非签名者数量（类型4）
}
```

**位置：** `transaction-view/src/message_header_frame.rs`

### 1.3 账户布局示例

假设有以下账户：
- A: Writable + Signer
- B: Writable + Signer  
- C: Readonly + Signer
- D: Writable + Unsigned
- E: Readonly + Unsigned

排序后的 `account_keys` 数组：
```
索引 0: A (Writable + Signer)
索引 1: B (Writable + Signer)
索引 2: C (Readonly + Signer)
索引 3: D (Writable + Unsigned)
索引 4: E (Readonly + Unsigned)
```

对应的 Header：
```rust
MessageHeader {
    num_required_signatures: 3,        // A, B, C 都是签名者
    num_readonly_signed_accounts: 1,   // C 是只读签名者
    num_readonly_unsigned_accounts: 1, // E 是只读非签名者
}
```

---

## 2. 运行时解析阶段

### 2.1 判断是否为签名者

**位置：** `transaction-view/src/resolved_transaction_view.rs:223-225`

```rust
fn is_signer(&self, index: usize) -> bool {
    index < usize::from(self.view.num_required_signatures())
}
```

**规则：** 账户索引 < `num_required_signatures` 则为签名者

### 2.2 判断是否可写

**位置：** `transaction-view/src/resolved_transaction_view.rs:91-149`

```rust
fn cache_is_writable(
    view: &TransactionView<true, D>,
    resolved_addresses: Option<&LoadedAddresses>,
    reserved_account_keys: &HashSet<Pubkey>,
) -> [bool; 256] {
    let num_signed_accounts = usize::from(view.num_required_signatures());
    let num_writable_signed_static_accounts =
        usize::from(view.num_writable_signed_static_accounts());
    let num_writable_unsigned_static_accounts =
        usize::from(view.num_writable_unsigned_static_accounts());

    for (index, key) in account_keys.iter().enumerate() {
        let is_requested_write = {
            if index >= num_signed_accounts {
                // 非签名者账户
                let unsigned_account_index = index.wrapping_sub(num_signed_accounts);
                unsigned_account_index < num_writable_unsigned_static_accounts
            } else {
                // 签名者账户
                index < num_writable_signed_static_accounts
            }
        };
        
        is_writable_cache[index] = is_requested_write && !reserved_account_keys.contains(key);
    }
}
```

**计算公式：**
```rust
// 可写签名者数量
num_writable_signed = num_required_signatures - num_readonly_signed_accounts

// 可写非签名者数量
num_writable_unsigned = num_unsigned_accounts - num_readonly_unsigned_accounts
```

**位置：** `transaction-view/src/transaction_view.rs:209-220`

---

## 3. 指令准备阶段

### 3.1 创建 InstructionAccount

**位置：** `program-runtime/src/invoke_context.rs:437-475`

```rust
pub fn prepare_next_top_level_instruction(
    &mut self,
    message: &impl SVMMessage,
    instruction: &SVMInstruction,
    program_account_index: IndexOfAccount,
    data: &'ix_data [u8],
) -> Result<(), InstructionError> {
    let mut instruction_accounts: Vec<InstructionAccount> =
        Vec::with_capacity(instruction.accounts.len());
    
    for index_in_transaction in instruction.accounts.iter() {
        let index_in_transaction = *index_in_transaction as usize;
        instruction_accounts.push(InstructionAccount::new(
            index_in_transaction as IndexOfAccount,
            message.is_signer(index_in_transaction),      // 从 message 获取
            message.is_writable(index_in_transaction),    // 从 message 获取
        ));
    }

    self.transaction_context.configure_next_instruction(
        program_account_index,
        instruction_accounts,
        transaction_callee_map,
        Cow::Borrowed(data),
    )?;
    Ok(())
}
```

### 3.2 InstructionAccount 结构

**位置：** `transaction-context/src/instruction_accounts.rs:19-56`

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InstructionAccount {
    pub index_in_transaction: IndexOfAccount,
    is_signer: u8,    // 0 或 1
    is_writable: u8,  // 0 或 1
}

impl InstructionAccount {
    pub fn new(
        index_in_transaction: IndexOfAccount,
        is_signer: bool,
        is_writable: bool,
    ) -> InstructionAccount {
        InstructionAccount {
            index_in_transaction,
            is_signer: is_signer as u8,
            is_writable: is_writable as u8,
        }
    }

    pub fn is_signer(&self) -> bool {
        self.is_signer != 0
    }

    pub fn is_writable(&self) -> bool {
        self.is_writable != 0
    }
}
```

### 3.3 配置到 TransactionContext

**位置：** `transaction-context/src/lib.rs:244-262`

```rust
pub fn configure_next_instruction(
    &mut self,
    program_index: IndexOfAccount,
    instruction_accounts: Vec<InstructionAccount>,
    deduplication_map: Vec<u16>,
    instruction_data: Cow<'ix_data, [u8]>,
) -> Result<(), InstructionError> {
    let instruction = self
        .instruction_trace
        .last_mut()
        .ok_or(InstructionError::CallDepth)?;
    instruction.program_account_index_in_tx = program_index;
    instruction.instruction_accounts = instruction_accounts;
    instruction.instruction_data = instruction_data;
    instruction.dedup_map = deduplication_map;
    Ok(())
}
```

---

## 4. 指令执行阶段

### 4.1 InstructionContext 结构

**位置：** `transaction-context/src/instruction.rs:27-36`

```rust
pub struct InstructionContext<'a, 'ix_data> {
    pub(crate) transaction_context: &'a TransactionContext<'ix_data>,
    pub(crate) index_in_trace: usize,
    pub(crate) nesting_level: usize,
    pub(crate) program_account_index_in_tx: IndexOfAccount,
    pub(crate) instruction_accounts: &'a [InstructionAccount],  // 引用
    pub(crate) dedup_map: &'a [u16],
    pub(crate) instruction_data: &'ix_data [u8],
}
```

### 4.2 获取 InstructionContext

**位置：** `transaction-context/src/lib.rs:171-188`

```rust
pub fn get_instruction_context_at_index_in_trace(
    &self,
    index_in_trace: usize,
) -> Result<InstructionContext<'_, '_>, InstructionError> {
    let instruction = self
        .instruction_trace
        .get(index_in_trace)
        .ok_or(InstructionError::CallDepth)?;
    Ok(InstructionContext {
        transaction_context: self,
        index_in_trace,
        nesting_level: instruction.nesting_level,
        program_account_index_in_tx: instruction.program_account_index_in_tx,
        instruction_accounts: &instruction.instruction_accounts,  // 引用 InstructionFrame 中的数据
        dedup_map: &instruction.dedup_map,
        instruction_data: &instruction.instruction_data,
    })
}
```

### 4.3 收集签名者

**位置：** `transaction-context/src/instruction.rs:201-213`

```rust
pub fn get_signers(&self) -> Result<HashSet<Pubkey>, InstructionError> {
    let mut result = HashSet::new();
    for instruction_account in self.instruction_accounts.iter() {
        if instruction_account.is_signer() {
            result.insert(
                *self
                    .transaction_context
                    .get_key_of_account_at_index(instruction_account.index_in_transaction)?,
            );
        }
    }
    Ok(result)
}
```

### 4.4 实际使用

**位置：** `programs/system/src/system_processor.rs:296`

```rust
let signers = instruction_context.get_signers()?;
match instruction {
    SystemInstruction::CreateAccount { ... } => { ... }
    // 使用 signers 进行权限验证
}
```

---

## 5. 完整数据流

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 客户端构建交易                                                │
├─────────────────────────────────────────────────────────────────┤
│ • 收集 AccountMeta (pubkey, is_signer, is_writable)             │
│ • 按规则排序账户                                                 │
│ • 统计并填充 MessageHeader                                       │
│   - num_required_signatures                                     │
│   - num_readonly_signed_accounts                                │
│   - num_readonly_unsigned_accounts                              │
│ • 序列化交易                                                     │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 运行时解析交易                                                │
├─────────────────────────────────────────────────────────────────┤
│ • 反序列化 MessageHeader                                         │
│ • 解析 account_keys 数组                                         │
│ • 根据索引位置和 header 字段判断账户属性：                        │
│   - is_signer(index) = index < num_required_signatures          │
│   - is_writable(index) = 根据分段计算                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 准备指令上下文                                                │
├─────────────────────────────────────────────────────────────────┤
│ • prepare_next_top_level_instruction()                          │
│ • 遍历指令的账户索引                                             │
│ • 创建 InstructionAccount：                                      │
│   - index_in_transaction                                        │
│   - is_signer = message.is_signer(index)                        │
│   - is_writable = message.is_writable(index)                    │
│ • configure_next_instruction() 存储到 InstructionFrame          │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 执行指令                                                      │
├─────────────────────────────────────────────────────────────────┤
│ • get_instruction_context_at_index_in_trace()                   │
│ • 创建 InstructionContext（引用 instruction_accounts）           │
│ • get_signers()：                                                │
│   - 遍历 instruction_accounts                                    │
│   - 过滤 is_signer = true 的账户                                 │
│   - 通过 index_in_transaction 获取 Pubkey                        │
│   - 返回 HashSet<Pubkey>                                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 程序使用                                                      │
├─────────────────────────────────────────────────────────────────┤
│ • let signers = instruction_context.get_signers()?;             │
│ • 验证权限：signers.contains(&authority)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. 关键要点

### 6.1 签名者标记的来源

- **不是运行时动态判断**，而是在交易构建时就已确定
- 通过账户在 `account_keys` 数组中的位置决定
- `num_required_signatures` 标记了前 N 个账户需要签名

### 6.2 实际签名验证

- 签名验证发生在交易处理的**更早阶段**（交易验证时）
- `get_signers()` 只是**收集**那些被标记为签名者的账户公钥
- 不做实际的签名验证，只做权限检查

### 6.3 账户索引的重要性

```rust
// 账户在交易中的全局索引
index_in_transaction: IndexOfAccount

// 通过索引判断属性
is_signer = index < num_required_signatures
is_writable = 根据分段和 header 字段计算
```

### 6.4 数据结构层次

```
TransactionContext
  └─ instruction_trace: Vec<InstructionFrame>
       └─ InstructionFrame
            └─ instruction_accounts: Vec<InstructionAccount>
                 └─ InstructionAccount { index_in_transaction, is_signer, is_writable }

InstructionContext (视图)
  └─ instruction_accounts: &[InstructionAccount]  // 引用
       └─ get_signers() 遍历并收集
```

---

## 7. 代码位置索引

| 功能 | 文件路径 | 行号 |
|------|---------|------|
| **SDK 层（账户编译和排序）** | | |
| CompiledKeys::compile | `solana-sdk/message/src/compiled_keys.rs` | 59-84 |
| try_into_message_components | `solana-sdk/message/src/compiled_keys.rs` | 85-138 |
| Message::new_with_blockhash | `solana-sdk/message/src/legacy.rs` | 274-292 |
| **运行时层（解析和判断）** | | |
| MessageHeader 定义 | `transaction-view/src/message_header_frame.rs` | 11-25 |
| is_signer 判断 | `transaction-view/src/resolved_transaction_view.rs` | 223-225 |
| is_writable 缓存 | `transaction-view/src/resolved_transaction_view.rs` | 91-149 |
| **指令准备层** | | |
| InstructionAccount 定义 | `transaction-context/src/instruction_accounts.rs` | 19-56 |
| prepare_next_top_level_instruction | `program-runtime/src/invoke_context.rs` | 437-475 |
| configure_next_instruction | `transaction-context/src/lib.rs` | 244-262 |
| **指令执行层** | | |
| InstructionContext 定义 | `transaction-context/src/instruction.rs` | 27-36 |
| get_signers 实现 | `transaction-context/src/instruction.rs` | 201-213 |
| 实际使用示例 | `programs/system/src/system_processor.rs` | 296 |

---

## 8. 总结

Solana 的签名者机制是一个**SDK 编译、运行时解析**的过程：

1. **SDK 编译阶段**（`solana-sdk`）：
   - `CompiledKeys::compile()` 收集所有指令中的账户元数据
   - 使用 `BTreeMap` 去重，属性通过 OR 操作合并
   - `try_into_message_components()` 按规则分组排序账户
   - 生成 `MessageHeader` 和排序后的 `account_keys`

2. **运行时解析阶段**（`agave`）：
   - 从交易字节流反序列化 `MessageHeader`
   - 根据账户索引位置和 header 字段判断账户属性

3. **指令准备阶段**：
   - 将属性标记复制到 `InstructionAccount`

4. **指令执行阶段**：
   - 通过 `get_signers()` 收集签名者公钥用于权限验证

**核心发现：**
- 账户排序和 header 生成由 **SDK 的 `CompiledKeys`** 完成，不是客户端手动排序
- 排序规则固定：Writable Signer → Readonly Signer → Writable Unsigned → Readonly Unsigned
- payer 自动成为第一个账户（Writable + Signer）
- 整个过程没有动态签名验证，只是根据交易结构中的位置信息进行属性判断和收集
