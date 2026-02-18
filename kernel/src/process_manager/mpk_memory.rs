/* ========== [MPK-DEV] MPK 内存管理器模块 ========== */
//! MPK (Memory Protection Keys) 内存管理器
//! 
//! 此模块实现了 VMPL-0 Monitor 侧的 MPK 内存管理功能。
//! 
//! ## 设计说明
//! 
//! 新设计：VMPL-1 传入虚拟地址，Monitor 只负责：
//! - 分配 pkey (通过 PkeyAllocator 位图管理)
//! - 在页表中设置带 pkey 的映射
//! - 维护 vaddr -> pkey 的映射关系（用于释放时查找）
//! 
//! ## 与原 Wallet-VMPL 项目的区别
//! 
//! 原项目的 `pal_svsm_virt_alloc` 由 Monitor 决定虚拟地址，
//! 本模块的设计让 VMPL-1 (未来的 WASM 运行时) 自主管理虚拟地址空间，
//! 更灵活地支持 serverless 函数模块的内存隔离需求。
//! 
//! ## 错误码定义
//! 
//! | 错误码 | 含义 |
//! |--------|------|
//! | 0 | 成功 |
//! | 1 | 地址或大小未页对齐 (在 runtime.rs 中检查) |
//! | 2 | 地址未找到 (释放时) |
//! | 3 | 地址已被使用 (分配时) |
//! | 4 | 大小不匹配 (释放时) |
//! | 5 | 内存分配失败 (预留) |
//! | 6 | 无空闲 pkey |

// 导入所需的模块
use crate::locking::SpinLock;
use crate::address::{PhysAddr, VirtAddr};
use crate::process_manager::process_paging::{ProcessPageTableRef, ProcessPageFlags};
// [MPK-DEV] 注意：如果后续需要在 mpk_free_memory 中逐页清零内存，
// 需要导入以下宏和常量（当前已移除逐页清零以避免性能问题）：
// use crate::{map_paddr, paddr_as_u64_slice, vaddr_as_u64_slice};
// use crate::mm::PerCPUPageMappingGuard;
// use crate::process_manager::memory_helper::ZERO_PAGE;
// use core::ptr::replace;

// 使用 alloc crate 中的 BTreeMap (在 no_std 环境下可用)
extern crate alloc;
use alloc::collections::BTreeMap;

/* ========== [MPK-DEV] pkey 分配器 ========== */

/// pkey 分配器 - 使用 u16 位图管理 16 个 pkey
/// 
/// ## 设计说明
/// 
/// x86-64 MPK 支持 16 个 pkey (0-15)，其中：
/// - pkey 0: 保留给系统默认域，不分配给用户
/// - pkey 1-15: 可分配给不同的函数模块
/// 
/// 使用位图 (bitmap) 管理分配状态：
/// - bit i = 1 表示 pkey i 已分配
/// - bit i = 0 表示 pkey i 空闲
/// 
/// 初始值 0x0001 表示 pkey 0 已被保留（bit 0 = 1）
#[derive(Debug)]
struct PkeyAllocator {
    /// 位图：bit i = 1 表示 pkey i 已分配
    /// 初始值 0x0001 表示 pkey 0 已被保留
    bitmap: u16,
}

impl PkeyAllocator {
    /// 创建新的 pkey 分配器
    /// 
    /// 初始化时将 pkey 0 标记为已分配（保留给系统）
    /// 
    /// ## const fn
    /// 
    /// 使用 const fn 使其可以在 static 变量初始化中使用
    const fn new() -> Self {
        Self { 
            bitmap: 0x0001  // pkey 0 保留，bit 0 = 1
        }
    }
    
    /// 分配一个空闲的 pkey
    /// 
    /// ## 返回值
    /// 
    /// - `Some(pkey)`: 成功分配，返回 pkey 值 (1-15)
    /// - `None`: 无空闲 pkey
    /// 
    /// ## 算法
    /// 
    /// 从 pkey 1 开始遍历，找到第一个为 0 的 bit，
    /// 将其设为 1 并返回对应的 pkey 值
    fn alloc(&mut self) -> Option<u32> {
        // 从 1 开始遍历（跳过保留的 pkey 0）
        for i in 1..16u32 {
            // 检查第 i 位是否为 0（空闲）
            if (self.bitmap & (1 << i)) == 0 {
                // 将第 i 位设为 1（标记为已分配）
                self.bitmap |= 1 << i;
                return Some(i);
            }
        }
        // 所有 pkey 都已分配
        None
    }
    
    /// 释放一个 pkey
    /// 
    /// ## 参数
    /// 
    /// - `pkey`: 要释放的 pkey 值
    /// 
    /// ## 说明
    /// 
    /// 只有 pkey 1-15 可以被释放，pkey 0 始终保留
    fn free(&mut self, pkey: u32) {
        // 只释放有效范围内的 pkey (1-15)
        if pkey > 0 && pkey < 16 {
            // 将第 pkey 位清零（标记为空闲）
            // !(1 << pkey) 创建一个只有第 pkey 位为 0 的掩码
            self.bitmap &= !(1 << pkey);
        }
    }
}

/* ========== [MPK-DEV] MPK 分配记录 ========== */

/// MPK 分配记录
/// 
/// 记录每次 MPK 内存分配的信息，用于释放时验证和查找
#[derive(Debug, Clone, Copy)]
struct MpkAllocation {
    /// 分配的 pkey 值 (1-15)
    pkey: u32,
    /// 分配的大小 (字节，已页对齐)
    size: u64,
}

/* ========== [MPK-DEV] MPK 内存管理器 ========== */

/// MPK 内存管理器
/// 
/// 管理所有 MPK 内存分配，包括：
/// - pkey 的分配和释放
/// - vaddr -> pkey 的映射关系
#[derive(Debug)]
pub struct MpkMemoryManager {
    /// pkey 分配器
    pkey_allocator: PkeyAllocator,
    /// 分配记录表: vaddr -> MpkAllocation
    /// 使用 BTreeMap 实现有序映射，支持快速查找
    allocations: BTreeMap<u64, MpkAllocation>,
}

/// 全局 MPK 内存管理器实例
/// 
/// 使用 SpinLock 保护，支持多核并发访问
/// 
/// ## 线程安全
/// 
/// 多个 CPU 核心可能同时处理不同 Trustlet 的 MPK 请求，
/// 因此需要使用自旋锁保护共享的管理器状态
static MPK_MANAGER: SpinLock<MpkMemoryManager> = SpinLock::new(MpkMemoryManager::new());

impl MpkMemoryManager {
    /// 创建新的 MPK 内存管理器
    /// 
    /// ## const fn
    /// 
    /// 使用 const fn 使其可以在 static 变量初始化中使用
    pub const fn new() -> Self {
        Self {
            pkey_allocator: PkeyAllocator::new(),
            allocations: BTreeMap::new(),
        }
    }
}

/* ========== [MPK-DEV] MPK 六接口公开 API ========== */

/// 仅分配 pkey（不分配内存）
///
/// 此函数由 runtime.rs 中的 `pal_svsm_mpk_pkey_alloc` 处理函数调用。
///
/// ## 功能
///
/// 从 PkeyAllocator 位图中分配一个空闲的 pkey 编号，不做任何内存操作。
/// 调用方后续可用此 pkey 调用 `mpk_alloc_memory()` 分配带标记的内存。
///
/// ## 返回值
///
/// - `Ok(pkey)`: 成功，返回 pkey (1-15)
/// - `Err(6)`: 无空闲 pkey
pub fn mpk_pkey_alloc_only() -> Result<u32, u32> {
    let mut manager = MPK_MANAGER.lock();
    let pkey = manager.pkey_allocator.alloc().ok_or(6u32)?;  // 错误码 6: 无空闲 pkey
    log::info!("[MPK] mpk_pkey_alloc_only: allocated pkey={}", pkey);
    Ok(pkey)
}

/// 分配带 pkey 标记的内存（使用外部传入的 pkey）
///
/// 此函数由 runtime.rs 中的新版 `pal_svsm_mpk_alloc` 处理函数调用。
///
/// ## 与旧版 `mpk_allocate` 的区别
///
/// 旧版 `mpk_allocate` 内部自动分配 pkey；本函数接受外部传入的 pkey，
/// 实现 pkey 分配与内存分配的解耦，支持六接口方案中的独立 pkey 管理。
///
/// ## 参数
///
/// - `page_table_cr3`: VMPL-1 进程的页表基址 (来自 VMSA.cr3)
/// - `addr`: 虚拟地址 (由 VMPL-1 确定，必须页对齐)
/// - `size`: 大小 (字节，必须页对齐)
/// - `pkey`: 要绑定到此内存区域的 pkey (1-15，由 pkey_alloc_only 分配)
///
/// ## 返回值
///
/// - `Ok(())`: 成功
/// - `Err(3)`: 地址已被使用
pub fn mpk_alloc_memory(page_table_cr3: u64, addr: u64, size: u64, pkey: u32) -> Result<(), u32> {
    let mut manager = MPK_MANAGER.lock();

    // 1. 检查地址是否已分配
    if manager.allocations.contains_key(&addr) {
        log::warn!("[MPK] mpk_alloc_memory: addr {:#x} already allocated", addr);
        return Err(3);  // 错误码 3: 地址已被使用
    }

    // 2. 设置 VMPL-1 进程的页表引用（复用 Wallet 项目的 ProcessPageTableRef）
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(page_table_cr3);

    // 3. 计算页数并创建带 pkey 的页标志
    let page_count = size / 4096;
    let flags = ProcessPageFlags::data_with_pkey(pkey);

    // 4. 分配物理页并建立映射（复用 Wallet 项目的 add_pages）
    //    add_pages() 内部会：分配物理页、清零、rmp_adjust、设置 PTE flags
    page_table_ref.add_pages(VirtAddr::from(addr), page_count, flags);

    // 5. 记录分配信息
    manager.allocations.insert(addr, MpkAllocation { pkey, size });

    log::info!("[MPK] mpk_alloc_memory: addr={:#x}, size={}, pkey={}, pages={}",
               addr, size, pkey, page_count);

    Ok(())
}

/// 仅释放内存（不释放 pkey）
///
/// 此函数由 runtime.rs 中的 `pal_svsm_mpk_free` 处理函数调用（新语义）。
///
/// ## 功能
///
/// 1. 查找分配记录并验证大小
/// 2. 遍历每页清除 PTE 中的 pkey 标记（clear_pkey）
/// 3. 释放物理页并解除映射（remove_pages）
/// 4. 删除分配记录
/// 5. **不归还 pkey**——pkey 仍保持已分配状态
///
/// ## 参数
///
/// - `page_table_cr3`: VMPL-1 进程的页表基址
/// - `addr`: 虚拟地址
/// - `size`: 大小
///
/// ## 返回值
///
/// - `Ok(())`: 成功
/// - `Err(2)`: 地址未找到
/// - `Err(4)`: 大小不匹配
pub fn mpk_free_memory(page_table_cr3: u64, addr: u64, size: u64) -> Result<(), u32> {
    let mut manager = MPK_MANAGER.lock();

    // 1. 查找分配记录
    let alloc = manager.allocations.get(&addr).ok_or(2u32)?;  // 错误码 2: 地址未找到

    // 2. 验证大小匹配
    if alloc.size != size {
        log::warn!("[MPK] mpk_free_memory: size mismatch, expected {}, got {}", alloc.size, size);
        return Err(4);  // 错误码 4: 大小不匹配
    }

    let pkey = alloc.pkey;

    // 3. 设置页表引用
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(page_table_cr3);

    // 4. 遍历每页清除 PTE 中的 pkey 标记
    //    在释放物理页之前先清除 pkey 位，确保页表干净。
    //    注意：不在此处逐页清零内存内容，因为逐页创建 PerCPUPageMappingGuard
    //    映射开销过大（256 页 = 2500+ 次临时映射），会导致系统卡死。
    //    内存清零由 Wallet 项目的 map_4k_pages() 在下次分配时自动完成
    //    （通过 replace(s, ZERO_PAGE) 清零新分配的页面）。
    let page_count = size / 4096;
    for i in 0..page_count {
        let vaddr = VirtAddr::from(addr + i * 4096);

        // // 4a. 通过页表查找物理地址，映射后清零页面内容
        // let phys_addr = page_table_ref.get_page(vaddr);
        // if phys_addr != PhysAddr::null() {
        //     let (_mapping, page_data) = paddr_as_u64_slice!(phys_addr);
        //     // 用全零页覆盖内存内容（复用 Wallet 项目的 ZERO_PAGE 常量）
        //     _ = unsafe { replace(page_data, ZERO_PAGE) };
        // }

        // 4b. 清除 PTE 中的 pkey 位，确保页表干净
        page_table_ref.clear_pkey(vaddr);
    }

    // 5. 释放物理页并解除映射（复用 Wallet 项目的 remove_pages）
    page_table_ref.remove_pages(VirtAddr::from(addr), page_count);

    // 6. 删除分配记录（不归还 pkey）
    manager.allocations.remove(&addr);

    log::info!("[MPK] mpk_free_memory: addr={:#x}, size={}, pkey={} (pkey retained)",
               addr, size, pkey);

    Ok(())
}

/// 释放 pkey（可选同时释放内存）
///
/// 此函数由 runtime.rs 中的 `pal_svsm_mpk_free_pkey` 处理函数调用。
///
/// ## 功能
///
/// 组合操作：
/// 1. 若 addr != 0 且 size != 0，先调用 mpk_free_memory() 释放内存
/// 2. 在 PkeyAllocator 位图中归还 pkey
///
/// ## 参数
///
/// - `pkey`: 要释放的 pkey (1-15)
/// - `page_table_cr3`: VMPL-1 进程的页表基址
/// - `addr`: 虚拟地址（0 表示不释放内存）
/// - `size`: 大小（0 表示不释放内存）
///
/// ## 返回值
///
/// - `Ok(())`: 成功
/// - `Err(错误码)`: mpk_free_memory 失败时透传错误码
pub fn mpk_free_pkey(pkey: u32, page_table_cr3: u64, addr: u64, size: u64) -> Result<(), u32> {
    // 1. 若有内存需要释放，先释放内存
    if addr != 0 && size != 0 {
        mpk_free_memory(page_table_cr3, addr, size)?;
    }

    // 2. 归还 pkey 到空闲池
    let mut manager = MPK_MANAGER.lock();
    manager.pkey_allocator.free(pkey);

    log::info!("[MPK] mpk_free_pkey: pkey={} freed", pkey);

    Ok(())
}

/* ========== [MPK-DEV] 调试辅助函数（可选） ========== */

/// 获取当前已分配的 pkey 数量（调试用）
#[allow(dead_code)]
pub fn get_allocated_pkey_count() -> u32 {
    let manager = MPK_MANAGER.lock();
    // 计算位图中为 1 的位数（不包括 pkey 0）
    // count_ones() 返回 u32，直接返回即可，无需类型转换
    manager.pkey_allocator.bitmap.count_ones() - 1
}

/// 获取当前分配记录数量（调试用）
#[allow(dead_code)]
pub fn get_allocation_count() -> usize {
    let manager = MPK_MANAGER.lock();
    manager.allocations.len()
}

/* ========== [MPK-DEV] MPK 内存管理器模块结束 ========== */
