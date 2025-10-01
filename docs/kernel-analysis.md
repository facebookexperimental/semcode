# Linux Kernel Analysis Examples

This document provides examples of using semcode to analyze the Linux kernel.

## Common Analysis Scenarios

### 1. Memory Management Functions

Index memory management subsystem:
```bash
./bin/semcode-index \
    --source /path/to/linux/mm \
    --database ./mm.db \
    --batch-size 50
```

Query memory allocation functions:
```
semcode> func kmalloc
semcode> func vmalloc
semcode> func __get_free_pages
semcode> func alloc_pages
semcode> type struct page
semcode> type struct mm_struct
```

### 2. File System Analysis

Index a specific file system (e.g., ext4):
```bash
./bin/semcode-index \
    --source /path/to/linux/fs/ext4 \
    --database ./ext4.db
```

Query file system structures:
```
semcode> type struct inode
semcode> type struct dentry
semcode> type struct file
semcode> func ext4_readdir
semcode> func ext4_create
```

### 3. Network Stack Analysis

Index networking code:
```bash
./bin/semcode-index \
    --source /path/to/linux/net \
    --database ./net.db \
    --max-depth 8
```

Query networking functions:
```
semcode> type struct sk_buff
semcode> type struct socket
semcode> func tcp_sendmsg
semcode> func ip_rcv
semcode> func netif_rx
```

### 4. Device Drivers

Index specific driver subsystems:
```bash
# USB drivers
./bin/semcode-index \
    --source /path/to/linux/drivers/usb \
    --database ./usb.db

# Network drivers
./bin/semcode-index \
    --source /path/to/linux/drivers/net \
    --database ./net-drivers.db
```

### 5. Core Kernel Functions

Index core kernel:
```bash
./bin/semcode-index \
    --source /path/to/linux/kernel \
    --database ./kernel-core.db
```

Query scheduler and process management:
```
semcode> func schedule
semcode> func wake_up_process
semcode> func do_fork
semcode> type struct task_struct
semcode> type struct sched_entity
```

## Advanced Queries

### Finding Lock Usage

Look for spinlock-related functions:
```
semcode> func spin_lock
semcode> func spin_unlock
semcode> func spin_lock_irqsave
semcode> type spinlock_t
semcode> type struct mutex
```

### Interrupt Handlers

```
semcode> func request_irq
semcode> func free_irq
semcode> type struct irq_desc
semcode> type irqreturn_t
```

### System Calls

```
semcode> func sys_open
semcode> func sys_read
semcode> func sys_write
semcode> func SYSCALL_DEFINE
```

## Performance Optimization

### Large-Scale Indexing

For indexing the entire kernel (slow but comprehensive):
```bash
./bin/semcode-index \
    --source /path/to/linux \
    --database ./full-kernel.db \
    --batch-size 500 \
    --max-depth 15
```

This may take 30-60 minutes depending on your system.

### Targeted Analysis

For faster, targeted analysis, index only the subsystems you're interested in:

```bash
# Create separate databases for different subsystems
for subsys in mm fs kernel drivers/net arch/x86; do
    ./bin/semcode-index \
        --source /path/to/linux/$subsys \
        --database ./${subsys//\//_}.db
done
```

## Integration with Development Workflow

### 1. Finding Function Implementations

When you encounter a function call in the kernel source:
```
semcode> func might_sleep
```

### 2. Understanding Data Structures

When you need to understand a complex structure:
```
semcode> type struct vm_area_struct
```

### 3. Tracing Call Paths

The tool shows both functions called by and functions that call a given function,
helping you trace execution paths through the kernel.

### 4. Checking Symbol Availability

Before using a kernel function in a module, verify it exists and understand its signature:
```
semcode> func kallsyms_lookup_name
```

## Tips

1. **Include Paths**: The indexer uses default include paths. For better results with the kernel, you might need to modify the clang arguments in the source code.

2. **Macros**: Complex kernel macros might not be fully expanded. The tool works best with actual function definitions.

3. **Headers**: Including header files in the indexing can provide more complete type information.

4. **Incremental Analysis**: Currently not supported, but you can create multiple databases for different subsystems and query them separately.
