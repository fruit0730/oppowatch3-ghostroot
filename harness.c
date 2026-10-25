/* Offset extraction harness for OW3 (ARM32, kernel 5.4.134).
 * Compile against the full kernel headers with -fdump-record-layouts
 * to dump exact struct field offsets/sizes for the GhostLock exploit. */
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/pipe_fs_i.h>
#include <linux/fs.h>
#include <linux/configfs.h>
#include <linux/rtmutex.h>

/* rt_mutex_waiter is defined in kernel/locking/rtmutex_common.h (not in
 * include/), so reproduce it here verbatim (5.4, CONFIG_DEBUG_RT_MUTEXES=n). */
struct rt_mutex_waiter_local {
	struct rb_node          tree_entry;
	struct rb_node          pi_tree_entry;
	struct task_struct	*task;
	struct rt_mutex		*lock;
	int prio;
	u64 deadline;
};

/* configfs_buffer is defined in fs/configfs/file.c, reproduce it here. */
struct configfs_buffer_local {
	size_t			count;
	loff_t			pos;
	char			* page;
	struct configfs_item_operations	* ops;
	struct mutex		mutex;
	int			needs_read_fill;
	bool			read_in_progress;
	bool			write_in_progress;
	char			*bin_buffer;
	int			bin_buffer_size;
	int			cb_max_size;
	struct config_item	*item;
	struct module		*owner;
	union {
		struct configfs_attribute	*attr;
		struct configfs_bin_attribute	*bin_attr;
	};
};

/* Reference the structs so the layout dump includes them. */
struct task_struct  *h_task;
struct mm_struct    *h_mm;
struct page         *h_page;
struct cred         *h_cred;
struct nsproxy      *h_nsproxy;
struct pipe_buffer  *h_pipe_buffer;
struct pipe_inode_info *h_pipe;
struct file         *h_file;
struct file_operations *h_fops;
struct configfs_buffer *h_cfg;
struct rt_mutex     *h_rt_mutex;
struct rt_mutex_waiter *h_rt_waiter;
struct rt_mutex_waiter_local *h_rt_waiter_l;
struct configfs_buffer *h_cfg;
struct configfs_buffer_local *h_cfg_l;

void *keep(void) {
  return (void *)(h_task || h_mm || h_page || h_cred || h_nsproxy ||
                  h_pipe_buffer || h_pipe || h_file || h_fops || h_cfg ||
                  h_rt_mutex || h_rt_waiter || h_rt_waiter_l || h_cfg_l);
}

/* Force complete-layout computation for the local/reproduced structs. */
struct rt_mutex __force_rtm;
struct rt_mutex_waiter_local __force_rtwl;
struct configfs_buffer_local __force_cfgl;
