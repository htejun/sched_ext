// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/poison.h>

struct bpf_rbtree {
	struct bpf_map map;
	struct rb_root_cached root;
	struct bpf_spin_lock *lock;
	struct bpf_map *lock_map;
};

static bool __rbtree_lock_held(struct bpf_rbtree *tree)
{
	return spin_is_locked((spinlock_t *)tree->lock);
}

static int rbtree_map_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries || !attr->btf_value_type_id)
		return -EINVAL;

	return 0;
}

static void __rbtree_map_free(struct bpf_rbtree *tree)
{
	if (tree->lock_map)
		bpf_map_put(tree->lock_map);
	else if (tree->lock)
		kfree(tree->lock);
	bpf_map_area_free(tree);
}

static struct bpf_map *rbtree_map_alloc(union bpf_attr *attr)
{
	u32 lock_map_ufd, lock_map_offset;
	struct bpf_rbtree *tree;
	u64 lock_map_addr;
	int numa_node;
	int err;

	if (!bpf_capable())
		return ERR_PTR(-EPERM);

	if (attr->value_size == 0)
		return ERR_PTR(-EINVAL);

	numa_node = bpf_map_attr_numa_node(attr);
	tree = bpf_map_area_alloc(sizeof(*tree), numa_node);
	if (!tree)
		return ERR_PTR(-ENOMEM);

	tree->root = RB_ROOT_CACHED;
	bpf_map_init_from_attr(&tree->map, attr);

	if (!attr->map_extra) {
		tree->lock = bpf_map_kzalloc(&tree->map, sizeof(struct bpf_spin_lock),
					     GFP_KERNEL | __GFP_NOWARN);
		if (!tree->lock) {
			err = -ENOMEM;
			goto err_free;
		}
	} else {
		lock_map_ufd = (u32)(attr->map_extra >> 32);
		lock_map_offset = (u32)attr->map_extra;
		tree->lock_map = bpf_map_get(lock_map_ufd);
		if (IS_ERR(tree->lock_map) || !tree->lock_map->ops->map_direct_value_addr) {
			err = PTR_ERR(tree->lock_map);
			tree->lock_map = NULL;
			goto err_free;
		}

		err = tree->lock_map->ops->map_direct_value_addr(tree->lock_map, &lock_map_addr,
								 lock_map_offset);
		if (err)
			goto err_free;

		tree->lock = (struct bpf_spin_lock *)(lock_map_addr + lock_map_offset);
	}

	return &tree->map;
err_free:
	__rbtree_map_free(tree);
	return ERR_PTR(err);
}

static struct rb_node *rbtree_map_alloc_node(struct bpf_map *map, size_t sz)
{
	struct rb_node *node;

	node = bpf_map_kmalloc_node(map, sz, GFP_NOWAIT, map->numa_node);
	if (!node)
		return NULL;
	RB_CLEAR_NODE(node);
	return node;
}

BPF_CALL_2(bpf_rbtree_alloc_node, struct bpf_map *, map, u32, sz)
{
	struct rb_node *node;

	if (map->map_type != BPF_MAP_TYPE_RBTREE)
		return (u64)NULL;

	if (sz < sizeof(*node))
		return (u64)NULL;

	node = rbtree_map_alloc_node(map, (size_t)sz);
	if (!node)
		return (u64)NULL;

	return (u64)node;
}

const struct bpf_func_proto bpf_rbtree_alloc_node_proto = {
	.func = bpf_rbtree_alloc_node,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

BPF_CALL_3(bpf_rbtree_add, struct bpf_map *, map, void *, value, void *, cb)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);
	struct rb_node *node = (struct rb_node *)value;

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	if (WARN_ON_ONCE(!RB_EMPTY_NODE(node)))
		return (u64)NULL;

	rb_add_cached(node, &tree->root, (bool (*)(struct rb_node *, const struct rb_node *))cb);
	return (u64)node;
}

const struct bpf_func_proto bpf_rbtree_add_proto = {
	.func = bpf_rbtree_add,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL | OBJ_NON_OWNING_REF | CONDITIONAL_RELEASE,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID | OBJ_RELEASE,
	.arg2_btf_id = BPF_PTR_POISON,
	.arg3_type = ARG_PTR_TO_FUNC,
};

BPF_CALL_3(bpf_rbtree_find, struct bpf_map *, map, void *, key, void *, cb)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	return (u64)rb_find(key, &tree->root.rb_root,
			    (int (*)(const void *key,
				     const struct rb_node *))cb);
}

const struct bpf_func_proto bpf_rbtree_find_proto = {
	.func = bpf_rbtree_find,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL | OBJ_NON_OWNING_REF,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_PTR_TO_FUNC,
};

BPF_CALL_1(bpf_rbtree_first, struct bpf_map *, map)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	return (u64)rb_first_cached(&tree->root);
}

const struct bpf_func_proto bpf_rbtree_first_proto = {
	.func = bpf_rbtree_first,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL/* | PTR_ITER*/ | OBJ_NON_OWNING_REF,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
};

BPF_CALL_1(bpf_rbtree_last, struct bpf_map *, map)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	return (u64)rb_last(&tree->root.rb_root);
}

const struct bpf_func_proto bpf_rbtree_last_proto = {
	.func = bpf_rbtree_last,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL | PTR_ITER | OBJ_NON_OWNING_REF,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
};

BPF_CALL_2(bpf_rbtree_next, struct bpf_map *, map, void *, cur)
{
	struct rb_node *next = rb_next((struct rb_node *)cur);
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	return (u64)next;
}

const struct bpf_func_proto bpf_rbtree_next_proto = {
	.func = bpf_rbtree_next,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL | PTR_ITER_END | OBJ_NON_OWNING_REF,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID | PTR_ITER,
	.arg2_btf_id = BPF_PTR_POISON,
};

BPF_CALL_2(bpf_rbtree_prev, struct bpf_map *, map, void *, cur)
{
	struct rb_node *node = (struct rb_node *)cur;
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	return (u64)rb_prev(node);
}

const struct bpf_func_proto bpf_rbtree_prev_proto = {
	.func = bpf_rbtree_prev,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL | PTR_ITER_END | OBJ_NON_OWNING_REF,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID | PTR_ITER,
	.arg2_btf_id = BPF_PTR_POISON,
};

/* Like rbtree_postorder_for_each_entry_safe, but 'pos' and 'n' are
 * 'rb_node *', so field name of rb_node within containing struct is not
 * needed.
 *
 * Since bpf_rb_tree's node always has 'struct rb_node' at offset 0 it's
 * not necessary to know field name or type of node struct
 */
#define bpf_rbtree_postorder_for_each_entry_safe(pos, n, root) \
	for (pos = rb_first_postorder(root); \
	     pos && ({ n = rb_next_postorder(pos); 1; }); \
	     pos = n)

static void rbtree_map_free(struct bpf_map *map)
{
	struct rb_node *pos, *n;
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	bpf_rbtree_postorder_for_each_entry_safe(pos, n, &tree->root.rb_root)
		kfree(pos);
	__rbtree_map_free(tree);
}

static int rbtree_map_check_btf(const struct bpf_map *map,
				const struct btf *btf,
				const struct btf_type *key_type,
				const struct btf_type *value_type)
{
	if (!map_value_has_rb_node(map))
		return -EINVAL;

	if (map->rb_node_off > 0)
		return -EINVAL;

	return 0;
}

static int rbtree_map_push_elem(struct bpf_map *map, void *value, u64 flags)
{
	/* Use bpf_rbtree_add helper instead
	 */
	return -ENOTSUPP;
}

static int rbtree_map_pop_elem(struct bpf_map *map, void *value)
{
	return -ENOTSUPP;
}

static int rbtree_map_peek_elem(struct bpf_map *map, void *value)
{
	return -ENOTSUPP;
}

static void *rbtree_map_lookup_elem(struct bpf_map *map, void *value)
{
	/* Use bpf_rbtree_find helper instead
	 */
	return ERR_PTR(-ENOTSUPP);
}

static int rbtree_map_update_elem(struct bpf_map *map, void *key, void *value,
				  u64 flags)
{
	return -ENOTSUPP;
}

static int rbtree_map_delete_elem(struct bpf_map *map, void *value)
{
	return -ENOTSUPP;
}

static bool rbtree_map_lock_held(struct bpf_map *map, void *current_lock)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	return tree->lock == current_lock;
}

BPF_CALL_2(bpf_rbtree_remove, struct bpf_map *, map, void *, value)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);
	struct rb_node *node = (struct rb_node *)value;

	if (!__rbtree_lock_held(tree))
		return (u64)NULL;

	if (WARN_ON_ONCE(RB_EMPTY_NODE(node)))
		return (u64)NULL;

	rb_erase_cached(node, &tree->root);
	RB_CLEAR_NODE(node);
	return (u64)node;
}

const struct bpf_func_proto bpf_rbtree_remove_proto = {
	.func = bpf_rbtree_remove,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id = BPF_PTR_POISON,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID,
	.arg2_btf_id = BPF_PTR_POISON,
};

BPF_CALL_2(bpf_rbtree_free_node, struct bpf_map *, map, void *, value)
{
	struct rb_node *node = (struct rb_node *)value;

	WARN_ON_ONCE(!RB_EMPTY_NODE(node));
	kfree(node);
	return 0;
}

const struct bpf_func_proto bpf_rbtree_free_node_proto = {
	.func = bpf_rbtree_free_node,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID | OBJ_RELEASE,
	.arg2_btf_id = BPF_PTR_POISON,
};

static int rbtree_map_get_next_key(struct bpf_map *map, void *key,
				   void *next_key)
{
	return -ENOTSUPP;
}

BPF_CALL_1(bpf_rbtree_get_lock, struct bpf_map *, map)
{
	struct bpf_rbtree *tree = container_of(map, struct bpf_rbtree, map);

	return (u64)tree->lock;
}

const struct bpf_func_proto bpf_rbtree_get_lock_proto = {
	.func = bpf_rbtree_get_lock,
	.gpl_only = true,
	.ret_type = RET_PTR_TO_SPIN_LOCK,
	.arg1_type = ARG_CONST_MAP_PTR,
};

extern void __bpf_spin_unlock_irqrestore(struct bpf_spin_lock *lock);
extern void __bpf_spin_lock_irqsave(struct bpf_spin_lock *lock);

BPF_CALL_1(bpf_rbtree_lock, void *, lock)
{
	__bpf_spin_lock_irqsave((struct bpf_spin_lock *)lock);
	return 0;
}

const struct bpf_func_proto bpf_rbtree_lock_proto = {
	.func = bpf_rbtree_lock,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_SPIN_LOCK,
};

BPF_CALL_1(bpf_rbtree_unlock, void *, lock)
{
	__bpf_spin_unlock_irqrestore((struct bpf_spin_lock *)lock);
	return 0;
}

const struct bpf_func_proto bpf_rbtree_unlock_proto = {
	.func = bpf_rbtree_unlock,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_SPIN_LOCK,
};

BPF_CALL_3(bpf_rbtree_node_xchg, struct bpf_map *, map, void *, map_value, void *, ptr)
{
        unsigned long *kptr = map_value;

        return xchg(kptr, (unsigned long)ptr);
}

const struct bpf_func_proto bpf_rbtree_node_xchg_proto = {
	.func         = bpf_rbtree_node_xchg,
	.gpl_only     = true,
	.ret_type     = RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id   = BPF_PTR_POISON,
	.arg1_type    = ARG_CONST_MAP_PTR,
	.arg2_type    = ARG_ANYTHING,
	.arg3_type    = ARG_PTR_TO_BTF_ID_OR_NULL | OBJ_RELEASE,
	.arg3_btf_id  = BPF_PTR_POISON,
};

BTF_ID_LIST_SINGLE(bpf_rbtree_map_btf_ids, struct, bpf_rbtree)
const struct bpf_map_ops rbtree_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = rbtree_map_alloc_check,
	.map_alloc = rbtree_map_alloc,
	.map_free = rbtree_map_free,
	.map_get_next_key = rbtree_map_get_next_key,
	.map_push_elem = rbtree_map_push_elem,
	.map_peek_elem = rbtree_map_peek_elem,
	.map_pop_elem = rbtree_map_pop_elem,
	.map_lookup_elem = rbtree_map_lookup_elem,
	.map_update_elem = rbtree_map_update_elem,
	.map_delete_elem = rbtree_map_delete_elem,
	.map_check_btf = rbtree_map_check_btf,
	.map_btf_id = &bpf_rbtree_map_btf_ids[0],
	.map_lock_held = rbtree_map_lock_held,
};
