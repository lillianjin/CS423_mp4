#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	/*
	 * Add your code here
	 * ...
	 */
	struct dentry *dentry;
	int sid, size = 128, ret;
	char * buffer;

	if(!inode){
		pr_err("inode is null\n");
		return ENOENT;
	}

	// grab a hashed alias of inode
	dentry = d_find_alias(inode);
	if(!dentry){
		pr_err("dentry is null\n");
		return ENOENT;
	} 

	buffer = kmalloc(size, GFP_KERNEL);
	if(!buffer){
		dput(dentry);
		pr_err("buffer not allocated\n");
		return -ENOMEM;
	}
	
	// get xattr of this inode
	if (!inode->i_op->getxattr) {
		kfree(buffer);
		dput(dentry);
		pr_err("xattr not exist\n");
		return -ENOENT;
	}

	ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, buffer, size);
	if(ret < 0 || ret == -ERANGE) {
		dput(dentry);
		kfree(buffer);
		return -ERANGE;
	}

	size = ret;
	buffer[size] = '\0';
	sid = __cred_ctx_to_sid(buffer);
	kfree(buffer);
	dput(dentry);

	return sid;
}

/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	/*
	 * Add your code here
	 * ...
	 */
	int sid;
	struct dentry * dentry;
	struct inode * inode;
	
	// if creds already prepared
	if (bprm->cred_prepared){
		pr_info("creds already prepared");
    	return ENOENT;
	}

	if(!bprm->cred || !bprm -> cred -> security || !bprm || !bprm->file){
		pr_info("cred is NULL");
    	return ENOENT;
	}

	dentry = bprm -> file -> f_path.dentry;
	if(!dentry){
		pr_info("dentry is NULL");
    	return ENOENT;
	}

	inode = dentry -> d_inode;
	if(!inode){
		pr_info("inode is NULL");
    	return ENOENT;
	}

	// read the xattr value of the inode used to create the process
	sid = get_inode_sid(inode);

	if (sid == MP4_TARGET_SID) {
		 ((struct mp4_security*)(bprm -> cred -> security)) -> mp4_flags = MP4_TARGET_SID;
	}
	
	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/*
	 * Add your code here
	 * ...
	 */
	struct mp4_security * new_blob;
	if(!cred){
		return -ENOMEM;
	}
	new_blob = kmalloc(sizeof(struct mp4_security), gfp);
	if(!new_blob){
		return -ENOMEM;
	}
	//initialized the label as MP4_NO_ACCESS
	new_blob -> mp4_flags = MP4_NO_ACCESS;
	// hook the pointer to new blob
	cred -> security = new_blob;
	return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	/*
	 * Add your code here
	 * ...
	 */
	if(!cred || !cred->security){
		return;
	}
	cred->security = NULL;
	kfree(cred -> security);
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	mp4_cred_alloc_blank(new, gfp);
	if(old->security){
		new -> security = old -> security;
	}

	return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
	// int sid = get_inode_sid(inode);
	// char * ptr1, ptr2, ptr3;

	// if(!current_cred() || !dir || !inode){

	// }
	return 0;
}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	
	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
