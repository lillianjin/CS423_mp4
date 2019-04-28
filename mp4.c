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
	int sid, size, ret;
	char * buffer;

	size = 100;

	if(!inode){
		pr_err("get_inode_sid: inode is null\n");
		return MP4_NO_ACCESS;
	}

	// grab a hashed alias of inode
	dentry = d_find_alias(inode);
	if(!dentry){
		pr_err("get_inode_sid: dentry is null\n");
		return MP4_NO_ACCESS;
	} 

	buffer = kmalloc(size, GFP_KERNEL);
	if(!buffer){
		dput(dentry);
		pr_err("get_inode_sid: buffer not allocated\n");
		return MP4_NO_ACCESS;
	}
	
	// get xattr of this inode
	if (!inode->i_op->getxattr) {
		dput(dentry);
		kfree(buffer);
		pr_err("get_inode_sid: xattr not exist\n");
		return MP4_NO_ACCESS;
	}

	// return value of the getxattr()
	ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, buffer, size);
	if(ret <= 0 || ret == -ERANGE) {
		dput(dentry);
		kfree(buffer);
		return MP4_NO_ACCESS;
	}

	buffer[ret] = '\0';
	sid = __cred_ctx_to_sid(buffer);
	dput(dentry);
	kfree(buffer);

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
	struct mp4_security * curr;
	
	pr_info("mp4 set credentials for a new task..");

	// if creds already prepared
	if (bprm->cred_prepared){
		pr_info("creds already prepared");
    	return MP4_NO_ACCESS;
	}

	if(!bprm || !bprm->cred || !bprm->cred->security ){
		pr_info("cred is NULL");
    	return MP4_NO_ACCESS;
	}

	if(!bprm->file || !bprm-> file->f_inode){
		pr_info("file is NULL");
    	return MP4_NO_ACCESS;
	}

	// read the xattr value of the inode used to create the process
	sid = get_inode_sid(bprm->file->f_inode);
	curr = (struct mp4_security *)(bprm->cred->security);

	if (sid == MP4_TARGET_SID) {
		curr->mp4_flags = sid;
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
	pr_info("mp4 allocates a blank label..");
	if(!cred){
		return -ENOENT;
	}
	new_blob = kzalloc(sizeof(struct mp4_security), gfp);
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
	pr_info("mp4 free a security label..");
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
	pr_info("mp4 prepare a new credential for modification..");
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
	int sid;
	char *tmp;

	if( !dir || !inode || !current_cred() || !(current_cred() -> security)) {
		return -EOPNOTSUPP;
	}

	sid = get_inode_sid(inode);
	if(sid == MP4_TARGET_SID) {
		if(XATTR_NAME_MP4){
			*name = XATTR_NAME_MP4;
			*len = sizeof(XATTR_NAME_MP4);
		} else {
			return -ENOMEM;
		}

		if(S_ISDIR(inode->i_mode)) {
			tmp = kstrdup("dir-write", GFP_KERNEL);
		} else {
			tmp = kstrdup("read-write", GFP_KERNEL);
		}

		if(!tmp){
			return -ENOMEM;
		}
		*value = tmp;
	}
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
	int rc = 0;
	switch (osid)
	{
	case MP4_NO_ACCESS:
		rc = -EACCES;
		break;

	case MP4_READ_OBJ:
		if((mask & MAY_WRITE) || (mask & MAY_EXEC) || (mask & MAY_APPEND)){
			rc = -EACCES;
		} else {
			rc = 0;
		}
		break;

	case MP4_WRITE_OBJ:
		if(ssid == MP4_TARGET_SID){
			if((mask & MAY_EXEC) || (mask & MAY_READ)){
				rc = -EACCES;
			} else {
				rc = 0;
			}
		} else{
			if((mask & MAY_WRITE) || (mask & MAY_EXEC) || (mask & MAY_APPEND)){
				rc = -EACCES;
			} else {
				rc = 0;
			}
		}
		break;
		
	case MP4_READ_WRITE:
		if(ssid == MP4_TARGET_SID){
			if(mask & MAY_EXEC){
				rc = -EACCES;
			} else {
				rc = 0;
			}
		} else {
			if((mask & MAY_WRITE) || (mask & MAY_EXEC) || (mask & MAY_APPEND)){
				rc = -EACCES;
			} else {
				rc = 0;
			}
		}
		break;

	case MP4_EXEC_OBJ:
		if((mask & MAY_APPEND) || (mask & MAY_WRITE)){
			rc = -EACCES;
		} else {
			rc = 0;
		}
		break;

	case MP4_READ_DIR:
		if(mask & MAY_WRITE){
			rc = -EACCES;
		} else {
			rc = 0;
		}
		break;
	
	case MP4_RW_DIR:
		rc = 0;
		break;
	}
	return rc;
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
	struct dentry * dentry;
	char * checked_path, * buffer;
	int size = 100;
	int ssid, osid, permission;

	if(!inode){
		pr_err("mp4_inode_permission: inode is null\n");
		return -EACCES;
	}

	// no permission to check
	if(!mask){
		pr_err("mp4_inode_permission: mask is null\n");
		return -EACCES;
	}

	//obtain the path of the inode being checked
	dentry = d_find_alias(inode);

	if(!dentry){
		pr_err("mp4_inode_permission: dentry is null\n");
		return -EACCES;
	} 

	buffer = kmalloc(size, GFP_KERNEL);
	if(!buffer){
		dput(dentry);
		pr_err("mp4_inode_permission: buffer not allocated\n");
		return -EACCES;
	}

	// get checked path
	checked_path = dentry_path_raw(dentry, buffer, size);
	if(!checked_path){
		kfree(buffer);
		dput(dentry);
		pr_err("mp4_inode_permission: path not found\n");
		return -EACCES;
	}

	// check if should skip
	if(mp4_should_skip_path(checked_path)){
		kfree(buffer);
		dput(dentry);
		pr_err("mp4_inode_permission: skip the path\n");
		return 0;
	}

	if(!current_cred()){
		kfree(buffer);
		dput(dentry);
		pr_err("mp4_inode_permission: current cred not found\n");
		return -EACCES;
	}

	if(!current_cred()->security){
		ssid = MP4_NO_ACCESS;
	} else {
		ssid = ((struct mp4_security *) current_cred()->security)->mp4_flags;
	}

	osid = get_inode_sid(inode);
	if(printk_ratelimit()) {
		pr_info("SSID: %d, OSID:%d, mask:%d\n", ssid, osid, mask);
	}

	permission = mp4_has_permission(ssid, osid, mask);
	if(printk_ratelimit()) {
		pr_info("permission: %d\n", permission);
	}

	kfree(buffer);
	dput(dentry);

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
