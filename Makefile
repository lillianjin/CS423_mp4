#
# Makefile for the kernel security code
#

obj-$(CONFIG_KEYS)                      += keys/
subdir-$(CONFIG_SECURITY_SELINUX)       += selinux
subdir-$(CONFIG_SECURITY_SMACK)         += smack
subdir-$(CONFIG_SECURITY_TOMOYO)        += tomoyo
subdir-$(CONFIG_SECURITY_APPARMOR)      += apparmor                                                                                       5,1           13%
subdir-$(CONFIG_SECURITY_YAMA)          += yama
subdir-$(CONFIG SECURITY MP4 LSM)       += mp4

# always enable default capabilities
obj-y                                   += commoncap.o
obj-$(CONFIG_MMU)                       += min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)                  += security.o
obj-$(CONFIG_SECURITYFS)                += inode.o
obj-$(CONFIG_SECURITY_SELINUX)          += selinux/
obj-$(CONFIG_SECURITY_SMACK)            += smack/
obj-$(CONFIG_AUDIT)                     += lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)           += tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)         += apparmor/
obj-$(CONFIG_SECURITY_YAMA)             += yama/
obj-$(CONFIG_CGROUP_DEVICE)             += device_cgroup.o
obj-$(CONFIG SECURITY MP4 LSM)          += mp4/

# Object integrity file lists
subdir-$(CONFIG_INTEGRITY)              += integrity
obj-$(CONFIG_INTEGRITY)                 += integrity/