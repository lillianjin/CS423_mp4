#
# Makefile for the MP4 LSM
#
ubdir-$(CONFIG SECURITY MP4 LSM) += mp4
obj-$(CONFIG SECURITY MP4 LSM) += mp4/
obj-$(CONFIG_SECURITY_MP4_LSM) := mp4.o
