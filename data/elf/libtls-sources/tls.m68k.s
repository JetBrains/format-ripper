	.text
	.globl	get
	.type	get, @function
get:
	moveq	#0, %d0
	rts
	.size	get, .-get

	.section	.tdata, "awT", @progbits
	.balign	4
	.globl	tdata_var
	.type	tdata_var, @object
	.size	tdata_var, 4
tdata_var:
	.long	0x11223344
	.globl	tdata_var2
	.type	tdata_var2, @object
	.size	tdata_var2, 8
tdata_var2:
	.long	0x55667788, 0x99AABBCC

	.section	.tbss, "awT", @nobits
	.balign	4
	.globl	tbss_var
	.type	tbss_var, @object
	.size	tbss_var, 24
tbss_var:
	.zero	24
