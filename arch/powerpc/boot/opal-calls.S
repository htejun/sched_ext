/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2016 IBM Corporation.
 */

#include "ppc_asm.h"
#include "../include/asm/opal-api.h"

	.text

	.globl opal_kentry
opal_kentry:
	/* r3 is the fdt ptr */
	mtctr r4
	li	r4, 0
	li	r5, 0
	li	r6, 0
	li	r7, 0
	LOAD_REG_ADDR(r11, opal)
	ld	r8,0(r11)
	ld	r9,8(r11)
	bctr

#define OPAL_CALL(name, token)				\
	.globl name;					\
name:							\
	li	r0, token;				\
	b	opal_call;

opal_call:
	mflr	r11
	std	r11,16(r1)
	mfcr	r12
	stw	r12,8(r1)
	mr	r13,r2

	/* Set opal return address */
	LOAD_REG_ADDR(r11, opal_return)
	mtlr	r11
	mfmsr	r12

	/* switch to BE when we enter OPAL */
	li	r11,MSR_LE
	andc	r12,r12,r11
	mtspr	SPRN_HSRR1,r12

	/* load the opal call entry point and base */
	LOAD_REG_ADDR(r11, opal)
	ld	r12,8(r11)
	ld	r2,0(r11)
	mtspr	SPRN_HSRR0,r12
	hrfid

opal_return:
	FIXUP_ENDIAN
	mr	r2,r13;
	lwz	r11,8(r1);
	ld	r12,16(r1)
	mtcr	r11;
	mtlr	r12
	blr

OPAL_CALL(opal_console_write,			OPAL_CONSOLE_WRITE);
OPAL_CALL(opal_console_read,			OPAL_CONSOLE_READ);
OPAL_CALL(opal_console_write_buffer_space,	OPAL_CONSOLE_WRITE_BUFFER_SPACE);
OPAL_CALL(opal_poll_events,			OPAL_POLL_EVENTS);
OPAL_CALL(opal_console_flush,			OPAL_CONSOLE_FLUSH);
