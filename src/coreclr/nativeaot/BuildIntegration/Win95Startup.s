# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

# Windows 95 x86 SEH registration is a linked list at FS:[0].
.def @feat.00
    .scl 3
    .type 0
.endef
.set @feat.00, 1

.text
.extern _Win95ExceptionHandler
.extern _Win95Initialize
.extern _wmainCRTStartup
.safeseh _Win95ExceptionHandler

.globl _Win95Startup
_Win95Startup:
    calll _Win95Initialize
    testl %eax, %eax
    jz _wmainCRTStartup
    pushl $_Win95ExceptionHandler
    pushl %fs:0
    movl %esp, %fs:0
    calll _wmainCRTStartup
    popl %edx
    movl %edx, %fs:0
    addl $4, %esp
    retl

.globl _Win95CallThread
_Win95CallThread:
    pushl %ebp
    movl %esp, %ebp
    pushl $_Win95ExceptionHandler
    pushl %fs:0
    movl %esp, %fs:0
    pushl 12(%ebp)
    calll *8(%ebp)
    popl %edx
    movl %edx, %fs:0
    addl $4, %esp
    popl %ebp
    retl
