    
__restore_fp:
    mv  t0 , a2
    ld  ra, (0*8)(t0)  
    ld  sp, (1*8)(t0)  
    ld  gp, (2*8)(t0)  
    ld  t2, (6*8)(t0)  
    ld  s0, (7*8)(t0)  
    ld  s1, (8*8)(t0)  
    ld  a2, (11*8)(t0) 
    ld  a3, (12*8)(t0) 
    ld  a4, (13*8)(t0) 
    ld  a5, (14*8)(t0) 
    ld  a6, (15*8)(t0) 
    ld  a7, (16*8)(t0) 
    ld  s2, (17*8)(t0) 
    ld  s3, (18*8)(t0) 
    ld  s4, (19*8)(t0) 
    ld  s5, (20*8)(t0) 
    ld  s6, (21*8)(t0) 
    ld  s7, (22*8)(t0) 
    ld  s8, (23*8)(t0) 
    ld  s9, (24*8)(t0) 
    ld  s10, (25*8)(t0)
    ld  s11, (26*8)(t0)
    ld  t3, (27*8)(t0) 
    ld  t4, (28*8)(t0) 
    ld  t5, (29*8)(t0) 
    ld  t6, (30*8)(t0) 
    ld  t1, (3*8)(t0)  
    add tp, t1, x0  
    ld  t1, (34*8)(t0)
    csrw sepc, t1  
    csrw sscratch, t0
    ld  t1, (32*8)(t0) 
    csrw sstatus, t1
    ld  t1, (5*8)(t0)
    ld  t0, (4*8)(t0) 
    sret