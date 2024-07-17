changequote([[,]])dnl
dnl
define([[codegen_define]], defn([[define]]))dnl
define([[codegen_divert]], defn([[divert]]))dnl
define([[codegen_ifelse]], defn([[ifelse]]))dnl
define([[codegen_popdef]], defn([[popdef]]))dnl
define([[codegen_pushdef]], defn([[pushdef]]))dnl
define([[codegen_dnl]], defn([[dnl]]))dnl
dnl
define([[codegen_include]],
[[codegen_pushdef([[codegen_divnus]], codegen_divnum)]])dnl
dnl
define([[codegen_exclude]],
[[codegen_pushdef([[codegen_divnus]], codegen_divnum)dnl
codegen_define([[codegen_divnum]], [[-1]])dnl
codegen_divert([[-1]])]])dnl
dnl
define([[codegen_else]],
[[codegen_ifelse(codegen_divnus, [[-1]], [[]],
    [[codegen_ifelse(codegen_divnum, [[0]],
        [[codegen_define([[codegen_divnum]], [[-1]])codegen_divert([[-1]])]],
        [[codegen_define([[codegen_divnum]],  [[0]])codegen_divert( [[0]])]])]])]])dnl
dnl
define([[codegen_end]],
[[codegen_define([[codegen_divnum]], codegen_divnus)dnl
codegen_popdef([[codegen_divnus]])dnl
codegen_divert(codegen_divnum)]])dnl
dnl
pushdef([[codegen_divnus]], [[0]])dnl
define([[codegen_divnum]], codegen_divnus)dnl
