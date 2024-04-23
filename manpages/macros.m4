changequote(<,>)dnl
dnl
define(<manpage_define>, defn(<define>))dnl
define(<manpage_divert>, defn(<divert>))dnl
define(<manpage_ifelse>, defn(<ifelse>))dnl
define(<manpage_popdef>, defn(<popdef>))dnl
define(<manpage_pushdef>, defn(<pushdef>))dnl
define(<manpage_dnl>, defn(<dnl>))dnl
dnl
define(<manpage_include>,
<manpage_pushdef(<manpage_divnus>, manpage_divnum)>)dnl
dnl
define(<manpage_exclude>,
<manpage_pushdef(<manpage_divnus>, manpage_divnum)dnl
manpage_define(<manpage_divnum>, <-1>)dnl
manpage_divert(<-1>)>)dnl
dnl
define(<manpage_else>,
<manpage_ifelse(manpage_divnus, <-1>, <>,
    <manpage_ifelse(manpage_divnum, <0>,
        <manpage_define(<manpage_divnum>, <-1>)manpage_divert(<-1>)>,
        <manpage_define(<manpage_divnum>,  <0>)manpage_divert( <0>)>)>)>)dnl
dnl
define(<manpage_end>,
<manpage_define(<manpage_divnum>, manpage_divnus)dnl
manpage_popdef(<manpage_divnus>)dnl
manpage_divert(manpage_divnum)>)dnl
dnl
pushdef(<manpage_divnus>, <0>)dnl
define(<manpage_divnum>, manpage_divnus)dnl
