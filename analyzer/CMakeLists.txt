spicy_add_analyzer(
    NAME SSDP
    PACKAGE_NAME zeek-parser-SSDP
    SOURCES ssdp.spicy ssdp.evt zeek_ssdp.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
