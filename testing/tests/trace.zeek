# @TEST-DOC: Test Zeek parsing a trace file through the SSDP analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/udp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff ssdp.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event SSDP::message(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing SSDP: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
    }
