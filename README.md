# rawdns

cat open_test|go run main.go

Gopacket works really fine. This flings DNS requests (in fact the same DNS request near enough) at lots of servers but 
could be adapted to do something else. Fire and forget.

Go is more than capable of producing something akin to Massdns - would be interesting to have a event loop and attempt 
to do this with http. Gopacket has a lot of stuff for packet reassembly and it would only be small packets..
