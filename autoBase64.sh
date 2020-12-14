# to encode raw_list with base64 automatically
openssl base64 -in gfwlist_raw.txt | tr -d '\r' > gfwlist.txt
