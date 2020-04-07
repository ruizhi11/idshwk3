global a: set[addr];
global r: table[addr] of set[string];

event zeek_init()
	{
	}
event new_connection(c:connection)
	{
	}
event http_header(c:connection, is_orig:bool, name:string, value:string)
	{
	if (!(c$id$orig_h in a))
	{
	add a[c$id$orig_h];
	r[c$id$orig_h]=set();
	}
	if (name == "USER-AGENT")
	{
	add r[c$id$orig_h][to_lower(value)];
	}
	}
event zeek_done()
	{
	for (i in a)
	{
	if (|r[i]|>=3)
		print fmt("%s is a proxy",i);
	}
	}
