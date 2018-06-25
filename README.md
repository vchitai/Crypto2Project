# Crypto2Project
##AS
###api/register_new_device
Client
-> [device_name, public_key]
{
	'device_name': device_name,
	'public_key': client_public_key
}

Server 
<- m = (device_id)
	[c = m^dc (Encrypt by client PublicKey), hash(m)]
{
	'c': c,
	'h': h
}
	
###api/new_connection
Client
-> [device_name]
{
	'device_name':device_name
}
Server 
<- m = (device_id, randomS, server_public_key)
	[c = m^dc, hash(m)]
{
	'c': c,
	'h': h
}

###api/connection_verify ['POST']
Client 
-> m = (randomC, randomS)
	[device_name, c = m^ec, hash(m)]
{
	'device_name': device_name
	'c': c,
	'h': h
}

Server
<- m = (randomC, publicKeySS, connectIP, messageForSS)
	[c = m^dc, hash(m)]
{
	'c': c,
	'h': h
}


##SS
###api/new_connection
Client 
-> m = (device_name, AESkey)
	[messageForSS, c = m^ec, hash(m)]
{
	'messageForSS', messageForSS
	'c': c,
	'h': h
}
Server
<- m = (AESkey, tokenSS)
	[c = m^dc, hash(m)]
{
	'c': c,
	'h': h
}

###api/store_message
Client 
-> m = (store_message)
BasicAuth tokenSS:"any pass phrase" [m Encrypted by AES, hash(m)]
{
	'c': c,
	'h': h
}
Server
<- 
{
	confirm: "success"/"fail"
}