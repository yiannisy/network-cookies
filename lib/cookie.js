struct = restruct.
    int32lu('chip').
    int32lu('pad1').
    int32lu('timestamp').
    int32lu('pad2').
    string('uuid', 16).
    string('sig', 16);

struct_sig = restruct.
    int32lu('chip').
    int32lu('pad1').
    int32lu('timestamp').
    int32lu('pad2').
    string('uuid', 16);

function CookieDescriptor(chip, seed) {
    this.chip = chip;
    this.seed = seed;

    this.generateCookie = function() {
	return new Cookie(this.chip, this.seed);
    }
}

function Cookie(chip, seed) {
    this.chip = chip;
    this.seed = seed;

    // Create a cookie
    do {
	// Timestamp
	this.timestamp = Math.floor(Date.now() / 1000);

	// UUID
	this.uuid = Math.uuid();

	var str = this.chip + "\r\n" + this.timestamp + "\r\n" + this.uuid;
    
	// Signature
	this.sig = asmCrypto.HMAC_SHA1.hex(str, this.seed);

	// Concatenate value using \r\n as delimiter. 
	this.cookie_raw_value = this.chip + "\r\n" + this.timestamp + "\r\n" + this.uuid + "\r\n" + this.sig;
    }
    // Check that only 3 delimiters are present.
    // Otherwise (e.g., in the rare case there is one in the signature create a new one).
    while (this.cookie_raw_value.match(/\r\n/g).length != 3);
    
    this.toBytes = function() {
	
	vals =  struct.pack({chip:this.chip, timestamp:this.timestamp,
			    uuid:this.uuid, sig:this.sig});
	_data = new ArrayBuffer(vals.length);
	for (var i = 0; i < vals.length; i++) {
	    _data[i] = vals[i];
	}
	data = new Uint8Array(_data);
	return data;
    }

    this.toString = function() {
	return btoa(this.cookie_raw_value);
    }
}
