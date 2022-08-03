console.log('node run: rsacodec.js');




// usage:
// 1, include jsencrypt.js

var fs = require('fs');
eval(fs.readFileSync('./jsencrypt.min.js')+'');


// 2, encrypt

var encrypt = new JSEncrypt();
encrypt.setPublicKey('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDs+SfHVT2dWL6sbUOg7zFh/nbtltf2UPvh2W2EJdGGawbv0Z8ekcd/aSA40VlK8apf0/gaywpphCJXbbpwzOTYUDoeYewaSpzhTEuIbGcZzoiSi9vjhV7PoZueu45X0kOZ7skxUDbriIRPzuUG1ahwuneGPdVOSUIrEixyxIAfwQIDAQAB');
var encrypted = encrypt.encrypt('sunnymix');
console.log(encrypted);
