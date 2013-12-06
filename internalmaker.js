"use strict";

var internal = require('./internal');
var _ = require('underscorem')
/*
var user;
exports.getUser = function(){
	_.assertDefined(user)
	return user;
}
*/
exports.make = function(hosts, cb){
	_.assertLength(arguments, 2)
	
	internal.make(hosts, function(ii){
		_.assertFunction(ii.findUser)
		//user = ii;
		if(cb) cb(ii)
	});
}

