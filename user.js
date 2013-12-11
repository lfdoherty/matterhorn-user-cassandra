
//TODO - lost password reset
//TODO - session expiry

var internalmaker = require('./internalmaker')

var _ = require('underscorem');

exports.secure = require('./ssluser');
exports.insecure = require('./insecureuser');

var log = require('quicklog').make('user-cassandra/api')


function makeAuthenticate(internal, prefix){
	return function authenticate(req, res, next){
		//console.log('authenticating: ' + JSON.stringify(req.cookies));

		if(req.cookies.SID === undefined){
			doLoginRedirect();
			return;
		}

		/*var pi = req.cookies.SID.indexOf('|')
		if(pi === -1){
			doLoginRedirect();
			return;
		}*/
	
		//console.log('cookies: ' + JSON.stringify(req.cookies))
		/*if(req.cookies.LOGGEDOUT){
			doLoginRedirect()
			return
		}*/
		var sid = req.cookies.SID//.substr(0, pi);

		function doLoginRedirect(){
			var protocol = req.headers["x-forwarded-proto"] || req.protocol
			
			//console.log('*redirecting to ' + secureHost+'/login?next='+req.headers.host+req.url + ' ' + protocol);
			//console.log(JSON.stringify(req.headers))
			//res.redirect(secureHost+'/login?next=' + host + req.url);
			var newUrl = 'https://' + req.headers.host + prefix+'/login?next='+protocol+'://' + req.headers.host + req.url
			//console.log('*redirecting to: ' + newUrl)
			res.header('Cache-Control', 'no-cache, no-store')
			res.redirect(newUrl);
		}


		internal.checkSession(sid, function(ok, userId){
			if(ok){
				//_.assertInt(userId)
				internal.getEmail(userId, function(email){
					req.user = {id: userId, email: email};
					req.userToken = userId
					req.email = email
					//console.log('session ok: ' + userId)
					next();
				});
			}else{
				//util.debug('redirecting to login');
				doLoginRedirect();
			}
		});
	}
}
exports.makeClient = function(hosts, prefix, cb){
	internalmaker.make(hosts, function(internal){
		_.assertDefined(internal)

		var handle = {
			getEmail: function(userId, cb){
				exports.getEmail(userId, cb)
			}
		}
	
		handle.hasSession = hasSession = function(req, cb){
			var sid = req.cookies.SID;
			if(sid === undefined){
				log('no SID cookie found')
				cb(false);
			}else{
				sid = sid.substr(0, sid.indexOf('|'))
				internal.checkSession(sid, function(ok, userId){
					cb(ok);
				});
			}
		}
		
		function authenticateByToken(token, cb){
			_.assertString(token)
			_.assertFunction(cb)
		
			internal.checkSession(token, function(ok, userId){
				if(ok){
					cb(undefined, userId)
				}else{
					cb('authentication failed')
				}
			});
		}
		

		handle.authenticateRequest = makeAuthenticate(internal, prefix)
		handle.authenticateByToken = authenticateByToken

		
		handle.findUser = internal.findUser
		handle.makeUser = internal.makeUser
		handle.authenticate = internal.authenticate
		handle.makeSession = internal.makeSession
		
		handle.getEmail = internal.getEmail
	
		cb(handle)
	})
}

exports.makeService = function(config,/*hosts, app, secureApp, host, secureHost, prefix,*/ cb, userMadeCb){
	//_.assertLength(arguments, 6)
	//_.assertObject(listeners)
	
	internalmaker.make(config.hosts, function(internal){
		_.assertDefined(internal)

		
		//var insecureAuthenticate = exports.insecure.load(app, secureHost, internal, makeAuthenticate(internal, prefix))
		var secureAuthenticate = exports.secure.load(config, internal,/*app, secureApp, host, secureHost, internal, prefix,*/ userMadeCb)
		
		cb()
	
		/*var handle = {
			//handle: insecureAuthenticate,
			insecureAuthenticate: insecureAuthenticate.authenticate,
			secureAuthenticate: secureAuthenticate.authenticate,
			authenticateByToken: insecureAuthenticate.authenticateByToken,
			onUserMade: insecureAuthenticate.onUserMade,
			getEmail: function(userId, cb){
				exports.getEmail(userId, cb)
			}
		}
	
		handle.hasSession = hasSession = function(req, cb){
			var sid = req.cookies.SID;
			if(sid === undefined){
				log('no SID cookie found')
				cb(false);
			}else{
				sid = sid.substr(0, sid.indexOf('|'))
				internal.checkSession(sid, function(ok, userId){
					cb(ok);
				});
			}
		}
		
		handle.findUser = internal.findUser
		handle.makeUser = internal.makeUser
		handle.authenticate = internal.authenticate
		handle.makeSession = internal.makeSession
		
		handle.getEmail = internal.getEmail
	
		cb(handle)*/
	})
}

