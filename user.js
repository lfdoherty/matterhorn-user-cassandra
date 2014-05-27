
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

		var sid = req.cookies.SID

		function doLoginRedirect(){
			var protocol = req.headers["x-forwarded-proto"] || req.protocol
			
			//console.log('*redirecting to ' + secureHost+'/login?next='+req.headers.host+req.url + ' ' + protocol);
			//console.log(JSON.stringify(req.headers))
			//res.redirect(secureHost+'/login?next=' + host + req.url);
			var newUrl = 'https://' + req.headers.host + prefix+'/login?next='+protocol+'://' + req.headers.host + req.url
			//console.log('*redirecting to: ' + newUrl)
			res.header('Cache-Control', 'no-cache, no-store')
			res.header('Pragma', 'no-cache')
			res.header('Expires', '0')
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
exports.makeClient = function(hosts, keyspace, prefix, cb){
	_.assertLength(arguments, 4)
	internalmaker.make(hosts, keyspace, function(internal){
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
				if(!sid){
					console.log('ERROR: no SID in cookie:  ' + req.cookies.SID)
					cb(false)
					return
				}
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

		handle.setPassword = internal.setPassword
		
		handle.findUser = internal.findUser
		handle.makeUser = internal.makeUser
		handle.authenticate = internal.authenticate
		handle.makeSession = internal.makeSession
		
		handle.getEmail = internal.getEmail
	
		cb(handle)
	})
}

exports.makeService = function(config, cb, userMadeCb){
	_.assertString(config.keyspace)
	
	internalmaker.make(config.hosts, config.keyspace, function(internal){
		_.assertDefined(internal)

		var secureAuthenticate = exports.secure.load(config, internal, userMadeCb)
		
		cb()
	})
}

