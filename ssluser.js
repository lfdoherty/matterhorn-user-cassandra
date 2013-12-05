
exports.module = module

var urlModule = require('url')
var querystring = require('querystring')
var _ = require('underscorem')
var log = require('quicklog').make('user-cassandra/secure')
var sys = require('util')

function setSessionCookie(res, session){
	res.cookie('SID', session, {httpOnly: true, secure: true, maxAge: 24 * 60 * 60 * 1000});
}

exports.load = function(app, secureApp, host, secureHost, internal, prefix, userMadeCb){
	//_.assertLength(arguments, 6)
	prefix = prefix||''

	function authenticateByToken(token, cb){
		_.assertFunction(cb)
		if(!token){
			cb('undefined token provided')
			return
		}
		_.assertString(token)
		//console.log('authenticating by token')
		
		internal.checkSession(token, function(ok, userId){
			if(ok){
				cb(undefined, userId)
			}else{
				cb('authentication failed')
			}
		});
	}
	function authenticate(req, res, next){
		//console.log('authenticating: ' + JSON.stringify(req.cookies));

		if(req.cookies.SID === undefined){
			doLoginRedirect();
			return;
		}

		var pi = req.cookies.SID.indexOf('|')
		if(pi === -1){
			doLoginRedirect();
			return;
		}
		
		if(req.cookies.LOGGEDOUT){
			doLoginRedirect()
			return
		}
		var sid = req.cookies.SID.substr(0, pi);

		function doLoginRedirect(){
			var protocol = req.headers["x-forwarded-proto"] || req.protocol
			var newUrl = 'https://' + req.headers.host + prefix+'/login?next='+protocol+'://' + req.headers.host + req.url
			res.header('Cache-Control', 'no-cache, no-store')
			res.redirect(newUrl);
		}


		internal.checkSession(sid, function(ok, userId){
			if(ok){
				internal.getEmail(userId, function(email){
					req.user = {id: userId, email: email};
					req.userToken = userId
					req.email = email
					next();
				});
			}else{
				doLoginRedirect();
			}
		});
	}


	//set up services for signup, login, logout, and lost password reset.
	//all to be accessed via AJAX (these are not HTML resources.)

	function signup(req, res){

		var data = req.body;
		
		if(!_.isString(data.email) || !_.isString(data.password)){
			res.send({
				error: 'missing email or password'
			}, 400)
			return
		}

		log('/ajax/signup request received .email: ' + data.email);

		res.header('Cache-Control', 'no-cache, no-store')
		
		internal.findUser(data.email, function(userId){

			log('/ajax/signup found user?: ' + userId);
			
			if(userId !== undefined){
				internal.authenticate(userId, data.password, function(ok){
					if(ok){
						login(req,res);
					}else{
						res.send({
							error: 'user already exists and authentication failed'
						}, 403);
					}
				})
			}else{
				internal.makeUser(data.email, data.password, function(userId){
				
					log('created user ' + userId + ' ' + data.email);
					
					if(userMadeCb) userMadeCb(userId, data.email)

					var session = internal.makeSession(userId, function(token){
						_.assertString(token)

						res.header('Cache-Control', 'no-cache, no-store')

						setSessionCookie(res, token)
						res.redirect('../../home/')
						
						/*var parsedUrl = urlModule.parse(req.url, true)
						var next = parsedUrl.query.next
			
						if(next){
							console.log('redirecting to: ' + next)
							res.redirect(next)
						}else{
							console.log('straightforward msg: ' + req.url + ' ' + JSON.stringify(parsedUrl))
							res.send('<html><body>You have been signed up and logged in.</body></html>');
						}*/
					});
				}, true);
			}
		})
	}

	secureApp.post('/ajax/signup', signup);

	function login(req, res){

		var data = req.body;

		log('/ajax/login request received .email: ' + data.email);

		res.header('Cache-Control', 'no-cache, no-store')

		internal.findUser(data.email, function(userId){
			log('found user: ' + userId);
			if(userId === undefined){
				res.send({
					error: 'authentication failed'
				}, 403);
			}else{
				internal.authenticate(userId, data.password, function(ok){

					if(ok){
						internal.makeSession(userId, function(token){
							res.header('Cache-Control', 'no-cache, no-store')

							setSessionCookie(res, token)
							res.redirect('../../home/')

							/*var parsedUrl = urlModule.parse(req.url, true)
							var next = parsedUrl.query.next
				
							if(next){
								console.log('redirecting to: ' + next)
								res.redirect(next)
							}else{
								console.log('straightforward msg: ' + req.url + ' ' + JSON.stringify(parsedUrl))
								res.send('<html><body>You have been logged in.</body></html>');
							}*/
						});

					}else{
						res.send({
							error: 'authentication failed'
						}, 403);
					}
				});
			}
		});
	}

	secureApp.post('/ajax/login', login);

	function logoutHandler(req, res){
		
		console.log('/logout GET')
		
		res.header('Cache-Control', 'no-cache, no-store')
		
		doLogout(req, res, function(err){
			if(err){
				console.log('err: ' + err)
				res.send('<html><body>Error during logout: ' + err + '</body></html>')//{result: err});
			}else{
				var parsedUrl = urlModule.parse(req.url, true)
				var next = parsedUrl.query.next
				
				if(next){
					console.log('redirecting to: ' + next)
					res.redirect(next)
				}else{
					console.log('straightforward msg: ' + req.url + ' ' + JSON.stringify(parsedUrl))
					res.send('<html><body>You have been logged out.</body></html>');
				}
			}
		})
	}
	secureApp.get('/logout', logoutHandler)
	
	function doLogout(req, res, cb){
		var sid = req.cookies.SID;

		if(sid !== undefined){
			if(sid.indexOf('|') !== -1) sid = sid.substr(0, sid.indexOf('|'));
			res.clearCookie('SID');
			console.log('doing clear')
			internal.clearAllSessions(sid, function(did){
				if(did){
					cb()
				}else{
					cb('unknown session token')
				}
			});
		}else{
			cb('no cookie')
		}
	}

	secureApp.post('/ajax/logout', logout);
	function logout(req, res){
	
		res.header('Cache-Control', 'no-cache, no-store')

		doLogout(req, res, function(err){
			if(err){
				res.send({result: err});
			}else{
				res.send({result: 'ok'});
			}
		})
	}

	var loginPage = {
		url: '/login',
		js: './js/simple_login',
		cb: function(req, res, cb){
			console.log('cbing: ' + req.query.next);
			var url = prefix+'/ajax/login'
			if(req.query.next) url += '?next='+req.query.next
			cb({after: req.query.next, securePort: secureApp.port, PostUrl: url,
				SignupUrl: prefix+'/signup',
				title: secureApp.loginTitle || 'Log In'
			});
		}
	};	
	var signupPage = {
		url: '/signup',
		js: './js/simple_signup',
		cb: function(req, res, cb){
			cb({securePort: res.app.getSecurePort(), 
				PostUrl: prefix+'/ajax/signup',
				title: secureApp.signupTitle || 'Sign Up'
			})
		}
	};	

	secureApp.post('/ajax/signup', signup);
	secureApp.post('/ajax/login', login);

	secureApp.page(exports, loginPage);
	secureApp.page(exports, signupPage);
	
	return {
		authenticate: authenticate,
		authenticateByToken: authenticateByToken,
		onUserMade: function(listener){
			internal.onUserMade(listener)
		}
	}
}
