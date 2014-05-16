"use strict";

var bcrypt = require('bcrypt'),
	random = require('seedrandom'),
	_ = require('underscorem'),
	sys = require('sys');
	
function hashPassword(password, salt){
	var hash = bcrypt.hashSync(password, salt);
	return hash;
}

var log = require('quicklog').make('user-cassandra/internal')

var emailCache = {}

var cql = require('node-cassandra-cql')

function make(hosts, keyspace, cb){

	_.assertLength(arguments, 3);
	_.assertString(keyspace)
	_.assertFunction(cb);

	var Client = cql.Client;
	var client = new Client({hosts: hosts, keyspace: keyspace})
	
	client.connect(function(){
		var cdl = _.latch(4, function(){
			finishMake(client, cb)
		})
	
		client.execute('CREATE TABLE users_v2 ('+
			'userId timeuuid,'+
			'email text,'+
			'createdTime timestamp,'+
			'passwordChangedTime timestamp,'+
			'hash text,'+
			'guest boolean,'+
			'PRIMARY KEY (userId)'+
		');', cdl)
	
		client.execute('CREATE TABLE sessions ('+
			'userId timeuuid,'+
			'sessionToken text,'+
			'PRIMARY KEY (userId)'+
		');', cdl)
		
		client.execute('CREATE TABLE reverse_sessions_lookup ('+
			'sessionToken text,'+
			'userId timeuuid,'+
			'PRIMARY KEY(sessionToken)'+
		');', cdl)

		client.execute('CREATE TABLE user_by_email ('+
			'email text,'+
			'userId timeuuid,'+
			'hash text,'+
			'PRIMARY KEY(email)'+
		');', cdl)

		client.on('log', function(level, message) {
		  //console.log('log event: %s -- %j', level, message);
		});
	})
}

function finishMake(c, cb){


	function addUserToIndexes(userId, email, hash, cb){
		c.execute('insert into user_by_email (userId, email,hash) VALUES (?,?,?)', [userId, email,hash], 1, function(err, result){
			if(err) throw err

			cb()
		})
	}
	var handle = {
	
		makeGuest: function(email, cb){
			var now = Date.now()

			var userId = cql.types.timeuuid()
			
			c.execute('insert into users_v2 (userId, createdTime, email, passwordChangedTime,guest) VALUES (?,?,?,?,?)', [userId, {hint: 'timestamp', value: now}, email, {hint: 'timestamp', value: now},true], 1, function(err, result){
				if(err) throw err
			
				addUserToIndexes(userId, email, '', function(){
					cb(userId)
				})
			})
		},
		makeUser: function(email, password, cb, errCb){

			var salt = bcrypt.genSaltSync(10);
			var hash = hashPassword(password, salt)
			var now = Date.now()
			
			if(errCb) _.assertFunction(errCb)

			var userId = cql.types.timeuuid()
			
			c.execute('insert into users_v2 (userId, createdTime, email, passwordChangedTime, hash) VALUES (?,?,?,?,?)', [userId,{hint: 'timestamp', value: now}, email, {hint: 'timestamp', value: now}, hash], 1, function(err, result){
				if(err){
					if(errCb) errCb(err)
					else throw err
				}
				
				addUserToIndexes(userId, email, hash, function(){
					cb(userId)
				})
			})
		},
		
		//note that 'authentication key' here refers to keys used for lost password retrieval, not sessions
		//hence we only want 1 to exist at a time, and we need to be able to delete it once it has been used
		createAuthenticationKey: function(email, cb){
			_.errout('TODO')
		},
		getAuthenticationKeyEmail: function(token, cb){
			_.errout('TODO')
		},
		expireAuthenticationKey: function(key){
			_.errout('TODO')		
		},
		setEmail: function(id, email){
			_.assertString(email)

			c.snap('singleUser', [id], function(err, suv){
				if(err) throw err
				suv.user.email.set(email)
			})
		},
		getEmail: function(id, cb){
			if(!id) throw new Error('id is not valid: ' + id)
			
			if(emailCache[id] !== undefined){
				process.nextTick(function(){
					cb(emailCache[id])
				})
				return
			}
			//console.log('get-user-email')
			c.execute('SELECT email FROM users_v2 WHERE userId=?', [id], 1,function(err, result){
				if(err) throw err
				if(result.rows.length === 0){
					cb()
				}else{
					var email = result.rows[0].email
					emailCache[id] = email
					cb(email)
				}
			})
		},
		setPassword: function(id, email, password, cb){

			var salt = bcrypt.genSaltSync(10);
			var hash = hashPassword(password, salt)
			var now = Date.now()
			
			//c.execute('insert into users (userId, createdTime, email, passwordChangedTime, hash) VALUES (now(),?,?,?,?)', [now, email, now, hash], 1, function(err, result){
			//console.log('set-user-password')
			c.execute('UPDATE users_v2 SET hash=?, passwordChangedTime=? WHERE userId=?', [hash, now, id], 1, function(err, result){
				if(err) throw err
				
				if(cb) cb()
			})			
		},
		authenticate: function(id, password, cb){

			//_.assert(id > 0)
			c.execute('SELECT hash FROM users_v2 WHERE userId=?', [id], 1,function(err, result){
				if(err) throw err

				var hash = result.rows[0].hash
				
				var passed = bcrypt.compareSync(password, hash);
				//console.log('hash: ' + hash)
				//console.log('password: ' + password)
				//console.log('passed: ' + passed)
				if(passed){
					cb(true);
				}else{
					cb(false);
					//TODO set up fail delay
				}
			})
		},
		findUser: function(email, cb){

			if(!email) throw new Error('email undefined')
			console.log('find-user')
			c.execute('SELECT userId FROM user_by_email WHERE email=?', [email], 1,function(err, result){
				if(err) throw err
				
				if(result.rows.length > 0){
					var userId = result.rows[0].userid
					cb(userId)
				}else{
					cb()
				}
			})
		},
		
		makeSession: function(id, cb){
			var token = random.uidBase64()
			c.execute('insert into sessions (userId, sessionToken) VALUES (?,?)', [id, token], 1, function(err, result){
				if(err) throw err

				c.execute('insert into reverse_sessions_lookup (userId, sessionToken) VALUES (?,?)', [id, token], 1, function(err, result){
					if(err) throw err
			
					if(cb){
						cb(token)
					}
				})
			})
		},
		checkSession: function(token, cb){
			if(!_.isString(token)){
				console.log('warning in checkSession: token not a string')
				cb(false)
				return
			}else if(token.length === 0){
				console.log('warning in checkSession: token too short')
				cb(false)
				return
			}
			

			c.execute('SELECT userId FROM reverse_sessions_lookup WHERE sessionToken=?', [token], 1,function(err, result){
				if(err) throw err
				
				if(result.rows.length > 0){
					var row = result.rows[0]
					var userId = row.userid
					cb(true, userId)
				}else{
					cb(false)
				}
			})
		},
		clearAllUserSessions: function(userId, sessionToken, cb){
				
			c.execute('DELETE FROM sessions WHERE userId=?', [userId], 1, function(err, result){
				if(err) throw err

				c.execute('DELETE FROM reverse_sessions_lookup WHERE sessionToken=?', [sessionToken], 1, function(err, result){
					if(err) throw err
					console.log('all sessions cleared')

					if(cb){
						cb()
					}
				})
			})
		},
		clearAllSessions: function(token, cb){

			c.execute('SELECT userId FROM reverse_sessions_lookup WHERE sessionToken=?', [token], 1,function(err, result){
				if(err) throw err
				
				if(result.rows.length === 0){
					console.log('WARNING: userId not found for clear: ' + token)
					if(cb) cb()
				}else{
					var userId = result.rows[0].userid
					handle.clearAllUserSessions(userId, token, cb)
				}
			})
		}
	};
	
	cb(handle);
}

exports.make = make;
