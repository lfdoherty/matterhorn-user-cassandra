
var page = require('fpage')

var u = require('./utils')

var pollsave = require('matterhorn-standard/js/pollsave')

var script = '<div>'+
	'<noscript><h1><font color="red">You must enable Javascript to use this website.<br/><br/><br/></font></h1></noscript>'+
	'<h2>' + page.params.title + '</h2>'+
	'<form action="'+page.params.PostUrl+'" method="post">'+
	'Email: <input id="email" name="email" type="text"></input><br/><br/>'+
	'Password: <input id="password" name="password" type="password" size="25"></input>' + 
		'&nbsp;&nbsp;&nbsp;&nbsp;<a href="'+page.params.urlPrefix+'/lostpassword/' + window.location.search + '">I Forgot My Password</a>' +
	'<br/><br/>'+
	'<input id="submit" type="submit" value="Submit"></input>'+
	'<span style="padding-left:3em"><a id="signuplink" href="'+page.params.SignupUrl+'">Create New Account</a></span>'+
	'</form>'+
	'<br/><br/>'+
	'<div id="result"/>'+
	'</div>';

document.addEventListener('DOMContentLoaded', function(){
	document.body.innerHTML = script
});
