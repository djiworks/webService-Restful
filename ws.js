"use strict";

// Title of process in PS and TOP
process.title = 'WebService';
 
// Server Configuration
var wsPort = 8080;
var express = require('express');
var https = require('https');
var fs = require('fs');

//To use JSON Web Token
var jwt = require('jwt-simple');
var crypto = require('crypto');
var shasum = crypto.createHash('sha1');
shasum.update('symetric_key');
var intern_key = shasum.digest('hex'); 

//Used temporarly to store token (should be removed using a database)
var tokens = {};

//Used temporarly to checkuser
function checkUser (req, res, next) {
	
	//Collect auth info
	var bearer = req.headers.bearer;
	var uuid = req.headers.apikey;
	
	//If auth info is valid
	if (typeof(bearer) !== 'undefined' && typeof(uuid) !== 'undefined'){
		//Search the token into array
		var item = {};
		for (var i in tokens) {	
			item = tokens[i];
			//Token found	
			if(item.token == bearer)
			{
				//var decoded = jwt.decode(bearer, intern_key);
				//decoded.username && decoded.uuid available
				//Check if the token is linked with uudi of the request
				if (item.uuid == uuid)
				{
					next();
				}
			}
		}
		res.json(401,{"error" : "401 Unauthorized"});
		console.log("Error 401: " + req.ip + " tried to connect with wrong token:"+ bearer +" and/or uuid on "+ (new Date()));	
	}
	else //When bearer and/or apikey hearders not exist
	{
		res.json(406,{"error" : "406 Not Acceptable"});
		console.log("Error 406: " + req.ip + " tried to connect without token or/and apikey headers on "+ (new Date()));	
	}
}


var app = express();
app.configure(function(){
  app.set('title', 'WebService');
  //Put here code to get production mode
  app.use(express.bodyParser());
  //Used for HTTPS Basic Auth like .htaccess, please check http://expressjs.com/api.html#basicAuth
  //app.use(express.basicAuth('user', 'password'));
  //Other solution using JSON Web Token : http://coderead.wordpress.com/2012/08/16/securing-node-js-restful-services-with-jwt-tokens/
  //Other solution using oAuth and finally create our own autorizing server : https://github.com/jaredhanson/oauth2orize
});

//Configure https
var privateKey  = fs.readFileSync('./sslcert/server.key', 'utf8');
var certificate = fs.readFileSync('./sslcert/server.crt', 'utf8');
var credentials = {key: privateKey, cert: certificate};


//Routes
var route = 'one_route';
var token = ':uuid/auth';


//By default test if the request header is valid
app.use(function(req, res, next){
   		//The request has not a JSON Header or don't wait for a JSON response
		if(!req.is('application/json') || (req.accepts('application/json') === undefined))
		{
			res.json(406,{"error" : "406 Not Acceptable"});
			console.log("Error 406: " + req.ip + " tried to connect with a Content-Type: "+ req.get('Content-Type') +" and a Accept:"+ 
			req.get('Accept')+" on "+ (new Date()));
		}
		else
		next();
});

//Auth request to record a new user
app.get('/'+token, function(req, res) {
	
	//Collect auth info
	var username = req.headers.username;
	var password = req.headers.password;

	//If auth info is valid
	if (typeof(username) !== 'undefined' && typeof(password) !== 'undefined'){
	
		//Store username and uuid into token
		var payload =  {"username": username, "uuid": req.params.uuid} ;
		
		//Encrypt with server key
		var jsontoken = jwt.encode(payload, intern_key);
		
		//Store it in a db
		tokens[username] = {"username": username, "password": password, "token": jsontoken, "uuid": req.params.uuid};
		console.log(req.ip + " (new user) registred as "+username+" with token "+ jsontoken+ " on "+ (new Date()));		
		res.json(200,{"token" : jsontoken});
	}
	else //Auth info is not valid
	{
		res.json(406,{"error" : "406 Not Acceptable"});
		console.log("Error 406: " + req.ip + " tried to connect without username and/or password headers on "+ (new Date()));
	}
});



//Welcome request
app.get('/', checkUser, function(req, res) {
		res.json(200,{"message" : "You're using WebService v0.8, please check the documentation and make sure you are allowed to use it"});
		console.log(req.ip + " tried to connect on "+ (new Date()));
});

//GET /version to get version status
app.get('/'+route, checkUser, function(req, res) {
		res.json(200,{"Date": new Date(), "Data": "One"});
		console.log(req.ip + " asked to get route on "+ (new Date()));
});


//POST '{"name":"foo"}' /route
app.post('/'+route, checkUser, function(req, res) {
		//Try make a process
		if(!req.body.hasOwnProperty('name')) 
		{
			res.json(400,{"error" : "400 Bad Request"});
			console.log("Error 400: " + req.ip + " tried to post an incorrect data: "+ JSON.stringify(req.body) +" on "+ (new Date()));
		}
		else
		{
			//Is OK
			res.json(200,{"result" : "OK", "message": "Thank you to help us"});
			console.log(req.ip + " added a name: "+ JSON.stringify(req.body) +" on "+ (new Date()));	
		}
});

//If the request is unknown
app.use(function(req, res){
   res.json(404, { "error": '404 Not Found' })
   console.log("Error 404: " + req.ip + " tried to get unknown page" + req.originalUrl +" on "+ (new Date()));
});


console.log("Starting %s on port %d in %s mode", app.get('title'), wsPort, app.settings.env);
https.createServer(credentials,app).listen(wsPort);
//app.listen(wsPort); to allow http connection (not recommanded)
console.log("%s started on %s", app.get('title'), (new Date()));