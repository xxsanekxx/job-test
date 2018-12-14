const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const basicAuth = require('express-basic-auth')

const usersRouter = express.Router();
const users = {
	'test': 'test',
};
const blackListTokens = [];
const secret = 'somesecret';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function(req, res, next) {
  res.send('index');
});

app.post('/signUp', function(req, res, next) {
	// push to users
	users[req.body.user] = req.body.password;
  	res.send({ success: true });
});

app.get('/signIn', basicAuth({ users, challenge: true }), function(req, res, next) {
  	const token = jwt.sign({ [req.auth.user]: req.auth.password }, secret);
	const indexBlockedToken = blackListTokens.indexOf(token);
	
	if (indexBlockedToken !== -1) {
	  blackListTokens.splice(indexBlockedToken, 1);
	}
	
	res.send({
		success: true,
		token,
	});
});

app.get('/logout', function(req, res, next) {
	const token = req.body.token || req.params.token || req.headers['x-access-token'];
	if (token && blackListTokens.indexOf(token) === -1) {
		blackListTokens.push(token);
	}
  	res.send({ success: true });
});

usersRouter.use(function(req, res, next) {
	const token = req.body.token || req.params.token || req.headers['x-access-token'];

	if (token) {
		console.log(blackListTokens);
		if (blackListTokens.indexOf(token) !== -1) {
			return res.json({ error: { message: 'Token was expired' } });
		}
		jwt.verify(token, secret, function(err, decoded) {
			if (err) {
				return res.json({ error: { message: 'Failed to authenticate token.' } });
			}
			next();
		});
		return;

	}
	
	res.status(403).send({ error: { message: 'No token' } });

});

usersRouter.get('/', function(req, res, next) {
	res.send(users);
});

usersRouter.get('/:id', function(req, res, next) {
	res.send(users[req.params.id]);
});

usersRouter.put('/:id', function(req, res, next) {
        // do something with user[req.params.id]
	res.send(users[req.params.id]);
});

usersRouter.delete('/:id', function(req, res, next) {
    	delete users[req.params.id];
	res.send({ success: true });
});

app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  	next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  	// set locals, only providing error in development
  	res.locals.message = err.message;
  	res.locals.error = req.app.get('env') === 'development' ? err : {};

  	// render the error page
  	res.status(err.status || 500);
	res.json({ error: { message: 'Error' } });
});

app.listen(3000, function() { console.log('Listen on 3000'); });
