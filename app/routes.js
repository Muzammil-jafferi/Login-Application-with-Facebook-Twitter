module.exports = function(app, passport) {

	app.get('/', function(req, res) {
		res.render('signup.ejs'); 
	});

	app.get('/login', function(req, res) {
		res.render('login.ejs', { message: req.flash('loginMessage') });
	});

	app.post('/login', passport.authenticate('local-login', {
		successRedirect : '/profile', 
		failureRedirect : '/login', 
		failureFlash : true 
	}));

	app.get('/signup', function(req, res) {
		res.render('signup.ejs', { message: req.flash('signupMessage') });
	});

	app.post('/signup', passport.authenticate('local-signup', {
		successRedirect : '/login', 
		failureRedirect : '/signup', 
		failureFlash : true 
	}));

	app.get('/profile', isLoggedIn, function(req, res) {
		res.render('profile.ejs', {
			user : req.user 
		});
	});

	app.get('/auth/facebook', passport.authenticate('facebook', { scope : ['user_friends','email'] }));

	app.get('/auth/facebook/callback',
		passport.authenticate('facebook', {
			successRedirect : '/profile',
			failureRedirect : '/'
		}));


	app.get('/auth/twitter', passport.authenticate('twitter'));

	app.get('/auth/twitter/callback', 
  		passport.authenticate('twitter', { 
  			failureRedirect: '/signup' 
  		}), function(req, res) {
    		res.redirect('/profile');
  		});

	app.get('/logout', function(req, res) {
		req.logout();
		res.redirect('/');
	});
};

function isLoggedIn(req, res, next) {

	if (req.isAuthenticated())
		return next();

	res.redirect('/');
}
