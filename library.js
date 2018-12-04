var passport = module.parent.require('passport'),
    passportLocal = module.parent.require('passport-local').Strategy,
    plugin = {};
var async = require('async');
var request = require('request');
var db = require.main.require('./src/database');
var user = require.main.require('./src/user');
var userController = require.main.require('./src/controllers').user;

plugin.filterUserCreate = function (data, callback) {
    data.user.auid = data.data.auid;
    callback(null, data);
};

plugin.whitelistFields = function(data, callback) {
	data.whitelist.push('auid');
	callback(null, data);
};

plugin.auidSet = function(data, callback) {
    db.sortedSetAdd('auid:uid', data.user.uid, data.user.auid, callback);
}

plugin.thirdLogin = function() {
    passport.use(new passportLocal({passReqToCallback: true}, plugin.continueLogin));
};

plugin.getUidByAUid = function(auid, callback) {
	if (!auid) {
		return callback(null, 0);
	}
    db.sortedSetScore('auid:uid', auid, callback);
};

plugin.getUserDataByField = function (callerUid, field, fieldValue, callback) {
	async.waterfall([
		function (next) {
			if (field === 'uid') {
				next(null, fieldValue);
			} else if (field === 'auid') {
				plugin.getUidByAUid(fieldValue, next);
			} else if (field === 'username') {
				user.getUidByUsername(fieldValue, next);
			} else if (field === 'email') {
				user.getUidByEmail(fieldValue, next);
			} else {
				next(null, null);
			}
		},
		function (uid, next) {
			if (!uid) {
				return next(null, null);
			}
			userController.getUserDataByUID(callerUid, uid, next);
		},
	], callback);
};

plugin.continueLogin = function(req, username, password, next) {
    //var user = module.parent.require('../user');
    
    var userObj = {}

	async.waterfall([
        function (callback) {
            if (!username || !password) {
                return callback(new Error('Il nome utente o la password non possono essere vuoti'));
            } else {
                request.post({url:'https://www.simosnap.org/rest/service.php/rlogin', form:{username: username, password: password}}, function(error, response, body) {
                    if (!error && response.statusCode == 200) {
                        const data = JSON.parse(body)
                        //console.log(data);
                        if (data.ERROR == null) {
                            if (data.UNCONFIRMED == null) {
                                userObj = data
                                return callback(null, userObj);
                            } else {
                                //console.log(data.msg)
                                return callback(new Error("Account non confermato."));
                            }
                        } else {
                            //console.log(data.msg)
                            return callback(new Error("Accesso non riuscito."));
                        }
                    } else {
                        return callback(new Error('Errore di rete...'));
                    }
                    if (error) {
                        return callback(new Error('Errore'));
                    }
                })
            }
        },
        function (userObj, callback) {
            //user.getUidByEmail(String(userObj.email), callback)
            plugin.getUserDataByField('1', 'auid', userObj.uid, function(err, userData) {
                console.log(userData);
            	callback(null, userData.auid, userData.uid );
            });

        },
        function (_auid, _uid, callback) {
		console.log("auid: " + _auid);
            if (!_auid) {
                user.create({
                    auid: userObj.uid,
                    username: userObj.display,
                    email: userObj.email
                }, callback);
            } else {
                callback(null, _uid)
            }
        },  function (_uid, callback) {
            if (_uid) {
                user.updateProfile(1, { uid: _uid, username: userObj.display });
                user.updateProfile(1, { uid: _uid, email: userObj.email });
                next(null, {
                    uid: _uid
                }, '[[success:authentication-successful]]');
            } else {
                return callback(new Error('L\'utente non esiste'));
            }
        }], function(error, res) {
            if (error) {
                next(error);
            }
        })
};

module.exports = plugin;
